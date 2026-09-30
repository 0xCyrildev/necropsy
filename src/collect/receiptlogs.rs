//! Receipt logs: the authoritative record of what value actually moved.
//!
//! This is where the design's central measurement landed. On the endpoint I
//! tested, `debug_traceTransaction` + `callTracer` returned `logs: null` on every
//! frame under `withLog`, `enableLog` and `withLogs` alike — so per-frame
//! emission attribution is not available and is not pretended to. The receipt,
//! by contrast:
//!
//!   * needs no archive state, so it works on endpoints that refuse `cast run`;
//!   * carries `address` = the EVM **storage context**, i.e. the USDC proxy and
//!     not the delegatecall implementation one line deeper in the same trace;
//!   * contains only logs that *committed*, so a transfer inside a subtree that
//!     later reverted is simply not there.

use crate::collect::rpc::Rpc;
use crate::error::{Error, Result};
use crate::model::address::hex_bytes;
use crate::model::{Address, RawLog, TokenEvent, Topic32, TxHash};
use serde_json::Value;

/// Parse `eth_getTransactionReceipt` logs. A malformed entry is counted, not
/// skipped, so `logs_in == parsed + unparseable`.
pub fn logs_from_receipt(receipt: &Value) -> (Vec<RawLog>, usize) {
    let mut out = Vec::new();
    let mut malformed = 0usize;
    let Some(arr) = receipt.get("logs").and_then(|l| l.as_array()) else {
        return (out, 0);
    };
    for (i, l) in arr.iter().enumerate() {
        let Some(address) = l
            .get("address")
            .and_then(|a| a.as_str())
            .and_then(|s| s.parse::<Address>().ok())
        else {
            malformed += 1;
            continue;
        };
        let topics = match l.get("topics").and_then(|t| t.as_array()) {
            Some(ts) => ts
                .iter()
                .filter_map(|t| t.as_str())
                .filter_map(hex_bytes)
                .filter_map(|b| Topic32::from_slice(&b))
                .collect::<Vec<_>>(),
            None => Vec::new(),
        };
        // A topic we could not decode is dropped from `topics`, which changes the
        // arity the classifier sees; that would silently misclassify the log as a
        // different event, so the whole entry is counted malformed instead.
        let declared_topics = l
            .get("topics")
            .and_then(|t| t.as_array())
            .map_or(0, |a| a.len());
        if declared_topics != topics.len() {
            malformed += 1;
            continue;
        }
        let data = l
            .get("data")
            .and_then(|d| d.as_str())
            .and_then(hex_bytes)
            .unwrap_or_default();
        let log_index = l
            .get("logIndex")
            .and_then(|v| v.as_str())
            .and_then(crate::collect::rpc::hex_u64)
            // Absent logIndex falls back to array position. That is sound because
            // receipt logs are emitted in order, but the report cannot then prove
            // which it got, so the collector records it as a degraded input.
            .unwrap_or(i as u64) as u32;
        out.push(RawLog {
            address,
            topics,
            data,
            log_index,
        });
    }
    (out, malformed)
}

pub fn fetch_receipt_logs(rpc: &dyn Rpc, hash: TxHash) -> Result<(Vec<RawLog>, usize)> {
    let receipt = rpc.request(
        "eth_getTransactionReceipt",
        &[serde_json::json!(hash.to_hex())],
    )?;
    if receipt.is_null() {
        return Err(Error::NotFound {
            hash: hash.to_hex(),
        });
    }
    Ok(logs_from_receipt(&receipt))
}

/// Classify every log. Returns the events plus the count that could not be
/// classified — the number that has to appear in a report before "no transfers
/// found" can be trusted.
pub fn classify(logs: &[RawLog]) -> (Vec<TokenEvent>, usize) {
    let mut events = Vec::with_capacity(logs.len());
    let mut unclassified = 0;
    for l in logs {
        let ev = crate::model::events::classify(l);
        if matches!(ev, TokenEvent::Unclassified { .. }) {
            unclassified += 1;
        }
        events.push(ev);
    }
    (events, unclassified)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::events::classify as classify_one;
    use serde_json::json;

    const TRANSFER_TOPIC: &str =
        "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

    /// Left-pad an address into a 32-byte ABI topic word.
    fn addr_word(addr: &str) -> String {
        format!("0x{:0>64}", addr.trim_start_matches("0x"))
    }

    // The real receipt for 0x5b515946…, transcribed from the response body:
    // log.address is the PROXY even though the emitting frame was a
    // DELEGATECALL into 0xa2327a93….
    #[test]
    fn receipt_log_address_is_the_token_not_the_implementation() {
        let receipt = json!({
            "status": "0x1",
            "logs": [{
                "address": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
                "topics": [TRANSFER_TOPIC,
                           addr_word("0xfacf9ec2d27045b31291e79f4ac982cce66bf241"),
                           addr_word("0xcffad3200574698b78f32232aa9d63eabd290703")],
                "data": "0x0000000000000000000000000000000000000000000000000000000012e24cf6",
                "logIndex": "0x0"
            }]
        });
        let (logs, malformed) = logs_from_receipt(&receipt);
        assert_eq!(malformed, 0);
        assert_eq!(logs.len(), 1);
        match classify_one(&logs[0]) {
            TokenEvent::Erc20Transfer {
                token,
                from,
                to,
                amount,
                ..
            } => {
                assert_eq!(token.to_hex(), "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48");
                assert_eq!(from.to_hex(), "0xfacf9ec2d27045b31291e79f4ac982cce66bf241");
                assert_eq!(to.to_hex(), "0xcffad3200574698b78f32232aa9d63eabd290703");
                assert_eq!(amount.to_decimal_string(), "316820726");
            }
            other => panic!("expected the USDC transfer, got {other:?}"),
        }
    }

    #[test]
    fn malformed_entries_are_counted_not_dropped() {
        let receipt = json!({"logs": [
            {"address": "not-an-address", "topics": [], "data": "0x"},
            {"address": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
             "topics": [TRANSFER_TOPIC, "0xshort", addr_word("0x1")], "data": "0x00"},
            {"address": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
             "topics": [TRANSFER_TOPIC, addr_word("0x1"), addr_word("0x2")],
             "data": "0x0000000000000000000000000000000000000000000000000000000000000001",
             "logIndex": "0x2"}
        ]});
        let (logs, malformed) = logs_from_receipt(&receipt);
        assert_eq!(logs.len(), 1);
        assert_eq!(
            malformed, 2,
            "a bad topic must not reduce arity and silently reclassify the log"
        );
        assert_eq!(
            logs[0].log_index, 2,
            "the real logIndex is preserved, not the array position"
        );
    }

    #[test]
    fn missing_logs_array_is_zero_not_panic() {
        let (logs, malformed) = logs_from_receipt(&json!({ "status": "0x1" }));
        assert!(logs.is_empty());
        assert_eq!(malformed, 0);
    }

    #[test]
    fn classify_counts_the_unclassifiable() {
        let logs = vec![
            RawLog {
                address: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
                    .parse()
                    .unwrap(),
                topics: vec![],
                data: vec![],
                log_index: 0,
            };
            2
        ];
        let (events, unclassified) = classify(&logs);
        assert_eq!(events.len(), 2);
        assert_eq!(
            unclassified, 2,
            "topicless logs must be counted, not read as 'no transfers'"
        );
    }
}
