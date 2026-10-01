//! Transaction and receipt metadata.
//!
//! The origin and the callee are what make a sink interpretable: without
//! `tx.from` and `tx.to`, an EOA that drained the contract and a pool that
//! merely passed value through look identical in the ranking.

use crate::collect::rpc::{Rpc, field_addr, field_hex_u64};
use crate::error::{Error, Result};
use crate::model::{Address, Amount, Selector, TxHash};
use serde::Serialize;
use serde_json::Value;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TxStatus {
    Success,
    /// The transaction itself reverted. Analysing these is the point of the
    /// tool — an attempted exploit usually reverts — so this is a fact about the
    /// transaction, never an error from necropsy.
    Reverted,
}

#[derive(Debug, Clone, Serialize)]
pub struct TxMeta {
    pub hash: TxHash,
    pub from: Address,
    /// `None` for a creation.
    pub to: Option<Address>,
    pub block_number: Option<u64>,
    pub chain_id: Option<u64>,
    /// `None` when no receipt was available. Distinct from `Some(Success)`.
    pub status: Option<TxStatus>,
    pub value: Amount,
    pub gas_used: Option<u64>,
    /// Selector of the top-level call.
    pub selector: Option<Selector>,
}

pub fn get_chain_id(rpc: &dyn Rpc) -> Result<Option<u64>> {
    match rpc.request("eth_chainId", &[]) {
        Ok(v) => Ok(v.as_str().and_then(field_hex_u64_str)),
        // A node that does not answer eth_chainId is not an error: it just means
        // the run cannot be chain-guarded, which the report then states.
        Err(_) => Ok(None),
    }
}

fn field_hex_u64_str(s: &str) -> Option<u64> {
    crate::collect::rpc::hex_u64(s)
}

pub fn get_transaction(rpc: &dyn Rpc, hash: TxHash) -> Result<Value> {
    let v = rpc.request(
        "eth_getTransactionByHash",
        &[serde_json::json!(hash.to_hex())],
    )?;
    if v.is_null() {
        return Err(Error::NotFound {
            hash: hash.to_hex(),
        });
    }
    Ok(v)
}

pub fn get_receipt(rpc: &dyn Rpc, hash: TxHash) -> Result<Value> {
    let v = rpc.request(
        "eth_getTransactionReceipt",
        &[serde_json::json!(hash.to_hex())],
    )?;
    if v.is_null() {
        return Err(Error::NotFound {
            hash: hash.to_hex(),
        });
    }
    Ok(v)
}

pub fn get_code(rpc: &dyn Rpc, address: Address, block_tag: &str) -> Result<Option<Vec<u8>>> {
    let params = [
        serde_json::json!(address.to_hex()),
        serde_json::json!(block_tag),
    ];
    match rpc.request("eth_getCode", &params) {
        Ok(v) => Ok(v.as_str().and_then(crate::model::address::hex_bytes)),
        Err(_) => Ok(None),
    }
}

pub fn meta_from(
    hash: TxHash,
    tx: &Value,
    receipt: Option<&Value>,
    chain_id: Option<u64>,
) -> Result<TxMeta> {
    let from =
        field_addr(tx, "from").ok_or_else(|| Error::Collect("transaction has no `from`".into()))?;
    let input =
        crate::model::address::hex_bytes(tx.get("input").and_then(|v| v.as_str()).unwrap_or("0x"));
    let selector = input.as_deref().and_then(Selector::from_calldata);
    let value = tx
        .get("value")
        .and_then(|v| v.as_str())
        .and_then(Amount::from_hex)
        .unwrap_or(Amount::ZERO);

    let status = receipt.and_then(|r| match r.get("status") {
        Some(Value::String(s)) => Some(if s == "0x1" || s == "0x01" {
            TxStatus::Success
        } else {
            TxStatus::Reverted
        }),
        // Pre-Byzantium receipts carry no status field at all. Saying "unknown"
        // is correct; saying "success" would be a guess.
        _ => None,
    });

    Ok(TxMeta {
        hash,
        from,
        to: field_addr(tx, "to"),
        block_number: field_hex_u64(tx, "blockNumber"),
        chain_id,
        status,
        value,
        gas_used: receipt.and_then(|r| field_hex_u64(r, "gasUsed")),
        selector,
    })
}

impl TxMeta {
    /// The block tag every state read for this transaction must use, stated in
    /// one place. `latest` would read a *different chain state* than the one the
    /// transaction saw, which silently changes decimals, balances and code.
    pub fn block_tag(&self) -> String {
        match self.block_number {
            Some(n) => format!("0x{n:x}"),
            None => "latest".to_string(),
        }
    }

    pub fn is_creation(&self) -> bool {
        self.to.is_none()
    }
}

/// Parse a hash the way the CLI does, so every entry point shares one
/// rule instead of two that can drift.
pub fn parse_tx_hash(s: &str) -> Result<TxHash> {
    TxHash::from_str(s).map_err(|e| Error::BadTxHash {
        input: s.to_string(),
        reason: e.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::rpc::MemoryRpc;
    use serde_json::json;

    const USDC: &str = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";

    #[test]
    fn chain_id_is_optional_but_read_when_present() {
        let rpc = MemoryRpc::new([("eth_chainId", json!("0x1"))]);
        assert_eq!(get_chain_id(&rpc).unwrap(), Some(1));
        let none = MemoryRpc::new([("other", json!(1))]);
        assert_eq!(get_chain_id(&none).unwrap(), None);
    }

    #[test]
    fn meta_reads_status_from_the_receipt_not_the_exit_code() {
        // `cast run` exits 0 on a reverted transaction, so process status is not
        // evidence about execution. The receipt is.
        let hash =
            parse_tx_hash("0x6cdee82dca12b9662d883dadb1a3c828ffdca273f6f99eab10891aece197e601")
                .unwrap();
        let tx = json!({
            "from": "0x6982508145454Ce325dDbE47a25d4ec3d2311933",
            "to": USDC,
            "value": "0x0",
            "input": "0xa9059cbb0000",
            "blockNumber": "0x115df1e",
        });
        let rec = json!({ "status": "0x0", "gasUsed": "0x8238" });
        let m = meta_from(hash, &tx, Some(&rec), Some(1)).unwrap();
        assert_eq!(m.status, Some(TxStatus::Reverted));
        assert_eq!(m.block_number, Some(18_210_590));
        assert_eq!(m.block_tag(), "0x115df1e");
        assert_eq!(
            m.selector.map(|s| s.to_hex()),
            Some("0xa9059cbb".to_string())
        );
        assert_eq!(m.gas_used, Some(33_336));
    }

    #[test]
    fn a_receipt_without_status_is_unknown_not_success() {
        let hash = parse_tx_hash(&format!("0x{}", "ab".repeat(32))).unwrap();
        let tx =
            json!({"from": USDC, "to": USDC, "value": "0x0", "input": "0x", "blockNumber": "0x1"});
        let rec = json!({ "gasUsed": "0x1" });
        let m = meta_from(hash, &tx, Some(&rec), Some(1)).unwrap();
        assert_eq!(m.status, None);
    }

    #[test]
    fn missing_block_number_does_not_become_block_zero() {
        let hash = parse_tx_hash(&format!("0x{}", "cd".repeat(32))).unwrap();
        let tx = json!({"from": USDC, "to": USDC, "value": "0x0", "input": "0x"});
        let m = meta_from(hash, &tx, None, None).unwrap();
        assert_eq!(m.block_number, None);
        assert_eq!(m.block_tag(), "latest");
        assert_eq!(m.status, None);
    }

    #[test]
    fn creation_transactions_have_no_callee() {
        let hash = parse_tx_hash(&format!("0x{}", "ef".repeat(32))).unwrap();
        let tx = json!({"from": USDC, "to": null, "value": "0x0", "input": "0x6080", "blockNumber": "0x1"});
        let m = meta_from(hash, &tx, None, None).unwrap();
        assert!(m.is_creation());
    }

    #[test]
    fn a_null_transaction_is_not_found_not_a_parse_error() {
        let rpc = MemoryRpc::new([("eth_getTransactionByHash", json!(null))]);
        let hash = parse_tx_hash(&format!("0x{}", "11".repeat(32))).unwrap();
        assert!(matches!(
            get_transaction(&rpc, hash),
            Err(Error::NotFound { .. })
        ));
    }

    #[test]
    fn bad_hash_shapes_are_rejected_before_any_request() {
        let right_length_wrong_chars = format!("0xzz{}", "0".repeat(62));
        for bad in [
            "",
            "abc",
            "0x123",
            "-force",
            right_length_wrong_chars.as_str(),
        ] {
            assert!(
                parse_tx_hash(bad).is_err(),
                "{bad} must not reach the transport"
            );
        }
    }
}
