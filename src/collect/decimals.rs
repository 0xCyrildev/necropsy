//! Per-asset decimal places, read from the chain instead of assumed.
//!
//! The ledger prints base units because a 6-decimal stablecoin is not 10¹² of an
//! 18-decimal token, and scaling by a *guessed* exponent would put a wrong number on
//! every line — which is why [`crate::model::format_units`] has existed for a while and
//! has never been called. This asks each token what it says about itself.
//!
//! Two rules the fetch obeys:
//!
//!   * **The transaction's own block tag, never `latest`.** Metadata read at a later
//!     state than the money it describes answers a different question: a token can move
//!     its decimals the way a proxy moves its implementation. `TxMeta::block_tag` exists
//!     for exactly this call.
//!   * **One call per token, sequentially.** These endpoints refuse batches whose
//!     members each work alone, and a refused batch reads exactly like a token that has
//!     nothing to say.
//!
//! And one distinction that is easy to lose: `Some(0)` is an *answer* — a token with no
//! fractional unit. It is not the same fact as `None`, "the endpoint would not say", and
//! the report renders them differently. Nothing here defaults to 18.

use crate::collect::rpc::Rpc;
use crate::error::Error;
use crate::model::{Address, AssetId};
use serde::Serialize;
use serde::ser::{SerializeMap, Serializer};
use std::collections::BTreeMap;

/// `decimals()` — four bytes, no arguments.
const DECIMALS_CALL: &str = "0x313ce567";

/// Not a fetched fact. The EVM's own unit is 10¹⁸ wei, and no token is consulted.
pub const NATIVE_DECIMALS: u8 = 18;

/// What each asset in a ledger is worth in fractional digits, and why anything is still
/// missing.
#[derive(Debug, Clone, Default)]
pub struct Decimals {
    answers: BTreeMap<Address, Option<u8>>,
    reasons: Vec<String>,
}

/// How a decimal count was arrived at, because the three cases must not look alike.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// The token was asked at the transaction's block and answered.
    Fetched,
    /// Never asked, and no answer could contradict it: native ETH is 18 by protocol.
    Protocol,
    /// Nothing is known, so this asset's amounts stay base units.
    Unknown,
}

impl Decimals {
    /// The answer for `asset`, and how it was obtained.
    pub fn of(&self, asset: AssetId) -> (Option<u8>, Source) {
        match asset {
            AssetId::Native => (Some(NATIVE_DECIMALS), Source::Protocol),
            AssetId::Erc20(token) => match self.answers.get(&token) {
                Some(Some(digits)) => (Some(*digits), Source::Fetched),
                _ => (None, Source::Unknown),
            },
        }
    }

    /// The decimal count when one is known.
    pub fn scaled(&self, asset: AssetId) -> Option<u8> {
        self.of(asset).0
    }

    /// Why an asset was left unscaled, in the order it happened.
    pub fn reasons(&self) -> &[String] {
        &self.reasons
    }

    /// True when no token was asked — the state a report is in when the caller declined
    /// the fetch, which must not be printed as though a node had refused.
    pub fn is_empty(&self) -> bool {
        self.answers.is_empty()
    }

    /// A deliberate non-fetch, carrying the reason that will be printed.
    pub fn unscaled(reason: impl Into<String>) -> Self {
        Decimals {
            answers: BTreeMap::new(),
            reasons: vec![reason.into()],
        }
    }

    /// How many of `assets` will render as base units only.
    pub fn unscaled_count(&self, assets: &[AssetId]) -> usize {
        assets.iter().filter(|a| self.scaled(**a).is_none()).count()
    }
}

/// A checksummed address is a legal JSON object key, but an `Address` is not: a derived
/// `Serialize` over a map keyed by one fails at *runtime*, the same trap that makes
/// `Ledger` write its own. So the key is converted to a string here, and the order is
/// the `BTreeMap`'s — sorted by address bytes, so two runs of one incident agree.
impl Serialize for Decimals {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        let mut map = s.serialize_map(Some(self.answers.len()))?;
        for (token, digits) in &self.answers {
            map.serialize_entry(&token.to_checksum(), digits)?;
        }
        map.end()
    }
}

/// Ask every ERC-20 in `assets` for its decimals at `tag`.
///
/// A `None` tag means the pipeline has no block to ask at — the endpoint returned no
/// transaction — and that is answered by fetching nothing, rather than by falling back to
/// `latest` and hoping the answer still applies.
pub fn fetch(rpc: &dyn Rpc, assets: &[AssetId], tag: Option<&str>) -> Decimals {
    let mut out = Decimals::default();
    let Some(tag) = tag else {
        out.reasons.push(
            "the endpoint returned no transaction, so there is no block to read token metadata at"
                .into(),
        );
        return out;
    };

    for asset in assets {
        let AssetId::Erc20(token) = *asset else {
            continue;
        };
        if out.answers.contains_key(&token) {
            continue;
        }
        match ask(rpc, token, tag) {
            Ok(digits) => {
                out.answers.insert(token, Some(digits));
            }
            Err(why) => {
                out.answers.insert(token, None);
                out.reasons.push(format!("{}: {why}", token.to_checksum()));
            }
        }
    }
    out
}

fn ask(rpc: &dyn Rpc, token: Address, tag: &str) -> std::result::Result<u8, String> {
    let params = [
        serde_json::json!({ "to": token.to_hex(), "data": DECIMALS_CALL }),
        serde_json::json!(tag),
    ];
    let reply = rpc.request("eth_call", &params).map_err(|e| quotable(&e))?;
    decode(&reply)
}

/// The half of a provider failure that is safe to print in a report.
///
/// A transport error's text can quote the request URL, and this string is printed rather
/// than sent to stderr, where the CLI's redactor would have caught it. So the number that
/// identifies the failure survives and the sentence does not: `-32000` is enough for an
/// analyst to know which call went wrong, and it cannot carry a key.
fn quotable(e: &Error) -> String {
    match e {
        Error::RpcError { code, .. } => format!("JSON-RPC error {code}"),
        Error::Http { status } => format!("HTTP {status}"),
        _ => "the call could not be completed".into(),
    }
}

/// Decode `eth_call`'s return data as a decimal count.
///
/// `decimals()` is a `uint8` in the interface but a `uint256` on the wire, so a padded
/// 32-byte word and a bare `0x12` both mean 18. `0x0100` means 256, which is not a
/// decimal count and is not truncated into one; `0x` means the call returned nothing at
/// all, which is also what a reverting view call answers. None of those become zero.
fn decode(v: &serde_json::Value) -> std::result::Result<u8, String> {
    let text = v
        .as_str()
        .ok_or_else(|| "the endpoint did not answer with a hex string".to_string())?;
    let body = text.strip_prefix("0x").unwrap_or(text);
    if body.is_empty() {
        return Err("returned no data (a view call that reverts also answers 0x)".into());
    }
    if body.len() % 2 == 1 {
        return Err(format!("odd-length hex return data: {text}"));
    }
    let bytes = hex::decode(body).map_err(|_| format!("return data is not hex: {text}"))?;
    let (last, leading) = bytes
        .split_last()
        .ok_or_else(|| "empty return data".to_string())?;
    if leading.iter().any(|b| *b != 0) {
        return Err(format!(
            "{text} is wider than one byte, which is not a decimal count"
        ));
    }
    Ok(*last)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Result;
    use serde_json::{Value, json};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    enum Reply {
        Hex(String),
        Number(Value),
        /// A transport failure whose text quotes the endpoint, to prove it is dropped.
        RpcText(String),
        /// A JSON-RPC error whose message carries a credential, to prove only the code
        /// survives into a printed reason.
        Code(i64, String),
    }

    struct Fake {
        reply: Reply,
        calls: AtomicUsize,
        asked: Mutex<Vec<String>>,
    }

    impl Fake {
        fn answering(hex: &str) -> Self {
            Self::with(Reply::Hex(hex.into()))
        }
        fn failing(r: Reply) -> Self {
            Self::with(r)
        }
        fn with(reply: Reply) -> Self {
            Fake {
                reply,
                calls: AtomicUsize::new(0),
                asked: Mutex::new(Vec::new()),
            }
        }
        fn count(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
        fn asked(&self) -> Vec<String> {
            self.asked.lock().unwrap().clone()
        }
    }

    impl Rpc for Fake {
        fn request(&self, method: &str, params: &[Value]) -> Result<Value> {
            assert_eq!(method, "eth_call", "decimals must be the only thing asked");
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.asked.lock().unwrap().push(
                params
                    .iter()
                    .map(Value::to_string)
                    .collect::<Vec<_>>()
                    .join("|"),
            );
            match &self.reply {
                Reply::Hex(h) => Ok(json!(h)),
                Reply::Number(v) => Ok(v.clone()),
                Reply::RpcText(t) => Err(Error::Rpc(t.clone())),
                Reply::Code(c, m) => Err(Error::RpcError {
                    code: *c,
                    message: m.clone(),
                }),
            }
        }

        fn describe(&self) -> String {
            "fake".into()
        }
    }

    fn token(n: u8) -> AssetId {
        let mut b = [0u8; 20];
        b[19] = n;
        AssetId::Erc20(Address(b))
    }

    fn pad(hex64: &str) -> String {
        format!("0x{hex64}")
    }

    #[test]
    fn a_padded_word_and_a_bare_byte_both_answer_eighteen() {
        let padded = pad("0000000000000000000000000000000000000000000000000000000000000012");
        let f = Fake::answering(&padded);
        let d = fetch(&f, &[token(1)], Some("0x14bcb7f"));
        assert_eq!(
            d.of(token(1)),
            (Some(18), Source::Fetched),
            "{:?}",
            d.reasons
        );

        let f = Fake::answering("0x12");
        let d = fetch(&f, &[token(1)], Some("0x1"));
        assert_eq!(d.scaled(token(1)), Some(18), "unpadded is the same answer");
    }

    #[test]
    fn zero_is_an_answer_and_not_a_missing_one() {
        // A token with no fractional unit answers 0. Treating that as unknown would
        // leave it base units — which for such a token *is* the human number.
        let f = Fake::answering("0x00");
        let d = fetch(&f, &[token(7)], Some("0x1"));
        assert_eq!(
            d.of(token(7)),
            (Some(0), Source::Fetched),
            "{:?}",
            d.reasons
        );
        assert_eq!(d.unscaled_count(&[token(7)]), 0);
        assert!(d.reasons().is_empty(), "{:?}", d.reasons());
    }

    #[test]
    fn a_reverting_view_call_is_unknown_and_says_why() {
        let f = Fake::answering("0x");
        let d = fetch(&f, &[token(1)], Some("0x1"));
        assert_eq!(d.scaled(token(1)), None);
        assert!(
            d.reasons()[0].contains("reverts"),
            "0x is also what a revert answers, and the reader needs to know that: {:?}",
            d.reasons()
        );
    }

    #[test]
    fn a_count_wider_than_one_byte_is_refused_not_truncated() {
        let f = Fake::answering("0x0100");
        let d = fetch(&f, &[token(1)], Some("0x1"));
        assert_eq!(d.scaled(token(1)), None);
        assert!(
            d.reasons()[0].contains("wider than one byte"),
            "{:?}",
            d.reasons()
        );
    }

    #[test]
    fn malformed_answers_are_refused_rather_than_guessed() {
        let f = Fake::answering("0x1");
        let d = fetch(&f, &[token(1)], Some("0x1"));
        assert!(d.reasons()[0].contains("odd-length"), "{:?}", d.reasons());

        let f = Fake::failing(Reply::Number(json!(18)));
        let d = fetch(&f, &[token(1)], Some("0x1"));
        assert_eq!(d.scaled(token(1)), None);
        assert!(
            d.reasons()[0].contains("hex string"),
            "a bare number is not the shape eth_call answers with: {:?}",
            d.reasons()
        );
    }

    #[test]
    fn provider_error_text_never_reaches_the_report() {
        // `reasons` are printed in a report, where the CLI's stderr redactor is not
        // waiting to catch a URL.
        let f = Fake::failing(Reply::RpcText(
            "dial https://eth.example/v2/targetkey1234567890 refused".into(),
        ));
        let d = fetch(&f, &[token(1)], Some("0x1"));
        let reason = &d.reasons()[0];
        assert!(
            !reason.contains("targetkey1234567890"),
            "the transport sentence is dropped entirely: {reason}"
        );
        assert!(reason.contains("could not be completed"), "{reason}");

        let f = Fake::failing(Reply::Code(
            -32000,
            "no archive state at https://eth.example/v2/baselinekey0987654321".into(),
        ));
        let d = fetch(&f, &[token(1)], Some("0x1"));
        let reason = &d.reasons()[0];
        assert!(reason.contains("-32000"), "the code is kept: {reason}");
        assert!(
            !reason.contains("baselinekey0987654321"),
            "the message is not: {reason}"
        );
    }

    #[test]
    fn native_eth_is_never_asked_and_is_18_by_protocol() {
        let f = Fake::answering("0x12");
        let d = fetch(&f, &[AssetId::Native], Some("0x1"));
        assert_eq!(f.count(), 0, "no token to ask");
        assert_eq!(d.of(AssetId::Native), (Some(18), Source::Protocol));
    }

    #[test]
    fn one_call_per_token_even_when_an_asset_repeats() {
        let f = Fake::answering("0x12");
        let assets = [token(1), token(1), token(2)];
        let d = fetch(&f, &assets, Some("0x1"));
        assert_eq!(
            f.count(),
            2,
            "one per distinct token, no batching, no repeats"
        );
        assert_eq!(d.scaled(token(1)), Some(18));
        assert_eq!(d.scaled(token(2)), Some(18));
    }

    #[test]
    fn the_request_carries_the_selector_and_the_transactions_own_block() {
        // `latest` here would read metadata from a state the money did not see.
        let f = Fake::answering("0x12");
        fetch(&f, &[token(9)], Some("0x14bcb7f"));
        let asked = f.asked();
        assert!(asked[0].contains("313ce567"), "{asked:?}");
        assert!(asked[0].contains("0x14bcb7f"), "{asked:?}");
    }

    #[test]
    fn with_no_block_to_ask_at_nothing_is_fetched() {
        let f = Fake::answering("0x12");
        let d = fetch(&f, &[token(1)], None);
        assert_eq!(
            f.count(),
            0,
            "there is no tag to ask at, so do not guess one"
        );
        assert!(
            d.reasons()[0].contains("no transaction"),
            "{:?}",
            d.reasons()
        );
    }

    #[test]
    fn json_keys_are_checksummed_strings_and_unknowns_stay_null() {
        // A derived `Serialize` over a map keyed by `Address` fails at runtime; this
        // asserts the hand-written one actually produces text.
        let f = Fake::answering("0x06");
        let mut d = fetch(&f, &[token(6)], Some("0x1"));
        let g = Fake::answering("0x");
        d.answers
            .extend(fetch(&g, &[token(7)], Some("0x1")).answers);
        let v = serde_json::to_value(&d).expect("an address key must serialize");
        let obj = v.as_object().expect("an object");
        assert_eq!(obj.len(), 2, "{v}");
        let six = obj
            .iter()
            .find(|(k, _)| k.ends_with('6'))
            .expect("both tokens present");
        assert_eq!(*six.1, json!(6), "{v}");
        let seven = obj
            .iter()
            .find(|(k, _)| k.ends_with('7'))
            .expect("both present");
        assert_eq!(*seven.1, json!(null), "unknown is null, not 0: {v}");
        assert!(
            six.0.starts_with("0x") && six.0.len() == 42,
            "checksummed: {}",
            six.0
        );
    }

    #[test]
    fn a_declined_fetch_is_not_reported_as_a_failed_one() {
        let d = Decimals::unscaled("--no-decimals was given");
        assert!(d.is_empty());
        assert_eq!(d.reasons(), ["--no-decimals was given"]);
        assert_eq!(
            d.unscaled_count(&[token(1), AssetId::Native]),
            1,
            "native is known by protocol"
        );
    }
}
