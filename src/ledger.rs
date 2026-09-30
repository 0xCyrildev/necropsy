//! Per-asset value ledger.
//!
//! Four rules separate this from the version it replaces:
//!
//!   1. **Nothing is summed across assets.** A 6-decimal stablecoin and an
//!      18-decimal token are different monies; netting them into one number makes
//!      the ranking track decimal places rather than value, and lets a drain in one
//!      token cancel an unrelated inflow in another.
//!   2. **Amounts are 256-bit and netting is a comparison.** The previous code did
//!      `net -= amount as i128`, which for an inflow above `i128::MAX` wraps
//!      negative, turns the subtraction into an addition, and then hides the row
//!      behind a `net > 0` filter — the largest inflow in the transaction vanishes
//!      from the answer to the tool's only question.
//!   3. **Value that did not commit is not value.** A frame inside a subtree that
//!      reverted moved nothing, and a transaction that reverted moved nothing.
//!      Receipt logs already exclude reverted emissions; native ETH flows come
//!      from frames, which do not, so they are filtered here.
//!   4. **Ordering is deterministic.** Ties break on address bytes. A HashMap
//!      iterates in a different order every process run, which makes two
//!      investigations of the same incident look like two different results.

use crate::collect::txdata::TxStatus;
use crate::model::{Address, Amount, AssetId, Net, TokenEvent, Trace};
use serde::{Serialize, Serializer};
use std::collections::{BTreeMap, HashSet};

pub type FlowKey = (AssetId, Address);

#[derive(Debug, Clone, Default)]
pub struct Ledger {
    /// (asset, address) → (inflow, outflow) in that asset's base units.
    /// Insertion-ordered by key so a report reads the same twice.
    flows: BTreeMap<FlowKey, (Amount, Amount)>,
    /// Additions that could not be represented in 256 bits. Should never happen
    /// on real data; when it does, the totals are wrong and the report must say so.
    pub overflow: Vec<String>,
    /// Native ETH frames dropped because something on their path to the root
    /// reverted.
    pub skipped_undone_frames: usize,
    /// True when the transaction itself reverted, so every figure here is an
    /// *attempt*, not a movement.
    pub attempted_only: bool,
    /// Fungible events the ledger could not apply, counted rather than dropped.
    pub unapplied_events: usize,
}

impl Ledger {
    fn add_to(&mut self, key: FlowKey, side: Side, amount: Amount) {
        if amount.is_zero() {
            return;
        }
        let entry = self
            .flows
            .entry(key)
            .or_insert((Amount::ZERO, Amount::ZERO));
        let (target, label) = match side {
            Side::In => (&mut entry.0, "inflow"),
            Side::Out => (&mut entry.1, "outflow"),
        };
        match target.checked_add(amount) {
            Some(sum) => *target = sum,
            None => self.overflow.push(format!(
                "{label} of {amount} for {key:?} would exceed 2^256-1 and was not counted"
            )),
        }
    }

    pub fn credit(&mut self, asset: AssetId, addr: Address, amount: Amount) {
        self.add_to((asset, addr), Side::In, amount);
    }

    pub fn debit(&mut self, asset: AssetId, addr: Address, amount: Amount) {
        self.add_to((asset, addr), Side::Out, amount);
    }

    pub fn net(&self, asset: AssetId, addr: Address) -> Net {
        match self.flows.get(&(asset, addr)) {
            None => Net::Zero,
            Some((i, o)) => Net::net_of(*i, *o),
        }
    }

    pub fn assets(&self) -> Vec<AssetId> {
        let mut seen: Vec<AssetId> = self.flows.keys().map(|(a, _)| *a).collect();
        seen.sort();
        seen.dedup();
        seen
    }

    pub fn rows(&self) -> impl Iterator<Item = (&FlowKey, &(Amount, Amount))> {
        self.flows.iter()
    }

    /// The two sides a net was computed from, so a report can show *why* an
    /// address ranks the way it does instead of asserting a single number.
    pub fn in_out(&self, asset: AssetId, addr: Address) -> (Amount, Amount) {
        self.flows
            .get(&(asset, addr))
            .copied()
            .unwrap_or((Amount::ZERO, Amount::ZERO))
    }

    /// Every address with something to receive in `asset`, largest first, ties on
    /// address bytes so two runs of the same trace print the same table.
    pub fn receivers(&self, asset: AssetId) -> Vec<(Address, Net)> {
        let mut v: Vec<(Address, Net)> = self
            .flows
            .iter()
            .filter(|((a, addr), _)| *a == asset && !addr.is_zero())
            .map(|((_, addr), (i, o))| (*addr, Net::net_of(*i, *o)))
            .filter(|(_, net)| net.is_receiver())
            .collect();
        v.sort_by(|a, b| b.1.magnitude().cmp(&a.1.magnitude()).then(a.0.cmp(&b.0)));
        v
    }

    /// Net across all assets — only ever as a count of movements, never as a
    /// single number, because there is no such thing.
    pub fn total_asset_rows(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    /// Addresses that ended the transaction holding more of something. Used by the
    /// report and the analysis layer; a drain is usually a short list.
    pub fn distinct_receivers(&self) -> Vec<Address> {
        let mut set: HashSet<Address> = HashSet::new();
        for ((asset, addr), (i, o)) in self.flows.iter() {
            if *asset != AssetId::Native && i > o && !addr.is_zero() {
                set.insert(*addr);
            }
        }
        let mut v: Vec<Address> = set.into_iter().collect();
        v.sort();
        v
    }
}

enum Side {
    In,
    Out,
}

/// A row as machine-readable output shows it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LedgerRow {
    pub asset: AssetId,
    pub address: Address,
    pub inflow: Amount,
    pub outflow: Amount,
    pub net: Net,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LedgerView<'a> {
    rows: Vec<LedgerRow>,
    overflow: &'a [String],
    skipped_undone_frames: &'a usize,
    attempted_only: &'a bool,
    unapplied_events: &'a usize,
}

/// Written by hand, because the internal key is a `(AssetId, Address)` tuple and a
/// tuple cannot be a JSON object key at all: deriving `Serialize` over `flows`
/// made JSON output die with *"key must be a string"* on any ledger holding a
/// single row. Rows are an array ordered by asset then address, so two runs over
/// one transaction produce byte-identical JSON.
impl Serialize for Ledger {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        LedgerView {
            rows: self
                .rows()
                .map(|(k, (i, o))| LedgerRow {
                    asset: k.0,
                    address: k.1,
                    inflow: *i,
                    outflow: *o,
                    net: Net::net_of(*i, *o),
                })
                .collect(),
            overflow: &self.overflow,
            skipped_undone_frames: &self.skipped_undone_frames,
            attempted_only: &self.attempted_only,
            unapplied_events: &self.unapplied_events,
        }
        .serialize(s)
    }
}

/// Frames whose value never committed: their own status, or any ancestor's, is a
/// revert or failure. Single pass, because parents always precede children in the
/// arena.
fn undone_frames(trace: &Trace) -> HashSet<u32> {
    let mut undone = HashSet::new();
    for f in &trace.frames {
        let bad = f.status.reverted();
        let parent_bad = f.parent.map(|p| undone.contains(&p)).unwrap_or(false);
        if bad || parent_bad {
            undone.insert(f.id);
        }
    }
    undone
}

/// Build the ledger from classified events plus native ETH from the trace.
///
/// WETH is handled as the two-sided event it is, but *only* on the token side:
/// a `Deposit` credits the owner with WETH and does not also debit their ETH,
/// because that ETH leg is already visible as the frame value that carried ETH
/// into the WETH contract. Counting both would make one wrap look like two
/// movements and inflate the ranking.
pub fn build(events: &[TokenEvent], trace: &Trace, tx_status: Option<TxStatus>) -> Ledger {
    let mut l = Ledger::default();

    let root_reverted = trace
        .root
        .and_then(|r| trace.frame(r))
        .map(|f| f.status.reverted())
        .unwrap_or(false);
    l.attempted_only = root_reverted || matches!(tx_status, Some(TxStatus::Reverted));

    // Token side, from receipt logs: already revert-filtered by the chain itself.
    for e in events {
        match e {
            TokenEvent::Erc20Transfer {
                token,
                from,
                to,
                amount,
                ..
            } => {
                let asset = AssetId::Erc20(*token);
                l.debit(asset, *from, *amount);
                l.credit(asset, *to, *amount);
            }
            TokenEvent::WethDeposit {
                weth,
                owner,
                amount,
                ..
            } => {
                l.credit(AssetId::Erc20(*weth), *owner, *amount);
            }
            TokenEvent::WethWithdrawal {
                weth,
                owner,
                amount,
                ..
            } => {
                l.debit(AssetId::Erc20(*weth), *owner, *amount);
            }
            TokenEvent::Erc721Transfer { .. }
            | TokenEvent::Erc1155Single { .. }
            | TokenEvent::Erc1155Batch { .. } => {
                // Non-fungible: never netted into a fungible ranking. Counted so
                // "the ledger is empty" cannot be read as "nothing moved" when an
                // NFT was in fact taken.
                l.unapplied_events += 1;
            }
            TokenEvent::NonValue { .. } => {}
            TokenEvent::Unclassified { .. } => l.unapplied_events += 1,
        }
    }

    // Native side, from frame values. These are not revert-filtered by anyone, so
    // they are filtered here.
    let undone = undone_frames(trace);
    for f in &trace.frames {
        let Some(value) = f.value else { continue };
        if value.is_zero() {
            continue;
        }
        if f.kind.is_creation() {
            // A creation's `from` is the creator and `to` the new contract; that is
            // a real transfer of ETH to the new address, so it is kept.
        }
        if undone.contains(&f.id) {
            l.skipped_undone_frames += 1;
            continue;
        }
        l.debit(AssetId::Native, f.from, value);
        l.credit(AssetId::Native, f.to.unwrap_or(f.from), value);
    }

    l
}

impl Ledger {
    /// A one-line statement a report can print next to any "no value moved"
    /// conclusion, so absence of findings is never confused with absence of data.
    pub fn coverage_sentence(&self) -> String {
        if self.attempted_only {
            return format!(
                "the transaction reverted, so every figure below is an attempt: no value committed on chain. \
                 {} native frame(s) inside reverted subtrees were excluded.",
                self.skipped_undone_frames
            );
        }
        let mut parts = vec![format!("{} asset row(s)", self.total_asset_rows())];
        if self.unapplied_events > 0 {
            parts.push(format!(
                "{} event(s) not applicable to a fungible ledger",
                self.unapplied_events
            ));
        }
        if self.skipped_undone_frames > 0 {
            parts.push(format!(
                "{} reverted native transfer(s) excluded",
                self.skipped_undone_frames
            ));
        }
        if !self.overflow.is_empty() {
            parts.push(format!(
                "{} addition(s) overflowed 256 bits and are NOT counted",
                self.overflow.len()
            ));
        }
        parts.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        CallKind, Collector, Disposition, Frame, FrameStatus, Provenance, TraceBuilder,
    };
    use ruint::aliases::U256;

    fn addr(n: u8) -> Address {
        let mut b = [0u8; 20];
        b[19] = n;
        Address(b)
    }

    fn token(n: u8) -> Address {
        let mut b = [0u8; 20];
        b[19] = n;
        Address(b)
    }

    fn frame(kind: CallKind, from: Address, to: Address, value: Option<u64>) -> Frame {
        Frame {
            id: 0,
            kind,
            from,
            to: Some(to),
            context: Address::ZERO,
            value: value.map(|v| Amount::new(U256::from(v))),
            gas_used: None,
            selector: None,
            label: None,
            status: FrameStatus::Success,
            return_bytes: None,
            parent: None,
            children: Vec::new(),
            depth: 0,
        }
    }

    fn empty_trace() -> Trace {
        TraceBuilder::new(prov()).finish()
    }

    fn prov() -> Provenance {
        Provenance {
            collector: Collector::CallTracerJson,
            cast_version: None,
            chain_id: None,
            block: None,
        }
    }

    fn t20(token: Address, from: Address, to: Address, raw: &str) -> TokenEvent {
        TokenEvent::Erc20Transfer {
            token,
            from,
            to,
            amount: Amount::from_decimal(raw).unwrap(),
            log_index: 0,
        }
    }

    #[test]
    fn two_tokens_are_never_one_number() {
        // 100 USDC (6 decimals) and 1e-18 of an 18-decimal token. Summed as raw
        // integers, the dust token looks 10^12 times larger than the real money —
        // which is how the previous ranking got its order backwards.
        let usdc = token(0x10);
        let weird = token(0x20);
        let alice = addr(1);
        let bob = addr(2);
        let events = vec![
            t20(usdc, alice, bob, "100000000"), // 100 USDC
            t20(weird, alice, bob, "1"),        // 1 wei of an 18-dec token
        ];
        let l = build(&events, &empty_trace(), Some(TxStatus::Success));
        assert_eq!(l.assets().len(), 2, "two assets, two rows");
        let (usdc, weird) = (AssetId::token(usdc), AssetId::token(weird));
        assert_eq!(
            l.net(usdc, bob).magnitude().to_decimal_string(),
            "100000000"
        );
        assert_eq!(l.net(weird, bob).magnitude().to_decimal_string(), "1");
        assert!(l.receivers(usdc)[0].1.magnitude() > l.receivers(weird)[0].1.magnitude());
        assert_eq!(l.receivers(AssetId::Native).len(), 0, "no ETH moved");
    }

    #[test]
    fn an_inflow_above_i128_max_still_ranks_as_a_receiver() {
        // The exact regression: 2^126 was cast to i128 (negative), `net -= amount`
        // added, and the `net > 0` filter then dropped the row entirely.
        let tok = token(0x30);
        let attacker = addr(0xEE);
        let asset = AssetId::Erc20(tok);
        // 2^126, above i128::MAX and far above u64.
        let huge = Amount::from_decimal("85070591730234615865843651857942052864").unwrap();
        let mut l = Ledger::default();
        l.credit(asset, attacker, huge);
        let net = l.net(asset, attacker);
        assert!(
            net.is_receiver(),
            "a sole inflow of 2^126 must survive netting, not vanish"
        );
        assert_eq!(net.magnitude(), huge);
        assert_eq!(
            l.receivers(asset).len(),
            1,
            "and must still appear in the sink table the report prints"
        );
    }

    #[test]
    fn pass_through_intermediaries_cancel_and_the_sink_stays_visible() {
        let tok = token(0x31);
        let (a, b, c) = (addr(1), addr(2), addr(3));
        let events = vec![t20(tok, a, b, "500"), t20(tok, b, c, "500")];
        let l = build(&events, &empty_trace(), Some(TxStatus::Success));
        let tok = AssetId::token(tok);
        assert_eq!(
            l.net(tok, a),
            Net::Negative(Amount::from_decimal("500").unwrap())
        );
        assert_eq!(
            l.net(tok, b),
            Net::Zero,
            "the router nets to zero, which is the point"
        );
        assert_eq!(
            l.net(tok, c),
            Net::Positive(Amount::from_decimal("500").unwrap())
        );
        let sinks = l.receivers(tok);
        assert_eq!(sinks.len(), 1);
        assert_eq!(sinks[0].0, c);
    }

    #[test]
    fn native_eth_flows_from_frame_values() {
        let (a, b) = (addr(0xA), addr(0xB));
        let mut tb = TraceBuilder::new(prov());
        let root = tb.push(None, frame(CallKind::Call, Address::ZERO, a, Some(0)));
        tb.push(
            Some(root),
            frame(CallKind::Call, a, b, Some(3_000_000_000_000_000_000)),
        );
        let trace = tb.finish();
        let l = build(&[], &trace, Some(TxStatus::Success));
        assert_eq!(
            l.net(AssetId::Native, b),
            Net::Positive(Amount::new(U256::from(3_000_000_000_000_000_000u64))),
            "an ETH-only drain must produce a non-empty sink table"
        );
        assert_eq!(l.receivers(AssetId::Native).len(), 1);
    }

    #[test]
    fn value_inside_a_reverted_subtree_is_not_moved_value() {
        let (a, victim, attacker) = (addr(1), addr(2), addr(3));
        let mut tb = TraceBuilder::new(prov());
        let root = tb.push(None, frame(CallKind::Call, Address::ZERO, a, None));
        tb.push(Some(root), frame(CallKind::Call, a, victim, Some(5)));
        let reverted = tb.push(Some(root), {
            let mut f = frame(CallKind::Call, a, attacker, Some(9));
            f.status = FrameStatus::Reverted { reason: None };
            f
        });
        // A grandchild of the reverted frame must also be excluded.
        tb.push(
            Some(reverted),
            frame(CallKind::Call, attacker, addr(4), Some(7)),
        );
        let trace = tb.finish();

        let l = build(&[], &trace, Some(TxStatus::Success));
        assert_eq!(
            l.net(AssetId::Native, victim)
                .magnitude()
                .to_decimal_string(),
            "5"
        );
        assert_eq!(
            l.net(AssetId::Native, attacker),
            Net::Zero,
            "a reverted call moved nothing"
        );
        assert_eq!(
            l.net(AssetId::Native, addr(4)),
            Net::Zero,
            "nor did anything inside it"
        );
        assert_eq!(l.skipped_undone_frames, 2);
        assert!(!l.attempted_only, "the transaction itself committed");
    }

    #[test]
    fn a_reverted_transaction_is_all_attempts() {
        let mut tb = TraceBuilder::new(prov());
        let mut root = frame(CallKind::Call, Address::ZERO, addr(1), Some(10));
        root.status = FrameStatus::Reverted {
            reason: Some("x".into()),
        };
        tb.push(None, root);
        let trace = tb.finish();
        let l = build(&[], &trace, Some(TxStatus::Reverted));
        assert!(l.attempted_only);
        assert!(
            l.coverage_sentence().contains("attempt"),
            "{}",
            l.coverage_sentence()
        );
        assert_eq!(l.skipped_undone_frames, 1);
    }

    #[test]
    fn weth_deposit_credits_the_token_without_double_counting_the_eth() {
        let weth = token(0xC0);
        let owner = addr(7);
        let events = vec![TokenEvent::WethDeposit {
            weth,
            owner,
            amount: Amount::from_decimal("1000").unwrap(),
            log_index: 0,
        }];
        let l = build(&events, &empty_trace(), Some(TxStatus::Success));
        assert_eq!(
            l.net(AssetId::Erc20(weth), owner)
                .magnitude()
                .to_decimal_string(),
            "1000"
        );
        assert_eq!(
            l.net(AssetId::Native, owner),
            Net::Zero,
            "the ETH leg is the frame value, not a second entry"
        );
    }

    #[test]
    fn non_fungible_and_unclassified_events_are_counted_not_silently_dropped() {
        let events = vec![
            TokenEvent::Erc721Transfer {
                token: token(1),
                from: addr(1),
                to: addr(2),
                token_id: Amount::from_decimal("7").unwrap(),
                log_index: 0,
            },
            TokenEvent::Unclassified {
                address: token(2),
                topic0: None,
                n_topics: 0,
                data_len: 0,
                log_index: 1,
                why: "no topic0",
            },
        ];
        let l = build(&events, &empty_trace(), Some(TxStatus::Success));
        assert!(l.is_empty(), "nothing fungible moved");
        assert_eq!(l.unapplied_events, 2);
        assert!(l.coverage_sentence().contains("not applicable"));
    }

    #[test]
    fn ties_are_ordered_deterministically_by_address_bytes() {
        let tok = token(0x32);
        let (x, y) = (addr(0x0F), addr(0x0E));
        let events = vec![t20(tok, addr(1), x, "10"), t20(tok, addr(1), y, "10")];
        let l = build(&events, &empty_trace(), Some(TxStatus::Success));
        let tok = AssetId::token(tok);
        let a = l.receivers(tok);
        let b = l.receivers(tok);
        assert_eq!(
            a, b,
            "same input, same order — a report must be reproducible"
        );
        assert_eq!(a[0].0, y, "lower address bytes first among equals");
    }

    #[test]
    fn the_zero_address_is_never_reported_as_a_sink() {
        let tok = token(0x33);
        let events = vec![
            t20(tok, Address::ZERO, addr(9), "1000"),
            t20(tok, addr(9), Address::ZERO, "1"),
        ];
        let l = build(&events, &empty_trace(), Some(TxStatus::Success));
        let tok = AssetId::token(tok);
        assert!(
            !l.receivers(tok).iter().any(|(a, _)| a.is_zero()),
            "mints and burns are not destinations"
        );
        assert_eq!(l.net(tok, addr(9)).magnitude().to_decimal_string(), "999");
    }

    #[test]
    fn a_256_bit_overflow_is_reported_not_wrapped() {
        let tok = token(0x34);
        let who = addr(1);
        let mut l = Ledger::default();
        l.credit(AssetId::Erc20(tok), who, Amount::new(U256::MAX));
        l.credit(AssetId::Erc20(tok), who, Amount::new(U256::from(1u64)));
        assert_eq!(
            l.overflow.len(),
            1,
            "refusing to wrap is the whole point of checked math"
        );
        assert!(l.coverage_sentence().contains("overflowed"));
        assert_eq!(
            l.net(AssetId::Erc20(tok), who).magnitude(),
            Amount::new(U256::MAX)
        );
    }

    #[test]
    fn self_transfers_do_not_fabricate_movement() {
        let tok = token(0x35);
        let me = addr(5);
        let l = build(
            &[t20(tok, me, me, "700")],
            &empty_trace(),
            Some(TxStatus::Success),
        );
        assert_eq!(l.net(AssetId::token(tok), me), Net::Zero);
    }

    #[test]
    fn conservation_of_line_dispositions_is_untouched_by_the_ledger() {
        // Guard against a refactor that starts reclassifying lines in flow.
        let mut tb = TraceBuilder::new(prov());
        tb.line(Disposition::Trailer);
        let trace = tb.finish();
        let l = build(&[], &trace, None);
        assert_eq!(l.coverage_sentence(), "0 asset row(s)");
    }

    #[test]
    fn a_populated_ledger_serializes_to_json_at_all() {
        // The internal key is a `(asset, address)` tuple, and a tuple cannot be a
        // JSON object key: a derived `Serialize` over `flows` failed at runtime on
        // the very first row, so every `--json` run died instead of reporting.
        let mut l = Ledger::default();
        l.credit(AssetId::Native, addr(1), Amount::new(U256::from(7u64)));
        let json = serde_json::to_string(&l).expect("a one-row ledger must serialize");
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["rows"][0]["asset"], "native");
        assert_eq!(
            v["rows"][0]["inflow"], "7",
            "amounts must stay strings, not doubles"
        );
        assert_eq!(v["rows"][0]["net"], "+7");
        assert_eq!(v["attemptedOnly"], false);
        assert!(json.contains("\"overflow\""), "{json}");
    }

    #[test]
    fn json_rows_are_ordered_so_two_runs_of_one_transaction_are_identical() {
        let tok = token(0x40);
        let mut l = Ledger::default();
        // Inserted high address first on purpose: the output order must come from
        // the key, not from the order the chain happened to emit logs.
        l.credit(
            AssetId::Erc20(tok),
            addr(0xFF),
            Amount::new(U256::from(1u64)),
        );
        l.credit(
            AssetId::Erc20(tok),
            addr(0x02),
            Amount::new(U256::from(1u64)),
        );
        l.credit(AssetId::Native, addr(0x03), Amount::new(U256::from(1u64)));
        let a = serde_json::to_string(&l).unwrap();
        let b = serde_json::to_string(&l).unwrap();
        assert_eq!(a, b, "one ledger, two serializations, identical bytes");
        let v: serde_json::Value = serde_json::from_str(&a).unwrap();
        let rows: Vec<(String, String)> = v["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| {
                (
                    r["asset"].as_str().unwrap().to_string(),
                    r["address"].as_str().unwrap().to_string(),
                )
            })
            .collect();
        assert_eq!(
            rows,
            vec![
                ("native".to_string(), addr(3).to_hex()),
                (addr(0x40).to_hex(), addr(2).to_hex()),
                (addr(0x40).to_hex(), addr(0xFF).to_hex()),
            ],
            "ordered by (asset, address bytes), never by the order the chain emitted"
        );
    }
}
