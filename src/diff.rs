//! Structural comparison of two call trees — "what changed about how this
//! transaction ran", given a benign reference execution of the same flow.
//!
//! This is deliberately **structural, not semantic**. It compares the shape of the
//! two traces: which position holds which call, to whom, with which selector. It does
//! not compare amounts, storage, or return data, and it never says a difference is a
//! vulnerability. A flash-loan reuse, a different route through the same pool, or a
//! proxy that upgraded between the two blocks all produce a real diff that means
//! nothing; a reviewer decides.
//!
//! Two limits are stated in the output rather than hidden here:
//!
//!   * **Positions shift.** Paths are child indices, so one extra call early in the
//!     tree moves every frame after it. A `changed` row means *the frame at this
//!     position differs*, not *this call was modified*.
//!   * **Orphans cannot be matched.** An orphan's path is `orphan/<arena id>`, which is
//!     an artifact of one collection, not a location. They are counted and named, never
//!     paired.

use crate::model::{Address, CallKind, Frame, Selector, Trace};
use serde::{Deserialize, Serialize};

/// What one position holds, in a form two traces can be compared on.
///
/// `Frame::diff_signature` is the authority on which fields count; it excludes `label`
/// and `value` because a label resolved by one collector and not the other, or an ETH
/// value rendered by one and omitted by the other, would report every node as changed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Signature {
    pub kind: String,
    pub from: Address,
    pub to: Option<Address>,
    pub selector: Option<Selector>,
}

impl Signature {
    fn of(f: &Frame) -> Signature {
        let (kind, from, to, selector) = f.diff_signature();
        Signature {
            kind: kind_text(&kind),
            from,
            to,
            selector,
        }
    }
}

/// `CallKind::Other` keeps the unrecognised text precisely so it can be shown;
/// collapsing it to `"other"` would make an `AUTHCALL` indistinguishable from a
/// different unmodelled kind.
fn kind_text(k: &CallKind) -> String {
    match k {
        CallKind::Other(t) => format!("other:{t}"),
        other => other.tag().to_string(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ChangeKind {
    Added,
    Removed,
    Changed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Change {
    pub path: String,
    pub change: ChangeKind,
    /// `None` when the position exists only in the target.
    pub baseline: Option<Signature>,
    /// `None` when the position exists only in the baseline.
    pub target: Option<Signature>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Diff {
    pub baseline_frames: usize,
    pub target_frames: usize,
    pub baseline_orphans: usize,
    pub target_orphans: usize,
    pub changes: Vec<Change>,
}

impl Diff {
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    pub fn added(&self) -> usize {
        self.count(ChangeKind::Added)
    }
    pub fn removed(&self) -> usize {
        self.count(ChangeKind::Removed)
    }
    pub fn changed(&self) -> usize {
        self.count(ChangeKind::Changed)
    }

    fn count(&self, k: ChangeKind) -> usize {
        self.changes.iter().filter(|c| c.change == k).count()
    }

    /// The honest one-liner: a non-empty diff is a question, not a verdict, and the
    /// counts are meaningless next to a shifted position.
    pub fn summary(&self) -> String {
        if self.is_empty() {
            return format!(
                "structurally identical to the baseline ({} frame(s) matched)",
                self.target_frames
            );
        }
        let mut s = format!(
            "{} difference(s): {} added, {} removed, {} changed — positions are child indices, so one inserted call shifts every later path; a `changed` row means the frame at that position differs, not that a call was modified",
            self.changes.len(),
            self.added(),
            self.removed(),
            self.changed()
        );
        if self.baseline_orphans > 0 || self.target_orphans > 0 {
            s.push_str(&format!(
                "; {} orphan(s) in baseline and {} in target could not be matched at all",
                self.baseline_orphans, self.target_orphans
            ));
        }
        s
    }
}

/// Compare `baseline` against `target`. Both sides are walked in execution order so a
/// frame's path reflects its position among siblings.
pub fn diff(baseline: &Trace, target: &Trace) -> Diff {
    let base = positions(baseline);
    let targ = positions(target);

    let mut keys: Vec<String> = base.keys().chain(targ.keys()).cloned().collect();
    keys.sort_by(|a, b| compare_paths(a, b));
    keys.dedup();

    let mut changes = Vec::new();
    for path in keys {
        match (base.get(&path), targ.get(&path)) {
            (Some(b), Some(t)) if b == t => {}
            (Some(b), Some(t)) => changes.push(Change {
                path,
                change: ChangeKind::Changed,
                baseline: Some(b.clone()),
                target: Some(t.clone()),
            }),
            (None, Some(t)) => changes.push(Change {
                path,
                change: ChangeKind::Added,
                baseline: None,
                target: Some(t.clone()),
            }),
            (Some(b), None) => changes.push(Change {
                path,
                change: ChangeKind::Removed,
                baseline: Some(b.clone()),
                target: None,
            }),
            (None, None) => unreachable!("a key came from one of the two maps"),
        }
    }

    Diff {
        baseline_frames: baseline.len(),
        target_frames: target.len(),
        baseline_orphans: baseline.orphans.len(),
        target_orphans: target.orphans.len(),
        changes,
    }
}

fn positions(t: &Trace) -> std::collections::BTreeMap<String, Signature> {
    let mut m = std::collections::BTreeMap::new();
    for id in t.preorder() {
        if let Some(f) = t.frame(id) {
            m.insert(t.path(id), Signature::of(f));
        }
    }
    m
}

/// Compare two paths as sequences, numeric segments by value.
///
/// Sorting paths as plain strings puts `root/10` before `root/2`, which makes a report
/// read like a shuffled deck. Determinism alone would be enough; legible ordering is
/// cheap once determinism is being computed anyway.
fn compare_paths(a: &str, b: &str) -> std::cmp::Ordering {
    let mut ai = a.split('/');
    let mut bi = b.split('/');
    loop {
        match (ai.next(), bi.next()) {
            (None, None) => return std::cmp::Ordering::Equal,
            (None, Some(_)) => return std::cmp::Ordering::Less,
            (Some(_), None) => return std::cmp::Ordering::Greater,
            (Some(x), Some(y)) => {
                let ord = match (x.parse::<u32>(), y.parse::<u32>()) {
                    (Ok(nx), Ok(ny)) => nx.cmp(&ny),
                    _ => x.cmp(y),
                };
                if ord != std::cmp::Ordering::Equal {
                    return ord;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Amount, Collector, FrameStatus, Provenance, TraceBuilder};
    use ruint::aliases::U256;

    fn addr(n: u8) -> Address {
        let mut b = [0u8; 20];
        b[19] = n;
        Address(b)
    }

    fn prov() -> Provenance {
        Provenance {
            collector: Collector::CallTracerJson,
            cast_version: None,
            chain_id: None,
            block: None,
        }
    }

    fn frame(kind: CallKind, to: Address) -> Frame {
        Frame {
            id: 0,
            kind,
            from: addr(1),
            to: Some(to),
            context: Address::ZERO,
            value: None,
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

    /// root → [a→X, a→Y]
    fn baseline() -> Trace {
        let mut b = TraceBuilder::new(prov());
        let root = b.push(None, frame(CallKind::Call, addr(2)));
        b.push(Some(root), frame(CallKind::StaticCall, addr(3)));
        b.push(Some(root), frame(CallKind::StaticCall, addr(4)));
        b.finish()
    }

    #[test]
    fn the_same_tree_differs_from_nothing() {
        let t = baseline();
        let d = diff(&t, &t);
        assert!(d.is_empty(), "{:?}", d.changes);
        assert!(
            d.summary().contains("structurally identical"),
            "{}",
            d.summary()
        );
    }

    #[test]
    fn one_extra_call_is_reported_as_an_insertion() {
        let base = baseline();
        let mut b = TraceBuilder::new(prov());
        let root = b.push(None, frame(CallKind::Call, addr(2)));
        b.push(Some(root), frame(CallKind::StaticCall, addr(3)));
        // the second external call an exploit adds before the first one already present
        let extra = b.push(Some(root), frame(CallKind::Call, addr(9)));
        b.push(Some(extra), frame(CallKind::DelegateCall, addr(10)));
        b.push(Some(root), frame(CallKind::StaticCall, addr(4)));
        let target = b.finish();

        let d = diff(&base, &target);
        assert!(!d.is_empty());
        assert!(d.added() > 0, "expected additions: {:?}", d.changes);
        assert!(
            d.summary().contains("positions are child indices"),
            "the caveat must travel with the counts: {}",
            d.summary()
        );
    }

    #[test]
    fn a_changed_selector_at_the_same_position_is_a_change_not_an_insert() {
        let base = baseline();
        let mut b = TraceBuilder::new(prov());
        let root = b.push(None, frame(CallKind::Call, addr(2)));
        let kid = b.push(Some(root), frame(CallKind::StaticCall, addr(3)));
        b.set_selector(kid, Selector([0x70, 0xa0, 0x82, 0x31]));
        b.push(Some(root), frame(CallKind::StaticCall, addr(4)));
        let target = b.finish();

        let d = diff(&base, &target);
        assert_eq!(d.changes.len(), 1, "{:?}", d.changes);
        let c = &d.changes[0];
        assert_eq!(c.change, ChangeKind::Changed);
        assert_eq!(c.path, "root/0");
        assert_eq!(c.baseline.as_ref().unwrap().selector, None);
        assert_eq!(
            c.target.as_ref().unwrap().selector.unwrap().to_hex(),
            "0x70a08231"
        );
    }

    #[test]
    fn reversing_the_inputs_flips_added_and_removed() {
        let base = baseline();
        let mut b = TraceBuilder::new(prov());
        let root = b.push(None, frame(CallKind::Call, addr(2)));
        b.push(Some(root), frame(CallKind::StaticCall, addr(3)));
        b.push(Some(root), frame(CallKind::StaticCall, addr(4)));
        b.push(Some(root), frame(CallKind::Call, addr(7)));
        let target = b.finish();

        let forward = diff(&base, &target);
        let backward = diff(&target, &base);
        assert_eq!(forward.added(), 1);
        assert_eq!(forward.removed(), 0);
        assert_eq!(backward.added(), 0);
        assert_eq!(backward.removed(), 1);
        assert_eq!(forward.changes[0].path, backward.changes[0].path);
    }

    #[test]
    fn diffing_is_deterministic_and_json_safe() {
        let base = baseline();
        let mut b = TraceBuilder::new(prov());
        let root = b.push(None, frame(CallKind::Call, addr(2)));
        b.push(Some(root), frame(CallKind::DelegateCall, addr(5)));
        let target = b.finish();

        let a = serde_json::to_string(&diff(&base, &target)).unwrap();
        let c = serde_json::to_string(&diff(&base, &target)).unwrap();
        assert_eq!(
            a, c,
            "one pair of traces, two serializations, identical bytes"
        );
        assert!(
            a.contains("\"change\":\"added\"") || a.contains("\"change\":\"removed\""),
            "{a}"
        );

        let d: Diff = serde_json::from_str(&a).unwrap();
        assert_eq!(
            d,
            diff(&base, &target),
            "the diff must survive its own JSON form"
        );
    }

    #[test]
    fn paths_sort_numerically_so_root_10_does_not_precede_root_2() {
        assert_eq!(
            compare_paths("root/2", "root/10"),
            std::cmp::Ordering::Less,
            "string sorting would put 10 before 2"
        );
        assert_eq!(
            compare_paths("root/0/1", "root/1"),
            std::cmp::Ordering::Less
        );
    }

    #[test]
    fn orphans_are_counted_and_declared_unmatchable() {
        // Two parentless frames: the second becomes an orphan whose path carries its
        // arena id, so it can line up only by accident.
        let mut b = TraceBuilder::new(prov());
        b.push(None, frame(CallKind::Call, addr(2)));
        b.push(None, frame(CallKind::Call, addr(3)));
        let t = b.finish();
        assert_eq!(t.orphans.len(), 1);
        let d = diff(&t, &t);
        assert!(
            d.summary().contains("structurally identical"),
            "identical inputs still match: {}",
            d.summary()
        );
        assert_eq!(d.target_orphans, 1);
    }

    #[test]
    fn amounts_and_labels_are_not_compared() {
        // Same shape, different value and label: the two collectors disagree on both
        // routinely, so a diff that counted them would report every frame as changed.
        let mut b = TraceBuilder::new(prov());
        b.push(None, frame(CallKind::Call, addr(2)));
        let mut t1 = b.finish();
        t1.frames[0].value = Some(Amount::new(U256::from(999u64)));
        t1.frames[0].label = Some("withdraw".into());
        let mut t2 = b_retry();
        t2.frames[0].value = Some(Amount::new(U256::from(1u64)));
        t2.frames[0].label = Some("deposit".into());
        let d = diff(&t1, &t2);
        assert!(
            d.is_empty(),
            "value and label must not create a difference: {:?}",
            d.changes
        );
    }

    fn b_retry() -> Trace {
        let mut b = TraceBuilder::new(prov());
        b.push(None, frame(CallKind::Call, addr(2)));
        b.finish()
    }
}
