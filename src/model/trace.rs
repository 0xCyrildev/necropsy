//! The trace model both collectors converge on.
//!
//! A transaction trace is a **rooted ordered tree**, so that is what is stored:
//! a flat arena of [`Frame`]s with `Vec<FrameId>` child lists. There is no
//! general graph here, and deliberately no graph library — an empty edge
//! struct plus a side map duplicating the same child lists is two
//! representations of one fact, free to desynchronise.
//!
//! Two properties are load-bearing downstream and are established here once:
//!
//! * **`context`** — the address whose storage a frame executes against. For a
//!   `DELEGATECALL`/`CALLCODE` frame this is the *parent's* context, not the
//!   frame's own `to`, which is merely the code being run. Attribution of a
//!   token to an address is wrong without it.
//! * **conservation** — every line of collector input gets exactly one
//!   [`Disposition`], and anything that could be a frame but was not parsed is
//!   [`Disposition::Unclassified`]. Silent drops are what make a mis-nested tree
//!   look plausible; the counter makes it loud.

use super::address::{Address, Selector};
use super::value::Amount;
use serde::Serialize;

pub type FrameId = u32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum CallKind {
    Call,
    StaticCall,
    DelegateCall,
    CallCode,
    Create,
    Create2,
    /// A kind this build does not model — mainnet L2s emit `AUTHCALL`, for
    /// example. Kept as text rather than coerced to `Call`, because coercion is
    /// how an unsupported chain starts producing confident output.
    Other(String),
}

impl CallKind {
    /// Executes callee code against the *caller's* storage.
    pub fn inherits_context(&self) -> bool {
        matches!(self, CallKind::DelegateCall | CallKind::CallCode)
    }

    pub fn is_creation(&self) -> bool {
        matches!(self, CallKind::Create | CallKind::Create2)
    }

    /// Kinds for which the EVM itself forbids a value transfer, so an omitted
    /// `value` is a known zero rather than an unknown.
    ///
    /// `callTracer` reports `value: 0x0` on ordinary calls and leaves the field
    /// out entirely on `STATICCALL`/`DELEGATECALL`/`CALLCODE`. Rendering that
    /// omission as "unknown" therefore put a `value ?` on every read-only frame of
    /// a real trace, and the marker stopped carrying information: a genuinely
    /// unreported value on a call that *could* move ETH looks identical to a frame
    /// that cannot move ETH by protocol.
    pub fn cannot_carry_value(&self) -> bool {
        matches!(
            self,
            CallKind::StaticCall | CallKind::DelegateCall | CallKind::CallCode
        )
    }

    pub fn tag(&self) -> &'static str {
        match self {
            CallKind::Call => "call",
            CallKind::StaticCall => "staticcall",
            CallKind::DelegateCall => "delegatecall",
            CallKind::CallCode => "callcode",
            CallKind::Create => "create",
            CallKind::Create2 => "create2",
            CallKind::Other(_) => "other",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum FrameStatus {
    Success,
    /// `error: "execution revert"` / `← [Revert] <reason>`. Value moved inside a
    /// reverted subtree is *attempted*, not moved.
    Reverted {
        reason: Option<String>,
    },
    /// Out of gas, invalid jump depth, and every other non-revert failure.
    Failed {
        reason: Option<String>,
    },
    /// The collector did not tell us. Distinct from `Success`: a tool that
    /// defaults unknown to ok cannot distinguish "it worked" from "nobody said".
    Unknown,
}

impl FrameStatus {
    pub fn reverted(&self) -> bool {
        matches!(
            self,
            FrameStatus::Reverted { .. } | FrameStatus::Failed { .. }
        )
    }

    pub fn reason(&self) -> Option<&str> {
        match self {
            FrameStatus::Reverted { reason: Some(r) } | FrameStatus::Failed { reason: Some(r) } => {
                Some(r)
            }
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Frame {
    pub id: FrameId,
    pub kind: CallKind,
    pub from: Address,
    /// `None` for a creation whose address the collector did not report.
    pub to: Option<Address>,
    /// Storage context, computed once in [`TraceBuilder::finish`].
    pub context: Address,
    /// Wei forwarded with the call. `None` means the collector did not say,
    /// which is not the same as zero.
    pub value: Option<Amount>,
    /// Gas *used* by this frame. The previous implementation called this `gas`
    /// and parsed it as if it were a limit; `cast` prints usage.
    pub gas_used: Option<u64>,
    /// First four calldata bytes. The only argument-derived field: full ABI
    /// decoding is out of scope, so who *controls* a value stays unanswerable
    /// and the tool says so.
    pub selector: Option<Selector>,
    /// Human name, e.g. `transfer`. For display only — never compared, because
    /// whether a name exists depends on whether a label lookup succeeded.
    pub label: Option<String>,
    pub status: FrameStatus,
    /// Bytes returned. Kept as a length because the payload itself is useless
    /// without ABI decoding, and carrying it would imply we can read it.
    pub return_bytes: Option<usize>,
    pub parent: Option<FrameId>,
    pub children: Vec<FrameId>,
    pub depth: u32,
}

impl Frame {
    pub fn is_precompile(&self) -> bool {
        !self.kind.is_creation() && self.to.is_some_and(|a| a.is_precompile())
    }

    /// What a structural diff compares. `label` and `value` are excluded: a
    /// label present on one collector and absent on the other, or an ETH value
    /// rendered by one and omitted by the other, would report every node as
    /// changed.
    pub fn diff_signature(&self) -> (CallKind, Address, Option<Address>, Option<Selector>) {
        (self.kind.clone(), self.from, self.to, self.selector)
    }
}

/// How one line of collector input was accounted for. Every line gets exactly
/// one, and the total is asserted to equal the sum of the parts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    Frame,
    Emission,
    Result,
    Trailer,
    Blank,
    Unclassified,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UnclassifiedLine {
    pub line: usize,
    pub text: String,
    pub why: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
pub struct Conservation {
    pub total: usize,
    pub frames: usize,
    pub emissions: usize,
    pub results: usize,
    pub trailers: usize,
    pub blanks: usize,
    pub unclassified: usize,
}

impl Conservation {
    pub fn record(&mut self, d: Disposition) {
        self.total += 1;
        match d {
            Disposition::Frame => self.frames += 1,
            Disposition::Emission => self.emissions += 1,
            Disposition::Result => self.results += 1,
            Disposition::Trailer => self.trailers += 1,
            Disposition::Blank => self.blanks += 1,
            Disposition::Unclassified => self.unclassified += 1,
        }
    }

    /// The conservation invariant: nothing is dropped, so nothing can be
    /// silently missing from a report that looks complete.
    pub fn balances(&self) -> bool {
        self.total
            == self.frames
                + self.emissions
                + self.results
                + self.trailers
                + self.blanks
                + self.unclassified
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Collector {
    /// `debug_traceTransaction` + `callTracer`, parsed as JSON.
    CallTracerJson,
    /// `cast run --debug-trace-transaction`, parsed from rendered text.
    CastTextRendered,
    /// `cast run` re-executing the block locally. Numbers from this source are
    /// labelled "local replay", because replay can diverge from chain.
    CastLocalReplay,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Provenance {
    pub collector: Collector,
    /// Version of `cast`, when the text collector ran.
    pub cast_version: Option<String>,
    /// Chain id the endpoint reported for this transaction.
    pub chain_id: Option<u64>,
    pub block: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Trace {
    pub frames: Vec<Frame>,
    pub root: Option<FrameId>,
    /// Frames whose parent could not be determined — including every descendant
    /// of an unparseable frame. Counted and named, never quietly re-parented.
    pub orphans: Vec<FrameId>,
    pub unclassified: Vec<UnclassifiedLine>,
    pub conservation: Conservation,
    pub provenance: Provenance,
}

impl Trace {
    pub fn frame(&self, id: FrameId) -> Option<&Frame> {
        self.frames.get(id as usize)
    }

    pub fn len(&self) -> usize {
        self.frames.len()
    }

    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    /// Depth-first pre-order from the root only — execution order, since a
    /// frame's children all run before its next sibling. Iterative on purpose:
    /// real exploit traces nest deeply enough to overflow the stack, and
    /// crashing mid-report is the worst place to run out of room.
    pub fn root_walk(&self) -> Vec<FrameId> {
        let mut out = Vec::with_capacity(self.frames.len());
        let Some(root) = self.root else { return out };
        out.push(root);
        let mut stack: Vec<std::vec::IntoIter<FrameId>> = vec![self.children_of(root).into_iter()];
        while let Some(it) = stack.last_mut() {
            match it.next() {
                Some(id) => {
                    out.push(id);
                    stack.push(self.children_of(id).into_iter());
                }
                None => {
                    stack.pop();
                }
            }
        }
        out
    }

    /// Every frame the trace can show: the root walk, then any orphan. Callers
    /// that mean "what actually executed in order" want `root_walk`.
    pub fn preorder(&self) -> Vec<FrameId> {
        let mut out = self.root_walk();
        let seen: std::collections::HashSet<FrameId> = out.iter().copied().collect();
        out.extend(self.orphans.iter().copied().filter(|o| !seen.contains(o)));
        out
    }

    pub fn children_of(&self, id: FrameId) -> Vec<FrameId> {
        self.frame(id)
            .map(|f| f.children.clone())
            .unwrap_or_default()
    }

    /// Root to `id`, inclusive — the open-frame set, which is what a call *re-enters*
    /// along. `Trace::path` walks it, so [`crate::diff`] reaches it transitively;
    /// nothing here decides whether a repeated address on that chain is an exploit.
    pub fn ancestors(&self, id: FrameId) -> Vec<FrameId> {
        let mut chain = Vec::new();
        let mut cur = Some(id);
        while let Some(f) = cur.and_then(|i| self.frame(i)) {
            chain.push(f.id);
            cur = f.parent;
            // A cycle would mean a corrupted arena; bounded by frame count so a
            // bug degrades into a truncated path rather than a hung process.
            if chain.len() > self.frames.len() + 1 {
                break;
            }
        }
        chain.reverse();
        chain
    }

    /// Position path, e.g. `root/0/2/1` — the coordinate [`crate::diff`] compares two
    /// traces on. Orphans get `orphan/<arena id>`, which identifies one collection
    /// rather than a location, and the diff says so instead of pairing them.
    pub fn path(&self, id: FrameId) -> String {
        let chain = self.ancestors(id);
        if chain
            .first()
            .and_then(|&i| self.frame(i))
            .map(|f| f.parent.is_none())
            == Some(true)
        {
            let mut s = String::from("root");
            for pair in chain.windows(2) {
                let parent = pair[0];
                let child = pair[1];
                if let Some(pos) = self.children_of(parent).iter().position(|&c| c == child) {
                    s.push_str(&format!("/{pos}"));
                }
            }
            s
        } else {
            format!("orphan/{id}")
        }
    }

    /// Frames reachable from the root. Differs from `len()` by exactly the
    /// orphans, which is why the old `node_count()` prose and the printed tree
    /// could disagree.
    pub fn reachable(&self) -> usize {
        self.root_walk().len()
    }

    /// Fill in a root caller the collector could not see. Returns whether it did
    /// anything.
    ///
    /// `TraceBuilder::push` resolves an absent caller from the enclosing frame's
    /// context, which is right for every frame except the root — a root has no
    /// enclosing frame, so `cast`, which renders callees only, leaves `from` at
    /// `Address::ZERO` there. That is not a cosmetic gap: the ledger debits native
    /// ETH from `f.from`, so a value-bearing transaction traced through `cast`
    /// would attribute the sender's outflow to the burn address. The sender is
    /// authoritative in `eth_getTransactionByHash`, so the caller passes it in.
    pub fn attribute_root_sender(&mut self, from: Address) -> bool {
        let Some(root) = self.root else { return false };
        let Some(f) = self.frames.get_mut(root as usize) else {
            return false;
        };
        // Only a collector that did not report a caller looks like this. A real
        // call from the zero address is not a thing to overwrite.
        if f.from != Address::ZERO {
            return false;
        }
        f.from = from;
        true
    }
}

/// Accumulates frames in pre-order, which both collectors naturally produce.
pub struct TraceBuilder {
    frames: Vec<Frame>,
    unclassified: Vec<UnclassifiedLine>,
    conservation: Conservation,
    provenance: Provenance,
}

impl TraceBuilder {
    pub fn new(provenance: Provenance) -> Self {
        TraceBuilder {
            frames: Vec::new(),
            unclassified: Vec::new(),
            conservation: Conservation::default(),
            provenance,
        }
    }

    /// Add a frame whose parent is already known. Parents are always added
    /// before children, which is what lets `push` resolve the storage context
    /// immediately and `finish` compute depth in a single index-ordered pass.
    ///
    /// A collector that cannot see the caller (`cast` prints only the callee)
    /// passes `from == Address::ZERO`, which is filled in from the enclosing
    /// frame's context here. The zero address cannot be a real caller, so using it
    /// as the sentinel is safe rather than merely convenient.
    pub fn push(&mut self, parent: Option<FrameId>, mut f: Frame) -> FrameId {
        let id = self.frames.len() as FrameId;
        f.id = id;
        f.parent = parent;
        f.children.clear();
        if let Some(p) = parent {
            let pctx = self.frames[p as usize].context;
            if f.from == Address::ZERO {
                f.from = pctx;
            }
            f.context = if f.kind.inherits_context() {
                pctx
            } else {
                f.to.unwrap_or(pctx)
            };
            self.frames[p as usize].children.push(id);
        } else {
            f.context = f.to.unwrap_or(f.from);
        }
        self.frames.push(f);
        self.conservation.record(Disposition::Frame);
        id
    }

    /// Attach a terminal status to an already-pushed frame. Used by the text
    /// collector, where the `← [Return]` / `← [Revert]` line arrives after the
    /// frame it describes.
    pub fn set_status(&mut self, id: FrameId, status: FrameStatus) {
        if let Some(f) = self.frames.get_mut(id as usize) {
            f.status = status;
        }
    }

    pub fn set_return_bytes(&mut self, id: FrameId, n: usize) {
        if let Some(f) = self.frames.get_mut(id as usize) {
            f.return_bytes = Some(n);
        }
    }

    /// Attach a selector to an already-pushed frame, for a collector that learns it
    /// after the frame line — the same shape as [`TraceBuilder::set_status`].
    pub fn set_selector(&mut self, id: FrameId, selector: Selector) {
        if let Some(f) = self.frames.get_mut(id as usize) {
            f.selector = Some(selector);
        }
    }

    pub fn unclassified(&mut self, line: usize, text: impl Into<String>, why: impl Into<String>) {
        self.unclassified.push(UnclassifiedLine {
            line,
            text: text.into(),
            why: why.into(),
        });
        self.conservation.record(Disposition::Unclassified);
    }

    pub fn line(&mut self, d: Disposition) {
        self.conservation.record(d);
    }

    pub fn provenance(&mut self, p: Provenance) {
        self.provenance = p;
    }

    pub fn finish(mut self) -> Trace {
        let mut root = None;
        let mut orphans = Vec::new();
        for i in 0..self.frames.len() {
            let id = i as FrameId;
            let parent = self.frames[i].parent;
            match parent {
                None => {
                    if root.is_none() {
                        root = Some(id);
                        self.frames[i].depth = 0;
                        self.frames[i].context = self.frames[i]
                            .to
                            .or(Some(self.frames[i].from))
                            .unwrap_or(Address::ZERO);
                    } else {
                        orphans.push(id);
                        self.frames[i].depth = 0;
                        self.frames[i].context = self.frames[i].to.unwrap_or(self.frames[i].from);
                    }
                }
                Some(p) => {
                    // `push` already resolved `context` from the parent; depth is
                    // the only remaining derived field, and a parent necessarily
                    // precedes its child in insertion order.
                    self.frames[i].depth = self.frames[p as usize].depth + 1;
                }
            }
        }

        // A frame that was never inserted cannot have a child id; sort/unique
        // keeps the orphan list deterministic across runs.
        orphans.sort_unstable();
        orphans.dedup();

        Trace {
            frames: self.frames,
            root,
            orphans,
            unclassified: self.unclassified,
            conservation: self.conservation,
            provenance: self.provenance,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::address::Address;

    fn addr(n: u8) -> Address {
        let mut b = [0u8; 20];
        b[19] = n;
        Address(b)
    }

    fn frame(kind: CallKind, from: Address, to: Address) -> Frame {
        Frame {
            id: 0,
            kind,
            from,
            to: Some(to),
            context: Address::ZERO,
            value: None,
            gas_used: None,
            selector: None,
            label: None,
            status: FrameStatus::Unknown,
            return_bytes: None,
            parent: None,
            children: Vec::new(),
            depth: 0,
        }
    }

    #[test]
    fn delegatecall_frame_keeps_the_parents_context() {
        let mut b = TraceBuilder::new(Provenance {
            collector: Collector::CallTracerJson,
            cast_version: None,
            chain_id: None,
            block: None,
        });
        // proxy USDC -> implementation, the captured 0x5b515946 shape
        let proxy = addr(0x01);
        let impls = addr(0x02);
        let root = b.push(None, frame(CallKind::Call, addr(0xaa), proxy));
        let dl = b.push(Some(root), frame(CallKind::DelegateCall, proxy, impls));
        let t = b.finish();
        assert_eq!(t.frame(root).unwrap().context, proxy);
        assert_eq!(
            t.frame(dl).unwrap().context,
            proxy,
            "a delegatecall frame runs implementation code against the PROXY's storage; \
             attributing its transfers to the implementation address invents a token"
        );
        assert_eq!(t.frame(dl).unwrap().to, Some(impls));
    }

    #[test]
    fn second_parentless_frame_is_an_orphan_not_silently_dropped() {
        let mut b = TraceBuilder::new(Provenance {
            collector: Collector::CastTextRendered,
            cast_version: None,
            chain_id: None,
            block: None,
        });
        let r = b.push(None, frame(CallKind::Call, addr(1), addr(2)));
        let o = b.push(None, frame(CallKind::Call, addr(3), addr(4)));
        let t = b.finish();
        assert_eq!(t.root, Some(r));
        assert_eq!(t.orphans, vec![o]);
        assert_eq!(t.len(), 2, "both frames exist");
        assert!(
            t.preorder().contains(&o),
            "and the orphan is still reachable for reporting"
        );
    }

    #[test]
    fn conservation_must_balance() {
        let mut b = TraceBuilder::new(Provenance {
            collector: Collector::CastTextRendered,
            cast_version: None,
            chain_id: None,
            block: None,
        });
        b.line(Disposition::Trailer);
        b.line(Disposition::Emission);
        b.push(None, frame(CallKind::Call, addr(1), addr(2)));
        b.unclassified(7, "  [9] BROKEN(", "no address shape");
        let t = b.finish();
        assert!(t.conservation.balances());
        assert_eq!(t.conservation.total, 4);
        assert_eq!(t.conservation.unclassified, 1);
    }

    #[test]
    fn preorder_is_execution_order_and_survives_depth() {
        let mut b = TraceBuilder::new(Provenance {
            collector: Collector::CallTracerJson,
            cast_version: None,
            chain_id: None,
            block: None,
        });
        let root = b.push(None, frame(CallKind::Call, addr(0), addr(1)));
        let a = b.push(Some(root), frame(CallKind::Call, addr(1), addr(2)));
        let a1 = b.push(Some(a), frame(CallKind::Call, addr(2), addr(3)));
        let bb = b.push(Some(root), frame(CallKind::StaticCall, addr(1), addr(4)));
        let t = b.finish();
        assert_eq!(t.preorder(), vec![root, a, a1, bb]);
        assert_eq!(t.ancestors(a1), vec![root, a, a1]);
        assert_eq!(t.path(a1), "root/0/0");
        assert_eq!(t.path(bb), "root/1");
        assert_eq!(t.frame(bb).unwrap().depth, 1);

        // Deeply nested without recursion: 20k frames, which would blow the stack
        // in a recursive renderer.
        let mut deep = TraceBuilder::new(Provenance {
            collector: Collector::CallTracerJson,
            cast_version: None,
            chain_id: None,
            block: None,
        });
        let mut prev = deep.push(None, frame(CallKind::Call, addr(0), addr(1)));
        for i in 1..20_000u32 {
            prev = deep.push(
                Some(prev),
                frame(CallKind::Call, addr(1), Address([i as u8; 20])),
            );
        }
        let dt = deep.finish();
        assert_eq!(dt.preorder().len(), 20_000);
        assert_eq!(dt.frame(prev).unwrap().depth, 19_999);
    }

    #[test]
    fn only_kinds_that_can_move_eth_leave_value_open() {
        // The report prints "value ?" for a frame that could carry ETH and whose
        // value was not reported. For these kinds the protocol already answered,
        // so an omitted value is a zero, not a gap.
        assert!(CallKind::StaticCall.cannot_carry_value());
        assert!(CallKind::DelegateCall.cannot_carry_value());
        assert!(CallKind::CallCode.cannot_carry_value());
        assert!(!CallKind::Call.cannot_carry_value());
        assert!(!CallKind::Create.cannot_carry_value());
        // An unmodelled kind is not assumed read-only: `AUTHCALL` on an L2 would
        // otherwise silently lose its value column.
        assert!(!CallKind::Other("AUTHCALL".into()).cannot_carry_value());
    }

    #[test]
    fn a_root_caller_of_zero_is_filled_but_a_real_caller_never_is() {
        // `cast` renders callees only, so its root arrives with no caller. The
        // transaction's sender fills that hole; leaving it would let the ledger put
        // the sender's ETH outflow on the burn address.
        let mut b = TraceBuilder::new(Provenance {
            collector: Collector::CastTextRendered,
            cast_version: None,
            chain_id: None,
            block: None,
        });
        b.push(None, frame(CallKind::Call, Address::ZERO, addr(2)));
        let mut t = b.finish();

        assert!(
            t.attribute_root_sender(addr(0xAA)),
            "the zero caller must be replaced"
        );
        assert_eq!(t.frame(t.root.unwrap()).unwrap().from, addr(0xAA));

        // Idempotent, and it must not overwrite a caller the collector did report.
        assert!(
            !t.attribute_root_sender(addr(0xBB)),
            "a filled-in caller stays filled in"
        );
        assert_eq!(t.frame(t.root.unwrap()).unwrap().from, addr(0xAA));

        let mut b2 = TraceBuilder::new(Provenance {
            collector: Collector::CallTracerJson,
            cast_version: None,
            chain_id: None,
            block: None,
        });
        b2.push(None, frame(CallKind::Call, addr(7), addr(2)));
        let mut t2 = b2.finish();
        assert!(
            !t2.attribute_root_sender(addr(0xAA)),
            "a reported caller is evidence; overwriting it destroys the difference between the collectors"
        );
        assert_eq!(t2.frame(t2.root.unwrap()).unwrap().from, addr(7));
    }

    #[test]
    fn attributing_a_sender_to_an_empty_trace_does_nothing() {
        let mut t = TraceBuilder::new(Provenance {
            collector: Collector::CastTextRendered,
            cast_version: None,
            chain_id: None,
            block: None,
        })
        .finish();
        assert_eq!(t.root, None);
        assert!(!t.attribute_root_sender(addr(1)));
    }
}
