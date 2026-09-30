//! The `callTracer` collector: `debug_traceTransaction` JSON in, [`Trace`] out.
//!
//! This is the primary path. It exists because rendering a call tree to text and
//! regexing it back is a lossy round trip through someone else's pretty-printer:
//! the JSON keeps the revert reason, the ETH value on every frame, and the gas
//! actually used, none of which the previous implementation could see.
//!
//! Walked with an explicit stack, not recursion. Reentrancy exploits nest
//! thousands of frames deep and a stack overflow while printing the report is the
//! worst possible way to fail on exactly the transaction that matters.

use crate::error::{Error, Result};
use crate::model::address::hex_bytes;
use crate::model::{
    Address, Amount, CallKind, Collector, Frame, FrameId, FrameStatus, Provenance, Selector, Trace,
    TraceBuilder,
};
use serde_json::Value;

pub fn kind_from_tracer(s: &str) -> CallKind {
    match s.to_ascii_uppercase().as_str() {
        "CALL" => CallKind::Call,
        "STATICCALL" => CallKind::StaticCall,
        "DELEGATECALL" => CallKind::DelegateCall,
        "CALLCODE" => CallKind::CallCode,
        "CREATE" => CallKind::Create,
        "CREATE2" => CallKind::Create2,
        // Arbitrum and a few other stacks emit AUTHCALL. Kept verbatim rather
        // than coerced to Call: silently accepting an unmodelled chain is how a
        // tool starts producing confident output about a chain it cannot read.
        other => CallKind::Other(other.to_string()),
    }
}

pub fn status_from_frame(node: &Value) -> FrameStatus {
    let err = node.get("error").and_then(|e| e.as_str());
    let reason = node
        .get("revertReason")
        .and_then(|r| r.as_str())
        .map(|s| s.to_string());
    match err {
        None => FrameStatus::Success,
        Some("execution reverted") => FrameStatus::Reverted { reason },
        Some("out of gas") => FrameStatus::Failed {
            reason: reason.or(Some("out of gas".into())),
        },
        Some(other) => FrameStatus::Failed {
            reason: Some(reason.unwrap_or_else(|| other.to_string())),
        },
    }
}

fn frame_from(node: &Value) -> std::result::Result<Frame, &'static str> {
    let kind = kind_from_tracer(node.get("type").and_then(|t| t.as_str()).unwrap_or("CALL"));
    let from = node
        .get("from")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<Address>().ok())
        .ok_or("frame has no parsable `from`")?;
    let to = match node.get("to").and_then(|v| v.as_str()) {
        Some(s) => s.parse::<Address>().ok(),
        None => None,
    };
    if kind.is_creation() && to.is_none() {
        // A create with no address is representable; the created contract simply
        // is not known to this tracer.
    }
    let input = node
        .get("input")
        .and_then(|v| v.as_str())
        .and_then(hex_bytes);
    let output = node
        .get("output")
        .and_then(|v| v.as_str())
        .and_then(hex_bytes);

    Ok(Frame {
        id: 0,
        kind,
        from,
        to,
        context: Address::ZERO,
        // `value` is absent on delegate/static frames. Absent is not zero: the
        // frame inherited its parent's value, and inventing 0 would hide an ETH
        // move that the ledger is supposed to count.
        value: node
            .get("value")
            .and_then(|v| v.as_str())
            .and_then(Amount::from_hex),
        gas_used: node
            .get("gasUsed")
            .and_then(|v| v.as_str())
            .and_then(crate::collect::rpc::hex_u64),
        selector: input.as_deref().and_then(Selector::from_calldata),
        // The tracer gives no names. Names are a *cast* feature, and this path
        // deliberately does not pretend to have them.
        label: None,
        status: status_from_frame(node),
        return_bytes: output.map(|o| o.len()),
        parent: None,
        children: Vec::new(),
        depth: 0,
    })
}

/// Build the trace tree. `nodes_seen` is returned so the caller can assert that
/// every frame in the payload was accounted for.
pub fn build_trace(root: &Value, provenance: Provenance) -> Result<(Trace, usize)> {
    if !root.is_object() {
        return Err(Error::Collect(format!(
            "callTracer returned {} where an object was expected",
            json_kind(root)
        )));
    }

    let mut b = TraceBuilder::new(provenance);
    let mut nodes_seen = 0usize;
    let mut stack: Vec<(&Value, Option<FrameId>)> = vec![(root, None)];

    while let Some((node, parent)) = stack.pop() {
        nodes_seen += 1;
        let id = match frame_from(node) {
            Ok(f) => b.push(parent, f),
            Err(why) => {
                b.unclassified(nodes_seen, summarize(node), why);
                // Children of an unreadable frame cannot be attached to it, and
                // attaching them to its parent would silently mis-nest the whole
                // subtree. They become orphans instead: counted, flagged, wrong
                // in the direction of admitting it.
                let mut sunk = Vec::new();
                // Descendants of an unreadable frame are still payload nodes and
                // still have to be counted, or the conservation arithmetic would
                // read as though they had never arrived.
                nodes_seen += collect_descendants(node, &mut sunk);
                for mut orphan in sunk {
                    orphan.parent = None;
                    b.push(None, orphan);
                }
                continue;
            }
        };
        if let Some(calls) = node.get("calls").and_then(|c| c.as_array()) {
            // Reversed so the stack pops them in trace order.
            for child in calls.iter().rev() {
                stack.push((child, Some(id)));
            }
        }
    }

    // `frame_from` failures were already recorded; `nodes_seen` counted them once.
    let trace = b.finish();
    Ok((trace, nodes_seen))
}

/// Flatten an unreadable frame's *descendants* into standalone frames, returning
/// how many were visited. Iterative for the same reason the main walk is: an
/// unparseable node deep in a 6,000-frame reentrancy trace must not be the thing
/// that overflows the stack.
fn collect_descendants(node: &Value, out: &mut Vec<Frame>) -> usize {
    let mut stack: Vec<&Value> = Vec::new();
    if let Some(calls) = node.get("calls").and_then(|c| c.as_array()) {
        stack.extend(calls.iter());
    }
    let mut count = 0usize;
    while let Some(n) = stack.pop() {
        count += 1;
        if count > 200_000 {
            return count;
        }
        if let Ok(f) = frame_from(n) {
            out.push(f);
        }
        if let Some(calls) = n.get("calls").and_then(|c| c.as_array()) {
            stack.extend(calls.iter());
        }
    }
    count
}

fn json_kind(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Short, secret-free description of a node we could not read.
fn summarize(node: &Value) -> String {
    let ty = node.get("type").and_then(|t| t.as_str()).unwrap_or("?");
    let from = node.get("from").and_then(|f| f.as_str()).unwrap_or("?");
    let to = node.get("to").and_then(|f| f.as_str()).unwrap_or("?");
    format!("{{type:{ty},from:{from},to:{to}}}")
}

pub fn provenance(chain_id: Option<u64>, block: Option<u64>) -> Provenance {
    Provenance {
        collector: Collector::CallTracerJson,
        cast_version: None,
        chain_id,
        block,
    }
}

/// The `withLog` family of options is not requested, because it does not help:
/// measured against eth.drpc.org, `withLog`, `enableLog` and `withLogs` all
/// returned `logs: null` on every frame. Logs come from the receipt instead.
pub fn tracer_args() -> Value {
    serde_json::json!({ "tracer": "callTracer" })
}

pub fn trace_transaction(
    rpc: &dyn crate::collect::rpc::Rpc,
    hash: crate::model::TxHash,
    provenance: Provenance,
) -> Result<(Trace, usize)> {
    let raw = rpc.request(
        "debug_traceTransaction",
        &[serde_json::json!(hash.to_hex()), tracer_args()],
    )?;
    build_trace(&raw, provenance)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::str::FromStr;

    fn a(s: &str) -> Address {
        Address::from_str(s).unwrap()
    }

    fn prov() -> Provenance {
        provenance(Some(1), Some(1))
    }

    const PROXY: &str = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
    const IMPL: &str = "0xa2327a938Febf5FEC13baCFb16Ae10EcBc4cbDCF";

    #[test]
    fn nested_frames_keep_execution_order_and_depth() {
        // Shape taken from the captured USDC transfer 0x5b515946…
        let root = json!({
            "type": "CALL",
            "from": "0xfacf9ec2d27045b31291e79f4ac982cce66bf241",
            "to": PROXY,
            "value": "0x0",
            "gas": "0x186a0",
            "gasUsed": "0xaacd",
            "input": "0xa9059cbb00000000",
            "output": "0x0000000000000000000000000000000000000000000000000000000000000001",
            "calls": [
                {"type": "DELEGATECALL", "from": PROXY, "to": IMPL,
                 "gas": "0x4c00", "gasUsed": "0x4ca6", "input": "0xa9059cbb00000000"}
            ]
        });
        let (t, seen) = build_trace(&root, prov()).unwrap();
        assert_eq!(seen, 2);
        assert_eq!(t.len(), 2);
        assert_eq!(t.conservation.frames, 2);
        assert!(t.conservation.balances());
        assert!(t.unclassified.is_empty());

        let ids = t.root_walk();
        assert_eq!(ids.len(), 2);
        let root_id = t.root.unwrap();
        assert_eq!(t.frame(root_id).unwrap().depth, 0);
        let dl = *t.children_of(root_id).first().unwrap();
        assert_eq!(t.frame(dl).unwrap().depth, 1);
        assert_eq!(t.frame(dl).unwrap().kind, CallKind::DelegateCall);
        assert_eq!(t.frame(dl).unwrap().to, Some(a(IMPL)));
        assert_eq!(t.frame(dl).unwrap().context, a(PROXY));
        assert_eq!(
            t.frame(dl).unwrap().context,
            a(PROXY),
            "the delegatecall frame must be attributed to the proxy, which holds the balances"
        );
    }

    #[test]
    fn value_absent_is_not_value_zero() {
        let root = json!({"type":"CALL","from":PROXY,"to":IMPL,"gasUsed":"0x1","input":"0x"});
        let (t, _) = build_trace(&root, prov()).unwrap();
        let f = t.frame(t.root.unwrap()).unwrap();
        assert_eq!(
            f.value, None,
            "a missing `value` field means the tracer did not say"
        );

        let with_zero = json!({"type":"CALL","from":PROXY,"to":IMPL,"value":"0x0","gasUsed":"0x1","input":"0x"});
        let (t2, _) = build_trace(&with_zero, prov()).unwrap();
        assert_eq!(
            t2.frame(t2.root.unwrap()).unwrap().value,
            Some(Amount::ZERO)
        );
    }

    #[test]
    fn revert_reason_is_carried_and_distinguished_from_other_failures() {
        let rev = json!({"type":"CALL","from":PROXY,"to":IMPL,"gasUsed":"0x1","input":"0x",
                         "error":"execution reverted","revertReason":"ERC20: transfer amount exceeds balance"});
        let (t, _) = build_trace(&rev, prov()).unwrap();
        match &t.frame(t.root.unwrap()).unwrap().status {
            FrameStatus::Reverted { reason } => {
                assert_eq!(
                    reason.as_deref(),
                    Some("ERC20: transfer amount exceeds balance")
                )
            }
            other => panic!("expected reverted, got {other:?}"),
        }

        let oog = json!({"type":"CALL","from":PROXY,"to":IMPL,"gasUsed":"0x1","input":"0x","error":"out of gas"});
        let (t2, _) = build_trace(&oog, prov()).unwrap();
        assert!(matches!(
            t2.frame(t2.root.unwrap()).unwrap().status,
            FrameStatus::Failed { .. }
        ));
    }

    #[test]
    fn an_unreadable_frame_is_counted_not_dropped_and_its_children_survive_as_orphans() {
        let root = json!({
            "type":"CALL","from":PROXY,"to":IMPL,"gasUsed":"0x10","input":"0x",
            "calls":[{
                "nope":1,
                "calls":[{"type":"CALL","from":PROXY,"to":IMPL,"gasUsed":"0x1","input":"0x"}]
            }]
        });
        let (t, seen) = build_trace(&root, prov()).unwrap();
        assert_eq!(seen, 3, "every node in the payload is accounted for");
        assert_eq!(t.conservation.frames + t.conservation.unclassified, seen);
        assert_eq!(t.unclassified.len(), 1);
        assert_eq!(t.orphans.len(), 1);
        assert!(
            t.children_of(t.root.unwrap()).is_empty(),
            "root has no child frame here: its only child was unreadable. Saying \
             'no children' and listing an adopted grandchild would be the lie."
        );
        assert!(
            t.preorder().contains(&t.orphans[0]),
            "the grandchild is still reachable for reporting"
        );
    }

    #[test]
    fn unknown_call_kinds_are_preserved_as_text() {
        let root = json!({"type":"AUTHCALL","from":PROXY,"to":IMPL,"gasUsed":"0x1","input":"0x"});
        let (t, _) = build_trace(&root, prov()).unwrap();
        assert_eq!(
            t.frame(t.root.unwrap()).unwrap().kind,
            CallKind::Other("AUTHCALL".into())
        );
        assert!(!t.frame(t.root.unwrap()).unwrap().kind.inherits_context());
    }

    #[test]
    fn a_non_object_response_is_an_error_not_an_empty_trace() {
        // An empty tree would print as "no calls" — indistinguishable from a
        // transaction that genuinely did nothing.
        assert!(build_trace(&json!(null), prov()).is_err());
        assert!(build_trace(&json!([]), prov()).is_err());
    }

    /// Build a `depth`-deep callTracer value *without* `json!`.
    ///
    /// `json!({"calls":[node]})` serializes the interpolated `node` with
    /// `to_value`, which is recursive — so using the macro here would overflow
    /// the stack inside the test harness and report a bug in the wrong place.
    /// `serde_json`'s deserializer is recursive too, which is precisely why real
    /// collection runs on [`crate::collect::with_large_stack`].
    fn deep_trace(depth: u32) -> Value {
        use serde_json::{Map, Value};
        let leaf = || {
            let mut m = Map::new();
            m.insert("type".into(), Value::String("CALL".into()));
            m.insert("from".into(), Value::String(PROXY.into()));
            m.insert("to".into(), Value::String(IMPL.into()));
            m.insert("gasUsed".into(), Value::String("0x1".into()));
            m.insert("input".into(), Value::String("0x".into()));
            Value::Object(m)
        };
        let mut node = leaf();
        for _ in 0..depth {
            let mut m = leaf().as_object().cloned().unwrap();
            m.insert("calls".into(), Value::Array(vec![node]));
            node = Value::Object(m);
        }
        node
    }

    #[test]
    fn deep_nesting_does_not_recurse() {
        let node = deep_trace(6000);
        // The drop of that value is recursive, so it happens on the sized stack,
        // exactly like a real response parsed by `read_json`.
        let (walked, deepest) = crate::collect::with_large_stack(move || {
            let (t, seen) = build_trace(&node, prov()).unwrap();
            assert_eq!(seen, 6001);
            (t.root_walk().len(), t.frames.last().unwrap().depth)
        })
        .expect("sized-stack thread");
        assert_eq!(walked, 6001);
        assert_eq!(deepest, 6000);
    }
}
