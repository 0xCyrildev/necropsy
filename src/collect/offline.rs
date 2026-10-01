//! Reading a captured trace from disk instead of dialing a node.
//!
//! A `debug_traceTransaction` response is often the artifact someone actually has —
//! saved during an incident, exported by an explorer, pasted into a file by a colleague.
//! Two things follow from analysing one offline, and both are stated in the report rather
//! than hidden:
//!
//!   * **There is no receipt.** A trace alone says nothing about token movements, so the
//!     ledger holds no ERC-20 rows and the notes say why. An empty ledger here is *not*
//!     evidence that nothing moved.
//!   * **The transaction's own metadata is unknown** — origin, callee, block. The run is
//!     therefore degraded (exit 4), because `Collection::tx` is `None`. Anything resting on
//!     who called has no support.

use crate::collect::Collection;
use crate::collect::calltracer::build_trace;
use crate::error::{Error, Result};
use crate::model::{Collector, Provenance};
use serde_json::Value;
use std::io::Read;

/// Load a callTracer tree from a file: the bare frame object, or a JSON-RPC envelope
/// carrying it under `result`.
///
/// Both bounds apply to the file path as well as the network path. A captured trace is
/// somebody else's artifact — exported, pasted, produced by a tool nobody audited — and
/// reading it without a cap means that file decides this process's memory. `max_bytes` is
/// enforced *while reading*, not from a `metadata()` call that a swap could invalidate.
pub fn collection_from_json(path: &str, max_bytes: u64, max_depth: usize) -> Result<Collection> {
    let bad = |message: String| Error::Input {
        path: path.to_string(),
        message,
    };

    let mut raw = Vec::new();
    std::fs::File::open(path)
        .and_then(|mut f| {
            f.by_ref()
                .take(max_bytes.saturating_add(1))
                .read_to_end(&mut raw)
        })
        .map_err(|e| bad(format!("could not be read: {e}")))?;
    if raw.len() as u64 > max_bytes {
        return Err(bad(format!(
            "is larger than the {max_bytes} byte read limit, so it is not a trace anyone \
             vouched for; --max-response-mb moves the limit"
        )));
    }

    // A captured *error* response is not an empty trace. Reading it as one would turn
    // someone else's failed request into "this transaction did nothing".
    let doc = match crate::collect::depth::bounded_value(&raw, max_depth) {
        Ok(doc) => doc,
        // The depth limit is a property of the file, not of the flag that carried it in, so
        // it is reported as an input problem naming the file — with the flag to move.
        Err(Error::TraceTooDeep { depth, limit }) => {
            return Err(bad(format!(
                "nests {depth} levels deep, past the {limit} allowed by --max-trace-depth"
            )));
        }
        Err(e) => return Err(bad(format!("is not valid JSON: {e}"))),
    };
    if let Some(err) = doc.get("error").filter(|e| !e.is_null()) {
        return Err(bad(format!(
            "holds a JSON-RPC error, not a trace: {}",
            err.as_str().unwrap_or(&err.to_string())
        )));
    }

    let frame = doc.get("result").filter(|r| r.is_object()).unwrap_or(&doc);
    if !looks_like_a_frame(frame) {
        return Err(bad(format!(
            "does not look like a callTracer frame; its keys were {}",
            keys_of(frame)
        )));
    }

    let prov = Provenance {
        collector: Collector::OfflineFile,
        cast_version: None,
        chain_id: None,
        block: None,
    };
    let (trace, _nodes_seen) = build_trace(frame, prov)?;

    Ok(Collection {
        trace,
        logs: Vec::new(),
        events: Vec::new(),
        tx: None,
        notes: vec![
            "read from a local file, not a node: there is no receipt, so no token transfer is known. \
             An empty ledger here does not mean nothing moved"
                .into(),
            "the transaction hash is what the operator claimed. Nothing in a bare trace ties this file \
             to that hash."
                .into(),
        ],
    })
}

/// Must look like a frame, not merely be an object. An unrelated `{}` parses into an
/// empty tree, and an empty tree is the one output a forensic tool must never offer as if
/// it were a result.
fn looks_like_a_frame(v: &Value) -> bool {
    v.is_object()
        && ["type", "from", "to", "input", "output", "gas", "calls"]
            .iter()
            .any(|k| v.get(*k).is_some())
}

fn keys_of(v: &Value) -> String {
    match v
        .as_object()
        .map(|m| m.keys().map(String::as_str).collect::<Vec<_>>())
    {
        Some(ks) if !ks.is_empty() => ks.join(", "),
        Some(_) => "(none — an empty object)".into(),
        None => format!("(not an object: {v})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp(name: &str, body: &str) -> String {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "necropsy-offline-test-{name}-{pid}.json",
            pid = std::process::id()
        ));
        let mut f = std::fs::File::create(&p).expect("temp file");
        f.write_all(body.as_bytes()).expect("write temp");
        p.to_string_lossy().into_owned()
    }

    use crate::collect::rpc::{DEFAULT_MAX_RESPONSE_BYTES, DEFAULT_MAX_TRACE_DEPTH};

    /// Same bounds the CLI uses by default, so the tests exercise the shipped policy.
    fn read(path: &str) -> Result<Collection> {
        collection_from_json(path, DEFAULT_MAX_RESPONSE_BYTES, DEFAULT_MAX_TRACE_DEPTH)
    }

    /// The real captured response, committed as a fixture — not a hand-written imitation.
    fn captured() -> String {
        format!(
            "{}/tests/fixtures/usdc-transfer-18214590.calltracer.json",
            env!("CARGO_MANIFEST_DIR")
        )
    }

    #[test]
    fn a_captured_calltracer_file_builds_the_same_two_frame_tree() {
        let c = read(&captured()).expect("the fixture parses");
        assert_eq!(c.trace.len(), 2);
        assert_eq!(c.logs.len(), 0, "a trace alone carries no logs");
        assert!(c.tx.is_none(), "and no transaction metadata either");
        assert!(
            c.provenance().contains("file"),
            "the provenance must say this was not a node read: {}",
            c.provenance()
        );
    }

    #[test]
    fn a_json_rpc_envelope_is_unwrapped_not_rejected() {
        let inner = std::fs::read_to_string(captured()).unwrap();
        let path = temp(
            "envelope",
            &format!(
                "{{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{inner}}}",
                inner = inner
            ),
        );
        let c = read(&path).expect("envelope parses");
        assert_eq!(c.trace.len(), 2);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_captured_error_response_is_refused_not_read_as_an_empty_trace() {
        // This is the dangerous one: "-32603: internal error" parsed as a tree would
        // report a transaction that did nothing.
        let path = temp(
            "err",
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"internal error"}}"#,
        );
        let e = read(&path).unwrap_err();
        assert!(e.to_string().contains("JSON-RPC error"), "{e}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn an_object_that_is_not_a_frame_is_refused() {
        let path = temp("notframe", r#"{"foo":1,"bar":2}"#);
        let e = read(&path).unwrap_err();
        let msg = e.to_string();
        assert!(
            msg.contains("foo") && msg.contains("bar"),
            "name what it saw: {msg}"
        );
        let _ = std::fs::remove_file(&path);

        let empty = temp("empty", "{}");
        assert!(
            read(&empty).is_err(),
            "an empty object is not an empty trace"
        );
        let _ = std::fs::remove_file(&empty);
    }

    #[test]
    fn a_missing_file_is_a_usage_error_naming_the_path() {
        let e = read("/nonexistent/necropsy-trace.json").unwrap_err();
        assert!(
            e.to_string().contains("/nonexistent/necropsy-trace.json"),
            "{e}"
        );
        assert_eq!(crate::exit::Exit::from_error(&e), crate::exit::Exit::Usage);
    }
}
