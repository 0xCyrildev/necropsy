//! Offline tests over **captured public chain data**.
//!
//! The unit suites build traces from inline strings, which is right for the cases nobody can
//! capture — a 6,000-frame nesting, an orphan the collector could not parent. What inline
//! strings cannot answer is "does this shape actually come out of a node?", so these fixtures
//! are a real `callTracer` response and a real receipt, captured once from mainnet for the
//! transaction the README documents and then committed. See `tests/fixtures/README.md` for
//! provenance.
//!
//! They exist to make one invariant checkable from data instead of from prose: the tree has 2
//! frames, the receipt has 1 log, and that log's global index is 293.

use necropsy::collect::{calltracer, receiptlogs};
use necropsy::model::{Collector, Provenance};

const TRACE: &str = "usdc-transfer-18214590.calltracer.json";
const RECEIPT: &str = "usdc-transfer-18214590.receipt.json";

fn fixture(name: &str) -> serde_json::Value {
    let path = format!("{}/tests/fixtures/{}", env!("CARGO_MANIFEST_DIR"), name);
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn prov() -> Provenance {
    Provenance {
        collector: Collector::CallTracerJson,
        cast_version: None,
        chain_id: Some(1),
        block: Some(18_214_590),
    }
}

#[test]
fn captured_trace_and_receipt_share_no_position() {
    // The second value is `nodes_seen`, not an error count: it exists so a caller can assert
    // that every frame in the payload became a frame in the tree. Two numbers that disagree
    // would mean the parser silently dropped something on the way in.
    let (trace, nodes_seen) =
        calltracer::build_trace(&fixture(TRACE), prov()).expect("the captured trace parses");
    assert_eq!(
        trace.len(),
        2,
        "the fixture is not the shape that was captured"
    );
    assert_eq!(
        nodes_seen,
        trace.len(),
        "the parser accounted for a different number of frames than the payload held"
    );

    let (logs, malformed) = receiptlogs::logs_from_receipt(&fixture(RECEIPT));
    assert_eq!(logs.len(), 1);
    assert_eq!(malformed, 0);
    assert_eq!(logs[0].log_index, 293);

    // The trap, as an assertion. Joining the two tables on position would attach log 293 to
    // the only other frame available, and the report would look exactly as confident. Both
    // sequences are real; neither one indexes the other.
    assert!(
        (trace.len() as u32) < logs[0].log_index,
        "if the frame count ever exceeds the log index, this fixture stops proving the point"
    );
}

#[test]
fn captured_receipt_log_classifies_as_a_fungible_move() {
    let (logs, _) = receiptlogs::logs_from_receipt(&fixture(RECEIPT));
    let (events, unclassified) = receiptlogs::classify(&logs);
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(
        unclassified, 0,
        "the log was recognised, so nothing is unaccounted for"
    );
    assert!(
        events[0].is_fungible_move(),
        "an ERC-20 Transfer must reach the ledger, not the unclassified bucket: {:?}",
        events[0]
    );
}
