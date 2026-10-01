//! Hostile input, without the word "fuzz" in the CI config.
//!
//! `cargo-fuzz` needs a nightly toolchain and a registry dependency nobody has reviewed for
//! this crate, and neither is worth it here: every entry point below takes bytes or a
//! `serde_json::Value` that somebody else wrote, so a *deterministic* corpus of degenerate
//! documents and mechanical mutations answers the question that matters — does a parse path
//! panic, or index past the end — without new machinery. It runs in well under a second and it
//! lives in `cargo test --all-targets`, so a regression is caught by the same command that
//! catches everything else.
//!
//! The bar is not "returns `Ok`". It is: **either** a report **or** a typed error. A panic is
//! the bug being looked for. Whether a given document should be accepted is decided by the
//! suites that assert content, not here.

use necropsy::collect::calltracer::build_trace;
use necropsy::collect::depth::{bounded_value, max_nesting};
use necropsy::collect::receiptlogs;
use necropsy::model::{Collector, Provenance};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicUsize, Ordering};

fn prov() -> Provenance {
    Provenance {
        collector: Collector::CallTracerJson,
        cast_version: None,
        chain_id: Some(1),
        block: Some(18_214_590),
    }
}

fn fixture_text() -> String {
    std::fs::read_to_string(format!(
        "{}/tests/fixtures/usdc-transfer-18214590.calltracer.json",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("the committed fixture")
}

/// The shapes a real endpoint and a real human produce, plus the ones only a bug or a proxy
/// page produces.
fn corpus() -> Vec<Value> {
    let real: Value = serde_json::from_str(&fixture_text()).unwrap();
    let wide: Vec<Value> = (0..200).map(|i| json!({"type": "call", "id": i})).collect();
    vec![
        real,
        json!(null),
        json!([]),
        json!({}),
        json!({"type": null, "from": null, "calls": null}),
        json!({"type": "call", "from": "not-an-address", "to": "", "input": "0x", "gas": -1}),
        json!({"type":"call","from":"0x00","calls":[{"type":"call","calls":[]}]}),
        json!({"input": "0xZZZZ", "gas": "0xgg", "value": "-1"}),
        json!({"value": u64::MAX, "gas": 9007199254740993_u64}),
        json!({"calls": wide}),
        json!({"type": "\u{0}\u{7f}🦀", "from": "\t\n", "to": "0x"}),
        json!({"result": {"error": {"code": -32603}}}),
        json!({"error": "internal error"}),
        // A gateway's HTML, arriving as bytes rather than as a status code.
        json!("<html><body>502</body></html>"),
    ]
}

/// Numbers no `Value` can hold, so they can only arrive as bytes. An endpoint is free to send
/// them: `serde_json` without `arbitrary_precision` has nowhere to put an integer past u64,
/// and how it says so is exactly the kind of thing a panic-on-untrusted-input claim turns on.
fn raw_corpus() -> Vec<&'static str> {
    vec![
        r#"{"value": 340282366920938463463374607431768211457}"#,
        r#"{"value": -170141183460469231731687303715884105728}"#,
        r#"{"gas": 1e400}"#,
        r#"{"gas": -1e400}"#,
        r#"{"gas": 1e-400}"#,
        r#"{"gas": 0.000000000000000000000000000000000000000000001}"#,
        r#"{"x": 00}"#,
        r#"{"x": 1.}"#,
        r#"{"x": .1}"#,
        r#"{"x": +1}"#,
        r#"{"nonce": 0x123}"#,
        r#""\ud800""#,
        r#""\q""#,
        r#"{"a":tru}"#,
    ]
}

/// Every mutation strategy runs over every corpus member. Deterministic: no RNG, so a failure
/// today reproduces tomorrow with the same line number.
fn mutate(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();

    // Truncation, at every 1/32th of the document — the shape a connection cut mid-response
    // produces.
    for i in 1..=32 {
        out.push(bytes[..bytes.len() * i / 32].to_vec());
    }
    // Single-byte flips over a bounded window: enough to break every structural token
    // (`"`, `{`, `[`, `:`, `,`, digits) without turning the suite into a minute of noise.
    let step = (bytes.len() / 240).max(1);
    for i in (0..bytes.len()).step_by(step) {
        for flip in [b'"', b'}', b']', b'\\', b'0', b'x', b'\n', 0xff] {
            let mut v = bytes.to_vec();
            v[i] = flip;
            out.push(v);
        }
    }
    // Inserted control characters, which is what a field that survives JSON but not a
    // hex/utf8 decoder looks like.
    for c in ['\u{0}', '\u{1b}', 'ÿ', '\u{feff}'] {
        let mut prefix = c.to_string().into_bytes();
        prefix.extend_from_slice(bytes);
        out.push(prefix);
        let mut suffix = bytes.to_vec();
        suffix.extend_from_slice(c.to_string().as_bytes());
        out.push(suffix);
    }
    out
}

#[test]
fn no_corpus_document_panics_the_depth_scanner() {
    for doc in corpus() {
        for bytes in mutate(doc.to_string().as_bytes()) {
            // The scanner is total by construction; the assertion is that it stays that way
            // under input nobody validated, including unbalanced brackets and invalid UTF-8.
            let _ = max_nesting(&bytes);
        }
    }
}

#[test]
fn no_corpus_document_panics_the_bounded_parser() {
    for doc in corpus() {
        for bytes in mutate(doc.to_string().as_bytes()) {
            // Any limit is fine here — the point is that the scan happens before the parse, so
            // the parser cannot be the thing that overflows.
            let _ = bounded_value(&bytes, 4096);
        }
    }
}

#[test]
fn numbers_past_what_a_json_number_holds_are_an_error_not_a_panic() {
    // The one family of inputs that a `Value`-based corpus cannot express, so it arrives here
    // as text. Whatever `serde_json` decides, it must decide by returning: an endpoint can
    // send these, and a panic would make a hostile answer indistinguishable from a crash.
    for raw in raw_corpus() {
        let outcome = std::panic::catch_unwind(|| bounded_value(raw.as_bytes(), 4096));
        match outcome {
            Err(_) => panic!("the parser panicked on {:?}", raw),
            Ok(Ok(value)) => {
                // Accepted is allowed (an out-of-range float may round to infinity), but a
                // number this extreme must not silently become a plausible integer.
                let as_int = value
                    .get("value")
                    .or_else(|| value.get("gas"))
                    .and_then(|v| v.as_i64());
                assert!(
                    as_int.is_none() || raw.len() < 40,
                    "{raw} was accepted as the integer {as_int:?}"
                );
            }
            Ok(Err(_)) => {}
        }
    }
}

#[test]
fn no_corpus_document_panics_the_trace_builder() {
    // A panic in any of these fails the test on its own, which is what a `#[test]` is for. The
    // counter is here to prove the mutations actually reached the builder instead of being
    // rejected one stage earlier — a green run that parsed nothing would prove nothing.
    let reached = AtomicUsize::new(0);
    for doc in corpus() {
        for bytes in mutate(doc.to_string().as_bytes()) {
            let Ok(value) = bounded_value(&bytes, 4096) else {
                continue;
            };
            let _ = build_trace(&value, prov());
            reached.fetch_add(1, Ordering::SeqCst);
        }
    }
    assert!(
        reached.load(Ordering::SeqCst) > 300,
        "the corpus handed only {} documents to the builder, so this proves nothing",
        reached.load(Ordering::SeqCst)
    );
}

#[test]
fn no_corpus_document_panics_the_receipt_log_classifier() {
    // Receipt logs arrive as an array of objects, and every field of one is attacker-writable.
    let logs = json!([
        {"address":"0x00","topics":[null,"0xzz"],"data":"0x","logIndex":"not-hex"},
        {"address": 5, "topics": "nope", "data": [], "logIndex": -3, "blockNumber": 1e300},
        {"topics": [[]]},
        "a log that is a string",
    ]);
    let value = json!({"logs": logs});
    for bytes in mutate(value.to_string().as_bytes()) {
        let Ok(doc) = bounded_value(&bytes, 4096) else {
            continue;
        };
        // Both halves of the real path: JSON to `RawLog`, then `RawLog` to an event class.
        let (parsed, _unclassified) = receiptlogs::logs_from_receipt(&doc);
        let _ = receiptlogs::classify(&parsed);
    }
}

#[test]
fn a_truncated_real_trace_is_an_error_not_a_smaller_tree() {
    // The plausible accident: a proxy that cuts the response mid-array. If that parses at all
    // it must be a *JSON* error, never a tree with fewer frames than the transaction had.
    let text = fixture_text();
    let bytes = text.as_bytes();
    for i in (1..bytes.len()).step_by((bytes.len() / 40).max(1)) {
        let outcome = bounded_value(&bytes[..i], 4096);
        assert!(
            outcome.is_err(),
            "a truncated trace parsed into something at {i} bytes: {outcome:?}"
        );
    }
}
