//! Live endpoint contract — **opt-in and `#[ignore]`d**, so `cargo test --all-targets` and the ordinary
//! CI job never dial a node. These encode the checks that were, until now, manual: run once by hand,
//! reported in prose, and gone. An endpoint-only regression — a `debug_` namespace that disappears, a
//! collector that starts disagreeing with the other, an amount that stops being a string — used to be
//! caught by nobody until someone thought to look.
//!
//! ```sh
//! NECROPSY_LIVE_URL=https://eth.drpc.org cargo test --test live -- --ignored --nocapture
//! ```
//!
//! `NECROPSY_LIVE_TX` overrides which transaction is examined; empty means "use the default". The
//! default is the transaction documented in the README, because its shape is known: two frames, one
//! receipt log, an ERC-20 with 6 decimals, and a global log index nowhere near the frame count — the
//! standing proof that the tree and the receipt logs must not be joined positionally. Point it at
//! another chain and the assertions about *this* transaction's shape stop meaning anything.
//!
//! ## What a red run means here, and what it does not
//!
//! Reading is separated from judging. **Exit 3 — "nothing could be read" — skips rather than failing:**
//! a rate limit, a node that dropped its `debug_` namespace, or a pruned endpoint that no longer holds
//! the transaction are facts about the environment, and letting them fail the job would train whoever
//! reads the result to ignore it. What these tests do fail on is the *content* of a report that was
//! successfully read, because that is the surface a regression in necropsy actually moves. A usage
//! error (exit 2) is never excused — the command line is ours to get right.

use assert_cmd::Command;
use serde_json::Value;
use std::process::Output;

const DEFAULT_TX: &str = "0x5b515946dc1177149f140777ac90879312b182117e3392e8e2703ed3cd697153";

fn live() -> Option<(String, String)> {
    let url = std::env::var("NECROPSY_LIVE_URL")
        .ok()
        .map(|u| u.trim().to_string())
        .filter(|u| !u.is_empty())?;
    let tx = std::env::var("NECROPSY_LIVE_TX")
        .ok()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .unwrap_or_else(|| DEFAULT_TX.to_string());
    Some((url, tx))
}

fn necropsy() -> Command {
    let mut c = Command::cargo_bin("necropsy").expect("the binary builds for tests");
    // The ambient variable must not silently decide which endpoint a live check hits.
    c.env_remove("ETH_RPC_URL");
    c
}

fn run(url: &str, extra: &[&str], tx: &str) -> Output {
    let mut c = necropsy();
    c.arg("--rpc-url").arg(url);
    c.args(extra);
    c.arg(tx);
    c.output().expect("the binary runs")
}

/// The report if the endpoint gave one; `None` after naming why it could not.
fn read(url: &str, extra: &[&str], tx: &str) -> Option<Output> {
    let out = run(url, extra, tx);
    match out.status.code() {
        Some(0) => Some(out),
        Some(3) => {
            let why = String::from_utf8_lossy(&out.stderr)
                .lines()
                .next()
                .unwrap_or("(no message)")
                .to_string();
            eprintln!("SKIPPED — environment, not a defect: the endpoint could not be read: {why}");
            None
        }
        Some(c) => panic!(
            "unexpected exit {c} (a usage error is ours, never the node's): {}",
            String::from_utf8_lossy(&out.stderr)
        ),
        None => panic!("the process was terminated by a signal"),
    }
}

fn text_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

macro_rules! skipped {
    () => {{
        eprintln!("SKIPPED: set NECROPSY_LIVE_URL to a reachable endpoint with a debug_ namespace");
        return;
    }};
}

#[test]
#[ignore = "dials a live endpoint; run with: cargo test --test live -- --ignored"]
fn live_report_accounts_for_every_input_line() {
    let Some((url, tx)) = live() else { skipped!() };
    let Some(out) = read(&url, &[], &tx) else {
        return;
    };
    let text = text_of(&out);
    assert!(text.contains("Call tree"), "no tree was rendered: {text}");
    assert!(
        text.contains("balances    yes"),
        "line conservation did not balance, so the report must say so:\n{text}"
    );
    assert!(!text.contains("treat this report as suspect"), "{text}");
    assert!(
        text.contains("(ERC-20, ") && text.contains(" decimals)"),
        "no token answered decimals() on a transaction that moved an ERC-20:\n{text}"
    );
}

#[test]
#[ignore = "dials a live endpoint"]
fn live_json_is_a_consumable_document_with_string_amounts() {
    let Some((url, tx)) = live() else { skipped!() };
    let Some(out) = read(&url, &["--json"], &tx) else {
        return;
    };
    let doc: Value = serde_json::from_slice(&out.stdout).expect("--json must parse");
    for key in [
        "tool",
        "version",
        "degraded",
        "hash",
        "tx",
        "provenance",
        "accounting",
        "trace",
        "events",
        "ledger",
        "notes",
    ] {
        assert!(doc.get(key).is_some(), "missing top-level key {key}: {doc}");
    }
    let rows = doc["ledger"]["rows"].as_array().expect("rows is an array");
    assert!(
        !rows.is_empty(),
        "a value-moving tx produced no ledger rows: {doc}"
    );
    for row in rows.iter().take(3) {
        // 256-bit amounts leave the tool as strings. A JSON number loses precision past 2^53, and a
        // consumer that re-adds the lost digits gets a confident wrong number.
        for field in ["inflow", "outflow", "net"] {
            assert!(
                row[field].is_string(),
                "{field} must be a string, got {}: {row}",
                row[field]
            );
        }
    }
    assert!(
        doc["decimals"].is_object(),
        "tokens were asked, so their counts must travel with the rows: {doc}"
    );
}

#[test]
#[ignore = "dials a live endpoint twice"]
fn live_collectors_agree_on_where_the_money_went() {
    let Some((url, tx)) = live() else { skipped!() };
    let json_for = |collector: &'static str| -> Option<Value> {
        read(&url, &["--collector", collector, "--json"], &tx)
            .and_then(|o| serde_json::from_slice(&o.stdout).ok())
    };
    // Each side skips on its own if the mechanism is unavailable: `cast` needs Foundry, the rpc
    // collector needs a debug_ namespace. A missing second mechanism is a thinner comparison, not a
    // wrong answer, so it must not be allowed to read as a defect.
    let Some(rpc) = json_for("rpc") else { return };
    let Some(cast) = json_for("cast") else { return };

    assert_eq!(
        rpc["accounting"]["frames_total"], cast["accounting"]["frames_total"],
        "the collectors disagreed on how many frames this transaction has"
    );
    assert_eq!(
        rpc["ledger"]["rows"], cast["ledger"]["rows"],
        "the two collectors produced different ledgers for one transaction"
    );
}

#[test]
#[ignore = "dials a live endpoint"]
fn live_diff_against_itself_is_called_a_tautology() {
    let Some((url, tx)) = live() else { skipped!() };
    let t = tx.as_str();
    let Some(out) = read(&url, &["--baseline-tx-hash", t], &tx) else {
        return;
    };
    let text = text_of(&out);
    assert!(
        text.contains("tautology"),
        "a diff against the same hash must be named a tautology, not a match:\n{text}"
    );
    assert!(text.contains("structurally identical"), "{text}");
}

#[test]
#[ignore = "dials a live endpoint"]
fn live_chain_guard_stops_a_wrong_chain() {
    let Some((url, tx)) = live() else { skipped!() };
    // Positive control first. Without it a dead endpoint returns exit 3 for its own reasons and the
    // guard looks like it worked when nothing was ever compared.
    if read(&url, &[], &tx).is_none() {
        return;
    }
    let out = run(&url, &["--chain", "999999"], &tx);
    assert_eq!(
        out.status.code(),
        Some(3),
        "--chain must stop the run rather than price one chain from another: {}",
        text_of(&out)
    );
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        err.contains("chain"),
        "the refusal must name the guard: {err}"
    );
}

#[test]
#[ignore = "dials a live endpoint"]
fn live_declined_decimals_blame_the_operator_not_a_node() {
    let Some((url, tx)) = live() else { skipped!() };
    let Some(out) = read(&url, &["--no-decimals"], &tx) else {
        return;
    };
    let text = text_of(&out);
    assert!(text.contains("decimals unknown"), "{text}");
    assert!(
        text.contains("--no-decimals was given"),
        "the reason must read as a choice, not a failure:\n{text}"
    );
    assert!(
        !text.contains(" decimals)"),
        "nothing should have been scaled:\n{text}"
    );
}
