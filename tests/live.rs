//! Live endpoint contract — **opt-in and `#[ignore]`d**, so `cargo test --all-targets` and CI never dial
//! a node. These encode the checks that were, until now, manual: run once by hand, reported in prose, and
//! gone. An endpoint-only regression — a `debug_` namespace that disappears, a refusal that reads like
//! absent evidence, a token that stops answering `decimals()` — used to be caught by nobody until someone
//! thought to look.
//!
//! ```sh
//! NECROPSY_LIVE_URL=https://eth.drpc.org cargo test --test live -- --ignored --nocapture
//! ```
//!
//! `NECROPSY_LIVE_TX` overrides which transaction is examined. It defaults to the one documented in the
//! README, because that one has a known shape: two frames, one receipt log, an ERC-20 with 6 decimals, and
//! a `#293`-style global log index that is nowhere near the frame count — the standing proof that the tree
//! and the receipt logs must not be joined positionally.
//!
//! A failure here is not automatically a defect in necropsy: a public endpoint can rate-limit, shed, or
//! change namespace support between two runs. Read the message before believing the red.

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;

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
    let out = necropsy()
        .arg("--rpc-url")
        .arg(&url)
        .arg(&tx)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8_lossy(&out);
    assert!(text.contains("Call tree"), "no tree was rendered: {text}");
    assert!(
        text.contains("balances    yes"),
        "line conservation did not balance — the report should be marked suspect:\n{text}"
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
    let out = necropsy()
        .arg("--rpc-url")
        .arg(&url)
        .arg("--json")
        .arg(&tx)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let doc: Value = serde_json::from_slice(&out).expect("--json must parse");
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
        // 256-bit amounts leave the tool as strings. A JSON number silently loses precision past 2^53, and
        // a consumer that re-adds the lost digits gets a confident wrong number.
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
        "tokens were asked, so the counts must travel with the rows: {doc}"
    );
}

#[test]
#[ignore = "dials a live endpoint twice"]
fn live_collectors_agree_on_where_the_money_went() {
    let Some((url, tx)) = live() else { skipped!() };
    let run = |collector: &str| -> Option<Value> {
        let out = necropsy()
            .args([
                "--rpc-url",
                url.as_str(),
                "--collector",
                collector,
                "--json",
            ])
            .arg(&tx)
            .output()
            .ok()?;
        if !out.status.success() {
            eprintln!(
                "{} collector did not answer: {}",
                collector,
                String::from_utf8_lossy(&out.stderr)
                    .lines()
                    .next()
                    .unwrap_or("")
            );
            return None;
        }
        serde_json::from_slice(&out.stdout).ok()
    };

    let Some(rpc) = run("rpc") else {
        eprintln!("SKIPPED: the rpc collector could not read this endpoint");
        return;
    };
    let Some(cast) = run("cast") else {
        // Not a failure: `cast` needs Foundry installed and a node it can render from. Absence of the
        // second mechanism is a missing environment, not a wrong answer.
        eprintln!("SKIPPED: the cast collector was unavailable, so the two could not be compared");
        return;
    };

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
    necropsy()
        .arg("--rpc-url")
        .arg(&url)
        .arg("--baseline-tx-hash")
        .arg(&tx)
        .arg(&tx)
        .assert()
        .success()
        .stdout(predicate::str::contains("tautology"))
        .stdout(predicate::str::contains("structurally identical"));
}

#[test]
#[ignore = "dials a live endpoint"]
fn live_chain_guard_stops_a_wrong_chain() {
    let Some((url, tx)) = live() else { skipped!() };
    // 999999 is not a chain anyone serves; the run must stop rather than price one chain from another.
    necropsy()
        .arg("--rpc-url")
        .arg(&url)
        .arg("--chain")
        .arg("999999")
        .arg(&tx)
        .assert()
        .code(3)
        .stderr(predicate::str::contains("chain"));
}

#[test]
#[ignore = "dials a live endpoint"]
fn live_declined_decimals_blame_the_operator_not_a_node() {
    let Some((url, tx)) = live() else { skipped!() };
    let out = necropsy()
        .args(["--rpc-url", url.as_str(), "--no-decimals"])
        .arg(&tx)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8_lossy(&out);
    assert!(text.contains("decimals unknown"), "{text}");
    assert!(
        text.contains("--no-decimals was given"),
        "the reason must read as a choice, not a failure:\n{text}"
    );
    assert!(
        !text.contains("(ERC-20, ") || !text.contains(" decimals)"),
        "nothing should have been scaled:\n{text}"
    );
}
