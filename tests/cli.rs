//! End-to-end exit-status tests.
//!
//! The unit tests cover the pipeline; these cover the *contract with scripts*,
//! which is what a triage queue actually reads. Every case is offline: port 1
//! (tcpmux) is a reserved port nothing serves, so a connection is refused
//! immediately instead of after a timeout or a network round trip.

use assert_cmd::Command;
use predicates::prelude::*;

const HASH: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DEAD: &str = "http://127.0.0.1:1";

fn necropsy() -> Command {
    let mut c = Command::cargo_bin("necropsy").expect("the binary builds for tests");
    // The ambient environment must not decide whether a test passes: a developer's
    // real ETH_RPC_URL would turn these offline cases into live network calls.
    c.env_remove("ETH_RPC_URL");
    c
}

#[test]
fn a_hash_that_is_not_a_hash_is_a_usage_error() {
    necropsy()
        .arg("--rpc-url")
        .arg(DEAD)
        .arg("nonsense")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("invalid transaction hash"));
}

#[test]
fn no_endpoint_configured_is_usage_not_unavailability() {
    necropsy()
        .arg(HASH)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("no RPC endpoint configured"));
}

#[test]
fn an_empty_environment_variable_counts_as_no_endpoint() {
    // `ETH_RPC_URL=` is how CI "unsets" a variable it declared. Passing an empty
    // string through as a URL would surface as a transport failure (3), which
    // tells the operator to go fix the network instead of the config.
    necropsy()
        .env("ETH_RPC_URL", "")
        .arg(HASH)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("no RPC endpoint configured"));
}

#[test]
fn an_unreachable_endpoint_is_unavailable() {
    // Nothing was read: no findings, no partial report. Exit 0 here was the
    // pre-rework defect this whole status enum exists to fix.
    necropsy()
        .arg("--rpc-url")
        .arg(DEAD)
        .arg(HASH)
        .assert()
        .code(3);
}

#[test]
fn failure_prints_nothing_on_stdout() {
    // A caller piping stdout into an evidence file must not receive a half-report
    // that reads like an answer.
    let out = necropsy()
        .arg("--rpc-url")
        .arg(DEAD)
        .arg(HASH)
        .output()
        .expect("runs");
    assert!(
        out.stdout.is_empty(),
        "stdout must stay empty on failure: {:?}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(!out.stderr.is_empty(), "the reason must reach stderr");
}

#[test]
fn a_key_in_the_endpoint_url_never_reaches_the_terminal() {
    // The property under test is *no leak*, not "a marker was printed": this
    // endpoint is refused at the transport layer, so the message happens to contain
    // no URL and nothing needs redacting. Asserting a marker here would test the
    // shape of one provider's error string. The redaction path itself is covered by
    // `error`'s unit tests, which feed it messages that do embed the URL.
    let secret = "SuperSecretKeyValue1234567";
    let url = format!("{DEAD}/v2/{secret}");
    let out = necropsy()
        .arg("--rpc-url")
        .arg(&url)
        .arg("--verbose")
        .arg(HASH)
        .output()
        .expect("runs");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains(secret),
        "the key leaked into stderr: {stderr}"
    );
    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn an_unknown_flag_is_the_same_usage_status_as_a_bad_hash() {
    // Deliberate: clap's argument-error code is 2, and `Exit::Usage` is 2, so a
    // caller has one status for "the command was wrong" rather than two.
    necropsy().arg("--not-a-flag").arg(HASH).assert().code(2);
}

#[test]
fn a_bad_baseline_hash_is_a_usage_error_that_never_dials_the_endpoint() {
    // The point of parsing both hashes up front: a typo in the second one is not
    // allowed to cost a fetch of the first. The endpoint here is a reserved port
    // nothing serves, so reaching the network would change the status to 3.
    necropsy()
        .arg("--rpc-url")
        .arg(DEAD)
        .arg("--baseline-tx-hash")
        .arg("0zzz")
        .arg(HASH)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("invalid transaction hash"));
}

#[test]
fn a_baseline_is_read_from_the_same_endpoint_and_its_absence_is_unavailability() {
    // Not a usage error: the command was well formed, the node could not answer.
    necropsy()
        .arg("--rpc-url")
        .arg(DEAD)
        .arg("--baseline-tx-hash")
        .arg(HASH)
        .arg(HASH)
        .assert()
        .code(3);
}

#[test]
fn the_baseline_flag_documents_itself_as_structural() {
    // The name and the caveat are the interface. A reader who thinks this compares
    // amounts will over-read the output, so the help text carries the limit.
    necropsy()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("--baseline-tx-hash"))
        .stdout(predicate::str::contains("Structural only"));
}

#[test]
fn a_baseline_endpoint_without_a_baseline_transaction_is_a_usage_error() {
    // Naming a second endpoint and no second transaction is a typo, not a mode: it
    // would silently read the baseline from the first endpoint and answer a different
    // question than the one the operator meant.
    necropsy()
        .arg("--rpc-url")
        .arg(DEAD)
        .arg("--baseline-rpc-url")
        .arg(DEAD)
        .arg(HASH)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("baseline"));
}
