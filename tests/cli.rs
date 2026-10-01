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

#[test]
fn the_narrative_refuses_to_be_combined_with_the_json_report() {
    // The JSON document carries the tree as data, so a second rendering of it would be
    // a second thing to keep in sync. The flag says so at parse time instead of
    // silently producing one of the two.
    necropsy()
        .arg("--rpc-url")
        .arg(DEAD)
        .arg("--narrative")
        .arg("--json")
        .arg(HASH)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("--narrative"));
}

#[test]
fn the_narrative_flag_is_documented() {
    necropsy()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("--narrative"));
}

// --- --from-json: analysing a captured trace without dialling a node -------------------

/// The committed fixture is a real callTracer response for the transaction the README
/// documents, so this exercises the offline path against captured data rather than a
/// hand-written imitation of one.
fn fixture_path() -> String {
    format!(
        "{}/tests/fixtures/usdc-transfer-18214590.calltracer.json",
        env!("CARGO_MANIFEST_DIR")
    )
}

#[test]
fn a_captured_trace_is_reported_as_degraded_because_no_receipt_came_with_it() {
    // The exit code is the point: an offline trace has no logs and no transaction
    // metadata, and reporting that as a complete answer (exit 0) is the failure mode
    // this whole tool exists to avoid.
    necropsy()
        .arg("--from-json")
        .arg(fixture_path())
        .arg(HASH)
        .assert()
        .code(4)
        .stdout(predicate::str::contains("offline JSON file"))
        .stdout(predicate::str::contains("no token transfer is known"))
        // The two places a missing receipt must not be rendered as a measurement.
        .stdout(predicate::str::contains(
            "logs none supplied (no receipt came with this file)",
        ))
        .stdout(predicate::str::contains(
            "token movements are unknown, not zero",
        ))
        .stdout(predicate::str::contains("log(s) on the receipt").not());
}

#[test]
fn a_file_input_refuses_the_node_only_flags() {
    // Silently ignoring --rpc-url would leave a reader unsure which input was analysed.
    necropsy()
        .arg("--from-json")
        .arg(fixture_path())
        .arg("--rpc-url")
        .arg(DEAD)
        .arg(HASH)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("--from-json"));
}

#[test]
fn help_does_not_echo_the_endpoint_it_found_in_the_environment() {
    // `--help` is the most-pasted output a CLI has. An env default printed verbatim turns a
    // request for usage into a credential disclosure, which is the one rule the report itself
    // already keeps.
    necropsy()
        .env(
            "ETH_RPC_URL",
            "https://provider.example/v2/SECRETheader1234",
        )
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("ETH_RPC_URL"))
        .stdout(predicate::str::contains("SECRETheader1234").not());
}

#[test]
fn an_endpoint_left_in_the_environment_does_not_refuse_a_file_input() {
    // The other half of that rule. `ETH_RPC_URL` is exported by habit by anyone who uses a
    // node daily — refusing here would make --from-json unusable for exactly the people who
    // need it, and the workaround ("unset it first") is how a flag gets quietly dropped.
    // The URL is a dead port, so this passing also proves nothing was dialled.
    necropsy()
        .env("ETH_RPC_URL", DEAD)
        .arg("--from-json")
        .arg(fixture_path())
        .arg(HASH)
        .assert()
        .code(4)
        .stdout(predicate::str::contains("offline JSON file"));
}

#[test]
fn a_captured_trace_cannot_answer_a_chain_guard() {
    // Nothing in a bare trace records which chain it came from, so `--chain` has nothing to
    // check against. The guard must fail closed rather than accept a file that happens to
    // look like the chain the operator meant.
    necropsy()
        .arg("--from-json")
        .arg(fixture_path())
        .arg("--chain")
        .arg("1")
        .arg(HASH)
        .assert()
        .code(3)
        .stderr(predicate::str::contains("no chain id"))
        .stderr(predicate::str::contains("--from-json"));
}

#[test]
fn a_missing_trace_file_is_a_usage_error_that_names_the_path() {
    necropsy()
        .arg("--from-json")
        .arg("/nonexistent/not-a-trace.json")
        .arg(HASH)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("/nonexistent/not-a-trace.json"));
}

#[test]
fn a_captured_error_response_is_not_read_as_an_empty_trace() {
    // The dangerous input: a saved "-32603 internal error" parsed as a frame tree would
    // report a transaction that did nothing.
    let path = temp_file(
        "err",
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"internal error"}}"#,
    );
    necropsy()
        .arg("--from-json")
        .arg(&path)
        .arg(HASH)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("JSON-RPC error"));
    let _ = std::fs::remove_file(&path);
}

/// A file in the temp dir, named for the process so parallel tests cannot collide.
fn temp_file(name: &str, body: &str) -> String {
    let mut path = std::env::temp_dir();
    path.push(format!("necropsy-cli-{name}-{}.json", std::process::id()));
    std::fs::write(&path, body).expect("temp written");
    path.to_string_lossy().into_owned()
}

#[test]
fn a_trace_nesting_past_the_bound_is_refused_with_the_number() {
    // 300 levels. `serde_json` would call this a parse error; the point of the guard is that
    // it is a *policy* answer the operator can move with a flag, naming both numbers.
    let nested = format!("{}1{}", "[".repeat(300), "]".repeat(300));
    let path = temp_file("deep", &nested);
    necropsy()
        .args(["--from-json", &path, "--max-trace-depth", "128"])
        .arg(HASH)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("--max-trace-depth"))
        .stderr(predicate::str::contains("300"));
    // The same file, bound raised: the depth guard lets it through, and the next one — is it
    // a frame at all — is what rejects it. Two different rules, two different sentences.
    necropsy()
        .args(["--from-json", &path, "--max-trace-depth", "512"])
        .arg(HASH)
        .assert()
        .code(2)
        .stderr(predicate::str::contains(
            "does not look like a callTracer frame",
        ));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_file_larger_than_the_read_limit_is_refused_before_it_is_parsed() {
    // 2 MiB of JSON against a 1 MB ceiling. Refusing after reading would have allocated it
    // anyway, but the point of the message is that the *file* is what was rejected.
    let big = format!(
        "{{\"type\":\"call\",\"from\":\"0x{}\",\"to\":\"0x{}\",\"input\":\"0x{}\",\"gas\":1,\"calls\":[]}}",
        "a".repeat(40),
        "b".repeat(40),
        "f".repeat(2 * 1024 * 1024)
    );
    let path = temp_file("big", &big);
    necropsy()
        .args(["--from-json", &path, "--max-response-mb", "1"])
        .arg(HASH)
        .assert()
        .code(2)
        .stderr(predicate::str::contains(
            "larger than the 1048576 byte read limit",
        ));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn build_info_answers_without_a_transaction_and_refuses_with_one() {
    // A packaging tool asks this to prove it unpacked the right binary, so it has to work with no
    // positional argument at all -- and it must not quietly ignore a hash someone also typed.
    necropsy()
        .arg("--build-info")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"tool\": \"necropsy\""))
        .stdout(predicate::str::contains("\"schema_version\""));

    necropsy()
        .arg("--build-info")
        .arg(HASH)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("One question per run"));

    // No transaction and no --build-info is still a usage error, not an empty report.
    necropsy()
        .assert()
        .code(2)
        .stderr(predicate::str::contains("<TX>"));
}

#[test]
fn build_info_reports_the_platform_the_binary_was_built_for() {
    // os/arch are read from the running process, which is the point: the value cannot be a string
    // the build system wrote into a manifest and then got wrong.
    necropsy()
        .arg("--build-info")
        .assert()
        .success()
        .stdout(predicate::str::contains(format!(
            "\"os\": \"{}\"",
            std::env::consts::OS
        )))
        .stdout(predicate::str::contains(format!(
            "\"arch\": \"{}\"",
            std::env::consts::ARCH
        )))
        .stdout(predicate::str::contains(format!(
            "\"version\": \"{}\"",
            env!("CARGO_PKG_VERSION")
        )));
}

#[test]
fn a_reader_that_went_away_is_not_a_failed_run() {
    // `necropsy … | head -2` closes the pipe while the report is still being written. Rust
    // ignores SIGPIPE, so that arrives as an EPIPE *write error*, and `println!` panics:
    // exit 101, outside the documented 0/2/3/4, for a pipeline the operator chose.
    use std::process::{Command, Stdio};
    let bin = env!("CARGO_BIN_EXE_necropsy");
    let mut child = Command::new(bin)
        .args(["--from-json", &fixture_path(), "--tree", "0"])
        .arg(HASH)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawned");
    // Closing the read end is the hang-up. The wide fixture is ~3,000 frames, so the report
    // is far larger than a pipe buffer and the write cannot complete quietly.
    drop(child.stdout.take());
    let out = child.wait_with_output().expect("waited");
    assert!(
        out.status.code() == Some(0),
        "a broken pipe must not be a crash: got {:?}",
        out.status
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        !err.contains("panicked"),
        "the printing layer panicked at the operator: {err}"
    );
}
