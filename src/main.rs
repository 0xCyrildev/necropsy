//! necropsy — the command line.
//!
//! Deliberately thin: it parses arguments, moves bytes, and chooses an exit
//! status. Every decision that affects an answer lives in the library, where it
//! can be tested without spawning a process.
//!
//! Exit statuses are the contract with scripts (`necropsy::exit`): a run that
//! could not read anything must not look like a run that found nothing.

// The production code of the binary is held to the library's rule. `#![forbid]` cannot be
// re-allowed locally, so the exception is scoped by `cfg` instead: one test clears `PATH` to
// prove the `cast` fallback fails cleanly, and that test is the only unsafe in the tree.
#![cfg_attr(not(test), forbid(unsafe_code))]

use clap::parser::ValueSource;
use clap::{CommandFactory, FromArgMatches, Parser, ValueEnum};
use necropsy::collect::castbin::{self, CastMode};
use necropsy::collect::decimals::Decimals;
use necropsy::collect::rpc::HttpRpc;
use necropsy::collect::{self, CollectorChoice};
use necropsy::error::{Error, Redactor, Result};
use necropsy::exit::Exit;
use necropsy::{ledger, report};
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(
    name = "necropsy",
    version,
    about = "Post-transaction forensics for EVM: reconstruct the call tree and rank where value ended up"
)]
struct Args {
    /// Transaction hash: 0x plus 64 hex digits.
    tx: String,

    /// A second transaction from the same endpoint, to compare the call tree against.
    /// Structural only: it reports shape differences and compares no amounts, so a
    /// difference is a question for a reviewer and never changes the exit status.
    #[arg(long, value_name = "HASH")]
    baseline_tx_hash: Option<String>,

    /// Where to read the baseline from. Defaults to `--rpc-url`; set it to compare how
    /// two providers answer for the same transaction, or one chain against another.
    /// `--chain` then guards both endpoints, not just this one.
    #[arg(long, value_name = "URL", requires = "baseline_tx_hash")]
    baseline_rpc_url: Option<String>,

    /// JSON-RPC endpoint. Falls back to ETH_RPC_URL. The value is deliberately not echoed
    /// in `--help`: clap prints an env default verbatim, and a provider URL is a credential
    /// — `--help` is the one output people paste into an issue or a chat window.
    #[arg(long, env = "ETH_RPC_URL", hide_env_values = true)]
    rpc_url: Option<String>,

    /// Refuse to analyze unless the endpoint agrees this is the chain you mean.
    /// Pricing chain A while reading chain B produces a report that looks normal.
    #[arg(long)]
    chain: Option<u64>,

    /// How to obtain the trace.
    #[arg(long, value_enum, default_value = "auto")]
    collector: CollectorArg,

    /// For the `cast` collector: read the node's tracer, or re-execute the block
    /// locally. Replay needs archive state and can diverge from what chain did.
    #[arg(long, value_enum, default_value = "rendered")]
    cast_mode: CastModeArg,

    /// Analyse a captured `callTracer` response from a file instead of dialling a node.
    /// Accepts the bare frame object or a JSON-RPC envelope. Such a file holds no receipt,
    /// so no token movement is known and the run exits 4 (degraded): a smaller answer is
    /// reported as smaller, never as a complete one. An `ETH_RPC_URL` left in the
    /// environment is ignored; `--rpc-url` typed beside this is refused, because a run has
    /// one source.
    #[arg(long, value_name = "PATH",
          conflicts_with_all = ["collector", "baseline_tx_hash", "baseline_rpc_url"])]
    from_json: Option<String>,

    /// Emit the machine-readable report instead of the text one.
    #[arg(long)]
    json: bool,

    /// Do not ask each token for its decimal count; print base units only. This saves
    /// one `eth_call` per token, which matters on a node without archive state — where
    /// the calls would fail anyway and every amount would stay in base units regardless.
    #[arg(long)]
    no_decimals: bool,

    /// Call-tree lines to print; 0 prints every frame.
    #[arg(long, default_value_t = report::DEFAULT_TREE_LIMIT)]
    tree: usize,

    /// Also print the flat execution narrative: the same frames as a numbered sequence
    /// naming each call's parent, for reading a story instead of tracing an indent. Text
    /// report only — `--json` already carries the tree as data, so the two conflict.
    #[arg(long, conflicts_with = "json")]
    narrative: bool,

    /// Per-request timeout, in seconds.
    #[arg(long, default_value_t = 60)]
    timeout: u64,

    /// Print a provider's full error text (still redacted) rather than one line.
    #[arg(long)]
    verbose: bool,

    /// Refuse a JSON-RPC response larger than this, instead of reading it. The default is
    /// ~500x the largest mainnet trace measured here (62 KB), and the alternative is
    /// letting a gateway's HTML error page, or a hostile endpoint, decide this process's
    /// memory.
    #[arg(long, value_name = "MB", default_value_t = 32)]
    max_response_mb: u32,

    /// Refuse a trace that nests deeper than this, instead of recursing into it. Nesting is
    /// what a stack is spent on, and a re-entrancy exploit is exactly the deep case: the
    /// number is a budget, not a judgement about the transaction.
    #[arg(long, value_name = "LEVELS", default_value_t = 2048)]
    max_trace_depth: usize,
}

#[derive(ValueEnum, Debug, Clone, Copy)]
enum CollectorArg {
    Auto,
    Rpc,
    Cast,
}

#[derive(ValueEnum, Debug, Clone, Copy)]
enum CastModeArg {
    Rendered,
    Replay,
}

impl From<CollectorArg> for CollectorChoice {
    fn from(c: CollectorArg) -> Self {
        match c {
            CollectorArg::Auto => CollectorChoice::Auto,
            CollectorArg::Rpc => CollectorChoice::Rpc,
            CollectorArg::Cast => CollectorChoice::Cast,
        }
    }
}

impl From<CastModeArg> for CastMode {
    fn from(m: CastModeArg) -> Self {
        match m {
            CastModeArg::Rendered => CastMode::Rendered,
            CastModeArg::Replay => CastMode::Replay,
        }
    }
}

fn main() -> std::process::ExitCode {
    // Matches are taken directly, not through `Args::parse`, because one question below
    // cannot be answered from the parsed struct: whether `--rpc-url` was *typed* or merely
    // picked up from `ETH_RPC_URL`. Only the typed form contradicts `--from-json`.
    let cmd = Args::command();
    let matches = cmd
        .try_get_matches_from(std::env::args_os())
        .unwrap_or_else(|e| e.exit());
    let endpoint_named = matches.value_source("rpc_url") == Some(ValueSource::CommandLine);
    let args = Args::from_arg_matches(&matches).unwrap_or_else(|e| e.exit());
    match run(&args, endpoint_named) {
        Ok((mut body, status)) => {
            body.push('\n');
            match write_out(&body) {
                Write::Done => status.into(),
                // The reader closed the pipe. The analysis succeeded and its bytes went as far
                // as anyone wanted them; `| head` is not a failed investigation, and a panic
                // here would report 101 — a code outside the documented contract — for a
                // pipeline the operator built on purpose.
                Write::Gone => Exit::Ok.into(),
                Write::Failed(why) => {
                    eprintln!("necropsy: could not write the report: {why}");
                    Exit::Unavailable.into()
                }
            }
        }
        Err(e) => {
            // The error goes to stderr, which can be closed too. There is nothing left to
            // report *that* to, so the exit status is the only surviving signal.
            let _ = write_err(&format!("necropsy: {}\n", message(&args, &e)));
            Exit::from_error(&e).into()
        }
    }
}

enum Write {
    Done,
    Gone,
    Failed(String),
}

/// Write one block of text without trusting the reader to still be there.
///
/// Rust ignores `SIGPIPE` at startup, so a closed pipe arrives as an `EPIPE` *error* — and
/// `println!` turns that error into a panic. This is the printing layer's own version of the
/// rule the rest of the tool follows: a failure to deliver is reported as one, with a status
/// a script can read, and never as a crash or a silent success.
fn write_out(text: &str) -> Write {
    write_with(std::io::stdout(), text)
}

fn write_err(text: &str) -> Write {
    write_with(std::io::stderr(), text)
}

fn write_with(mut stream: impl std::io::Write, text: &str) -> Write {
    match stream
        .write_all(text.as_bytes())
        .and_then(|_| stream.flush())
    {
        Ok(()) => Write::Done,
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Write::Gone,
        Err(e) => Write::Failed(e.to_string()),
    }
}

fn run(args: &Args, endpoint_named: bool) -> Result<(String, Exit)> {
    let hash = necropsy::collect::txdata::parse_tx_hash(&args.tx)?;
    // Parsed up front, with the target: a typo in the *second* hash should cost a
    // usage error immediately, not a transaction fetch that then gets thrown away.
    let baseline_hash = args
        .baseline_tx_hash
        .as_deref()
        .map(necropsy::collect::txdata::parse_tx_hash)
        .transpose()?;

    let timeout = Duration::from_secs(args.timeout.max(1));
    let mode = args.cast_mode.into();
    // Both bounds are read here rather than defaulted inside each reader, so one pair of
    // flags governs the network path and the file path alike. `max(1)` because 0 would
    // refuse every answer, which is not the failure the operator asked for.
    let max_bytes = args.max_response_mb.max(1) as u64 * 1024 * 1024;
    let max_depth = args.max_trace_depth.max(1);

    // Either a node is dialled or a file is read. clap refuses the node-only flags
    // alongside --from-json; an endpoint named on the command line is refused here, because
    // it says "dial" in the same breath as "read this file". `ETH_RPC_URL` does not: that is
    // configuration left in the environment, not an instruction about this transaction.
    if endpoint_named {
        if let Some(path) = args.from_json.as_deref() {
            return Err(Error::MixedSource {
                path: path.to_string(),
            });
        }
    }
    let node = if args.from_json.is_some() {
        None
    } else {
        // An empty `ETH_RPC_URL` is set-but-blank, which is how CI often "unset" a
        // variable. clap hands it over as a value, so without this the run would dial
        // an empty URL and fail as an unreachable endpoint rather than as unconfigured.
        let url = args
            .rpc_url
            .clone()
            .map(|u| u.trim().to_string())
            .filter(|u| !u.is_empty())
            .ok_or(Error::NoRpcUrl)?;
        // A second endpoint is opt-in. Without it the baseline is read from the same
        // node, and `--chain` stays the single guard it was. Set-but-blank applies here
        // too: an empty value means "same as --rpc-url", not "dial the empty string".
        let baseline_url = args
            .baseline_rpc_url
            .clone()
            .map(|u| u.trim().to_string())
            .filter(|u| !u.is_empty())
            .unwrap_or_else(|| url.clone());
        let (rpc, cast_cfg) = endpoint(&url, timeout, mode, max_bytes, max_depth);
        Some(Node {
            url,
            rpc,
            cast_cfg,
            baseline_url,
        })
    };

    let mut c = match (&node, args.from_json.as_deref()) {
        (Some(n), _) => collect::collect(
            n.rpc.clone(),
            hash,
            args.collector.into(),
            Some(n.cast_cfg.clone()),
        )?,
        // The file path gets the same sized stack as the node path, for the same reason:
        // dropping a nested `serde_json::Value` recurses, and the depth the operator allowed
        // with `--max-trace-depth` is a promise about memory, not about the main thread's
        // 2 MiB. It also gets the same two bounds, so `--from-json` is not the hole in a rule
        // that holds on the network.
        (None, Some(path)) => {
            let path = path.to_string();
            collect::with_large_stack(move || {
                collect::offline::collection_from_json(&path, max_bytes, max_depth)
            })
            .map_err(Error::Collect)??
        }
        (None, None) => return Err(Error::NoRpcUrl),
    };

    // A `--from-json` run has no endpoint to warn about, so this rides on the node path only.
    if let Some(n) = &node {
        if let Some(note) = cleartext_note(&n.url) {
            c.notes.push(note);
        }
    }
    let l = ledger::build(&c.events, &c.trace, c.tx.as_ref().and_then(|m| m.status));

    if let Some(wanted) = args.chain {
        let at = match &node {
            Some(n) => n.rpc.describe(),
            // A file is the thing that would not say which chain it came from.
            None => "the file passed to --from-json".to_string(),
        };
        c.verify_chain(wanted, &at)?;
    }

    // Read the baseline *after* the target's chain guard, so an endpoint on the wrong
    // chain cannot spend a second request before the run stops. Two separate calls,
    // never a batch: these endpoints refuse batches whose members each work alone, and a
    // refusal would read exactly like a transaction that does not exist.
    let comparison = match (baseline_hash, &node) {
        (Some(bhash), Some(n)) => {
            let (brpc, bcast) = if n.baseline_url == n.url {
                (n.rpc.clone(), n.cast_cfg.clone())
            } else {
                endpoint(&n.baseline_url, timeout, mode, max_bytes, max_depth)
            };
            let baseline =
                collect::collect(brpc.clone(), bhash, args.collector.into(), Some(bcast))?;
            // Guarded on its own terms: with two endpoints, a `--chain` satisfied only
            // by the target would compare one chain's tree against another chain's.
            if let Some(wanted) = args.chain {
                baseline.verify_chain(wanted, &brpc.describe())?;
            }
            Some(necropsy::diff::compare(bhash, hash, &baseline, &c))
        }
        _ => None,
    };

    // Asked last, once every guard has passed: the ledger says which assets are worth
    // asking about, and a run that stops on a wrong chain should not have spent token
    // calls on the way. Both ways of not asking are reported as their own reason, so a
    // file input never reads as an operator who declined, or a decline as a node refusing.
    let asked_decimals = node.is_some() && !args.no_decimals;
    let decimals = match (&node, args.no_decimals, args.from_json.as_deref()) {
        (Some(n), false, _) => collect::decimals::fetch(
            &*n.rpc,
            &l.assets(),
            c.tx.as_ref().map(|m| m.block_tag()).as_deref(),
        ),
        // Each way of not asking gets its own sentence. A file input must not read as an
        // operator who declined, and a decline must not read as a node that refused.
        (None, _, Some(_)) => Decimals::unscaled(
            "--from-json supplied a trace with no node to ask, so no token's decimals() was fetched"
                .to_string(),
        ),
        (_, true, _) => Decimals::unscaled(
            "--no-decimals was given, so amounts stay in base units and no token was asked"
                .to_string(),
        ),
        (None, false, None) => Decimals::unscaled(
            "no endpoint was configured, so no token was asked".to_string(),
        ),
    };

    let body = if args.json {
        report::Report::build(&c, &l, hash)
            .with_decimals(asked_decimals.then_some(&decimals))
            .with_diff(comparison.as_ref())
            .to_json()?
    } else {
        report::text_with(
            &c,
            &l,
            hash,
            args.tree,
            comparison.as_ref(),
            &decimals,
            args.narrative,
        )
    };

    let status = if report::degraded(&c, &l) {
        Exit::Degraded
    } else {
        // A reverted transaction is a complete answer, not a failed run. Naming a
        // finding as one would need a severity model the tool does not have yet,
        // so `Exit::Findings` is deliberately unreachable from here. A non-empty
        // diff is not a finding either: `comparison` is never consulted below.
        Exit::Ok
    };

    Ok((body, status))
}

/// The node side of a run: the endpoint dialled for the target, and the second
/// endpoint if one was named. Absent entirely when the trace came from a file.
struct Node {
    url: String,
    rpc: collect::SharedRpc,
    cast_cfg: castbin::CastConfig,
    baseline_url: String,
}

/// One endpoint: an RPC handle, plus the `cast` configuration that makes `auto`'s
/// fallback possible on a node with no `debug_` namespace. Built twice only when
/// `--baseline-rpc-url` names a second one; constructing it never runs `cast`.
fn endpoint(
    url: &str,
    timeout: Duration,
    mode: CastMode,
    max_bytes: u64,
    max_depth: usize,
) -> (collect::SharedRpc, castbin::CastConfig) {
    let rpc: collect::SharedRpc =
        std::sync::Arc::new(HttpRpc::with_limits(url, timeout, 2, max_bytes, max_depth));
    let cast = castbin::CastConfig {
        max_bytes,
        rpc_url: url.to_string(),
        // Rendering a trace is not a JSON-RPC round trip; a timeout tuned for the
        // latter would kill the former.
        timeout: timeout.max(Duration::from_secs(120)),
        mode,
        external_identification: false,
    };
    (rpc, cast)
}

/// A plain-HTTP endpoint is legitimate — a local signer, an `anvil` on a dev box, an RPC
/// behind a sidecar proxy — but it is also the one configuration where a credential carried
/// in the URL travels in clear text. Refusing it would break the local cases; saying nothing
/// hides the remote one. So it is a note in the report, next to the numbers it does not
/// change, and the operator decides.
fn cleartext_note(url: &str) -> Option<String> {
    let rest = url.strip_prefix("http://")?;
    // Anything before the last `@` is userinfo, which is exactly the part that must not be
    // echoed. The host alone is what `Rpc::describe()` already prints by design.
    let authority = rest.split('@').next_back().unwrap_or(rest);
    // An IPv6 literal is bracketed and its host is full of colons, so splitting on `:` would
    // cut `[::1]:8545` down to `[` — which is not loopback and would warn about a local signer.
    let host = if let Some(bracketed) = authority.strip_prefix('[') {
        bracketed.split(']').next().unwrap_or(bracketed)
    } else {
        authority
            .split(['/', '?', ':', '#'])
            .next()
            .unwrap_or(authority)
    }
    .trim();
    if host.is_empty() || matches!(host, "localhost" | "127.0.0.1" | "::1" | "0.0.0.0" | "[::]") {
        return None;
    }
    Some(format!(
        "the endpoint is plain HTTP ({host}), so any credential in its URL crosses the network unencrypted"
    ))
}

/// An error message that cannot carry a credential, whatever the provider said.
///
/// Both endpoints are redacted. A baseline read from a different URL can fail with its
/// own key in the provider's text, and one URL's redactor knows nothing about the other.
fn message(args: &Args, e: &Error) -> String {
    let urls = [args.rpc_url.as_deref(), args.baseline_rpc_url.as_deref()]
        .into_iter()
        .flatten()
        .map(str::trim)
        .filter(|u| !u.is_empty())
        .collect::<Vec<_>>();
    let Some(first) = urls.first() else {
        return e.to_string();
    };
    let mut text = e.to_string();
    for url in &urls {
        text = Redactor::from_url(url).redact(&text);
    }
    if args.verbose {
        text
    } else {
        // `first_line` is formatting only — the redaction above already happened.
        Redactor::from_url(first).first_line(&text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TX: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn args(argv: &[&str]) -> Args {
        // `tx` is the one required positional; every fixture here is a full command.
        Args::parse_from(std::iter::once("necropsy").chain(argv.iter().copied()))
    }

    /// The property this exists to hold: no path through the error printer may let a
    /// credential through, whichever endpoint it belonged to.
    /// The cleartext note has to fire on the remote case and stay quiet on the local one.
    /// Refusing `http://localhost:8545` would break the signer/anvil setups this tool is used
    /// with daily; saying nothing about `http://provider.example` would hide a key on the wire.
    #[test]
    fn a_remote_http_endpoint_is_flagged_and_a_local_one_is_not() {
        assert!(cleartext_note("https://eth.example/v2/key1234567890").is_none());
        for local in [
            "http://localhost:8545",
            "http://127.0.0.1:8545",
            "http://127.0.0.1:8545/v2/key1234567890",
            "http://[::1]:8545",
        ] {
            assert!(
                cleartext_note(local).is_none(),
                "a local endpoint is the normal case, not a warning: {local}"
            );
        }
        let remote = cleartext_note("http://rpc.example.com/v2/key1234567890").expect("flagged");
        assert!(remote.contains("plain HTTP"), "{remote}");
        assert!(
            !remote.contains("key1234567890"),
            "the note names the host, never the credential: {remote}"
        );
    }

    #[test]
    fn a_credential_in_either_endpoint_url_is_redacted() {
        let a = args(&[
            "--rpc-url",
            "https://eth.example/v2/targetkey1234567890",
            "--baseline-rpc-url",
            "https://base.example/v2/baselinekey0987654321",
            "--baseline-tx-hash",
            TX,
            TX,
        ]);
        let e = Error::Rpc("dial https://base.example/v2/baselinekey0987654321 failed".into());
        let msg = message(&a, &e);
        assert!(
            !msg.contains("baselinekey0987654321"),
            "the baseline URL is a secret too: {msg}"
        );
        let e2 = Error::Rpc("dial https://eth.example/v2/targetkey1234567890 failed".into());
        assert!(
            !message(&a, &e2).contains("targetkey1234567890"),
            "the target URL is still redacted: {}",
            message(&a, &e2)
        );
    }

    #[test]
    fn verbose_asks_for_more_text_not_more_credential() {
        let a = args(&[
            "--rpc-url",
            "https://eth.example/v2/targetkey1234567890",
            "--verbose",
            TX,
        ]);
        let multi = "provider failed\n  at https://eth.example/v2/targetkey1234567890\n  context";
        let msg = message(&a, &Error::Rpc(multi.into()));
        assert!(
            msg.contains("context"),
            "--verbose keeps the extra text: {msg}"
        );
        assert!(
            !msg.contains("targetkey1234567890"),
            "but never the credential: {msg}"
        );
    }

    #[test]
    fn an_unconfigured_endpoint_leaves_the_message_alone() {
        let a = args(&[TX]);
        assert_eq!(message(&a, &Error::NoRpcUrl), Error::NoRpcUrl.to_string());
    }
}
