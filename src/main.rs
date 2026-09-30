//! necropsy — the command line.
//!
//! Deliberately thin: it parses arguments, moves bytes, and chooses an exit
//! status. Every decision that affects an answer lives in the library, where it
//! can be tested without spawning a process.
//!
//! Exit statuses are the contract with scripts (`necropsy::exit`): a run that
//! could not read anything must not look like a run that found nothing.

use clap::{Parser, ValueEnum};
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

    /// JSON-RPC endpoint. Falls back to ETH_RPC_URL.
    #[arg(long, env = "ETH_RPC_URL")]
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

    /// Per-request timeout, in seconds.
    #[arg(long, default_value_t = 60)]
    timeout: u64,

    /// Print a provider's full error text (still redacted) rather than one line.
    #[arg(long)]
    verbose: bool,
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
    let args = Args::parse();
    match run(&args) {
        Ok((body, status)) => {
            println!("{body}");
            status.into()
        }
        Err(e) => {
            eprintln!("necropsy: {}", message(&args, &e));
            Exit::from_error(&e).into()
        }
    }
}

fn run(args: &Args) -> Result<(String, Exit)> {
    // An empty `ETH_RPC_URL` is set-but-blank, which is how CI often "unset" a
    // variable. clap hands it over as a value, so without this the run would dial
    // an empty URL and fail as an unreachable endpoint rather than as unconfigured.
    let url = args
        .rpc_url
        .clone()
        .map(|u| u.trim().to_string())
        .filter(|u| !u.is_empty())
        .ok_or(Error::NoRpcUrl)?;
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
    let (rpc, cast_cfg) = endpoint(&url, timeout, mode);

    // A second endpoint is opt-in. Without it the baseline is read from the same node,
    // and `--chain` stays the single guard it was. Set-but-blank applies here too: an
    // empty value means "same as --rpc-url", not "dial the empty string".
    let baseline_url = args
        .baseline_rpc_url
        .clone()
        .map(|u| u.trim().to_string())
        .filter(|u| !u.is_empty())
        .unwrap_or_else(|| url.clone());

    let c = collect::collect(
        rpc.clone(),
        hash,
        args.collector.into(),
        Some(cast_cfg.clone()),
    )?;
    let l = ledger::build(&c.events, &c.trace, c.tx.as_ref().and_then(|m| m.status));

    if let Some(wanted) = args.chain {
        c.verify_chain(wanted, &rpc.describe())?;
    }

    // Read the baseline *after* the target's chain guard, so an endpoint on the wrong
    // chain cannot spend a second request before the run stops. Two separate calls,
    // never a batch: these endpoints refuse batches whose members each work alone, and a
    // refusal would read exactly like a transaction that does not exist.
    let comparison = match baseline_hash {
        Some(bhash) => {
            let (brpc, bcast) = if baseline_url == url {
                (rpc.clone(), cast_cfg.clone())
            } else {
                endpoint(&baseline_url, timeout, mode)
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
        None => None,
    };

    // Asked last, once every guard has passed: the ledger is what says which assets are
    // worth asking about, and a run that stops on a wrong chain should not have spent
    // token calls on the way.
    let decimals = if args.no_decimals {
        Decimals::unscaled(
            "--no-decimals was given, so amounts stay in base units and no token was asked",
        )
    } else {
        collect::decimals::fetch(
            &*rpc,
            &l.assets(),
            c.tx.as_ref().map(|m| m.block_tag()).as_deref(),
        )
    };

    let body = if args.json {
        report::Report::build(&c, &l, hash)
            .with_decimals((!args.no_decimals).then_some(&decimals))
            .with_diff(comparison.as_ref())
            .to_json()?
    } else {
        report::text_with(&c, &l, hash, args.tree, comparison.as_ref(), &decimals)
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

/// One endpoint: an RPC handle, plus the `cast` configuration that makes `auto`'s
/// fallback possible on a node with no `debug_` namespace. Built twice only when
/// `--baseline-rpc-url` names a second one; constructing it never runs `cast`.
fn endpoint(
    url: &str,
    timeout: Duration,
    mode: CastMode,
) -> (collect::SharedRpc, castbin::CastConfig) {
    let rpc: collect::SharedRpc = std::sync::Arc::new(HttpRpc::new(url, timeout, 2));
    let cast = castbin::CastConfig {
        rpc_url: url.to_string(),
        // Rendering a trace is not a JSON-RPC round trip; a timeout tuned for the
        // latter would kill the former.
        timeout: timeout.max(Duration::from_secs(120)),
        mode,
        external_identification: false,
    };
    (rpc, cast)
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
