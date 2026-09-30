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

    let timeout = Duration::from_secs(args.timeout.max(1));
    let rpc = std::sync::Arc::new(HttpRpc::new(&url, timeout, 2));

    // Always supplied, even for `--collector rpc`, because `auto` is the default
    // and its fallback is the only thing that works on a node without a `debug_`
    // namespace. Building the config does not run `cast`.
    let cast_cfg = castbin::CastConfig {
        rpc_url: url.clone(),
        timeout: timeout.max(Duration::from_secs(120)),
        mode: args.cast_mode.into(),
        external_identification: false,
    };

    let c = collect::collect(rpc, hash, args.collector.into(), Some(cast_cfg))?;
    let l = ledger::build(&c.events, &c.trace, c.tx.as_ref().and_then(|m| m.status));

    if let Some(wanted) = args.chain {
        match c.trace.provenance.chain_id {
            Some(got) if got == wanted => {}
            Some(got) => {
                return Err(Error::ChainMismatch {
                    endpoint: got,
                    requested: wanted,
                });
            }
            // Silence is not agreement: an endpoint that will not say which chain
            // it is on cannot honour a guard meant to prevent exactly that mix-up.
            None => {
                return Err(Error::Collect(format!(
                    "this endpoint would not report a chain id, so --chain {wanted} cannot be verified"
                )));
            }
        }
    }

    let body = if args.json {
        report::Report::build(&c, &l, hash).to_json()?
    } else {
        report::text(&c, &l, hash, args.tree)
    };

    let status = if report::degraded(&c, &l) {
        Exit::Degraded
    } else {
        // A reverted transaction is a complete answer, not a failed run. Naming a
        // finding as one would need a severity model the tool does not have yet,
        // so `Exit::Findings` is deliberately unreachable from here.
        Exit::Ok
    };

    Ok((body, status))
}

/// An error message that cannot carry a credential, whatever the provider said.
fn message(args: &Args, e: &Error) -> String {
    match args.rpc_url.as_deref() {
        Some(url) => {
            let r = Redactor::from_url(url);
            if args.verbose {
                r.redact(&e.to_string())
            } else {
                r.first_line(&e.to_string())
            }
        }
        None => e.to_string(),
    }
}
