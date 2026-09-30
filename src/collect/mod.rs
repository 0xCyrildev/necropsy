//! Collection: turn a transaction hash into a trace plus the logs that moved value.
//!
//! The two are deliberately separate products of two separate RPC calls. Merging
//! them — attaching receipt logs to trace frames by position — is the trap:
//! `callTracer` orders logs per frame while the receipt orders them globally, and
//! pre-order DFS of the tree is not global emission order. A positional join
//! would silently mis-attribute, so nothing here joins them. They are joined only
//! at render time, and only as separate tables.

pub mod calltracer;
pub mod castbin;
pub mod casttext;
pub mod decimals;
pub mod receiptlogs;
pub mod rpc;
pub mod txdata;

use crate::error::{Error, Result};
use crate::model::{Collector, Provenance, RawLog, TokenEvent, Trace, TxHash};
pub use rpc::Rpc;
pub use txdata::{TxMeta, TxStatus};

/// How to obtain the trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollectorChoice {
    /// callTracer over RPC; if the node has no `debug_` namespace, fall back to
    /// `cast` rendering the same thing.
    Auto,
    /// RPC only. Fails rather than silently switching mechanism.
    Rpc,
    /// `cast` only, for replaying an incident exactly as Foundry saw it.
    Cast,
}

#[derive(Debug, Clone)]
pub struct Collection {
    pub trace: Trace,
    pub logs: Vec<RawLog>,
    pub events: Vec<TokenEvent>,
    /// `None` when the endpoint could not be reached at all — the tree may still
    /// be real, but the origin, the callee and the block are not known, and any
    /// conclusion that depends on them has to say so.
    pub tx: Option<TxMeta>,
    /// Anything the pipeline had to give up on, in the order it happened. These
    /// strings end up in the report; "no findings" is only meaningful alongside
    /// them.
    pub notes: Vec<String>,
}

impl Collection {
    pub fn provenance(&self) -> &'static str {
        match self.trace.provenance.collector {
            Collector::CallTracerJson => "callTracer JSON over RPC",
            Collector::CastTextRendered => "cast rendered text (debug_traceTransaction)",
            Collector::CastLocalReplay => {
                "cast local block replay — numbers may diverge from chain"
            }
        }
    }

    pub fn unclassified(&self) -> usize {
        self.trace.unclassified.len()
    }

    /// Logs that could not be parsed, or that parsed but carry no recognisable
    /// event. This is the number that must appear next to any "no transfers"
    /// claim.
    pub fn unaccounted_logs(&self) -> usize {
        self.events
            .iter()
            .filter(|e| matches!(e, TokenEvent::Unclassified { .. }))
            .count()
    }

    /// Refuse to be trusted when the endpoint cannot confirm it is the chain `wanted`.
    ///
    /// This lives on the collection rather than in the command line because a baseline
    /// comparison reads from two endpoints: a guard that only looked at the target would
    /// price one chain while reading another, which is exactly the mix-up `--chain`
    /// exists to prevent.
    ///
    /// `at` is a redacted host, used only where the failure is silence — "this endpoint
    /// would not report a chain id" tells the reader nothing if they cannot tell *which*
    /// endpoint is being discussed.
    pub fn verify_chain(&self, wanted: u64, at: &str) -> Result<()> {
        match self.trace.provenance.chain_id {
            Some(got) if got == wanted => Ok(()),
            Some(got) => Err(Error::ChainMismatch {
                endpoint: got,
                requested: wanted,
            }),
            // Silence is not agreement: an endpoint that will not say which chain it is
            // on cannot honour a guard meant to prevent exactly that mix-up.
            None => Err(Error::Collect(format!(
                "the endpoint at {at} would not report a chain id, so --chain {wanted} cannot be verified"
            ))),
        }
    }
}

/// Collect via RPC: callTracer for the tree, receipt for the value movement.
pub fn collect_rpc(rpc: &dyn Rpc, hash: TxHash) -> Result<Collection> {
    let mut notes = Vec::new();

    let chain_id = txdata::get_chain_id(rpc)?;
    let tx = txdata::get_transaction(rpc, hash)?;
    let receipt = txdata::get_receipt(rpc, hash).ok();
    let meta = txdata::meta_from(hash, &tx, receipt.as_ref(), chain_id)?;

    let prov = Provenance {
        collector: Collector::CallTracerJson,
        cast_version: None,
        chain_id,
        block: meta.block_number,
    };

    let (trace, _nodes) = calltracer::trace_transaction(rpc, hash, prov)?;

    let logs = match receipt.as_ref() {
        Some(r) => {
            let (logs, malformed) = receiptlogs::logs_from_receipt(r);
            if malformed > 0 {
                notes.push(format!(
                    "{malformed} receipt log(s) could not be decoded and are excluded from the ledger"
                ));
            }
            logs
        }
        // No receipt means the transaction is pending or the endpoint pruned it.
        // The tree may still be traceable, but no value movement can be claimed.
        None => {
            notes.push("no receipt available: value movement cannot be established".to_string());
            Vec::new()
        }
    };
    let (events, _unclassified) = receiptlogs::classify(&logs);

    Ok(Collection {
        trace,
        logs,
        events,
        tx: Some(meta),
        notes,
    })
}

/// Run `f` on a thread with a deliberately large stack.
///
/// This is not defensive padding. `serde_json` drops a nested `Value`
/// *recursively*, and a `callTracer` response for a reentrancy exploit nests
/// thousands of frames deep, so the crash happens on the way out of parsing —
/// long after this crate's own traversal, which is iterative. Measured directly:
/// a 6,000-frame tree overflows the default 2 MiB main-thread stack and aborts
/// the process, mid-investigation. Collecting on a sized stack turns that into a
/// completed report.
///
/// A failure to start the thread, or a panic inside it, is returned as an error
/// rather than being papered over by re-running `f` here: `f` has already been
/// moved into the spawn call, and silently falling back to this thread would put
/// the stack overflow right back.
pub fn with_large_stack<T: Send + 'static, F: FnOnce() -> T + Send + 'static>(
    f: F,
) -> std::result::Result<T, String> {
    const STACK: usize = 256 * 1024 * 1024;
    match std::thread::Builder::new().stack_size(STACK).spawn(f) {
        Ok(handle) => handle
            .join()
            .map_err(|_| "collection thread panicked".to_string()),
        Err(e) => Err(format!("could not start a collection thread: {e}")),
    }
}

/// Shared handle so collection can move onto the sized stack.
pub type SharedRpc = std::sync::Arc<dyn Rpc>;

/// Entry point honouring the operator's collector choice.
///
/// `cast_cfg` is what makes the text fallback possible at all; when it is absent
/// and the endpoint has no `debug_` namespace, the run stops with an instruction
/// rather than pretending a fallback happened.
///
/// Runs on [`with_large_stack`] because the response it parses is deep and
/// dropping that JSON is recursive.
pub fn collect(
    rpc: SharedRpc,
    hash: TxHash,
    choice: CollectorChoice,
    cast_cfg: Option<castbin::CastConfig>,
) -> Result<Collection> {
    with_large_stack(move || collect_inner(&*rpc, hash, choice, cast_cfg.as_ref()))
        .map_err(Error::Collect)?
}

fn collect_inner(
    rpc: &dyn Rpc,
    hash: TxHash,
    choice: CollectorChoice,
    cast_cfg: Option<&castbin::CastConfig>,
) -> Result<Collection> {
    match choice {
        CollectorChoice::Rpc => collect_rpc(rpc, hash),
        CollectorChoice::Cast => match cast_cfg {
            Some(cfg) => collect_cast(rpc, hash, cfg),
            None => Err(Error::Collect(
                "--collector cast needs an RPC endpoint for `cast` to read; pass --rpc-url or set ETH_RPC_URL".into(),
            )),
        },
        CollectorChoice::Auto => match collect_rpc(rpc, hash) {
            Ok(c) => Ok(c),
            // -32601 is "this node does not speak debug_traceTransaction", the
            // one failure where a different mechanism genuinely helps.
            Err(Error::RpcError { code: -32601, .. }) => match cast_cfg {
                Some(cfg) => {
                    let mut c = collect_cast(rpc, hash, cfg)?;
                    c.notes.push(format!(
                        "endpoint {} has no debug_ namespace; the trace was rendered by `cast` instead",
                        rpc.describe()
                    ));
                    Ok(c)
                }
                None => Err(Error::Collect(format!(
                    "{} does not expose debug_traceTransaction and no `cast` configuration was supplied",
                    rpc.describe()
                ))),
            },
            Err(e) => Err(e),
        },
    }
}

/// The text path. The **tree** comes from `cast`, but the transaction metadata
/// and the receipt logs still come from RPC when reachable: both work on
/// endpoints that refuse historical state, and topic0-based event classification
/// beats name-matching on rendered text for every purpose it can be used for.
fn collect_cast(rpc: &dyn Rpc, hash: TxHash, cfg: &castbin::CastConfig) -> Result<Collection> {
    let mut notes = Vec::new();
    let raw = castbin::run_cast_with(cfg, hash)?;
    let mut parsed = casttext::parse(&raw, castbin::version())?;

    if parsed.cast_reported_success == Some(false) {
        notes.push(
            "`cast` reported the transaction as failed; the tree is what it did before reverting"
                .to_string(),
        );
    }

    let (tx, logs, events) = match txdata::get_transaction(rpc, hash) {
        Ok(txjson) => {
            let chain_id = txdata::get_chain_id(rpc).unwrap_or(None);
            let receipt = txdata::get_receipt(rpc, hash).ok();
            let meta = txdata::meta_from(hash, &txjson, receipt.as_ref(), chain_id)?;
            let logs = receipt
                .as_ref()
                .map(|r| receiptlogs::logs_from_receipt(r).0)
                .unwrap_or_default();
            let (events, _u) = receiptlogs::classify(&logs);
            if logs.is_empty() && receipt.is_none() {
                notes.push("no receipt from this endpoint; value movement is taken from rendered event names, which cannot distinguish ERC-20 from ERC-721".to_string());
            }
            (Some(meta), logs, events)
        }
        Err(_) => {
            let (events, ambiguous) = casttext::events_from_text(&parsed);
            notes.push(format!(
                "ledger built from {} rendered emit line(s) without a receipt; ERC-20/ERC-721 are indistinguishable in text{suffix}",
                events.len(),
                suffix = if ambiguous > 0 {
                    format!(", and {ambiguous} could not be shaped at all")
                } else {
                    String::new()
                }
            ));
            (None, Vec::new(), events)
        }
    };

    // `cast` renders callees only, so its root frame arrives with the zero address
    // as its caller. The sender is known independently from the transaction, and
    // leaving zeros there would put the sender's ETH outflow on the burn address in
    // the ledger.
    if let Some(m) = &tx {
        parsed.trace.attribute_root_sender(m.from);
    }

    Ok(Collection {
        trace: parsed.trace,
        logs,
        events,
        tx,
        notes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_provenance_is_labelled_as_such() {
        // A local replay can diverge from chain; the report text is the only
        // place that difference can survive to the analyst.
        assert!(format!("{:?}", Collector::CastLocalReplay).contains("CastLocalReplay"));
    }

    fn collected(chain_id: Option<u64>) -> Collection {
        let tb = crate::model::TraceBuilder::new(Provenance {
            collector: Collector::CallTracerJson,
            cast_version: None,
            chain_id,
            block: None,
        });
        Collection {
            trace: tb.finish(),
            logs: Vec::new(),
            events: Vec::new(),
            tx: None,
            notes: Vec::new(),
        }
    }

    #[test]
    fn a_matching_chain_id_passes_the_guard() {
        assert!(collected(Some(1)).verify_chain(1, "eth.drpc.org").is_ok());
    }

    #[test]
    fn a_differing_chain_id_keeps_its_typed_error() {
        // Exit mapping reads this variant; flattening it into a string would turn a
        // wrong-chain stop into a generic failure.
        let e = collected(Some(10))
            .verify_chain(1, "eth.drpc.org")
            .unwrap_err();
        assert!(
            matches!(
                e,
                Error::ChainMismatch {
                    endpoint: 10,
                    requested: 1
                }
            ),
            "{e}"
        );
    }

    #[test]
    fn a_silent_endpoint_is_refused_and_named() {
        let e = collected(None)
            .verify_chain(1, "other.provider")
            .unwrap_err();
        let msg = e.to_string();
        assert!(
            msg.contains("other.provider"),
            "with two endpoints in play, the message has to say which one went silent: {msg}"
        );
        assert!(msg.contains("--chain 1"), "{msg}");
    }
}
