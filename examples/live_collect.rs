//! Live end-to-end check of the collection pipeline against a real endpoint.
//!
//! The test suite is deliberately hermetic, which means it cannot see transport breakage, a
//! node that stopped exposing `debug_`, or a response shape that drifted. This does: it
//! collects one transaction, asks its tokens for decimals, and prints what the pipeline
//! actually accounted for. Run it with
//!
//! ```text
//! ETH_RPC_URL=https://eth.drpc.org cargo run --example live_collect -- <tx hash>
//! ```
//!
//! It renders through [`necropsy::report`] rather than printing its own tables, and that is
//! the load-bearing decision. A probe with a second renderer can disagree with the product it
//! is supposed to be testing — which is exactly what happened here. This example's own frame
//! line ended in `f.value.map(…).unwrap_or_default()`, so a frame whose `value` the collector
//! never reported printed *nothing*, which is indistinguishable from what it printed for a
//! `staticcall` or `delegatecall`, where the silence is a protocol answer. `report` renders
//! the first as `value ?` and the second as nothing, on purpose. Sharing the renderer turns
//! this probe into a canary for the real code path instead of a competing description of it,
//! and the elapsed line is what is genuinely unique to a probe.

use necropsy::collect::castbin::{self, CastMode};
use necropsy::collect::decimals;
use necropsy::collect::rpc::HttpRpc;
use necropsy::collect::{self, CollectorChoice};
use necropsy::model::TxHash;
use necropsy::{ledger, report};
use std::str::FromStr;
use std::time::{Duration, Instant};

fn main() {
    let url = std::env::var("ETH_RPC_URL").expect("set ETH_RPC_URL to a reachable endpoint");
    let hash = TxHash::from_str(
        &std::env::args()
            .nth(1)
            .expect("usage: live_collect <0x…tx hash>"),
    )
    .expect("bad tx hash");

    let rpc = std::sync::Arc::new(HttpRpc::new(&url, Duration::from_secs(60), 2));
    let cfg = castbin::CastConfig {
        rpc_url: url.clone(),
        timeout: Duration::from_secs(120),
        mode: CastMode::Rendered,
        external_identification: false,
    };

    let started = Instant::now();
    let c = collect::collect(rpc.clone(), hash, CollectorChoice::Auto, Some(cfg))
        .unwrap_or_else(|e| panic!("collection failed: {e}"));
    let elapsed = started.elapsed();

    let l = ledger::build(&c.events, &c.trace, c.tx.as_ref().and_then(|m| m.status));
    // Fetched at the transaction's own block tag, exactly as the CLI does — a probe that
    // read metadata at `latest` would be checking something the report never does.
    let tag = c.tx.as_ref().map(|m| m.block_tag());
    let d = decimals::fetch(&*rpc, &l.assets(), tag.as_deref());

    println!("collected in {elapsed:?} via {}", c.provenance());
    // The narrative too: on a live tree this is where an ordering surprise shows up fastest.
    print!(
        "{}",
        report::text_with(&c, &l, hash, report::DEFAULT_TREE_LIMIT, None, &d, true)
    );
}
