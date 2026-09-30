//! Live end-to-end check of the collection pipeline against a real endpoint.
//!
//! The test suite is deliberately hermetic, which means it cannot see transport
//! breakage, a node that stopped exposing `debug_`, or a response shape that
//! drifted. This example does: it collects one transaction and prints what the
//! pipeline actually accounted for. Run it with
//!
//! ```text
//! ETH_RPC_URL=https://eth.drpc.org cargo run --example live_collect -- <tx hash>
//! ```

use necropsy::collect::{self, CollectorChoice, castbin, rpc::HttpRpc};
use necropsy::model::TxHash;
use std::str::FromStr;
use std::time::Duration;

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
        mode: castbin::CastMode::Rendered,
        external_identification: false,
    };

    let started = std::time::Instant::now();
    let c = collect::collect(rpc.clone(), hash, CollectorChoice::Auto, Some(cfg))
        .unwrap_or_else(|e| panic!("collection failed: {e}"));
    println!(
        "collected in {:?} via {}",
        started.elapsed(),
        c.provenance()
    );

    let t = &c.trace;
    println!(
        "frames: total {} | reachable {} | orphans {} | unclassified {}",
        t.len(),
        t.reachable(),
        t.orphans.len(),
        t.unclassified.len()
    );
    let cv = t.conservation;
    println!(
        "conservation: total {} = frames {} + emit {} + result {} + trailer {} + blank {} + unclassified {}  (balances: {})",
        cv.total,
        cv.frames,
        cv.emissions,
        cv.results,
        cv.trailers,
        cv.blanks,
        cv.unclassified,
        cv.balances()
    );
    if let Some(u) = t.unclassified.first() {
        println!(
            "  first unclassified: line {} {:?} — {}",
            u.line, u.text, u.why
        );
    }

    println!(
        "tx: {:?}",
        c.tx.as_ref().map(|m| (
            m.from.to_checksum(),
            m.to.map(|a| a.to_checksum()),
            m.block_number,
            m.status
        ))
    );
    println!(
        "logs: {} | classified fungible {} | unaccounted {}",
        c.logs.len(),
        c.events.iter().filter(|e| e.is_fungible_move()).count(),
        c.unaccounted_logs()
    );
    for n in &c.notes {
        println!("note: {n}");
    }

    // Show the first frames so a human can eyeball ordering and context.
    for (i, id) in t.root_walk().iter().take(12).enumerate() {
        let f = t.frame(*id).unwrap();
        println!(
            "  {:>2}. {:<12} {} -> {} ctx {} {}{}",
            i + 1,
            f.kind.tag(),
            f.from.short(),
            f.to.map(|a| a.short()).unwrap_or_else(|| "-".into()),
            f.context.short(),
            f.label.clone().unwrap_or_default(),
            f.value.map(|v| format!(" value {}", v)).unwrap_or_default(),
        );
    }
}
