mod fetcher;
mod graph;
mod diff;
mod flow;
mod narrate;
mod evm { pub mod trace; }
mod sui { pub mod trace; }

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "necropsy")]
#[command(about = "Post-exploit forensics reconstruction for EVM/Sui transactions")]
struct Args {
    /// Transaction hash to trace and reconstruct
    #[arg(long)]
    tx_hash: String,

    /// Optional reference (benign) transaction hash to diff the exploit
    /// trace against. When set, deviations from this baseline are reported
    /// structurally and folded into the narrative summary.
    #[arg(long)]
    baseline_tx_hash: Option<String>,
}

fn main() {
    let args = Args::parse();

    println!("Replaying and tracing transaction {}...", args.tx_hash);
    let raw_trace = match fetcher::run_cast_trace(&args.tx_hash) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Error: {e}");
            return;
        }
    };

    println!("Parsing trace into call graph...");
    let call_graph = match graph::parse_cast_trace(&raw_trace) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("Error parsing trace: {e}");
            return;
        }
    };

    println!(
        "Parsed {} calls into graph. Reconstructed tree:\n",
        call_graph.graph.node_count()
    );
    graph::print_tree(&call_graph);

    println!("\nAnalyzing fund flow...\n");
    let transfers = match flow::parse_transfers(&raw_trace) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Error parsing transfers: {e}");
            return;
        }
    };
    let net_flow = flow::compute_net_flow(&transfers);
    flow::print_flow_summary(&transfers, &net_flow);

    let diff_entries = if let Some(baseline_hash) = &args.baseline_tx_hash {
        println!("\nFetching baseline transaction {baseline_hash}...");
        match fetcher::run_cast_trace(baseline_hash) {
            Ok(baseline_raw) => match graph::parse_cast_trace(&baseline_raw) {
                Ok(baseline_graph) => {
                    println!("\nDiffing against baseline...\n");
                    let entries = diff::diff_call_graphs(&baseline_graph, &call_graph);
                    diff::print_diff_summary(&entries);
                    Some(entries)
                }
                Err(e) => {
                    eprintln!("Error parsing baseline trace: {e}");
                    None
                }
            },
            Err(e) => {
                eprintln!("Error fetching baseline: {e}");
                None
            }
        }
    } else {
        None
    };

    println!("\nExecution timeline:\n");
    let timeline = narrate::build_call_timeline(&call_graph);
    narrate::print_timeline(&timeline);

    println!("\nSummary:\n");
    let narrative = narrate::build_narrative(
        &call_graph,
        &transfers,
        &net_flow,
        diff_entries.as_deref(),
    );
    narrate::print_narrative(&narrative);
}
