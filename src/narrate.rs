use crate::diff::DiffEntry;
use crate::flow::{top_sinks, TransferEvent};
use crate::graph::{CallGraph, CallType};
use petgraph::graph::NodeIndex;
use std::collections::HashMap;

/// One step in the execution-order timeline. Order matches the DFS
/// pre-order walk of the call tree, which is the actual execution order
/// for a trace (a call's children execute, in order, before its next
/// sibling) — not a reconstruction, this is exact.
#[derive(Debug, Clone)]
pub struct TimelineStep {
    pub depth: usize,
    pub call_type: CallType,
    pub address: String,
    pub function: String,
}

/// Walks the call graph in execution order. This is exact for call
/// sequencing. It is NOT joined against `TransferEvent`s — flow.rs doesn't
/// track which call node emitted which transfer (same limitation flow.rs
/// itself documents: transfers aren't attributed to a token or, by
/// extension, a specific call frame), so transfers are reported separately
/// in `build_narrative` rather than falsely attached to a step here.
pub fn build_call_timeline(call_graph: &CallGraph) -> Vec<TimelineStep> {
    let mut steps = Vec::new();
    if let Some(root) = call_graph.root {
        walk(call_graph, root, 0, &mut steps);
    }
    steps
}

fn walk(call_graph: &CallGraph, idx: NodeIndex, depth: usize, steps: &mut Vec<TimelineStep>) {
    let node = &call_graph.graph[idx];
    steps.push(TimelineStep {
        depth,
        call_type: node.call_type.clone(),
        address: node.address.clone(),
        function: node.function.clone(),
    });

    if let Some(children) = call_graph.children.get(&idx) {
        for &child in children {
            walk(call_graph, child, depth + 1, steps);
        }
    }
}

pub fn print_timeline(steps: &[TimelineStep]) {
    println!("Execution timeline ({} call(s)):\n", steps.len());
    for (i, step) in steps.iter().enumerate() {
        let indent = "  ".repeat(step.depth);
        let tag = match step.call_type {
            CallType::Call => "",
            CallType::Delegatecall => " [delegatecall]",
            CallType::Staticcall => " [staticcall]",
            CallType::Create => " [create]",
        };
        println!(
            "  {:>3}. {indent}{}::{}{tag}",
            i + 1,
            step.address,
            step.function
        );
    }
}

/// Builds a prose summary of the forensics run. Purely templated from
/// already-computed data — no inference beyond what graph.rs/flow.rs/
/// diff.rs established, so this can't assert anything the rest of the
/// tool hasn't already backed with structure.
pub fn build_narrative(
    call_graph: &CallGraph,
    transfers: &[TransferEvent],
    net_flow: &HashMap<String, i128>,
    diff_entries: Option<&[DiffEntry]>,
) -> String {
    let mut out = String::new();

    let call_count = call_graph.graph.node_count();
    let root_desc = call_graph
        .root
        .map(|r| {
            let node = &call_graph.graph[r];
            format!("{}::{}", node.address, node.function)
        })
        .unwrap_or_else(|| "(no root call parsed)".to_string());

    out.push_str(&format!(
        "The traced transaction entered at {root_desc} and expanded into {call_count} call(s) total. "
    ));

    if transfers.is_empty() {
        out.push_str("No Transfer events were emitted during execution.\n\n");
    } else {
        out.push_str(&format!(
            "{} Transfer event(s) were emitted during execution.\n\n",
            transfers.len()
        ));

        let sinks = top_sinks(net_flow, 3);
        if sinks.is_empty() {
            out.push_str(
                "No address ended the transaction as a net-positive recipient \
                 (all flows netted to zero or negative, or only minting was observed).\n\n",
            );
        } else {
            out.push_str("Value concentrated at, in order:\n");
            for (addr, net) in &sinks {
                out.push_str(&format!("  - {addr}, net +{net}\n"));
            }
            out.push('\n');
        }
    }

    match diff_entries {
        None => {}
        Some([]) => {
            out.push_str(
                "No structural deviation was found against the supplied baseline trace — \
                 the call sequence matches a reference (benign) call to the same entry point.\n\n",
            );
        }
        Some(entries) => {
            out.push_str(&format!(
                "{} deviation(s) from the baseline trace were found, meaning the exploit tx's \
                 call sequence diverges from a reference (benign) call at these positions:\n",
                entries.len()
            ));
            for entry in entries.iter().take(10) {
                match entry {
                    DiffEntry::Changed { path, baseline, target } => out.push_str(&format!(
                        "  - @ {path}: baseline called {}::{}, target instead called {}::{}\n",
                        baseline.address, baseline.function, target.address, target.function
                    )),
                    DiffEntry::Added { path, target } => out.push_str(&format!(
                        "  - @ {path}: target made an extra call to {}::{} not present in baseline\n",
                        target.address, target.function
                    )),
                    DiffEntry::Removed { path, baseline } => out.push_str(&format!(
                        "  - @ {path}: target skipped a call to {}::{} that baseline made\n",
                        baseline.address, baseline.function
                    )),
                }
            }
            if entries.len() > 10 {
                out.push_str(&format!("  ... and {} more (see full diff output).\n", entries.len() - 10));
            }
            out.push('\n');
        }
    }

    out.push_str(
        "This is a structural summary only — every observation above is drawn directly from \
         the parsed trace and transfer log, not inferred. Root-cause attribution still requires \
         manual review of the flagged call(s).",
    );

    out
}

pub fn print_narrative(narrative: &str) {
    println!("{narrative}");
}
