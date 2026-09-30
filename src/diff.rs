use crate::graph::{CallGraph, CallNode, CallType};
use petgraph::graph::NodeIndex;

/// Result of comparing one call node position against its counterpart in the
/// baseline tree. "Position" means the same DFS path (root -> child index ->
/// child index -> ...), not the same address/function — that's the whole
/// point: a call at the same tree position that goes somewhere different is
/// exactly the kind of deviation post-exploit forensics is looking for.
#[derive(Debug, Clone)]
pub enum DiffEntry {
    /// Same position in both trees, but call_type/address/function differs.
    Changed {
        path: String,
        baseline: CallSummary,
        target: CallSummary,
    },
    /// Present in target but no counterpart at this position in baseline —
    /// a call the exploit tx made that the reference tx never made.
    Added { path: String, target: CallSummary },
    /// Present in baseline but missing at this position in target — a call
    /// the reference tx made that the exploit tx skipped.
    Removed { path: String, baseline: CallSummary },
}

#[derive(Debug, Clone)]
pub struct CallSummary {
    pub call_type: CallType,
    pub address: String,
    pub function: String,
}

impl From<&CallNode> for CallSummary {
    fn from(node: &CallNode) -> Self {
        CallSummary {
            call_type: node.call_type.clone(),
            address: node.address.clone(),
            function: node.function.clone(),
        }
    }
}

/// Structurally diffs `target` (e.g. the exploit tx) against `baseline`
/// (e.g. a prior benign call to the same entry point). Walks both trees in
/// lockstep by child index — NOT by matching addresses/functions — since
/// the interesting signal is "the Nth call this contract makes deviates",
/// which a content-based diff would blur by re-aligning around the change.
pub fn diff_call_graphs(baseline: &CallGraph, target: &CallGraph) -> Vec<DiffEntry> {
    let mut entries = Vec::new();

    match (baseline.root, target.root) {
        (Some(b_root), Some(t_root)) => {
            diff_node(baseline, b_root, target, t_root, "root", &mut entries);
        }
        (None, Some(t_root)) => {
            let node = &target.graph[t_root];
            entries.push(DiffEntry::Added {
                path: "root".to_string(),
                target: node.into(),
            });
        }
        (Some(b_root), None) => {
            let node = &baseline.graph[b_root];
            entries.push(DiffEntry::Removed {
                path: "root".to_string(),
                baseline: node.into(),
            });
        }
        (None, None) => {}
    }

    entries
}

fn diff_node(
    baseline: &CallGraph,
    b_idx: NodeIndex,
    target: &CallGraph,
    t_idx: NodeIndex,
    path: &str,
    entries: &mut Vec<DiffEntry>,
) {
    let b_node = &baseline.graph[b_idx];
    let t_node = &target.graph[t_idx];

    if b_node.call_type != t_node.call_type
        || b_node.address != t_node.address
        || b_node.function != t_node.function
    {
        entries.push(DiffEntry::Changed {
            path: path.to_string(),
            baseline: b_node.into(),
            target: t_node.into(),
        });
    }

    let b_children = baseline.children.get(&b_idx).cloned().unwrap_or_default();
    let t_children = target.children.get(&t_idx).cloned().unwrap_or_default();

    let max_len = b_children.len().max(t_children.len());
    for i in 0..max_len {
        let child_path = format!("{path}/{i}");
        match (b_children.get(i), t_children.get(i)) {
            (Some(&b_child), Some(&t_child)) => {
                diff_node(baseline, b_child, target, t_child, &child_path, entries);
            }
            (Some(&b_child), None) => {
                let node = &baseline.graph[b_child];
                entries.push(DiffEntry::Removed {
                    path: child_path,
                    baseline: node.into(),
                });
            }
            (None, Some(&t_child)) => {
                let node = &target.graph[t_child];
                entries.push(DiffEntry::Added {
                    path: child_path,
                    target: node.into(),
                });
            }
            (None, None) => unreachable!("i < max_len guarantees at least one side has a child"),
        }
    }
}

/// Debug helper: print a readable summary of the structural diff.
pub fn print_diff_summary(entries: &[DiffEntry]) {
    if entries.is_empty() {
        println!("No structural deviation from baseline trace.");
        return;
    }

    println!("Found {} deviation(s) from baseline trace:\n", entries.len());
    for entry in entries {
        match entry {
            DiffEntry::Changed { path, baseline, target } => {
                println!(
                    "  [CHANGED @ {path}] baseline: {}::{}  ->  target: {}::{}",
                    baseline.address, baseline.function, target.address, target.function
                );
            }
            DiffEntry::Added { path, target } => {
                println!(
                    "  [ADDED   @ {path}] target only: {}::{}",
                    target.address, target.function
                );
            }
            DiffEntry::Removed { path, baseline } => {
                println!(
                    "  [REMOVED @ {path}] baseline only: {}::{}",
                    baseline.address, baseline.function
                );
            }
        }
    }
}
