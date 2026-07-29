use anyhow::Result;
use petgraph::graph::{Graph, NodeIndex};
use regex::Regex;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub enum CallType {
    Call,
    Delegatecall,
    Staticcall,
    Create,
}

#[derive(Debug, Clone)]
pub struct CallNode {
    pub call_type: CallType,
    pub address: String,
    pub function: String,
    pub args: String,
    pub gas: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct CallEdge;

pub struct CallGraph {
    pub graph: Graph<CallNode, CallEdge>,
    pub root: Option<NodeIndex>,
    /// Explicit child ordering per node, since petgraph's neighbors() iterates
    /// edges in reverse insertion order by default. Tracking this separately
    /// keeps tree printing/traversal in the same left-to-right order as the
    /// original trace.
    pub children: HashMap<NodeIndex, Vec<NodeIndex>>,
}

/// Parses the indented tree output of `cast run` into a proper graph structure.
/// Uses a stack keyed by each line's leading indent width (counting tree-drawing
/// characters and spaces) rather than trying to compute an exact nesting depth —
/// this is robust to the variable-width box-drawing prefixes without needing to
/// know the tree renderer's exact character conventions.
pub fn parse_cast_trace(raw: &str) -> Result<CallGraph> {
    let call_re = Regex::new(
        r"^\[(?P<gas>\d+)\]\s+(?:→\s+new\s+(?:<unknown>)?@(?P<create_addr>0x[0-9a-fA-F]+)|(?P<addr>0x[0-9a-fA-F]+)::(?P<func>[^\(]+)\((?P<args>.*)\))\s*(?P<tag>\[(?:delegatecall|staticcall)\])?\s*$"
    )?;

    let mut graph = Graph::<CallNode, CallEdge>::new();
    let mut stack: Vec<(usize, NodeIndex)> = Vec::new();
    let mut children_map: HashMap<NodeIndex, Vec<NodeIndex>> = HashMap::new();
    let mut root = None;

    for line in raw.lines() {
        let indent_width = line
            .chars()
            .take_while(|c| matches!(c, '│' | '├' | '└' | '─' | ' '))
            .count();

        let content_start = line
            .char_indices()
            .find(|(_, c)| !matches!(c, '│' | '├' | '└' | '─' | ' '))
            .map(|(i, _)| i)
            .unwrap_or(line.len());
        let content = &line[content_start..];

        if !content.starts_with('[') {
            continue;
        }

        if let Some(caps) = call_re.captures(content) {
            let gas = caps.name("gas").and_then(|m| m.as_str().parse::<u64>().ok());

            let call_type = if caps.name("create_addr").is_some() {
                CallType::Create
            } else if caps
                .name("tag")
                .map(|t| t.as_str().contains("delegatecall"))
                .unwrap_or(false)
            {
                CallType::Delegatecall
            } else if caps
                .name("tag")
                .map(|t| t.as_str().contains("staticcall"))
                .unwrap_or(false)
            {
                CallType::Staticcall
            } else {
                CallType::Call
            };

            let address = caps
                .name("create_addr")
                .or_else(|| caps.name("addr"))
                .map(|m| m.as_str().to_string())
                .unwrap_or_default();

            let function = caps
                .name("func")
                .map(|m| m.as_str().trim().to_string())
                .unwrap_or_else(|| "<constructor>".to_string());

            let args = caps
                .name("args")
                .map(|m| m.as_str().to_string())
                .unwrap_or_default();

            let node = CallNode {
                call_type,
                address,
                function,
                args,
                gas,
            };
            let idx = graph.add_node(node);

            while let Some(&(top_indent, _)) = stack.last() {
                if top_indent >= indent_width {
                    stack.pop();
                } else {
                    break;
                }
            }

            if let Some(&(_, parent_idx)) = stack.last() {
                graph.add_edge(parent_idx, idx, CallEdge::default());
                children_map.entry(parent_idx).or_default().push(idx);
            } else if root.is_none() {
                root = Some(idx);
            }

            stack.push((indent_width, idx));
        }
    }

    Ok(CallGraph {
        graph,
        root,
        children: children_map,
    })
}

/// Debug helper: print the parsed graph as an indented tree, so we can visually
/// confirm the parser reconstructed the structure correctly, in the original
/// left-to-right sibling order.
pub fn print_tree(call_graph: &CallGraph) {
    if let Some(root) = call_graph.root {
        print_node(call_graph, root, 0);
    } else {
        println!("(no root call found)");
    }
}

fn print_node(call_graph: &CallGraph, idx: NodeIndex, depth: usize) {
    let node = &call_graph.graph[idx];
    let indent = "  ".repeat(depth);
    let tag = match node.call_type {
        CallType::Call => "",
        CallType::Delegatecall => " [delegatecall]",
        CallType::Staticcall => " [staticcall]",
        CallType::Create => " [create]",
    };
    println!(
        "{indent}{}::{}({}){tag}",
        node.address, node.function, node.args
    );

    if let Some(kids) = call_graph.children.get(&idx) {
        for &child in kids {
            print_node(call_graph, child, depth + 1);
        }
    }
}