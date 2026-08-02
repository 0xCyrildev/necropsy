use anyhow::Result;
use regex::Regex;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct TransferEvent {
    pub from: String,
    pub to: String,
    pub amount: u128,
}

/// Parses every `emit Transfer(from: ..., to: ..., amount: ...)` line out of
/// the raw cast run trace text. Doesn't attribute which token each transfer
/// belongs to (that requires tracking delegatecall execution context) — this
/// aggregates all Transfer events as raw value movement, which is enough to
/// answer "where did value end up" even without per-token precision.
pub fn parse_transfers(raw: &str) -> Result<Vec<TransferEvent>> {
    let transfer_re = Regex::new(
        r"emit\s+Transfer\(from:\s*(0x[0-9a-fA-F]+),\s*to:\s*(0x[0-9a-fA-F]+),\s*amount:\s*(\d+)"
    )?;

    let mut events = Vec::new();

    for line in raw.lines() {
        if let Some(caps) = transfer_re.captures(line) {
            let from = caps[1].to_string();
            let to = caps[2].to_string();
            let amount: u128 = match caps[3].parse() {
                Ok(a) => a,
                Err(_) => continue, // amount too large for u128 or malformed — skip rather than crash
            };
            events.push(TransferEvent { from, to, amount });
        }
    }

    Ok(events)
}

/// Computes net value change per address across all transfer events:
/// positive = net receiver, negative = net sender. Uses i128 to allow
/// negative net values while still covering realistic transfer magnitudes.
pub fn compute_net_flow(events: &[TransferEvent]) -> HashMap<String, i128> {
    let mut net: HashMap<String, i128> = HashMap::new();

    for event in events {
        *net.entry(event.from.clone()).or_insert(0) -= event.amount as i128;
        *net.entry(event.to.clone()).or_insert(0) += event.amount as i128;
    }

    net
}

/// Returns addresses sorted by net positive value received, descending —
/// the most likely candidates for "where the exploited value ended up".
/// The zero address is excluded since Transfer(from: 0x0, ...) commonly
/// represents minting, not a real fund destination.
pub fn top_sinks(net_flow: &HashMap<String, i128>, top_n: usize) -> Vec<(String, i128)> {
    let zero = "0x0000000000000000000000000000000000000000";

    let mut entries: Vec<(String, i128)> = net_flow
        .iter()
        .filter(|(addr, net)| addr.as_str() != zero && **net > 0)
        .map(|(addr, net)| (addr.clone(), *net))
        .collect();

    entries.sort_by(|a, b| b.1.cmp(&a.1));
    entries.truncate(top_n);
    entries
}

/// Debug helper: print a readable summary of the fund flow analysis.
pub fn print_flow_summary(events: &[TransferEvent], net_flow: &HashMap<String, i128>) {
    println!("Parsed {} Transfer event(s).", events.len());

    let sinks = top_sinks(net_flow, 5);
    if sinks.is_empty() {
        println!("No net-positive addresses found (or all flows netted to zero/negative).");
        return;
    }

    println!("\nTop net-positive addresses (likely fund destinations):");
    for (addr, net) in sinks {
        println!("  {addr}  net +{net}");
    }
}