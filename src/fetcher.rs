use anyhow::{Context, Result};
use std::env;
use std::process::Command;

/// Reads the Alchemy (or any EVM JSON-RPC) endpoint URL from the environment.
/// Never hardcode this — it's a credential.
pub fn rpc_url() -> Result<String> {
    env::var("ALCHEMY_ETH_RPC_URL")
        .context("ALCHEMY_ETH_RPC_URL environment variable not set")
}

/// Shells out to `cast run <tx_hash> --rpc-url <url>`, which replays the historical
/// transaction locally using Foundry's own EVM and prints a full call trace.
/// This avoids relying on debug_traceTransaction / trace_transaction RPC methods
/// entirely, sidestepping free-tier gating and anvil's fork-mode tracing bug.
pub fn run_cast_trace(tx_hash: &str) -> Result<String> {
    let url = rpc_url()?;

    let output = Command::new("cast")
        .args(["run", tx_hash, "--rpc-url", &url])
        .output()
        .context("failed to spawn cast run — is Foundry installed and on PATH?")?;

    if !output.status.success() {
        anyhow::bail!(
            "cast run failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}