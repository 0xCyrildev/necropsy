//! Spawning `cast`.
//!
//! Two hard rules, both from measured failure modes:
//!
//!   * the RPC URL goes to the child through the environment, never through
//!     argv. `/proc/<pid>/cmdline` is world-readable, and `cast` honours
//!     `ETH_RPC_URL` natively, so passing `-r` buys nothing and costs a credential.
//!   * `cast`'s stderr is never echoed verbatim. A reverted transaction prints
//!     `Error: Transaction failed.` there while still exiting 0 and still
//!     producing a complete tree on stdout, and provider errors embed the full
//!     RPC URL including the key.

use crate::error::{Error, Redactor, Result};
use crate::model::TxHash;
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CastMode {
    /// `--debug-trace-transaction`: the node's tracer, rendered. No block replay,
    /// so it works without archive state.
    Rendered,
    /// Default `cast run`: re-execute the block locally. Needs archive state, can
    /// diverge from what chain did, and its numbers must be labelled as such.
    Replay,
}

#[derive(Debug, Clone)]
pub struct CastConfig {
    pub rpc_url: String,
    pub timeout: Duration,
    pub mode: CastMode,
    /// Set to keep `cast`'s label and signature lookups on. Off by default,
    /// because a resolved name replaces the address in the line we parse — which
    /// makes fixture output depend on whether a network lookup succeeded.
    pub external_identification: bool,
}

impl CastConfig {
    pub fn from_env(timeout: Duration, mode: CastMode) -> Option<Result<Self>> {
        std::env::var("ETH_RPC_URL").ok().map(|url| {
            Ok(CastConfig {
                rpc_url: url,
                timeout,
                mode,
                external_identification: false,
            })
        })
    }
}

/// Flags that keep the rendered text parseable and the run free of side lookups.
pub fn args_for(hash_hex: &str, mode: CastMode, external: bool) -> Vec<String> {
    let mut v = vec!["run".to_string()];
    if mode == CastMode::Rendered {
        v.push("--debug-trace-transaction".to_string());
    }
    v.push("--color".to_string());
    v.push("never".to_string());
    v.push("--disable-labels".to_string());
    if !external {
        v.push("--disable-external-identification".to_string());
    }
    // Validated upstream as `0x` + 64 hex, so it can never begin with `-` and be
    // read as a flag. Passed as its own argv slot regardless.
    v.push(hash_hex.to_string());
    v
}

pub fn version() -> Option<String> {
    let out = Command::new("cast")
        .arg("--version")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines().next().map(|l| l.trim().to_string())
}

/// Run `cast`, returning stdout. Kills the child at the deadline.
pub fn run_cast_with(cfg: &CastConfig, hash: TxHash) -> Result<String> {
    let redactor = Redactor::from_url(&cfg.rpc_url);
    let args = args_for(&hash.to_hex(), cfg.mode, cfg.external_identification);

    let mut child = Command::new("cast")
        .args(&args)
        // The credential path: environment, not argv.
        .env("ETH_RPC_URL", &cfg.rpc_url)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => Error::CastMissing,
            other => Error::Io(std::io::Error::new(other, e)),
        })?;

    // stdout is drained on this thread while we poll, so a large trace cannot
    // fill the pipe buffer and deadlock the child we are about to kill.
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| Error::Collect("no stdout pipe".into()))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| Error::Collect("no stderr pipe".into()))?;

    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout.read_to_end(&mut buf);
        buf
    });
    let err_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stderr.read_to_end(&mut buf);
        buf
    });

    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st,
            Ok(None) => {
                if start.elapsed() > cfg.timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(Error::CastTimeout(cfg.timeout));
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(e) => return Err(Error::Io(e)),
        }
    };

    let out_bytes = reader
        .join()
        .map_err(|_| Error::Collect("cast stdout reader panicked".into()))?;
    let err_bytes = err_reader
        .join()
        .map_err(|_| Error::Collect("cast stderr reader panicked".into()))?;

    let stdout_text = String::from_utf8_lossy(&out_bytes).to_string();

    if !status.success() {
        // A non-zero `cast` is a real failure of the *command*, never a statement
        // about the transaction: a reverted transaction exits 0.
        let detail = redactor.first_line(&String::from_utf8_lossy(&err_bytes));
        return Err(Error::Collect(format!(
            "cast exited {}: {detail}",
            status.code().unwrap_or(-1)
        )));
    }

    if stdout_text.trim().is_empty() {
        return Err(Error::Collect(format!(
            "cast exited 0 but wrote no trace; stderr said: {}",
            redactor.first_line(&String::from_utf8_lossy(&err_bytes))
        )));
    }

    Ok(stdout_text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_rpc_url_is_never_an_argument() {
        let args = args_for("0xabcd", CastMode::Rendered, false);
        let joined = args.join(" ");
        assert!(!joined.contains("http"), "{joined}");
        assert!(!joined.contains("-r"), "{joined}");
        assert!(!joined.contains("rpc-url"), "{joined}");
        assert!(joined.contains("--debug-trace-transaction"));
        assert!(joined.contains("--color never"));
        assert!(joined.contains("--disable-labels"));
        assert!(joined.contains("--disable-external-identification"));
    }

    #[test]
    fn replay_mode_omits_the_tracer_flag_because_cast_rejects_the_pairing() {
        let args = args_for("0xabcd", CastMode::Replay, true).join(" ");
        assert!(!args.contains("--debug-trace-transaction"), "{args}");
        assert!(!args.contains("disable-external-identification"), "{args}");
    }

    #[test]
    fn a_hash_is_always_its_own_argument() {
        let args = args_for(
            "0x5b515946dc1177149f140777ac90879312b182117e3392e8e2703ed3cd697153",
            CastMode::Rendered,
            false,
        );
        assert_eq!(
            args.last().unwrap(),
            "0x5b515946dc1177149f140777ac90879312b182117e3392e8e2703ed3cd697153"
        );
    }

    #[test]
    fn missing_cast_is_reported_as_such() {
        // A PATH with nothing on it stands in for "Foundry not installed".
        let cfg = CastConfig {
            rpc_url: "https://x.invalid/v2/SECRETVALUE123456".into(),
            timeout: Duration::from_millis(50),
            mode: CastMode::Rendered,
            external_identification: false,
        };
        let hash: TxHash = format!("0x{}", "00".repeat(32)).parse().unwrap();
        let path_backup = std::env::var("PATH").unwrap_or_default();
        unsafe { std::env::set_var("PATH", "") };
        let e = run_cast_with(&cfg, hash).unwrap_err();
        unsafe { std::env::set_var("PATH", path_backup) };
        // Either "not on PATH" or "cannot spawn" is fine; a leak of the URL is not.
        let msg = e.to_string();
        assert!(!msg.contains("SECRETVALUE123456"), "leaked: {msg}");
        assert!(
            matches!(e, Error::CastMissing) || msg.contains("spawn") || msg.contains("No such"),
            "{msg}"
        );
    }
}
