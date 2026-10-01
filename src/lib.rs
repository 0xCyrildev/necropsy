//! Necropsy: post-transaction forensics for EVM chains.
//!
//! Library surface. `main.rs` is a thin wrapper over these modules so the
//! parsers, ledger and analysis layer can be tested without spawning the CLI.

// No `unsafe` in the shipped code, enforced at the crate root rather than in review: this
// library parses untrusted bytes from a network and hands the result to someone making a
// forensic judgement. It is scoped by `cfg` rather than unconditional because `forbid` cannot
// be re-allowed locally, and one test clears `PATH` to prove the `cast` fallback fails
// cleanly — `std::env::set_var` is unsafe from edition 2024 on. That exception applies only
// to `cargo test`, never to a build anyone runs.
#![cfg_attr(not(test), forbid(unsafe_code))]

pub mod collect;
pub mod diff;
pub mod error;
pub mod exit;
pub mod ledger;
pub mod model;
pub mod report;
