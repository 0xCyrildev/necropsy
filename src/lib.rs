//! Necropsy: post-transaction forensics for EVM chains.
//!
//! Library surface. `main.rs` is a thin wrapper over these modules so the
//! parsers, ledger and analysis layer can be tested without spawning the CLI.

pub mod collect;
pub mod diff;
pub mod error;
pub mod exit;
pub mod ledger;
pub mod model;
pub mod report;
