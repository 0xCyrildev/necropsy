//! Process exit statuses.
//!
//! A forensics CLI gets scripted: CI, triage queues, alert pipelines. Those
//! callers need "no findings" and "I could not read anything" to be
//! distinguishable without parsing prose, which is why every failure path in the
//! previous implementation returning 0 was a defect rather than a detail.

use crate::error::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// Collected and analyzed, nothing at or above `--fail-on`.
    Ok = 0,
    /// Collected and analyzed, with findings at or above the configured level.
    Findings = 1,
    /// The command itself was wrong: bad flags, bad transaction hash shape.
    Usage = 2,
    /// Nothing could be analyzed: no endpoint, RPC failure, transaction absent.
    Unavailable = 3,
    /// Analyzed, but some input could not be accounted for. The report is
    /// partial and says so.
    Degraded = 4,
}

impl Exit {
    pub fn code(self) -> i32 {
        self as i32
    }

    /// Map a failure to a status. Note that a *transaction* that reverted is not
    /// an error at all — analyzing a failed transaction is the point of the tool,
    /// so that path returns a report and exits on findings, never here.
    pub fn from_error(e: &Error) -> Exit {
        match e {
            Error::NoRpcUrl
            | Error::BadTxHash { .. }
            | Error::Input { .. }
            | Error::Http {
                status: 400..=404, ..
            } => Exit::Usage,
            _ => Exit::Unavailable,
        }
    }
}

impl From<Exit> for std::process::ExitCode {
    fn from(e: Exit) -> std::process::ExitCode {
        // 2 and 4 are deliberate choices, so the standard Failure/Success
        // mapping does not get to decide them.
        std::process::ExitCode::from(e.code() as u8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_the_documented_numbers() {
        for (e, c) in [
            (Exit::Ok, 0u8),
            (Exit::Findings, 1),
            (Exit::Usage, 2),
            (Exit::Unavailable, 3),
            (Exit::Degraded, 4),
        ] {
            assert_eq!(e.code() as u8, c);
            assert_eq!(
                std::process::ExitCode::from(e),
                std::process::ExitCode::from(c)
            );
        }
    }

    #[test]
    fn a_bad_hash_is_usage_and_a_dead_endpoint_is_unavailable() {
        let usage = Error::BadTxHash {
            input: "-vm".into(),
            reason: "not hex".into(),
        };
        assert_eq!(Exit::from_error(&usage), Exit::Usage);
        let gone = Error::Rpc("connection refused".into());
        assert_eq!(Exit::from_error(&gone), Exit::Unavailable);
        let absent = Error::NotFound { hash: "0x0".into() };
        assert_eq!(Exit::from_error(&absent), Exit::Unavailable);
        let wrong_chain = Error::ChainMismatch {
            endpoint: 10,
            requested: 1,
        };
        assert_eq!(
            Exit::from_error(&wrong_chain),
            Exit::Unavailable,
            "analyzing chain A while pricing chain B must stop the run, not warn"
        );
    }

    #[test]
    fn missing_cast_is_unavailable_not_usage() {
        // A user with --collector cast and no Foundry installed cannot proceed;
        // that is an environment failure, not a malformed command.
        assert_eq!(Exit::from_error(&Error::CastMissing), Exit::Unavailable);
    }
}
