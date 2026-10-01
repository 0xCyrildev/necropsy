//! Errors and their exit codes.
//!
//! Every failure path in the previous implementation printed and then `return`ed
//! from `main`, so a script saw exit 0 on a transaction it never fetched. Errors
//! are typed here precisely so the mapping to exit status is mechanical.

use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("no RPC endpoint configured: pass --rpc-url or set ETH_RPC_URL")]
    NoRpcUrl,

    #[error("invalid transaction hash {input:?}: {reason}")]
    BadTxHash { input: String, reason: String },

    #[error("rpc request failed: {0}")]
    Rpc(String),

    #[error("rpc endpoint answered HTTP {status}")]
    Http { status: u16 },

    /// The response was bounded on purpose. Silence here would be the worst outcome a
    /// forensics tool can have: a truncated trace parses into a smaller tree, and a
    /// smaller tree is a confident wrong answer about who received what. Phrased without a
    /// mechanism, because the same rule now covers the HTTP body and `cast`'s stdout.
    #[error(
        "the answer was larger than {limit} bytes and was refused, not truncated; raise --max-response-mb"
    )]
    ResponseTooLarge { limit: u64 },

    #[error("trace nests {depth} levels deep, past the {limit} allowed; raise --max-trace-depth")]
    TraceTooDeep { depth: usize, limit: usize },

    #[error("rpc endpoint answered JSON-RPC error {code}: {message}")]
    RpcError { code: i64, message: String },

    #[error("transaction {hash} was not found on this endpoint")]
    NotFound { hash: String },

    #[error("endpoint reports chain id {endpoint}, which is not the requested chain {requested}")]
    ChainMismatch { endpoint: u64, requested: u64 },

    #[error("no trace could be collected: {0}")]
    Collect(String),

    #[error("`cast` is not on PATH; install Foundry or use --collector rpc")]
    CastMissing,

    #[error("`cast` did not finish within {0:?}")]
    CastTimeout(Duration),

    /// `ETH_RPC_URL` is configuration that happens to be set; `--rpc-url` is a sentence
    /// about *this* run. The first can coexist with `--from-json`, the second contradicts
    /// it, and neither is printed here — the endpoint may carry a credential.
    #[error("--from-json {path:?} and --rpc-url name two sources for one run; pass one")]
    MixedSource { path: String },

    #[error("input file {path}: {message}")]
    Input { path: String, message: String },

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Strings that must never appear in output.
///
/// The previous implementation passed the RPC URL to `cast` as a command-line
/// argument — visible to any process in `/proc/<pid>/cmdline` — and then printed
/// `cast`'s stderr verbatim on failure, which is where provider errors embed the
/// full URL including the key. Both leak a credential into terminal scrollback,
/// CI logs and anything pasted from them.
#[derive(Debug, Clone, Default)]
pub struct Redactor {
    needles: Vec<String>,
}

impl Redactor {
    pub fn new<I, S>(secrets: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut needles: Vec<String> = secrets
            .into_iter()
            .map(|s| s.as_ref().to_string())
            .filter(|s| s.len() >= 4)
            .collect();
        // Longest first: replacing a short substring before the whole URL would
        // leave fragments of the credential behind.
        needles.sort_by_key(|b| std::cmp::Reverse(b.len()));
        needles.dedup();
        Redactor { needles }
    }

    /// Derive the credential-shaped parts of an endpoint URL. A key can sit in
    /// the userinfo, in the path (the common `…/v2/<key>` shape), or in a query
    /// parameter, so all three are treated as secrets.
    pub fn from_url(url: &str) -> Self {
        let mut parts: Vec<String> = vec![url.to_string()];
        if let Some(rest) = url.split_once("://").map(|(_, r)| r) {
            let authority = rest.split(['/', '?']).next().unwrap_or("");
            if let Some((userinfo, hostpart)) = authority.split_once('@') {
                parts.push(userinfo.to_string());
                parts.push(format!("{userinfo}@{hostpart}"));
                // The password alone is the credential, and an error message can
                // quote just that piece without the username attached.
                if let Some((user, pass)) = userinfo.split_once(':') {
                    parts.push(pass.to_string());
                    parts.push(user.to_string());
                }
            }
            let path = rest.split(['?']).next().unwrap_or("");
            if let Some(seg) = path.rsplit('/').next().filter(|s| s.len() >= 12) {
                parts.push(seg.to_string());
            }
            if let Some((_, query)) = rest.split_once('?') {
                for kv in query.split('&') {
                    if let Some((k, v)) = kv.split_once('=')
                        && matches!(
                            k.to_ascii_lowercase().as_str(),
                            "key" | "api_key" | "apikey" | "token"
                        )
                    {
                        parts.push(v.to_string());
                        parts.push(format!("{k}={v}"));
                    }
                }
            }
        }
        Redactor::new(parts)
    }

    pub fn redact(&self, text: &str) -> String {
        let mut out = text.to_string();
        for needle in &self.needles {
            out = replace_ci(&out, needle, "<redacted>");
        }
        out
    }

    /// One line, capped. A provider's full error body routinely contains request
    /// metadata we have not audited for secrets, so the default is minimal and
    /// `--verbose` is what opts into the whole thing (still redacted).
    pub fn first_line(&self, text: &str) -> String {
        let trimmed = text
            .lines()
            .find(|l| !l.trim().is_empty())
            .unwrap_or("")
            .trim();
        let one = if trimmed.chars().count() > 400 {
            let cut: String = trimmed.chars().take(400).collect();
            format!("{cut}…")
        } else {
            trimmed.to_string()
        };
        self.redact(&one)
    }
}

fn replace_ci(haystack: &str, needle: &str, replacement: &str) -> String {
    if needle.is_empty() || !needle.is_ascii() || !haystack.is_ascii() {
        return haystack.to_string();
    }
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    let mut out = String::with_capacity(haystack.len());
    let mut i = 0;
    while i < h.len() {
        if i + n.len() <= h.len() && h[i..i + n.len()].eq_ignore_ascii_case(n) {
            out.push_str(replacement);
            i += n.len();
        } else {
            out.push(h[i] as char);
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_a_key_in_the_path() {
        let r = Redactor::from_url("https://g.alchemy.com/v2/abcdefghIJKLMN1234567890");
        let leaked = "request to https://g.alchemy.com/v2/abcdefghIJKLMN1234567890 failed: 429";
        let got = r.redact(leaked);
        assert!(!got.contains("abcdefghIJKLMN"), "{got}");
        assert!(got.contains("<redacted>"));
    }

    #[test]
    fn redacts_userinfo_and_query_credentials() {
        let r =
            Redactor::from_url("https://user:secretpw@host.example/rpc?key=TOPSECRETVALUE1&x=1");
        for leak in [
            "dialing https://user:secretpw@host.example/rpc?key=TOPSECRETVALUE1",
            "secretpw",
            "TOPSECRETVALUE1",
        ] {
            assert!(
                !r.redact(leak).contains("secretpw"),
                "userinfo leaked: {leak}"
            );
            assert!(
                !r.redact(leak).contains("TOPSECRETVALUE1"),
                "query key leaked: {leak}"
            );
        }
    }

    #[test]
    fn case_differences_still_redact() {
        let r = Redactor::new(["AbCdEf123456"]);
        assert!(
            r.redact("token abcdef123456 expired")
                .contains("<redacted>")
        );
    }

    #[test]
    fn first_line_truncates_and_keeps_the_message() {
        let r = Redactor::new(["s3cr3tkey12345"]);
        let multi = "\nprovider error: https://x.example/v2/s3cr3tkey12345\nContext:\n- blah\n";
        let one = r.first_line(multi);
        assert_eq!(one.lines().count(), 1);
        assert!(one.starts_with("provider error:"), "{one}");
        assert!(!one.contains("s3cr3tkey12345"));
    }

    #[test]
    fn short_or_empty_secrets_are_not_needles() {
        // Replacing "0x" or "a" everywhere would destroy the message without
        // protecting anything.
        let r = Redactor::new(["a", "0x", ""]);
        assert_eq!(r.redact("0xdeadbeef"), "0xdeadbeef");
    }
}
