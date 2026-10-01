//! Minimal JSON-RPC client.
//!
//! Deliberately sequential and never batched: measured against
//! `https://eth.drpc.org`, a JSON-RPC *batch* request is refused while every
//! single method in it works, and a refused batch reads exactly like "the chain
//! has nothing here". A forensics tool must not turn a transport answer into an
//! absence of evidence, so batching is not offered at all.

use crate::error::{Error, Redactor, Result};
use serde_json::{Value, json};
use std::str::FromStr;
use std::time::Duration;

/// The seam every collector and analysis is written against, so the whole
/// pipeline can run offline against committed fixtures. `Send + Sync` because
/// collection happens on a thread with an explicitly sized stack.
pub trait Rpc: Send + Sync {
    fn request(&self, method: &str, params: &[Value]) -> Result<Value>;

    /// Endpoint identity for the report. Already redacted: this string is
    /// printed, so it must not be able to carry a key.
    fn describe(&self) -> String;
}

impl<R: Rpc + ?Sized> Rpc for &R {
    fn request(&self, method: &str, params: &[Value]) -> Result<Value> {
        (**self).request(method, params)
    }
    fn describe(&self) -> String {
        (**self).describe()
    }
}

/// The largest response necropsy will read, in bytes, unless `--max-response-mb` says
/// otherwise. Measured across the 16 mainnet transactions in the live record, the biggest
/// `callTracer` answer is 62 KB, so this is ~500x the largest real answer the tool has ever
/// had to work with — and one number short of "unlimited", which is `ureq`'s default and
/// means a gateway HTML page, a mispointed URL or a hostile endpoint decides this process's
/// memory.
pub const DEFAULT_MAX_RESPONSE_BYTES: u64 = 32 * 1024 * 1024;

/// How deep a JSON document may nest before it is refused, unless `--max-trace-depth` says
/// otherwise. `serde_json`'s own limit is 128 and is disabled here, because a genuine
/// reentrancy trace nests past it and the resulting *parse* error reads as "this is not
/// JSON" rather than as the depth problem it is. 2,048 costs roughly a megabyte of stack on
/// the collection thread (256 MiB), which is the budget that decides it.
pub const DEFAULT_MAX_TRACE_DEPTH: usize = 2048;

#[derive(Clone)]
pub struct HttpRpc {
    url: String,
    redactor: Redactor,
    retries: u32,
    max_bytes: u64,
    max_depth: usize,
    agent: ureq::Agent,
}

/// Statuses worth a second attempt. A rate limit and a shed are answers about *load*;
/// re-asking is the whole point of them, and they are exactly what a public endpoint gives
/// you at 03:00 when you are working an incident.
fn retryable_status(status: u16) -> bool {
    matches!(status, 408 | 425 | 429 | 500 | 502 | 503 | 504)
}

impl HttpRpc {
    pub fn new(url: &str, timeout: Duration, retries: u32) -> Self {
        HttpRpc::with_limits(
            url,
            timeout,
            retries,
            DEFAULT_MAX_RESPONSE_BYTES,
            DEFAULT_MAX_TRACE_DEPTH,
        )
    }

    /// The bounds are constructor arguments rather than globals because the offline suites
    /// and `examples/` must be able to ask for a *smaller* one and watch it fire.
    pub fn with_limits(
        url: &str,
        timeout: Duration,
        retries: u32,
        max_bytes: u64,
        max_depth: usize,
    ) -> Self {
        let mut config = ureq::config::Config::builder()
            .timeout_per_call(Some(timeout))
            // necropsy is a forensics tool that scripts against exit codes. A 404 has to
            // arrive as a response the caller can read the status of, not as an error that
            // has already thrown the headers away — which is also where `Retry-After` lives.
            .http_status_as_error(false)
            // Says who is asking, in terms an endpoint operator can act on. Rate limits are
            // often set from the UA, and "unknown client" is not recoverable after the fact.
            .user_agent(concat!("necropsy/", env!("CARGO_PKG_VERSION")));
        // `cast` does system-proxy detection and so must we, or the same
        // --rpc-url works under one tool and not the other.
        if let Some(p) = ureq::Proxy::try_from_env() {
            config = config.proxy(Some(p));
        }
        HttpRpc {
            url: url.to_string(),
            redactor: Redactor::from_url(url),
            retries,
            max_bytes,
            max_depth,
            // One agent, cloned per call: `Agent::clone` is documented cheap, and building
            // a fresh agent per request put a full TLS handshake on every one of a
            // deliberately *sequential* client.
            agent: ureq::Agent::new_with_config(config.build()),
        }
    }

    /// Read at most `max_bytes + 1`, so "exactly at the limit" and "over it" are different
    /// observable facts rather than one silent truncation.
    fn read_capped(
        &self,
        resp: &mut ureq::http::Response<ureq::Body>,
    ) -> std::result::Result<Vec<u8>, ureq::Error> {
        use std::io::Read;
        let mut reader = resp.body_mut().as_reader();
        let mut buf = Vec::new();
        reader
            .by_ref()
            .take(self.max_bytes.saturating_add(1))
            .read_to_end(&mut buf)?;
        Ok(buf)
    }

    /// A transport fault, in one line and with the credential out of it.
    fn transport_error(&self, e: &impl std::fmt::Display) -> String {
        self.redactor.first_line(&e.to_string())
    }

    /// Parse under the shared depth guard. The ordering that matters — measure, then
    /// switch off the parser's own limit — is documented on
    /// [`crate::collect::depth::bounded_value`].
    fn parse_capped(&self, bytes: &[u8], _method: &str) -> Result<Value> {
        crate::collect::depth::bounded_value(bytes, self.max_depth)
    }
}

/// One attempt, sorted into what a retry loop can use.
enum Attempt {
    Answer(Value),
    /// The endpoint answered something necropsy will not read. Asking again cannot change
    /// that, so it ends the loop and keeps its own exit status.
    Fatal(Error),
    /// Transport, or a status that says "try later".
    Retry(String),
    /// A status that says "try later", with the endpoint's own number of seconds attached.
    Wait(String, Option<u64>),
}

impl Rpc for HttpRpc {
    fn request(&self, method: &str, params: &[Value]) -> Result<Value> {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let mut last = Error::Rpc(format!("{method}: failed with no error value"));
        for attempt in 0..=self.retries {
            match self.send_once(&body, method) {
                Attempt::Answer(value) => return Ok(value),
                Attempt::Fatal(e) => return Err(e),
                Attempt::Retry(why) => last = Error::Rpc(why),
                Attempt::Wait(why, after) => {
                    last = Error::Rpc(why);
                    if attempt == self.retries {
                        break;
                    }
                    // Backoff doubles from 300 ms; a `Retry-After` the endpoint actually sent
                    // is honoured, but capped, because an endpoint asking for an hour is not
                    // evidence about the transaction.
                    let backoff = Duration::from_millis(300 * (1 << attempt));
                    let wait = after
                        .map(|s| Duration::from_secs(s.min(15)))
                        .unwrap_or(backoff)
                        .max(backoff);
                    std::thread::sleep(wait);
                    continue;
                }
            }
            if attempt == self.retries {
                break;
            }
            std::thread::sleep(Duration::from_millis(300 * (1 << attempt)));
        }
        Err(last)
    }

    fn describe(&self) -> String {
        // Host only, never the path or userinfo: enough for an analyst to know
        // which endpoint answered, not enough to replay the credential.
        let host = self
            .url
            .split_once("://")
            .map(|(_, r)| r.split(['/', '?']).next().unwrap_or(r))
            .unwrap_or(&self.url);
        self.redactor.redact(host)
    }
}

impl HttpRpc {
    fn send_once(&self, body: &Value, method: &str) -> Attempt {
        let mut resp = match self.agent.post(&self.url).send_json(body) {
            Ok(resp) => resp,
            Err(e) => return Attempt::Retry(self.transport_error(&e)),
        };
        let status = resp.status();
        if !status.is_success() {
            let why = format!("{method}: http status {status}");
            // `Retry-After` in delta-seconds. The HTTP-date form would need a clock and a
            // parser for a header almost no RPC gateway sends, so an unreadable value is
            // treated as absent — which is the same outcome as never having asked.
            let after = resp
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse::<u64>().ok());
            let code = status.as_u16();
            return if retryable_status(code) {
                Attempt::Wait(why, after)
            } else {
                Attempt::Fatal(Error::Http { status: code })
            };
        }
        let bytes = match self.read_capped(&mut resp) {
            Ok(bytes) => bytes,
            Err(e) => return Attempt::Retry(self.transport_error(&e)),
        };
        // One byte past the cap is the proof the cap bit, and the reason this is Fatal
        // rather than a retry: asking again gets the same oversized answer.
        if bytes.len() as u64 > self.max_bytes {
            return Attempt::Fatal(Error::ResponseTooLarge {
                limit: self.max_bytes,
            });
        }
        match self.parse_capped(&bytes, method) {
            Ok(value) => match parse_envelope(value, method, &self.redactor) {
                // A JSON-RPC error envelope is an *answer*, including -32601, which is how
                // `auto` knows to switch collectors. Only transport faults retry.
                Ok(result) => Attempt::Answer(result),
                Err(e) => Attempt::Fatal(e),
            },
            Err(e) => Attempt::Fatal(e),
        }
    }
}

fn parse_envelope(mut value: Value, method: &str, redactor: &Redactor) -> Result<Value> {
    if let Some(err) = value.get("error") {
        if !err.is_null() {
            let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(-1);
            let message = err
                .get("message")
                .and_then(|m| m.as_str())
                .map(|s| redactor.redact(s))
                .unwrap_else_placeholder();
            return Err(Error::RpcError { code, message });
        }
    }
    value.get_mut("result").map(std::mem::take).ok_or_else(|| {
        Error::Rpc(format!(
            "{method}: response carried neither `result` nor `error`"
        ))
    })
}

trait UnwrapElsePlaceholder {
    fn unwrap_else_placeholder(self) -> String;
}
impl UnwrapElsePlaceholder for Option<String> {
    fn unwrap_else_placeholder(self) -> String {
        self.unwrap_or_else(|| "unspecified error".to_string())
    }
}

/// An RPC backed by canned answers: what the offline suites
/// use, and the reason no test in this crate can touch the network by accident.
pub struct MemoryRpc {
    responses: Vec<(String, Value)>,
}

impl MemoryRpc {
    pub fn new<I, S>(entries: I) -> Self
    where
        I: IntoIterator<Item = (S, Value)>,
        S: Into<String>,
    {
        MemoryRpc {
            responses: entries.into_iter().map(|(k, v)| (k.into(), v)).collect(),
        }
    }
}

impl Rpc for MemoryRpc {
    fn request(&self, method: &str, _params: &[Value]) -> Result<Value> {
        self.responses
            .iter()
            .find(|(m, _)| m == method)
            .map(|(_, v)| v.clone())
            .ok_or_else(|| Error::Rpc(format!("no canned response for {method}")))
    }

    fn describe(&self) -> String {
        "memory-fixture".to_string()
    }
}

pub fn hex_u64(s: &str) -> Option<u64> {
    let digits = s.strip_prefix("0x").unwrap_or(s);
    if digits.is_empty() {
        return Some(0);
    }
    u64::from_str_radix(digits, 16).ok()
}

/// RPC fields arrive as `"0x…"`, sometimes as absent, sometimes already numeric
/// from a lenient gateway. Absent is `None`, never 0 — a missing block number
/// printed as block 0 would be a fabrication.
pub fn field_hex_u64(obj: &Value, key: &str) -> Option<u64> {
    match obj.get(key) {
        Some(Value::String(s)) => hex_u64(s),
        Some(Value::Number(n)) => n.as_u64(),
        Some(Value::Null) | None => None,
        Some(_) => None,
    }
}

pub fn field_addr(obj: &Value, key: &str) -> Option<crate::model::Address> {
    obj.get(key)
        .and_then(|v| v.as_str())
        .and_then(|s| crate::model::Address::from_str(s).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_numbers_parse_and_absent_stays_absent() {
        assert_eq!(hex_u64("0x115df1e"), Some(18_210_590));
        assert_eq!(hex_u64("0x0"), Some(0));
        let obj = json!({ "a": "0xff", "b": 255, "c": null });
        assert_eq!(field_hex_u64(&obj, "a"), Some(255));
        assert_eq!(field_hex_u64(&obj, "b"), Some(255));
        assert_eq!(field_hex_u64(&obj, "c"), None);
        assert_eq!(field_hex_u64(&obj, "missing"), None);
    }

    #[test]
    fn jsonrpc_errors_keep_their_code_so_a_fallback_can_act_on_it() {
        // -32601 means "this node has no debug_ namespace", which is the exact
        // condition for switching collectors rather than failing.
        let red = Redactor::new(["unusedsecret1"]);
        let mut v =
            json!({"error": {"code": -32601, "message": "method not found"}, "result": null});
        let e = parse_envelope(v.take(), "debug_traceTransaction", &red).unwrap_err();
        match e {
            Error::RpcError { code, .. } => assert_eq!(code, -32601),
            other => panic!("expected RpcError, got {other:?}"),
        }
        // An explicit JSON null error is a success envelope.
        let ok = json!({"error": null, "result": {"x": 1}});
        assert!(parse_envelope(ok, "m", &red).is_ok());
        let neither = json!({ "id": 1 });
        assert!(matches!(
            parse_envelope(neither, "eth_call", &red),
            Err(Error::Rpc(_))
        ));
    }

    #[test]
    fn a_provider_error_message_is_redacted() {
        let r = Redactor::from_url("https://rpc.example/v2/SEKRETPATHVALUE1234");
        let mut v = json!({"error": {"code": -32000, "message": "upstream https://rpc.example/v2/SEKRETPATHVALUE1234 rejected us"}});
        let e = parse_envelope(v.take(), "eth_call", &r).unwrap_err();
        let text = e.to_string();
        assert!(!text.contains("SEKRETPATHVALUE1234"), "leaked: {text}");
    }

    #[test]
    fn memory_rpc_describes_itself_as_a_fixture_not_an_endpoint() {
        let m = MemoryRpc::new([("eth_chainId", json!("0x1"))]);
        assert_eq!(m.describe(), "memory-fixture");
        assert_eq!(m.request("eth_chainId", &[]).unwrap(), json!("0x1"));
        assert!(m.request("eth_getBalance", &[]).is_err());
    }
}
