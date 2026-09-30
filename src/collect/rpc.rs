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

#[derive(Debug, Clone)]
pub struct HttpRpc {
    url: String,
    redactor: Redactor,
    timeout: Duration,
    retries: u32,
}

impl HttpRpc {
    pub fn new(url: &str, timeout: Duration, retries: u32) -> Self {
        HttpRpc {
            url: url.to_string(),
            redactor: Redactor::from_url(url),
            timeout,
            retries,
        }
    }

    fn send_once(&self, body: &Value) -> std::result::Result<Value, ureq::Error> {
        let mut config = ureq::config::Config::builder().timeout_per_call(Some(self.timeout));
        // `cast` does system-proxy detection and so must we, or the same
        // --rpc-url works under one tool and not the other.
        if let Some(p) = ureq::Proxy::try_from_env() {
            config = config.proxy(Some(p));
        }
        let agent = ureq::Agent::new_with_config(config.build());
        let mut resp = agent.post(&self.url).send_json(body)?;
        resp.body_mut().read_json::<Value>()
    }
}

impl Rpc for HttpRpc {
    fn request(&self, method: &str, params: &[Value]) -> Result<Value> {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let mut last: Option<Error> = None;
        for attempt in 0..=self.retries {
            match self.send_once(&body) {
                Ok(value) => return parse_envelope(value, method, &self.redactor),
                Err(e) => {
                    // A 4xx/5xx is a deterministic answer: retrying it just makes
                    // a failed run slower. Only transport faults retry.
                    let retryable = !matches!(e, ureq::Error::StatusCode(_));
                    let msg = self.redactor.first_line(&e.to_string());
                    last = Some(match e {
                        ureq::Error::StatusCode(status) => Error::Http { status },
                        _ => Error::Rpc(msg),
                    });
                    if !retryable || attempt == self.retries {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(300 * (1 << attempt)));
                }
            }
        }
        Err(last.unwrap_or_else(|| Error::Rpc(format!("{method}: failed with no error value"))))
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

/// An RPC backed by canned answers: what the offline suites and `--from-json`
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
