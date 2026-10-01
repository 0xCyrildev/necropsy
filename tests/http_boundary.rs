//! The HTTP boundary, tested against a socket on the loopback interface.
//!
//! The suite is described as hermetic, and it is: none of these files reach the internet.
//! But "hermetic" was being used to mean "no tests for the transport at all", which left the
//! bounds this file checks — response size, nesting depth, which statuses retry — verified by
//! reasoning rather than by evidence. A `TcpListener` on `127.0.0.1:0` is deterministic, needs
//! no endpoint and cannot rate-limit us, so there was never a reason for that gap.
//!
//! Each case speaks raw HTTP/1.1 rather than using a server framework: the responses are four
//! lines, and a dependency bought to avoid writing them would be the larger risk.

use necropsy::collect::rpc::{HttpRpc, Rpc};
use necropsy::error::Error;
use necropsy::exit::Exit;
use std::io::{BufRead, BufReader, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// Serve `responses` in order, one per connection. Returns the port, a counter of how many
/// requests actually arrived — which is how "did it retry?" becomes an assertion rather than a
/// claim — and the server handle.
fn serve(responses: Vec<String>) -> (u16, Arc<AtomicUsize>, JoinHandle<()>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("loopback bind");
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    let handle = std::thread::spawn(move || {
        for response in responses {
            let (mut socket, _) = listener.accept().expect("accept");
            // Counted after the accept, so the number is requests served, not responses the
            // test happened to queue up.
            counter.fetch_add(1, Ordering::SeqCst);
            // Drain the request headers, or the client blocks writing a body it has already
            // sent. The body itself is never parsed here — the test is about what comes back.
            {
                let mut reader = BufReader::new(socket.try_clone().unwrap());
                let mut line = String::new();
                loop {
                    line.clear();
                    match reader.read_line(&mut line) {
                        Ok(0) => break,
                        Ok(_) if line.trim().is_empty() => break,
                        Ok(_) => {}
                        Err(_) => break,
                    }
                }
            }
            let _ = socket.write_all(response.as_bytes());
            let _ = socket.flush();
        }
    });
    (port, hits, handle)
}

fn http_response(body: &str, extra: Option<&str>) -> String {
    format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n{}\r\n{body}",
        body.len(),
        extra.unwrap_or("")
    )
}

fn status_response(status: &str, body: &str, extra: Option<&str>) -> String {
    format!(
        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n{}\r\n{body}",
        body.len(),
        extra.unwrap_or("")
    )
}

/// `--timeout` is per call and the retries sleep; keep every case inside a second or two.
fn client(port: u16, max_bytes: u64, max_depth: usize) -> HttpRpc {
    HttpRpc::with_limits(
        &format!("http://127.0.0.1:{port}"),
        Duration::from_secs(5),
        2,
        max_bytes,
        max_depth,
    )
}

const OK_BODY: &str = r#"{"jsonrpc":"2.0","id":1,"result":{"chainId":"0x1"}}"#;

#[test]
fn a_normal_answer_arrives_through_the_real_transport() {
    let (port, hits, server) = serve(vec![http_response(OK_BODY, None)]);
    let rpc = client(port, 1024 * 1024, 128);
    let value = rpc
        .request("eth_chainId", &[])
        .expect("the response parses");
    assert_eq!(value["chainId"], "0x1");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "a success is asked for once"
    );
    drop(server);
}

#[test]
fn a_jsonrpc_error_envelope_is_an_answer_not_a_transport_fault() {
    // -32601 is what `--collector auto` reads to decide to switch mechanism. If the client
    // turned it into a retryable transport error, `auto` would never see it.
    let body = r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}"#;
    let (port, _hits, server) = serve(vec![http_response(body, None)]);
    let rpc = client(port, 1024 * 1024, 128);
    let e = rpc.request("debug_traceTransaction", &[]).unwrap_err();
    assert!(
        matches!(e, Error::RpcError { code: -32601, .. }),
        "the collector fallback depends on this exact shape: {e}"
    );
    drop(server);
}

#[test]
fn a_rate_limit_retries_and_a_wrong_path_does_not() {
    // A 502 says "ask again" — a shed, at 03:00, from a public endpoint. A 404 says "there is
    // nothing there", and re-asking for a missing path is how a misconfigured endpoint turns
    // into a slow run that still ends in the wrong blame.
    let (port, hits, server) = serve(vec![
        status_response("502 Bad Gateway", "{}", None),
        http_response(OK_BODY, None),
    ]);
    let rpc = client(port, 1024 * 1024, 128);
    let value = rpc
        .request("eth_chainId", &[])
        .expect("a 429 followed by a 200 succeeds");
    assert_eq!(value["chainId"], "0x1");
    assert_eq!(hits.load(Ordering::SeqCst), 2, "one retry happened");
    drop(server);

    let (port2, hits2, server2) = serve(vec![
        status_response("404 Not Found", "<html>gateway</html>", None),
        http_response(OK_BODY, None),
    ]);
    let rpc2 = client(port2, 1024 * 1024, 128);
    let e = rpc2.request("eth_chainId", &[]).unwrap_err();
    assert!(matches!(e, Error::Http { status: 404 }), "{e}");
    assert_eq!(
        hits2.load(Ordering::SeqCst),
        1,
        "a 404 is not asked for twice"
    );
    // And it is not blamed on the operator's command line any more.
    assert_eq!(Exit::from_error(&e), Exit::Unavailable);
    drop(server2);
}

#[test]
fn a_retry_after_is_waited_out_rather_than_burned_immediately() {
    let (port, hits, server) = serve(vec![
        status_response("429 Too Many Requests", "{}", Some("retry-after: 1\r\n")),
        http_response(OK_BODY, None),
    ]);
    let rpc = client(port, 1024 * 1024, 128);
    let start = Instant::now();
    let value = rpc
        .request("eth_chainId", &[])
        .expect("the second attempt answers");
    let elapsed = start.elapsed();
    assert_eq!(value["chainId"], "0x1");
    assert_eq!(hits.load(Ordering::SeqCst), 2);
    assert!(
        elapsed >= Duration::from_millis(950),
        "the endpoint asked for 1s and got it: {elapsed:?}"
    );
    drop(server);
}

#[test]
fn an_oversized_response_is_refused_not_truncated() {
    // The cap is what turns "unlimited memory" into a decision. 64 KiB of JSON-RPC envelope,
    // client capped at 8 KiB.
    let fat = format!(
        r#"{{"jsonrpc":"2.0","id":1,"result":{{"blob":"{}"}}}}"#,
        "x".repeat(64 * 1024)
    );
    let (port, hits, server) = serve(vec![http_response(&fat, None)]);
    let rpc = client(port, 8 * 1024, 128);
    let e = rpc.request("debug_traceTransaction", &[]).unwrap_err();
    assert!(
        matches!(e, Error::ResponseTooLarge { limit } if limit == 8 * 1024),
        "{e}"
    );
    assert!(e.to_string().contains("--max-response-mb"), "{e}");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "asking again gets the same oversized answer"
    );
    assert_eq!(Exit::from_error(&e), Exit::Unavailable);
    drop(server);
}

#[test]
fn nesting_past_the_bound_is_named_in_levels() {
    // 200 levels of array inside a legal JSON-RPC envelope. `serde_json` alone refuses this
    // at 128 with a *parse* error, which would read as "this endpoint sent garbage".
    let deep = format!("{}1{}", "[".repeat(200), "]".repeat(200));
    let body = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{deep}}}"#);
    let (port, _hits, server) = serve(vec![http_response(&body, None)]);

    let strict = client(port, 1024 * 1024, 128);
    let e = strict.request("debug_traceTransaction", &[]).unwrap_err();
    assert!(
        matches!(e, Error::TraceTooDeep { depth: 201, .. }),
        "the refusal should count the envelope too: {e}"
    );
    assert!(e.to_string().contains("--max-trace-depth"), "{e}");

    let (port2, _h2, server2) = serve(vec![http_response(&body, None)]);
    let lenient = client(port2, 1024 * 1024, 4096);
    let value = lenient
        .request("debug_traceTransaction", &[])
        .expect("a document inside our own bound parses, past serde's");
    // `parse_envelope` hands back the contents of `result`, so the array is the value.
    assert!(value.is_array(), "the tree came through: {value}");
    drop(server);
    drop(server2);
}

#[test]
fn a_gateway_html_page_is_a_readable_failure() {
    // The realistic version of "not JSON": a proxy answering with a page. It must arrive as
    // one line, not as a panic and not as an empty trace.
    // 400, not 502: a shed is retryable and is tested as one below. A refused request is not,
    // and the difference is the whole point of classifying statuses at all.
    let (port, hits, server) = serve(vec![
        status_response("400 Bad Request", "<html><body>400</body></html>", None),
        http_response(OK_BODY, None),
    ]);
    let rpc = client(port, 1024 * 1024, 128);
    let e = rpc.request("eth_chainId", &[]).unwrap_err();
    assert!(matches!(e, Error::Http { status: 400 }), "{e}");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "a refused request is not re-sent"
    );
    assert_eq!(Exit::from_error(&e), Exit::Unavailable);
    drop(server);
}

#[test]
fn the_endpoint_host_is_describable_without_the_path_being_readable() {
    // `describe()` is printed in the report. The port is fine; a key in the path is not.
    let (port, _hits, server) = serve(vec![http_response(OK_BODY, None)]);
    let rpc = HttpRpc::new(
        &format!("http://127.0.0.1:{port}/v2/SECRETPARTY1234567890"),
        Duration::from_secs(5),
        2,
    );
    let said = rpc.describe();
    assert!(said.contains("127.0.0.1"), "{said}");
    assert!(!said.contains("SECRETPARTY1234567890"), "{said}");
    drop(server);
}
