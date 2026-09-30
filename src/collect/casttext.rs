//! The `cast` text collector: rendered trace lines in, [`Trace`] out.
//!
//! Hand-parsed rather than regexed, and every line is assigned exactly one
//! [`Disposition`]. That is the point. The previous implementation tested one
//! regex against each line and `continue`d on a miss, which is the worst possible
//! failure for a forensics tool: an unrecognised frame is not merely missing from
//! the tree, it also stops occupying a slot on the parent stack, so its children
//! re-parent to the grandparent and its later siblings detach a level up. One
//! unknown line quietly corrupts a whole subtree while every count still looks
//! reasonable.
//!
//! Line shapes below were captured from `cast 1.8.1` on real mainnet
//! transactions, not from documentation:
//!
//! ```text
//!   [116514] 0x3fC91A3afd…::execute{value: 100000000000000000}(0x0b08, […])
//!     ├─ [19628] 0xa2327a93…::transfer(0xCFFAd3…, 316820726 [3.168e8]) [delegatecall]
//!     │   ├─ emit Transfer(from: 0xFACf9E…, to: 0xCFFAd3…, amount: 316820726 [3.168e8])
//!     │   └─ ← [Return] true
//!     ├─ emit Sync(: 1.27e26, : 1.56e19)          <- unnamed params
//!   [1149217] → new <unknown>@0x9520e4Bb…
//!     └─ ← [Revert] ERC20: transfer amount exceeds balance
//! ```

use crate::error::Result;
use crate::model::{
    Address, Amount, CallKind, Collector, Disposition, Frame, FrameId, FrameStatus, Provenance,
    Trace, TraceBuilder,
};
use std::str::FromStr;

/// An `emit` line, with the frame it appeared inside. Whether that frame was a
/// delegatecall is resolved after the tree is built, via `Trace`'s `context`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextEmission {
    pub line: usize,
    pub name: String,
    /// Argument values with any `key:` prefix removed and the trailing
    /// `[1.695e9]` human-scale suffix dropped.
    pub args: Vec<String>,
    pub frame: Option<FrameId>,
}

#[derive(Debug, Clone)]
pub struct ParsedText {
    pub trace: Trace,
    pub emissions: Vec<TextEmission>,
    /// What `cast` said about the transaction's own outcome. `None` means the
    /// trailer was not present, which is not the same as success.
    pub cast_reported_success: Option<bool>,
    pub gas_used_line: Option<u64>,
}

const TREE_CHARS: [char; 6] = ['│', '├', '└', '─', ' ', '\t'];

const TRAILERS: &[&str] = &[
    "Traces:",
    "Gas used:",
    "Transaction successfully executed.",
    "Fail:",
    "Pass:",
    "##",
    "Setting block",
    "Block:",
    "Warning",
    "Compiling",
    "No files",
    "Error:",
];

fn indent_width(line: &str) -> usize {
    line.chars().take_while(|c| TREE_CHARS.contains(c)).count()
}

fn content(line: &str) -> &str {
    let idx = line
        .char_indices()
        .find(|(_, c)| !TREE_CHARS.contains(c))
        .map(|(i, _)| i)
        .unwrap_or(line.len());
    &line[idx..]
}

/// Split a bracketed argument list on top-level commas only: `[a, [b, c]], d`
/// must not split inside the nested brackets.
fn split_args(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut cur = String::new();
    for c in s.chars() {
        match c {
            '[' | '(' | '<' => {
                depth += 1;
                cur.push(c);
            }
            ']' | ')' | '>' => {
                depth -= 1;
                cur.push(c);
            }
            ',' if depth <= 0 => {
                out.push(std::mem::take(&mut cur).trim().to_string());
            }
            _ => cur.push(c),
        }
    }
    let last = cur.trim().to_string();
    if !last.is_empty() || !out.is_empty() {
        out.push(last);
    }
    out.into_iter().filter(|p| !p.is_empty()).collect()
}

/// `316820726 [3.168e8]` → `316820726`; `0xdeadbeef` → unchanged.
///
/// Only a trailing bracketed *number* is a scale hint. An array argument such as
/// `[0x01, 0x02]` also ends in `]`, and stripping it would delete the value
/// rather than format it, so the bracket contents are checked.
fn strip_scale(v: &str) -> String {
    let t = v.trim();
    if let Some(open) = t.rfind(" [")
        && t.ends_with(']')
    {
        let inner = &t[open + 2..t.len() - 1];
        if !inner.is_empty()
            && inner
                .chars()
                .all(|c| matches!(c, '0'..='9' | '.' | 'e' | 'E' | '+' | '-'))
        {
            return t[..open].trim().to_string();
        }
    }
    t.to_string()
}

fn parse_amount(v: &str) -> Option<Amount> {
    let t = strip_scale(v);
    Amount::from_decimal(&t).or_else(|| Amount::from_hex(&t))
}

fn parse_addr(v: &str) -> Option<Address> {
    let t = strip_scale(v);
    Address::from_str(&t).ok()
}

/// Drop a `key:` prefix — `from:`, `amount:`, `param0:`, or nothing at all for
/// unnamed params, which cast prints as a bare `: value`.
///
/// The key must be a bare identifier, so a value that happens to contain a colon
/// is not chopped in half.
fn strip_key(v: &str) -> String {
    match v.split_once(':') {
        Some((k, rest)) => {
            let k = k.trim();
            let identifier = k.is_empty()
                || (k
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                    && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'));
            if identifier {
                rest.trim().to_string()
            } else {
                v.trim().to_string()
            }
        }
        None => v.trim().to_string(),
    }
}

struct StackEntry {
    indent: usize,
    /// `None` marks a ghost: the frame at this indent could not be parsed, so
    /// anything nested under it has an unknown parent.
    frame: Option<FrameId>,
}

pub fn parse(raw: &str, cast_version: Option<String>) -> Result<ParsedText> {
    let mut b = TraceBuilder::new(Provenance {
        collector: Collector::CastTextRendered,
        cast_version,
        chain_id: None,
        block: None,
    });
    let mut stack: Vec<StackEntry> = Vec::new();
    let mut emissions: Vec<TextEmission> = Vec::new();
    let mut cast_reported_success = None;
    let mut gas_used_line = None;

    for (i, line) in raw.lines().enumerate() {
        let lineno = i + 1;
        let text = line.trim_end();
        if text.trim().is_empty() {
            b.line(Disposition::Blank);
            continue;
        }
        let body = content(text);
        let indent = indent_width(text);

        if body.starts_with("emit ") {
            b.line(Disposition::Emission);
            emissions.push(parse_emit(body, lineno, stack.last().and_then(|s| s.frame)));
            continue;
        }

        if body.starts_with('←') {
            b.line(Disposition::Result);
            apply_result(body, &mut b, &mut stack);
            continue;
        }

        if let Some(rest) = frame_body(body) {
            match parse_frame(rest) {
                Ok(spec) => {
                    let parent = nearest_frame(&stack, indent);
                    let f = Frame {
                        id: 0,
                        kind: spec.kind,
                        // The renderer prints only the callee, so the caller is
                        // unknown here and `TraceBuilder::push` fills it from the
                        // enclosing frame's context.
                        from: Address::ZERO,
                        to: spec.to,
                        context: Address::ZERO,
                        value: spec.value,
                        gas_used: spec.gas_used,
                        selector: None,
                        label: spec.label,
                        status: FrameStatus::Unknown,
                        return_bytes: None,
                        parent,
                        children: Vec::new(),
                        depth: 0,
                    };
                    let id = b.push(parent, f);
                    pop_to(&mut stack, indent);
                    stack.push(StackEntry {
                        indent,
                        frame: Some(id),
                    });
                }
                Err(why) => {
                    b.unclassified(lineno, body.to_string(), why);
                    pop_to(&mut stack, indent);
                    stack.push(StackEntry {
                        indent,
                        frame: None,
                    });
                }
            }
            continue;
        }

        if TRAILERS.iter().any(|t| body.starts_with(t)) {
            b.line(Disposition::Trailer);
            if body.starts_with("Transaction successfully executed.") {
                cast_reported_success = Some(true);
            } else if body.starts_with("Fail:") || body.starts_with("Error:") {
                cast_reported_success = Some(false);
            } else if let Some(n) = body.strip_prefix("Gas used:") {
                gas_used_line = n.trim().parse::<u64>().ok().or(gas_used_line);
            }
            continue;
        }

        b.unclassified(
            lineno,
            body.to_string(),
            "line matches no known frame, emit, result or trailer shape",
        );
    }

    let trace = b.finish();
    Ok(ParsedText {
        trace,
        emissions,
        cast_reported_success,
        gas_used_line,
    })
}

/// A line is a frame candidate when it starts with a `[` — the gas bracket. The
/// whole body is handed to `parse_frame`, which is the single place that decides
/// whether the bracket and the rest form a frame. Consuming the bracket here
/// would leave `parse_frame` unable to read gas, and dropping the line here would
/// lose the frame entirely.
fn frame_body(body: &str) -> Option<&str> {
    body.starts_with('[').then_some(body)
}

struct FrameSpec {
    kind: CallKind,
    to: Option<Address>,
    value: Option<Amount>,
    gas_used: Option<u64>,
    label: Option<String>,
}

fn parse_frame(rest: &str) -> std::result::Result<FrameSpec, &'static str> {
    let gas_used = rest
        .strip_prefix('[')
        .and_then(|r| r.split(']').next())
        .and_then(|d| d.parse::<u64>().ok());

    // frame_body() already consumed the bracket when it was well-formed; when the
    // line is bracket-shaped but broken, `rest` is the whole line and we must not
    // report it as successfully parsed.
    let body = if rest.starts_with('[') {
        match rest.find(']') {
            Some(i) => rest[i + 1..].trim_start(),
            None => return Err("gas bracket is unterminated"),
        }
    } else {
        rest
    };

    if let Some(create) = body.strip_prefix("→ new ") {
        // `→ new <unknown>@0x…` or `→ new TokenName@0x…`
        let addr_text = create.rsplit('@').next().unwrap_or("");
        let name = create
            .strip_suffix(&format!("@{addr_text}"))
            .unwrap_or(create);
        let to = parse_addr(addr_text).ok_or("create frame carries no parsable address")?;
        return Ok(FrameSpec {
            kind: CallKind::Create,
            to: Some(to),
            value: None,
            gas_used,
            label: Some(name.trim().to_string()),
        });
    }

    let (addr_text, tail) = body
        .split_once("::")
        .ok_or("no `::` between an address and a function name")?;
    let addr = parse_addr(addr_text.trim()).ok_or(
        "caller is not a 20-byte hex address (labels resolved, so this line is not address-keyed)",
    )?;

    let open = tail
        .find('(')
        .ok_or("function name is not followed by an argument list")?;
    let head = tail[..open].trim();

    let (name, value) = match head.find("{value:") {
        Some(vi) => {
            let name = head[..vi].trim();
            let vtext = &head[vi + "{value:".len()..];
            let vtext = vtext.trim_start_matches(':').trim();
            let inner = vtext.strip_suffix('}').unwrap_or(vtext);
            (name, parse_amount(inner))
        }
        None => (head.trim(), None),
    };

    let mut kind = CallKind::Call;
    let mut name = name.to_string();
    // The tag follows the closing paren in the raw line; recover it from `tail`.
    if let Some(pos) = tail.rfind(')') {
        let after = tail[pos + 1..].trim();
        if after.contains("delegatecall") {
            kind = CallKind::DelegateCall;
        } else if after.contains("staticcall") {
            kind = CallKind::StaticCall;
        } else if after.contains("callcode") {
            kind = CallKind::CallCode;
        } else if !after.is_empty() {
            name.push(' ');
            name.push_str(after);
        }
    }

    Ok(FrameSpec {
        kind,
        to: Some(addr),
        value,
        gas_used,
        label: if name.is_empty() { None } else { Some(name) },
    })
}

fn apply_result(body: &str, b: &mut TraceBuilder, stack: &mut Vec<StackEntry>) {
    let after = body['←'.len_utf8()..].trim_start();
    let status = if let Some(inner) = after.strip_prefix('[').and_then(|r| r.split(']').next()) {
        let rest = after
            .split_once(']')
            .map(|(_, r)| r.trim().to_string())
            .unwrap_or_default();
        match inner.trim() {
            "return" | "Return" | "Stop" | "SelfDestruct" | "ReturnSelfDestruct" => {
                FrameStatus::Success
            }
            "Revert" => FrameStatus::Reverted {
                reason: (!rest.is_empty()).then_some(rest),
            },
            other => FrameStatus::Failed {
                reason: Some(if rest.is_empty() {
                    other.to_string()
                } else {
                    rest
                }),
            },
        }
    } else {
        FrameStatus::Unknown
    };

    // A result line belongs to the frame currently open, i.e. the deepest real
    // frame on the stack. Ghosts are skipped: their children's results still
    // describe the ghost's own frame, which we cannot name.
    let target = stack.iter().rev().find_map(|s| s.frame);
    if let Some(id) = target {
        b.set_status(id, status);
        // The frame is complete; pop back to its parent so the next sibling
        // resolves against the same ancestor `cast` intended.
        if let Some(pos) = stack.iter().rposition(|s| s.frame == Some(id)) {
            stack.truncate(pos);
        }
    }
}

fn pop_to(stack: &mut Vec<StackEntry>, indent: usize) {
    while let Some(top) = stack.last() {
        if top.indent >= indent {
            stack.pop();
        } else {
            break;
        }
    }
}

fn nearest_frame(stack: &[StackEntry], indent: usize) -> Option<FrameId> {
    stack
        .iter()
        .rev()
        .find(|s| s.indent < indent)
        .and_then(|s| s.frame)
}

fn parse_emit(body: &str, line: usize, frame: Option<FrameId>) -> TextEmission {
    let inner = body.strip_prefix("emit ").unwrap_or(body);
    let (name, args_raw) = match inner.find('(') {
        Some(i) => {
            let (n, rest) = inner.split_at(i);
            (
                n.trim().to_string(),
                rest.strip_prefix('(')
                    .and_then(|r| r.strip_suffix(')'))
                    .unwrap_or(rest)
                    .to_string(),
            )
        }
        None => (inner.trim().to_string(), String::new()),
    };
    let args = split_args(&args_raw)
        .into_iter()
        .map(|s| strip_scale(&strip_key(&s)))
        .collect();
    TextEmission {
        line,
        name,
        args,
        frame,
    }
}

impl ParsedText {
    /// Token address for an emission: the storage context of the frame that
    /// emitted it. For a delegatecall frame that is the *proxy*, which is the
    /// whole reason this is resolved against `Trace.context` rather than the
    /// frame's own printed address.
    pub fn emission_token(&self, e: &TextEmission) -> Option<Address> {
        e.frame.and_then(|f| self.trace.frame(f)).map(|f| f.context)
    }

    /// Emissions that look like an ERC-20 `Transfer`. Labeled **heuristic** by
    /// every caller: text output has no topic0, so ERC-20 and ERC-721 cannot be
    /// told apart by signature, and this is exactly the case the receipt path
    /// settles exactly.
    pub fn transfer_candidates(&self) -> Vec<(Option<Address>, TextEmission)> {
        self.emissions
            .iter()
            .filter(|e| e.name == "Transfer")
            .map(|e| (self.emission_token(e), e.clone()))
            .collect()
    }
}

/// Parse the three-address-plus-amount shape used by the heuristic ledger.
pub fn as_erc20_shaped(args: &[String]) -> Option<(Address, Address, Amount)> {
    if args.len() != 3 {
        return None;
    }
    let from = parse_addr(&args[0])?;
    let to = parse_addr(&args[1])?;
    let amount = parse_amount(&args[2])?;
    Some((from, to, amount))
}

/// Build token events from rendered `emit` lines.
///
/// This is a **heuristic** and is only used when no receipt is available: text
/// output carries no topic0, so a `Transfer` here could be ERC-20 or ERC-721 and
/// there is no way on this path to tell. Callers must say so in the report, which
/// is why the count of lines that had to be guessed about is returned rather than
/// swallowed.
pub fn events_from_text(parsed: &ParsedText) -> (Vec<crate::model::TokenEvent>, usize) {
    let mut out = Vec::new();
    let mut ambiguous = 0usize;
    for e in &parsed.emissions {
        if e.name != "Transfer" {
            continue;
        }
        match (parsed.emission_token(e), as_erc20_shaped(&e.args)) {
            (Some(token), Some((from, to, amount))) => {
                out.push(crate::model::TokenEvent::Erc20Transfer {
                    token,
                    from,
                    to,
                    amount,
                    log_index: e.line as u32,
                })
            }
            _ => ambiguous += 1,
        }
    }
    (out, ambiguous)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROXY: &str = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
    const IMPL: &str = "0xa2327a938Febf5FEC13baCFb16Ae10EcBc4cbDCF";

    fn frames(t: &Trace) -> Vec<(String, String)> {
        t.root_walk()
            .iter()
            .map(|&id| {
                let f = t.frame(id).unwrap();
                (
                    f.to.map(|a| a.to_hex()).unwrap_or_default(),
                    f.label.clone().unwrap_or_default(),
                )
            })
            .collect()
    }

    // Verbatim shape from `cast run 0x5b515946… --debug-trace-transaction`.
    const USDC: &str = "Traces:
  [43725] 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48::transfer(0xCFFAd3200574698b78f32232aa9D63eABD290703, 316820726 [3.168e8])
    ├─ [19628] 0xa2327a938Febf5FEC13baCFb16Ae10EcBc4cbDCF::transfer(0xCFFAd3200574698b78f32232aa9D63eABD290703, 316820726 [3.168e8]) [delegatecall]
    │   ├─ emit Transfer(from: 0xFACf9Ec2D27045b31291e79f4Ac982cce66BF241, to: 0xCFFAd3200574698b78f32232aa9D63eABD290703, amount: 316820726 [3.168e8])
    │   └─ ← [Return] true
    └─ ← [Return] true


Transaction successfully executed.
Gas used: 43725
";

    #[test]
    fn parses_the_captured_usdc_trace_exactly() {
        let p = parse(USDC, Some("cast 1.8.1".into())).unwrap();
        assert_eq!(p.trace.len(), 2);
        assert_eq!(p.trace.unclassified.len(), 0, "{:?}", p.trace.unclassified);
        assert!(p.trace.conservation.balances());
        assert_eq!(p.trace.conservation.emissions, 1);
        assert_eq!(p.trace.conservation.results, 2);
        assert_eq!(p.cast_reported_success, Some(true));
        assert_eq!(p.gas_used_line, Some(43725));

        let root = p.trace.root.unwrap();
        assert_eq!(
            p.trace.frame(root).unwrap().to.map(|a| a.to_hex()).unwrap(),
            PROXY.to_lowercase()
        );
        assert_eq!(
            p.trace.frame(root).unwrap().gas_used,
            Some(43725),
            "the bracketed number is gas USED, not a limit"
        );
        let dl = *p.trace.children_of(root).first().unwrap();
        assert_eq!(p.trace.frame(dl).unwrap().kind, CallKind::DelegateCall);
        assert_eq!(
            p.trace.frame(dl).unwrap().to.map(|a| a.to_hex()).unwrap(),
            IMPL.to_lowercase()
        );
        assert_eq!(
            p.trace.frame(dl).unwrap().context.to_hex(),
            p.trace.frame(root).unwrap().to.unwrap().to_hex(),
            "the delegatecall frame's storage context is the proxy, and that is what an emitted Transfer belongs to"
        );

        assert_eq!(p.emissions.len(), 1);
        assert_eq!(
            p.emission_token(&p.emissions[0]).unwrap().to_hex(),
            PROXY.to_lowercase()
        );
        let (tok, e) = &p.transfer_candidates()[0];
        assert_eq!(tok.unwrap().to_hex(), PROXY.to_lowercase());
        let (from, to, amount) =
            as_erc20_shaped(&e.args).expect("captured args must be ERC-20 shaped");
        assert_eq!(from.to_hex(), "0xfacf9ec2d27045b31291e79f4ac982cce66bf241");
        assert_eq!(to.to_hex(), "0xcffad3200574698b78f32232aa9d63eabd290703");
        assert_eq!(amount.to_decimal_string(), "316820726");
    }

    // Verbatim shape from the captured Uniswap UR execute, which is the case the
    // old regex corrupted: `{value: …}` sits between the name and the paren.
    const VALUE: &str = "Traces:
  [116514] 0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD::execute{value: 100000000000000000}(0x0b08, [0x01, 0x02], 1695668315 [1.695e9])
    ├─ [23974] 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2::deposit{value: 100000000000000000}()
    │   ├─ emit Deposit(param0: 0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD, param1: 100000000000000000 [1e17])
    │   └─ ← [Return]
    ├─ [2851] 0x170dEC83C7753AaAD20c01a0016b5A2E143990d4::balanceOf(0xF54e4bbEF53D2c3A5e41AeFBe37eb4346CfEb5F1) [staticcall]
    │   └─ ← [Return] 0
    ├─ emit Sync(: 127634464603597248556706808 [1.276e26], : 15684704644811172740 [1.568e19])
    └─ ← [Return]
";

    #[test]
    fn value_is_extracted_and_the_function_name_is_not_corrupted() {
        let p = parse(VALUE, None).unwrap();
        assert_eq!(p.trace.unclassified.len(), 0, "{:?}", p.trace.unclassified);
        let root = p.trace.root.unwrap();
        let f = p.trace.frame(root).unwrap();
        assert_eq!(
            f.label.as_deref(),
            Some("execute"),
            "the old parser made this `execute{{value: …}}`"
        );
        assert_eq!(f.value.unwrap().to_decimal_string(), "100000000000000000");
        let kids = p.trace.children_of(root);
        assert_eq!(
            kids.len(),
            2,
            "deposit and balanceOf; the Sync line is an emit, not a frame"
        );
        let dep = p.trace.frame(kids[0]).unwrap();
        assert_eq!(dep.label.as_deref(), Some("deposit"));
        assert_eq!(dep.value.unwrap().to_decimal_string(), "100000000000000000");
        assert_eq!(dep.status, FrameStatus::Success);
        let bal = p.trace.frame(kids[1]).unwrap();
        assert_eq!(bal.kind, CallKind::StaticCall);
        assert_eq!(bal.label.as_deref(), Some("balanceOf"));
        assert_eq!(
            bal.value, None,
            "a staticcall forwards no value and the line does not say one"
        );
        // The nested frame's own result must not be applied to its parent.
        assert_eq!(p.trace.len(), 3, "execute, deposit, balanceOf");
        assert_eq!(p.emissions.len(), 2);
        assert_eq!(p.emissions[1].name, "Sync");
        // Unnamed params render as `: value`, so the key prefix is empty.
        assert_eq!(p.emissions[1].args.len(), 2);
        assert_eq!(p.emissions[1].args[0], "127634464603597248556706808");
    }

    #[test]
    fn revert_reason_is_captured_on_the_frame_it_belongs_to() {
        const REV: &str = "Traces:
  [33336] 0x6982508145454Ce325dDbE47a25d4ec3d2311933::transfer(0xc94259ec73D3b8271C360eBDc3333Af2138E06Da, 18901975697117306000000000 [1.89e25])
    └─ ← [Revert] ERC20: transfer amount exceeds balance


Gas used: 33336
";
        let p = parse(REV, None).unwrap();
        assert_eq!(
            p.cast_reported_success, None,
            "no success trailer was printed"
        );
        let root = p.trace.root.unwrap();
        match &p.trace.frame(root).unwrap().status {
            FrameStatus::Reverted { reason } => {
                assert_eq!(
                    reason.as_deref(),
                    Some("ERC20: transfer amount exceeds balance")
                )
            }
            other => panic!("expected revert with reason, got {other:?}"),
        }
    }

    #[test]
    fn creation_frames_are_parsed_including_a_named_create() {
        const CREATE: &str = "Traces:
  [1149217] → new <unknown>@0x9520e4Bb81F3c71ef8f6665aAf023c47dECa8db1
    └─ ← [Return] 5036 bytes of code
";
        let p = parse(CREATE, None).unwrap();
        assert_eq!(p.trace.unclassified.len(), 0);
        let root = p.trace.root.unwrap();
        let f = p.trace.frame(root).unwrap();
        assert_eq!(f.kind, CallKind::Create);
        assert_eq!(
            f.to.map(|a| a.to_hex()).unwrap(),
            "0x9520e4bb81f3c71ef8f6665aaf023c47deca8db1"
        );
        assert_eq!(
            f.context.to_hex(),
            f.to.unwrap().to_hex(),
            "a created contract is its own context"
        );
        assert_eq!(f.label.as_deref(), Some("<unknown>"));
    }

    #[test]
    fn a_labeled_create_is_not_silently_dropped() {
        // `→ new TokenName@0x…` — the old regex only accepted `<unknown>`.
        const LABELED: &str = "Traces:
  [1149217] → new MyToken@0x9520e4Bb81F3c71ef8f6665aAf023c47dECa8db1
    ├─ [100] 0x9520e4Bb81F3c71ef8f6665aAf023c47dECa8db1::initialize()
    │   └─ ← [Return]
    └─ ← [Return] 5036 bytes of code
";
        let p = parse(LABELED, None).unwrap();
        assert_eq!(p.trace.len(), 2);
        assert_eq!(p.trace.unclassified.len(), 0);
        assert_eq!(
            p.trace
                .frame(p.trace.root.unwrap())
                .unwrap()
                .label
                .as_deref(),
            Some("MyToken")
        );
        let child = *p.trace.children_of(p.trace.root.unwrap()).first().unwrap();
        assert_eq!(
            p.trace.frame(child).unwrap().depth,
            1,
            "the child of a named create must not become an orphan"
        );
    }

    #[test]
    fn an_unparseable_frame_does_not_steal_its_siblings_parent() {
        // The regression the conservation counter exists for. A labelled frame
        // (`USDC::transfer`, no 0x address) in the middle of a list: its
        // *sibling* must still attach to the real parent, and its *child* must
        // become an orphan rather than silently re-parenting to the grandparent.
        const BROKEN: &str = "Traces:
  [1000] 0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD::execute()
    ├─ [10] USDC::transfer(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2, 1)
    │   ├─ [11] 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2::inner()
    │   └─ ← [Return]
    ├─ [20] 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2::deposit()
    │   └─ ← [Return]
    └─ ← [Return]
";
        let p = parse(BROKEN, None).unwrap();
        assert_eq!(p.trace.conservation.frames, 3);
        assert_eq!(p.trace.conservation.unclassified, 1);
        assert!(p.trace.conservation.balances());
        let root = p.trace.root.unwrap();
        let kids = p.trace.children_of(root);
        assert_eq!(kids.len(), 1, "only the readable sibling attaches to root");
        assert_eq!(
            p.trace.frame(kids[0]).unwrap().label.as_deref(),
            Some("deposit"),
            "the sibling after an unparseable frame keeps its true parent"
        );
        assert_eq!(
            p.trace.orphans.len(),
            1,
            "and the child of the unparseable frame is an orphan, admitting it has an unknown parent"
        );
        assert!(p.trace.unclassified[0].text.contains("USDC::transfer"));
    }

    #[test]
    fn precompile_frames_are_classified_by_address_not_by_label() {
        // Whether cast prints `PRECOMPILES::ecrecover(...)` or the bare address is
        // a renderer detail; 0x01..0x09 is chain fact.
        let line = "  [500] 0x0000000000000000000000000000000000000001::verify(0x)";
        let p = parse(line, None).unwrap();
        let f = p.trace.frame(p.trace.root.unwrap()).unwrap();
        assert!(f.is_precompile());
    }

    #[test]
    fn every_line_lands_in_exactly_one_bucket() {
        let p = parse(USDC, None).unwrap();
        let c = p.trace.conservation;
        assert!(c.balances());
        assert_eq!(
            c.total,
            USDC.lines().count(),
            "no line is neither counted nor reported"
        );
        assert_eq!(
            c.frames + c.emissions + c.results + c.trailers + c.blanks + c.unclassified,
            c.total
        );
    }

    #[test]
    fn deep_nesting_survives() {
        let mut s = String::from("Traces:\n");
        s.push_str("  [9] 0x00000000000000000000000000000000000000aa::f()\n");
        for d in 1..3000 {
            let prefix = format!("{}  ├─ ", "│   ".repeat(d));
            s.push_str(&format!("{prefix}[{}] 0x{:0>40x}::f()\n", d, d % 255));
        }
        let p = parse(&s, None).unwrap();
        assert_eq!(p.trace.root_walk().len(), 3000);
        assert_eq!(p.trace.unclassified.len(), 0);
    }

    #[test]
    fn garbage_input_is_unclassified_rather_than_empty_and_clean() {
        let p = parse("i am not a trace at all\nsecond junk line\n", None).unwrap();
        assert!(p.trace.is_empty());
        assert_eq!(p.trace.conservation.unclassified, 2);
        assert_eq!(frames(&p.trace).len(), 0);
    }

    #[test]
    fn empty_input_produces_an_empty_trace_not_a_failure() {
        let p = parse("", None).unwrap();
        assert!(p.trace.root.is_none());
        assert_eq!(p.trace.conservation.total, 0);
    }

    #[test]
    fn trailing_scale_suffix_never_leaks_into_amounts() {
        assert_eq!(strip_scale("316820726 [3.168e8]"), "316820726");
        assert_eq!(strip_scale("0xdeadbeef"), "0xdeadbeef");
        assert_eq!(
            parse_amount("18901975697117306000000000 [1.89e25]")
                .unwrap()
                .to_decimal_string(),
            "18901975697117306000000000"
        );
    }

    #[test]
    fn argument_splitting_respects_nesting() {
        assert_eq!(
            split_args("0x0b08, [0x01, 0x02], 5"),
            vec!["0x0b08", "[0x01, 0x02]", "5"]
        );
    }

    #[test]
    fn an_error_is_returned_only_for_input_that_is_not_text_at_all() {
        // Parsing is total: it reports what it could not read instead of failing,
        // so a partial trace still reaches the analyst.
        assert!(parse("<<<>>>", None).is_ok());
    }

    #[test]
    fn unknown_result_tags_are_not_treated_as_success() {
        const U: &str = "Traces:\n  [9] 0x00000000000000000000000000000000000000aa::f()\n    └─ ← [UndefinedOpcode]\n";
        let p = parse(U, None).unwrap();
        let f = p.trace.frame(p.trace.root.unwrap()).unwrap();
        assert!(
            matches!(f.status, FrameStatus::Failed { .. }),
            "{:?}",
            f.status
        );
        assert!(
            f.status.reverted(),
            "an unknown terminal is a failure signal, never a silent ok"
        );
    }

    #[test]
    fn scale_hints_are_stripped_without_eating_array_arguments() {
        assert_eq!(strip_scale("150000000000 [1.5e11]"), "150000000000");
        assert_eq!(strip_scale("0x1234"), "0x1234");
        // An array argument also ends in `]`, and stripping it would delete the
        // value entirely rather than format it.
        assert_eq!(strip_scale("[0x01, 0x02]"), "[0x01, 0x02]");
        assert_eq!(strip_scale("0x[deadbeef]"), "0x[deadbeef]");
    }

    #[test]
    fn named_unnamed_and_param_indexed_keys_all_strip_the_same_way() {
        // The same event renders three different ways depending on whether cast
        // resolved an ABI, so the parser must not care.
        assert_eq!(strip_key("from: 0xaaaa"), "0xaaaa");
        assert_eq!(strip_key("param0: 0xaaaa"), "0xaaaa");
        assert_eq!(strip_key(": 0xaaaa"), "0xaaaa");
        assert_eq!(
            strip_key("amount: 100 [1e2]"),
            "amount: 100 [1e2]".trim_start_matches("amount: ").trim()
        );
        // A value containing a colon is not a key/value pair.
        assert_eq!(strip_key("1:2"), "1:2");
        assert_eq!(strip_key("0xdead"), "0xdead");
    }
}
