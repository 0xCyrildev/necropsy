//! Rendering. The report *is* the product: every other module exists so that a
//! human can trust the numbers on this page.
//!
//! Three rules, each the consequence of something easy to get wrong:
//!
//!   * **The tree and the logs are never merged.** They share no positional truth
//!     (see `collect`'s module docs), so they print as two tables with the gap
//!     visible rather than as one table with the gap hidden.
//!   * **Every count sits next to the count it excludes.** "No transfers" printed
//!     above a receipt of forty undecodable logs is worse than no answer, because
//!     it looks like one.
//!   * **Absence is labelled.** An unknown value, an `Unknown` frame status and a
//!     zero render differently, because they mean different things.

use crate::collect::Collection;
use crate::collect::decimals::{self, Decimals};
use crate::collect::txdata::{TxMeta, TxStatus};
use crate::diff::{ChangeKind, Comparison, Signature};
use crate::ledger::Ledger;
use crate::model::{
    AssetId, Frame, FrameStatus, Net, Provenance, TokenEvent, Topic32, Trace, TxHash,
    UnclassifiedLine, format_units,
};
use serde::Serialize;

/// Tree lines printed before the report says "and more".
pub const DEFAULT_TREE_LIMIT: usize = 200;

/// Diff rows printed before the tail is collapsed. The JSON report always carries
/// every row, so a cap here never costs anyone information they can ask for.
pub const DEFAULT_DIFF_LIMIT: usize = 50;

/// Receivers listed per asset before the tail is collapsed.
const RECEIVER_LIMIT: usize = 15;

/// True when something the pipeline was handed could not be accounted for.
///
/// Deliberately narrower than "notes is non-empty": a note like *this endpoint
/// has no `debug_` namespace, so `cast` rendered the tree instead* records a
/// change of mechanism, not lost input, and a tool that cries degraded on every
/// note trains the analyst to ignore the word. Nor is `attempted_only` —
/// analyzing a reverted transaction is a finding, not a broken run.
pub fn degraded(c: &Collection, l: &Ledger) -> bool {
    !c.trace.conservation.balances()
        || c.unclassified() > 0
        || c.unaccounted_logs() > 0
        || c.tx.is_none()
        || !l.overflow.is_empty()
}

/// The machine-readable report. A versioned document, not a dump of internal
/// types, so a consumer can depend on the shape.
#[derive(Debug, Serialize)]
pub struct Report<'a> {
    pub tool: &'a str,
    pub version: &'a str,
    pub degraded: bool,
    /// The hash that was asked for. Always present, because it is the argument,
    /// even when the endpoint said nothing about it.
    pub hash: String,
    /// `None` when the endpoint returned no transaction: origin, callee and block
    /// are then unknown, and any conclusion resting on them is unsupportable.
    pub tx: Option<&'a TxMeta>,
    pub provenance: &'a Provenance,
    pub accounting: Accounting,
    pub trace: &'a Trace,
    pub events: &'a [TokenEvent],
    pub ledger: &'a Ledger,
    /// Per-asset decimal counts, present only when tokens were asked. A consumer that
    /// scales amounts needs this alongside the base-unit rows; an empty map would not
    /// distinguish "not asked" from "asked and refused".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decimals: Option<&'a Decimals>,
    /// Present only when a baseline transaction was supplied. Absent does not mean
    /// "identical to everything" — it means nothing was compared.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff: Option<&'a Comparison>,
    pub notes: &'a [String],
}

#[derive(Debug, Serialize)]
pub struct Accounting {
    pub frames_total: usize,
    pub frames_reachable: usize,
    pub frames_orphaned: usize,
    pub unclassified_lines: usize,
    pub lines_balance: bool,
    pub logs_total: usize,
    pub logs_unaccounted: usize,
    pub events_fungible: usize,
    pub ledger_rows: usize,
    pub ledger_attempted_only: bool,
}

impl<'a> Report<'a> {
    pub fn build(c: &'a Collection, l: &'a Ledger, hash: TxHash) -> Report<'a> {
        Report {
            tool: "necropsy",
            version: env!("CARGO_PKG_VERSION"),
            degraded: degraded(c, l),
            hash: hash.to_hex(),
            tx: c.tx.as_ref(),
            provenance: &c.trace.provenance,
            accounting: Accounting {
                frames_total: c.trace.len(),
                frames_reachable: c.trace.reachable(),
                frames_orphaned: c.trace.orphans.len(),
                unclassified_lines: c.unclassified(),
                lines_balance: c.trace.conservation.balances(),
                logs_total: c.logs.len(),
                logs_unaccounted: c.unaccounted_logs(),
                events_fungible: c.events.iter().filter(|e| e.is_fungible_move()).count(),
                ledger_rows: l.total_asset_rows(),
                ledger_attempted_only: l.attempted_only,
            },
            trace: &c.trace,
            events: &c.events,
            ledger: l,
            decimals: None,
            diff: None,
            notes: &c.notes,
        }
    }

    /// Attach the fetched decimal counts. `None` when nothing was asked.
    pub fn with_decimals(mut self, d: Option<&'a Decimals>) -> Self {
        self.decimals = d;
        self
    }

    /// Attach the baseline comparison. Separate from `build` so the ordinary single
    /// transaction path never has to carry an empty diff through the renderer.
    pub fn with_diff(mut self, cmp: Option<&'a Comparison>) -> Self {
        self.diff = cmp;
        self
    }

    pub fn to_json(&self) -> crate::error::Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }
}

/// Render the text report. `tree_limit` of `0` prints every frame.
pub fn text(c: &Collection, l: &Ledger, hash: TxHash, tree_limit: usize) -> String {
    // An empty `Decimals` knows nothing, which renders what the report rendered before
    // metadata was ever asked for: base units, and a line saying why.
    text_with(c, l, hash, tree_limit, None, &Decimals::default(), false)
}

/// As [`text`], with a baseline comparison, per-asset decimal counts, and the optional
/// flat narrative reading of the tree.
pub fn text_with(
    c: &Collection,
    l: &Ledger,
    hash: TxHash,
    tree_limit: usize,
    comparison: Option<&Comparison>,
    decimals: &Decimals,
    narrative: bool,
) -> String {
    let mut out = String::new();
    header(c, hash, &mut out);
    accounting(c, &mut out);
    if l.attempted_only {
        out.push_str(
            "\n  *** THE TRANSACTION REVERTED. Every amount below is an ATTEMPT,\n  \
             *** not a movement that committed on chain.\n",
        );
    }
    ledger(l, decimals, &mut out);
    tree(&c.trace, tree_limit, &mut out);
    if narrative {
        narrative_section(&c.trace, tree_limit, &mut out);
    }
    events(c, &mut out);
    if let Some(cmp) = comparison {
        diff_section(cmp, &mut out);
    }
    caveats(c, l, &mut out);
    out
}

fn header(c: &Collection, hash: TxHash, out: &mut String) {
    let provenance = c.provenance();
    out.push_str(&format!(
        "necropsy {} — via {provenance}\n",
        env!("CARGO_PKG_VERSION")
    ));
    match &c.tx {
        Some(m) => {
            field(out, "tx", &format!("{}{}", m.hash.to_hex(), cast_suffix(c)));
            field(out, "from", &m.from.to_checksum());
            field(
                out,
                "to",
                &m.to
                    .map(|a| a.to_checksum())
                    .unwrap_or_else(|| "contract creation (no callee)".into()),
            );
            field(
                out,
                "chain / block",
                &format!(
                    "{} / {}",
                    m.chain_id
                        .map(|c| c.to_string())
                        .unwrap_or_else(|| "unknown".into()),
                    m.block_number
                        .map(|b| b.to_string())
                        .unwrap_or_else(|| "unknown".into()),
                ),
            );
            field(
                out,
                "status",
                match m.status {
                    Some(TxStatus::Success) => "SUCCESS",
                    Some(TxStatus::Reverted) => "REVERTED",
                    None => "unknown — no receipt from this endpoint",
                },
            );
            field(out, "value", &format!("{} wei", m.value));
            field(
                out,
                "gas used",
                &m.gas_used
                    .map(|g| g.to_string())
                    .unwrap_or_else(|| "unknown".into()),
            );
            if let Some(sel) = m.selector {
                field(out, "selector", &sel.to_hex());
            }
        }
        // The header is where an analyst decides whether to trust what follows, so
        // an absent transaction is stated as explicitly as a present one.
        None => {
            field(
                out,
                "tx",
                &format!(
                    "{} — {}",
                    hash.to_hex(),
                    if c.offline() {
                        "no transaction metadata came with this file"
                    } else {
                        "no transaction returned by this endpoint"
                    }
                ),
            );
            out.push_str("  from / to / block: unknown, so nothing downstream can be attributed to an origin\n");
        }
    }
}

fn cast_suffix(c: &Collection) -> String {
    c.trace
        .provenance
        .cast_version
        .as_ref()
        .map(|v| format!("  (cast: {v})"))
        .unwrap_or_default()
}

fn field(out: &mut String, key: &str, value: &str) {
    out.push_str(&format!("  {key:<13} {value}\n"));
}

fn accounting(c: &Collection, out: &mut String) {
    let t = &c.trace;
    let cv = t.conservation;
    out.push_str("\nAccounting\n");
    out.push_str(&format!(
        "  frames      {} total | {} reachable from root | {} orphan(s)\n",
        t.len(),
        t.reachable(),
        t.orphans.len()
    ));
    out.push_str(&format!(
        "  line split  total {} = frames {} + emissions {} + results {} + trailers {} + blanks {} + unclassified {}\n",
        cv.total, cv.frames, cv.emissions, cv.results, cv.trailers, cv.blanks, cv.unclassified
    ));
    out.push_str(&format!(
        "  balances    {}\n",
        if cv.balances() {
            "yes — every input line lands in exactly one bucket"
        } else {
            "NO — the counts above do not add up; treat this report as suspect"
        }
    ));
    // For a captured trace there is no receipt to have contained zero logs. Printing the
    // count would turn an absent artifact into a measurement — the one move this report is
    // built to prevent.
    let coverage = if c.offline() {
        "  coverage    logs none supplied (no receipt came with this file) | fungible events 0\n"
            .to_string()
    } else {
        format!(
            "  coverage    logs {} ({} unaccounted) | fungible events {}\n",
            c.logs.len(),
            c.unaccounted_logs(),
            c.events.iter().filter(|e| e.is_fungible_move()).count(),
        )
    };
    out.push_str(&coverage);
    if let Some(u) = t.unclassified.first() {
        out.push_str(&format!(
            "  first unclassified input: {}\n",
            describe_unclassified(u)
        ));
    }
}

fn describe_unclassified(u: &UnclassifiedLine) -> String {
    let preview: String = u.text.chars().take(72).collect();
    format!("line {} {preview:?} — {}", u.line, u.why)
}

fn ledger(l: &Ledger, d: &Decimals, out: &mut String) {
    out.push_str("\nValue ledger — largest net receiver first, per asset\n");
    if l.is_empty() {
        out.push_str("  (no rows: nothing netted in any asset)\n");
    }
    for asset in l.assets() {
        out.push_str(&format!("  {}\n", asset_line(asset, d)));
        let receivers = l.receivers(asset);
        if receivers.is_empty() {
            out.push_str(
                "    (no net receiver — every address in this asset netted zero or below)\n",
            );
            continue;
        }
        // The base amount is the number that is exact and comparable; the scaled one is
        // appended rather than substituted, so a reader can always get back to the
        // integer the chain actually moved.
        let digits = digits_for(asset, d);
        for (addr, net) in receivers.iter().take(RECEIVER_LIMIT) {
            let (inflow, outflow) = l.in_out(asset, *addr);
            let scaled = match (digits, *net) {
                (Some(dp), Net::Positive(a)) => format_units(&a.to_decimal_string(), dp),
                (Some(dp), Net::Negative(a)) => {
                    format_units(&a.to_decimal_string(), dp).map(|s| format!("-{s}"))
                }
                (Some(_), Net::Zero) => Some("0".to_string()),
                _ => None,
            };
            out.push_str(&format!(
                "    {:>14}{}  {}   ({} in / {} out)\n",
                format_net(*net),
                scaled.map(|s| format!("  = {s}")).unwrap_or_default(),
                addr.to_checksum(),
                inflow,
                outflow
            ));
        }
        if receivers.len() > RECEIVER_LIMIT {
            out.push_str(&format!(
                "    … {} more receiver(s)\n",
                receivers.len() - RECEIVER_LIMIT
            ));
        }
    }
    out.push_str(&format!("  coverage: {}\n", l.coverage_sentence()));
    scaling_note(l, d, out);
}

/// The decimal count the renderer can actually use.
///
/// A token is free to answer `decimals()` with something `format_units` cannot build an
/// exponent for. That is still a fetched fact and still printed on the asset line — it
/// simply does not produce a scaled number, and the footer says so rather than staying
/// quiet.
fn digits_for(asset: AssetId, d: &Decimals) -> Option<u8> {
    let dp = d.scaled(asset)?;
    format_units("1", dp).map(|_| dp)
}

/// What the amounts on this page are denominated in, and what was asked to know that.
///
/// Two different silences must not look the same: a node that refused, and an operator
/// who asked for base units.
fn scaling_note(l: &Ledger, d: &Decimals, out: &mut String) {
    let assets = l.assets();
    let scaled = assets
        .iter()
        .filter(|a| digits_for(**a, d).is_some())
        .count();
    if scaled > 0 {
        out.push_str(
            "  base units first; \"= n\" is the same amount scaled by that token's own decimals()\n  counts read from the chain at this transaction's block; native ETH is 18 by protocol\n",
        );
    }
    let unanswered = assets.iter().filter(|a| d.scaled(**a).is_none()).count();
    let unusable = assets
        .iter()
        .filter(|a| d.scaled(**a).is_some() && digits_for(**a, d).is_none())
        .count();
    if unanswered > 0 {
        out.push_str(&format!(
            "  {unanswered} asset(s) are base units only — no decimal count was obtained\n"
        ));
        for reason in d.reasons() {
            out.push_str(&format!("    ! {reason}\n"));
        }
    }
    if unusable > 0 {
        out.push_str(&format!(
            "  {unusable} asset(s) answered a decimal count too large to scale; base units shown\n"
        ));
    }
}

/// The asset heading, which now carries the token's own answer. `by protocol` is spelled
/// out for ETH because every other number on this line was obtained from a node.
fn asset_line(asset: AssetId, d: &Decimals) -> String {
    match asset {
        AssetId::Native => format!(
            "native ETH ({} decimals, by protocol)",
            decimals::NATIVE_DECIMALS
        ),
        AssetId::Erc20(a) => match d.scaled(asset) {
            Some(dp) => format!("{} (ERC-20, {dp} decimals)", a.to_checksum()),
            None => format!("{} (ERC-20, decimals unknown)", a.to_checksum()),
        },
    }
}

fn format_net(net: Net) -> String {
    match net {
        Net::Zero => "0".to_string(),
        Net::Positive(a) => format!("+{a}"),
        Net::Negative(a) => format!("-{a}"),
    }
}

fn tree(t: &Trace, limit: usize, out: &mut String) {
    let walk = t.root_walk();
    let shown = if limit == 0 {
        walk.len()
    } else {
        walk.len().min(limit)
    };
    let hint = if limit == 0 {
        ""
    } else {
        ", --tree 0 prints all"
    };
    out.push_str(&format!(
        "\nCall tree — execution order ({shown} of {} frame(s){hint})\n",
        walk.len()
    ));
    if t.is_empty() {
        out.push_str("  (no frames)\n");
    }
    for id in walk.iter().take(shown) {
        if let Some(f) = t.frame(*id) {
            out.push_str(&tree_line(f));
            out.push('\n');
        }
    }
    if shown < walk.len() {
        out.push_str(&format!(
            "  … {} more frame(s) not shown\n",
            walk.len() - shown
        ));
    }
    if !t.orphans.is_empty() {
        out.push_str(&format!(
            "\nOrphaned frames ({}) — the collector could not place these under any parent\n",
            t.orphans.len()
        ));
        for id in &t.orphans {
            if let Some(f) = t.frame(*id) {
                out.push_str(&tree_line(f));
                out.push('\n');
            }
        }
    }
}

fn tree_line(f: &Frame) -> String {
    let indent = "  ".repeat(f.depth as usize + 1);
    let target = f.to.map(|a| a.short()).unwrap_or_else(|| "—".into());
    let mut s = format!(
        "{indent}#{} {} {}→{target}",
        f.id,
        f.kind.tag(),
        f.from.short()
    );
    if f.kind.inherits_context() {
        // A delegatecall runs against someone else's storage; without this the
        // tree reads as though `to` owned the balances it moved.
        s.push_str(&format!(" [ctx {}]", f.context.short()));
    }
    if let Some(label) = &f.label {
        s.push_str(&format!(" {label}"));
    }
    if let Some(sel) = f.selector {
        s.push_str(&format!(" {}", sel.to_hex()));
    }
    match f.value {
        Some(v) if !v.is_zero() => s.push_str(&format!(" value {v}")),
        // A gap worth printing: this frame could have moved ETH and the collector
        // did not say. A staticcall omitting `value` is a protocol-level zero, not
        // a gap, so it stays silent.
        None if !f.kind.cannot_carry_value() => s.push_str(" value ?"),
        _ => {}
    }
    if let Some(g) = f.gas_used {
        s.push_str(&format!(" gas {g}"));
    }
    s.push_str(&status_suffix(f));
    s
}

fn status_suffix(f: &Frame) -> String {
    match &f.status {
        FrameStatus::Success => String::new(),
        FrameStatus::Reverted { reason } => format!("  x reverted{}", reason_suffix(reason)),
        FrameStatus::Failed { reason } => format!("  x failed{}", reason_suffix(reason)),
        FrameStatus::Unknown => "  ? status unknown".to_string(),
    }
}

fn reason_suffix(reason: &Option<String>) -> String {
    reason
        .as_ref()
        .map(|r| format!(": {r}"))
        .unwrap_or_default()
}

/// The same tree read as a flat sequence, for a reader who wants the story rather than
/// the structure.
///
/// There is no per-frame clock and this does not pretend otherwise: `callTracer` answers
/// with nesting and no timestamps, so the order below is *call order*. Receipt logs are a
/// second, genuinely separate sequence, so they are not interleaved here — the section
/// ends by pointing at them rather than silently borrowing their order.
fn narrative_section(t: &Trace, limit: usize, out: &mut String) {
    let walk = t.root_walk();
    let shown = if limit == 0 {
        walk.len()
    } else {
        walk.len().min(limit)
    };
    out.push_str(&format!(
        "\nExecution narrative — the same frames as a flat sequence, in call order ({shown} of {} frame(s))\n",
        walk.len()
    ));
    if walk.is_empty() {
        out.push_str("  (no reachable frames — nothing to narrate; see Call tree above)\n");
    }

    let mut ordinals: std::collections::BTreeMap<crate::model::FrameId, usize> =
        std::collections::BTreeMap::new();
    for (i, id) in walk.iter().enumerate() {
        ordinals.insert(*id, i + 1);
    }
    for (i, id) in walk.iter().enumerate().take(shown) {
        if let Some(f) = t.frame(*id) {
            out.push_str(&format!("  {}. {}\n", i + 1, narrative_line(f, &ordinals)));
        }
    }
    if shown < walk.len() {
        out.push_str(&format!(
            "  … {} more frame(s) not shown — the tree above and --json carry all {}\n",
            walk.len() - shown,
            walk.len()
        ));
    }
    if !t.orphans.is_empty() {
        out.push_str(&format!(
            "  {} orphaned frame(s) are absent from this sequence by construction; they are named under Call tree\n",
            t.orphans.len()
        ));
    }
    out.push_str(
        "  no per-frame clock exists: callTracer reports nesting, not time. This is call order.\n  Receipt logs are a separate sequence and are not interleaved here.\n",
    );
}

fn narrative_line(
    f: &Frame,
    ordinals: &std::collections::BTreeMap<crate::model::FrameId, usize>,
) -> String {
    let place = match f.parent {
        None => "root".to_string(),
        Some(p) => match ordinals.get(&p) {
            Some(n) => format!("inside {n}"),
            // A parent outside the walked set must not be drawn as a root.
            None => "inside an unnumbered frame".to_string(),
        },
    };
    let target = f.to.map(|a| a.short()).unwrap_or_else(|| "—".into());
    let mut s = format!("{place}: {}→{target} {}", f.from.short(), f.kind.tag());
    if f.kind.inherits_context() {
        s.push_str(&format!(" [storage {}]", f.context.short()));
    }
    if let Some(sel) = f.selector {
        s.push_str(&format!(" {}", sel.to_hex()));
    }
    match f.value {
        Some(v) if !v.is_zero() => s.push_str(&format!(" moves {v}")),
        // The tree's unknown-versus-protocol-zero rule, unchanged.
        None if !f.kind.cannot_carry_value() => s.push_str(" value ?"),
        _ => {}
    }
    s.push_str(&status_suffix(f));
    s
}

fn events(c: &Collection, out: &mut String) {
    out.push_str("\nReceipt logs — a separate table, deliberately not joined to the tree\n");
    if c.events.is_empty() {
        // A file input has no receipt to have produced zero logs. Saying "0 logs" would
        // turn an absent artifact into a measurement, which is the error this whole table
        // exists to avoid making.
        if c.offline() {
            out.push_str("  (no receipt was supplied with this trace — token movements are unknown, not zero)\n");
            return;
        }
        out.push_str(&format!(
            "  (no classifiable events; {} log(s) on the receipt)\n",
            c.logs.len()
        ));
        return;
    }
    for e in &c.events {
        out.push_str(&format!("  {}\n", event_line(e)));
    }
}

fn event_line(e: &TokenEvent) -> String {
    match e {
        TokenEvent::Erc20Transfer {
            token,
            from,
            to,
            amount,
            log_index,
        } => format!(
            "#{log_index} Transfer      {}   {} -> {}   {amount}",
            token.short(),
            from.short(),
            to.short()
        ),
        TokenEvent::Erc721Transfer {
            token,
            from,
            to,
            token_id,
            log_index,
        } => format!(
            "#{log_index} Transfer(721) {}   {} -> {}   id {token_id}",
            token.short(),
            from.short(),
            to.short()
        ),
        TokenEvent::Erc1155Single {
            token,
            from,
            to,
            id,
            value,
            log_index,
            ..
        } => format!(
            "#{log_index} TransferSingle {}   {} -> {}   id {id} value {value}",
            token.short(),
            from.short(),
            to.short()
        ),
        TokenEvent::Erc1155Batch {
            token,
            from,
            to,
            ids,
            values,
            log_index,
            ..
        } => format!(
            "#{log_index} TransferBatch {}   {} -> {}   {} id(s), {} value(s)",
            token.short(),
            from.short(),
            to.short(),
            ids.len(),
            values.len()
        ),
        TokenEvent::WethDeposit {
            weth,
            owner,
            amount,
            log_index,
        } => {
            format!(
                "#{log_index} WETH Deposit    {}   {owner}   +{amount} WETH",
                weth.short()
            )
        }
        TokenEvent::WethWithdrawal {
            weth,
            owner,
            amount,
            log_index,
        } => {
            format!(
                "#{log_index} WETH Withdrawal {}   {owner}   -{amount} WETH",
                weth.short()
            )
        }
        TokenEvent::NonValue {
            token,
            topic0,
            log_index,
        } => {
            format!(
                "#{log_index} non-value       {}   topic0 {}",
                token.short(),
                short_topic(*topic0)
            )
        }
        TokenEvent::Unclassified {
            address,
            topic0,
            n_topics,
            data_len,
            log_index,
            why,
        } => format!(
            "#{log_index} UNCLASSIFIED    {}   topics={n_topics} data={data_len} bytes{}   ({why})",
            address.short(),
            topic0
                .map(|t| format!(" topic0 {}", short_topic(t)))
                .unwrap_or_default()
        ),
    }
}

fn short_topic(t: Topic32) -> String {
    let f = t.first4();
    format!("0x{}…", hex::encode(f))
}

/// The baseline comparison, rendered only when one was asked for.
///
/// The counts come first and the rows after them, because the counts are the part a
/// reader can act on: most rows in a large diff are positions that shifted when a call
/// was inserted earlier, which `Diff::summary` says in as many words.
fn diff_section(cmp: &Comparison, out: &mut String) {
    out.push_str(&format!(
        "\nStructural diff against {} — shape only; a difference is a question, not a verdict\n",
        cmp.baseline
    ));
    out.push_str(&format!(
        "  read by: baseline {}, target {}\n",
        cmp.baseline_collector, cmp.target_collector
    ));
    for caveat in &cmp.caveats {
        out.push_str(&format!("  ! {caveat}\n"));
    }
    out.push_str(&format!("  {}\n", cmp.diff.summary()));
    if cmp.diff.changes.is_empty() {
        return;
    }
    for change in cmp.diff.changes.iter().take(DEFAULT_DIFF_LIMIT) {
        out.push_str(&format!(
            "  {}  {}\n",
            change.path,
            change_text(change.change)
        ));
        if let Some(s) = &change.baseline {
            out.push_str(&format!("      was  {}\n", signature_text(s)));
        }
        if let Some(s) = &change.target {
            out.push_str(&format!("      now  {}\n", signature_text(s)));
        }
    }
    let hidden = cmp.diff.changes.len().saturating_sub(DEFAULT_DIFF_LIMIT);
    if hidden > 0 {
        out.push_str(&format!(
            "  … {hidden} more difference(s) not shown; --json carries all {}\n",
            cmp.diff.changes.len()
        ));
    }
}

fn change_text(k: ChangeKind) -> &'static str {
    match k {
        ChangeKind::Added => "inserted in the target",
        ChangeKind::Removed => "absent from the target",
        ChangeKind::Changed => "different at this position",
    }
}

/// One side of a diff row. Deliberately narrower than a tree line: no value, no label,
/// no gas, because those are exactly the fields `Frame::diff_signature` excludes and
/// printing them here would invite a reader to compare them.
fn signature_text(s: &Signature) -> String {
    let to = s.to.map(|a| a.short()).unwrap_or_else(|| "—".into());
    let mut t = format!("{} {}→{to}", s.kind, s.from.short());
    if let Some(sel) = s.selector {
        t.push_str(&format!(" {}", sel.to_hex()));
    }
    t
}

fn caveats(c: &Collection, l: &Ledger, out: &mut String) {
    let mut items: Vec<String> = c.notes.clone();
    if l.unapplied_events > 0 {
        items.push(format!(
            "{} event(s) were not applied to the fungible ledger (non-fungible or unclassifiable)",
            l.unapplied_events
        ));
    }
    if c.unclassified() > 1 {
        items.push(format!(
            "{} further unclassified input line(s)",
            c.unclassified() - 1
        ));
    }
    for o in &l.overflow {
        items.push(format!("overflow: {o}"));
    }
    if items.is_empty() {
        return;
    }
    out.push_str("\nCaveats\n");
    for i in &items {
        out.push_str(&format!("  - {i}\n"));
    }
    if degraded(c, l) {
        out.push_str("\nDEGRADED: some input could not be accounted for. Exit status 4.\n");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::receiptlogs;
    use crate::model::{Address, Amount, CallKind, Collector, Disposition, TraceBuilder};
    use ruint::aliases::U256;

    fn addr(n: u8) -> Address {
        let mut b = [0u8; 20];
        b[19] = n;
        Address(b)
    }

    fn prov() -> Provenance {
        Provenance {
            collector: Collector::CallTracerJson,
            cast_version: None,
            chain_id: Some(1),
            block: Some(21_000_000),
        }
    }

    fn meta() -> TxMeta {
        TxMeta {
            hash: TxHash([7u8; 32]),
            from: addr(1),
            to: Some(addr(2)),
            block_number: Some(21_000_000),
            chain_id: Some(1),
            status: Some(TxStatus::Success),
            value: Amount::new(U256::from(5u64)),
            gas_used: Some(21_000),
            selector: None,
        }
    }

    fn frame(kind: CallKind, from: Address, to: Address, value: u64) -> Frame {
        Frame {
            id: 0,
            kind,
            from,
            to: Some(to),
            context: Address::ZERO,
            value: Some(Amount::new(U256::from(value))),
            gas_used: None,
            selector: None,
            label: None,
            status: FrameStatus::Success,
            return_bytes: None,
            parent: None,
            children: Vec::new(),
            depth: 0,
        }
    }

    fn collection(events: Vec<TokenEvent>, trace: Trace, tx: Option<TxMeta>) -> Collection {
        Collection {
            trace,
            logs: Vec::new(),
            events,
            tx,
            notes: Vec::new(),
        }
    }

    fn hash() -> TxHash {
        TxHash([7u8; 32])
    }

    /// A two-frame tree that delegates, moving 1000 of one token to address 9.
    fn drained() -> Collection {
        let mut tb = TraceBuilder::new(prov());
        let root = tb.push(None, frame(CallKind::Call, addr(1), addr(2), 0));
        tb.push(
            Some(root),
            frame(CallKind::DelegateCall, addr(2), addr(3), 0),
        );
        collection(
            vec![TokenEvent::Erc20Transfer {
                token: addr(0x20),
                from: addr(2),
                to: addr(9),
                amount: Amount::new(U256::from(1_000u64)),
                log_index: 0,
            }],
            tb.finish(),
            Some(meta()),
        )
    }

    fn ledger_of(c: &Collection) -> Ledger {
        crate::ledger::build(&c.events, &c.trace, c.tx.as_ref().and_then(|m| m.status))
    }

    #[test]
    fn report_names_the_asset_and_prints_the_receiver() {
        let c = drained();
        let l = ledger_of(&c);
        let s = text(&c, &l, hash(), 0);
        assert!(s.contains("ERC-20"), "{s}");
        assert!(s.contains("Value ledger"), "{s}");
        assert!(s.contains("+1000"), "the net inflow must be printed: {s}");
        assert!(
            s.contains("1000 in / 0 out"),
            "both sides must be shown: {s}"
        );
        assert!(!degraded(&c, &l), "a complete collection is not degraded");
    }

    #[test]
    fn a_missing_tx_is_stated_rather_than_left_blank() {
        let c = collection(vec![], TraceBuilder::new(prov()).finish(), None);
        let l = ledger_of(&c);
        let s = text(&c, &l, hash(), 0);
        assert!(s.contains("no transaction returned"), "{s}");
        assert!(
            s.contains(&hash().to_hex()[..10]),
            "the hash asked for is still named: {s}"
        );
        assert!(
            degraded(&c, &l),
            "without a tx, origin and callee are unknown"
        );
    }

    #[test]
    fn delegatecall_shows_the_storage_it_actually_touched() {
        let c = drained();
        let l = ledger_of(&c);
        let s = text(&c, &l, hash(), 0);
        assert!(
            s.contains("[ctx"),
            "a delegatecall line must show its context: {s}"
        );
    }

    #[test]
    fn an_absent_value_renders_as_unknown_only_where_value_is_possible() {
        let mut f = frame(CallKind::Call, addr(1), addr(2), 0);
        f.value = None;
        assert!(
            tree_line(&f).contains("value ?"),
            "an ordinary call with no reported value is a gap: {}",
            tree_line(&f)
        );
        f.value = Some(Amount::ZERO);
        assert!(
            !tree_line(&f).contains("value ?"),
            "a real zero is not an unknown"
        );

        // The protocol forbids value here, so the collector's silence is an answer.
        for kind in [
            CallKind::StaticCall,
            CallKind::DelegateCall,
            CallKind::CallCode,
        ] {
            let label = format!("{kind:?}");
            let mut g = frame(kind, addr(1), addr(2), 0);
            g.value = None;
            let line = tree_line(&g);
            assert!(
                !line.contains("value ?"),
                "{label} cannot carry value: {line}"
            );
        }
    }

    #[test]
    fn tree_is_capped_and_says_so() {
        let mut tb = TraceBuilder::new(prov());
        let root = tb.push(None, frame(CallKind::Call, addr(1), addr(2), 0));
        for i in 0..250u32 {
            let mut f = frame(CallKind::Call, addr(2), addr(3), 0);
            f.to = Some(addr(3 + i as u8 % 200));
            tb.push(Some(root), f);
        }
        let c = collection(vec![], tb.finish(), Some(meta()));
        let l = ledger_of(&c);
        let capped = text(&c, &l, hash(), DEFAULT_TREE_LIMIT);
        assert!(
            capped.contains("not shown"),
            "a truncated tree must be labelled: {capped}"
        );
        assert!(
            capped.contains("--tree 0"),
            "and say how to see the rest: {capped}"
        );
        let all = text(&c, &l, hash(), 0);
        assert!(!all.contains("not shown"), "{all}");
    }

    #[test]
    fn json_is_a_versioned_document_with_string_amounts() {
        let c = drained();
        let l = ledger_of(&c);
        let r = Report::build(&c, &l, hash());
        assert_eq!(r.tool, "necropsy");
        assert_eq!(r.version, env!("CARGO_PKG_VERSION"));
        let json = r.to_json().unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["degraded"], serde_json::Value::Bool(false));
        assert_eq!(v["accounting"]["frames_total"], 2);
        assert_eq!(v["accounting"]["events_fungible"], 1);
        assert!(
            json.contains("\"1000\""),
            "uint256 cannot be a JSON number: {json}"
        );
    }

    #[test]
    fn unclassifiable_logs_are_counted_and_mark_the_run_degraded() {
        let log = crate::model::RawLog {
            address: addr(3),
            topics: vec![],
            data: vec![],
            log_index: 0,
        };
        let (events, _u) = receiptlogs::classify(std::slice::from_ref(&log));
        let mut c = collection(events, TraceBuilder::new(prov()).finish(), Some(meta()));
        c.logs = vec![log];
        let l = ledger_of(&c);
        assert!(degraded(&c, &l), "an unaccounted log is degraded input");
        let s = text(&c, &l, hash(), 0);
        assert!(s.contains("UNCLASSIFIED"), "{s}");
        assert!(s.contains("DEGRADED"), "{s}");
        assert!(s.contains("Exit status 4"), "{s}");
    }

    #[test]
    fn a_reverted_transaction_is_reported_as_an_attempt_not_an_error() {
        let mut tb = TraceBuilder::new(prov());
        let mut root = frame(CallKind::Call, addr(1), addr(2), 10);
        root.status = FrameStatus::Reverted {
            reason: Some("slippage".into()),
        };
        tb.push(None, root);
        let mut m = meta();
        m.status = Some(TxStatus::Reverted);
        let c = collection(vec![], tb.finish(), Some(m));
        let l = crate::ledger::build(&c.events, &c.trace, Some(TxStatus::Reverted));
        let s = text(&c, &l, hash(), 0);
        assert!(s.contains("ATTEMPT"), "{s}");
        assert!(s.contains("REVERTED"), "{s}");
        assert!(
            s.contains("slippage"),
            "the revert reason is the finding: {s}"
        );
        assert!(s.contains("x reverted"), "the frame itself is marked: {s}");
        assert!(
            !degraded(&c, &l),
            "a reverted tx is a complete answer, not a missing input"
        );
    }

    #[test]
    fn an_unbalanced_line_split_is_called_suspect() {
        // Conservation is the pipeline's own proof that it saw every line. If it
        // does not balance, no number in the report can be trusted, so the report
        // has to say so rather than quietly printing the totals.
        let mut tb = TraceBuilder::new(prov());
        tb.line(Disposition::Frame);
        let mut t = tb.finish();
        t.conservation.total = 99;
        let c = collection(vec![], t, Some(meta()));
        let l = ledger_of(&c);
        let s = text(&c, &l, hash(), 0);
        assert!(s.contains("NO — the counts above do not add up"), "{s}");
        assert!(degraded(&c, &l));
    }

    #[test]
    fn orphans_get_their_own_heading_instead_of_vanishing() {
        let mut tb = TraceBuilder::new(prov());
        tb.push(None, frame(CallKind::Call, addr(1), addr(2), 0));
        tb.push(None, frame(CallKind::Call, addr(1), addr(3), 0));
        let c = collection(vec![], tb.finish(), Some(meta()));
        assert_eq!(c.trace.orphans.len(), 1);
        let l = ledger_of(&c);
        let s = text(&c, &l, hash(), 0);
        assert!(s.contains("Orphaned frames (1)"), "{s}");
    }

    /// A child that became a value-bearing call to a different address at the same
    /// position — the shape a real deviation takes.
    fn pair() -> (Collection, Collection) {
        let mut tb = TraceBuilder::new(prov());
        let root = tb.push(None, frame(CallKind::Call, addr(1), addr(2), 0));
        tb.push(Some(root), frame(CallKind::StaticCall, addr(2), addr(4), 0));
        let base = collection(vec![], tb.finish(), Some(meta()));

        let mut tb = TraceBuilder::new(prov());
        let root = tb.push(None, frame(CallKind::Call, addr(1), addr(2), 0));
        tb.push(Some(root), frame(CallKind::Call, addr(2), addr(9), 1000));
        (base, collection(vec![], tb.finish(), Some(meta())))
    }

    #[test]
    fn a_requested_baseline_renders_both_sides_of_every_row() {
        let (base, targ) = pair();
        let cmp = crate::diff::compare(TxHash([9u8; 32]), hash(), &base, &targ);
        let l = ledger_of(&targ);
        let s = text_with(
            &targ,
            &l,
            hash(),
            0,
            Some(&cmp),
            &Decimals::default(),
            false,
        );
        assert!(s.contains("Structural diff against"), "{s}");
        assert!(
            s.contains(&TxHash([9u8; 32]).to_hex()),
            "the baseline must be named by the hash that was asked for: {s}"
        );
        // Slice to the section itself: the ledger above legitimately prints amounts,
        // so checking the whole report would prove nothing about the diff rows.
        let section = &s[s.find("Structural diff against").unwrap()..];
        assert!(
            section.contains("root/0"),
            "the position is printed: {section}"
        );
        assert!(section.contains("was"), "{section}");
        assert!(section.contains("now"), "{section}");
        // The value the signature deliberately excluded must not sneak back in, or the
        // section invites a reader to compare amounts across the two sides.
        assert!(
            !section.contains("1000"),
            "no amounts in a diff row: {section}"
        );
    }

    #[test]
    fn an_unrequested_baseline_does_not_render_as_a_match() {
        // The lie this guards: an empty "identical" line where nothing was compared.
        let c = drained();
        let l = ledger_of(&c);
        let s = text(&c, &l, hash(), 0);
        assert!(
            !s.contains("Structural diff"),
            "no baseline asked means no comparison claimed: {s}"
        );
    }

    #[test]
    fn diff_rows_past_the_cap_are_counted_rather_than_lost() {
        let wide = |side: u8| {
            let mut tb = TraceBuilder::new(prov());
            let root = tb.push(None, frame(CallKind::Call, addr(1), addr(2), 0));
            for _ in 0..60u8 {
                tb.push(
                    Some(root),
                    frame(CallKind::StaticCall, addr(2), addr(side), 0),
                );
            }
            collection(vec![], tb.finish(), Some(meta()))
        };
        let (base, targ) = (wide(4), wide(5));
        let cmp = crate::diff::compare(TxHash([9u8; 32]), hash(), &base, &targ);
        assert_eq!(cmp.diff.changes.len(), 60);
        let l = ledger_of(&targ);
        let s = text_with(
            &targ,
            &l,
            hash(),
            0,
            Some(&cmp),
            &Decimals::default(),
            false,
        );
        assert!(
            s.contains(&format!(
                "{} more difference(s) not shown",
                60 - DEFAULT_DIFF_LIMIT
            )),
            "the suppression is announced: {s}"
        );
        assert!(s.contains("carries all 60"), "the total is printed: {s}");
    }

    #[test]
    fn json_carries_a_diff_only_when_one_was_computed() {
        let c = drained();
        let l = ledger_of(&c);
        let plain: serde_json::Value =
            serde_json::from_str(&Report::build(&c, &l, hash()).to_json().unwrap()).unwrap();
        assert!(
            plain.get("diff").is_none(),
            "an absent comparison must not serialize as an empty one: {plain}"
        );

        let cmp = crate::diff::compare(TxHash([9u8; 32]), hash(), &c, &c);
        let json = Report::build(&c, &l, hash())
            .with_diff(Some(&cmp))
            .to_json()
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["diff"]["baseline"], cmp.baseline);
        assert!(
            v["diff"]["changes"].is_array(),
            "the flattened Diff keeps its own keys: {v}"
        );
        assert!(v["diff"]["caveats"].is_array());
    }

    /// The Value ledger section alone. Assertions here cannot be made against the whole
    /// report: the accounting block prints `total 2 = frames 2 + …`, which contains the
    /// same characters a scaled amount is marked with.
    fn ledger_text(s: &str) -> &str {
        let start = s
            .find("Value ledger")
            .expect("the ledger is always printed");
        let end = s.find("Call tree").unwrap_or(s.len());
        &s[start..end]
    }

    /// A canned `eth_call` answer for every token in the ledger. `MemoryRpc` keys by
    /// method, so one answer stands in for all of them — enough to exercise the
    /// renderer, which is what these tests are about.
    fn decimals_answering(hex: &str) -> Decimals {
        let rpc = crate::collect::rpc::MemoryRpc::new([("eth_call", serde_json::json!(hex))]);
        decimals::fetch(&rpc, &[AssetId::token(addr(0x20))], Some("0x14bcb7f"))
    }

    #[test]
    fn a_fetched_decimal_count_scales_the_receiver_row_without_replacing_it() {
        let c = drained();
        let l = ledger_of(&c);
        let d = decimals_answering("0x06");
        let s = text_with(&c, &l, hash(), 0, None, &d, false);
        let rows = ledger_text(&s);
        assert!(rows.contains("(ERC-20, 6 decimals)"), "{rows}");
        // 1000 base units at 6 decimals.
        assert!(
            rows.contains("= 0.001"),
            "the scaled value is shown: {rows}"
        );
        assert!(
            rows.contains("+1000"),
            "and the exact base amount stays: {rows}"
        );
        assert!(s.contains("base units first"), "{s}");
    }

    #[test]
    fn an_unanswered_token_stays_base_units_and_says_which_one_and_why() {
        let c = drained();
        let l = ledger_of(&c);
        let d = decimals_answering("0x");
        let s = text_with(&c, &l, hash(), 0, None, &d, false);
        let rows = ledger_text(&s);
        assert!(rows.contains("(ERC-20, decimals unknown)"), "{rows}");
        assert!(!rows.contains("= "), "nothing was scaled: {rows}");
        assert!(s.contains("1 asset(s) are base units only"), "{s}");
        assert!(
            s.contains("reverts"),
            "the reason travels with the count: {s}"
        );
    }

    #[test]
    fn native_eth_is_scaled_by_a_protocol_fact_and_labelled_as_one() {
        let mut tb = TraceBuilder::new(prov());
        tb.push(None, frame(CallKind::Call, addr(1), addr(2), 5));
        let c = collection(vec![], tb.finish(), Some(meta()));
        let l = ledger_of(&c);
        // No token asked at all: the 18 comes from the EVM, not from a node.
        let s = text_with(&c, &l, hash(), 0, None, &Decimals::default(), false);
        let rows = ledger_text(&s);
        assert!(rows.contains("18 decimals, by protocol"), "{rows}");
        assert!(
            rows.contains("= 0.000000000000000005"),
            "5 wei is 5e-18 ETH, exactly: {rows}"
        );
    }

    #[test]
    fn a_count_too_large_to_scale_is_still_reported_as_the_answer_it_was() {
        let c = drained();
        let l = ledger_of(&c);
        let d = decimals_answering("0xc8");
        let s = text_with(&c, &l, hash(), 0, None, &d, false);
        let rows = ledger_text(&s);
        assert!(
            rows.contains("(ERC-20, 200 decimals)"),
            "the fetched fact is not discarded because it is inconvenient: {rows}"
        );
        assert!(s.contains("too large to scale"), "{s}");
        assert!(
            !rows.contains("= "),
            "but no scaled number is invented: {rows}"
        );
    }

    #[test]
    fn json_omits_decimals_when_no_token_was_asked() {
        let c = drained();
        let l = ledger_of(&c);
        let plain: serde_json::Value =
            serde_json::from_str(&Report::build(&c, &l, hash()).to_json().unwrap()).unwrap();
        assert!(plain.get("decimals").is_none(), "{plain}");

        let d = decimals_answering("0x12");
        let v: serde_json::Value = serde_json::from_str(
            &Report::build(&c, &l, hash())
                .with_decimals(Some(&d))
                .to_json()
                .unwrap(),
        )
        .unwrap();
        let obj = v["decimals"]
            .as_object()
            .expect("an object of token → count");
        assert_eq!(obj.len(), 1, "{v}");
        assert_eq!(
            obj.values().next().unwrap(),
            &serde_json::json!(18),
            "a fetched count travels with the rows it explains"
        );
    }

    /// The narrative section alone. The slice stops at the receipt *table* header (with
    /// its em dash) because the narrative's own disclaimer mentions receipt logs too.
    fn narrative_slice(s: &str) -> &str {
        let start = s
            .find("Execution narrative")
            .expect("--narrative was asked for");
        let end = s.find("Receipt logs —").unwrap_or(s.len());
        &s[start..end]
    }

    #[test]
    fn the_narrative_is_absent_unless_asked_and_flat_when_present() {
        let c = drained();
        let l = ledger_of(&c);
        let plain = text(&c, &l, hash(), 0);
        assert!(
            !plain.contains("Execution narrative"),
            "the default report must not change for anyone who did not ask: {plain}"
        );

        let s = text_with(&c, &l, hash(), 0, None, &Decimals::default(), true);
        let section = narrative_slice(&s);
        assert!(section.contains("1. root:"), "{section}");
        assert!(
            section.contains("2. inside 1:"),
            "the parent is named by the number the reader just saw: {section}"
        );
        assert!(section.contains("2 of 2 frame(s)"), "{section}");
    }

    #[test]
    fn the_narrative_keeps_the_trees_rule_about_an_unknown_value() {
        let mut tb = TraceBuilder::new(prov());
        let root = tb.push(None, frame(CallKind::Call, addr(1), addr(2), 0));
        tb.push(Some(root), frame(CallKind::StaticCall, addr(2), addr(3), 0));
        let mut t = tb.finish();
        // A Call whose value the collector never reported: a gap, and printed as one.
        t.frames[0].value = None;
        let c = collection(vec![], t, Some(meta()));
        let l = ledger_of(&c);
        let s = text_with(&c, &l, hash(), 0, None, &Decimals::default(), true);
        let section = narrative_slice(&s);
        assert!(section.contains("value ?"), "a gap is a gap: {section}");
        assert_eq!(
            section.matches("value ?").count(),
            1,
            "the staticcall's silence is a protocol answer, not a gap: {section}"
        );
    }

    #[test]
    fn orphaned_frames_are_announced_rather_than_quietly_absent() {
        let mut tb = TraceBuilder::new(prov());
        tb.push(None, frame(CallKind::Call, addr(1), addr(2), 0));
        tb.push(None, frame(CallKind::Call, addr(1), addr(3), 0));
        let c = collection(vec![], tb.finish(), Some(meta()));
        let l = ledger_of(&c);
        let s = text_with(&c, &l, hash(), 0, None, &Decimals::default(), true);
        assert!(
            s.contains("1 orphaned frame(s) are absent from this sequence"),
            "the sequence cannot place them, and says so: {s}"
        );
    }

    #[test]
    fn the_narrative_caps_on_the_same_limit_as_the_tree() {
        let mut tb = TraceBuilder::new(prov());
        let root = tb.push(None, frame(CallKind::Call, addr(1), addr(2), 0));
        for i in 0..30u8 {
            tb.push(
                Some(root),
                frame(CallKind::StaticCall, addr(2), addr(3 + i), 0),
            );
        }
        let c = collection(vec![], tb.finish(), Some(meta()));
        let l = ledger_of(&c);
        let s = text_with(&c, &l, hash(), 10, None, &Decimals::default(), true);
        let section = narrative_slice(&s);
        assert!(section.contains("10 of 31 frame(s)"), "{section}");
        assert!(section.contains("21 more frame(s) not shown"), "{section}");
    }
}
