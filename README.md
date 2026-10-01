# necropsy

Post-transaction forensics for EVM chains. Give it a transaction hash; it
reconstructs the call tree, classifies the receipt logs, and ranks where value
actually ended up.

It is a reader, not a scanner. It does not guess at vulnerabilities — it answers
"what did this transaction do, and who ended up with the money", which is the
question that is hard to answer from a block explorer and easy to answer badly
from a raw `debug_traceTransaction`.

## What it can do

- **Rebuild the call tree** from a node's `callTracer`, from `cast`'s rendered trace, or from a
  trace someone captured earlier (`--from-json`) — and name which of the three produced the
  answer.
- **Rank where value ended up**, per asset, from the receipt logs and the frame values. Amounts
  are 256-bit integers in base units; the same amount scaled by that token's own `decimals()`
  sits beside them, never in place of them.
- **Classify the logs it can and list the ones it cannot**, so the size of the blind spot is in
  the report rather than inferred by the reader.
- **Account for every input line** — frames, emission lines, results, trailers — and say so
  plainly when the split does not balance.
- **Compare two transactions structurally** (`--baseline-tx-hash`, optionally read from two
  different endpoints): which position holds which call, to whom, with which selector.
- **Produce identical bytes for the same transaction twice**, so two people triaging one
  incident can tell a real difference from a different tool version.
- **Refuse to overstate.** A reverted transaction is reported as attempts. An unknown value
  prints `value ?`. An absent artifact never becomes a zero. Exit 4 means a report was produced
  from inputs that could not all be accounted for.

## Status

Still under active development — 0.x, and the answer to "can I rely on this" is
**not yet**. Concretely:

- The `--json` document shape is versioned but **not frozen**; field names may change
  between 0.x releases. The text report's wording is not a stable interface at all.
- Every number it prints has a stated provenance (which collector, which block, what
  it could not account for), but the tool makes **no findings claims** — there is no
  severity, no price, and no ABI decoding, so it cannot tell you whether a transaction
  was an attack.
- The baseline comparison is **shape only**: positions, callees and selectors. It reads no
  amounts, no labels and no storage, so a row is a question for a reviewer and it never
  changes the exit status.

## Build

```sh
cargo build --release
./target/release/necropsy --rpc-url "$ETH_RPC_URL" 0x5b515946dc1177149f140777ac90879312b182117e3392e8e2703ed3cd697153
```

`ETH_RPC_URL` is read automatically if set. The release binary links nothing but
`libc` and `libgcc` (`ldd target/release/necropsy`); TLS is rustls, so there is no
OpenSSL to carry onto a target machine. `cast` from Foundry is needed only for
`--collector cast`.

## What it prints

```
necropsy 0.2.0 — via callTracer JSON over RPC
  tx            0x5b515946dc1177149f140777ac90879312b182117e3392e8e2703ed3cd697153
  from          0xFACf9Ec2D27045b31291e79f4Ac982cce66BF241
  to            0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48
  chain / block 1 / 18214590
  status        SUCCESS
  value         0 wei
  gas used      43725
  selector      0xa9059cbb

Accounting
  frames      2 total | 2 reachable from root | 0 orphan(s)
  line split  total 2 = frames 2 + emissions 0 + results 0 + trailers 0 + blanks 0 + unclassified 0
  balances    yes — every input line lands in exactly one bucket
  coverage    logs 1 (0 unaccounted) | fungible events 1

Value ledger — largest net receiver first, per asset
  0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 (ERC-20, 6 decimals)
        +316820726  = 316.820726  0xCFFAd3200574698b78f32232aa9D63eABD290703   (316820726 in / 0 out)
  coverage: 2 asset row(s)
  base units first; "= n" is the same amount scaled by that token's own decimals()
  counts read from the chain at this transaction's block; native ETH is 18 by protocol

Call tree — execution order (2 of 2 frame(s), --tree 0 prints all)
  #0 call 0xFACf…F241→0xA0b8…eB48 0xa9059cbb gas 43725
    #1 delegatecall 0xA0b8…eB48→0xa232…bDCF [ctx 0xA0b8…eB48] 0xa9059cbb gas 19628

Receipt logs — a separate table, deliberately not joined to the tree
  #293 Transfer      0xA0b8…eB48   0xFACf…F241 -> 0xCFFA…0703   316820726
```

That last line is the design in one number: the tree has two frames, and the
transfer it produced is receipt log **293**. A tool that attached logs to frames
by position would attribute them to the wrong call, so necropsy keeps the two
artifacts in separate tables and never joins them.

The same transaction read from a captured file, with no node behind it, keeps the
shape of the report and changes what it claims:

```
necropsy 0.2.0 — via offline JSON file (no node asked; no receipt, so no token movement is known)
  tx            0x5b515946dc1177149f140777ac90879312b182117e3392e8e2703ed3cd697153 — no transaction metadata came with this file
  from / to / block: unknown, so nothing downstream can be attributed to an origin
...
  coverage    logs none supplied (no receipt came with this file) | fungible events 0
...
Receipt logs — a separate table, deliberately not joined to the tree
  (no receipt was supplied with this trace — token movements are unknown, not zero)

Caveats
  - read from a local file, not a node: there is no receipt, so no token transfer is known. An empty ledger here does not mean nothing moved
  - the transaction hash is what the operator claimed. Nothing in a bare trace ties this file to that hash.

DEGRADED: some input could not be accounted for. Exit status 4.
```

The tree is real there; the money is unknown. An empty ledger and a `logs 0` would both be
measurements of something that was never supplied, which is the failure this tool exists to
avoid, so the absence is written as an absence and the exit status says the same thing to a
script.

## Why the numbers are shaped this way

- **Nothing is summed across assets.** A 6-decimal stablecoin and an 18-decimal
  token are different monies. Netting them into one column makes the ranking track
  decimal places, and lets a drain in one token cancel an unrelated inflow in
  another.
- **Amounts are 256-bit and netting is a comparison.** `in` and `out` accumulate in
  `U256` and the net is the difference of the two sides, so an inflow above
  `i128::MAX` cannot wrap negative and vanish from the answer.
- **Value that did not commit is not value.** A transaction that reverted produced
  *attempts*, and necropsy says so at the top of the report. Frames inside a
  reverted subtree are excluded from native-ETH flows (receipt logs already exclude
  reverted emissions, so only the trace side needs filtering).
- **Ordering is deterministic.** Rows tie-break on address bytes, so two runs of one
  transaction produce byte-identical output, including the JSON.
- **Unknown is never rendered as zero.** A frame whose value the collector did not
  report prints `value ?`. A frame that cannot carry value at all (staticcall,
  delegatecall, callcode) stays silent, because there the protocol already answered.
- **A credential cannot leak into the output.** RPC URLs are treated as secrets:
  `cast` receives the endpoint through its environment rather than argv, and error
  text is redacted from the URL's userinfo, path and query before printing.

## Options

```
necropsy [OPTIONS] <TX>

  --rpc-url <URL>      JSON-RPC endpoint [env: ETH_RPC_URL]
  --chain <ID>         refuse to analyze unless the endpoint agrees this is that chain
  --collector <KIND>   auto | rpc | cast          [default: auto]
  --cast-mode <MODE>   rendered | replay          [default: rendered]
  --baseline-tx-hash <HASH>  compare the call tree against a second transaction
  --baseline-rpc-url <URL>  endpoint for the baseline  [default: --rpc-url]
  --from-json <PATH>   read a captured callTracer response instead of dialling a node
  --json               machine-readable report
  --tree <N>           call-tree lines to print; 0 prints every frame  [default: 200]
  --narrative          also print a flat execution narrative  [text report only]
  --no-decimals        base units only; do not ask each token for its decimals()
  --max-response-mb <MB>     refuse an answer larger than this   [default: 32]
  --max-trace-depth <LEVELS> refuse a trace nesting deeper than this  [default: 2048]
  --timeout <SECONDS>  per-request timeout        [default: 60]
  --verbose            full provider error text (still redacted)
```

`--collector auto` uses `debug_traceTransaction` and falls back to `cast` only when
the node answers JSON-RPC `-32601` (no `debug_` namespace). `--collector rpc`
refuses to fall back rather than silently changing mechanism, because the two
collectors report different things. `replay` re-executes the block locally, so its
numbers are labelled as potentially divergent from chain.

`--baseline-tx-hash` reads a second transaction from the same endpoint and prints a
**structural** diff: which position holds which call, to whom, with which selector.
It compares no amounts, no labels and no storage, so a row is a question for a
reviewer rather than a verdict, and it never changes the exit status. The report says
out loud when the comparison is weak — the same hash on both sides, two different
collector mechanisms, or a chain id that only one side reported. Paths are child
indices, so one inserted call shifts every later position; text prints the first 50
rows and counts the rest, and `--json` carries all of them under a `diff` key that is
absent, not empty, when no baseline was asked for.

`--baseline-rpc-url` reads the baseline from a **different endpoint**: a second provider
for the same chain, or a deliberate cross-chain pair. `--chain` then guards *both* sides —
a run asked for chain 1 stops if the baseline node answers 8453, because comparing one
chain's tree against another's is exactly the mix-up the flag exists to prevent. Without
`--chain` the comparison still runs, and the report states that the two chains differ
rather than leaving that for the reader to notice.

`--from-json` analyses a `debug_traceTransaction` response someone already has — saved during an
incident, exported by an explorer, pasted in by a colleague. It takes the bare frame object or a
JSON-RPC envelope, and **refuses a captured error response** rather than parsing it into an empty
tree: a saved `-32603` is somebody's failed request, not evidence that a transaction did nothing.
A file cannot supply what a node supplies, so the report states what is missing instead of
printing zeros — no receipt, therefore no token movement is known and the ERC-20 side of the
ledger is empty by absence; no transaction metadata, therefore no origin, callee or block; and
nothing in the file ties it to the hash on the command line, which the notes say out loud. Such a
run exits **4 (degraded)**. `--chain` cannot be honoured against a file, because a trace records
no chain id, and the run stops rather than assuming. An `ETH_RPC_URL` left in the environment is
ignored by this path; `--rpc-url` typed beside `--from-json` is refused, because one run has one
source. The two size guards are not network-only: a file is read up to `--max-response-mb` and
refused past it, and its nesting is measured before it is parsed.

Token decimal counts come from one `eth_call` per distinct token, at the transaction's own
block tag — never `latest`, because metadata read from a later state describes a different
world, and never batched, because these endpoints refuse batches whose members each work
alone. A token that reverts the view call, answers something wider than one byte, or cannot
be reached stays in base units with the reason printed beside it. `0` is a real answer and
is scaled as one. Nothing is assumed to be 18 except native ETH, which the protocol defines
— and `--no-decimals` declines the calls, printing base units and saying that *you* asked
for that, not that a node refused.

`--narrative` adds a flat, numbered reading of the same frames — each line naming the call
it sits inside — for a reader who wants a story rather than an indent to trace. It is opt-in
because the tree is the default answer, and it conflicts with `--json`, which already carries
the tree as data. It is also explicit about what it does not have: `callTracer` reports
nesting, not time, so the sequence is *call order*, and the receipt logs stay a separate
sequence rather than being interleaved with it. Numbering follows the same `--tree` limit.

## Exit statuses

Scripts are the second audience, so the status distinguishes "nothing was found"
from "nothing was read".

| code | meaning |
|---|---|
| 0 | report produced |
| 2 | the command was wrong (bad flags, malformed hash, no endpoint configured) |
| 3 | nothing could be read (endpoint down, transaction absent, `cast` missing, chain mismatch, an answer too large or too deep to read) |
| 4 | **degraded** — a report was produced, but some input could not be accounted for |

`2` is reserved for something the operator can fix by editing the command line. An HTTP status is
not that: a gateway answering 404 for a healthy node, or 400 for a request it refused to forward,
says something about the path between, and a caller told "your flags are wrong" will go re-read the
manual instead of looking at the endpoint.

A closed pipe — `necropsy … | head -2` — exits 0. The analysis succeeded and its bytes went as far
as anyone wanted them; Rust ignores `SIGPIPE`, so this arrived as a write error, and reporting it
as a crash would have produced exit 101, a code outside the contract above.

A transaction that *reverted* exits 0. Analyzing a failed transaction is the point
of the tool; its revert status is a fact in the report, not an error from necropsy.

`4` is set when line conservation does not balance, when input lines or receipt logs
could not be classified, when the endpoint returned no transaction, or when a 256-bit
addition overflowed. It is deliberately not set for a note like "this endpoint has no
`debug_` namespace, so `cast` rendered the tree" — that records a change of mechanism,
not lost evidence, and a tool that cries degraded on every note trains the analyst to
ignore the word.

## Production posture

What is guaranteed, and what is not. Both halves matter: a tool used during an incident is
trustworthy when its reader knows where the guarantee stops.

- **Bounded input, everywhere it arrives.** A response body, a captured file and `cast`'s stdout
  are each read up to a ceiling (`--max-response-mb`, 32 MiB by default — about 500x the largest
  mainnet `callTracer` answer measured here, 62 KB), and refused *rather than truncated*. Nesting
  is measured by a linear scan before anything parses, so `--max-trace-depth` (2,048) is a
  decision the tool states instead of a limit a parser hits on its way to a segfault. Collection
  runs on a 256 MiB stack, including the file path.
- **No `unsafe` in shipped code.** `#![forbid(unsafe_code)]` on both crates, scoped by `cfg` so
  the one test that clears `PATH` can still run.
- **A panic on untrusted bytes is a bug.** `tests/hostile_input.rs` runs a deterministic corpus of
  degenerate documents through truncation, single-byte flips and inserted control characters,
  across the scanner, the parser, the trace builder and the log classifier. No RNG, so a failure
  reproduces with the same line number.
- **The transport is tested, not assumed.** `tests/http_boundary.rs` drives the real client against
  a loopback server: which statuses retry (429/502 do, 400/404 do not), that a `Retry-After` is
  waited out, that an oversized answer is refused after one request, and that a `-32601` still
  arrives as an answer the collector switch can act on. None of it reaches the internet.
- **Reproducible build.** `Cargo.lock` is committed, CI builds `--locked`, CI actions are pinned by
  commit rather than by a moving tag, the runner image *and* the toolchain are pinned (a newer
  clippy turns `-D warnings` red on a commit that changed nothing), and the declared MSRV is
  compiled against in CI instead of asserted in a file. The floor is 1.90 and it is not ours:
  `ruint` — the `U256` every amount in the ledger is stored in — declares `rust-version =
  "1.90"`, and a dependency's floor is the build's floor.
- **A credential cannot leave the process.** See above — error text, `--help`, `cast`'s argv and the
  notes all redact, and a remote plain-HTTP endpoint says so in the report.
- **205 offline tests**, `cargo clippy --all-targets -- -D warnings` and `cargo fmt --check` clean,
  and `cargo publish --dry-run` verified to ship no file outside `src/`, `tests/`, `examples/`,
  the workflows and the docs (this repository's project memory is gitignored and stays local),
  plus the opt-in live tier and its scheduled run.

What is **not** guaranteed: no release exists (no tag, no artifact — see `CHANGELOG.md`); the
`--json` shape is versioned by `schema_version` but still 0.x, so a minor bump may rename a field;
there is no ABI decoding, no severity model and no price; `--from-json` cannot know the chain, the
receipt or the hash of the file it reads; and a public endpoint can rate-limit, shed or drop a
namespace between two runs, which is why the live tier distinguishes a skip from a failure.

Report a security problem through **SECURITY.md**, which also says what this tool's threat model
does and does not cover.

## Library

`necropsy` is also a library, because a binary that cannot be tested without
spawning a process is a binary whose correctness claims are unfalsifiable.

```rust
use necropsy::collect::{self, CollectorChoice, rpc::HttpRpc};
use necropsy::{ledger, report};

let rpc = std::sync::Arc::new(HttpRpc::new(url, timeout, 2));
let c = collect::collect(rpc, hash, CollectorChoice::Auto, None)?;
let l = ledger::build(&c.events, &c.trace, c.tx.as_ref().and_then(|m| m.status));
print!("{}", report::text(&c, &l, hash, 200));
```

Collection runs on a thread with a 256 MiB stack. That is not defensive padding:
`serde_json` drops nested values recursively, and a `callTracer` response for a
reentrancy exploit nests thousands of frames deep — measured directly, a
6,000-frame tree overflows the default 2 MiB main-thread stack and aborts the
process, *after* parsing, mid-report.

## What it does not do

Each line says whether the absence is a decision or unfinished work. The difference matters to
a reader deciding what to trust the report with.

- **No batching — by design.** JSON-RPC batch requests are refused by real public endpoints
  (measured against `eth.drpc.org`), and a refused batch reads exactly like "this chain has
  nothing here". Every request is sequential, so transport problems cannot masquerade as absent
  evidence.
- **No prices, no ticker names — by design.** Every token is asked for its `decimals()` at the
  block the transaction was mined in — a number the token publishes and the amount is interpreted
  with — so `= 316.820726` is exact, and it is shown *beside* the base amount rather than in
  place of it. A `symbol()` is a self-declared string; an address that moved 316 USDC and one
  that moved 316 of a token naming itself "USDC" are not the same fact, and no worth is implied
  either way. Scaling is display-only; netting and comparison stay on base-unit integers, so a
  6-decimal stablecoin is still never added to an 18-decimal one.
- **No findings, no severity — by design, for now.** There is no ranking of "is this an attack"
  and no USD figure, so a report cannot imply that a drain was worth more than a transfer because
  its token had more decimals. `Exit::Findings` exists in the code and is deliberately
  unreachable from `run()`.
- **No ABI decoding — not yet.** Frames carry the 4-byte selector and nothing else, so
  *who controls a value* — the question that separates an exploit from an ordinary swap — is
  unanswerable here and is not claimed.
- **No join between the tree and the receipt logs — by design, and it needs a different
  collector to change.** That tree has two frames and the transfer it produced is receipt log
  **293**, so attaching logs to frames by position attributes them to the wrong call. necropsy
  keeps the two artifacts in separate tables and never joins them.

## Roadmap

Ordered by what each one unblocks, not by ease. None of these is a promise about a version.

1. **Decode calldata past the selector.** Turns `0xa9059cbb` into *which argument moved how much
   to whom*, which is the difference between a ledger of addresses and a ledger of intent. The
   constraint it has to satisfy: a resolved name must not decide what a fixture prints, because
   then a test passes or fails on whether a label lookup happened.
2. **Attribute logs to the frame that emitted them** — only from a collector that *reports* the
   pairing (an opcode-level tracer), never inferred from position. Item 1 without this still
   leaves token movements and calls in different universes.
3. **Name re-entrancy in the tree as shape.** `Trace::ancestors` already returns the open-frame
   chain a call re-enters along; a repeated (callee, selector) on that chain is a structural
   observation with the same standing as the diff — a question, not a verdict.
4. **`--baseline-from-json`**, so two captured traces can be compared when neither node is still
   reachable. The offline caveats then have to be compared too, not just the trees.
5. **A severity model, and only then `Exit::Findings`.** This is the last item on purpose: a
   finding needs a stated model of what makes one, a denominator to price against, and a way to
   say "unknown worth" that a caller can act on. Until it exists, the tool is a reader, and a
   report that reads as a verdict is a bug rather than a feature.

## Tests

```sh
cargo test --all-targets   # 162 library + 4 argument-handling + 23 CLI-contract + 2 fixture
                         # + 8 loopback-HTTP + 6 hostile-input tests — all offline
cargo clippy --all-targets
```

The suite is hermetic: it runs against committed trace fixtures and a
`MemoryRpc`, so it never needs a node. `tests/fixtures/` holds a real `callTracer`
response and receipt captured once from public mainnet — two frames in the tree, one
log, and that log's global index is 293 — so the rule that the two sequences share no
position is checked against data rather than asserted in prose. `tests/live.rs` and
`examples/live_collect.rs` cover what a hermetic suite structurally cannot — the example
renders through `report`, so it exercises the shipped path and prints what the pipeline
accounted for:

```sh
ETH_RPC_URL=https://eth.drpc.org cargo run --example live_collect -- 0x<tx hash>
```

A second tier covers what a hermetic suite structurally cannot see: an endpoint that changes
underneath the tool. `tests/live.rs` is `#[ignore]`d, so `cargo test` never dials a node — run it
deliberately, and note the variable is its own, not `ETH_RPC_URL`, which the offline tests actively
remove so ambient configuration cannot turn them into network calls:

```sh
NECROPSY_LIVE_URL=https://eth.drpc.org cargo test --test live -- --ignored
```

Six checks, each one a claim this README makes: every input line accounted for, the JSON document
consumable with amounts as strings, **both collectors producing the same ledger for one
transaction**, a self-diff declared a tautology, `--chain` refusing a wrong chain, and
`--no-decimals` blaming the operator rather than a node. `NECROPSY_LIVE_TX` points them at another
transaction. A red here is not automatically a defect — a public endpoint can rate-limit or drop a
namespace between runs, so read the message before believing it.

`.github/workflows/live.yml` runs those checks daily and on demand, with one retry, and it is written so
an endpoint problem cannot masquerade as a regression: **exit 3 skips**, and only the content of a report
that *was* read can fail the job. Each run records the node's chain id and whether it still exposes
`debug_` before any claim is judged. The rpc-vs-cast agreement skips on the runner — it has no Foundry,
and installing a third-party toolchain on a schedule to satisfy one check is a supply-chain decision, not
a testing one — so that particular check runs locally.

## License

MIT.
