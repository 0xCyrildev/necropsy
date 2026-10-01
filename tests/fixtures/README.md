# Fixtures

Captured responses from **public mainnet**, committed so the invariant they prove can be
checked offline. These are the only files in the repo that came from a node; everything the
unit suites parse is built from inline strings.

| File | What it is |
|---|---|
| `usdc-transfer-18214590.calltracer.json` | The `debug_traceTransaction` + `callTracer` **result** for tx `0x5b515946dc1177149f140777ac90879312b182117e3392e8e2703ed3cd697153` — the same transaction the README documents. Verbatim shape, unwrapped from the JSON-RPC envelope. It is parsed twice: as a node response in `tests/fixtures.rs`, and as a file on disk by `--from-json` in `tests/cli.rs`, so the offline path is exercised against captured data rather than an imitation of it |
| `usdc-transfer-18214590.receipt.json` | A **subset** of that transaction's `eth_getTransactionReceipt`: `logs` (only the fields the parser reads), `status`, `blockNumber`. Not a whole receipt — the fields it drops are irrelevant here, and carrying them would suggest they were tested |

Both describe public Ethereum data: a transaction in block 18,214,590 that moved
`316820726` of USDC (`0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48`, 6 decimals — 316.820726).

## What they are for

Two frames in the tree, one log in the receipt, and that log's global index is **293**.
That is invariant 1 made checkable from data: the call tree and the receipt logs are two
real sequences that do not index each other, and any code that merges them positionally
would attach log 293 to the second frame and render a confident wrong answer.
`tests/fixtures.rs` asserts exactly that, and asserts the log classifies as a fungible move
so the ledger path is exercised by the same file.

## Naming

The name states only what was verified in this repo: the token, and the block. It does
**not** carry the incident label that older notes attached to this transaction — that
attribution was never checked here, and a filename in a public repo is a claim.

## Adding a fixture

1. Capture the raw response and keep only what a parser reads:
   `curl -sS -X POST $URL -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"debug_traceTransaction","params":["0x<hash>",{"tracer":"callTracer"}]}'`
2. Strip the JSON-RPC envelope (`.result`), compact it (`separators=(',',':')`), and keep the
   file under a few KB. If a case needs a big response, build it as an inline string in the
   unit tests instead — which is also how the 6,000-frame and orphan cases are made.
3. Name it for observable facts, not conclusions.
4. Never commit a trace of someone else's live incident, a private chain, or anything with a
   host that carries a credential. Public mainnet only.
