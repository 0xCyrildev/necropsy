# Changelog

The format is [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) **within 0.x**: a minor
bump may rename a `--json` field, and a patch bump may not.

## What is released

`v0.2.0` is the first tag, so it is the first artifact: five platform binaries, one checksum
manifest, six npm tarballs, all attached to the GitHub Release and built by the pipeline described
in `RELEASE.md`. Nothing before this existed as anything but source.

## 0.2.0 — 2026-10-01

### Added

- `--build-info` — the version, the `--json` schema version, and the `os`/`arch` the *running binary*
  reports. A packager needs a claim the artifact cannot fake; `--version` is a string the build
  system wrote.
- npm distribution under `@0xcyrildev`: a launcher plus one package per platform, selected by npm's
  `os`/`cpu` fields. No `postinstall`, and no download at install time. Linux x86_64 (glibc and
  musl), Linux arm64, macOS arm64 and macOS x86_64. **No Windows package** — nothing in this tree has
  ever run there, and an unverified binary would be a claim rather than a feature.
- Release pipeline: `v*` tags build every target, verify each asset against the target its name
  claims (ELF/Mach-O header, plus execution directly or under qemu), stage it as a byte-reproducible
  `.tar.gz`, checksum into one `SHA256SUMS.txt`, and publish a GitHub Release. A
  `workflow_dispatch` runs the same pipeline and publishes nothing, so the first execution of it is
  never the release itself.
- `scripts/targets.mjs` is the single list of platforms; the CI matrix, the npm manifests and the
  packaging script all read it, so they cannot drift.
- `--from-json <PATH>` — analyse a captured `callTracer` response (bare frame object or
  JSON-RPC envelope) without dialling a node. Exits 4, because a file carries no receipt and no
  transaction metadata, and the report names both absences instead of printing zeros.
- `--max-response-mb <MB>` (default 32) and `--max-trace-depth <LEVELS>` (default 2,048) —
  ceilings on what untrusted input may consume. They govern the HTTP body, `cast`'s stdout and
  `--from-json` alike, and a refusal says which number was crossed rather than reading as a
  parse failure.
- `schema_version` in the `--json` document: the shape's version, distinct from the crate's.
- CI compiles the declared MSRV instead of asserting it. `rust-version` was **1.85 and is now
  1.90**, because `ruint` — the `U256` the ledger's amounts are — declares 1.90 in its own manifest;
  the older number had never been built. Also verified: `cargo publish --dry-run` packages nothing
  outside `src/`, `tests/`, `examples/`, the workflows and the docs.
- `--baseline-tx-hash` / `--baseline-rpc-url` — structural comparison against a second
  transaction, from the same endpoint or a different one, with `--chain` guarding both sides.
- Per-token `decimals()` read at the transaction's own block tag; amounts scale beside base
  units, never in place of them. `--no-decimals` declines the calls.
- `--narrative` — the same frames as a numbered sequence naming each call's parent.
- Test tiers: committed mainnet fixtures, an opt-in live endpoint contract
  (`NECROPSY_LIVE_URL`, `#[ignore]`d), a scheduled CI job for it, and loopback HTTP tests that
  exercise the real transport without reaching the internet.

### Changed

- **Exit status 2 is now only for reasons the operator can fix by editing the command line.**
  An HTTP 400–404 was previously `2`, which told a caller to re-read the manual when the
  endpoint, not the flags, was the problem. Status codes from the network are `3`.
- 429/500/502/503/504 retry with backoff, and a `Retry-After` the endpoint sends is waited out.
  Deterministic statuses do not retry.
- `--help` no longer echoes `ETH_RPC_URL`. clap prints an env default verbatim, and a provider
  URL is a credential — the usage screen is the one output people paste into an issue.
- `--from-json` plus an exported `ETH_RPC_URL` works; `--from-json` plus a typed `--rpc-url` is
  refused as two sources for one run. Previously the environment case was refused too, which
  made the flag unusable for anyone who uses a node daily.
- A closed pipe (`necropsy … | head`) exits 0 instead of panicking with 101, a code outside the
  documented contract.
- One HTTP agent per endpoint instead of one per request, and a `necropsy/<version>`
  User-Agent, so a sequential client stops paying a TLS handshake per call and stops looking
  like an unknown client to the endpoint's own rate limits.

### Fixed

- A response body of any size was read into memory with no ceiling (`ureq`'s default limit is
  unlimited) — on both collectors, since `cast`'s stdout had the same `read_to_end`.
- Nesting depth was capped by `serde_json`'s hidden 128-level limit, so a genuinely deep trace
  arrived as "not valid JSON" rather than as a depth decision, and the file path parsed on the
  main thread's 2 MiB stack instead of the sized collection stack.
- Two doc comments and one commit message described a `--from-json` flag that no commit had
  ever defined; the README's Status section claimed the baseline comparison had "no replacement
  yet" 85 lines above its own documentation for it.
