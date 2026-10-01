# Security policy

necropsy is a reader. It reconstructs what a transaction did and reports what it could not
account for. That framing sets what a security problem here looks like: the damage is not a
compromised server, it is an analyst trusting an answer the tool did not actually have.

## What counts as a vulnerability

- **A wrong number presented as a right one.** A truncated trace reported as a complete tree,
  an absent receipt rendered as zero transfers, a value summed across two tokens, an amount
  losing precision past 2^53. These are the failures this tool exists not to have, and a
  reproducible case for any of them is a bug worth a private report.
- **A credential escaping the process.** The RPC URL is treated as a secret everywhere it can
  appear: provider error text, `--help`, the report, `cast`'s argv. Anything that puts a key, a
  token path segment or a proxy userinfo pair into stdout, stderr, a file, or a child process's
  command line is in scope.
- **Unbounded consumption of a resource the operator did not ask for.** A response body, a
  nesting depth, a frame count, a retry loop or a child process's output that necropsy reads
  without a ceiling — because the practical attack on a forensics tool is a hostile endpoint
  that makes it die mid-run, or quietly truncate.
- **A parse path that panics on untrusted input.** Every `debug_traceTransaction` response,
  receipt and `--from-json` file in this tool is somebody else's bytes. A corpus input that
  reaches `unwrap`/`expect`/indexing in production code is in scope. (`tests/` panicking is not.)
- **Path handling in `--from-json`** — it opens exactly the file named and reads a bounded
  prefix of it. Anything beyond that is in scope.

## What is out of scope

- The chain, the endpoint, and anything the transaction did. necropsy does not execute,
  replay, sign or send anything, and it does not decide whether a transaction was an attack.
  A report saying "necropsy found nothing harmful here" is not evidence about the transaction —
  it never looks for harm, and it has no severity model.
- A dependency's advisory that cannot be reached through the surface above.
- Prompt-level confusion caused by wording (`degraded`, `unknown`, `?`) unless it survives a
  concrete reproducible case of a wrong claim being made.

## How to report

Open a **private vulnerability report** on the repository's Security tab
(`github.com/0xCyrildev/necropsy/security/advisories/new`) rather than a public issue. If that
is not available, open a normal issue with just the word "security" in the title and no details,
and the details will follow privately.

There is no PGP key, no SLA and no bug bounty. This is an unmaintained-by-a-company 0.x tool:
what you can expect is that a report with a reproducible case gets read, fixed and credited if
you want it, and that the fix comes with a test that would have caught it.

## Priorities when a report is valid

1. Anything that makes a wrong answer look confident.
2. Anything that leaks a credential.
3. Anything that crashes instead of refusing.

That order is the same one the invariants in the code follow, and it is not an accident.
