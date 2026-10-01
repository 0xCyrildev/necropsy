#!/usr/bin/env node
// Every `steps.<id>.outputs.<name>` in a workflow must have a matching `- id: <id>`.
//
// A step that writes to $GITHUB_OUTPUT without an `id` still succeeds — and its outputs are
// unreachable, so anything downstream reads an empty string. In a release workflow that means a
// matrix that expands to zero jobs: the run turns red with a green plan step and no build job at
// all, which is close to the worst possible failure to debug. This happened here (commit
// `c170764`), so the check is now in CI instead of in someone's memory.
//
// Regex over the file rather than a YAML parse, because a dependency for one assertion is not
// worth it and the pattern it looks for is a line-level one.

import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const files = readdirSync(join(ROOT, ".github", "workflows")).filter((f) => f.endsWith(".yml"));
const failures = [];

for (const f of files) {
  const path = join(ROOT, ".github", "workflows", f);
  const text = readFileSync(path, "utf8");
  const ids = new Set([...text.matchAll(/^\s*-?\s*id:\s*([A-Za-z0-9_-]+)/gm)].map((m) => m[1]));
  const refs = [...text.matchAll(/steps\.([A-Za-z0-9_-]+)\.outputs/g)].map((m) => m[1]);
  for (const ref of new Set(refs)) {
    if (!ids.has(ref)) failures.push(`${f}: references steps.${ref}.outputs with no matching "id: ${ref}"`);
  }
}

for (const line of failures) console.error(`WORKFLOW IDS: ${line}`);
if (failures.length) process.exit(1);
console.log(`workflow step ids check ok across ${files.length} files: ${files.join(", ")}`);
