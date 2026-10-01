#!/usr/bin/env node
// Two cheap structural rules about the workflow files, each learned by being broken here.
//
// 1. Every `steps.<id>.outputs.<name>` needs a matching `- id: <id>`. A step that writes to
//    $GITHUB_OUTPUT without an `id` still succeeds, but its outputs are unreachable, so the job
//    output arrives empty — in a release workflow that was a matrix expanding to zero jobs, with a
//    green plan step and no build job anywhere in the run.
//
// 2. Only workflow-level keys may sit at column zero. `environment` is legal on a job and illegal at
//    the top level, and GitHub's response to that mistake was one failed run per push with no jobs
//    and no readable message: an invalid workflow file looks like a red pipeline, not like a config
//    error, which is why this is a check and not a note.
//
// Regex rather than a YAML parse on purpose — both rules are line-level, and a dependency bought to
// assert two properties of our own files is the larger risk.

import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const DIR = join(ROOT, ".github", "workflows");

const WORKFLOW_KEYS = new Set([
  "name",
  "on",
  "permissions",
  "env",
  "defaults",
  "concurrency",
  "run-name",
  "jobs",
]);

const failures = [];
const files = readdirSync(DIR).filter((f) => f.endsWith(".yml"));

for (const f of files) {
  const text = readFileSync(join(DIR, f), "utf8");

  for (const [i, line] of text.split("\n").entries()) {
    const top = line.match(/^([A-Za-z][A-Za-z0-9_-]*):/);
    if (top && !WORKFLOW_KEYS.has(top[1])) {
      failures.push(
        `${f}:${i + 1}: "${top[1]}:" at column 0 is not a workflow-level key — is it meant for a job?`,
      );
    }
  }

  const ids = new Set([...text.matchAll(/^\s*-?\s*id:\s*([A-Za-z0-9_-]+)/gm)].map((m) => m[1]));
  const refs = [...text.matchAll(/steps\.([A-Za-z0-9_-]+)\.outputs/g)].map((m) => m[1]);
  for (const ref of new Set(refs)) {
    if (!ids.has(ref)) {
      failures.push(`${f}: references steps.${ref}.outputs with no matching "id: ${ref}"`);
    }
  }
}

for (const line of failures) console.error(`WORKFLOW LINT: ${line}`);
if (failures.length) process.exit(1);
console.log(`workflow lint ok across ${files.length} files: ${files.join(", ")}`);
