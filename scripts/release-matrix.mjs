#!/usr/bin/env node
// Emit the release job's build matrix from scripts/targets.mjs, as a GitHub Actions output.
//
// The matrix and the npm packages must never disagree: a target in one but not the other is
// either a release asset nobody can install, or an npm package that 404s on download. Generating
// the CI matrix from the same module the packages are generated from is what makes that
// impossible rather than merely unlikely.

import { TARGETS } from "./targets.mjs";

const include = TARGETS.map((t) => ({
  npmName: t.npmName,
  dir: t.dir,
  cargoTarget: t.cargoTarget,
  os: t.os,
  cpu: t.cpu,
  runner: t.runner,
  system: t.system === true,
  apt: t.apt ?? [],
  linker: t.linker ?? "",
}));

// Always print, never write the file directly: the workflow redirects stdout into GITHUB_OUTPUT, so
// there is exactly one mechanism moving this value and no chance of it landing twice — or, if the
// env var were unset in a job, of silently producing an empty output that expands to zero build
// jobs and fails the run with nothing in it.
console.log(`matrix=${JSON.stringify({ include })}`);
