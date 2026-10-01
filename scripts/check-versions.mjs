#!/usr/bin/env node
// Fail if the npm manifests and the crate disagree. Run in CI; it is the cheap half of the
// promise that `npm i @0xcyrildev/necropsy@X` installs binaries built from version X.
//
// What it does *not* do is verify the tarball contents — that is pack-npm.mjs, which runs the
// binary and reads --build-info. This file only catches the disagreement a human can introduce
// by editing one JSON by hand.

import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { TARGETS, CLI_PACKAGE } from "./targets.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const errors = [];

const crateVersion = readFileSync(join(ROOT, "Cargo.toml"), "utf8").match(
  /^version = "([^"]+)"$/m,
)[1];

function read(dir) {
  const path = join(ROOT, "npm", dir, "package.json");
  if (!existsSync(path)) {
    errors.push(`missing ${path.slice(ROOT.length + 1)} — run scripts/write-manifests.mjs`);
    return null;
  }
  return JSON.parse(readFileSync(path, "utf8"));
}

const cli = read("cli");
if (cli) {
  if (cli.name !== CLI_PACKAGE) errors.push(`cli package is named ${cli.name}, expected ${CLI_PACKAGE}`);
  if (cli.version !== crateVersion) errors.push(`cli version ${cli.version} != crate ${crateVersion}`);
  const deps = cli.optionalDependencies ?? {};
  for (const t of TARGETS) {
    if (deps[t.npmName] !== crateVersion) {
      errors.push(`optionalDependency ${t.npmName} is ${deps[t.npmName]}, expected ${crateVersion}`);
    }
  }
  for (const name of Object.keys(deps)) {
    if (!TARGETS.some((t) => t.npmName === name)) {
      errors.push(`optionalDependency ${name} is not in scripts/targets.mjs`);
    }
  }
  if (!existsSync(join(ROOT, "npm", "cli", "bin", "necropsy.js"))) errors.push("npm/cli/bin/necropsy.js is missing");
}

for (const t of TARGETS) {
  const pkg = read(t.dir);
  if (!pkg) continue;
  if (pkg.name !== t.npmName) errors.push(`npm/${t.dir} is named ${pkg.name}, expected ${t.npmName}`);
  if (pkg.version !== crateVersion) errors.push(`npm/${t.dir} version ${pkg.version} != crate ${crateVersion}`);
  if (!pkg.os?.includes(t.os)) errors.push(`npm/${t.dir} os is ${JSON.stringify(pkg.os)}, expected ${t.os}`);
  if (!pkg.cpu?.includes(t.cpu)) errors.push(`npm/${t.dir} cpu is ${JSON.stringify(pkg.cpu)}, expected ${t.cpu}`);
  if (pkg.license !== "MIT") errors.push(`npm/${t.dir} license is ${pkg.license}`);
  if (!pkg.files?.some((f) => f.startsWith("bin/necropsy"))) {
    errors.push(`npm/${t.dir} files does not include the binary, so npm would publish an empty package`);
  }
}

if (!existsSync(join(ROOT, "LICENSE"))) errors.push("LICENSE is missing at the repository root");

if (errors.length) {
  for (const e of errors) console.error(`VERSION CHECK: ${e}`);
  process.exit(1);
}
console.log(`versions agree: crate ${crateVersion}, ${TARGETS.length} platform packages + ${CLI_PACKAGE}`);
