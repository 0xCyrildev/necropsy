#!/usr/bin/env node
// Generate every package.json in npm/ from scripts/targets.mjs and the crate version in
// Cargo.toml. Run it after changing either, and commit the result: CI re-runs it and fails on a
// diff, so a manifest can never disagree with the matrix or the crate.
//
// The version has one source — Cargo.toml. A package.json that drifted from the binary it packs
// is the failure this whole file exists to prevent.

import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { TARGETS, CLI_PACKAGE } from "./targets.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

function crateVersion() {
  const toml = readFileSync(join(ROOT, "Cargo.toml"), "utf8");
  const m = toml.match(/^version = "([^"]+)"$/m);
  if (!m) throw new Error("no `version = \"…\"` line in Cargo.toml");
  return m[1];
}

const version = crateVersion();
const repository = {
  type: "git",
  url: "git+https://github.com/0xCyrildev/necropsy.git",
};
const common = { license: "MIT", repository, homepage: "https://github.com/0xCyrildev/necropsy#readme" };

const cli = {
  name: CLI_PACKAGE,
  version,
  description:
    "Post-transaction forensics for EVM chains: reconstruct the call tree and rank where value ended up",
  bin: { necropsy: "bin/necropsy.js" },
  engines: { node: ">=18" },
  optionalDependencies: Object.fromEntries(TARGETS.map((t) => [t.npmName, version])),
  files: ["bin/necropsy.js", "README.md", "LICENSE"],
  keywords: ["ethereum", "evm", "forensics", "transaction", "call-tracer", "incident-response"],
  ...common,
};

write(join(ROOT, "npm", "cli", "package.json"), cli);

for (const t of TARGETS) {
  const pkg = {
    name: t.npmName,
    version,
    description: `necropsy binary for ${t.os}/${t.cpu}${t.libc ? ` (${t.libc})` : ""}`,
    os: [t.os],
    cpu: [t.cpu],
    // Documentation only — npm ignores it — but it is the field that explains why linux/x64 has
    // two packages and a `--libc` mismatch is otherwise invisible.
    ...(t.libc ? { libc: t.libc } : {}),
    files: ["bin/necropsy", "README.md", "LICENSE"],
    ...common,
  };
  write(join(ROOT, "npm", t.dir, "package.json"), pkg);
}

function write(path, obj) {
  if (!existsSync(dirname(path))) mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(obj, null, 2) + "\n");
  console.log(`wrote ${path.slice(ROOT.length + 1)}`);
}
