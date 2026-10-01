#!/usr/bin/env node
// Resolve the platform binary that npm installed alongside this package, and run it.
//
// There is no install-time download here. The binaries arrive as ordinary npm dependencies —
// one per platform, selected by `os`/`cpu` in their package.json — so `npm install` does what it
// always does, and nothing in this file reaches the network. A postinstall that curls a release
// asset would add a fetch-and-exec step to every install of every user of this tool, and it is
// the kind of step that gets quietly repointed at different bytes.
//
// It also does not decide which binary by filename guessing or by reading `process.platform`
// into a path it then trusts. It resolves a *package*, checks that the package's version matches
// this one, and only then execs what it contains.

"use strict";

const { spawnSync } = require("node:child_process");
const path = require("node:path");

const SELF = require("../package.json");

// node's `process.platform`/`process.arch`, mapped onto the packages in TARGETS.
function candidates() {
  const { platform, arch } = process;
  if (platform === "darwin") {
    return [`@0xcyrildev/necropsy-darwin-${arch === "arm64" ? "arm64" : "x64"}`];
  }
  if (platform === "linux") {
    // musl and glibc builds of the same architecture are different binaries, and picking wrong
    // is a load error the user cannot interpret. Node reports the C it was built against.
    const musl = isMusl();
    const cpu = arch === "arm64" ? "arm64" : "x64";
    const primary = `@0xcyrildev/necropsy-linux-${cpu}-${musl ? "musl" : "gnu"}`;
    const fallback = `@0xcyrildev/necropsy-linux-${cpu}-${musl ? "gnu" : "musl"}`;
    return [primary, fallback];
  }
  return [];
}

function isMusl() {
  try {
    const report = process.report?.getReport?.();
    const header = report?.header ?? {};
    // glibcVersionRuntime is present on a glibc-linked Node and absent on musl.
    return header.glibcVersionRuntime === undefined && header.glibcVersion === undefined;
  } catch {
    return false;
  }
}

function resolveBinary() {
  const tried = [];
  for (const name of candidates()) {
    try {
      const pkg = require(`${name}/package.json`);
      if (pkg.version !== SELF.version) {
        fail(
          `the platform package ${name} is version ${pkg.version} but ${SELF.name} is ` +
            `${SELF.version}. Reinstall both at the same version — a mixed tree runs a binary ` +
            `nobody tested against this launcher.`,
        );
      }
      const exe = path.join(path.dirname(require.resolve(`${name}/package.json`)), "bin", `necropsy${process.platform === "win32" ? ".exe" : ""}`);
      return { exe, name };
    } catch (e) {
      tried.push(`${name} (${e.code || e.message})`);
    }
  }
  fail(
    `no necropsy binary is installed for ${process.platform}/${process.arch}. Tried: ` +
      `${tried.join(", ") || "nothing"}. The packages that exist are ` +
      `linux-x64-gnu, linux-x64-musl, linux-arm64-gnu, darwin-arm64 and darwin-x64 — ` +
      `there is no Windows build, and no build for other platforms.`,
  );
}

function fail(message) {
  process.stderr.write(`necropsy: ${message}\n`);
  process.exit(2);
}

const { exe, name } = resolveBinary();
const result = spawnSync(exe, process.argv.slice(2), { stdio: "inherit", env: process.env });

if (result.error) {
  // The exec itself failed: a missing bit, a non-executable mode, an ELF loader that could not
  // satisfy the binary's libc. Say which package it came from, because that is the thing the
  // operator can act on.
  fail(`could not run ${exe} from ${name}: ${result.error.message}`);
}

if (result.signal) {
  // Reproduce the signal so a pipeline that watched for 128+N still sees it, and so Ctrl-C in a
  // parent shell is not swallowed by the wrapper being the last process standing.
  process.kill(process.pid, result.signal);
} else {
  process.exit(result.status ?? 1);
}
