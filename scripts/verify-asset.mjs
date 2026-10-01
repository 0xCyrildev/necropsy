#!/usr/bin/env node
// Prove a built binary really is the target it is about to be labelled.
//
// Two ways to get this wrong, and CI catches only one of them. A build can silently produce the
// host's binary while being *asked* for a cross target (a linker override that did not take), and
// an asset can be renamed onto the wrong platform by hand. So: if this machine can execute the
// file, ask it what it is via `--build-info`. If it cannot, read the header — the ELF `e_machine`
// word or the Mach-O `cputype` — which is what the loader itself keys on.
//
// `file(1)` is not used because its output is prose that varies by distro; the bytes do not.

import { readFileSync, existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { TARGETS } from "./targets.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const targetName = process.argv[2];
const target = TARGETS.find((t) => t.cargoTarget === targetName);
if (!target) {
  console.error(`unknown cargo target: ${targetName}`);
  process.exit(2);
}

const bin = process.argv[3] ?? join(ROOT, "target", targetName, "release", "necropsy");
if (!existsSync(bin)) {
  console.error(`no binary at ${bin}`);
  process.exit(1);
}

const want = wantMachine(target.cargoTarget);
const bytes = readFileSync(bin);
const found = sniff(bytes);

if (!found) {
  console.error(`${bin} is neither an ELF nor a Mach-O64 file (magic ${bytes.subarray(0, 4).toString("hex")})`);
  process.exit(1);
}
if (found.machine !== want.machine) {
  console.error(
    `MISMATCH: ${bin} reports ${found.kind}/${found.machine} but ${targetName} requires ${want.machine}`,
  );
  process.exit(1);
}

// Cross-check with the binary's own answer when this host can run it. A header can be forged by
// a bad rename; the running process cannot claim to be an arch it is not.
let ran = false;
// An emulation prefix, when CI supplied one: `qemu-aarch64 -L <sysroot>` runs an arm64 ELF on an
// x86_64 runner. Without it the arm64 and macOS-intel assets are checked by header alone, and a
// header is only as honest as the rename that wrote it.
const emulation = (process.env.NECROPSY_QEMU || "").split(/\s+/).filter(Boolean);
if (executableHere(target) || emulation.length) {
  const argv = [...emulation, bin, "--build-info"];
  const info = JSON.parse(execFileSync(argv[0], argv.slice(1), { encoding: "utf8" }));
  if (info.os !== target.rustOs || info.arch !== target.rustArch) {
    console.error(
      `MISMATCH: ${bin} runs and reports os=${info.os} arch=${info.arch}, expected ${target.rustOs}/${target.rustArch}`,
    );
    process.exit(1);
  }
  const expectVersion = process.argv[4];
  if (expectVersion && info.version !== expectVersion) {
    console.error(`MISMATCH: ${bin} reports version ${info.version}, release is ${expectVersion}`);
    process.exit(1);
  }
  console.log(
    `verified by header (${found.kind} ${found.machine}) and by ${emulation.length ? "qemu: " : "running "}${info.version}`,
  );
  ran = true;
} else {
  console.log(`verified by header only (${found.kind} ${found.machine}) — this host cannot exec ${targetName}`);
}

console.log(`OK ${targetName} ${bin}${ran ? "" : " (not executed)"}`);

function wantMachine(cargo) {
  if (cargo.endsWith("x86_64-unknown-linux-musl") || cargo.endsWith("x86_64-unknown-linux-gnu")) {
    return { kind: "elf", machine: "x86-64" };
  }
  if (cargo.startsWith("aarch64-unknown-linux")) return { kind: "elf", machine: "aarch64" };
  if (cargo === "x86_64-apple-darwin") return { kind: "macho64", machine: "x86_64" };
  if (cargo === "aarch64-apple-darwin") return { kind: "macho64", machine: "arm64" };
  throw new Error(`no header expectation for ${cargo}`);
}

function sniff(bytes) {
  if (bytes.subarray(0, 4).toString("hex") === "7f454c46") {
    const e = bytes.readUInt16LE(18);
    return { kind: "elf", machine: { 0x3e: "x86-64", 0xb7: "aarch64" }[e] ?? `0x${e.toString(16)}` };
  }
  const magic = bytes.readUInt32LE(0);
  if (magic === 0xfeedfacf || magic === 0xcfafedbe) {
    const cpu = bytes.readUInt32LE(4);
    return { kind: "macho64", machine: { 0x01000007: "x86_64", 0x0100000c: "arm64" }[cpu] ?? `0x${cpu.toString(16)}` };
  }
  return null;
}

// Whether *this* process could exec that file directly. Musl binaries run on a glibc host (they
// are static), and an x86_64 Linux runner can exec an x86_64 Linux ELF; nothing cross-arch can,
// and darwin-x64 built on an arm64 Mac cannot be exec'd without a Rosetta handshake that CI jobs
// do not get. Those cases fall back to the header, or to `NECROPSY_QEMU` when CI supplied one.
function executableHere(t) {
  if (t.os !== process.platform) return false;
  if (t.os === "darwin") return t.cpu === process.arch;
  return t.cpu === process.arch;
}
