#!/usr/bin/env node
// Stage one release asset: a .tar.gz holding the binary, LICENSE and README, byte-for-byte
// identical on every runner.
//
// GNU tar's `--sort --mtime --owner --group` recipe is what makes an archive reproducible on Linux,
// and macOS's bsdtar rejects `--sort=name` outright — which the first rehearsal discovered by failing
// on both Darwin jobs. Installing GNU tar on a Mac runner to keep a flag is the wrong trade; writing
// the archive here costs about ninety lines, uses no dependency, and produces the same bytes on
// every platform instead of the same *intent*.
//
// Determinism matters because a checksum is only evidence when a change in it means a change in
// content. So: entries in a fixed order, mtime 0, uid/gid 0, mode 0755 for the binary and 0644 for
// the docs, no uname/gname, and a gzip envelope with a zero MTIME and no name field.

import { deflateRawSync } from "node:zlib";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join, basename } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const [binPath, outDir, version, cargoTarget] = process.argv.slice(2);
for (const [name, v] of [["binary", binPath], ["outDir", outDir], ["version", version], ["target", cargoTarget]]) {
  if (!v) {
    console.error(`usage: node scripts/stage-asset.mjs <binary> <outDir> <version> <cargoTarget>`);
    process.exit(2);
  }
  if (name === "binary" && !existsSync(v)) {
    console.error(`no binary at ${v}`);
    process.exit(1);
  }
}

const dir = `necropsy-${version}-${cargoTarget}`;

function main() {
  const entries = [
    { name: `${dir}/necropsy`, data: readFileSync(binPath), mode: 0o755 },
    { name: `${dir}/LICENSE`, data: readFileSync(join(ROOT, "LICENSE")), mode: 0o644 },
    { name: `${dir}/README.md`, data: readFileSync(join(ROOT, "README.md")), mode: 0o644 },
  ];

  const archive = tar(entries);
  const gz = gzip(archive);
  mkdirSync(outDir, { recursive: true });
  const asset = join(outDir, `${dir}.tar.gz`);
  writeFileSync(asset, gz);
  const sum = createHash("sha256").update(gz).digest("hex");
  writeFileSync(`${asset}.sha256`, `${sum}  ${basename(asset)}\n`);
  console.log(`staged ${asset} (${gz.length} bytes, sha256 ${sum.slice(0, 16)}…)`);
}

function tar(files) {
  const blocks = [];
  for (const f of files) {
    blocks.push(header(f));
    blocks.push(zeroPad(f.data));
  }
  blocks.push(Buffer.alloc(1024)); // two zero blocks end the archive
  return Buffer.concat(blocks);
}

function header({ name, data, mode }) {
  const h = Buffer.alloc(512);
  // ustar names longer than 100 bytes are split across name and prefix; the paths here are short
  // enough that the simple layout always holds, and the assert says so rather than silently
  // writing a corrupt member name.
  if (name.length > 100) throw new Error(`member name too long for ustar: ${name}`);
  h.write(name, 0, "ascii");
  octal(h, mode, 100, 8); // st_mode (no setuid/setgid bits in these files)
  octal(h, 0, 108, 8); // st_uid
  octal(h, 0, 116, 8); // st_gid
  octal(h, data.length, 124, 12);
  octal(h, 0, 136, 12); // st_mtime: the epoch, always. Two runs of one commit must agree.
  h.write("        ", 148, "ascii"); // checksum placeholder while summing
  h.write("0", 156, "ascii"); // typeflag: regular file
  h.write("ustar\0", 257, "ascii");
  h.write("00", 263, "ascii");
  let sum = 0;
  for (const b of h) sum += b;
  octal(h, sum, 148, 7);
  h.write(" ", 155, "ascii");
  return h;
}

function octal(buf, value, offset, length) {
  const s = value.toString(8).padStart(length - 1, "0");
  buf.write(s, offset, "ascii");
  buf.write("\0", offset + s.length, "ascii");
}

function zeroPad(data) {
  const rem = data.length % 512;
  return rem === 0 ? data : Buffer.concat([data, Buffer.alloc(512 - rem)]);
}

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

function gzip(raw) {
  const deflated = deflateRawSync(raw, { level: 9 });
  const out = Buffer.alloc(10 + deflated.length + 8);
  out[0] = 0x1f;
  out[1] = 0x8b;
  out[2] = 8; // CM: deflate
  out[3] = 0; // FLG: no name, no comment, no crc
  out.writeUInt32LE(0, 4); // MTIME = 0, so the envelope carries no timestamp either
  out[8] = 2; // XFL: maximum compression
  out[9] = 255; // OS: unknown — claiming a platform here would be a lie about the runner
  deflated.copy(out, 10);
  out.writeUInt32LE(crc32(raw), 10 + deflated.length);
  out.writeUInt32LE(raw.length >>> 0, 10 + deflated.length + 4);
  return out;
}


function crc32(buf) {
  let c = 0xffffffff;
  for (const b of buf) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

// Called last on purpose: the tables above are `const`, and in a module they initialize in
// source order — invoking the work earlier reads one before it exists.
main();
