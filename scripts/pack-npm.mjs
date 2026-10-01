#!/usr/bin/env node
// Put each built binary into its platform package, prove it is the binary it claims to be, and
// pack the tarballs npm would publish.
//
// Usage: node scripts/pack-npm.mjs <distDir> [--publish-dry-run]
//
// The verification step is the point of the script rather than the file copying: a release asset
// named `…-aarch64-…` that actually contains an x86_64 binary is a packaging mistake nobody
// discovers until a user cannot exec it. Where the current host can run the binary, run it and
// read `--build-info`; where it cannot, say so instead of pretending the check happened.

import { execFileSync, spawnSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { TARGETS, CLI_PACKAGE } from "./targets.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const dist = process.argv[2];
if (!dist) {
  console.error("usage: node scripts/pack-npm.mjs <distDir> [--publish-dry-run]");
  process.exit(2);
}
const dry = process.argv.includes("--publish-dry-run");

const version = readFileSync(join(ROOT, "Cargo.toml"), "utf8").match(/^version = "([^"]+)"$/m)[1];
const perTarget = new Map();
let skipped = 0;

for (const t of TARGETS) {
  const exeName = t.os === "windows" ? "necropsy.exe" : "necropsy";
  const asset = join(ROOT, dist, `necropsy-${t.cargoTarget}`);
  if (!existsSync(asset)) {
    console.error(`MISSING   ${asset}`);
    process.exit(1);
  }

  const pkgDir = join(ROOT, "npm", t.dir);
  const dest = join(pkgDir, "bin", exeName);
  mkdirSync(dirname(dest), { recursive: true });
  copyFileSync(asset, dest);
  chmodX(dest);

  const claim = verify(asset, t);
  copyFileSync(join(ROOT, "LICENSE"), join(pkgDir, "LICENSE"));
  writeFileSync(
    join(pkgDir, "README.md"),
    `# ${t.npmName}\n\nThe ${t.os}/${t.cpu}${t.libc ? ` (${t.libc})` : ""} build of [necropsy](https://github.com/0xCyrildev/necropsy), version \`${version}\`.\n\nThis package is installed automatically as an optional dependency of \`${CLI_PACKAGE}\` when\nyour platform matches its \`os\`/\`cpu\` fields. Install it directly only if you are wiring the\nbinary into something else; the executable lands at \`bin/necropsy\`.\n\n\`${claim}\`\n\nLicense: MIT.\n`,
  );
  perTarget.set(t.dir, dest);
  console.log(`packed    ${t.npmName}  <- ${asset}`);
}

// The launcher package: no binary, so nothing to verify beyond that the manifest is current.
copyFileSync(join(ROOT, "LICENSE"), join(ROOT, "npm", "cli", "LICENSE"));

if (dry) {
  for (const dir of ["cli", ...TARGETS.map((t) => t.dir)]) {
    const out = spawnSync("npm", ["pack", "--dry-run", "--json"], {
      cwd: join(ROOT, "npm", dir),
      encoding: "utf8",
    });
    if (out.status !== 0) {
      console.error(out.stdout + out.stderr);
      process.exit(1);
    }
    console.log(`npm pack --dry-run ok: npm/${dir}`);
  }
}

console.log(
  JSON.stringify({ version, packages: [...perTarget.keys()], skipped }, null, 2),
);

function chmodX(path) {
  execFileSync("chmod", ["+x", path]);
}

/// Run the binary if this host can, and read the truth out of it. Otherwise report the skipped
/// check — a cross-compiled arm64 ELF cannot be exec'd on x86_64 without an emulator, and an
/// unchecked asset must not be described as a checked one.
function verify(asset, t) {
  const local = t.os === process.platform && t.cpu === process.arch;
  if (!local) {
    console.log(`verify    ${t.cargoTarget}: SKIPPED (this host is ${process.platform}/${process.arch})`);
    skipped++;
    return `Verification: skipped on the packaging host (built for ${t.os}/${t.cpu}).`;
  }
  const info = JSON.parse(execFileSync(asset, ["--build-info"], { encoding: "utf8" }));
  const problems = [];
  if (info.version !== version) problems.push(`version ${info.version} != ${version}`);
  // Compared against the Rust names, not npm's: `consts::OS` answers "macos" where the package
  // field says "darwin", and "x86_64" where it says "x64".
  if (info.os !== t.rustOs) problems.push(`os ${info.os} != ${t.rustOs}`);
  if (info.arch !== t.rustArch) problems.push(`arch ${info.arch} != ${t.rustArch}`);
  if (problems.length) {
    console.error(`VERIFY FAILED ${t.cargoTarget}: ${problems.join(", ")}`);
    process.exit(1);
  }
  console.log(`verify    ${t.cargoTarget}: ${info.version} os=${info.os} arch=${info.arch}`);
  return `Verified by \`--build-info\`: version \`${info.version}\`, os \`${info.os}\`, arch \`${info.arch}\`.`;
}
