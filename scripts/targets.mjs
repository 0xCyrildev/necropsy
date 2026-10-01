// The platform matrix, in one place, because three things have to agree on it: the release
// workflow that builds each target, the npm packages that carry each binary, and the launcher
// that resolves one at run time. `scripts/check-versions.mjs` fails CI if they drift.
//
// `npmName` is the package that holds the binary for that target; `cargoTarget` is what
// `cargo build --target` is asked for; `runner` is the GitHub Actions image that can build it
// without a third-party toolchain.
//
// `os`/`cpu` are npm's (Node's) words for a platform, `rustOs`/`rustArch` are what
// `std::env::consts` reports from inside the binary — `darwin` vs `macos`, `x64` vs `x86_64`.
// Both are kept, because the check that proves an asset holds the right binary has to compare
// across the two vocabularies instead of assuming they agree.
export const TARGETS = [
  {
    npmName: "@0xcyrildev/necropsy-linux-x64-gnu",
    dir: "linux-x64-gnu",
    cargoTarget: "x86_64-unknown-linux-gnu",
    os: "linux",
    cpu: "x64",
    rustOs: "linux",
    rustArch: "x86_64",
    libc: "glibc",
    runner: "ubuntu-24.04",
    // The host target: no `rustup target add`, no extra linker.
    system: true,
  },
  {
    npmName: "@0xcyrildev/necropsy-linux-x64-musl",
    dir: "linux-x64-musl",
    cargoTarget: "x86_64-unknown-linux-musl",
    os: "linux",
    cpu: "x64",
    rustOs: "linux",
    rustArch: "x86_64",
    libc: "musl",
    runner: "ubuntu-24.04",
    apt: ["musl-tools"],
  },
  {
    npmName: "@0xcyrildev/necropsy-linux-arm64-gnu",
    dir: "linux-arm64-gnu",
    cargoTarget: "aarch64-unknown-linux-gnu",
    os: "linux",
    cpu: "arm64",
    rustOs: "linux",
    rustArch: "aarch64",
    libc: "glibc",
    runner: "ubuntu-24.04",
    // The cross *compiler* is not enough: `ring` (pulled in by rustls) compiles C, and it needs
    // the target's libc headers to do it. Without `libc6-dev-arm64-cross` the build dies on
    // `bits/libc-header-start.h: No such file`, which reads like a linker problem and is not one.
    // qemu-user-static is here so the Verify step can execute the arm64 binary rather than only
    // inspect it -- a header cannot tell a real aarch64 build from a renamed x86_64 one.
    apt: ["gcc-aarch64-linux-gnu", "libc6-dev-arm64-cross", "qemu-user-static"],
    linker: "aarch64-linux-gnu-gcc",
    cc: "aarch64-linux-gnu-gcc",
    ar: "aarch64-linux-gnu-ar",
    // `-static` is the name Ubuntu's qemu-user-static installs: /usr/bin/qemu-aarch64-static.
    // The unsuffixed binary belongs to qemu-user and is not what a static runner image provides --
    // asking for it produced `spawnSync qemu-aarch64 ENOENT` in the second rehearsal.
    qemu: "qemu-aarch64-static -L /usr/aarch64-linux-gnu",
  },
  {
    npmName: "@0xcyrildev/necropsy-darwin-arm64",
    dir: "darwin-arm64",
    cargoTarget: "aarch64-apple-darwin",
    os: "darwin",
    cpu: "arm64",
    rustOs: "macos",
    rustArch: "aarch64",
    runner: "macos-latest",
    system: true,
  },
  {
    npmName: "@0xcyrildev/necropsy-darwin-x64",
    dir: "darwin-x64",
    cargoTarget: "x86_64-apple-darwin",
    os: "darwin",
    cpu: "x64",
    rustOs: "macos",
    rustArch: "x86_64",
    runner: "macos-latest",
    // Cross-compiled from the arm64 runner: the macOS SDK is universal, so an Intel binary
    // does not need an Intel machine. Intel runners are the thing that gets deprecated.
  },
];

// Windows is deliberately absent. `x86_64-pc-windows-msvc` would build on a Windows runner,
// but the offline test suite spawns `necropsy` through assert_cmd with POSIX assumptions about
// paths and port 1, and nothing here has ever been run on Windows. A package that ships an
// unverified binary is worse than a package that says "not this platform yet".
export const UNSUPPORTED = ["win32"];

export const CRATE_NAME = "necropsy";
export const SCOPE = "@0xcyrildev";
export const CLI_PACKAGE = `${SCOPE}/necropsy`;
