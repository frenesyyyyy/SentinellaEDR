# Development

## Linux prerequisites

Use a disposable Linux x86_64 VM for sensor work. Install Rust stable, Node.js 22,
and the [Tauri Linux prerequisites](https://v2.tauri.app/start/prerequisites/).
For Debian/Ubuntu, the build also needs Clang/LLVM and libelf:

```sh
sudo apt-get update
sudo apt-get install -y build-essential pkg-config clang llvm libelf-dev curl zstd \
  libssl-dev libwebkit2gtk-4.1-dev libayatana-appindicator3-dev \
  librsvg2-dev libxdo-dev patchelf
rustup toolchain install stable --component rustfmt --component clippy
rustup toolchain install nightly-2026-05-20 --component rust-src --profile minimal
bash scripts/install-bpf-linker.sh
cargo xtask build-ebpf
cd apps/desktop
npm ci
npm run build
cd ../..
```

`xtask` places the object under `target/bpfel-unknown-none/debug/`. The desktop
embeds that file at compile time. For a release build, build the eBPF object with
`cargo xtask build-ebpf --release` first.

The installer downloads a version-pinned Linux x86_64 release of
[bpf-linker](https://github.com/aya-rs/bpf-linker#installation) and checks its SHA-256.
It needs `curl`, `zstd` and `tar`, and installs under `~/.cargo/bin` (on PATH with
a standard rustup setup). This avoids depending on the runner's system LLVM ABI.

## Checks

```sh
cargo fmt --all -- --check
cargo +stable fmt --manifest-path crates/sentinella-ebpf/Cargo.toml -- --check
cargo clippy --workspace --all-targets
cargo test --workspace
cd apps/desktop
npm run build
```

The desktop checks require the real compiled eBPF object and Linux GUI development
libraries, even though unit tests do not attach probes. Clippy currently reports
existing warnings; it is not configured to treat all warnings as errors.

## Manual runtime validation (not performed by CI)

1. Snapshot a disposable VM. Read the unconditional restricted-name policy before
   starting the sensor; Learning mode does not disable it.
2. Launch the built desktop binary with the required privileges in that VM.
3. Check ordinary exec events, batching counts and the distinction between scan
   count and displayed rows. Record the kernel, toolchain and commit used.
4. Exercise start/stop repeatedly, including an idle interval. Check for a stalled
   stop or stale status and verify that probes detach when the process exits.
5. Test mode persistence and baseline write failures using synthetic destinations.
6. Validate signal outcomes and alert limits with purpose-built fixtures in the VM,
   then measure capture loss and CPU under a controlled workload.

Do not interpret a frontend build or unit-test result as evidence for these runtime
properties. The legacy `check_ebpf` helper loads programs but does not make a
reliable automated runtime test: it prints failures rather than propagating all
of them through its exit status.
