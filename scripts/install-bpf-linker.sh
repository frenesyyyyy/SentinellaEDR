#!/usr/bin/env bash
set -euo pipefail

# Use the upstream Linux binary to avoid coupling the linker build to system LLVM.
archive="$(mktemp)"
trap 'rm -f "$archive"' EXIT
curl --fail --location --silent --show-error \
  https://github.com/aya-rs/bpf-linker/releases/download/v0.11.1/bpf-linker-x86_64-unknown-linux-musl.tar.zst \
  --output "$archive"
printf '%s  %s\n' e058a6aecc9e65fa4c977b298a8e4b738424d7629769fd352eed409fb57e16e8 "$archive" | sha256sum --check
mkdir -p "$HOME/.cargo/bin"
tar --zstd -xf "$archive" -C "$HOME/.cargo/bin"
"$HOME/.cargo/bin/bpf-linker" --version
