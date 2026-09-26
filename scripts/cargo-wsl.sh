#!/bin/sh
# Run cargo inside WSL with the build output on the Linux filesystem (never on the Windows drive).
# Use from the repo root, inside WSL:   sh scripts/cargo-wsl.sh build --release
# From Windows:                         wsl.exe -e sh -c 'cd <repo path under /mnt/c> && sh scripts/cargo-wsl.sh test'
set -eu
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/zsa/target}"
exec "${CARGO:-$HOME/.cargo/bin/cargo}" "$@"
