#!/usr/bin/env bash
set -euo pipefail

cargo build --release --locked
if [ -f target/release/interenv.exe ]; then
  BIN_PATH="target/release/interenv.exe"
else
  BIN_PATH="target/release/interenv"
fi

HASH1=$(sha256sum "$BIN_PATH" | awk '{print $1}')
echo "First build: $HASH1"

cargo clean -p interenv
cargo build --release --locked

HASH2=$(sha256sum "$BIN_PATH" | awk '{print $1}')
echo "Second build: $HASH2"

if [ "$HASH1" != "$HASH2" ]; then
  echo "Build is NOT reproducible" >&2
  exit 1
fi

echo "Build is reproducible"
