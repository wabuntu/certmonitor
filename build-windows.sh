#!/usr/bin/env bash
# Cross-compiles the Windows binary and zip package, locally (no CI).
# Requires the mingw-w64 toolchain (`sudo apt install mingw-w64`) and the
# x86_64-pc-windows-gnu rustup target (added automatically below if missing).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

WIN_TARGET=x86_64-pc-windows-gnu
VERSION=$(grep '^version' Cargo.toml | head -1 | cut -d'"' -f2)

if ! rustup target list --installed | grep -q "^${WIN_TARGET}\$"; then
    rustup target add "$WIN_TARGET"
fi
cargo build --release --target "$WIN_TARGET"

mkdir -p binaries
STAGE=$(mktemp -d)
cp "target/$WIN_TARGET/release/certmonitor.exe" "$STAGE/"
cp README.md "$STAGE/" 2>/dev/null || true
(cd "$STAGE" && zip -q "certmonitor-$VERSION-windows-x86_64.zip" certmonitor.exe README.md 2>/dev/null \
    || zip -q "certmonitor-$VERSION-windows-x86_64.zip" certmonitor.exe)
mv "$STAGE/certmonitor-$VERSION-windows-x86_64.zip" binaries/
cp "target/$WIN_TARGET/release/certmonitor.exe" "binaries/certmonitor-$VERSION-windows-x86_64.exe"
rm -rf "$STAGE"

# --- drop build cache, keeping only the outputs in binaries/ ---
dir="target/$WIN_TARGET/release"
rm -rf "$dir"/deps "$dir"/build "$dir"/.fingerprint "$dir"/incremental \
    "$dir"/examples "$dir"/*.d "$dir"/.cargo-artifact-lock \
    "$dir"/.cargo-build-lock "$dir"/.cargo-lock

echo
echo "Windows zip:         $(pwd)/binaries/certmonitor-$VERSION-windows-x86_64.zip"
echo "Windows exe:         $(pwd)/binaries/certmonitor-$VERSION-windows-x86_64.exe"
