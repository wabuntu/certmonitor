#!/usr/bin/env bash
# Builds the native Linux binary, a .deb, and a .rpm, and drops all three
# (plus the raw binary) into binaries/. Requires cargo-deb and rpmbuild.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

VERSION=$(grep '^version' Cargo.toml | head -1 | cut -d'"' -f2)
mkdir -p binaries

# --- native glibc release binary ---
cargo build --release
cp target/release/certmonitor "binaries/certmonitor-$VERSION-linux-x86_64"

# --- .deb, via cargo-deb ---
if ! command -v cargo-deb >/dev/null; then
    cargo install cargo-deb
fi
cargo deb
cp target/debian/*.deb binaries/

# --- .rpm, via rpmbuild ---
RPMTOP="$(pwd)/target/release/rpmbuild"
mkdir -p "$RPMTOP"/{SOURCES,SPECS,BUILD,RPMS,SRPMS,BUILDROOT}
STAGE=$(mktemp -d)
mkdir -p "$STAGE/certmonitor-$VERSION/usr/bin"
cp target/release/certmonitor "$STAGE/certmonitor-$VERSION/usr/bin/"
tar czf "$RPMTOP/SOURCES/certmonitor-$VERSION.tar.gz" -C "$STAGE" "certmonitor-$VERSION"
rm -rf "$STAGE"
sed -e "s/@@VERSION@@/$VERSION/" -e "s/@@RELEASE@@/1/" .rpm/certmonitor.spec > "$RPMTOP/SPECS/certmonitor.spec"
rpmbuild --define "_topdir $RPMTOP" -bb "$RPMTOP/SPECS/certmonitor.spec"
cp "$RPMTOP"/RPMS/x86_64/*.rpm binaries/

# --- drop build caches, keeping only what this script produces ---
rm -rf target/debug target/release/deps target/release/build \
    target/release/.fingerprint target/release/incremental target/release/examples

echo
echo "Binary: $(pwd)/binaries/certmonitor-$VERSION-linux-x86_64"
echo "Deb:    $(pwd)/binaries/$(basename target/debian/*.deb 2>/dev/null || echo '(see target/debian)')"
echo "Rpm:    $(pwd)/binaries/$(basename "$RPMTOP"/RPMS/x86_64/*.rpm)"
