#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
#
# STEP 2 of the Qubes build: the Rust core, OFFLINE, reproducibly.
#
# Runs in the build qube (netvm = none) on the bundle fetch-sources.sh made.
#
#   qubes/packaging/build-core.sh --bundle ~/QubesIncoming/<dvm>/bundle
#
# Reproducible -- measured, not assumed (FEASIBILITY_REPORT.md, Appendix B):
#   * --remap-path-prefix removes every build-machine path (without it the
#     library carried 117 of them, in panic locations);
#   * symbols stripped, no debug info;
#   * built at the FIXED path /build/OTRv4Plus: maturin's SBOM records the
#     source directory, which otherwise is the only difference between two
#     builds. With it, two clean builds in different qubes give the same
#     otrv4_core library byte for byte.
set -euo pipefail

BUNDLE=""
while [ $# -gt 0 ]; do
    case "$1" in
        --bundle) BUNDLE="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
[ -d "$BUNDLE" ] || { echo "--bundle DIR is required" >&2; exit 2; }
die() { echo "build-core: $*" >&2; exit 1; }

# Offline by construction, and checked: this qube must have no network.
if getent hosts static.rust-lang.org >/dev/null 2>&1 || ip route | grep -q default; then
    die "this qube has network; build only in a qube with netvm = none"
fi

# 1. The bundle arrived intact (manifest from the disposable qube) -- and the
#    trust anchors are checked again HERE, offline, not taken from there:
#    the Rust project's signature on the toolchain (crates are checked by
#    cargo against Cargo.lock; wheels by build-deb.sh against the lock).
( cd "$BUNDLE" && sha256sum --strict --quiet --check SHA256SUMS ) \
    || die "the bundle does not match its manifest"
export GNUPGHOME="$(mktemp -d)"
gpg --quiet --import "$BUNDLE"/rust/rust-key.gpg.ascii
gpg --with-colons --fingerprint 85AB96E6FA1BE5FE | grep -q '^fpr:.*85AB96E6FA1BE5FE:$' \
    || die "the Rust signing key is not the one pinned here"
gpg --quiet --verify "$BUNDLE"/rust/rust-*.tar.xz.asc "$BUNDLE"/rust/rust-*-x86_64-unknown-linux-gnu.tar.xz \
    || die "the Rust toolchain signature does not verify"

# 2. Rust, from the verified tarball, into the user's home (no root needed).
if ! command -v cargo >/dev/null; then
    tmp="$(mktemp -d)"
    tar -xJf "$BUNDLE"/rust/rust-*-x86_64-unknown-linux-gnu.tar.xz -C "$tmp"
    "$tmp"/rust-*/install.sh --prefix="$HOME/.local/rust" --disable-ldconfig >/dev/null
    export PATH="$HOME/.local/rust/bin:$PATH"
fi
cargo --version

# 3. The source at the fixed path, with vendored crates and no network.
sudo mkdir -p /build && sudo chown "$(id -u):$(id -g)" /build
rm -rf /build/OTRv4Plus
cp -a "$BUNDLE/OTRv4Plus" /build/OTRv4Plus
mkdir -p /build/OTRv4Plus/Rust/.cargo
sed "s|directory = \".*\"|directory = \"$BUNDLE/cargo-vendor\"|" \
    "$BUNDLE/cargo-vendor.config.toml" >> /build/OTRv4Plus/Rust/.cargo/config.toml
export CARGO_NET_OFFLINE=true

python3 -m venv /build/venv
/build/venv/bin/pip install --quiet --no-index --find-links "$BUNDLE/wheels-build" maturin==1.13.3

# 4. Build. `mls` is the secure-groups feature; no test-only feature is ever
#    passed (build-deb.sh refuses a core that exposes one).
export SOURCE_DATE_EPOCH="$(git -C /build/OTRv4Plus log -1 --format=%ct 2>/dev/null || echo 1791763200)"
export RUSTFLAGS="--remap-path-prefix=$HOME/.cargo=/cargo --remap-path-prefix=$BUNDLE/cargo-vendor=/vendor --remap-path-prefix=/build=/build -C debuginfo=0 -C strip=symbols"
( cd /build/OTRv4Plus/Rust && /build/venv/bin/maturin build --release --locked \
      --features mls --out /build/wheel )
sha256sum /build/wheel/otrv4_core-*.whl
unzip -p /build/wheel/otrv4_core-*.whl 'otrv4_core/*.so' | sha256sum | sed 's/-$/otrv4_core.abi3.so/'
echo "next: qubes/packaging/build-deb.sh --wheels $BUNDLE/wheels --core-wheel /build/wheel/otrv4_core-*.whl"
