#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
#
# STEP 1 of the Qubes build: fetch everything the offline build needs.
#
# Runs in a DISPOSABLE qube that has network (netvm = sys-firewall or
# sys-whonix). It never runs in the build template. Its output is one
# directory, checked here and checked AGAIN in the build qube, handed over
# with qvm-copy:
#
#   bundle/
#     OTRv4Plus/            the repository at the tag you verified
#     wheels/               Python wheels, each matching lock-cp313.sha256
#     cargo-vendor/         every Rust crate in Rust/Cargo.lock, vendored
#     rust/                 the official Rust toolchain tarball + signature
#
#   qubes/packaging/fetch-sources.sh --tag android-v0.7.0-experimental.rc.63
#   qvm-copy bundle            # -> otr-build: ~/QubesIncoming/<this-dvm>/
#
# Trust anchors, all checked here and none fetched blind:
#   * the git tag: compare `git rev-parse <tag>^{commit}` with the commit
#     published in the release notes, out of band
#   * Python wheels: SHA-256 pinned in lock-cp313.sha256 (in the repo)
#   * crates: SHA-256 in Rust/Cargo.lock, which cargo vendor checks
#   * Rust toolchain: the Rust project's release signing key
#     (85AB96E6FA1BE5FE), fingerprint compared by hand the first time
set -euo pipefail

TAG=""
REPO_URL="https://github.com/muc111/OTRv4Plus.git"
RUST_VERSION="1.91.0"
OUT="$PWD/bundle"
while [ $# -gt 0 ]; do
    case "$1" in
        --tag) TAG="$2"; shift 2 ;;
        --repo) REPO_URL="$2"; shift 2 ;;
        --rust) RUST_VERSION="$2"; shift 2 ;;
        --out) OUT="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
[ -n "$TAG" ] || { echo "--tag is required (a release tag you have checked)" >&2; exit 2; }
die() { echo "fetch-sources: $*" >&2; exit 1; }
mkdir -p "$OUT"

# 1. The source, at the tag.
git clone --quiet --branch "$TAG" --depth 1 "$REPO_URL" "$OUT/OTRv4Plus"
echo "source: $TAG = $(git -C "$OUT/OTRv4Plus" rev-parse HEAD)"
echo "        compare this commit with the release notes before going on"

# 2. Python wheels for the template's Python (3.13), exactly as pinned.
#    --no-deps: the lock IS the dependency list. slixmpp's optional DNS
#    chain (aiodns, pycares, cffi, pycparser) is deliberately absent.
LOCK="$OUT/OTRv4Plus/qubes/packaging/lock-cp313.sha256"
mkdir -p "$OUT/wheels"
python3 -m pip download --quiet --disable-pip-version-check --no-deps \
    --only-binary=:all: --python-version 3.13 --implementation cp \
    --platform manylinux2014_x86_64 --platform manylinux_2_17_x86_64 --platform any \
    --dest "$OUT/wheels" \
    "slixmpp==1.17.0" "PySocks==1.7.1" "pyasn1==0.6.4" "pyasn1-modules==0.4.2"
python3 -m pip download --quiet --disable-pip-version-check --no-deps \
    --no-binary=:all: --dest "$OUT/wheels" "opuslib==3.0.1"
( cd "$OUT/wheels" && sha256sum --strict --check "$LOCK" ) || die "a wheel does not match the lock"

# 3. The Rust toolchain, signed by the Rust project. Verified before it is
#    used here (for cargo vendor) and again by the build qube.
mkdir -p "$OUT/rust"
base="rust-$RUST_VERSION-x86_64-unknown-linux-gnu.tar.xz"
curl --proto '=https' --tlsv1.2 -fsSLo "$OUT/rust/$base" "https://static.rust-lang.org/dist/$base"
curl --proto '=https' --tlsv1.2 -fsSLo "$OUT/rust/$base.asc" "https://static.rust-lang.org/dist/$base.asc"
curl --proto '=https' --tlsv1.2 -fsSLo "$OUT/rust/rust-key.gpg.ascii" "https://static.rust-lang.org/rust-key.gpg.ascii"
export GNUPGHOME="$(mktemp -d)"
gpg --quiet --import "$OUT/rust/rust-key.gpg.ascii"
gpg --fingerprint 85AB96E6FA1BE5FE
gpg --verify "$OUT/rust/$base.asc" "$OUT/rust/$base" || die "Rust toolchain signature does not verify"
echo "rust: signature OK -- check the fingerprint above against https://forge.rust-lang.org/infra/other-installation-methods.html"

tmp="$(mktemp -d)"
tar -xJf "$OUT/rust/$base" -C "$tmp"
"$tmp"/rust-*/install.sh --prefix="$HOME/.local/rust" --disable-ldconfig >/dev/null
export PATH="$HOME/.local/rust/bin:$PATH"

# 4. Rust crates, vendored. cargo checks each against Cargo.lock's checksum.
( cd "$OUT/OTRv4Plus/Rust" && cargo vendor --locked --quiet "$OUT/cargo-vendor" \
      > "$OUT/cargo-vendor.config.toml" ) || die "cargo vendor failed"

# 5. Maturin, the wheel builder, pinned like the rest.
python3 -m pip download --quiet --disable-pip-version-check --no-deps \
    --only-binary=:all: --python-version 3.13 --implementation cp \
    --platform manylinux2014_x86_64 --platform manylinux_2_17_x86_64 \
    --dest "$OUT/wheels-build" "maturin==1.13.3"
# The manifest catches damage in transit. It is made in this (untrusted,
# networked) qube, so it is NOT a trust anchor: the build qube re-checks the
# lock, the Rust signature and the crate checksums itself, offline.
( cd "$OUT" && find . -type f ! -name SHA256SUMS | LC_ALL=C sort | xargs sha256sum ) > "$OUT/SHA256SUMS"
echo "bundle ready: $OUT"
echo "next: qvm-copy $OUT   (to the build qube)"
