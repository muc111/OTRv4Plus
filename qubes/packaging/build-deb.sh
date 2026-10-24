#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
#
# Build the OTRv4Plus terminal client as a Debian package, OFFLINE.
#
# Runs in the build qube (netvm=none). Every input is a local file whose
# SHA-256 is checked against a lock committed to the repository; nothing is
# fetched. Inputs come from fetch-sources.sh, run in a disposable networked
# qube and handed over with qvm-copy (see docs/FEASIBILITY_REPORT.md §5).
#
#   qubes/packaging/build-deb.sh --wheels DIR --core-wheel FILE \
#       [--pyver 3.13] [--out DIR] [--version X.Y.Z]
#
# Reproducible: fixed SOURCE_DATE_EPOCH, normalised mtimes and permissions,
# hash-checked bytecode, root-owned entries. Two builds of the same inputs
# give the same .deb (checked in the report, Appendix B).
#
# What goes in, and nothing else:
#   /opt/otrv4plus/app   the client's Python modules (+ .pyc), and the nine
#                        android_bridge modules Termux/Linux use
#   /opt/otrv4plus/lib   slixmpp, PySocks, pyasn1, pyasn1-modules, opuslib,
#                        otrv4_core (the Rust core) -- and NOT aiodns,
#                        pycares, cffi or pycparser: no C DNS resolver; an
#                        I2P-only qube makes no DNS queries (the APK ships
#                        without them too)
#   /usr/bin/otrv4plus   launcher; reads ~/.config/otrv4plus/args
#   desktop entry + icon (the Android launcher icon)
#   otrv4plus-sam-proxy  systemd unit, the chat qube's end of the qrexec SAM
#                        relay; starts only where `qvm-service otrv4plus-sam-proxy`
#                        is on (ConditionPathExists=/run/qubes-service/...)
#
# and a second, separate package for the sys-i2p TEMPLATE:
#   otrv4plus-i2p-relay  the relay's service end, /etc/qubes-rpc/otrv4plus.SamUdp
#                        (no client, no Python libraries, no keys)
#
# --stage DIR stops after laying out the client's files in DIR (no DEBIAN/):
# the RPM spec (otrv4plus.spec) installs from that, so both formats ship the
# same bytes.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
PYVER="3.13"
OUT="$PWD/dist"
WHEELS=""
CORE=""
VERSION=""
STAGE_ONLY=""

while [ $# -gt 0 ]; do
    case "$1" in
        --wheels) WHEELS="$2"; shift 2 ;;
        --core-wheel) CORE="$2"; shift 2 ;;
        --pyver) PYVER="$2"; shift 2 ;;
        --out) OUT="$2"; shift 2 ;;
        --version) VERSION="$2"; shift 2 ;;
        --stage) STAGE_ONLY="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
[ -d "$WHEELS" ] || { echo "--wheels DIR is required" >&2; exit 2; }
[ -f "$CORE" ] || { echo "--core-wheel FILE is required" >&2; exit 2; }

die() { echo "build-deb: $*" >&2; exit 1; }
PY="python$PYVER"
command -v "$PY" >/dev/null || die "$PY not found (the package targets Python $PYVER)"
[ -n "$STAGE_ONLY" ] || command -v dpkg-deb >/dev/null || die "dpkg-deb not found"

# 1. Every input is the one the lock names. A file that is not in the lock,
#    or whose hash differs, stops the build.
LOCK="$HERE/lock-cp${PYVER/./}.sha256"
[ -f "$LOCK" ] || die "no lock for Python $PYVER ($LOCK)"
( cd "$WHEELS" && sha256sum --strict --check "$LOCK" ) || die "an input does not match $LOCK"

if [ -z "$VERSION" ]; then
    VERSION="$(sed -n 's/^version *= *"\(.*\)"/\1/p' "$REPO/Rust/Cargo.toml" | head -1)"
fi
[ -n "$VERSION" ] || die "could not read the version"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$REPO" log -1 --format=%ct 2>/dev/null || echo 1791763200)}"
umask 022

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
ROOT="$STAGE/root"
APP="$ROOT/opt/otrv4plus/app"
LIB="$ROOT/opt/otrv4plus/lib"
mkdir -p "$APP/android_bridge" "$LIB" "$ROOT/usr/bin" "$ROOT/DEBIAN" \
         "$ROOT/usr/share/applications" "$ROOT/usr/share/icons/hicolor/192x192/apps" \
         "$ROOT/usr/share/doc/otrv4plus"

# 2. The client.
cp "$REPO"/client/otrv4_.py "$REPO"/client/otrv4plus.py "$REPO"/client/otrv4plus_*.py "$APP/"
rm -f "$APP/otrv4plus_tui.py.orig"
# The whole engine package: the terminal client uses nine of these modules;
# the desktop GUI's engine process (desktop_bridge) drives OtrApp and the
# connection controller exactly as the Android app does, and needs them all.
cp "$REPO"/android_bridge/*.py "$APP/android_bridge/"
mkdir -p "$APP/desktop_bridge"
cp "$REPO"/desktop_bridge/*.py "$APP/desktop_bridge/"
cp "$REPO/client/i2p_hosts.defaults" "$APP/" 2>/dev/null || true

# 3. Its libraries, from the checked files only (no index, no dependencies
#    resolved here: the lock is the dependency list).
"$PY" -m pip install --quiet --disable-pip-version-check --no-index --no-deps \
    --no-compile --target "$LIB" \
    "$WHEELS"/slixmpp-*.whl "$WHEELS"/PySocks-*.whl \
    "$WHEELS"/pyasn1-*.whl "$WHEELS"/pyasn1_modules-*.whl "$CORE"
# opuslib is published as source only and is pure Python: its package
# directory is all that is needed.
tar -xzf "$WHEELS"/opuslib-*.tar.gz -C "$STAGE"
cp -r "$STAGE"/opuslib-*/opuslib "$LIB/"
rm -rf "$LIB"/bin
find "$LIB" -name "__pycache__" -prune -exec rm -rf {} +
"$PY" - "$LIB" <<'EOF'
import os, sys
# A forbidden dependency must not ride in through a wheel's own metadata.
lib = sys.argv[1]
bad = [n for n in os.listdir(lib) if n.split("-")[0].lower() in ("aiodns", "pycares", "cffi", "pycparser", "_cffi_backend")]
if bad:
    sys.exit("forbidden packages in lib: %s" % bad)
EOF

# Every shipped module must import from the staged tree alone -- a module the
# client loads lazily (android_bridge.identity at sign-in, for one) and the
# package forgot is caught here, not at a user's first login.
( cd "$STAGE" && PYTHONPATH="$LIB:$APP" OTRV4PLUS_NO_VENV=1 \
  OTRV4PLUS_XMPP_STATE_DIR="$STAGE/state" HOME="$STAGE/home" "$PY" -s -B -c '
import importlib, os, sys
app = sys.argv[1]
names = sorted(f[:-3] for f in os.listdir(app) if f.endswith(".py") and f != "otrv4plus_tui.py")
for pkg in ("android_bridge", "desktop_bridge"):
    names += [pkg + "." + f[:-3] for f in sorted(os.listdir(os.path.join(app, pkg)))
              if f.endswith(".py") and f != "__init__.py"]
for n in names:
    importlib.import_module(n)
import otrv4_core
assert hasattr(otrv4_core, "RustMlsClient"), "core built without MLS"
# The raw-key test API (Cargo feature raw-key-test-api) must not ship. Kept
# equal to tests/test_release_guard.py by tests/test_qubes_packaging.py.
RAW_KEY_FUNCTIONS = (
    "py_ring_sign", "mldsa87_keygen", "mldsa87_sign",
    "aes256gcm_encrypt", "aes256gcm_decrypt",
    "mlkem1024_keygen", "mlkem1024_encaps", "mlkem1024_decaps",
    "seal_identity", "unseal_identity", "create_sealed_identity",
)
RAW_KEY_METHODS = {
    "RustDoubleRatchet": ("from_dakeresult",),
    "RustDAKE": ("new_from_bytearrays", "sign_profile_body_and_construct",
                 "ed448_sign_test"),
    "RustVoiceRoot": ("from_initial_agreement", "derive_rekey", "from_bytes"),
}
exposed = [n for n in RAW_KEY_FUNCTIONS if hasattr(otrv4_core, n)]
exposed += ["%s.%s" % (c, m) for c, ms in RAW_KEY_METHODS.items()
            for m in ms if hasattr(getattr(otrv4_core, c), m)]
assert not exposed, "test-only raw-key API in the core: %s" % exposed
print("self-check: %d modules import from the package alone" % len(names))
' "$APP" ) || die "the staged package failed its self-check (above)"

# 4. Bytecode, hash-checked so it does not depend on file times.
"$PY" -m compileall -q --invalidation-mode checked-hash -d /opt/otrv4plus/app "$APP" >/dev/null
"$PY" -m compileall -q --invalidation-mode checked-hash -d /opt/otrv4plus/lib "$LIB" >/dev/null

# 5. Launcher. The system allocator (freed buffers are not pooled), no
#    bytecode written at run time (/opt is read-only in an AppVM anyway),
#    no project .venv lookup.
cat > "$ROOT/usr/bin/otrv4plus" <<'EOF'
#!/bin/sh
# OTRv4Plus terminal client. Arguments: the command line, or else one per
# line from ~/.config/otrv4plus/args (what the desktop entry uses).
export PYTHONPATH=/opt/otrv4plus/lib
export PYTHONMALLOC=malloc
export PYTHONDONTWRITEBYTECODE=1
export OTRV4PLUS_NO_VENV=1
PY=@PY@
if [ "$#" -eq 0 ] && [ -r "$HOME/.config/otrv4plus/args" ]; then
    set --
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in ''|'#'*) ;; *) set -- "$@" "$line" ;; esac
    done < "$HOME/.config/otrv4plus/args"
fi
exec "$PY" -s /opt/otrv4plus/app/otrv4plus_xmpp.py "$@"
EOF
sed -i "s|@PY@|/usr/bin/$PY|" "$ROOT/usr/bin/otrv4plus"
chmod 0755 "$ROOT/usr/bin/otrv4plus"

# The desktop GUI's engine: the same Python and Rust, as a process the GUI
# (package otrv4plus-desktop, a separate JVM) speaks JSON lines to. No key
# ever reaches the GUI's process.
mkdir -p "$ROOT/usr/lib/otrv4plus"
cat > "$ROOT/usr/lib/otrv4plus/otrv4plus-engine" <<'EOF'
#!/bin/sh
# OTRv4Plus engine for the desktop GUI: JSON lines on stdin/stdout.
export PYTHONPATH=/opt/otrv4plus/lib
export PYTHONMALLOC=malloc
export PYTHONDONTWRITEBYTECODE=1
export OTRV4PLUS_NO_VENV=1
cd /opt/otrv4plus/app || exit 1
exec @PY@ -s -m desktop_bridge.host
EOF
sed -i "s|@PY@|/usr/bin/$PY|" "$ROOT/usr/lib/otrv4plus/otrv4plus-engine"

cat > "$ROOT/usr/share/applications/otrv4plus.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Name=Off The Record v4 Plus (terminal)
GenericName=Post-quantum encrypted chat
Comment=XMPP over I2P with OTRv4+ (X448 + ML-KEM-1024, ML-DSA-87)
Exec=xterm -fa Monospace -fs 11 -bg '#1C1B1F' -fg '#E6E1E5' -T 'Off The Record v4 Plus' -e otrv4plus
Icon=otrv4plus
Terminal=false
Categories=Network;InstantMessaging;
EOF
cp "$REPO/android/app/src/main/res/mipmap-xxxhdpi/ic_launcher.png" \
   "$ROOT/usr/share/icons/hicolor/192x192/apps/otrv4plus.png"
cp "$REPO/LICENSE" "$ROOT/usr/share/doc/otrv4plus/copyright"
cp "$REPO/NOTICE" "$ROOT/usr/share/doc/otrv4plus/NOTICE"

# The chat qube's end of the qrexec SAM relay (qubes/relay/).
mkdir -p "$ROOT/usr/lib/otrv4plus" "$ROOT/usr/lib/systemd/system"
sed "1s|.*|#!/usr/bin/$PY -I|" "$REPO/qubes/relay/otrv4plus-qubes-relay" \
    > "$ROOT/usr/lib/otrv4plus/otrv4plus-qubes-relay"
sed "s|@PY@|/usr/bin/$PY|" "$REPO/qubes/relay/otrv4plus-sam-proxy.service" \
    > "$ROOT/usr/lib/systemd/system/otrv4plus-sam-proxy.service"

normalise() {
    find "$1" -type d -exec chmod 0755 {} +
    find "$1" -type f -exec chmod 0644 {} +
    find "$1" \( -path '*/usr/bin/*' -o -path '*/usr/lib/otrv4plus/*' \
                -o -path '*/etc/qubes-rpc/*' -o -name '*.so' \) -type f -exec chmod 0755 {} +
    find "$1" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
}

if [ -n "$STAGE_ONLY" ]; then
    rm -rf "$ROOT/DEBIAN"
    normalise "$ROOT"
    mkdir -p "$STAGE_ONLY"
    cp -a "$ROOT"/. "$STAGE_ONLY"/
    echo "staged into $STAGE_ONLY"
    exit 0
fi

# 6. Control files.
SIZE_KB="$(du -sk --apparent-size "$ROOT" | cut -f1)"
cat > "$ROOT/DEBIAN/control" <<EOF
Package: otrv4plus
Version: $VERSION
Architecture: amd64
Maintainer: muc111 <noreply@otrv4plus.invalid>
Installed-Size: $SIZE_KB
Depends: python$PYVER, libopus0
Recommends: pulseaudio-utils, xterm
Section: net
Priority: optional
Homepage: https://github.com/muc111/OTRv4Plus
Description: OTRv4+ post-quantum encrypted XMPP client (terminal)
 XMPP over I2P with OTRv4+: X448 + ML-KEM-1024 key exchange, ML-DSA-87
 signatures, AES-256-GCM, SMP verification, file transfer, MLS groups.
 Cryptography in the Rust core (otrv4_core). Interoperates with the
 OTRv4Plus Android app and the Termux client.
EOF
( cd "$ROOT" && find . -path ./DEBIAN -prune -o -type f -print | LC_ALL=C sort \
    | sed 's|^\./||' | xargs md5sum ) > "$ROOT/DEBIAN/md5sums"

# 7. Normalise and build.
normalise "$ROOT"
mkdir -p "$OUT"
DEB="$OUT/otrv4plus_${VERSION}_amd64.deb"
dpkg-deb --root-owner-group -Zxz --build "$ROOT" "$DEB" >/dev/null
( cd "$OUT" && sha256sum "$(basename "$DEB")" > "$(basename "$DEB").sha256" )
echo "built $DEB"
cat "$DEB.sha256"

# 8. The sys-i2p template's package: the relay's service end, nothing else.
R="$STAGE/relay"
mkdir -p "$R/DEBIAN" "$R/usr/lib/otrv4plus" "$R/etc/qubes-rpc" \
         "$R/usr/share/doc/otrv4plus-i2p-relay"
sed "1s|.*|#!/usr/bin/$PY -I|" "$REPO/qubes/relay/otrv4plus-qubes-relay" \
    > "$R/usr/lib/otrv4plus/otrv4plus-qubes-relay"
cp "$REPO/qubes/relay/otrv4plus.SamUdp" "$R/etc/qubes-rpc/"
cp "$REPO/LICENSE" "$R/usr/share/doc/otrv4plus-i2p-relay/copyright"
cat > "$R/DEBIAN/control" <<EOF
Package: otrv4plus-i2p-relay
Version: $VERSION
Architecture: all
Maintainer: muc111 <noreply@otrv4plus.invalid>
Installed-Size: $(du -sk --apparent-size "$R" | cut -f1)
Depends: python$PYVER, i2pd
Section: net
Priority: optional
Homepage: https://github.com/muc111/OTRv4Plus
Description: OTRv4Plus: I2P SAM datagrams for a network-less Qubes qube
 The qrexec service otrv4plus.SamUdp, for the template of the qube that
 runs i2pd (sys-i2p). It lets a chat qube with no network make OTRv4Plus
 voice calls through this qube's I2P router. Loopback only.
EOF
( cd "$R" && find . -path ./DEBIAN -prune -o -type f -print | LC_ALL=C sort \
    | sed 's|^\./||' | xargs md5sum ) > "$R/DEBIAN/md5sums"
normalise "$R"
RDEB="$OUT/otrv4plus-i2p-relay_${VERSION}_all.deb"
dpkg-deb --root-owner-group -Zxz --build "$R" "$RDEB" >/dev/null
( cd "$OUT" && sha256sum "$(basename "$RDEB")" > "$(basename "$RDEB").sha256" )
echo "built $RDEB"
cat "$RDEB.sha256"
