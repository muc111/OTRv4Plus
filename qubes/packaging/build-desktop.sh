#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
#
# Build the desktop GUI (desktop/, Compose for Desktop) as otrv4plus-desktop,
# OFFLINE, in the build qube.
#
#   qubes/packaging/build-desktop.sh --gradle-cache DIR [--out DIR] [--version X]
#
# DIR is the read-only Gradle dependency cache fetch-sources.sh made in the
# disposable qube (GRADLE_RO_DEP_CACHE: Gradle's own mechanism for a cache
# that is copied in, not downloaded). Every jar in it is checked against
# desktop/gradle/verification-metadata.xml (SHA-256, committed) before it
# is used -- `--dependency-verification strict`. Nothing is fetched.
#
# What the package holds, and what it does not:
#   /opt/otrv4plus/desktop/lib     the GUI's jars (Compose, Skia bindings,
#                                  kotlinx) -- run on the template's JRE
#   /opt/otrv4plus/desktop/native  libskiko, extracted here at build time so
#                                  nothing executable is unpacked into $HOME
#   /usr/bin/otrv4plus-desktop     launcher; software rendering (an AppVM has
#                                  no GPU)
#   NO cryptography and NO keys: the GUI starts the engine
#   (/usr/lib/otrv4plus/otrv4plus-engine, package otrv4plus) as a child
#   process and talks to it in JSON lines. Every key stays in that process's
#   Rust core.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
OUT="$PWD/dist"
CACHE=""
VERSION=""
while [ $# -gt 0 ]; do
    case "$1" in
        --gradle-cache) CACHE="$2"; shift 2 ;;
        --out) OUT="$2"; shift 2 ;;
        --version) VERSION="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
die() { echo "build-desktop: $*" >&2; exit 1; }
command -v gradle >/dev/null || die "gradle not found (the bundle's gradle-*-bin.zip, unpacked)"
command -v java >/dev/null || die "a JDK 21 is required"
[ -z "$CACHE" ] || [ -d "$CACHE" ] || die "--gradle-cache: no such directory"
# The desktop app's own version (VERSIONING.md), not the Rust core's.
[ -n "$VERSION" ] || VERSION="$(sed -n 's/^version *= *"\(.*\)"/\1/p' "$REPO/desktop/build.gradle.kts" | head -1)"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$REPO" log -1 --format=%ct 2>/dev/null || echo 1791763200)}"
umask 022

# 1. Compile and lay out the jars, offline, every input verified. Without the
#    checksum file Gradle would verify nothing, so its absence stops here.
[ -f "$REPO/desktop/gradle/verification-metadata.xml" ] \
    || die "desktop/gradle/verification-metadata.xml is missing: commit the one CI writes (desktop.yml)"
[ -n "$CACHE" ] && export GRADLE_RO_DEP_CACHE="$CACHE"
GRADLE_USER_HOME="$(mktemp -d)"
export GRADLE_USER_HOME
gradle --no-daemon --offline --dependency-verification strict -q \
    -p "$REPO/desktop" clean desktopLib
LIBDIR="$REPO/desktop/build/desktop-lib"
ls "$LIBDIR"/*.jar >/dev/null 2>&1 || die "no jars were produced"

# 2. Stage.
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE" "$GRADLE_USER_HOME"' EXIT
ROOT="$STAGE/root"
mkdir -p "$ROOT/DEBIAN" "$ROOT/opt/otrv4plus/desktop/lib" "$ROOT/opt/otrv4plus/desktop/native" \
         "$ROOT/usr/bin" "$ROOT/usr/share/applications" "$ROOT/usr/share/doc/otrv4plus-desktop"
cp "$LIBDIR"/*.jar "$ROOT/opt/otrv4plus/desktop/lib/"
skiko="$(ls "$ROOT"/opt/otrv4plus/desktop/lib/skiko-awt-runtime-linux-x64-*.jar | head -1)"
[ -f "$skiko" ] || die "no skiko runtime for linux-x64 among the jars"
unzip -q -j -o "$skiko" 'libskiko-linux-x64.so' -d "$ROOT/opt/otrv4plus/desktop/native"

cat > "$ROOT/usr/bin/otrv4plus-desktop" <<'EOF'
#!/bin/sh
# OTRv4Plus desktop. The window holds no keys; it starts the engine
# (/usr/lib/otrv4plus/otrv4plus-engine) and talks to it over a pipe.
export OTRV4PLUS_ENGINE="${OTRV4PLUS_ENGINE:-/usr/lib/otrv4plus/otrv4plus-engine}"
exec java -Dskiko.renderApi=SOFTWARE \
     -Dskiko.library.path=/opt/otrv4plus/desktop/native \
     -Djava.io.tmpdir="${XDG_RUNTIME_DIR:-/tmp}" \
     -XX:+DisableAttachMechanism -Xmx512m \
     -cp '/opt/otrv4plus/desktop/lib/*' org.otrv4plus.desktop.MainKt "$@"
EOF
cat > "$ROOT/usr/share/applications/otrv4plus-desktop.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Name=Off The Record v4 Plus
GenericName=Post-quantum encrypted chat
Comment=XMPP over I2P with OTRv4+ (X448 + ML-KEM-1024, ML-DSA-87)
Exec=otrv4plus-desktop
Icon=otrv4plus
Terminal=false
Categories=Network;InstantMessaging;
EOF
cp "$REPO/LICENSE" "$ROOT/usr/share/doc/otrv4plus-desktop/copyright"

cat > "$ROOT/DEBIAN/control" <<EOF
Package: otrv4plus-desktop
Version: $VERSION
Architecture: amd64
Maintainer: muc111 <noreply@otrv4plus.invalid>
Installed-Size: $(du -sk --apparent-size "$ROOT" | cut -f1)
Depends: otrv4plus (= $VERSION), openjdk-21-jre
Recommends: libnotify-bin
Section: net
Priority: optional
Homepage: https://github.com/muc111/OTRv4Plus
Description: OTRv4Plus desktop app (Compose), the Android app's look on Linux
 A window for the OTRv4Plus engine: chats, contacts, rooms and encrypted
 groups, verification, files and calls. It holds no keys and does no
 cryptography; it runs the engine from the otrv4plus package as a separate
 process, where the Rust core keeps every key.
EOF
( cd "$ROOT" && find . -path ./DEBIAN -prune -o -type f -print | LC_ALL=C sort \
    | sed 's|^\./||' | xargs md5sum ) > "$ROOT/DEBIAN/md5sums"
find "$ROOT" -type d -exec chmod 0755 {} +
find "$ROOT" -type f -exec chmod 0644 {} +
chmod 0755 "$ROOT/usr/bin/otrv4plus-desktop" "$ROOT"/opt/otrv4plus/desktop/native/*.so
find "$ROOT" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +

mkdir -p "$OUT"
DEB="$OUT/otrv4plus-desktop_${VERSION}_amd64.deb"
dpkg-deb --root-owner-group -Zxz --build "$ROOT" "$DEB" >/dev/null
( cd "$OUT" && sha256sum "$(basename "$DEB")" > "$(basename "$DEB").sha256" )
echo "built $DEB"
cat "$DEB.sha256"
