#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
#
# Build and install the OTRv4+ desktop app on Ubuntu 24.04+ / Debian 13+,
# from the source in this clone. Nothing prebuilt is downloaded: the Rust
# core, the Python engine and the app are all built here, on your machine.
#
# Run from a clone (the README has the one-liner that clones and runs this):
#   bash desktop/install.sh            # install, then start the app
#   bash desktop/install.sh --no-run   # install only
#
# Re-running it updates: it pulls, rebuilds and keeps your keys and settings
# (they live in ~/.otrv4plus, outside the repository).
#
# What it changes outside this clone:
#   - apt packages: git python3 python3-venv build-essential curl libopus0
#     pulseaudio-utils openjdk-21-jdk i2pd (asks for your sudo password)
#   - Rust from rustup in ~/.cargo, only if cargo is missing
#   - ~/.local/bin/otrv4plus-desktop, a menu entry in
#     ~/.local/share/applications/otrv4plus-desktop.desktop and its icon in
#     ~/.local/share/icons/hicolor/192x192/apps/otrv4plus.png
set -euo pipefail

RUN=1
for arg in "$@"; do
    case "$arg" in
        --no-run) RUN=0 ;;
        -h|--help) sed -n '2,21p' "$0"; exit 0 ;;
        *) echo "unknown option: $arg" >&2; exit 2 ;;
    esac
done

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
step() { printf '\n==> %s\n' "$*"; }
die() { printf '\nINSTALL FAILED: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -ne 0 ] || die "run this as your own user, not root (it asks for sudo when it needs it)"
command -v apt-get >/dev/null || die "this script is for Ubuntu/Debian (apt). Other systems: desktop/README.md"

step "Installing system packages"
sudo apt-get update -qq
sudo apt-get install -y git python3 python3-venv build-essential curl \
    libopus0 pulseaudio-utils openjdk-21-jdk i2pd

step "Checking Rust"
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
if ! command -v cargo >/dev/null; then
    # The distributions' rustc is too old for the core; rustup's is not.
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    . "$HOME/.cargo/env"
fi
cargo --version

step "Updating the source"
cd "$REPO"
if [ -z "$(git status --porcelain --untracked-files=no)" ]; then
    git pull --ff-only || echo "(could not pull; building what is here)"
else
    echo "(local changes in $REPO: not pulling; building what is here)"
fi
git log -1 --format='building %h from %ad'

step "Building the Rust core and the engine (ends with BUILD OK)"
(cd Rust && bash build.sh)

step "Building the desktop app"
JAVA_HOME="$(dirname "$(dirname "$(readlink -f "$(command -v javac)")")")"
export JAVA_HOME
(cd desktop && ../android/gradlew --no-daemon -q -p . desktopLib)

step "Adding the launcher and menu entry"
ICONDIR="$HOME/.local/share/icons/hicolor/192x192/apps"
mkdir -p "$HOME/.local/bin" "$HOME/.local/share/applications" "$ICONDIR"
install -m 644 "$REPO/android/app/src/main/res/mipmap-xxxhdpi/ic_launcher.png" "$ICONDIR/otrv4plus.png"
LAUNCHER="$HOME/.local/bin/otrv4plus-desktop"
cat > "$LAUNCHER" <<EOF
#!/bin/sh
# Written by desktop/install.sh. Starts the app built in $REPO.
cd "$REPO" || exit 1
export OTRV4PLUS_ENGINE="$REPO/.venv/bin/python -s -m desktop_bridge.host"
export PYTHONMALLOC=malloc
exec "$JAVA_HOME/bin/java" -cp "$REPO/desktop/build/desktop-lib/*" org.otrv4plus.desktop.MainKt "\$@"
EOF
chmod 755 "$LAUNCHER"
cat > "$HOME/.local/share/applications/otrv4plus-desktop.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=OTRv4+
Comment=End-to-end encrypted chat over I2P
Exec=$LAUNCHER
Icon=otrv4plus
# Java names its window after the main class; this is how the desktop matches
# the window to this entry (and shows this icon, not a generic one).
StartupWMClass=org-otrv4plus-desktop-MainKt
Terminal=false
Categories=Network;InstantMessaging;
EOF

step "Done"
echo "Start it from your applications menu (OTRv4+) or with: otrv4plus-desktop"
echo "Update later by running this script again: bash $REPO/desktop/install.sh"
# Only when NO router is running at all. A machine that hosts the server runs
# its own router (i2pd-xmpp) and keeps the stock i2pd.service masked, and a
# second router started by hand counts too: telling that owner to enable
# i2pd would start a duplicate router (owner report, 2026-10-20).
if ! pgrep -x i2pd >/dev/null 2>&1 && ! systemctl is-active --quiet i2pd 2>/dev/null; then
    if [ "$(systemctl is-enabled i2pd 2>/dev/null)" = "masked" ]; then
        echo "Note: no I2P router is running (i2pd.service is masked here, so start the router you use)."
    else
        echo "Note: the I2P router is not running yet: sudo systemctl enable --now i2pd"
    fi
fi
if [ "$RUN" = 1 ]; then
    exec "$LAUNCHER"
fi
