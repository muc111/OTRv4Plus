#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
#
# Install the OTRv4+ server modules and limits on a Prosody built from
# source (the T450 layout: /usr/local). Safe to run again: it changes only
# what is not already so.
#
#   cd ~/OTRv4Plus && git pull && sudo bash prosody/install-server-limits.sh
#
# What it does (SECURITY_SESSIONS.md, SERVER_HARDENING.md):
#   1. backs up prosody.cfg.lua next to itself (prosody.cfg.lua.bak-<time>);
#   2. installs mod_otrv4plus_one_session (newest sign-in wins) and
#      mod_otrv4plus_capacity (online cap, sign-in pacing, sign-up limits)
#      and mod_otrv4plus_moderation (admins ban, unban, list every room);
#   3. replaces "c2s_limit_sessions" with "otrv4plus_one_session" and adds
#      "otrv4plus_capacity" and "otrv4plus_moderation" in modules_enabled;
#   4. sets max_resources = 1, max_online_users = 1600, login_rate = 10,
#      login_burst = 40, max_registrations_per_hour = 30,
#      max_registered_users = 5000, muc_event_rate = 10
#      and gc = { mode = "generational" };
#   5. runs `prosodyctl check config` -- and puts the backup back if it
#      fails -- then restarts Prosody and shows the new error-log lines.
#
# Override any value from the environment, e.g.
#   sudo LOGIN_RATE=20 bash prosody/install-server-limits.sh
set -euo pipefail

CFG="${PROSODY_CFG:-/usr/local/etc/prosody/prosody.cfg.lua}"
MODDIR="${PROSODY_MODULES:-/usr/local/lib/prosody/custom_modules}"
LOG="${PROSODY_LOG:-/usr/local/var/log/prosody/prosody.err}"
PROSODYCTL="${PROSODYCTL:-prosodyctl}"
RESTART="${RESTART:-1}"

MAX_RESOURCES="${MAX_RESOURCES:-1}"
# 1,600: what the T450 carried in STRESS_TEST.md (2026-10-20), ~40% of
# Prosody's core in steady chat, recovering from join bursts. Raise it only
# as far as a run on this machine shows.
MAX_ONLINE_USERS="${MAX_ONLINE_USERS:-1600}"
LOGIN_RATE="${LOGIN_RATE:-10}"
LOGIN_BURST="${LOGIN_BURST:-40}"
MAX_REGISTRATIONS_PER_HOUR="${MAX_REGISTRATIONS_PER_HOUR:-30}"
# Accounts in total (0 = no cap). Accounts that are not signed in cost
# little; this is a backstop against sign-ups filling the disk, on top of
# the hourly limit (owner, 2026-10-20: 5,000).
MAX_REGISTERED_USERS="${MAX_REGISTERED_USERS:-5000}"
# Lua's generational collector: with the default incremental one, a 1,990-
# user run (2026-10-18) stayed at 100% for an hour after joining stopped;
# with this, a 1,600-user run (2026-10-20) recovered within two minutes.
PROSODY_GC="${PROSODY_GC:-{ mode = \"generational\" \}}"
MUC_EVENT_RATE="${MUC_EVENT_RATE:-10}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
say() { printf '==> %s\n' "$*"; }
die() { printf 'STOPPED: %s\n' "$*" >&2; exit 1; }

[ "$RESTART" = 0 ] || [ "$(id -u)" -eq 0 ] || die "run it with sudo"
[ -f "$CFG" ] || die "no Prosody configuration at $CFG (set PROSODY_CFG)"
grep -q '^[[:space:]]*modules_enabled[[:space:]]*=[[:space:]]*{' "$CFG" \
    || die "no modules_enabled = { ... } list in $CFG"

# XMPP Guard (i2pd-dash), if installed, fingerprints modules and the config
# and would report this script's own changes as a possible backdoor. Its
# maintenance mode absorbs them into the new baseline instead; it expires by
# itself (XMPP Guard's maintenance_minutes).
GUARD_STATE="${XMPP_GUARD_STATE:-/var/lib/i2pd-dash}"
if [ "$RESTART" = 1 ] && [ -d "$GUARD_STATE" ]; then
    touch "$GUARD_STATE/maintenance"
    say "XMPP Guard: maintenance mode on, so these changes become its new baseline"
fi

BACKUP="$CFG.bak-$(date +%Y%m%d-%H%M%S)"
cp -a "$CFG" "$BACKUP"
say "backup: $BACKUP"

say "installing the modules into $MODDIR"
mkdir -p "$MODDIR"
install -m 644 "$HERE/mod_otrv4plus_one_session.lua" "$MODDIR/"
install -m 644 "$HERE/mod_otrv4plus_capacity.lua" "$MODDIR/"
install -m 644 "$HERE/mod_otrv4plus_moderation.lua" "$MODDIR/"
grep -q "$MODDIR" "$CFG" \
    || say "NOTE: $MODDIR is not in plugin_paths; add it, or Prosody will not find the modules"

say "modules_enabled"
# The old one-session module refuses the NEW sign-in; ours replaces the old
# one. The two must not run together.
sed -i 's/"c2s_limit_sessions";/"otrv4plus_one_session";/' "$CFG"
add_module() {
    grep -q "\"$1\"" "$CFG" && return 0
    sed -i "0,/^\([[:space:]]*modules_enabled[[:space:]]*=[[:space:]]*{\)/s//\1\n\t\"$1\";/" "$CFG"
}
add_module otrv4plus_one_session
add_module otrv4plus_capacity
add_module otrv4plus_moderation

say "limits"
set_option() {
    local key="$1" value="$2"
    if grep -qE "^[[:space:]]*$key[[:space:]]*=" "$CFG"; then
        sed -i -E "s|^([[:space:]]*$key[[:space:]]*=).*|\1 $value|" "$CFG"
    elif grep -q '^VirtualHost' "$CFG"; then
        # Global options belong before the first VirtualHost.
        sed -i "0,/^VirtualHost/s//$key = $value\nVirtualHost/" "$CFG"
    else
        printf '%s = %s\n' "$key" "$value" >> "$CFG"
    fi
}
set_option max_resources "$MAX_RESOURCES"
set_option max_online_users "$MAX_ONLINE_USERS"
set_option login_rate "$LOGIN_RATE"
set_option login_burst "$LOGIN_BURST"
set_option max_registrations_per_hour "$MAX_REGISTRATIONS_PER_HOUR"
set_option max_registered_users "$MAX_REGISTERED_USERS"
set_option gc "$PROSODY_GC"
set_option muc_event_rate "$MUC_EVENT_RATE"

say "checking the configuration"
if ! "$PROSODYCTL" check config; then
    cp -a "$BACKUP" "$CFG"
    die "prosodyctl check config failed: the backup is back in place, nothing restarted"
fi

if [ "$RESTART" = 1 ]; then
    lines=0
    [ -f "$LOG" ] && lines=$(wc -l < "$LOG")
    say "restarting Prosody"
    systemctl restart prosody
    sleep 3
    systemctl is-active --quiet prosody || die "Prosody did not start: sudo journalctl -u prosody -n 40"
    say "Prosody is running. New lines in $LOG (empty is good):"
    [ -f "$LOG" ] && tail -n +"$((lines + 1))" "$LOG" | tail -20
fi

say "now in $CFG:"
grep -nE '"otrv4plus_|c2s_limit_sessions|^[[:space:]]*(max_resources|max_online_users|login_rate|login_burst|max_registrations_per_hour|max_registered_users|muc_event_rate|gc)[[:space:]]*=' "$CFG"
say "done. To undo: sudo cp $BACKUP $CFG && sudo systemctl restart prosody"
