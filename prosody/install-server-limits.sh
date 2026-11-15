#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
#
# Install the OTRv4+ server modules and limits on a Prosody built from
# source (the T450 layout: /usr/local). Safe to run again: a second run finds
# nothing to change, and then changes nothing, backs up nothing and does not
# restart Prosody.
#
#   cd ~/OTRv4Plus && git pull && sudo bash prosody/install-server-limits.sh
#
# What it does (docs/SECURITY_SESSIONS.md, docs/SERVER_HARDENING.md):
#   0. BEFORE anything changes, says what it found: whether Prosody was
#      listening beyond this machine, whether federation was on, and whether
#      any setting stops the apps signing in. On a server meant to be hidden,
#      the first two are how it is found, and this run is about to remove
#      the evidence that they were open;
#   1. builds the new configuration in a scratch copy and checks it is still
#      valid Lua, so a bad edit stops here with the server untouched;
#   2. backs up prosody.cfg.lua next to itself (prosody.cfg.lua.bak-<time>);
#   3. installs mod_otrv4plus_one_session (newest sign-in wins),
#      mod_otrv4plus_capacity (online cap, sign-in pacing, sign-up limits)
#      and mod_otrv4plus_moderation (admins ban, unban, list every room);
#   4. replaces "c2s_limit_sessions" with "otrv4plus_one_session" and adds
#      "otrv4plus_capacity" and "otrv4plus_moderation" in modules_enabled;
#   5. sets max_resources = 1, max_online_users = 1600, login_rate = 10,
#      login_burst = 40, max_registrations_per_hour = 30,
#      max_registered_users = 5000, muc_event_rate = 10
#      and gc = { mode = "generational" };
#   6. runs `prosodyctl check config` on the result and puts the old config
#      and modules back if it fails; then restarts Prosody, shows the new
#      error-log lines, and stops if a module of ours did not load.
#
# Override any value from the environment, e.g.
#   sudo LOGIN_RATE=20 bash prosody/install-server-limits.sh
#
# See what it would do, changing nothing (no sudo needed if you can read the
# config):
#   bash prosody/install-server-limits.sh --check
#
# For a server that is reached ONLY through I2P or Tor, add HIDDEN_SERVICE=1:
#   sudo HIDDEN_SERVICE=1 bash prosody/install-server-limits.sh
# It also sets interfaces = { "127.0.0.1" }, turns federation (s2s) off and
# stops the server naming its operating system. Without these the machine's
# real address can be found: see "Keep the server's address hidden" in
# docs/SERVER_HARDENING.md. Not the default, because a server that federates
# or is reached directly needs the opposite. With it, a server that can
# still be found afterwards is a failure (exit 3), not a note; so is one
# this script could not look at (no `ss`), because "probably hidden" is not
# an answer.
#
# What this script prints can be sent to someone helping you: it never
# prints one of this machine's own addresses (only ports, and the wildcards
# 0.0.0.0, * and [::]), and of the configuration only the lines it changes.
# `prosodyctl check config`, whose output it shows, may name your hosts.
#
# Exit status
#   0   done, or nothing needed doing; with --check: nothing would change
#       and nothing is wrong
#   1   stopped: a precondition failed, the edited config was not valid, it
#       did not pass `prosodyctl check config` (the old one is back), Prosody
#       did not start, or a module of ours did not load
#   2   --check only: the script would change something (printed)
#   3   HIDDEN_SERVICE=1 and the server can still be found, or what it
#       listens on could not be read
#   4   a setting that stops the apps signing in (printed with the line to
#       change). Checked first, reported last; the rest still runs
#   64  bad usage
# When 3 and 4 both apply, 3 is returned and both are printed.
set -euo pipefail

usage() {
    cat <<'USAGE'
Usage: [sudo] [VAR=value ...] bash prosody/install-server-limits.sh [--check]

  --check   Change nothing. Say what is exposed now, what would stop the
            apps signing in, and exactly what a real run would change.
  --help    This text.

Variables: PROSODY_CFG, PROSODY_MODULES, PROSODY_LOG, PROSODYCTL, RESTART (0
to leave Prosody running as it is), HIDDEN_SERVICE (1 for a server reached
only through I2P or Tor), and the limits: MAX_RESOURCES, MAX_ONLINE_USERS,
LOGIN_RATE, LOGIN_BURST, MAX_REGISTRATIONS_PER_HOUR, MAX_REGISTERED_USERS,
MUC_EVENT_RATE.

Exit status: 0 done or nothing to do; 1 stopped; 2 --check found changes to
make; 3 HIDDEN_SERVICE=1 and still findable (or it could not be checked);
4 a setting that stops the apps signing in; 64 bad usage.
USAGE
}

CHECK=0
for arg in "$@"; do
    case "$arg" in
        --check|--dry-run|-n) CHECK=1 ;;
        -h|--help) usage; exit 0 ;;
        *) printf 'install-server-limits.sh: unknown argument: %s\n\n' "$arg" >&2
           usage >&2
           exit 64 ;;
    esac
done

CFG="${PROSODY_CFG:-/usr/local/etc/prosody/prosody.cfg.lua}"
MODDIR="${PROSODY_MODULES:-/usr/local/lib/prosody/custom_modules}"
LOG="${PROSODY_LOG:-/usr/local/var/log/prosody/prosody.err}"
PROSODYCTL="${PROSODYCTL:-prosodyctl}"
RESTART="${RESTART:-1}"
# The socket lister, so a test can supply a known answer.
SS="${SS:-ss}"

MAX_RESOURCES="${MAX_RESOURCES:-1}"
# 1,600: what the T450 carried in docs/STRESS_TEST.md (2026-10-20), ~40% of
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
HIDDEN_SERVICE="${HIDDEN_SERVICE:-0}"

# What the apps accept as a SCRAM iteration count (android_bridge/
# sasl_hardening.py, MIN_ITERATIONS and MAX_ITERATIONS). A server outside
# this is refused by every app from rc.204 on. tests/
# test_server_limits_installer.py holds the two pairs equal.
APP_MIN_ITERATIONS=4096
APP_MAX_ITERATIONS=2000000

MODULES="mod_otrv4plus_one_session.lua mod_otrv4plus_capacity.lua mod_otrv4plus_moderation.lua"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
say() { printf '==> %s\n' "$*"; }
detail() { printf '      %s\n' "$*"; }
die() { printf 'STOPPED: %s\n' "$*" >&2; exit 1; }

# ── preconditions: nothing below runs on a guess ────────────────────────────

[ -f "$CFG" ] || die "no Prosody configuration at $CFG (set PROSODY_CFG)"
[ -r "$CFG" ] || die "cannot read $CFG: run this with sudo"
grep -q '^[[:space:]]*modules_enabled[[:space:]]*=[[:space:]]*{' "$CFG" \
    || die "no modules_enabled = { ... } list in $CFG"
for module in $MODULES; do
    [ -f "$HERE/$module" ] || die "$HERE/$module is missing: run this from a complete checkout"
done
if [ "$CHECK" = 0 ] && [ "$RESTART" = 1 ] && [ "$(id -u)" -ne 0 ]; then
    die "run it with sudo (or with --check to only look)"
fi
if [ "$CHECK" = 0 ] && [ ! -w "$CFG" ]; then
    die "cannot write $CFG: run this with sudo (or with --check to only look)"
fi

WORK="$(mktemp)"
SAVED_MODULES=""
# shellcheck disable=SC2317  # reached through the EXIT trap
cleanup() {
    rm -f "$WORK"
    [ -z "$SAVED_MODULES" ] || rm -rf "$SAVED_MODULES"
}
trap cleanup EXIT

# ── reading the configuration ───────────────────────────────────────────────

# The lines of the GLOBAL list `$1 = { ... }` in file $2, comments removed.
# Global means before the first VirtualHost or Component; and the list ends
# at its own closing brace, on the same line or a later one.
list_block() {
    awk -v name="$1" '
        function strip(s) { sub(/--.*/, "", s); return s }
        /^[[:space:]]*(VirtualHost|Component)[[:space:]]/ { exit }
        !inside && $0 ~ "^[[:space:]]*" name "[[:space:]]*=[[:space:]]*\\{" {
            line = strip($0); print line
            inside = (line !~ /\}/)
            next
        }
        inside { line = strip($0); print line; if (line ~ /\}/) inside = 0 }
    ' "$2"
}
# (No `grep -q`: it stops reading at the first match, and under `pipefail`
# the writer it cuts off would turn a match into a failure.)
list_has() { list_block "$1" "$3" | grep "\"$2\"" >/dev/null; }

# The value of the global option $1 in file $2 (the last uncommented one).
global_option() {
    awk -v name="$1" '
        /^[[:space:]]*(VirtualHost|Component)[[:space:]]/ { exit }
        $0 ~ "^[[:space:]]*" name "[[:space:]]*=" {
            value = $0
            sub(/^[^=]*=[[:space:]]*/, "", value)
            sub(/[[:space:]]*(--.*)?$/, "", value)
            sub(/;$/, "", value)
            found = value
        }
        END { if (found != "") print found }
    ' "$2"
}

# ── step 0: what was true before this run ───────────────────────────────────

# Prosody's listening sockets that are not on this machine only, one per
# line and ready to print: `0.0.0.0:5222` for a wildcard, and for a specific
# address only its port. A specific address is this machine's own; this
# output gets pasted into requests for help, and for a hidden server that
# address is the one thing to keep back, so it never leaves this function.
#
# Whose socket it is: the lister names the owning process to root (and to
# anyone for their own processes), and then that is believed. Where it does
# not, the port decides: Prosody's defaults and any port the config names.
# Returns 2 if the socket lister could not be run.
listening_beyond_this_machine() {
    local sockets ports
    sockets="$("$SS" -H -ltnp 2>/dev/null)" || return 2
    ports="5222 5223 5269 5270 5280 5281 5000 5347 $(grep -E \
        '^[[:space:]]*[a-z0-9_]+_ports[[:space:]]*=' "$CFG" 2>/dev/null \
        | sed 's/--.*//' | grep -oE '[0-9]{2,5}' | tr '\n' ' ' || true)"
    printf '%s\n' "$sockets" | awk -v ports="$ports" '
        BEGIN { n = split(ports, list, " "); for (i = 1; i <= n; i++) want[list[i]] = 1 }
        NF >= 4 {
            address = $4
            port = address; sub(/^.*:/, "", port)
            host = substr(address, 1, length(address) - length(port) - 1)
            if ($0 ~ /users:\(\(/) ours = ($0 ~ /"(lua[a-z0-9.]*|prosody)"/)
            else ours = (port in want)
            if (!ours) next
            if (host ~ /^(127\.|\[::1\]$|\[::ffff:127\.|localhost$)/) next
            if (host == "0.0.0.0" || host == "*" || host == "[::]") print host ":" port
            else print "(an address of this machine):" port
        }' | sort -u
}

# For anything printed out of the configuration: the value of an
# `interfaces` option is withheld when it names a specific address, for the
# reason above. Wildcards and loopback say nothing about where the server is.
withhold_addresses() {
    awk '
        /interfaces[[:space:]]*=/ {
            value = $0; sub(/^[^=]*=/, "", value); sub(/--.*/, "", value)
            gsub(/"(127\.[0-9.]*|::1|localhost|\*|::|0\.0\.0\.0)"|[{};,[:space:]]/, "", value)
            if (value != "") sub(/=.*/, "= (not printed: it names an address of this machine)")
        }
        { print }'
}

# `*_interfaces` lines that override the global `interfaces` and name an
# address other than this machine: with them, HIDDEN_SERVICE cannot hide it.
overriding_interfaces() {
    awk '
        /^[[:space:]]*(VirtualHost|Component)[[:space:]]/ { exit }
        /^[[:space:]]*(c2s|s2s|http|https|c2s_direct_tls|s2s_direct_tls|legacy_ssl|component|proxy65)_interfaces[[:space:]]*=/ {
            value = $0; sub(/--.*/, "", value); sub(/^[^=]*=/, "", value)
            gsub(/"127\.[0-9.]*"|"::1"|"localhost"|[{};,[:space:]]/, "", value)
            if (value != "") printf "line %d: %s\n", NR, $0
        }' "$1" | withhold_addresses
}

# Prosody's version ("13.0.7"), or nothing when prosodyctl cannot say.
prosody_version() {
    local about
    about="$("$PROSODYCTL" --config "$CFG" about 2>/dev/null)" || about=""
    printf '%s\n' "$about" | awk '!found && /^Prosody [0-9]/ { print $2; found = 1 }'
}

# Settings that decide whether the apps can sign in. One finding per line:
# "STOP <text>" when nobody could sign in until it changes, "NOTE <text>"
# when it is only worth changing.
#
# Each rule here was measured, not assumed: the hardened client against
# Prosody 0.12.4 and 13.0.7 with the line in the config (2026-11-15), and
# tests/test_real_prosody.py runs the same table against whichever Prosody
# is installed, holding "STOP" equal to "the client could not sign in". Two
# rules depend on the version; with the version unknown both are STOP.
sign_in_stoppers() {
    local file="$1" count hash disabled version="" major="" low=0 high=0 plus=0
    count="$(global_option default_iteration_count "$file")"
    if printf '%s' "$count" | grep -E '^[0-9]+$' >/dev/null; then
        if [ "${#count}" -gt 12 ] || [ "$count" -gt "$APP_MAX_ITERATIONS" ]; then
            high=1
        elif [ "$count" -lt "$APP_MIN_ITERATIONS" ]; then
            low=1
        fi
    fi
    # Prosody offers one SCRAM family: the one its stored passwords are in.
    hash="$(global_option password_hash "$file" | tr -d "\"' ")"
    [ -n "$hash" ] || hash="SHA-1"
    disabled="$(list_block disable_sasl_mechanisms "$file")"
    if printf '%s\n' "$disabled" | grep -F "\"SCRAM-$hash-PLUS\"" >/dev/null; then
        plus=1
    fi
    if [ "$low" = 1 ] || [ "$plus" = 1 ]; then
        version="$(prosody_version)"
        major="${version%%.*}"
    fi

    if [ "$high" = 1 ]; then
        printf 'STOP %s\n' "default_iteration_count = $count: the apps accept $APP_MIN_ITERATIONS to $APP_MAX_ITERATIONS and end the sign-in above that. Set it within the range (100000 is a good value). An account whose password was set under this value keeps it until the password is changed."
    fi
    if [ "$low" = 1 ]; then
        if [ -n "$major" ] && [ "$major" -ge 13 ]; then
            # 13 enforces its own minimum, which is the apps' minimum.
            printf 'NOTE %s\n' "default_iteration_count = $count is below Prosody's own minimum; Prosody $version uses $APP_MIN_ITERATIONS instead and says so in its log. Set it to $APP_MIN_ITERATIONS or more (100000 is a good value)."
        else
            printf 'STOP %s\n' "default_iteration_count = $count: the apps accept $APP_MIN_ITERATIONS to $APP_MAX_ITERATIONS and end the sign-in below that. Set it within the range (100000 is a good value). An account whose password was set under this value keeps it until the password is changed."
        fi
    fi
    if printf '%s\n' "$disabled" | grep -F "\"SCRAM-$hash\"" >/dev/null; then
        printf 'STOP %s\n' "disable_sasl_mechanisms names \"SCRAM-$hash\", the mechanism the apps sign in with on this server. Over I2P and Tor they use nothing else, because anything else sends the password itself. Remove that entry."
    fi
    if [ "$plus" = 1 ]; then
        # The apps cannot do channel binding (Python's TLS does not export
        # the key material for it). Offered a -PLUS mechanism they decline
        # it and say so; offered none, their sign-in says "this server
        # offered no channel binding", which a server that does it reads as
        # the offer having been removed on the way, and fails.
        if [ -n "$major" ] && [ "$major" -lt 13 ]; then
            printf 'NOTE %s\n' "disable_sasl_mechanisms names \"SCRAM-$hash-PLUS\". On Prosody $version that fails the apps' sign-in only on connections older than TLS 1.3; on Prosody 13 and later it fails every one, as if the password were wrong. Remove that entry before upgrading."
        else
            printf 'STOP %s\n' "disable_sasl_mechanisms names \"SCRAM-$hash-PLUS\". With it not offered, Prosody 13 and later fails every sign-in from the apps as if the password were wrong (it takes the missing offer for an attack on the connection). Remove that entry: the apps then sign in with \"SCRAM-$hash\"."
        fi
    fi
}

say "what is true now, before anything is changed"
# yes: looked. unknown: the socket lister did not run. skipped: told not to
# look (RESTART=0 edits the configuration and leaves the server alone).
EXPOSED_BEFORE=""
LOOKED_BEFORE=skipped
if [ "$RESTART" = 1 ] || [ "$CHECK" = 1 ]; then
    if EXPOSED_BEFORE="$(listening_beyond_this_machine)"; then
        LOOKED_BEFORE=yes
        if [ -n "$EXPOSED_BEFORE" ]; then
            detail "listening beyond this machine: YES"
            printf '%s\n' "$EXPOSED_BEFORE" | while IFS= read -r socket; do detail "    $socket"; done
            detail "  Anyone who reaches this machine's address reaches Prosody. If the"
            detail "  server is meant to be reached only through I2P or Tor, this is how"
            detail "  its real address is found, and it was open until now."
        else
            detail "listening beyond this machine: no"
        fi
    else
        LOOKED_BEFORE=unknown
        detail "listening beyond this machine: COULD NOT TELL ('$SS' did not run)"
    fi
else
    detail "listening beyond this machine: not looked at (RESTART=0: config only)"
fi
FEDERATION_BEFORE=on
list_has modules_disabled s2s "$CFG" && FEDERATION_BEFORE=off
if [ "$FEDERATION_BEFORE" = on ]; then
    detail "federation (s2s): ON"
    detail "  Any account can make this server connect out, from its real address,"
    detail "  to a domain the account's owner controls."
else
    detail "federation (s2s): off"
fi
FINDINGS="$(sign_in_stoppers "$CFG")"
REFUSED="$(printf '%s\n' "$FINDINGS" | sed -n 's/^STOP //p')"
WORTH_CHANGING="$(printf '%s\n' "$FINDINGS" | sed -n 's/^NOTE //p')"
if [ -n "$REFUSED" ]; then
    detail "settings that stop the apps signing in: YES -- nobody can until this changes"
    printf '%s\n' "$REFUSED" | while IFS= read -r line; do detail "    $line"; done
else
    detail "settings that stop the apps signing in: none"
fi
if [ -n "$WORTH_CHANGING" ]; then
    detail "worth changing, though the apps sign in as it is:"
    printf '%s\n' "$WORTH_CHANGING" | while IFS= read -r line; do detail "    $line"; done
fi

# ── step 1: the new configuration, in a scratch copy ────────────────────────

cp "$CFG" "$WORK"

# The old one-session module refuses the NEW sign-in; ours replaces the old
# one. The two must not run together, so the entry is replaced whatever
# follows it (`;`, `,` or nothing); a commented-out one is left alone.
sed -i '/^[[:space:]]*--/! s/"c2s_limit_sessions"/"otrv4plus_one_session"/' "$WORK"
# Present means listed and not commented out: a `--"otrv4plus_capacity";`
# left from an experiment used to count, and the limits were then not in
# force with nothing to say so.
add_module() {
    list_has modules_enabled "$1" "$WORK" && return 0
    sed -i "0,/^\([[:space:]]*modules_enabled[[:space:]]*=[[:space:]]*{\)/s//\1\n\t\"$1\";/" "$WORK"
}
add_module otrv4plus_one_session
add_module otrv4plus_capacity
add_module otrv4plus_moderation

set_option() {
    local key="$1" value="$2"
    if grep -qE "^[[:space:]]*${key}[[:space:]]*=" "$WORK"; then
        sed -i -E "s|^([[:space:]]*${key}[[:space:]]*=).*|\1 $value|" "$WORK"
    elif grep -q '^VirtualHost' "$WORK"; then
        # Global options belong before the first VirtualHost.
        sed -i "0,/^VirtualHost/s//$key = $value\nVirtualHost/" "$WORK"
    else
        printf '%s = %s\n' "$key" "$value" >> "$WORK"
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

disable_module() {
    list_has modules_disabled "$1" "$WORK" && return 0
    if grep -qE '^[[:space:]]*modules_disabled[[:space:]]*=[[:space:]]*\{' "$WORK"; then
        sed -i "0,/^\([[:space:]]*modules_disabled[[:space:]]*=[[:space:]]*{\)/s//\1\n\t\"$1\";/" "$WORK"
    else
        set_option modules_disabled "{ \"$1\"; }"
    fi
}
if [ "$HIDDEN_SERVICE" = 1 ]; then
    # Prosody listens on every address by default. Reached that way, it
    # answers for its hidden name and shows its certificate to anyone
    # scanning the internet.
    set_option interfaces '{ "127.0.0.1" }'
    # With federation on, a message from any account to a domain its sender
    # controls makes this server connect there from its real address.
    disable_module s2s
    set_option hide_os_type true
fi

# A sed edit can only replace one line. If an option this script sets was
# written as a table over several lines, the result is not Lua any more;
# find that out here, with the server untouched.
lua_interpreter() {
    local candidate
    for candidate in lua5.4 lua5.3 lua5.2 lua5.1 lua luajit; do
        if command -v "$candidate" >/dev/null 2>&1; then
            printf '%s' "$candidate"
            return 0
        fi
    done
    return 1
}
valid_lua() {
    local lua="$1" file="$2"
    "$lua" -e "local chunk, problem = loadfile([[$file]])
        if not chunk then io.stderr:write(problem, '\n') os.exit(1) end" 2>&1 \
        | sed "s|$file|the configuration|g"
    return "${PIPESTATUS[0]}"
}
if LUA="$(lua_interpreter)"; then
    if ! PROBLEM="$(valid_lua "$LUA" "$CFG")"; then
        die "$CFG is not valid Lua as it stands, so it was left alone: $PROBLEM"
    fi
    if ! PROBLEM="$(valid_lua "$LUA" "$WORK")"; then
        die "the edited configuration would not be valid Lua, so nothing was changed: $PROBLEM. An option this script sets (interfaces, modules_disabled, gc or a limit) is probably written over several lines in $CFG; put it on one line, or set it yourself."
    fi
fi

CONFIG_CHANGES=0
cmp -s "$CFG" "$WORK" || CONFIG_CHANGES=1
MODULE_CHANGES=""
for module in $MODULES; do
    cmp -s "$HERE/$module" "$MODDIR/$module" 2>/dev/null || MODULE_CHANGES="$MODULE_CHANGES $module"
done
MODULE_DIR_UNLISTED=0
grep -qF "$MODDIR" "$WORK" || MODULE_DIR_UNLISTED=1

# ── what remains wrong whatever this script does ────────────────────────────

OVERRIDES="$(overriding_interfaces "$WORK")"
FEDERATION_AFTER=on
list_has modules_disabled s2s "$WORK" && FEDERATION_AFTER=off

# Exit status for what is wrong, once the work is done (3 before 4).
# $1: what Prosody listens on beyond this machine. $2: whether that was
# looked at (yes, unknown, skipped).
verdict() {
    local still_exposed="$1" looked="$2"
    if [ "$HIDDEN_SERVICE" = 1 ]; then
        if [ -n "$OVERRIDES" ] || [ "$FEDERATION_AFTER" = on ] || [ -n "$still_exposed" ]; then
            printf '\n' >&2
            printf 'FAILED (3): HIDDEN_SERVICE=1, and this server can still be found.\n' >&2
            if [ -n "$OVERRIDES" ]; then
                printf '  These lines in %s override the global interfaces and keep\n' "$CFG" >&2
                printf '  Prosody listening beyond this machine. Remove them, or name only\n' >&2
                printf '  "127.0.0.1" in them, then run this again:\n' >&2
                # Read from the file as it is now, so the line numbers are
                # the ones the operator will see when they open it.
                overriding_interfaces "$CFG" | sed 's/^/      /' >&2
            fi
            if [ "$FEDERATION_AFTER" = on ]; then
                printf '  Federation is still on: "s2s" is not in the global modules_disabled.\n' >&2
            fi
            if [ -n "$still_exposed" ]; then
                printf '  Prosody is still listening on:\n' >&2
                printf '%s\n' "$still_exposed" | sed 's/^/      /' >&2
                printf '  Check: sudo ss -ltnp | grep -E "lua|prosody"\n' >&2
            fi
            [ -z "$REFUSED" ] || printf '  (Also, a setting that stops the apps signing in: see above.)\n' >&2
            return 3
        fi
        if [ "$looked" = unknown ]; then
            # Not "probably fine": on a hidden server the one thing this
            # run exists to establish was not established.
            printf '\n' >&2
            printf 'FAILED (3): HIDDEN_SERVICE=1, and it could not be confirmed that this\n' >&2
            printf 'server cannot be found: what Prosody listens on could not be read\n' >&2
            printf "('%s' did not run). Install iproute2 and run this again, or look\n" "$SS" >&2
            printf 'yourself: every address Prosody listens on must begin with 127. or\n' >&2
            printf 'be [::1].\n' >&2
            printf '      sudo ss -ltnp | grep -E "lua|prosody"\n' >&2
            [ -z "$REFUSED" ] || printf '  (Also, a setting that stops the apps signing in: see above.)\n' >&2
            return 3
        fi
    fi
    if [ -n "$REFUSED" ]; then
        printf '\n' >&2
        printf 'FAILED (4): a setting in %s stops the apps signing in:\n' "$CFG" >&2
        printf '%s\n' "$REFUSED" | sed 's/^/      /' >&2
        return 4
    fi
    return 0
}

# ── --check: say it, change nothing ─────────────────────────────────────────

if [ "$CHECK" = 1 ]; then
    say "CHECK ONLY: nothing is changed"
    for module in $MODULES; do
        if [ ! -f "$MODDIR/$module" ]; then
            detail "$module: would be installed into $MODDIR"
        elif cmp -s "$HERE/$module" "$MODDIR/$module"; then
            detail "$module: up to date"
        else
            detail "$module: would be updated in $MODDIR"
        fi
    done
    if [ "$MODULE_DIR_UNLISTED" = 1 ]; then
        detail "NOTE: $MODDIR is not named in $CFG. Unless it is one of"
        detail "  Prosody's own module directories, add it to plugin_paths or the"
        detail "  modules will not load and none of the limits will apply."
    fi
    if [ "$CONFIG_CHANGES" = 1 ]; then
        detail "$CFG: would change. Only the changed lines are shown,"
        detail "with no lines around them, so nothing else in the file is printed:"
        # -U0: a config holds secrets (component and database passwords), and
        # a line beside one we change must not end up in a pasted report.
        diff -U0 --label "now" --label "after this script" "$CFG" "$WORK" \
            | withhold_addresses | sed 's/^/        /' || true
    else
        detail "$CFG: already as this script would leave it"
    fi
    if [ "$CONFIG_CHANGES" = 1 ] || [ -n "$MODULE_CHANGES" ]; then
        say "this script would make the changes above. Run it without --check to apply them."
        if [ "$HIDDEN_SERVICE" = 1 ] && [ -n "$OVERRIDES" ]; then
            detail "It would still not hide the server: these lines override 'interfaces':"
            overriding_interfaces "$CFG" | sed 's/^/          /'
        fi
        [ -z "$REFUSED" ] || detail "It would not fix the setting that stops the apps signing in (above)."
        exit 2
    fi
    say "nothing to change"
    verdict "$EXPOSED_BEFORE" "$LOOKED_BEFORE" || exit $?
    exit 0
fi

# ── steps 2-6: apply ────────────────────────────────────────────────────────

BACKUP=""
# How to go back, for a message; true whether or not the config was changed.
undo_hint() {
    if [ -n "$BACKUP" ]; then
        printf 'To go back: sudo cp %s %s && sudo systemctl restart prosody' "$BACKUP" "$CFG"
    else
        printf 'The configuration was not changed by this run; only module files in %s were.' "$MODDIR"
    fi
}
restore() {
    [ -z "$BACKUP" ] || cp -a "$BACKUP" "$CFG"
    if [ -n "$SAVED_MODULES" ]; then
        for module in $MODULES; do
            if [ -f "$SAVED_MODULES/$module" ]; then
                install -m 644 "$SAVED_MODULES/$module" "$MODDIR/$module"
            elif [ -f "$SAVED_MODULES/$module.absent" ]; then
                rm -f "$MODDIR/$module"
            fi
        done
    fi
}

if [ "$CONFIG_CHANGES" = 0 ] && [ -z "$MODULE_CHANGES" ]; then
    say "nothing to change: the modules and $CFG are already as this script leaves them"
    detail "No backup was made and Prosody was not restarted."
    APPLIED=0
else
    APPLIED=1
    # XMPP Guard (i2pd-dash), if installed, fingerprints modules and the
    # config and would report this script's own changes as a possible
    # backdoor. Its maintenance mode absorbs them into the new baseline
    # instead; it expires by itself (XMPP Guard's maintenance_minutes).
    GUARD_STATE="${XMPP_GUARD_STATE:-/var/lib/i2pd-dash}"
    if [ "$RESTART" = 1 ] && [ -d "$GUARD_STATE" ]; then
        touch "$GUARD_STATE/maintenance"
        say "XMPP Guard: maintenance mode on, so these changes become its new baseline"
    fi

    if [ "$CONFIG_CHANGES" = 1 ]; then
        BACKUP="$CFG.bak-$(date +%Y%m%d-%H%M%S)"
        cp -a "$CFG" "$BACKUP"
        say "backup: $BACKUP"
    fi

    if [ -n "$MODULE_CHANGES" ]; then
        say "installing the modules into $MODDIR"
        mkdir -p "$MODDIR"
        SAVED_MODULES="$(mktemp -d)"
        for module in $MODULE_CHANGES; do
            if [ -f "$MODDIR/$module" ]; then
                cp -a "$MODDIR/$module" "$SAVED_MODULES/$module"
            else
                : > "$SAVED_MODULES/$module.absent"
            fi
            install -m 644 "$HERE/$module" "$MODDIR/"
            detail "$module"
        done
    fi
    if [ "$MODULE_DIR_UNLISTED" = 1 ]; then
        say "NOTE: $MODDIR is not in plugin_paths; add it, or Prosody will not find the modules"
    fi

    if [ "$CONFIG_CHANGES" = 1 ]; then
        say "writing $CFG"
        # In place, so the file keeps its owner and mode.
        cat "$WORK" > "$CFG"
    fi

    say "checking the configuration"
    if ! "$PROSODYCTL" --config "$CFG" check config; then
        restore
        die "prosodyctl check config failed: the old configuration and modules are back in place, nothing restarted"
    fi

    if [ "$RESTART" = 1 ]; then
        lines=0
        [ -f "$LOG" ] && lines=$(wc -l < "$LOG")
        say "restarting Prosody"
        systemctl restart prosody
        sleep 3
        systemctl is-active --quiet prosody || die "Prosody did not start: sudo journalctl -u prosody -n 40. $(undo_hint)"
        say "Prosody is running. New lines in $LOG (empty is good):"
        NEW_LINES=""
        [ -f "$LOG" ] && NEW_LINES="$(tail -n +"$((lines + 1))" "$LOG" | tail -20)"
        [ -z "$NEW_LINES" ] || printf '%s\n' "$NEW_LINES"
        if printf '%s\n' "$NEW_LINES" | grep -iE "otrv4plus_(capacity|one_session|moderation)" >/dev/null; then
            die "a module of ours is named in Prosody's error log (above), so the limits may not be in force. Usually $MODDIR is not in plugin_paths. $(undo_hint)"
        fi
    fi
fi

# ── what is true now ────────────────────────────────────────────────────────

EXPOSED_AFTER=""
LOOKED_AFTER=skipped
if [ "$RESTART" = 1 ]; then
    if EXPOSED_AFTER="$(listening_beyond_this_machine)"; then
        LOOKED_AFTER=yes
    else
        LOOKED_AFTER=unknown
    fi
fi

# "YES", "no" or "could not tell", for one of the two looks.
answer() {
    case "$2" in
        yes) if [ -n "$1" ]; then printf 'YES'; else printf 'no'; fi ;;
        unknown) printf 'could not tell' ;;
        *) printf 'not looked at' ;;
    esac
}

say "before this run, and now"
if [ "$RESTART" = 1 ]; then
    detail "listening beyond this machine: $(answer "$EXPOSED_BEFORE" "$LOOKED_BEFORE")  ->  $(answer "$EXPOSED_AFTER" "$LOOKED_AFTER")"
else
    detail "listening beyond this machine: not looked at (RESTART=0)"
fi
detail "federation (s2s): $FEDERATION_BEFORE  ->  $FEDERATION_AFTER"

# Not an error without HIDDEN_SERVICE: a server that federates or is reached
# directly wants these.
if [ "$HIDDEN_SERVICE" != 1 ]; then
    if [ "$FEDERATION_AFTER" = on ]; then
        say "NOTE: federation (s2s) is on. If this server is reached only through"
        say "      I2P or Tor, any account can make it connect out from its real"
        say "      address. Run again with HIDDEN_SERVICE=1 (docs/SERVER_HARDENING.md)."
    fi
    if [ -n "$EXPOSED_AFTER" ]; then
        say "NOTE: Prosody is listening beyond this machine:"
        printf '%s\n' "$EXPOSED_AFTER" | sed 's/^/        /'
        say "      If this server is reached only through I2P or Tor, that is how"
        say "      its real address is found. Run again with HIDDEN_SERVICE=1."
    fi
elif [ "$RESTART" != 1 ] && [ "$APPLIED" = 1 ]; then
    say "NOTE: Prosody was not restarted (RESTART=0), so it still runs the old"
    say "      configuration and what it listens on was not checked."
fi

say "now in $CFG:"
grep -nE '"otrv4plus_|c2s_limit_sessions|^[[:space:]]*(max_resources|max_online_users|login_rate|login_burst|max_registrations_per_hour|max_registered_users|muc_event_rate|gc|interfaces|hide_os_type|modules_disabled)[[:space:]]*=' "$CFG" \
    | withhold_addresses || true
if [ -n "$BACKUP" ]; then
    say "done. To undo: sudo cp $BACKUP $CFG && sudo systemctl restart prosody"
else
    say "done."
fi

verdict "$EXPOSED_AFTER" "$LOOKED_AFTER" || exit $?
exit 0

