#!/usr/bin/env bash
# Build, check and install otrv4_core (with secure groups / MLS) for the
# terminal clients on Termux or Linux.
#
#     cd ~/OTRv4Plus/Rust
#     bash build.sh
#
# Prerequisites: Python 3.12+, Rust and a C compiler.
#     Termux: pkg install python rust clang
# They are checked first, before anything is built. Everything else is set up
# here, and nowhere else:
#
#   * the project virtualenv ~/OTRv4Plus/.venv (created if missing, recreated
#     if it no longer matches this Python) -- never activated in your shell.
#     It can see the global site-packages, so the clients' runtime modules
#     (slixmpp, PySocks, Termux's python-cryptography, ...) need no second
#     install, but otrv4_core and the build tool are its own and come first;
#   * the pinned build tool, maturin (MATURIN_VERSION below), inside that
#     virtualenv; a globally installed maturin is never used. On Termux it is
#     compiled once into a wheel cached under ~/.cache/otrv4plus (see below)
#     and installed from there on later runs.
#
# Then: Rust release tests (core and MLS), clippy with -D warnings, the
# MLS-enabled release build installed into .venv, and checks that prove the
# module Python loads is the one just built, from .venv, that it has every
# function the clients call, and that MLS works on this device.
#
# Run the clients with the same interpreter afterwards (both switch to it
# by themselves if started with another one):
#     cd ~/OTRv4Plus && .venv/bin/python otrv4plus_xmpp.py --jid ...
#     cd ~/OTRv4Plus && .venv/bin/python otrv4+.py -n <nick> -s <server>
#
# WHAT YOU SEE WHILE IT RUNS, AND WHERE THE LOG IS
# Every run is logged in full to ~/.cache/otrv4plus/logs/ (latest.log is the
# newest). Each step prints its start time; a long step prints a heartbeat
# with the time taken, crates compiled and whether the compiler is using CPU,
# and says plainly if nothing at all is happening. A failure ends with
# "BUILD FAILED", the reason, and a diagnostics block for the report. If a run
# was killed from outside (Android can do that to long builds), the next run
# says so first, and carries on from the work already done.
#
# WHY MATURIN IS PINNED BELOW 1.14
# maturin 1.14+ writes its own PyO3 config for every stable-ABI (abi3) build
# with PyO3 >= 0.29, and on Android that config names `python3` as the
# library to link. The extension then depends on libpython3.so, which does
# not provide the interpreter's symbols to it on Android, and the import dies:
#     dlopen failed: cannot locate symbol "_Py_NoneStruct" ... otrv4_core.abi3.so
# maturin 1.13.3 only writes that config when cross-compiling. Building on the
# device, PyO3 reads this Python's own sysconfig and links libpython3.X.so
# from its LIBDIR, which loads. PyO3 stays at 0.29: every 0.28.x release is
# affected by RUSTSEC-2026-0176 (GHSA-36hh-v3qg-5jq4).
#
# WHY TERMUX BUILDS MATURIN SERIALLY, IN ITS OWN DIRECTORIES
# PyPI has no maturin wheel Termux's pip can use, so pip compiles it (about
# 210 crates). Cargo runs each build script from target/.../build-script-build,
# which it normally hard-links into place. Android refuses hard links in an
# app's data directory, so cargo copies the file instead -- with the copy
# open for writing in cargo's own process. A parallel job forked in that
# moment inherits the open file until it execs, and executing the build
# script then fails with
#     could not execute process `.../build-script-build` (never executed)
#     Text file busy (os error 26)
# The maturin build therefore runs with CARGO_BUILD_JOBS=1, with its temp
# directory (emptied before every attempt) and cargo target directory under
# ~/.cache/otrv4plus -- not pip's throwaway pip-install-* directory. The
# target directory is kept between attempts and runs, so a compile Android
# killed half way resumes instead of starting over; it is emptied before the
# last attempt. Attempts are bounded (MATURIN_ATTEMPTS) and only a busy file,
# a killed compiler or memory exhaustion is retried. The finished wheel is
# checked and cached, so this happens once. The project's own cargo commands
# retry the same failures with one job at a time.

set -euo pipefail

MATURIN_VERSION="1.13.3"
MATURIN_CRATES_APPROX=210
PY_MIN_MAJOR=3
PY_MIN_MINOR=12
RUST_MIN="1.85"          # the core's rust-version (Cargo.toml)
MATURIN_RUST_MIN="1.89"  # maturin 1.13.3's rust-version, when compiling it
MATURIN_ATTEMPTS=3       # bounded; see RETRY_RE
CARGO_ATTEMPTS=3
TERMUX_MAX_JOBS=4        # parallel compile jobs on a phone, unless set
HEARTBEAT_SECS="${OTRV4PLUS_HEARTBEAT_SECS:-60}"
STALL_WARN_SECS="${OTRV4PLUS_STALL_WARN_SECS:-900}"
LOG_KEEP=10

RUST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$RUST_DIR/.." && pwd -P)"
VENV="$REPO_ROOT/.venv"
PY="$VENV/bin/python"
MATURIN="$VENV/bin/maturin"
CACHE_ROOT="${XDG_CACHE_HOME:-$HOME/.cache}/otrv4plus"
MATURIN_CACHE="$CACHE_ROOT/maturin-$MATURIN_VERSION"
LOG_DIR="$CACHE_ROOT/logs"
LOCK_DIR="$CACHE_ROOT/build.lock"

# Failures recognised in a command's output. The retryable ones are those a
# second try with one job at a time can get past.
ETXTBSY_RE='Text file busy|os error 26'
KILLED_RE='signal: 9|SIGKILL|\(signal 9\)|^Killed|terminated by signal 9'
OOM_RE='out of memory|memory allocation of [0-9]+ bytes failed|Cannot allocate memory|os error 12'
NOSPACE_RE='No space left on device|os error 28|Disk quota exceeded'
NETWORK_RE='Could not fetch URL|Network is unreachable|Temporary failure in name resolution|Name or service not known|Connection (refused|reset|timed out)|Max retries exceeded|No matching distribution found|failed to download|Could not resolve host'
RETRY_RE="$ETXTBSY_RE|$KILLED_RE|$OOM_RE"
# rustc's `warning:` lines and maturin's `⚠️ Warning:` lines.
WARNING_RE='^(warning|error)(\[[A-Za-z0-9_]+\])?:|⚠'

BUILD_T0="$(date +%s)"
STEP_NAME=""
STEP_T0="$BUILD_T0"
WATCH_PID=""
TEE_PID=""
RUN_LOG=""
PREV_LOG=""
HAVE_LOCK=""
WAKE_LOCKED=""
DIED=""
FINISHED=""
CLEANUP_PATHS=()

# ---------------------------------------------------------------- output ---

now() { date +%s; }
fmt_secs() { printf '%dm%02ds' $(($1 / 60)) $(($1 % 60)); }
info() { printf -- '--- %s\n' "$*"; }
# A notice that must not be missed: each argument is one line.
notice() {
    printf '\n!!! %s\n' "$1"
    shift
    local line
    for line in "$@"; do printf '!!! %s\n' "$line"; done
    printf '\n'
}
step() {
    local t
    t="$(now)"
    if [ -n "$STEP_NAME" ]; then info "step done in $(fmt_secs $((t - STEP_T0)))"; fi
    STEP_NAME="$*"
    STEP_T0="$t"
    printf '\n=== %s ===  [%s, %s since start]\n' "$*" "$(date +%H:%M:%S)" "$(fmt_secs $((t - BUILD_T0)))"
}

is_termux() {
    case "${PREFIX:-}" in */com.termux/*) return 0 ;; esac
    [ -n "${TERMUX_VERSION:-}" ]
}

prop() { command -v getprop >/dev/null 2>&1 && getprop "$1" 2>/dev/null || true; }
android_sdk() { local s; s="$(prop ro.build.version.sdk)"; printf '%s' "${s:-0}"; }

device_summary() {
    if [ -n "$(prop ro.build.version.release)" ]; then
        printf '%s %s, Android %s (SDK %s), kernel %s, %s' \
            "$(prop ro.product.manufacturer)" "$(prop ro.product.model)" \
            "$(prop ro.build.version.release)" "$(android_sdk)" "$(uname -r)" "$(uname -m)"
    else
        printf '%s %s %s' "$(uname -s)" "$(uname -r)" "$(uname -m)"
    fi
}

avail_mb() { df -Pk "$1" 2>/dev/null | awk 'NR==2 {print int($4 / 1024)}'; }
mem_summary() {
    [ -r /proc/meminfo ] || { printf 'unknown'; return; }
    awk '/^MemTotal:/ {t=$2} /^MemAvailable:/ {a=$2}
         END {printf "%d MB available of %d MB", a/1024, t/1024}' /proc/meminfo
}

print_diagnostics() {
    printf '\n--- diagnostics (send this block, or the whole log, with a report) ---\n'
    printf '    failed in: %s, %s after start\n' "${STEP_NAME:-start}" "$(fmt_secs $(($(now) - BUILD_T0)))"
    printf '    device:    %s\n' "$(device_summary)"
    printf '    termux:    %s\n' "${TERMUX_VERSION:-no} (PREFIX=${PREFIX:-unset})"
    printf '    rustc:     %s\n' "$(rustc --version 2>/dev/null || echo missing)"
    printf '    cargo:     %s\n' "$(cargo --version 2>/dev/null || echo missing)"
    printf '    python:    %s\n' "$("$PY" -c 'import sys; print(sys.version.split()[0], sys.executable)' 2>/dev/null || echo "no virtualenv yet")"
    printf '    maturin:   %s\n' "$("$MATURIN" --version 2>/dev/null || echo "not installed in .venv")"
    printf '    jobs:      CARGO_BUILD_JOBS=%s\n' "${CARGO_BUILD_JOBS:-default}"
    printf '    disk:      %s MB free for the repository, %s MB for the cache\n' \
        "$(avail_mb "$REPO_ROOT")" "$(avail_mb "$CACHE_ROOT")"
    printf '    memory:    %s\n' "$(mem_summary)"
    printf '    log:       %s\n' "$RUN_LOG"
}

die() {
    DIED=1
    watch_stop
    printf '\nBUILD FAILED: %s\n' "$*" >&2
    print_diagnostics >&2
    exit 1
}

# Explain the recognised causes of a failure found in a command's output.
android_kill_advice() {
    notice "${1:-Android stopped a compiler process (SIGKILL).}" \
        "On Android 12 and later the system kills child processes of apps it" \
        "considers background or too busy, and kills big ones when memory runs out." \
        "To let the build finish:" \
        "  * keep Termux open, in front, until the build ends (build.sh holds a" \
        "    Termux wake lock so the phone does not sleep);" \
        "  * Settings > Apps > Termux > Battery: Unrestricted;" \
        "  * Android 14 or newer: Settings > System > Developer options >" \
        "    'Disable child process restrictions' = on;" \
        "  * Android 12L/13, from a computer with adb:" \
        "      adb shell settings put global settings_enable_monitor_phantom_procs false" \
        "  * Android 12, from a computer with adb:" \
        "      adb shell device_config set_sync_disabled_for_tests persistent" \
        "      adb shell device_config put activity_manager max_phantom_processes 2147483647" \
        "Then run 'bash build.sh' again: work already finished is kept."
}
explain_failure() {
    local log="$1"
    if grep -Eq "$NOSPACE_RE" "$log"; then
        notice "The storage is full ('No space left on device')." \
            "Free: $(avail_mb "$REPO_ROOT") MB. A full build needs about 4 GB free." \
            "Free some space (for example 'pkg clean', or delete old downloads) and run" \
            "'bash build.sh' again."
    fi
    if grep -Eq "$KILLED_RE" "$log"; then android_kill_advice; fi
    if grep -Eq "$OOM_RE" "$log"; then
        notice "A compiler ran out of memory ($(mem_summary))." \
            "Close other apps and run 'bash build.sh' again; retries already use one" \
            "compile job at a time."
    fi
    if grep -Eq "$ETXTBSY_RE" "$log"; then
        notice "'Text file busy' (ETXTBSY) came back even with one compile job at a time." \
            "Run 'bash build.sh' again; the work already done is kept."
    fi
    if grep -Eq "$NETWORK_RE" "$log"; then
        notice "A download failed (PyPI or crates.io could not be reached)." \
            "Check the connection (and any VPN or proxy) and run 'bash build.sh' again."
    fi
    if grep -q 'Failed to determine Android API level' "$log"; then
        notice "maturin could not tell the Android API level." \
            "Run: ANDROID_API_LEVEL=24 bash build.sh   and report this log."
    fi
    if grep -q 'not a supported wheel on this platform' "$log"; then
        notice "pip refused the wheel for this Python (platform tag mismatch); send this log."
    fi
    if grep -q 'Blocking waiting for file lock' "$log"; then
        notice "cargo waited for a lock held by another cargo process." \
            "Close other Termux sessions that build Rust, or stop them: pkill cargo"
    fi
}

# ------------------------------------------------------------ liveness ---

# "pid own-ticks total-ticks" for every compiler-ish process this user can
# see. The total includes children the process has already reaped, so a rustc
# that started and finished between two samples still shows up in cargo's.
#
# Each file is read on its own: on a busy phone processes exit between listing
# /proc and reading it, and awk given all the files at once stops at the first
# one that has gone -- skipping every process after it (it reported "0
# processes" while rustc was linking).
compiler_snapshot() {
    [ -r /proc/self/stat ] || return 0
    local f line comm
    local -a fld
    for f in /proc/[0-9]*/stat; do
        { read -r line < "$f"; } 2>/dev/null || continue
        comm="${line#*(}"; comm="${comm%)*}"
        case "$comm" in
            rustc|cargo|cc|cc1|cc1plus|clang*|gcc|ld|ld.*|lld|ar|build-script-b*|build_script_*|maturin|python|python[0-9]*) ;;
            *) continue ;;
        esac
        # After "(comm) ": state ppid ... utime(11) stime(12) cutime(13) cstime(14)
        read -r -a fld <<< "${line##*) }"
        [ "${#fld[@]}" -gt 14 ] || continue
        printf '%s %s %s\n' "${line%% *}" $((fld[11] + fld[12])) \
            $((fld[11] + fld[12] + fld[13] + fld[14]))
    done
}
# CPU ticks used between two snapshots: the growth of a process seen in both,
# and only its own ticks for one that started in between.
cpu_delta() {
    awk 'NR == FNR { p[$1] = $3; next }
         { d = ($1 in p) ? $3 - p[$1] : $2; if (d > 0) s += d }
         END { print s + 0 }' "$1" "$2"
}

# Print a heartbeat while a long command runs. $1 is the file its output goes
# to, $2 a label, $3 "always" (the output is not on screen) or "quiet" (only
# when the output has been silent for a while), $4 an optional crate total.
watch_start() {
    local log="$1" label="$2" mode="$3" total="${4:-}"
    [ "$HEARTBEAT_SECS" -gt 0 ] || return 0
    (
        trap - EXIT INT TERM
        t0="$(date +%s)"; last_size=-1; idle_since="$t0"; warned=""
        hz="$(getconf CLK_TCK 2>/dev/null || echo 100)"
        prev="$(mktemp)"; cur="$(mktemp)"
        trap 'rm -f "$prev" "$cur"' EXIT
        trap 'rm -f "$prev" "$cur"; exit 0' TERM
        compiler_snapshot > "$prev"
        while sleep "$HEARTBEAT_SECS" >/dev/null 2>&1; do
            t="$(date +%s)"
            size="$(wc -c < "$log" 2>/dev/null || echo 0)"
            if [ "$size" != "$last_size" ]; then last_size="$size"; idle_since="$t"; warned=""; fi
            idle=$((t - idle_since))
            compiler_snapshot > "$cur"
            cpu=$(($(cpu_delta "$prev" "$cur") / hz))
            procs="$(wc -l < "$cur" | tr -d ' ')"
            cp "$cur" "$prev"
            # cargo or pip itself is always running here; seeing none means
            # this system hides process activity, not that nothing runs.
            if [ "$procs" -eq 0 ]; then
                activity="compiler activity not visible"
            else
                activity="compiler CPU ${cpu}s in the last ${HEARTBEAT_SECS}s ($procs processes)"
            fi
            if [ "$mode" = quiet ] && [ "$idle" -lt "$HEARTBEAT_SECS" ]; then continue; fi
            n="$(grep -cE '^[[:space:]]*Compiling ' "$log" 2>/dev/null || true)"
            if [ -n "$total" ]; then crates="$n of ~$total crates compiled"; else crates="$n crates compiled"; fi
            printf '    ... %s: %s running, %s, %s, last output %s ago\n' \
                "$label" "$(fmt_secs $((t - t0)))" "$crates" "$activity" "$(fmt_secs "$idle")"
            last="$(tail -n 1 "$log" 2>/dev/null | tr -d '\r' | cut -c1-110)"
            if [ "$idle" -ge "$HEARTBEAT_SECS" ] && [ -n "$last" ]; then
                printf '        last line: %s\n' "$last"
            fi
            case "$last" in
                *"Blocking waiting for file lock"*)
                    printf '!!! cargo is waiting for another cargo process to release its lock.\n'
                    printf '!!! Close other Termux sessions that build Rust, or run: pkill cargo\n' ;;
            esac
            if [ "$idle" -ge "$STALL_WARN_SECS" ] && [ -z "$warned" ]; then
                warned=1
                if [ "$procs" -eq 0 ]; then
                    printf '!!! No new output for %s. Process activity is not visible here, so this\n' "$(fmt_secs "$idle")"
                    printf '!!! cannot tell a slow step from a stall. The final optimised (LTO) link\n'
                    printf '!!! of otrv4_core is silent for a long time on a phone. If nothing changes\n'
                    printf '!!! for another %s, press Ctrl-C and run "bash build.sh" again.\n' "$(fmt_secs "$STALL_WARN_SECS")"
                elif [ "$cpu" -gt 0 ]; then
                    printf '!!! No new output for %s, but the compiler is busy (%ss CPU in the last %ss).\n' \
                        "$(fmt_secs "$idle")" "$cpu" "$HEARTBEAT_SECS"
                    printf '!!! Large crates and the final optimised (LTO) link are silent for a long\n'
                    printf '!!! time on a phone. This is normal; keep Termux open.\n'
                else
                    printf '!!! STALLED? No new output for %s and no compiler CPU use.\n' "$(fmt_secs "$idle")"
                    printf '!!! Usual causes: the screen went off or Termux was put in the background,\n'
                    printf '!!! battery optimisation, or a process Android killed. If nothing changes,\n'
                    printf '!!! press Ctrl-C and run "bash build.sh" again (finished work is kept).\n'
                fi
            fi
        done
    ) &
    WATCH_PID=$!
}
watch_stop() {
    if [ -n "$WATCH_PID" ]; then
        kill "$WATCH_PID" 2>/dev/null || true
        wait "$WATCH_PID" 2>/dev/null || true
        WATCH_PID=""
    fi
    return 0
}

# ------------------------------------------------------------- helpers ---

# `rustc 1.94.1 (...)` -> succeeds when at least $1.
rustc_at_least() {
    local have
    have="$(rustc --version | awk '{print $2}')"
    [ "$(printf '%s\n%s\n' "$1" "${have%%-*}" | sort -V | head -n1)" = "$1" ]
}

run_in() {
    local dir="$1" old="$PWD"
    shift
    cd "$dir"
    "$@"
    cd "$old"
}

# Run a cargo or maturin command, show its output, and fail on any warning it
# prints. The production build is warning-free; a new warning is a failure,
# not noise. A busy file, a killed compiler or memory exhaustion is retried,
# at most CARGO_ATTEMPTS times in all, with one job at a time; cargo resumes
# where it stopped. Every other failure fails at once, explained.
cargo_clean_output() {
    local log attempt=1
    local -a prefix=()
    log="$(mktemp)"
    CLEANUP_PATHS+=("$log")
    while :; do
        watch_start "$log" "${1##*/} $2" quiet
        if ${prefix[@]+"${prefix[@]}"} "$@" 2>&1 | tee "$log"; then
            watch_stop
            break
        fi
        watch_stop
        if ! grep -Eq "$NOSPACE_RE" "$log" && grep -Eq "$RETRY_RE" "$log" \
                && [ "$attempt" -lt "$CARGO_ATTEMPTS" ]; then
            attempt=$((attempt + 1))
            if grep -Eq "$ETXTBSY_RE" "$log"; then
                info "cargo hit 'Text file busy' (ETXTBSY)"
            else
                info "a compiler process was killed or ran out of memory"
            fi
            info "retrying with one compile job at a time, attempt $attempt of $CARGO_ATTEMPTS"
            prefix=(env CARGO_BUILD_JOBS=1)
            continue
        fi
        explain_failure "$log"
        die "'$*' failed (its output is above)"
    done
    if grep -Eq "$WARNING_RE" "$log"; then
        grep -E "$WARNING_RE" "$log" | sort | uniq -c >&2
        die "'$*' printed compiler warnings; the production build must have none"
    fi
    rm -f "$log"
}

have_maturin() {
    [ -x "$MATURIN" ] && [ "$("$MATURIN" --version 2>/dev/null)" = "maturin $MATURIN_VERSION" ]
}

# A maturin wheel is usable when it is an intact zip, is version
# MATURIN_VERSION and carries the maturin executable.
valid_maturin_wheel() {
    "$PY" - "$1" "$MATURIN_VERSION" <<'PYEOF' >/dev/null 2>&1
import sys, zipfile
path, version = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(path) as z:
    if z.testzip() is not None:
        sys.exit(1)
    names = z.namelist()
    meta = [n for n in names if n.endswith(".dist-info/METADATA")]
    if len(meta) != 1 or ("Version: " + version) not in z.read(meta[0]).decode().splitlines():
        sys.exit(1)
    if not any(n.endswith(".data/scripts/maturin") for n in names):
        sys.exit(1)
PYEOF
}

# Whether this Python's pip accepts a wheel's platform tags. Prints the tags
# on a mismatch, so a refusal is explained instead of left to pip.
wheel_fits_python() {
    "$PY" - "$1" <<'PYEOF'
import os, sys
try:
    from pip._vendor.packaging.tags import sys_tags
    from pip._vendor.packaging.utils import parse_wheel_filename
except Exception:
    sys.exit(0)  # cannot tell; let pip decide
_, _, _, tags = parse_wheel_filename(os.path.basename(sys.argv[1]))
supported = list(sys_tags())
if set(tags) & set(supported):
    sys.exit(0)
print("wheel tags:        " + ", ".join(sorted(str(t) for t in tags)))
print("this Python takes: " + ", ".join(str(t) for t in supported[:6]) + ", ...")
sys.exit(1)
PYEOF
}

# The one cached wheel, if there is exactly one.
cached_maturin_wheel() {
    local -a found=()
    shopt -s nullglob
    found=("$MATURIN_CACHE/wheel/maturin-$MATURIN_VERSION-"*.whl)
    shopt -u nullglob
    [ "${#found[@]}" -eq 1 ] && printf '%s\n' "${found[0]}"
}

install_maturin_wheel() {
    "$PY" -m pip install --no-index --no-deps --ignore-installed "$1" && have_maturin
}

# pip's own temp directories left by an earlier, killed maturin build. Only
# directories holding a maturin source tree and untouched for an hour, so a
# concurrent pip is never disturbed.
remove_stale_pip_dirs() {
    local tmp="${TMPDIR:-/tmp}" d
    shopt -s nullglob
    for d in "$tmp"/pip-install-* "$tmp"/pip-wheel-*; do
        [ -d "$d" ] || continue
        compgen -G "$d/maturin*" >/dev/null || continue
        [ -n "$(find "$d" -maxdepth 0 -mmin +60 2>/dev/null)" ] || continue
        info "removing stale pip build directory $d"
        rm -rf -- "$d"
    done
    shopt -u nullglob
}

# Compile maturin into a wheel and move it to MATURIN_CACHE/wheel once it
# validates. pip keeps build isolation (it fetches setuptools /
# setuptools-rust into its own build environment), but TMPDIR and
# CARGO_TARGET_DIR point at directories this script owns, so nothing lands in
# Rust/target. The detailed output goes to a log; the screen gets progress.
build_maturin_wheel() {
    local attempt log
    local -a built=()
    remove_stale_pip_dirs
    rm -rf -- "$MATURIN_CACHE/work"   # the layout before the target was kept
    rm -f "$MATURIN_CACHE"/build-attempt-*.log
    for attempt in $(seq 1 "$MATURIN_ATTEMPTS"); do
        log="$MATURIN_CACHE/build-attempt-$attempt.log"
        rm -rf -- "$MATURIN_CACHE/tmp" "$MATURIN_CACHE/out"
        if [ "$attempt" -eq "$MATURIN_ATTEMPTS" ] && [ "$attempt" -gt 1 ]; then
            info "last attempt: starting from an empty target directory"
            rm -rf -- "$MATURIN_CACHE/target"
        fi
        mkdir -p "$MATURIN_CACHE/tmp" "$MATURIN_CACHE/out" "$MATURIN_CACHE/target"
        info "compiling maturin $MATURIN_VERSION, attempt $attempt of $MATURIN_ATTEMPTS"
        info "  one compile job at a time; about $MATURIN_CRATES_APPROX crates; on a phone this"
        info "  takes a long time -- progress is printed every $HEARTBEAT_SECS s"
        info "  detailed output: $log"
        watch_start "$log" "maturin" always "$MATURIN_CRATES_APPROX"
        if env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS -u CARGO_BUILD_RUSTFLAGS \
               -u CARGO_BUILD_TARGET -u CARGO_BUILD_TARGET_DIR \
               TMPDIR="$MATURIN_CACHE/tmp" CARGO_TARGET_DIR="$MATURIN_CACHE/target" \
               CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 MATURIN_NO_INSTALL_RUST=1 \
               "$PY" -m pip wheel -v --no-deps \
                   --wheel-dir "$MATURIN_CACHE/out" "maturin==$MATURIN_VERSION" > "$log" 2>&1
        then
            watch_stop
            shopt -s nullglob
            built=("$MATURIN_CACHE/out/maturin-$MATURIN_VERSION-"*.whl)
            shopt -u nullglob
            if [ "${#built[@]}" -ne 1 ] || ! valid_maturin_wheel "${built[0]}"; then
                die "pip reported success but produced no valid maturin wheel in $MATURIN_CACHE/out"
            fi
            info "maturin compiled: $(grep -cE '^[[:space:]]*Compiling ' "$log" || true) crates"
            rm -rf -- "$MATURIN_CACHE/wheel"
            mkdir -p "$MATURIN_CACHE/wheel"
            mv -- "${built[0]}" "$MATURIN_CACHE/wheel/"
            rm -rf -- "$MATURIN_CACHE/tmp" "$MATURIN_CACHE/out" "$MATURIN_CACHE/target"
            return 0
        fi
        watch_stop
        if ! grep -Eq "$NOSPACE_RE" "$log" && grep -Eq "$RETRY_RE" "$log" \
                && [ "$attempt" -lt "$MATURIN_ATTEMPTS" ]; then
            if grep -Eq "$ETXTBSY_RE" "$log"; then
                info "attempt $attempt hit 'Text file busy' (ETXTBSY); retrying"
            else
                info "attempt $attempt: a compiler process was killed or ran out of memory; retrying"
            fi
            continue
        fi
        printf '\n--- last lines of %s:\n' "$log" >&2
        tail -n 40 "$log" >&2
        explain_failure "$log"
        if grep -Eq "$RETRY_RE" "$log"; then
            die "compiling maturin $MATURIN_VERSION failed $MATURIN_ATTEMPTS times. Full log: $log"
        fi
        die "compiling maturin $MATURIN_VERSION failed (a cause that retrying cannot fix). Full log: $log"
    done
}

# -------------------------------------------------------------- run log ---

on_exit() {
    local status=$?
    set +e
    watch_stop
    local p
    for p in ${CLEANUP_PATHS[@]+"${CLEANUP_PATHS[@]}"}; do rm -rf -- "$p"; done
    if [ -n "$WAKE_LOCKED" ]; then termux-wake-unlock >/dev/null 2>&1; fi
    if [ -n "$HAVE_LOCK" ]; then rm -rf -- "$LOCK_DIR"; fi
    if [ "$status" -ne 0 ] && [ -z "$DIED" ] && [ -z "$FINISHED" ]; then
        printf '\nBUILD FAILED: stopped (exit status %s) during "%s"\n' "$status" "${STEP_NAME:-start}"
        if [ -n "$LAST_ERR" ]; then printf -- '--- the command that failed: build.sh %s\n' "$LAST_ERR"; fi
        print_diagnostics
    fi
    if [ -n "$RUN_LOG" ]; then printf -- '--- full log: %s\n' "$RUN_LOG"; fi
    # Let tee write everything before the prompt comes back.
    if [ -n "$TEE_PID" ]; then
        exec 1>&- 2>&-
        wait "$TEE_PID" 2>/dev/null
    fi
}
trap on_exit EXIT
# Remember the command that failed, so an unexpected stop says where.
set -o errtrace
LAST_ERR=""
trap 'LAST_ERR="line $LINENO: $BASH_COMMAND"' ERR
trap 'printf "\n--- interrupted (Ctrl-C)\n"; exit 130' INT
trap 'printf "\n--- terminated\n"; exit 143' TERM

mkdir -p "$LOG_DIR" 2>/dev/null || { printf 'BUILD FAILED: cannot create %s\n' "$LOG_DIR" >&2; exit 1; }
if [ -e "$LOG_DIR/latest.log" ]; then
    PREV_LOG="$LOG_DIR/$(readlink "$LOG_DIR/latest.log" 2>/dev/null || true)"
fi
RUN_LOG="$LOG_DIR/build-$(date +%Y%m%d-%H%M%S)-$$.log"
: > "$RUN_LOG"
ln -sfn "$(basename "$RUN_LOG")" "$LOG_DIR/latest.log"
exec > >(tee -a "$RUN_LOG") 2>&1
TEE_PID=$!
# shellcheck disable=SC2012
ls -1t "$LOG_DIR"/build-*.log 2>/dev/null | tail -n +$((LOG_KEEP + 1)) | while read -r old; do rm -f -- "$old"; done

cd "$RUST_DIR"

# Nothing inherited from the calling shell may redirect the build to another
# Python, another PyO3 configuration or another module search path.
unset PYTHONPATH PYTHONHOME PYTHONSTARTUP PYTHONUSERBASE CONDA_PREFIX \
      PYO3_PYTHON PYO3_CONFIG_FILE PYO3_NO_PYTHON PYO3_CROSS \
      PYO3_CROSS_LIB_DIR PYO3_CROSS_PYTHON_VERSION PYO3_CROSS_PYTHON_IMPLEMENTATION \
      OTRV4PLUS_ALLOW_TEST_GATES OTRV4PLUS_ALLOW_LEGACY_DAKE_KEYS \
      OTRV4PLUS_ALLOW_RAW_KEY_TEST_API
export PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_INPUT=1

printf '=== otrv4_core build, %s ===\n' "$(date '+%Y-%m-%d %H:%M:%S')"
info "device: $(device_summary)"
info "log:    $RUN_LOG  (also: $LOG_DIR/latest.log)"

step "1/7 Prerequisites"
# One build at a time: a second one would wait on cargo's lock, silently.
if ! mkdir "$LOCK_DIR" 2>/dev/null; then
    other="$(cat "$LOCK_DIR/pid" 2>/dev/null || true)"
    if [ -n "$other" ] && kill -0 "$other" 2>/dev/null \
            && { [ ! -r "/proc/$other/cmdline" ] || tr '\0' ' ' < "/proc/$other/cmdline" | grep -q build.sh; }; then
        die "another build.sh is already running (pid $other). Let it finish, or stop it: kill $other"
    fi
    info "removing the lock of an earlier build.sh that is no longer running"
    rm -rf -- "$LOCK_DIR"
    mkdir "$LOCK_DIR" || die "cannot create $LOCK_DIR"
fi
echo "$$" > "$LOCK_DIR/pid"
HAVE_LOCK=1

# A previous run that left no result was stopped from outside.
if [ -n "$PREV_LOG" ] && [ -f "$PREV_LOG" ] && [ "$PREV_LOG" != "$RUN_LOG" ] \
        && ! grep -Eq '^(BUILD OK|BUILD FAILED)' "$PREV_LOG"; then
    notice "The previous build did not finish: it stopped without a result." \
        "Log: $PREV_LOG" \
        "Its last lines were:"
    tail -n 8 "$PREV_LOG" | sed 's/^/        /'
    if is_termux; then
        android_kill_advice "On a phone this usually means Android stopped Termux's processes."
    fi
    info "this run continues from the work already done"
fi

# Compilers left running by something else hold cargo's lock.
if [ -d /proc/self ]; then
    others="$(for f in /proc/[0-9]*/comm; do
        c="$(cat "$f" 2>/dev/null || true)"
        case "$c" in cargo|rustc) p="${f#/proc/}"; printf '%s ' "${p%/comm}" ;; esac
    done)"
    if [ -n "$others" ]; then
        notice "Other cargo/rustc processes are running (pid $others)." \
            "If they are left over from an earlier build, stop them first: kill $others" \
            "Otherwise this build waits for them."
    fi
fi

if is_termux; then
    info "platform: Termux ${TERMUX_VERSION:-(version unknown)} (PREFIX=${PREFIX:-unset})"
    PKG_HINT_RUST="pkg install rust"
    PKG_HINT_CC="pkg install clang"
    PKG_HINT_PY="pkg install python"
    # Keep the CPU awake while the screen is off.
    if command -v termux-wake-lock >/dev/null 2>&1; then
        if termux-wake-lock >/dev/null 2>&1; then
            WAKE_LOCKED=1
            info "holding a Termux wake lock until the build ends; keep Termux open"
        fi
    fi
    if [ -z "${CARGO_BUILD_JOBS:-}" ]; then
        cpus="$(nproc 2>/dev/null || echo 2)"
        export CARGO_BUILD_JOBS=$((cpus < TERMUX_MAX_JOBS ? cpus : TERMUX_MAX_JOBS))
        info "compile jobs: $CARGO_BUILD_JOBS of $cpus CPUs (fewer processes for Android to kill)"
    fi
else
    info "platform: $(uname -s) $(uname -m)"
    PKG_HINT_RUST="https://rustup.rs (or your distribution's rust/cargo)"
    PKG_HINT_CC="Debian/Ubuntu: apt install build-essential"
    PKG_HINT_PY="Debian/Ubuntu: apt install python3 python3-venv"
fi
command -v cargo >/dev/null || die "cargo not found. Install Rust: $PKG_HINT_RUST"
command -v rustc >/dev/null || die "rustc not found. Install Rust: $PKG_HINT_RUST"
rustc_at_least "$RUST_MIN" \
    || die "$(rustc --version) is older than $RUST_MIN, which the core needs. Update Rust: $PKG_HINT_RUST"
# The core's PQClean code (and maturin's zstd, when it is compiled) is C.
command -v cc >/dev/null || command -v clang >/dev/null || command -v gcc >/dev/null \
    || die "no C compiler (cc/clang/gcc) found. Install one: $PKG_HINT_CC"
command -v python3 >/dev/null || die "Python 3 not found. Install it: $PKG_HINT_PY"
BASE_PY="$(command -v python3)"
BASE_VER="$("$BASE_PY" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
"$BASE_PY" -c "import sys; sys.exit(0 if sys.version_info[:2] >= ($PY_MIN_MAJOR, $PY_MIN_MINOR) else 1)" \
    || die "$BASE_PY is Python $BASE_VER; OTRv4+ needs $PY_MIN_MAJOR.$PY_MIN_MINOR or newer"
info "rustc:  $(rustc --version)"
info "cargo:  $(cargo --version)"
info "python: $BASE_PY (Python $BASE_VER)"
cargo clippy --version >/dev/null 2>&1 \
    || die "cargo clippy not found. Termux: pkg install rust (it ships clippy)   rustup: rustup component add clippy"
# Creating the virtualenv needs venv and ensurepip (Debian splits them out).
if [ ! -x "$PY" ]; then
    "$BASE_PY" -c 'import venv, ensurepip' 2>/dev/null \
        || die "$BASE_PY cannot create a virtualenv (venv/ensurepip missing). Install: $PKG_HINT_PY"
fi
# On Termux maturin is compiled unless the virtualenv or the cache already has
# it; check now what that compile needs rather than fail inside it.
compile_maturin=""
if is_termux && ! have_maturin && ! cached_maturin_wheel >/dev/null; then
    compile_maturin=1
    info "maturin $MATURIN_VERSION will be compiled once (no installed copy, no cached wheel)"
    rustc_at_least "$MATURIN_RUST_MIN" \
        || die "$(rustc --version) is older than $MATURIN_RUST_MIN, which compiling maturin $MATURIN_VERSION needs. Update: pkg upgrade rust"
fi
mkdir -p "$MATURIN_CACHE" 2>/dev/null && [ -w "$MATURIN_CACHE" ] \
    || die "cannot write the build cache $MATURIN_CACHE (HOME=${HOME:-unset})"
# Space, before hours of compiling rather than after.
need_mb=600
[ -d "$RUST_DIR/target/release" ] || need_mb=$((need_mb + 1800))
[ -d "$RUST_DIR/mls/target/release" ] || need_mb=$((need_mb + 700))
[ -z "$compile_maturin" ] || need_mb=$((need_mb + 1200))
free_mb="$(avail_mb "$REPO_ROOT")"
if [ -n "$free_mb" ] && [ "$free_mb" -lt "$need_mb" ]; then
    die "this build needs about $need_mb MB of free storage; only $free_mb MB is free. Free some space (for example: pkg clean) and run bash build.sh again"
fi
info "storage: ${free_mb:-?} MB free (this build needs about $need_mb MB)"
info "memory:  $(mem_summary)"

step "2/7 Project virtualenv: $VENV"
recreate=""
if [ ! -e "$VENV" ]; then
    info "no virtualenv yet; creating it"
    recreate="new"
elif [ ! -f "$VENV/pyvenv.cfg" ] || [ ! -x "$PY" ] || ! "$PY" -c 'import sys' 2>/dev/null; then
    [ -f "$VENV/pyvenv.cfg" ] \
        || die "$VENV exists but is not a virtualenv; move it aside and run build.sh again"
    info "the virtualenv's interpreter no longer runs; recreating it"
    recreate="clear"
elif [ "$("$PY" -c 'import sys; print("%d.%d" % sys.version_info[:2])')" != "$BASE_VER" ]; then
    info "the virtualenv was made for another Python version; recreating it for $BASE_VER"
    recreate="clear"
elif ! grep -Eiq '^include-system-site-packages *= *true' "$VENV/pyvenv.cfg"; then
    info "the virtualenv cannot see the global modules the clients use; recreating it"
    recreate="clear"
fi
if [ -n "$recreate" ]; then
    args=(--system-site-packages)
    [ "$recreate" = "clear" ] && args+=(--clear)
    "$BASE_PY" -m venv "${args[@]}" "$VENV" \
        || die "could not create $VENV. Install: $PKG_HINT_PY"
fi
"$PY" -c 'import sys; sys.exit(0 if sys.prefix != sys.base_prefix else 1)' \
    || die "$PY is not running inside $VENV"
if ! "$PY" -m pip --version >/dev/null 2>&1; then
    info "pip missing in the virtualenv; bootstrapping it with ensurepip"
    "$PY" -m ensurepip --upgrade >/dev/null \
        || die "could not install pip into $VENV. Install: $PKG_HINT_PY"
fi
info "interpreter: $PY ($("$PY" -c 'import sys; print(sys.version.split()[0])'))"

# The clients' own Python modules, into the virtualenv when they are not
# already importable from it. Installed HERE because Debian and Ubuntu (and
# others following PEP 668) refuse `pip install` into the system Python
# ("externally-managed-environment"), while a virtualenv is always allowed.
# On Termux a global install is seen through --system-site-packages and
# nothing is fetched. The versions are the ones the APK ships.
if ! "$PY" -c 'import socks, slixmpp' 2>/dev/null; then
    info "installing the clients' Python modules into the virtualenv: PySocks, slixmpp (with aiodns)"
    "$PY" -m pip install --disable-pip-version-check -q "PySocks==1.7.1" "slixmpp==1.17.0" \
        || die "could not install PySocks and slixmpp into $VENV (network?). By hand: $PY -m pip install PySocks slixmpp"
fi
info "client modules: PySocks and slixmpp importable"

# Every later step -- cargo's PyO3 build scripts, maturin, the checks -- uses
# this interpreter and this environment.
export VIRTUAL_ENV="$VENV"
export PATH="$VENV/bin:$PATH"
export PYO3_PYTHON="$PY"
hash -r
# The Android API level for the wheel's platform tag: the one this Python was
# built for, which is exactly what its pip accepts. maturin's own guess reads
# the kernel's name, which not every Android kernel carries.
if is_termux && [ -z "${ANDROID_API_LEVEL:-}" ]; then
    api="$("$PY" -c 'import sys; print(sys.getandroidapilevel())' 2>/dev/null \
           || (clang -dumpmachine 2>/dev/null | sed -n 's/.*android\([0-9][0-9]*\)$/\1/p') || true)"
    if [ -n "$api" ]; then
        export ANDROID_API_LEVEL="$api"
        info "Android API level for the wheel: $ANDROID_API_LEVEL"
    fi
fi

step "3/7 Build tool: maturin $MATURIN_VERSION (in the virtualenv)"
if have_maturin; then
    info "already installed"
elif is_termux; then
    wheel="$(cached_maturin_wheel || true)"
    if [ -n "$wheel" ] && valid_maturin_wheel "$wheel" && install_maturin_wheel "$wheel"; then
        info "installed from the cached wheel $wheel"
    else
        if [ -n "$wheel" ]; then
            info "the cached wheel $wheel is unusable; discarding it"
        fi
        rm -rf -- "$MATURIN_CACHE/wheel"
        build_maturin_wheel
        wheel="$(cached_maturin_wheel)" || die "no maturin wheel in $MATURIN_CACHE/wheel after building it"
        info "installing $(basename "$wheel") into $VENV"
        install_maturin_wheel "$wheel" \
            || die "the freshly built $wheel did not install as maturin $MATURIN_VERSION into $VENV"
    fi
else
    info "installing maturin==$MATURIN_VERSION into $VENV"
    # --ignore-installed: a global maturin of the same version must not
    # satisfy this; the build uses $MATURIN and nothing else.
    log="$(mktemp)"
    CLEANUP_PATHS+=("$log")
    if ! "$PY" -m pip install --ignore-installed "maturin==$MATURIN_VERSION" 2>&1 | tee "$log"; then
        explain_failure "$log"
        die "pip could not install maturin==$MATURIN_VERSION into $VENV (output above)"
    fi
    have_maturin || die "maturin in $VENV is not version $MATURIN_VERSION after installing it"
fi
info "$("$MATURIN" --version) at $MATURIN"

step "4/7 Rust release tests"
info "otrv4_core"
cargo_clean_output cargo test --release
info "otrv4-mls (secure groups)"
run_in "$RUST_DIR/mls" cargo_clean_output cargo test --release

step "5/7 Clippy (-D warnings)"
info "otrv4_core, all targets, the feature set this build ships (mls)"
cargo_clean_output cargo clippy --release --all-targets --features mls -- -D warnings
info "otrv4-mls, all targets, all features"
run_in "$RUST_DIR/mls" cargo_clean_output cargo clippy --release --all-targets --all-features -- -D warnings

# Where the system Python (with its user site) finds an otrv4_core, or
# nothing. Run from / so the repository is not on the path.
outside_core() {
    (cd / && "$BASE_PY" -c 'import importlib.util as u
s = u.find_spec("otrv4_core")
print(s.origin if s and s.origin else "")' 2>/dev/null) || true
}

# One core: this build's, in .venv. Older ones installed into the system
# Python (pip install ./Rust, or a copied .so) are removed, because
# `python otrv4plus_xmpp.py` would load them instead. pip removes what it
# installed; a module copied by hand is deleted only when it is plainly an
# otrv4_core file or directory inside a site-packages directory.
remove_outside_cores() {
    local where before ver target round out
    out="$(mktemp)"
    CLEANUP_PATHS+=("$out")
    for round in 1 2 3 4; do
        where="$(outside_core)"
        [ -n "$where" ] || return 0
        ver="$(cd / && "$BASE_PY" -m pip show otrv4_core 2>/dev/null | sed -n 's/^Version: //p' || true)"
        info "removing an older otrv4_core${ver:+ $ver} from the system Python: $where"
        before="$where"
        "$BASE_PY" -m pip uninstall -y --break-system-packages otrv4_core > "$out" 2>&1 \
            || "$BASE_PY" -m pip uninstall -y otrv4_core >> "$out" 2>&1 || true
        where="$(outside_core)"
        if [ "$where" = "$before" ]; then
            # Not something pip installed: a module copied into place.
            target="$where"
            case "$target" in */__init__.py) target="${target%/__init__.py}" ;; esac
            case "$(basename "$(dirname "$target")")/$(basename "$target")" in
                site-packages/otrv4_core*|dist-packages/otrv4_core*)
                    rm -rf -- "$target" 2>>"$out" || true ;;
            esac
            if [ "$(outside_core)" = "$before" ]; then
                sed 's/^/        /' "$out"
                notice "Could not remove the older otrv4_core at:" \
                    "  $before" \
                    "Start the clients with .venv/bin/python, which uses this build;" \
                    "'python otrv4plus_xmpp.py' would load the old copy. Remove it by hand:" \
                    "  rm -rf '$target'"
                return 0
            fi
        fi
        [ "$round" -lt 4 ] || break
    done
    if [ -n "$(outside_core)" ]; then
        notice "An older otrv4_core is still found by the system Python at $(outside_core)."
    fi
}

step "6/7 MLS-enabled release build, installed into the virtualenv"
# Take out anything a previous build left where Python would find it first,
# so the import check below can only succeed with what is built now.
old_location="$(cd / && "$PY" -c 'import sys, importlib.util as u
s = u.find_spec("otrv4_core")
print(s.origin if s and s.origin else "")' 2>/dev/null || true)"
case "$old_location" in
    "$VENV"/*)
        info "removing the previously installed otrv4_core from $VENV"
        "$PY" -m pip uninstall -y otrv4_core >/dev/null \
            || die "could not uninstall the old otrv4_core from $VENV" ;;
esac
shopt -s nullglob
for stale in "$REPO_ROOT"/otrv4_core*.so "$REPO_ROOT"/otrv4_core*.pyd; do
    # The old `cargo build && cp ... ../otrv4_core.so` recipe put it here. The
    # clients run from the repository root, which Python searches before
    # site-packages, so it would shadow the module installed below.
    info "removing stale $stale (it would shadow the fresh build)"
    rm -f -- "$stale"
done
shopt -u nullglob
remove_outside_cores
# A regular wheel, installed the way `maturin develop` installs one (pip
# --no-deps --force-reinstall), but not editable: the editable path adds every
# native link-search directory to the rpath, which here is only
# pqcrypto-internals' target/ directory -- its C code is a static archive, so
# the rpath would do nothing except embed a build-machine path in the module.
WHEEL_DIR="$(mktemp -d)"
CLEANUP_PATHS+=("$WHEEL_DIR")
cargo_clean_output "$MATURIN" build --release --features mls \
    --interpreter "$PY" --out "$WHEEL_DIR"
shopt -s nullglob
wheels=("$WHEEL_DIR"/otrv4_core-*.whl)
shopt -u nullglob
[ "${#wheels[@]}" -eq 1 ] || die "expected one otrv4_core wheel in $WHEEL_DIR, found ${#wheels[@]}"
wheel_fits_python "${wheels[0]}" \
    || die "the built wheel $(basename "${wheels[0]}") does not match this Python's platform (tags above)"
info "installing $(basename "${wheels[0]}") into $VENV"
# --ignore-installed: the old copies are already gone (above), and pip must
# not go looking for one outside .venv.
"$PY" -m pip install --no-deps --ignore-installed "${wheels[0]}" \
    || die "pip could not install ${wheels[0]} into $VENV"

step "7/7 Checks: import, client API, MLS, both clients (IRC and XMPP)"
# Run from the repository root, as the clients are run, so a module anywhere
# Python looks first would be found -- and refused.
(cd "$REPO_ROOT" && OTRV4PLUS_VENV="$VENV" "$PY" - <<'PYEOF'
import os
import sys

venv = os.path.realpath(os.environ["OTRV4PLUS_VENV"])

def inside_venv(path):
    return os.path.commonpath([os.path.realpath(path), venv]) == venv

def fail(msg):
    print("IMPORT CHECK FAILED: " + msg, file=sys.stderr)
    sys.exit(1)

if not inside_venv(sys.prefix):
    fail("interpreter prefix %s is not %s" % (sys.prefix, venv))
try:
    import otrv4_core
except ImportError as exc:
    fail("import otrv4_core: %s" % exc)

paths = [otrv4_core.__file__]
native = getattr(otrv4_core, "otrv4_core", None)  # the compiled extension
if native is not None and getattr(native, "__file__", None):
    paths.append(native.__file__)
for p in paths:
    print("module path: " + os.path.realpath(p))
    if not inside_venv(p):
        fail("otrv4_core was loaded from %s, outside %s -- a stale or global "
             "copy is shadowing the fresh build" % (p, venv))
print("otrv4_core imported OK")
mls = hasattr(otrv4_core, "RustMlsClient")
print("secure groups (MLS): " + ("yes" if mls else "NO"))
if not mls:
    fail("RustMlsClient missing: the module was built without --features mls")

# Every core function the clients call, and the secure-groups adapter.
try:
    import otrv4plus_coreapi
    import otrv4plus_groups  # noqa: F401  (the /group commands)
except ImportError as exc:
    fail("the client modules do not import: %s" % exc)
missing = otrv4plus_coreapi.missing_core_api(otrv4_core)
if missing:
    fail("the core lacks functions the clients call: %s" % ", ".join(missing))
print("client API check: OK")

# MLS on this device, in memory: two members, one group, one message.
try:
    a = otrv4_core.RustMlsClient(b"build-selftest-a")
    b = otrv4_core.RustMlsClient(b"build-selftest-b")
    g = b"otrv4plus-build-selftest"
    a.create_group(g)
    ev = a.process(g, bytes(a.add_members(g, [bytes(b.key_package())])))
    assert ev["kind"] == "commit" and ev["ours"] and ev["welcome"], ev["kind"]
    assert bytes(b.join(bytes(ev["welcome"]))) == g
    out = b.process(g, bytes(a.encrypt(g, b"mls self-test")))
    assert out["kind"] == "application" and bytes(out["plaintext"]) == b"mls self-test"
    # Every new group is the hybrid suite (X448+ML-KEM-1024 / Ed448+ML-DSA-87).
    assert a.ciphersuite(g) == 0xF0A1, hex(a.ciphersuite(g))
    # Group voice keys from the epoch: one frame each way.
    va, vb = a.group_voice(g, b"selftest-call"), b.group_voice(g, b"selftest-call")
    assert bytes(vb.open(bytes(va.seal(b"frame")))[1]) == b"frame"
    va.zeroize()
    vb.zeroize()
    a.wipe()
    b.wipe()
except Exception as exc:
    fail("MLS self-test: %s: %s" % (type(exc).__name__, exc))
print("MLS self-test (2 members, 1 message, hybrid suite, group voice): OK")

# Both clients load the engine, otrv4+.py (the IRC client; the XMPP client
# imports it as otrv4plus). Its import-time check names every core entry
# point the 1:1 path needs (DAKE, ring signatures, key handles).
import importlib.util
for name, path in (("otrv4plus", "otrv4+.py"),):
    try:
        spec = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
    except Exception as exc:
        fail("the engine (%s) does not load with this core: %s: %s"
             % (path, type(exc).__name__, exc))
print("IRC client / OTRv4+ engine (otrv4+.py): OK")
try:
    import otrv4plus_xmpp  # noqa: F401
except Exception as exc:
    fail("the XMPP client does not load: %s: %s" % (type(exc).__name__, exc))
print("XMPP client (otrv4plus_xmpp.py): OK")
PYEOF
) || die "the installed module did not pass the checks above"

step "Done"
FINISHED=1
printf '\nBUILD OK in %s\n' "$(fmt_secs $(($(now) - BUILD_T0)))"
info "run the clients from the repository root:"
info "  XMPP: cd $REPO_ROOT && PYTHONMALLOC=malloc .venv/bin/python otrv4plus_xmpp.py --jid ..."
info "  IRC:  cd $REPO_ROOT && PYTHONMALLOC=malloc .venv/bin/python otrv4+.py -n <nick> -s <server>"
info "('python otrv4+.py' and 'python otrv4plus_xmpp.py' also work: they switch to .venv/bin/python)"
