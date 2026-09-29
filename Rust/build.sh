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
# MLS-enabled release build installed into .venv, and an import check that
# proves the module Python loads is the one just built, from .venv.
#
# Run the clients with the same interpreter afterwards:
#     cd ~/OTRv4Plus && .venv/bin/python otrv4plus_xmpp.py ...
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
# PyPI has no maturin wheel Termux's pip can use, so pip compiles it (255
# crates). Cargo runs each build script from target/.../build-script-build,
# which it normally hard-links into place. Android refuses hard links in an
# app's data directory, so cargo copies the file instead -- with the copy
# open for writing in cargo's own process. A parallel job forked in that
# moment inherits the open file until it execs, and executing the build
# script then fails with
#     could not execute process `.../build-script-build` (never executed)
#     Text file busy (os error 26)
# The maturin build therefore runs with CARGO_BUILD_JOBS=1, in a temp and
# target directory this script owns and empties before every attempt (not
# pip's throwaway pip-install-* directory), retried at most MATURIN_ATTEMPTS
# times and only for that error. The finished wheel is checked and cached,
# so this happens once. The project's own cargo commands retry the same way.

set -euo pipefail

MATURIN_VERSION="1.13.3"
PY_MIN_MAJOR=3
PY_MIN_MINOR=12
RUST_MIN="1.85"          # the core's rust-version (Cargo.toml)
MATURIN_RUST_MIN="1.89"  # maturin 1.13.3's rust-version, when compiling it
MATURIN_ATTEMPTS=3       # bounded: only "Text file busy" is retried
CARGO_ATTEMPTS=3

RUST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$RUST_DIR/.." && pwd -P)"
VENV="$REPO_ROOT/.venv"
PY="$VENV/bin/python"
MATURIN="$VENV/bin/maturin"
MATURIN_CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/otrv4plus/maturin-$MATURIN_VERSION"

step() { printf '\n=== %s ===\n' "$*"; }
info() { printf -- '--- %s\n' "$*"; }
die()  { printf '\nBUILD FAILED: %s\n' "$*" >&2; exit 1; }

# Termux, not merely "some Android": its prefix, or the variable the Termux
# app exports.
is_termux() {
    case "${PREFIX:-}" in */com.termux/*) return 0 ;; esac
    [ -n "${TERMUX_VERSION:-}" ]
}

# `rustc 1.94.1 (...)` -> succeeds when at least $1.
rustc_at_least() {
    local have
    have="$(rustc --version | awk '{print $2}')"
    [ "$(printf '%s\n%s\n' "$1" "${have%%-*}" | sort -V | head -n1)" = "$1" ]
}

ETXTBSY_RE='Text file busy|os error 26'

# Run a cargo or maturin command and fail on any warning it prints: rustc's
# `warning:` lines and maturin's `⚠️ Warning:` lines. The production build is
# warning-free; a new warning is a failure, not noise.
#
# "Text file busy" (see the note at the top) is retried, at most
# CARGO_ATTEMPTS times in all, serially; cargo resumes where it stopped.
# Every other failure fails at once.
WARNING_RE='^(warning|error)(\[[A-Za-z0-9_]+\])?:|⚠'
cargo_clean_output() {
    local log attempt=1
    local -a prefix=()
    log="$(mktemp)"
    while ! ${prefix[@]+"${prefix[@]}"} "$@" 2>&1 | tee "$log"; do
        if grep -Eq "$ETXTBSY_RE" "$log" && [ "$attempt" -lt "$CARGO_ATTEMPTS" ]; then
            attempt=$((attempt + 1))
            info "cargo hit 'Text file busy' (ETXTBSY); retrying serially, attempt $attempt of $CARGO_ATTEMPTS"
            prefix=(env CARGO_BUILD_JOBS=1)
            continue
        fi
        rm -f "$log"
        die "'$*' failed (output above)"
    done
    if grep -Eq "$WARNING_RE" "$log"; then
        grep -E "$WARNING_RE" "$log" | sort | uniq -c >&2
        rm -f "$log"
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

# The one cached wheel, if there is exactly one.
cached_maturin_wheel() {
    local -a found=()
    shopt -s nullglob
    found=("$MATURIN_CACHE"/wheel/maturin-"$MATURIN_VERSION"-*.whl)
    shopt -u nullglob
    [ "${#found[@]}" -eq 1 ] && printf '%s\n' "${found[0]}"
}

install_maturin_wheel() {
    "$PY" -m pip install --disable-pip-version-check --no-index --no-deps \
        --ignore-installed "$1" && have_maturin
}

# pip's own temp directories left by an earlier, killed maturin build (the
# failure this replaces used them). Only directories holding a maturin source
# tree and untouched for an hour, so a concurrent pip is never disturbed.
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

# Compile maturin into a wheel in MATURIN_CACHE/work and move it to
# MATURIN_CACHE/wheel once it validates. pip keeps build isolation (it fetches
# setuptools / setuptools-rust into its own build environment), but TMPDIR and
# CARGO_TARGET_DIR point at directories this script owns and empties first, so
# nothing half-built survives an attempt, and nothing lands in Rust/target.
build_maturin_wheel() {
    local work="$MATURIN_CACHE/work" attempt log
    local -a built=()
    remove_stale_pip_dirs
    rm -f "$MATURIN_CACHE"/build-attempt-*.log
    for attempt in $(seq 1 "$MATURIN_ATTEMPTS"); do
        rm -rf -- "$work"
        mkdir -p "$work/tmp" "$work/target" "$work/out"
        log="$MATURIN_CACHE/build-attempt-$attempt.log"
        info "compiling maturin $MATURIN_VERSION, attempt $attempt of $MATURIN_ATTEMPTS"
        info "  serial cargo (CARGO_BUILD_JOBS=1), temp and target under $work"
        info "  this takes a while on a phone; the log is $log"
        if env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS -u CARGO_BUILD_RUSTFLAGS \
               -u CARGO_BUILD_TARGET -u CARGO_BUILD_TARGET_DIR \
               TMPDIR="$work/tmp" CARGO_TARGET_DIR="$work/target" \
               CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 \
               MATURIN_NO_INSTALL_RUST=1 PIP_NO_INPUT=1 \
               "$PY" -m pip wheel --disable-pip-version-check --no-deps \
                   --wheel-dir "$work/out" "maturin==$MATURIN_VERSION" 2>&1 | tee "$log"
        then
            shopt -s nullglob
            built=("$work/out"/maturin-"$MATURIN_VERSION"-*.whl)
            shopt -u nullglob
            [ "${#built[@]}" -eq 1 ] && valid_maturin_wheel "${built[0]}" \
                || die "pip reported success but produced no valid maturin wheel in $work/out"
            rm -rf -- "$MATURIN_CACHE/wheel"
            mkdir -p "$MATURIN_CACHE/wheel"
            mv -- "${built[0]}" "$MATURIN_CACHE/wheel/"
            rm -rf -- "$work"
            return 0
        fi
        if grep -Eq "$ETXTBSY_RE" "$log" && [ "$attempt" -lt "$MATURIN_ATTEMPTS" ]; then
            info "attempt $attempt hit 'Text file busy' (ETXTBSY); emptying $work and retrying"
            continue
        fi
        rm -rf -- "$work"
        printf '\n--- last lines of %s:\n' "$log" >&2
        tail -n 40 "$log" >&2
        if grep -Eq "$ETXTBSY_RE" "$log"; then
            die "maturin $MATURIN_VERSION still hit 'Text file busy' after $MATURIN_ATTEMPTS serial attempts. Full log: $log"
        fi
        die "compiling maturin $MATURIN_VERSION failed (not ETXTBSY; not retried). Full log: $log"
    done
}

cd "$RUST_DIR"

# Nothing inherited from the calling shell may redirect the build to another
# Python, another PyO3 configuration or another module search path.
unset PYTHONPATH PYTHONHOME PYTHONSTARTUP PYTHONUSERBASE CONDA_PREFIX \
      PYO3_PYTHON PYO3_CONFIG_FILE PYO3_NO_PYTHON PYO3_CROSS \
      PYO3_CROSS_LIB_DIR PYO3_CROSS_PYTHON_VERSION PYO3_CROSS_PYTHON_IMPLEMENTATION \
      OTRV4PLUS_ALLOW_TEST_GATES OTRV4PLUS_ALLOW_LEGACY_DAKE_KEYS \
      OTRV4PLUS_ALLOW_RAW_KEY_TEST_API

step "1/7 Prerequisites"
if is_termux; then
    info "platform: Termux (PREFIX=${PREFIX:-unset})"
    PKG_HINT_RUST="pkg install rust"
    PKG_HINT_CC="pkg install clang"
    PKG_HINT_PY="pkg install python"
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
if is_termux && ! have_maturin && ! cached_maturin_wheel >/dev/null; then
    info "maturin $MATURIN_VERSION will be compiled once (no installed copy, no cached wheel)"
    rustc_at_least "$MATURIN_RUST_MIN" \
        || die "$(rustc --version) is older than $MATURIN_RUST_MIN, which compiling maturin $MATURIN_VERSION needs. Update: pkg upgrade rust"
fi
if is_termux; then
    mkdir -p "$MATURIN_CACHE" 2>/dev/null && [ -w "$MATURIN_CACHE" ] \
        || die "cannot write the build cache $MATURIN_CACHE (HOME=${HOME:-unset})"
    info "maturin cache: $MATURIN_CACHE"
fi
info "rustc:  $(rustc --version)"

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
        || die "could not create $VENV. Debian/Ubuntu: apt install python3-venv"
fi
"$PY" -c 'import sys; sys.exit(0 if sys.prefix != sys.base_prefix else 1)' \
    || die "$PY is not running inside $VENV"
if ! "$PY" -m pip --version >/dev/null 2>&1; then
    info "pip missing in the virtualenv; bootstrapping it with ensurepip"
    "$PY" -m ensurepip --upgrade >/dev/null \
        || die "could not install pip into $VENV. Debian/Ubuntu: apt install python3-venv"
fi
info "interpreter: $PY ($("$PY" -c 'import sys; print(sys.version.split()[0])'))"

# Every later step -- cargo's PyO3 build scripts, maturin, the import check --
# uses this interpreter and this environment.
export VIRTUAL_ENV="$VENV"
export PATH="$VENV/bin:$PATH"
export PYO3_PYTHON="$PY"
hash -r

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
    info "(on Termux pip compiles it from source: this takes several minutes once)"
    # --ignore-installed: a global maturin of the same version must not
    # satisfy this; the build uses $MATURIN and nothing else.
    "$PY" -m pip install --disable-pip-version-check --ignore-installed \
        "maturin==$MATURIN_VERSION" \
        || die "pip could not install maturin==$MATURIN_VERSION into $VENV (output above)"
    have_maturin || die "maturin in $VENV is not version $MATURIN_VERSION after installing it"
fi
info "$("$MATURIN" --version) at $MATURIN"

step "4/7 Rust release tests"
info "otrv4_core"
cargo_clean_output cargo test --release
info "otrv4-mls (secure groups)"
(cd "$RUST_DIR/mls" && cargo_clean_output cargo test --release)

step "5/7 Clippy (-D warnings)"
info "otrv4_core, all targets, the feature set this build ships (mls)"
cargo_clean_output cargo clippy --release --all-targets --features mls -- -D warnings
info "otrv4-mls, all targets, all features"
(cd "$RUST_DIR/mls" && cargo_clean_output cargo clippy --release --all-targets --all-features -- -D warnings)

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
# A regular wheel, installed the way `maturin develop` installs one (pip
# --no-deps --force-reinstall), but not editable: the editable path adds every
# native link-search directory to the rpath, which here is only
# pqcrypto-internals' target/ directory -- its C code is a static archive, so
# the rpath would do nothing except embed a build-machine path in the module.
WHEEL_DIR="$(mktemp -d)"
trap 'rm -rf "$WHEEL_DIR"' EXIT
cargo_clean_output "$MATURIN" build --release --features mls \
    --interpreter "$PY" --out "$WHEEL_DIR"
shopt -s nullglob
wheels=("$WHEEL_DIR"/otrv4_core-*.whl)
shopt -u nullglob
[ "${#wheels[@]}" -eq 1 ] || die "expected one otrv4_core wheel in $WHEEL_DIR, found ${#wheels[@]}"
info "installing $(basename "${wheels[0]}") into $VENV"
"$PY" -m pip install --disable-pip-version-check --no-deps --force-reinstall "${wheels[0]}" \
    || die "pip could not install ${wheels[0]} into $VENV"

step "7/7 Import check"
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
PYEOF
) || die "the installed module did not pass the import check"

step "Done"
info "run the clients with the project interpreter, from the repository root:"
info "  cd $REPO_ROOT && PYTHONMALLOC=malloc .venv/bin/python otrv4plus_xmpp.py --jid ..."
