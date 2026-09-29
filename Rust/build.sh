#!/usr/bin/env bash
# Build, check and install otrv4_core (with secure groups / MLS) for the
# terminal clients on Termux or Linux.
#
#     cd ~/OTRv4Plus/Rust
#     bash build.sh
#
# Prerequisites: Python 3.12+ and Rust. Termux: `pkg install python rust`.
# Everything else is set up here, in the repository, and nowhere else:
#
#   * the project virtualenv ~/OTRv4Plus/.venv (created if missing, recreated
#     if it no longer matches this Python) -- never activated in your shell.
#     It can see the global site-packages, so the clients' runtime modules
#     (slixmpp, PySocks, Termux's python-cryptography, ...) need no second
#     install, but otrv4_core and the build tool are its own and come first;
#   * the pinned build tool, maturin (MATURIN_VERSION below), inside that
#     virtualenv; a globally installed maturin is never used.
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

set -euo pipefail

MATURIN_VERSION="1.13.3"
PY_MIN_MAJOR=3
PY_MIN_MINOR=12

RUST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$RUST_DIR/.." && pwd -P)"
VENV="$REPO_ROOT/.venv"
PY="$VENV/bin/python"
MATURIN="$VENV/bin/maturin"

step() { printf '\n=== %s ===\n' "$*"; }
info() { printf -- '--- %s\n' "$*"; }
die()  { printf '\nBUILD FAILED: %s\n' "$*" >&2; exit 1; }

# Run a cargo or maturin command and fail on any warning it prints: rustc's
# `warning:` lines and maturin's `⚠️ Warning:` lines. The production build is
# warning-free; a new warning is a failure, not noise.
WARNING_RE='^(warning|error)(\[[A-Za-z0-9_]+\])?:|⚠'
cargo_clean_output() {
    local log
    log="$(mktemp)"
    if ! "$@" 2>&1 | tee "$log"; then
        rm -f "$log"
        die "'$*' failed (output above)"
    fi
    if grep -Eq "$WARNING_RE" "$log"; then
        grep -E "$WARNING_RE" "$log" | sort | uniq -c >&2
        rm -f "$log"
        die "'$*' printed compiler warnings; the production build must have none"
    fi
    rm -f "$log"
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
command -v cargo >/dev/null \
    || die "Rust not found. Termux: pkg install rust   Linux: https://rustup.rs"
command -v python3 >/dev/null \
    || die "Python 3 not found. Termux: pkg install python   Debian/Ubuntu: apt install python3 python3-venv"
BASE_PY="$(command -v python3)"
BASE_VER="$("$BASE_PY" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
"$BASE_PY" -c "import sys; sys.exit(0 if sys.version_info[:2] >= ($PY_MIN_MAJOR, $PY_MIN_MINOR) else 1)" \
    || die "$BASE_PY is Python $BASE_VER; OTRv4+ needs $PY_MIN_MAJOR.$PY_MIN_MINOR or newer"
info "cargo:  $(cargo --version)"
info "python: $BASE_PY (Python $BASE_VER)"
cargo clippy --version >/dev/null 2>&1 \
    || die "cargo clippy not found. Termux: pkg install rust (it ships clippy)   rustup: rustup component add clippy"

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
have_maturin() {
    [ -x "$MATURIN" ] && [ "$("$MATURIN" --version 2>/dev/null)" = "maturin $MATURIN_VERSION" ]
}
if have_maturin; then
    info "already installed"
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
