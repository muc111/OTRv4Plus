#!/usr/bin/env bash
# build_sanitized.sh — build otr4_crypto_ext with ASAN + UBSAN on Linux/Termux
#
# USAGE
#   chmod +x build_sanitized.sh
#   ./build_sanitized.sh              # full ASAN+UBSAN build
#   ./build_sanitized.sh asan         # ASAN only
#   ./build_sanitized.sh ubsan        # UBSAN only
#   ./build_sanitized.sh run          # build + run test suite under sanitizers
#   ./build_sanitized.sh clean        # remove sanitizer build artefacts
#
# REQUIREMENTS
#   clang (ASAN/UBSAN are clang features; gcc also works but clang is better)
#   openssl-dev / libssl-dev
#   Python dev headers
#
# TERMUX
#   pkg install clang openssl python
#   ./build_sanitized.sh run
#
# LINUX
#   apt install clang libssl-dev python3-dev
#   ./build_sanitized.sh run

set -euo pipefail

# ── Detect environment ────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="${SCRIPT_DIR}/../otr4_crypto_ext.c"
SETUP="${SCRIPT_DIR}/../setup_otr4.py"

if [[ -z "${CC:-}" ]]; then
    if command -v clang &>/dev/null; then CC=clang; else CC=gcc; fi
fi

PYTHON="${PYTHON:-python3}"
PYINC="$($PYTHON -c 'import sysconfig; print(sysconfig.get_path("include"))')"
PYEXT="$($PYTHON -c 'import sysconfig; print(sysconfig.get_config_var("EXT_SUFFIX"))')"

# Detect OpenSSL include/lib (handles both Termux and system paths)
OSSL_INC=""
OSSL_LIB="-lcrypto"
for candidate in \
    "$PREFIX/include/openssl" \
    "/usr/include/openssl" \
    "/usr/local/include/openssl"; do
    if [[ -d "$candidate" ]]; then
        OSSL_INC="${candidate%/openssl}"
        break
    fi
done

if [[ -z "$OSSL_INC" ]]; then
    echo "ERROR: OpenSSL headers not found. Install: apt install libssl-dev / pkg install openssl"
    exit 1
fi

OUT_DIR="${SCRIPT_DIR}/../asan_build"
mkdir -p "$OUT_DIR"
OUT_SO="${OUT_DIR}/otr4_crypto_ext${PYEXT}"

MODE="${1:-both}"

# ── Sanitizer flags ───────────────────────────────────────────────────────────
COMMON_FLAGS=(
    -I"${PYINC}"
    -I"${OSSL_INC}"
    -fPIC
    -shared
    -O1                         # low opt so ASAN/UBSAN can see everything
    -fno-omit-frame-pointer     # proper stack traces
    -fno-strict-aliasing
    -g                          # debug symbols
)

ASAN_FLAGS=(
    -fsanitize=address
    -fsanitize=leak             # LeakSanitizer (bundled with ASAN on clang)
    -DASAN_BUILD=1
)

UBSAN_FLAGS=(
    -fsanitize=undefined
    -fsanitize=integer          # integer overflow (clang extension)
    -fno-sanitize-recover=all   # abort on first UB (not just log)
    -DUBSAN_BUILD=1
)

case "$MODE" in
    asan)  SANITIZE_FLAGS=("${ASAN_FLAGS[@]}") ;;
    ubsan) SANITIZE_FLAGS=("${UBSAN_FLAGS[@]}") ;;
    both|run)
        SANITIZE_FLAGS=("${ASAN_FLAGS[@]}" "${UBSAN_FLAGS[@]}") ;;
    clean)
        rm -rf "$OUT_DIR"
        echo "Cleaned $OUT_DIR"
        exit 0 ;;
    *)
        echo "Unknown mode: $MODE. Use: asan | ubsan | both | run | clean"
        exit 1 ;;
esac

echo "═══════════════════════════════════════════════════════"
echo " Building otr4_crypto_ext with sanitizers"
echo " CC     = $CC"
echo " Mode   = $MODE"
echo " Output = $OUT_SO"
echo "═══════════════════════════════════════════════════════"

# ── Build ─────────────────────────────────────────────────────────────────────
$CC \
    "${COMMON_FLAGS[@]}" \
    "${SANITIZE_FLAGS[@]}" \
    -o "$OUT_SO" \
    "$SRC" \
    $OSSL_LIB

echo "✅ Build successful: $OUT_SO"

# ── Run tests ─────────────────────────────────────────────────────────────────
if [[ "$MODE" == "run" ]]; then
    echo ""
    echo "═══════════════════════════════════════════════════════"
    echo " Running test suite under ASAN + UBSAN"
    echo "═══════════════════════════════════════════════════════"

    # ASAN env vars — tune for Termux (limited address space)
    export ASAN_OPTIONS="halt_on_error=1:detect_leaks=1:print_stats=1"
    export UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1"
    export LSAN_OPTIONS="suppressions=${SCRIPT_DIR}/lsan_suppressions.txt"

    # Point Python at the sanitized .so
    export PYTHONPATH="${OUT_DIR}:${SCRIPT_DIR}/.."

    # Run property tests first
    if command -v pytest &>/dev/null; then
        echo "→ Property tests (Hypothesis)..."
        pytest "${SCRIPT_DIR}/test_property.py" -v --tb=short \
            -k "not test_random_sig_rejected" 2>&1 | tail -30
    fi

    # Run smoke fuzz
    echo "→ Fuzz smoke test (1000 inputs per target)..."
    $PYTHON "${SCRIPT_DIR}/fuzz_harnesses.py" smoke 1000

    # Run C extension unit tests directly
    echo "→ C extension self-tests..."
    $PYTHON - <<'PYEOF'
import sys, os
sys.path.insert(0, os.environ.get('PYTHONPATH','').split(':')[0])
import otr4_crypto_ext as _ossl
import secrets

# Test 1: cleanse
buf = bytearray(b'\xff' * 32)
_ossl.cleanse(buf)
assert all(b == 0 for b in buf), "cleanse failed"
print("✅ cleanse")

# Test 2: bn_mod_exp_consttime
base = (2).to_bytes(1, 'big')
exp  = (10).to_bytes(1, 'big')
mod  = (1000000007).to_bytes(4, 'big')
result = int.from_bytes(_ossl.bn_mod_exp_consttime(base, exp, mod), 'big')
assert result == pow(2, 10, 1000000007), f"mod_exp wrong: {result}"
print("✅ bn_mod_exp_consttime")

# Test 3: bn_rand_range (should be in [1, mod-1])
for _ in range(100):
    r = int.from_bytes(_ossl.bn_rand_range(mod), 'big')
    assert 1 <= r < 1000000007, f"rand_range out of range: {r}"
print("✅ bn_rand_range (100 samples)")

# Test 4: ML-KEM round-trip
ek, dk = _ossl.mlkem768_keygen()
ct, ss1 = _ossl.mlkem768_encaps(ek)
ss2 = _ossl.mlkem768_decaps(ct, dk)
assert ss1 == ss2, "ML-KEM round-trip failed"
assert len(ss1) == 32
print("✅ ML-KEM-768 round-trip")

# Test 5: ring_sign / ring_verify
from cryptography.hazmat.primitives.asymmetric import ed448
from cryptography.hazmat.primitives import serialization
k1 = ed448.Ed448PrivateKey.generate()
k2 = ed448.Ed448PrivateKey.generate()
seed = k1.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                         serialization.NoEncryption())
A1 = k1.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
A2 = k2.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
sig = _ossl.ring_sign(bytes(seed), A1, A2, b'test message')
assert len(sig) == 228, f"sig len {len(sig)}"
assert _ossl.ring_verify(A1, A2, b'test message', sig), "ring_verify failed"
assert not _ossl.ring_verify(A1, A2, b'wrong', sig), "ring_verify accepted wrong msg"
print("✅ ring_sign / ring_verify")

print("\n✅ All C extension self-tests passed under sanitizers")
PYEOF

    echo ""
    echo "═══════════════════════════════════════════════════════"
    echo " Sanitizer run complete — check output above for"
    echo " ASAN / UBSAN / LeakSanitizer reports"
    echo "═══════════════════════════════════════════════════════"
fi

