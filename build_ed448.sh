#!/data/data/com.termux/files/usr/bin/bash
# build_ed448.sh — Compile otr4_ed448_ct.so on Termux
#
# Run this once from the directory containing pop3_hardened.py:
#   chmod +x build_ed448.sh && ./build_ed448.sh

set -e

echo "=== otr4_ed448_ct build ==="

# 1. Install deps if missing
for pkg in clang openssl python; do
    if ! command -v ${pkg%%-*} &>/dev/null && ! pkg list-installed 2>/dev/null | grep -q "^$pkg"; then
        echo "Installing $pkg..."
        pkg install -y "$pkg"
    fi
done

TERMUX_PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"
PYTHON=$(command -v python3 || command -v python)
PY_VER=$("$PYTHON" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_INC="$TERMUX_PREFIX/include/python${PY_VER}"
SSL_INC="$TERMUX_PREFIX/include"
LIB_DIR="$TERMUX_PREFIX/lib"

echo "Python : $PYTHON ($PY_VER)"
echo "Headers: $PY_INC"
echo "OpenSSL: $SSL_INC"
echo "Libs   : $LIB_DIR"

# 2. Compile
# -lpython3.x is required on Android/Termux: unlike Linux, the interpreter
# binary does not re-export Python C API symbols into dlopen'd extensions.
clang -O2 -Wall -fPIC -shared -std=c99 \
    -I"$PY_INC" \
    -I"$SSL_INC" \
    -L"$LIB_DIR" \
    -o otr4_ed448_ct.so otr4_ed448_ct.c \
    -lpython${PY_VER} \
    -lcrypto

echo ""
echo "✅ Built: otr4_ed448_ct.so"
echo ""

# 3. Quick sanity test
"$PYTHON" - << 'PYEOF'
import sys, os
sys.path.insert(0, os.getcwd())
import otr4_ed448_ct, secrets
Q = 2**446 - 13818066809895115352007386748515426880336692474882178609894547503885
k = secrets.randbelow(Q - 1) + 1
r = otr4_ed448_ct.ed448_scalarmult_base(k.to_bytes(57, 'little'))
assert len(r) == 57 and r != bytes(57)
print("✅ ed448_scalarmult_base: OK")
r2 = otr4_ed448_ct.ed448_scalarmult(k.to_bytes(57, 'little'), r)
assert len(r2) == 57
print("✅ ed448_scalarmult: OK")
print("✅ CT Ed448 extension ready")
PYEOF
