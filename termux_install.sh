#!/bin/bash
# OTRv4+ One-Click Termux Installer (with robust C extension build)
set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo "=============================================="
echo "🚀 OTRv4+ Termux Installer"
echo "=============================================="

PROJECT_ROOT=$(pwd)

# --- 1. System dependencies ---
echo -e "\n[1/6] Installing system dependencies..."
pkg update -y
pkg install -y python python-pip rust binutils openssl-tool make clang

# --- 2. Python tools ---
echo -e "\n[2/6] Installing maturin and setuptools..."
pip install maturin setuptools

# --- 3. Clean old builds (keep prebuilt folder) ---
echo -e "\n[3/6] Cleaning old build files..."
rm -rf build/ *.so Rust/target 2>/dev/null || true

# --- 4. Detect Android API ---
echo -e "\n[4/6] Detecting Android API level..."
API_LEVEL=$(getprop ro.build.version.sdk 2>/dev/null || echo "24")
export ANDROID_API_LEVEL=${API_LEVEL:-24}
echo "→ Using Android API level: $ANDROID_API_LEVEL"

# --- 5. Build C extension (verbose) ---
echo -e "\n[5/6] Building C extension (otr4_crypto_ext)..."
if python setup_otr4.py build_ext --inplace -v; then
    # Sometimes --inplace puts the .so in build/lib.* – copy manually
    if [ -f "otr4_crypto_ext*.so" ]; then
        echo "✅ C extension built successfully."
    else
        echo -e "${YELLOW}⚠️  .so not found in current dir, searching in build/...${NC}"
        find build -name "otr4_crypto_ext*.so" -exec cp -v {} . \;
    fi
else
    echo -e "${RED}❌ C extension build failed.${NC}"
    echo -e "${YELLOW}Falling back to prebuilt binaries...${NC}"
    cp -v prebuilt/*.so . 2>/dev/null || true
fi

# --- 6. Build Rust core ---
echo -e "\n[6/6] Building Rust core..."
cd Rust
if cargo build --release; then
    cp target/release/libotrv4_core.so ../otrv4_core.so
    cd ..
else
    cd ..
    echo -e "${RED}❌ Rust build failed. Falling back to prebuilt...${NC}"
    cp -v prebuilt/*.so . 2>/dev/null || true
fi

# --- Final verification ---
echo -e "\nVerifying all modules import correctly..."
if python -c "
import otr4_crypto_ext
import otr4_ed448_ct
import otr4_mldsa_ext
import otrv4_core
print('All modules loaded successfully!')
" 2>/dev/null; then
    echo -e "${GREEN}✅ Installation successful!${NC}"
    echo ""
    echo "=============================================="
    echo -e "${GREEN}🎉 OTRv4+ is ready!${NC}"
    echo ""
    echo "Run with:"
    echo "  PYTHONMALLOC=malloc python otrv4+.py"
    echo "=============================================="
    exit 0
else
    echo -e "${RED}❌ Module verification failed.${NC}"
    echo "Try manual fallback: cp prebuilt/*.so ."
    exit 1
fi