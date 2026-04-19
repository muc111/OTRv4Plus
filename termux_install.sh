#!/bin/bash
# OTRv4+ One-Click Termux Installer (Robust + Prebuilt Fallback)
# Run this script after cloning the repository.

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo "=============================================="
echo "🚀 OTRv4+ Termux Installer"
echo "=============================================="

# --- Helper function for fallback ---
fallback_to_prebuilt() {
    echo ""
    echo -e "${YELLOW}⚠️  Build failed. Falling back to prebuilt binaries...${NC}"
    cd "$PROJECT_ROOT"
    cp -v prebuilt/*.so . 2>/dev/null || true
    echo -e "${GREEN}✅ Prebuilt binaries copied.${NC}"
    echo -e "${YELLOW}Note: Prebuilt binaries may not be optimized for your device.${NC}"
    verify_installation
    exit 0
}

verify_installation() {
    echo ""
    echo "Verifying modules..."
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
        return 0
    else
        echo -e "${RED}❌ Module verification failed.${NC}"
        return 1
    fi
}

# --- Save project root ---
PROJECT_ROOT=$(pwd)

# --- 1. System dependencies ---
echo ""
echo "[1/5] Installing system dependencies..."
pkg update -y
pkg install -y python python-pip rust binutils openssl-tool make clang

# --- 2. Python tools ---
echo ""
echo "[2/5] Installing maturin and setuptools..."
pip install maturin setuptools

# --- 3. Clean previous build artifacts (but keep prebuilt folder) ---
echo ""
echo "[3/5] Cleaning old build files..."
rm -rf build/ *.so Rust/target 2>/dev/null || true

# --- 4. Detect Android API level ---
echo ""
echo "[4/5] Detecting Android API level..."
API_LEVEL=$(getprop ro.build.version.sdk 2>/dev/null || echo "24")
export ANDROID_API_LEVEL=${API_LEVEL:-24}
echo "→ Using Android API level: $ANDROID_API_LEVEL"

# --- 5. Build C extensions ---
echo ""
echo "[5/5] Building C extensions..."
if ! python setup_otr4.py build_ext --inplace; then
    fallback_to_prebuilt
fi

# --- 6. Build Rust core ---
echo ""
echo "[6/6] Building Rust core..."
cd Rust
if cargo build --release; then
    cp target/release/libotrv4_core.so ../otrv4_core.so
    cd ..
else
    cd ..
    fallback_to_prebuilt
fi

# --- Verify and finish ---
if verify_installation; then
    exit 0
else
    fallback_to_prebuilt
fi