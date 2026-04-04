#!/bin/bash
# Build otrv4_core Rust crate on Termux
#
# Prerequisites:
#   pkg install rust python
#   pip install maturin
#
# Build:
#   cd otrv4_core
#   bash build.sh
#
# Test (Rust only, no Python):
#   cargo test
#
# Install into Python:
#   maturin develop --release

set -e

echo "=== Building otrv4_core ==="

# Check deps
command -v cargo >/dev/null || { echo "Install Rust: pkg install rust"; exit 1; }
command -v python3 >/dev/null || { echo "Install Python: pkg install python"; exit 1; }

# Run Rust tests first
echo "--- Running Rust tests ---"
cargo test --release 2>&1

# Build Python module
if command -v maturin >/dev/null; then
    echo "--- Building Python module ---"
    maturin develop --release
    echo "--- Testing Python import ---"
    python3 -c "import otrv4_core; print('otrv4_core imported OK')"
    echo "=== Done ==="
else
    echo "--- maturin not found, skipping Python build ---"
    echo "Install with: pip install maturin"
    echo "Then run: maturin develop --release"
fi
