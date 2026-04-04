"""
setup_otr4.py — Build the otr4_crypto_ext C extension.

Usage:
    python setup_otr4.py build_ext --inplace

Requirements:
    OpenSSL ≥ 1.1.1 development headers (libssl-dev / openssl-devel)
    Python ≥ 3.8

After building, otr4_crypto_ext.cpython-*.so will appear alongside Pop3_hardened.py.
"""

from setuptools import setup, Extension
import subprocess
import sys
import os

def _openssl_flags(flag):
    """Run pkg-config to get OpenSSL compile/link flags."""
    try:
        out = subprocess.check_output(
            ["pkg-config", "--" + flag, "openssl"],
            stderr=subprocess.DEVNULL
        ).decode().split()
        return out
    except Exception:
        return []

def _termux_openssl():
    """Termux uses a non-standard prefix."""
    prefix = os.environ.get("PREFIX", "/data/data/com.termux/files/usr")
    return (
        ["-I" + prefix + "/include"],
        ["-L" + prefix + "/lib", "-lssl", "-lcrypto"]
    )

# Build flags
cflags  = _openssl_flags("cflags")
ldflags = _openssl_flags("libs")

if not cflags:
    # Fallback: Termux / manual install
    extra_inc, extra_ld = _termux_openssl()
    cflags  = extra_inc
    ldflags = extra_ld

# Include dirs from -I flags
include_dirs = [f[2:] for f in cflags if f.startswith("-I")]
library_dirs = [f[2:] for f in ldflags if f.startswith("-L")]
libraries    = [f[2:] for f in ldflags if f.startswith("-l")]
extra_cflags = [f for f in cflags if not f.startswith("-I")]

# Hardening compile flags
hardening = [
    "-O2",
    "-fstack-protector-strong",
    "-D_FORTIFY_SOURCE=2",
    "-fPIC",
    "-DOPENSSL_API_COMPAT=0x10101000L",  # require OpenSSL ≥ 1.1.1
]

otr4_ext = Extension(
    "otr4_crypto_ext",
    sources=["otr4_crypto_ext.c"],
    include_dirs=include_dirs or None,
    library_dirs=library_dirs or None,
    libraries=libraries or ["ssl", "crypto"],
    extra_compile_args=hardening + extra_cflags,
    extra_link_args=["-Wl,-z,relro", "-Wl,-z,now"] if sys.platform.startswith("linux") else [],
)

setup(
    name="otr4_crypto_ext",
    version="1.0.0",
    description="OTRv4 OpenSSL-backed constant-time crypto extension",
    ext_modules=[otr4_ext],
    python_requires=">=3.8",
)
