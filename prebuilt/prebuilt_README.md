# Prebuilt Binaries

Compiled for **Termux on Android (aarch64, API 24+)**.
Copy all files from this directory into the same directory as `otrv4+.py` before running.

| File | Purpose |
|---|---|
| `otr4_crypto_ext.so` | OpenSSL-backed ML-KEM-1024, ring signatures, BN ops, core-dump suppressor |
| `otr4_crypto_ext.cpython-313-aarch64-linux-android.so` | Same — CPython 3.13 ABI variant |
| `otr4_ed448_ct.so` | Constant-time Ed448 scalar multiplication (Montgomery ladder) |
| `otr4_mldsa_ext.so` | ML-DSA-87 (FIPS 204) post-quantum signing — requires OpenSSL ≥ 3.5 |
| `otrv4_core.so` | Rust double-ratchet + SMP vault — `zeroize` on drop, zero `unsafe` blocks |
| `libotrv4_core.so` | Shared library form of the Rust core (loaded by `otrv4_core.so`) |

## Quick install (Termux)

```bash
cp prebuilt/*.so ~/OTRv4Plus/
```

## Which .so files does otrv4+.py need?

All six. The Python import chain is:

```
otrv4+.py
  └── import otr4_crypto_ext        → otr4_crypto_ext.so (or cpython-313 variant)
  └── import otr4_ed448_ct          → otr4_ed448_ct.so
  └── import otr4_mldsa_ext         → otr4_mldsa_ext.so
  └── from otrv4_core import ...    → otrv4_core.so → libotrv4_core.so
```

## Building from source

See `Rust/Cargo.toml` for the Rust core and `setup_otr4.py` for the C extensions.
The `termux_install.sh` script handles the full build automatically and falls back
to these prebuilt files if the build fails.

**Requirements:** `clang`, `openssl-dev` (≥ 3.5), `rust` via `pkg install`.
