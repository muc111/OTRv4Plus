# Prebuilt Binaries

These .so files are compiled for Termux on Android (aarch64).
Copy them into the same directory as otrv4+.py before running.

| File | Purpose |
|---|---|
| otr4_crypto_ext.so | OpenSSL-backed AES-GCM, ChaCha20, HKDF, core dumps suppressor |
| otr4_ed448_ct.so | Constant-time Ed448 scalar multiplication |
| otr4_mldsa_ext.so | ML-DSA-87 (FIPS 204) post-quantum signing - requires OpenSSL >= 3.5 |
| libotrv4_core.so | Rust double-ratchet core with zeroize-on-drop key material |

## Quick install (Termux)

cp prebuilt/*.so ~/OTRv4Plus/

## Building from source

See Rust/Cargo.toml and the C extension sources in c_ext/.
Requires: clang, openssl-dev, rust via pkg install.
