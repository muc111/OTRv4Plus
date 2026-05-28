# Prebuilt Binaries

These `.so` files are compiled for Termux on Android (aarch64).
Copy them into the same directory as `otrv4+.py` before running.

| File | Purpose |
|---|---|
| `otrv4_core.so` | Rust crypto core — Ed448, X448, ML-KEM-1024, ML-DSA-87, AES-256-GCM, Argon2id, ring signatures, SMP vault, double ratchet, DAKE.  PyO3 module. |
| `libotrv4_core.so` | Shared library form of the Rust core (the underlying `.so` that `otrv4_core.so` links to in the Termux PyO3 build). |

## Quick install (Termux)

```bash
cp prebuilt/*.so ~/OTRv4Plus/
```

## Building from source

See `Rust/Cargo.toml`.  As of v10.7.5 OTRv4+ is **Rust-core-only**: there are no C extensions to compile, no `setup_otr4.py`, no Python `cryptography` dependency.  The build is one command:

```bash
cd Rust
cargo build --release --no-default-features --features pq-rust
cp target/release/libotrv4_core.so ../otrv4_core.so
```

**Requirements:** `rust` via `pkg install`.  Approximately three minutes on a modern phone.

## History

Earlier versions of this directory also contained `otr4_crypto_ext.so`, `otr4_ed448_ct.so`, and `otr4_mldsa_ext.so`.  All three C extensions were retired in the v10.6.18 → v10.7.4 sequence (Phases 5.3i, 5.3j, 5.3k).  Their replacements all live inside the single Rust `otrv4_core.so` now.  See `CHANGELOG.md` for the full migration history.
