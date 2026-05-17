# Roadmap

What's next for OTRv4+. Ordered roughly by priority, not by ease.

## Recently shipped

- **v10.6.13** SMP regression fix from v10.6.12. Seven Python sites still used the legacy `.public_key().public_bytes()` chain; all converted to the Rust handle's `.public_bytes()` method.
- **v10.6.12** Phase 5.3e. Long-term identity keys generated inside Rust. `Ed448KeyHandle` and `X448KeyHandle` PyO3 classes own `SecretBytes<N>` and expose only public bytes and key-specific operations. Private bytes never appear on the Python heap.
- **v10.6.11** Phase 5.4. Rust-only crypto, no fallback paths. Import-time fail-fast if the Rust core is missing or stale.
- **v10.6.9** Phase 5.3c. DAKE3 Schnorr ring signature in pure Rust (`src/ring_sig.rs`, ~407 lines).
- **v10.6.8** Phase 5.3b. Removed dead-code disk persistence of private bytes. One-shot migration that overwrites legacy blobs.
- **v10.6.3** Phase 4. DAKE session keys never cross the Python heap. Audit closed 11/11.

## Phase 5.3f: drop the cryptography library and C extensions from boot

The boot-time cross-verify helpers (`_verify_ed448_rust_compat`, `_verify_ring_sig_rust_compat`) currently compare Rust output against OpenSSL (via the cryptography library) and against the C extension. They are the only reason those dependencies still load.

Plan: replace the runtime cross-verify with hardcoded RFC 8032 test vectors baked into the Rust crate. The Rust crypto either matches the published vectors or the test fails at build time, not at every startup. After this, the runtime drops:

- The `cryptography` Python package
- `otr4_crypto_ext.so`, `otr4_ed448_ct.so`, `otr4_mldsa_ext.so` C extensions
- The transitive OpenSSL build dependency for Termux

Scope: ~150 lines of Rust test vectors plus a `#[cfg(test)]` harness. One Python file change to remove the now-dead boot helpers. Estimated single-session work.

## Cargo.toml RustSec hardening

Three crates flagged or stale:

1. **`pqcrypto-kyber 0.8` → `pqcrypto-mlkem 0.2`**. Kyber is round-3 NIST submission; ML-KEM is FIPS 203 (the final standard). The two are not wire-compatible. Since OTRv4+ has no external peers yet, the wire change is acceptable. Refactoring `dake.rs` to use the new crate API is mechanical but the type names may differ between `pqcrypto_kyber::kyber1024` and `pqcrypto_mlkem::mlkem1024`. Will verify API surface before committing.

2. **`pqcrypto-mldsa 0.1.2` → `0.2`**. Version 0.1.2 is yanked. Same family bump. API likely stable but needs check.

3. **`lazy_static 1.5` → `std::sync::LazyLock`**. RustSec lists `lazy_static` as unmaintained. One use site in `smp.rs` (the MODP-2048 prime). Toolchain (Rust 1.94.1) supports `LazyLock` (stabilised in 1.80). Mechanical refactor.

Scope: one focused Cargo.toml commit plus a `smp.rs` refactor plus a `dake.rs` API rename. Estimated single-session work after the FIPS 203 crate API is verified.

## Phase 5.3g: persistent identity vault

Currently identity keys regenerate every launch. Fingerprints change. For a research prototype this is acceptable, but it makes SMP trust unbinding pointless across sessions.

Plan:

- Encrypted disk vault keyed by Argon2id from a user passphrase
- Vault stores the Ed448 seed and X448 private bytes
- On startup, vault is decrypted into fresh `Ed448KeyHandle` and `X448KeyHandle` via `Ed448KeyHandle.from_seed_bytes()` and `X448KeyHandle.from_priv_bytes()`
- If no vault exists, generate fresh (current behaviour)
- Vault file uses NIST SP 800-88r1 secure destruction on logout

The `from_seed_bytes` and `from_priv_bytes` constructors already exist for test compatibility. The vault wrapper is a new piece.

Scope: maybe 200 lines of Python plus a small Rust vault helper. Estimated one to two sessions.

## Other planned work

### Better trust UX

`/trust` currently asks `y` or `n` after fingerprint display. After Phase 5.3g, a long-term `~/.otrv4plus/trusted_fingerprints` file would survive restarts.

### Group messaging

Out of OTRv4 scope. OMEMO or MLS would be a separate project.

### Native Android APK

Building a signed `.apk` containing the Python interpreter, the Rust `.so`, and the C extensions has been investigated (see DEVELOPMENT.md). Possible but non-trivial. Termux is the supported dev environment; a native APK is future work.

### Tor onion service transport

I2P SAM bridge works today. Adding an alternative Tor `.onion` transport would broaden the deployment options. The current architecture (transport plugged into `Connection` class) supports this without crypto changes.

### Formal review

The crypto path is now small enough to be reviewable: ~3500 lines of Rust across `dake.rs`, `ratchet.rs`, `smp.rs`, `smp_vault.rs`, `ring_sig.rs`, `key_handles.rs`, `secure_mem.rs`, `kdf.rs`. A formal third-party review would significantly increase confidence. No funding for this; expression of interest welcome.

## What is not on the roadmap

- Backward compatibility with older v10.6.x versions. The no-fallbacks posture in v10.6.11 onward means peers must run the same major version. Wire incompatibility is accepted.
- Compatibility with stock OTRv4 implementations. The ML-DSA-87, ML-KEM-1024, and SHAKE-256 transcript additions are deliberate OTRv4+ extensions.
- Mobile push notifications. The IRC client uses persistent TCP, not push.
- File transfer. Out of scope.

## Tracking

Issues for the above are filed on the GitHub repo. Tag conventions: `phase-5.3f`, `cargo-hardening`, `phase-5.3g`. Priority is not strict; whichever has the cleanest scope on a given evening gets done.
