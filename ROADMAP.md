# Roadmap

What's next for OTRv4+. Ordered roughly by priority, not by ease.

## Recently shipped

- **v10.6.17** Phase 5.3f-narrow. Removed Python boot-time cross-verify helpers (`_verify_ed448_rust_compat`, `_verify_ring_sig_rust_compat`). RFC 8032 Ed448 test vectors moved to Rust `src/test_vectors.rs` with a `#[cfg(test)]` harness; `cargo test` is the new release gate for ed448 correctness. C extensions and the cryptography library are still load-bearing in production (see SECURITY.md).
- **v10.6.16** ML-KEM migration. `pqcrypto-kyber 0.8` (round-3 Kyber) replaced by `pqcrypto-mlkem 0.1.1` (FIPS 203). Drop-in API; wire-incompatible with v10.6.15. Build forces `default-features = false, features = ["std"]` to avoid avx2/neon SIGILL on Termux/aarch64.
- **v10.6.15** SMP race fix. When both peers run `/smp start` near-simultaneously, the side with the higher fingerprint yields to responder role; the side with the lower fingerprint keeps initiator role. Vault-based secret persistence makes the rebuild clean. Also restored `signing` + `pkcs8` features on `ed448-goldilocks-plus` that had been silently dropped, unblocking the v10.6.12 handle architecture as actually-live for the first time.
- **v10.6.14** `lazy_static 1.5` (unmaintained per RustSec) replaced by `std::sync::LazyLock` (stable Rust 1.80+). MSRV raised.
- **v10.6.13** SMP regression fix from v10.6.12. Seven Python sites still used the legacy `.public_key().public_bytes()` chain; all converted to the Rust handle's `.public_bytes()` method.
- **v10.6.12** Phase 5.3e. Long-term identity keys generated inside Rust. `Ed448KeyHandle` and `X448KeyHandle` PyO3 classes own `SecretBytes<N>` and expose only public bytes and key-specific operations. Private bytes never appear on the Python heap.
- **v10.6.11** Phase 5.4. Rust-only crypto, no fallback paths. Import-time fail-fast if the Rust core is missing or stale.
- **v10.6.9** Phase 5.3c. DAKE3 Schnorr ring signature in pure Rust (`src/ring_sig.rs`, ~407 lines).
- **v10.6.8** Phase 5.3b. Removed dead-code disk persistence of private bytes. One-shot migration that overwrites legacy blobs.
- **v10.6.3** Phase 4. DAKE session keys never cross the Python heap. Audit closed 11/11.

## Drop the cryptography library and C extensions from runtime

What was previously labelled "Phase 5.3f" turned out to be larger than a single commit. Splitting it honestly into named sub-phases:

### Phase 5.3f-narrow — boot helpers + RFC 8032 vectors

**Shipped in v10.6.17.** The two Python boot helpers and their four call sites have been removed. Rust `src/test_vectors.rs` is the new release-time gate.

The cryptography library import and the C extension imports are unchanged. They are still load-bearing in production.

### Phase 5.3h — replace runtime cryptography library uses

Three classes of remaining call site:

1. **`Ed448PublicKey.from_public_bytes`** at three sites in DAKE post-processing (lines ~4903, ~5046, ~5078). Used only to populate `self.remote_identity_key` for UI display. The simplest fix is to delete this attribute entirely and have the UI consume `remote_identity_pub_bytes` directly. The cryptography library `Ed448PublicKey` object provides no operations we need post-DAKE; everything goes through the Rust path.

2. **`AESGCM`** at five sites for the persistent SMP-secrets store. Replace with the `aes-gcm` Rust crate that the Rust core already pulls in. Needs a small PyO3 helper to expose AEAD encrypt/decrypt with associated-data binding.

3. **`serialization.Raw`** for byte conversion of cryptography key objects. Becomes dead after items 1 and 2 above.

Scope: maybe 100-150 lines of Python plus a small Rust AEAD helper. One focused session.

### Phase 5.3i — replace `otr4_crypto_ext` (`_ossl`) uses

1. **`_ossl.cleanse(buf)`** at 11 sites. Replace with a Rust-side `cleanse` exposed via PyO3 that wraps `zeroize::Zeroize`. Bytearrays only; Python `bytes` are immutable so the existing cleanse() calls already presuppose mutable buffers.

2. **`_ossl.bn_mod_exp_consttime`, `bn_mod_inverse`, `bn_rand_range`** for SMP. `num-bigint` is not constant-time, so this needs careful work — either a Rust binding around a vetted constant-time bignum crate, or a port of the SMP arithmetic onto a curve-scalar-based variant.

3. **`_ossl.mlkem1024_*`** in the `MLKEM1024BraceKEM` class. Check whether this class is still reachable in production (DAKE itself uses the Rust path now) or whether it is dead code that can be deleted outright.

4. **`_ossl.disable_core_dumps`** at boot. Replace with a Python `resource.setrlimit(RLIMIT_CORE, (0, 0))` or a Rust equivalent.

5. **`_ossl.ring_sign` and `_ossl.ring_verify`** at the previously-deleted `_verify_ring_sig_rust_compat` site. These C entry points are now genuinely unused and can be removed when the C extension source is next touched.

Scope: largest sub-phase, probably 200-300 lines plus the constant-time bignum decision. Two to three sessions.

### Phase 5.3j — replace `otr4_mldsa_ext` (`_mldsa`) uses

1. **`_mldsa.mldsa87_keygen`, `mldsa87_sign`, `mldsa87_verify`**. Pure Rust replacement using `pqcrypto-mldsa 0.1.2` (already in tree from the DAKE path). Expose three PyO3 helpers; the C extension entry points become dead code.

Scope: small, one session.

### Phase 5.3k — delete the C extensions and the cryptography library

After 5.3h through 5.3j land, this is purely deletion: remove the imports, remove the `.c` and `.h` files from the repo (or move to an `archived/` directory), drop the `setup_otr4.py` build target, update SECURITY.md to remove the C-extension caveat.

## Phase 5.3g: persistent identity vault

Currently identity keys regenerate every launch. Fingerprints change. For a research prototype this is acceptable, but it makes SMP trust unbinding pointless across sessions.

**Open question**: is persistent identity actually wanted? Ephemeral-by-design is defensible for a privacy-oriented IRC client. Tor Browser, Cwtch (by default), and Briar (until the user opts in) all keep identities short-lived. A persistent vault introduces:

- A passphrase the user must remember (Termux has no OS keyring)
- An on-disk attack surface that did not previously exist
- A trust assumption that the vault file is not exfiltrated

If the answer is "ephemeral by design", Phase 5.3g becomes a documentation-only update.

If the answer is "yes, persistent":

- Encrypted disk vault keyed by Argon2id from a user passphrase
- Vault stores the Ed448 seed and X448 private bytes
- On startup, vault is decrypted into fresh `Ed448KeyHandle` and `X448KeyHandle` via `Ed448KeyHandle.from_seed_bytes()` and `X448KeyHandle.from_priv_bytes()`
- If no vault exists, generate fresh (current behaviour)
- Vault file uses NIST SP 800-88r1 secure destruction on logout

The `from_seed_bytes` and `from_priv_bytes` constructors already exist for test compatibility. The vault wrapper is a new piece.

Scope (if persistent): maybe 200 lines of Python plus a small Rust vault helper. Estimated one to two sessions.

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
