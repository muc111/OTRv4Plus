# Roadmap

What's next for OTRv4+. Ordered roughly by priority, not by ease.

## Recently shipped

- **v10.6.19** Phase 5.3h, parts A2 + B + C (sub-phase scope correction). Three live AES-256-GCM call sites (in `SMPAutoRespondStorage`, `SecureKeyStorage`, and `_secure_file_destroy` itself) swapped from `cryptography.AESGCM` to `otrv4_core.aes256gcm_{encrypt,decrypt}` via the new `Rust/src/aead.rs` PyO3 module backed by the `aes-gcm` 0.10 crate.  Wire format byte-identical; encrypted SMP-secrets files written by v10.6.18 decrypt cleanly under v10.6.19.  Three Ed448PublicKey wrap sites in the Rust DAKE adapter replaced with raw bytes (`remote_identity_key` attribute now holds bytes; consumers were dead-code session_keys entries).  Top-of-file `cryptography` imports dropped `AESGCM` and `hashes` (the latter was never actually used in production).  Startup migration added: any legacy `~/.otrv4_vault` and `~/.otrv4_smp_secrets.json` files from pre-`~/.otrv4plus/` builds are now securely destroyed via `_secure_file_destroy` (NIST SP 800-88r1 single-pass AES-GCM ciphertext overwrite, key destroyed after use).  Phase 5.3h's remaining scope (x448 ratchet replacement, serialization.Raw byte conversions) is significantly larger and split into 5.3h-D for a later session.
- **v10.6.18** Phase 5.3j. `otr4_mldsa_ext` C extension retired. ML-DSA-87 keygen, sign, and verify now backed by `pqcrypto-mldsa 0.1.2` via Rust PyO3 bindings in `src/mldsa.rs`. Wire format byte-identical (FIPS 204 ML-DSA-87 parameter set unchanged: 2592-byte pk / 4896-byte sk / 4627-byte sig). Build process no longer requires `otr4_mldsa_ext.so`. `pqcrypto-mldsa` pinned to `default-features = false, features = ["std"]` to avoid the same NEON SIGILL trap that affected `pqcrypto-mlkem` in v10.6.16. Phase 5.3g answered: **ephemeral identity is the design choice** (see below); no persistent vault.
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

This phase turned out to be larger than a single commit (a pattern that repeated through 5.3f and 5.3j).  Honest split into sub-phases:

#### Phase 5.3h, parts A2 + B + C — shipped in v10.6.19

- **Part A2 (legacy file cleanup).** Startup migration that securely destroys `~/.otrv4_vault` and `~/.otrv4_smp_secrets.json` orphans from pre-`~/.otrv4plus/` builds, plus the legacy `~/.otrv4_keys/` directory.  Uses the existing `_secure_file_destroy` (NIST SP 800-88r1 single-pass AES-GCM ciphertext overwrite).  No-op for new installs.
- **Part B (AES-GCM swap).** Three live `AESGCM(key)` call sites swapped from `cryptography.hazmat.primitives.ciphers.aead.AESGCM` to `otrv4_core.aes256gcm_{encrypt,decrypt}` via the new `Rust/src/aead.rs` PyO3 module (wraps `aes-gcm` 0.10 crate).  Wire format identical.  Sites: `SMPAutoRespondStorage._load/_save`, `SecureKeyStorage._encrypt_key/_decrypt_key`, and `_secure_file_destroy` itself.
- **Part C (Ed448PublicKey wrap removal).** Three `Ed448PublicKey.from_public_bytes` call sites in the Rust DAKE adapter replaced with raw bytes.  `self.remote_identity_key` now holds bytes; consumers were dead-code `session_keys['peer_long_term_key']` entries.

#### Phase 5.3h, part D — pending (multi-session)

What remains under the "drop the cryptography library" goal:

1. **`ed448.Ed448PublicKey.from_public_bytes(...).verify(...)`** at `ClientProfile.decode()` (line ~2644).  Security-critical: this is the path that verifies an incoming peer's profile signature.  Needs a new Rust PyO3 `verify_ed448_sig(pub_bytes, msg, sig) -> bool` function (the `ed448-goldilocks-plus` crate already supports this; just need a thin wrapper).  One Python edit at line 2644 to swap the call.  Discovered during v10.6.19 audit; deferred for a focused commit with proper test cycle.
2. **`x448.X448PrivateKey` and `x448.X448PublicKey`** in the ratchet DH path and legacy DAKE.  Needs a new Rust X448 PyO3 binding (`Rust/src/x448_handle.rs` or similar) — the `x448` crate is already a Rust dependency.  Then refactor the ratchet's DH operations and the cryptography-lib X448 sites (~12 production sites).  Multi-session.
3. **`serialization.Raw` byte conversions** (~20 sites).  Becomes dead after X448 wrapper objects are gone.
4. **`ed448` legacy DAKE paths** at lines ~3794 and ~3988 plus the `Ed448PrivateKey` ClientProfile constructor (~2386, 2421).  Already gated by `if not self._use_rust:` which is false in v10.6.11+ production.  Pure-deletion when 5.3h-D lands.

Scope: significantly more than a single session.  Estimated 2-3 focused sessions.

### Phase 5.3i — replace `otr4_crypto_ext` (`_ossl`) uses

1. **`_ossl.cleanse(buf)`** at 11 sites. Replace with a Rust-side `cleanse` exposed via PyO3 that wraps `zeroize::Zeroize`. Bytearrays only; Python `bytes` are immutable so the existing cleanse() calls already presuppose mutable buffers.

2. **`_ossl.bn_mod_exp_consttime`, `bn_mod_inverse`, `bn_rand_range`** for SMP. `num-bigint` is not constant-time, so this needs careful work — either a Rust binding around a vetted constant-time bignum crate, or a port of the SMP arithmetic onto a curve-scalar-based variant.

3. **`_ossl.mlkem1024_*`** in the `MLKEM1024BraceKEM` class. Check whether this class is still reachable in production (DAKE itself uses the Rust path now) or whether it is dead code that can be deleted outright.

4. **`_ossl.disable_core_dumps`** at boot. Replace with a Python `resource.setrlimit(RLIMIT_CORE, (0, 0))` or a Rust equivalent.

5. **`_ossl.ring_sign` and `_ossl.ring_verify`** at the previously-deleted `_verify_ring_sig_rust_compat` site. These C entry points are now genuinely unused and can be removed when the C extension source is next touched.

Scope: largest sub-phase, probably 200-300 lines plus the constant-time bignum decision. Two to three sessions.

### Phase 5.3j — replace `otr4_mldsa_ext` (`_mldsa`) uses

**Shipped in v10.6.18.** `_mldsa.mldsa87_keygen`, `mldsa87_sign`, and `mldsa87_verify` now run through `pqcrypto-mldsa 0.1.2` via Rust PyO3 bindings in `src/mldsa.rs`.  The C extension entry points are no longer invoked.  `otr4_mldsa_ext.so` is no longer required for the build.

### Phase 5.3k — delete the C extensions and the cryptography library

After 5.3h and 5.3i land, this is purely deletion: remove the imports, remove the remaining `.c` and `.h` files (`otr4_crypto_ext`, `otr4_ed448_ct`) from the repo (or move to an `archived/` directory), drop the `setup_otr4.py` build target, update SECURITY.md to remove the C-extension caveat.  `otr4_mldsa_ext.c` and `.so` can already be archived; nothing references them after v10.6.18.

## Phase 5.3g — ephemeral identity by design (DECIDED at v10.6.18)

OTRv4+ keeps **ephemeral identities** by design. Fingerprints regenerate at every launch; there is no on-disk identity vault.

Rationale:

- **Threat model fits ephemeral.** OTRv4+ runs over I2P for an IRC channel; the assumption is short-lived sessions, not long-term identity binding.
- **No on-disk attack surface.** A persistent vault would create a high-value target for offline brute-force.
- **No passphrase to forget.** Termux has no OS keyring; a vault would require user passphrase prompts at every launch.
- **Aligns with privacy-oriented messaging norms.** Tor Browser, Cwtch (default), and Briar (before user opt-in) all keep identities short-lived.

SMP trust binding is meaningful within a session.  Across sessions, peers must re-verify on each connection.  This is correct behaviour for the project's design intent, not a limitation.

If a user explicitly wants persistence in the future, the `Ed448KeyHandle.from_seed_bytes()` and `X448KeyHandle.from_priv_bytes()` constructors already support reconstructing a handle from raw bytes — so an external user-managed vault is possible without further code changes in OTRv4+ itself.

## Other planned work

### Better trust UX

`/trust` currently asks `y` or `n` after fingerprint display.  Trust decisions do not persist across launches (consistent with the ephemeral-identity choice in 5.3g).

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
