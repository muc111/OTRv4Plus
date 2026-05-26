# Roadmap

What's next for OTRv4+. Ordered roughly by priority, not by ease.

## Recently shipped

- **v10.7** Phase 5.3h-D complete — the Python `cryptography` library is fully removed from the codebase. Stages 1 and 2 (v10.6.20, v10.6.21) moved Ed448 verification and the X448 ratchet DH into Rust. v10.7 (stage 3) deleted the dead pure-Python `OTRv4DAKE` fallback class (863 lines) and the unreachable `_use_rust` / `_py_fallback` machinery, rescued `_safe_b64decode` to module scope, removed the four remaining `serialization.Raw` byte-conversion sites, deleted the legacy `ed448`/`x448` `isinstance` branches from `ClientProfile`, and removed the `from cryptography...` import entirely. 883 lines net removed. No OpenSSL-backed Python crypto remains in any code path.
- **v10.6.21** Phase 5.3h-D stage 2. The double ratchet's X448 Diffie-Hellman moved from `cryptography.x448` to the Rust `X448KeyHandle` (`generate_x448_keypair`, `handle.dh`). No new Rust crypto — the handle already existed. The `x448` crate clamps the scalar per RFC 7748 and rejects low-order points, matching OpenSSL byte-for-byte. RFC 7748 §5.2 known-answer vector added to `key_handles.rs` as the build-time desync guard. Verified live across 5+ DH-ratchet epochs.
- **v10.6.20** Phase 5.3h-D stage 1. `ClientProfile.decode()` Ed448 signature verification moved from `cryptography.Ed448PublicKey.verify` to the Rust `verify_ed448_sig` function (`VerifyingKey::verify_raw`, the exact counterpart of `Ed448KeyHandle::sign`'s `sign_raw`). Three Rust unit tests including a sign-then-verify roundtrip.
- **v10.6.19** Phase 5.3h, parts A2 + B + C. Three live AES-256-GCM call sites (in `SMPAutoRespondStorage`, `SecureKeyStorage`, and `_secure_file_destroy` itself) swapped from `cryptography.AESGCM` to `otrv4_core.aes256gcm_{encrypt,decrypt}` via the new `Rust/src/aead.rs` PyO3 module backed by the `aes-gcm` 0.10 crate. Six `Ed448PublicKey` wrap sites replaced with raw bytes. Top-of-file `cryptography` imports dropped `AESGCM` and `hashes`. Startup migration added to securely destroy legacy `~/.otrv4_vault` and `~/.otrv4_smp_secrets.json` orphans.
- **v10.6.18** Phase 5.3j. `otr4_mldsa_ext` C extension retired. ML-DSA-87 keygen, sign, and verify now backed by `pqcrypto-mldsa 0.1.2` via Rust PyO3 bindings in `src/mldsa.rs`. Wire format byte-identical (FIPS 204 ML-DSA-87). Phase 5.3g answered: **ephemeral identity is the design choice** (see below); no persistent vault.
- **v10.6.17** Phase 5.3f-narrow. Removed Python boot-time cross-verify helpers. RFC 8032 Ed448 test vectors moved to Rust `src/test_vectors.rs` with a `#[cfg(test)]` harness; `cargo test` is the release gate for Ed448 correctness.
- **v10.6.16** ML-KEM migration. `pqcrypto-kyber 0.8` (round-3 Kyber) replaced by `pqcrypto-mlkem 0.1.1` (FIPS 203). Drop-in API; wire-incompatible with v10.6.15. Build forces `default-features = false, features = ["std"]` to avoid avx2/neon SIGILL on Termux/aarch64.
- **v10.6.15** SMP race fix. When both peers run `/smp start` near-simultaneously, the side with the higher fingerprint yields to responder role. Also restored `signing` + `pkcs8` features on `ed448-goldilocks-plus` that had been silently dropped.
- **v10.6.14** `lazy_static 1.5` (unmaintained per RustSec) replaced by `std::sync::LazyLock` (stable Rust 1.80+).
- **v10.6.13** SMP regression fix from v10.6.12. Seven Python sites still used the legacy `.public_key().public_bytes()` chain; all converted to the Rust handle's `.public_bytes()` method.
- **v10.6.12** Phase 5.3e. Long-term identity keys generated inside Rust. `Ed448KeyHandle` and `X448KeyHandle` PyO3 classes own `SecretBytes<N>` and expose only public bytes and key-specific operations.
- **v10.6.11** Phase 5.4. Rust-only crypto, no fallback paths. Import-time fail-fast if the Rust core is missing or stale.
- **v10.6.9** Phase 5.3c. DAKE3 Schnorr ring signature in pure Rust (`src/ring_sig.rs`).
- **v10.6.8** Phase 5.3b. Removed dead-code disk persistence of private bytes.
- **v10.6.3** Phase 4. DAKE session keys never cross the Python heap. Audit closed 11/11.

## Drop the cryptography library and C extensions from runtime

What was previously labelled "Phase 5.3f" turned out to be larger than a single commit. The honest split into named sub-phases, with the cryptography-library half now complete:

### Phase 5.3f-narrow — boot helpers + RFC 8032 vectors

**Shipped in v10.6.17.** The two Python boot helpers and their four call sites were removed. Rust `src/test_vectors.rs` is the Ed448 release-time gate.

### Phase 5.3h — replace runtime cryptography library uses

**Complete as of v10.7.** The phase was larger than a single commit and was split into sub-phases:

#### Phase 5.3h, parts A2 + B + C — shipped in v10.6.19

- **Part A2 (legacy file cleanup).** Startup migration securely destroying `~/.otrv4_vault`, `~/.otrv4_smp_secrets.json`, and `~/.otrv4_keys/` orphans via `_secure_file_destroy` (NIST SP 800-88r1).
- **Part B (AES-GCM swap).** Three live `AESGCM(key)` call sites swapped to `otrv4_core.aes256gcm_{encrypt,decrypt}` via `Rust/src/aead.rs` (`aes-gcm` 0.10 crate). Wire format identical.
- **Part C (Ed448PublicKey wrap removal).** Six `Ed448PublicKey.from_public_bytes` call sites replaced with raw bytes.

#### Phase 5.3h-D — shipped across v10.6.20, v10.6.21, v10.7

Staged so each piece could be live-tested in isolation before the next began:

1. **Stage 1 (v10.6.20).** `ClientProfile.decode()` Ed448 signature verification moved from `cryptography.Ed448PublicKey.verify` to the Rust `verify_ed448_sig` PyO3 function. The `ed448-goldilocks-plus` `VerifyingKey::verify_raw` is the exact counterpart of the `sign_raw` used by `Ed448KeyHandle::sign`.
2. **Stage 2 (v10.6.21).** The double ratchet's X448 DH moved from `cryptography.x448` to the Rust `X448KeyHandle`. No new Rust crypto — `generate_x448_keypair` and `X448KeyHandle.dh` already existed. RFC 7748 §5.2 known-answer vector added as the build-time desync guard.
3. **Stage 3 (v10.7).** Deleted the dead pure-Python `OTRv4DAKE` fallback class (863 lines). It was already uninstantiable: `RustDAKEAdapter` raised rather than constructing it, and the Rust ratchet and Rust SMP have been mandatory since v10.6.11, so a build without the Rust core could never complete a session regardless. Stripped the unreachable `_use_rust` / `_py_fallback` machinery, rescued `_safe_b64decode` to module scope, removed the four `serialization.Raw` byte-conversion sites, deleted the legacy `ed448`/`x448` `isinstance` branches from `ClientProfile`, and removed the `from cryptography...` import. The Python cryptography library is gone.

### Phase 5.3i — replace `otr4_crypto_ext` (`_ossl`) uses

This is now the largest remaining hardening item — the cryptography library is done; the C extensions are not.

1. **`_ossl.cleanse(buf)`** at the runtime memory-wipe sites. Replace with a Rust-side `cleanse` exposed via PyO3 that wraps `zeroize::Zeroize`. Bytearrays only; Python `bytes` are immutable.

2. **`_ossl.bn_mod_exp_consttime`, `bn_mod_inverse`, `bn_rand_range`** for SMP. `num-bigint` is not constant-time, so this needs careful work — either a Rust binding around a vetted constant-time bignum crate, or a port of the SMP arithmetic onto a curve-scalar-based variant.

3. **`_ossl.mlkem1024_*`** in the `MLKEM1024BraceKEM` class. Check whether this class is still reachable in production (DAKE itself uses the Rust path now) or whether it is dead code that can be deleted outright.

4. **`_ossl.disable_core_dumps`** at boot. Replace with a Python `resource.setrlimit(RLIMIT_CORE, (0, 0))` or a Rust equivalent.

5. **`_ossl.ring_sign` and `_ossl.ring_verify`** — now genuinely unused; can be removed when the C extension source is next touched.

Scope: largest remaining sub-phase, probably 200-300 lines plus the constant-time bignum decision. Two to three sessions.

### Phase 5.3j — replace `otr4_mldsa_ext` (`_mldsa`) uses

**Shipped in v10.6.18.** ML-DSA-87 keygen, sign, and verify run through `pqcrypto-mldsa 0.1.2` via Rust PyO3 bindings in `src/mldsa.rs`. `otr4_mldsa_ext.so` is no longer required for the build.

### Phase 5.3k — delete the C extensions

After 5.3i lands, this is purely deletion: remove the imports, remove the remaining `.c` and `.h` files (`otr4_crypto_ext`, `otr4_ed448_ct`) from the repo (or move to an `archived/` directory), drop the `setup_otr4.py` build target, update SECURITY.md and README.md to remove the C-extension caveat. `otr4_mldsa_ext.c` and `.so` can already be archived; nothing references them after v10.6.18. The cryptography-library caveat has already been removed as of v10.7.

## Phase 5.3g — ephemeral identity by design (DECIDED at v10.6.18)

OTRv4+ keeps **ephemeral identities** by design. Fingerprints regenerate at every launch; there is no on-disk identity vault.

Rationale:

- **Threat model fits ephemeral.** OTRv4+ runs over I2P for an IRC channel; the assumption is short-lived sessions, not long-term identity binding.
- **No on-disk attack surface.** A persistent vault would create a high-value target for offline brute-force.
- **No passphrase to forget.** Termux has no OS keyring; a vault would require user passphrase prompts at every launch.
- **Aligns with privacy-oriented messaging norms.** Tor Browser, Cwtch (default), and Briar (before user opt-in) all keep identities short-lived.

SMP trust binding is meaningful within a session. Across sessions, peers must re-verify on each connection. This is correct behaviour for the project's design intent, not a limitation.

If a user explicitly wants persistence in the future, the `Ed448KeyHandle.from_seed_bytes()` and `X448KeyHandle.from_priv_bytes()` constructors already support reconstructing a handle from raw bytes — so an external user-managed vault is possible without further code changes in OTRv4+ itself.

## Other planned work

### Better trust UX

`/trust` currently asks `y` or `n` after fingerprint display. Trust decisions do not persist across launches (consistent with the ephemeral-identity choice in 5.3g).

### Group messaging

Out of OTRv4 scope. OMEMO or MLS would be a separate project.

### Native Android APK

Building a signed `.apk` containing the Python interpreter, the Rust `.so`, and the C extensions has been investigated (see DEVELOPMENT.md). Possible but non-trivial. Termux is the supported dev environment; a native APK is future work.

### Tor onion service transport

I2P SAM bridge works today. Adding an alternative Tor `.onion` transport would broaden the deployment options. The current architecture (transport plugged into `Connection` class) supports this without crypto changes.

### Formal review

The crypto path is now small enough to be reviewable: ~3500 lines of Rust across `dake.rs`, `ratchet.rs`, `smp.rs`, `smp_vault.rs`, `ring_sig.rs`, `key_handles.rs`, `mldsa.rs`, `aead.rs`, `secure_mem.rs`, `kdf.rs`. With the Python cryptography library removed as of v10.7, the entire crypto surface is now Rust plus two C extensions slated for removal. A formal third-party review would significantly increase confidence. No funding for this; expression of interest welcome.

## What is not on the roadmap

- Backward compatibility with older v10.6.x versions. The no-fallbacks posture in v10.6.11 onward means peers must run the same major version. Wire incompatibility is accepted.
- Compatibility with stock OTRv4 implementations. The ML-DSA-87, ML-KEM-1024, and SHAKE-256 transcript additions are deliberate OTRv4+ extensions.
- Mobile push notifications. The IRC client uses persistent TCP, not push.
- File transfer. Out of scope.

## Tracking

Issues for the above are filed on the GitHub repo. Tag conventions: `phase-5.3i`, `cargo-hardening`, `phase-5.3g`. Priority is not strict; whichever has the cleanest scope on a given evening gets done.
