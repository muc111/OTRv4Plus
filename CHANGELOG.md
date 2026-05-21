# Changelog

OTRv4+ post-quantum messaging client. Solo dev project. AI-assisted (Claude). Each version live-tested between two I2P peers before commit.

---

## v10.6.19 (current) — Phase 5.3h, parts A2 + B + C

**Three of four production `cryptography` library use-classes retired. New Rust AEAD module. Startup migration for legacy orphan files.**

### Phase 5.3h scope reality check

Phase 5.3h was originally scoped as "one focused session, ~100-150 lines."  Diagnostic showed this estimate was off by an order of magnitude: the `cryptography` library has 4 use classes (AESGCM, Ed448PublicKey, X448PrivateKey/PublicKey, serialization.Raw), totalling 40+ call sites with deep coupling to the ratchet's DH path.

v10.6.19 ships the three smaller sub-phases (A2 + B + C).  The fourth (Part D — drop X448 and serialization.Raw) is multi-session and rescheduled.  See ROADMAP for the corrected split.

### Part A2 — legacy on-disk file cleanup

Startup migration in `main()` securely destroys orphan files from pre-`~/.otrv4plus/` builds:

- `~/.otrv4_vault` (633 bytes, no current code references it)
- `~/.otrv4_smp_secrets.json` (97 bytes, legacy SMP-secrets file at home root)
- `~/.otrv4_keys/` (legacy keys directory)

Uses the existing `_secure_file_destroy()` NIST SP 800-88r1 primitive: encrypt zeros with a fresh AES-256-GCM key, overwrite the file with ciphertext + tag, fsync, zeroize the key via `_ossl.cleanse`, then unlink.  No-op for new installs.

This brings the orphan files under the same Tails-mode "no trace on quit" design as `~/.otrv4plus/` itself.

### Part B — AES-256-GCM moved to Rust

New `Rust/src/aead.rs` exposes two PyO3 functions:

- `otrv4_core.aes256gcm_encrypt(key, nonce, plaintext, aad) -> bytes`
- `otrv4_core.aes256gcm_decrypt(key, nonce, ct_and_tag, aad) -> bytes`

Wraps the `aes-gcm` 0.10 crate (already in `Cargo.toml` for the ratchet path).  Wire-identical to `cryptography.hazmat.primitives.ciphers.aead.AESGCM`: encrypt output is `ciphertext || 16-byte tag`, decrypt accepts the same.

Three live AESGCM call sites swapped:

- `SMPAutoRespondStorage._load` and `_save` (encrypted SMP-secrets persistence)
- `SecureKeyStorage._encrypt_key` and `_decrypt_key` (encrypted key storage)
- `_secure_file_destroy` (the secure-wipe primitive itself — last remaining holdout)

Migration compatibility: files written by v10.6.18's `AESGCM(key).encrypt(...)` decrypt cleanly under v10.6.19's `aes256gcm_decrypt(...)`.  Same FIPS 197 AES-256, same NIST SP 800-38D GCM, same byte format.

Three new Rust unit tests (`aead::tests`): roundtrip, wrong-AAD-rejected, tampered-ciphertext-rejected.

### Part C — Ed448PublicKey wrap removed at SIX live sites (RustDAKEAdapter + OTRv4IRCClient)

Six `Ed448PublicKey.from_public_bytes(...)` call sites swapped from cryptography library wrapping to raw bytes (or `None` where the bytes path takes over):

**Three sites in `RustDAKEAdapter`** at the post-DAKE1, post-DAKE2-Rust, and post-DAKE2-legacy paths.  Each wrapped the peer's raw 57-byte identity pub into `Ed448PublicKey` stored as `self.remote_identity_key`.  Diagnostic showed the attribute is only consumed by `session_keys['peer_long_term_key']` dict entries which are never read by any downstream code.  v10.6.19 keeps the attribute name and stores raw bytes; type hint widened from `Optional[ed448.Ed448PublicKey]` to `Optional[Any]`.

**Three sites in `OTRv4IRCClient`** (DAKE2-initiator-establish, DAKE3-responder-establish, post-establish retry).  Each wrapped `session_keys['peer_long_term_pub']` (raw bytes) into `Ed448PublicKey` stored as `session.remote_long_term_pub`.  Used downstream at `get_fingerprint()` (~line 7220) and `_get_remote_fp` (~line 12860) only to call `.public_bytes()` on the object to extract the same bytes back, then SHA3-512 them for fingerprint.  Both call sites already have a fallback path that computes SHA3-512 directly from `_remote_long_term_pub_bytes` if `remote_long_term_pub` is None.

v10.6.19 sets `session.remote_long_term_pub = None` at all three sites; the fallback `_remote_long_term_pub_bytes` path produces an identical SHA3-512 fingerprint without the cryptography library round-trip.  Legacy-non-Rust branch (where `pub_key_data` is already an `Ed448PublicKey` object rather than bytes) is preserved untouched.

The third retry-wrap site (`if remote_long_term_pub is None and bytes is not None: wrap`) is deleted entirely — the comment explains the bytes path handles it.

### `cryptography` library import diet

Top-of-file imports before v10.6.19:

```python
from cryptography.hazmat.primitives.asymmetric import ed448, x448
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
```

After v10.6.19:

```python
from cryptography.hazmat.primitives.asymmetric import ed448, x448
from cryptography.hazmat.primitives import serialization
```

Dropped: `AESGCM` (replaced by Rust), `hashes` (confirmed unused by grep audit).

**`ed448` import remains** — not removed in v10.6.19 despite the earlier scope estimate.  Reason: `ClientProfile.decode()` at line ~2644 uses `ed448.Ed448PublicKey.from_public_bytes(...).verify(...)` for incoming-profile signature verification.  This is a security-critical code path; replacing it cleanly needs a new Rust PyO3 `verify_ed448_sig(pub, msg, sig) -> bool` function plus a focused test cycle.  Scheduled for Phase 5.3h-D.

What v10.6.19 DID drop with respect to `ed448`:
- Three `Ed448PublicKey.from_public_bytes` sites in `RustDAKEAdapter` (the `self.remote_identity_key` wraps)
- Three `Ed448PublicKey.from_public_bytes` sites in `OTRv4IRCClient._handle_dake*` (the `session.remote_long_term_pub` wraps)

Remaining live `ed448` use: one site at ~2644 for ClientProfile signature verification, plus legacy non-Rust DAKE paths at ~3794 and ~3988 (gated by `not self._use_rust`, never fires in v10.6.11+ production).

`x448` (ratchet DH and legacy DAKE), `serialization` (~20 byte-conversion sites): also still present; addressed in 5.3h-D.

### Files touched

- `Rust/src/aead.rs`: new file, ~165 lines including tests
- `Rust/src/lib.rs`: added `pub mod aead;` and two `add_function` registrations
- `Rust/Cargo.toml`: version 0.10.18 → 0.10.19 (no new deps; aes-gcm already pulled)
- `otrv4+.py`:
   - Top-of-file: dropped `AESGCM` and `hashes` imports
   - `_secure_file_destroy`: line 383 AESGCM swapped to Rust aead
   - `SMPAutoRespondStorage._load` (~5360) and `_save` (~5406): AESGCM swapped to Rust aead
   - `SecureKeyStorage._encrypt_key` (~5210) and `_decrypt_key` (~5226): AESGCM swapped to Rust aead
   - `RustDAKEAdapter`: three `Ed448PublicKey.from_public_bytes` sites at ~4671, ~4814, ~4846 replaced with raw-bytes assignment
   - Type hint at line ~3542: `Optional[ed448.Ed448PublicKey]` → `Optional[Any]`
   - `_check_rust_requirements`: required `aes256gcm_encrypt` and `aes256gcm_decrypt` on otrv4_core module
   - `main()`: startup migration to securely destroy `~/.otrv4_vault`, `~/.otrv4_smp_secrets.json`, `~/.otrv4_keys/`
   - VERSION → `10.6.19`
- `README.md`: chip update; caveat 5 narrowed (cryptography lib subset)
- `SECURITY.md`: caveat 4 updated to mention v10.6.19's three-class drop
- `ROADMAP.md`: Phase 5.3h split into A2/B/C (shipped) and D (pending, multi-session)
- `CHANGELOG.md`: this entry
- `FEATURES.md`: AES-256-GCM row points to `aes-gcm` Rust crate only

### Build verification

```
cargo test --release --no-default-features --features pq-rust
# expected: 12 passed (5 ring_sig + 1 RFC 8032 + 3 mldsa + 3 aead)
```

Live wire-test still produces `hybrid (ring-sig ✓ + ML-DSA-87 ✓)` on DAKE3 verification.  SMP auto-respond still loads cleanly from a pre-existing encrypted secrets file.

---

## v10.6.18 — Phase 5.3j + Phase 5.3g (ephemeral-by-design decided)

**`otr4_mldsa_ext` C extension retired; ML-DSA-87 now runs entirely on `pqcrypto-mldsa 0.1.2` via Rust PyO3 bindings.**

The Python `MLDSA87Auth` class is unchanged externally — same `PUB_BYTES = 2592`, `SIG_BYTES = 4627`, same wire-format guards across the four parse sites in `EnhancedOTR.{_handle_dake1, _handle_dake2, _handle_dake3_initiator, _handle_dake3_responder}`. Three call sites internal to the class now delegate to `_RustDAKE_module.mldsa87_keygen / mldsa87_sign / mldsa87_verify` instead of the deleted `_mldsa.mldsa87_*` C extension entry points.

The new Rust module `Rust/src/mldsa.rs` is a thin PyO3 wrapper over `pqcrypto-mldsa::mldsa87::{keypair, detached_sign, verify_detached_signature}`. Three unit tests in the same file: round-trip, tampered-message rejection, FIPS 204 byte-size assertions (2592 / 4896 / 4627).

### Wire format

Byte-identical to v10.6.17. Both v10.6.17 and v10.6.18 peers can DAKE with each other — same FIPS 204 ML-DSA-87 parameter set, same PQClean reference implementation underneath. The C extension and the Rust crate are both PQClean-derived; outputs match bit-for-bit.

### Cargo.toml hardening

`pqcrypto-mldsa` is pinned to `default-features = false, features = ["std"]` to disable AVX2 and NEON SIMD code paths. Same trap that hit `pqcrypto-mlkem` in v10.6.16: the NEON path triggers `SIGILL` on Termux/aarch64 at first `mldsa87_keygen()` call. Portable C reference is used.

### Phase 5.3g — ephemeral identity (DECIDED)

After consideration, OTRv4+ keeps ephemeral identities by design. Fingerprints regenerate at every launch; no persistent vault. Rationale documented in ROADMAP.md and SECURITY.md.

### Files touched
- `Rust/src/mldsa.rs`: new file, ~120 lines including tests
- `Rust/src/lib.rs`: added `pub mod mldsa;` and three `add_function` registrations
- `Rust/Cargo.toml`: pqcrypto-mldsa pinned to `default-features = false`, version 0.10.17 → 0.10.18
- `otrv4+.py`: removed `import otr4_mldsa_ext as _mldsa` block; `MLDSA87_AVAILABLE` reduced to a hardcoded `True` so the four wire-format guards stay structurally unchanged; three `_mldsa.*` calls in `MLDSA87Auth` swapped to `_RustDAKE_module.*`; `_check_rust_requirements` now requires `mldsa87_keygen/sign/verify` on the otrv4_core module; VERSION → `10.6.18`
- `README.md`: drop `gcc -o otr4_mldsa_ext.so` from Quick start; chip updated; caveats 4/5/7 updated; architecture box mentions FIPS 204 for ML-DSA
- `SECURITY.md`: caveat 4 (C extensions) updated to two remaining; new caveat 5 documents ephemeral-by-design rationale
- `ROADMAP.md`: Phase 5.3j marked shipped; Phase 5.3g rewritten as "decided: ephemeral by design" with rationale; Phase 5.3k note updated to mention `otr4_mldsa_ext` can be archived
- `FEATURES.md`: ML-DSA-87 row points to `pqcrypto-mldsa` only

### Build verification

```
cargo test --release --no-default-features --features pq-rust
# expected: 9 passed (5 ring_sig + 1 RFC 8032 + 3 mldsa)
```

---

## v10.6.17 — Phase 5.3f-narrow

**Boot-time cross-verify removed; RFC 8032 vectors now build-time gate.**

The Python boot helpers `_verify_ed448_rust_compat()` and `_verify_ring_sig_rust_compat()` are deleted. They previously generated a fresh Ed448 keypair via the cryptography library at every program start, signed a test message with both Rust and OpenSSL, and compared byte-for-byte. The ring-sig helper additionally invoked the C extension's `ring_sign`/`ring_verify` to confirm two-way wire-format compatibility with Rust.

Both functions and all four call sites (in `RingSignature.sign`, `RingSignature.verify`, `ClientProfile.encode`, `RustDAKEAdapter`) are removed. Their guard-clause `RuntimeError` raises are also gone.

Replacement: `Rust/src/test_vectors.rs` contains the RFC 8032 §7.4 "Blank" Ed448 vector as `const` arrays and a `#[cfg(test)]` harness that signs with `ed448-goldilocks-plus::SigningKey` and asserts byte-equality. Before any release:

```
cargo test --release --no-default-features --features pq-rust
```

If the test fails, the Rust Ed448 implementation has drifted from RFC 8032 and the build is not safe to ship.

**Boot is faster** (saves ~200ms of keypair-gen + Ed448 sign + ring-sig two-way check). Six obsolete boot-print lines no longer appear.

### Important — what this does NOT change

The C extensions (`otr4_crypto_ext`, `otr4_mldsa_ext`) and the Python `cryptography` library are **still load-bearing in production**. They were not previously dead, contrary to earlier documentation:

- `otr4_crypto_ext` is invoked from 20+ runtime sites (memory wiping, constant-time big-num arithmetic for SMP, ML-KEM keygen/encap/decap in the legacy `MLKEM1024BraceKEM` Python class, `mlock`, `disable_core_dumps`).
- `otr4_mldsa_ext` is invoked for all ML-DSA-87 keygen/sign/verify.
- The `cryptography` library is invoked for Ed448 public-key wrapping in three DAKE post-processing sites (UI-side `remote_identity_key` for fingerprint display), and for AES-GCM in the persistent SMP secrets store.

Removing these is multi-phase work tracked as Phase 5.3h, 5.3i, 5.3j, 5.3k on the ROADMAP.

### Files touched
- `otrv4+.py`: deleted ~150 lines (two helper functions, two globals, two boot comment blocks, four call sites). Updated three docstrings. VERSION → `10.6.17`.
- `Rust/src/test_vectors.rs`: new file, ~100 lines.
- `Rust/src/lib.rs`: added `pub mod test_vectors;`.
- `Rust/Cargo.toml`: version 0.10.16 → 0.10.17.
- README.md, SECURITY.md, ROADMAP.md: corrected previously-inaccurate claims about C extensions and the cryptography library being "not invoked at runtime".

---

## v10.6.16 — ML-KEM migration

**`pqcrypto-kyber 0.8` (round-3 Kyber) replaced by `pqcrypto-mlkem 0.1.1` (FIPS 203 ML-KEM-1024).**

NIST finalised FIPS 203 in August 2024. The standard differs from round-3 Kyber in the Fujisaki-Okamoto domain-separator constants; algorithms and parameter sizes are otherwise identical (same lattice, same 1568/3168/1568-byte pk/sk/ct, 32-byte shared secret).

The `pqcrypto-mlkem` Rust API is drop-in compatible with `pqcrypto-kyber`:

```rust
pub fn keypair() -> (PublicKey, SecretKey)
pub fn encapsulate(pk: &PublicKey) -> (SharedSecret, Ciphertext)
pub fn decapsulate(ct: &Ciphertext, sk: &SecretKey) -> SharedSecret
```

The `(SharedSecret, Ciphertext)` return-tuple footgun is preserved; the wrapper in `dake.rs` swaps to `(ct, ss)` for caller convenience as before.

### Cargo.toml carve-out

The `pqcrypto-mlkem` crate defaults to `["avx2", "neon", "std"]` features. On Termux/aarch64, the NEON path caused SIGILL at first `keypair()` call (an ARMv8 instruction extension not universally available). Pinned to `default-features = false, features = ["std"]` to select the portable PQClean C reference. Performance impact is invisible at session scale (ML-KEM runs once per DAKE).

### Wire compatibility

**Wire-incompatible with v10.6.15 and earlier.** Both peers must run v10.6.16+ to DAKE. Acceptable since OTRv4+ has no external users.

### Files touched
- `Rust/Cargo.toml`: dependency swap, version 0.10.14 → 0.10.16.
- `Rust/src/dake.rs`: 7 call sites renamed `pqcrypto_kyber::kyber1024::` → `pqcrypto_mlkem::mlkem1024::`.

---

## v10.6.15.5 — Cargo.toml: restore signing+pkcs8 features

**Latent silent build break exposed by `cargo clean`.**

An earlier hardening pass had set `ed448-goldilocks-plus` to `default-features = false, features = ["alloc"]`. This silently dropped the `signing` feature (which gates `SigningKey` export) and `pkcs8` (which `signing` transitively requires via an unconditional `pub use pkcs8;` in `sign.rs`).

Every use of `ed448_goldilocks_plus::SigningKey` in `dake.rs` and `key_handles.rs` would fail to compile. The break was latent because the live `.so` from the previous successful build (pre-change) kept running as long as no `cargo build` was actually forced. `cargo clean` exposed it.

Fix:

```toml
ed448-goldilocks-plus = {
    version          = "0.16",
    optional         = true,
    default-features = false,
    features         = ["alloc", "signing", "pkcs8"],
}
```

This restored the Phase 5.3e (v10.6.12) Rust handle architecture as genuinely-live for the first time.

---

## v10.6.15 — SMP race fix

**Tie-break by fingerprint when both peers run `/smp start` simultaneously.**

OTRv4 SMP is not symmetric: one side must initiate, the other must respond. If both peers run `/smp start` near-simultaneously, each generates SMP1 locally before either receives the other's SMP1. Each side then receives SMP1 while its own Rust SMP engine is in `AwaitingMsg2`, and the engine correctly rejects with "SMP not in Idle for SMP1".

Resolution: at SMP1 receive, if the engine is in non-Idle phase, compare identity public bytes:

- Lower fingerprint keeps initiator role; ignores incoming SMP1.
- Higher fingerprint yields: aborts its own `RustSMP`, rebuilds the engine fresh, rebinds the secret from the still-populated `RustSMPVault` (vault is a separate object, holding the secret independently of the SMP state machine), processes the incoming SMP1 as responder.

The vault-based persistence is what makes this clean. No re-prompting for the secret.

---

## v10.6.14 — `lazy_static` → `std::sync::LazyLock`

RustSec lists `lazy_static 1.5` as unmaintained. Replaced with stdlib `LazyLock` (stable since Rust 1.80, August 2024). Three statics in `smp.rs` (`SMP_PRIME`, `SMP_ORDER`, `SMP_GEN`) converted; all 31 call sites unchanged because `LazyLock<T>: Deref<Target=T>` matches the old proxy behaviour exactly.

MSRV raised to 1.80+. Current build uses 1.94.1.

---

## v10.6.13

**SMP regression fix from v10.6.12.**

v10.6.12 left seven Python call sites using the legacy cryptography library `.public_key().public_bytes(...)` chain on what was now a Rust handle. Handles do not have `.public_key()` (they expose `.public_bytes()` directly), so the chain raised `AttributeError` at runtime.

Most of those sites were silenced by surrounding `except` blocks and either fell back to the cached `identity_pub_bytes` (correct path) or did not fire. One site, `EnhancedOTRSession.set_smp_secret`, read the local fingerprint through the broken chain unconditionally and silently fell back to an empty bytes literal as `local_fp`. Both peers then computed `secret_hash = SHA3(b'' || remote_fp || password)`, with each peer's `remote_fp` being the other side's identity bytes. The two hashes diverged. SMP correctly reported "secrets did not match" even with identical passwords.

DAKE was unaffected because `identity_pub_bytes` is cached at `ClientProfile.__init__` and the DAKE path used the cache directly, never falling through to the broken chain.

Sites fixed in v10.6.13:

- `ClientProfile.get_fingerprint`
- `ClientProfile.get_prekey_fingerprint`
- `EnhancedOTRSession.set_smp_secret` (the actual SMP regression)
- `RustDAKEAdapter.__init__` defensive identity/prekey pub-bytes refresh (two sites)
- DAKE3 sign and verify A1/A2 fallback paths (four sites)

All converted to `bytes(handle.public_bytes())`. Production paths were already using the cache; the fallback paths now also do the correct thing if the cache is ever invalidated.

No Rust changes. Wire-compatible with v10.6.12.

---

## v10.6.12

**Phase 5.3e: long-term identity keys owned by Rust.**

`ClientProfile.identity_key` and `.prekey` are now `Ed448KeyHandle` and `X448KeyHandle` (opaque PyO3 classes). Their private bytes live inside Rust `SecretBytes<N>` (ZeroizeOnDrop) for the session lifetime. Python receives only public bytes via `handle.public_bytes()`.

This eliminates the cryptography library `Ed448PrivateKey` / `X448PrivateKey` Python objects from all production code paths. After v10.6.12, long-term identity private bytes never appear on the Python heap during normal session operation. The cryptography library remains loaded only for the boot-time compat-check helpers, which use fresh ephemeral test keys discarded immediately.

New Rust file `src/key_handles.rs`:

- `Ed448KeyHandle` with `SecretBytes<57>`, `public_bytes()`, `sign(msg)`, `ring_sign(A1, A2, msg)`
- `X448KeyHandle` with `SecretBytes<56>`, `public_bytes()`, `dh(peer_pub)`
- Factory functions `generate_ed448_keypair()` and `generate_x448_keypair()` produce fresh keypairs inside Rust
- `pub(crate)` accessors for crate-internal use by `dake.rs`

New Rust method `dake::PyDake::sign_profile_body_and_construct_with_handles`. Takes `&Bound<Ed448KeyHandle>` and `&Bound<X448KeyHandle>` instead of `Bound<PyByteArray>` for the private bytes. Reads from the handles inside Rust to construct `DakeState` and sign the profile in a single FFI call. Handles remain alive on `ClientProfile` after the call.

Python changes:

- `ClientProfile.__init__` generates via Rust factories by default. Accepts legacy `ed448.Ed448PrivateKey` / `x448.X448PrivateKey` for test backward compatibility (converts to handles via `from_seed_bytes` / `from_priv_bytes` with bytearray-and-wipe).
- `encode()` and `encode_unsigned()` use cached `identity_pub_bytes` / `prekey_pub_bytes` set at `__init__` from `handle.public_bytes()`.
- `encode()` signs via `self.identity_key.sign(profile_data)`. No seed extraction.
- `RingSignature.sign(handle, A1, A2, msg)` takes a handle and calls `handle.ring_sign(A1, A2, msg)`.
- `RustDAKEAdapter.__init__` uses `sign_profile_body_and_construct_with_handles` in a single FFI call. No Python-side bytearray extraction.
- Import-time fail-fast check now requires the new Rust symbols.

Wire-compatible with v10.6.11. No protocol-level changes.

---

## v10.6.11

**Phase 5.4: Rust-only, no fallbacks, regression fix.**

Architectural commitment release. OTRv4+ is now a thin Python wrapper around the `otrv4_core` Rust crate. No production codepath falls back to the C extension or the cryptography library. If the Rust core is missing or incompatible, the module raises at import time.

Regression fix from v10.6.10: v10.6.10's attempt to pass a Python `bytearray` directly to `py_ring_sign` as the FFI argument caused `DAKE3 GEN_FAILED` at runtime. PyO3's `&[u8]` does not reliably accept `bytearray` across versions. v10.6.11 reverts to `bytes(_seed)` as the FFI argument (one immediate snapshot, GC'd after the call). The bytearray is still used as the wipeable source.

Every production crypto site is now Rust-only and raises `RuntimeError` on failure:

- `RingSignature.sign` and `.verify` use `otrv4_core.py_ring_sign` / `py_ring_verify`
- `ClientProfile.encode` Ed448 signature uses `otrv4_core.RustDAKE.ed448_sign_test`
- `RustDAKEAdapter.__init__` uses `otrv4_core.RustDAKE` (no `OTRv4DAKE` Python fallback)
- SMP and ratchet were already Rust-mandatory

New `_check_rust_requirements()` runs at module load. Verifies `otrv4_core` is importable and exposes the required class methods and free functions. Missing anything raises `ImportError` with a specific rebuild instruction.

The boot-time cross-verify helpers (`_verify_ed448_rust_compat`, `_verify_ring_sig_rust_compat`) remain, but they are no longer fallback gates. They are boot validators. The C extension and the cryptography library are invoked once at startup to serve as ground-truth references. After both checks pass, neither is called again for any runtime crypto.

Deliberate consequences (user-accepted):

- v10.6.11 cannot interoperate with any peer that lacks the Rust `ring_sig` module in its `otrv4_core` `.so`. Older v10.6.x peers will fail DAKE3.
- Missing or stale `.so` means the app refuses to start.

---

## v10.6.10

**Phase 5.3d.** Bytearray + wipe in `RingSignature.sign()`. Removed the Rust signing path from `ClientProfile.encode()` (cryptography library `identity_key.sign(...)` keeps bytes in OpenSSL's C heap, not Python's).

This release contained a regression that broke DAKE3. `_rust_ring_sign` was called with a bare bytearray, which PyO3 rejected at runtime with `GEN_FAILED`. Fixed in v10.6.11.

---

## v10.6.9

**Phase 5.3c: Rust DAKE3 ring signature.** New file `src/ring_sig.rs` (~407 lines) implementing OTRv4 §4.3.3 Schnorr ring signature in pure Rust using `ed448-goldilocks-plus` and `sha3` (SHAKE-256). Direct port of `otr4_crypto_ext.c`'s `py_ring_sign` / `py_ring_verify` / `ring_challenge`.

Two-way cross-verify safeguard at startup: Rust signs, C verifies; C signs, Rust verifies. Both must pass before the Rust path activates.

---

## v10.6.8

**Phase 5.3b: dead-code disk persistence removal.** `_store_identity()` previously wrote encrypted private-key blobs to disk on every session start. Audit revealed nothing ever read them back. Removed the private-bytes extraction; still persists the public profile. Added one-shot migration that overwrites and unlinks legacy `identity.ed448.bin` / `prekey.x448.bin` files at startup.

---

## v10.6.7

**Phase 5.3a-cleanup.** Added `ClientProfile.encode_unsigned()`. `RustDAKEAdapter.__init__` now uses `sign_profile_body_and_construct` in a single FFI call. Eliminated the `bytes(_ik_priv)` snapshot at the constructor boundary.

---

## v10.6.6

**Phase 5.3a (Option A2): Ed448 sign via Rust.** Added `sign_profile_body_and_construct` and `ed448_sign_test` to the Rust DAKE class. Boot-time cross-verify check compares Rust Ed448 signatures against OpenSSL byte-for-byte on a fresh test key.

---

## v10.6.5

**Phase 5.2: `new_from_bytearrays`.** Rust constructor takes `Bound<PyByteArray>` instead of `&[u8]`. Rust copies into `SecretBytes<N>` via a `SecretVec` intermediate, then wipes the source bytearray in-place via `PyByteArray::set_item`. Eliminates the `bytes(...)` snapshot that v10.6.4's `&[u8]` argument created.

---

## v10.6.4

**Phase 5.1.** `RustDAKEAdapter.__init__` extracts identity and prekey private bytes into mutable bytearrays instead of immutable bytes. Wipes the bytearrays in place after Rust copies into `SecretBytes`. Removed the dead per-call `hasattr` probe for `client_profile.prekey_priv_bytes` (always False).

---

## v10.6.3

**Phase 4: DakeOutput opaque handle. 11/11 audit findings closed.**

DAKE session keys never cross the Python heap. The `DakeOutput` PyO3 handle holds them in a private `RefCell<Option<DakeSessionKeys>>` with no Python-visible accessor. `consume_into_ratchet()` moves them directly into the ratchet's owned `SecretBytes` fields.

Critical fix: `consume_into_ratchet` takes the actual `is_initiator` flag instead of hardcoded True. Role-based chain-key swap moved into `DoubleRatchet::new` inside Rust. Python cannot pre-swap chain keys.

---

## Older versions

Earlier v10.6.x and v10.5.x focused on Rust SMP, Rust double ratchet, X448 ratchet bugs, fragment buffer collision fixes, and the C extension constant-time Ed448 path. See git history for detail.
