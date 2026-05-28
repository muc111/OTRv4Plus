# Changelog

OTRv4+ post-quantum messaging client. Solo dev project. AI-assisted (Claude). Each version live-tested between two I2P peers before commit.

---

## v10.7.5 (current) — ClientProfile validity tightened to 14 days

The OTRv4 spec §4.1 recommends short ClientProfile lifetimes (weeks rather than years).  Earlier versions used a 365-day expiry that was inherited from the pre-ephemeral design and never revisited.  For OTRv4+, where the long-term identity key is regenerated at every launch, a 1-year profile validity widened the impersonation window without buying anything — peers see a fresh profile on every DAKE1 anyway.

**Changed.**  `ClientProfile.expires = self.created + 365 * 24 * 3600` → `self.created + self.VALIDITY_SECONDS`, where `VALIDITY_SECONDS = 14 * 24 * 3600`.  Two sites (constructor and `renew()`) now reference the single class-level constant, so they can't drift again.  Matches `otr4j`'s default.

No protocol or wire change.  Existing offline-cached profiles older than 14 days now require a fresh DAKE1 (which OTRv4+ would have done anyway because of session ephemerality).

---

## v10.7.4 — Phase 5.3k + 5.3i-D: Rust-core-only, the architectural finish line

**All C extensions retired.**  OTRv4+ now has a single cryptographic implementation surface: the Rust `otrv4_core` PyO3 module.  No second backend, no compile-time conditionals selecting between paths, no Python-vs-Rust comparison checks at boot.

**Phase 5.3k — file deletions and import removal.**
- `otrv4+.py`: the `otr4_ed448_ct` import block deleted.  A grep for `_ed448_ct.` member access was empty before deletion — the import was a defensive ground-truth that had no live callers anywhere in the codebase.  `ED448_CT_AVAILABLE` removed.  The `_sys.path.insert(...)` line was retained (still needed for `otrv4_core` import resolution).
- `git rm`: `otr4_crypto_ext.c`, `otr4_crypto_ext.so`, `otr4_crypto_ext.cpython-313-aarch64-linux-android.so`, `otr4_ed448_ct.c`, `otr4_ed448_ct.so`, `otr4_mldsa_ext.c`, `otr4_mldsa_ext.so` (the last set was orphaned since v10.6.18), `setup_otr4.py`.
- Test migration: seven test files in `tests/` (`test_mlkem_kat.py`, `test_property.py`, `test_differential.py`, `fuzz_harnesses.py`, `test_ratchet_torture.py`, `test_ring_android.py`, `test_attacks.py`) migrated from `import otr4_crypto_ext as _ossl` to `import otrv4_core as _ossl`.  The Rust module exposes `mlkem1024_keygen` / `_encaps` / `_decaps` with identical signatures, so the migration was a one-line import swap for six of them.  `test_attacks.py` additionally uses `_ossl.cleanse`, so it received a small `_OsslShim` providing the Rust ML-KEM functions plus a `ctypes.memset` cleanse.
- `git rm tests/test_otr.py` — this was a smoke test for all three retired C extensions' surfaces (bignum ops, `ring_sign`, `ed448_scalarmult`, `mldsa87_*`); after the migration it tested only deleted code.
- Documentation updated across `README.md`, `SECURITY.md`, `ROADMAP.md`, `CHANGELOG.md`, `FEATURES.md`, `DEVELOPMENT.md`, `MIGRATION.md`, `CONTRIBUTING.md`, and both `prebuilt/` READMEs.

**Phase 5.3i-D — `aead.rs` warning cleanup.**
The 13 deprecation warnings emitted by `aead.rs` since v10.6.19 were all uses of `aes-gcm 0.10`'s deprecated `GenericArray::from_slice` helper.  Fix: production sites now use `Aes256Gcm::new_from_slice(key)` (from the `KeyInit` trait, takes `&[u8]`, returns `Result<Self, InvalidLength>`) and convert the nonce slice to `&[u8; 12]` via `try_into()` then `Nonce::from(*nonce_arr)` (matching the actual `impl From<[u8; 12]> for GenericArray<u8, U12>` in `generic-array 0.14.7`).  Test sites use `Nonce::from(n)` directly since `n` is already `[u8; 12]`.  Restored the zero-warning Rust build that v10.6.18 originally achieved.

**Verified.**  `cargo test` 20 passed, 0 failed.  `cargo build` 0 warnings.  Live DAKE + SMP VERIFIED + multi-epoch ratchet across an I2P channel with peer `CopperFox`.

---

## v10.7.3 — Phase 5.3i-C: ML-KEM-1024 brace KEM moved to Rust

`MLKEM1024BraceKEM` (the double ratchet's post-quantum brace-key KEM) migrated from `_ossl.mlkem1024_*` to Rust `pqcrypto-mlkem 0.1.1`.  Same crate that already backs the DAKE KEM in `dake.rs`; the new `src/mlkem.rs` PyO3 module exposes three functions (`mlkem1024_keygen` / `_encaps` / `_decaps`) wrapping it.

**Subtlety.**  pqcrypto's `encapsulate(public_key)` returns `(SharedSecret, Ciphertext)` — the *opposite* tuple ordering from the C extension's `(ciphertext, shared_secret)`.  The Rust wrapper inverts the tuple to match the existing Python contract exactly; the existing Python callers and tests are unchanged.  Three Rust unit tests cover byte sizes against FIPS 203, full keygen→encaps→decaps shared-secret matching, and wrong-key rejection.

After this commit, `otr4_crypto_ext` had no remaining callers anywhere in the codebase.  The import block in `otrv4+.py` was removed; the `.c`/`.so` files were left in place for Phase 5.3k to delete.

`Rust/Cargo.toml`: `otrv4_core` version bumped 0.10.21 → 0.10.22 to reflect the new module.

---

## v10.7.2 — Phase 5.3i-B: `_ossl.cleanse` replaced with `ctypes.memset`

The OpenSSL-backed `_ossl.cleanse(bytearray)` zeroization helper replaced with a module-level `_secure_wipe(bytearray)` using `ctypes.memset` via a `c_char * len` view into the bytearray's buffer.  This is the standard dead-store-resistant wipe technique (memset through a `volatile`-ish indirection so LLVM cannot prove the writes are unobservable and elide them).

**Sites updated.**  Eight `_ossl.cleanse(...)` calls repointed to `_secure_wipe(...)`.  Two were deleted as redundant (`SecureMemory.zeroize` already wiped via `ctypes`; `_secure_file_destroy` already wiped its key buffer manually).

No third-party-library dependency for memory wiping anywhere in the codebase now — `ctypes` is stdlib, `zeroize::Zeroize` is in Rust.

---

## v10.7.1 — Phase 5.3i-A: dead bignum wrappers + `disable_core_dumps` migration

Four dead Python wrappers around the C extension's bignum surface deleted as part of the 5.3i lead-in.  All four were leftovers from the pre-Rust-SMP era when SMP arithmetic lived in Python and called into `otr4_crypto_ext.bn_*`.  Since the v10.6.x Rust SMP migration, SMP modular arithmetic has lived entirely inside `src/smp.rs` (using `num-bigint`); the wrappers had no callers.

- `_ct_mod_exp` (wrapper around `_ossl.bn_mod_exp_consttime`) — deleted.
- `_ct_mod_inv` (wrapper around `_ossl.bn_mod_inverse`) — deleted.
- `_ct_rand_range` (wrapper around `_ossl.bn_rand_range`) — deleted.
- `SHA3_512.hash_to_int` — deleted.  Referenced the long-removed `SMPConstants` class.

`disable_core_dumps()` migrated from `_ossl.disable_core_dumps` to Python `resource.setrlimit(RLIMIT_CORE, (0, 0))`.  Pure stdlib; no C extension call.

Python-only change; no Rust rebuild required.

---

## v10.7 — Phase 5.3h-D complete: Python cryptography library fully removed

**The Python `cryptography` library is no longer imported or used in any code path. Every asymmetric and symmetric cryptographic operation runs in the Rust `otrv4_core` core.**

v10.7 is the final stage of Phase 5.3h-D. Stages 1 and 2 (v10.6.20, v10.6.21) moved the last two live cryptography-library uses — Ed448 verification and the X448 ratchet DH — into Rust. v10.7 removes the dead code that still referenced the library and deletes the import.

### What was removed

**The pure-Python `OTRv4DAKE` fallback class — 863 lines.** This class was the original Python DAKE implementation, kept as a fallback for builds without the Rust core. It was already uninstantiable in practice:

- `RustDAKEAdapter.__init__` either succeeds with the Rust backend or raises `RuntimeError`. It never constructs `OTRv4DAKE`. The `_use_rust` flag was always `True` by the time any adapter method ran.
- The Rust ratchet (`RUST_RATCHET_AVAILABLE`) and Rust SMP have been mandatory since v10.6.11 — a build without the Rust core raises long before any DAKE fallback could matter. The Python DAKE could never actually carry a session to completion.

So `OTRv4DAKE` was ~860 lines of unreachable code plus, in `RustDAKEAdapter`, 12 dead `if not self._use_rust: return self._py_fallback.…` branches. All deleted.

**The `_use_rust` / `_py_fallback` machinery.** 12 dead guard blocks, the `self._use_rust` / `self._py_fallback` field declarations, the dangling end-of-`__init__` fail-fast block, and the `MLDSA87_AVAILABLE and self._use_rust` guard simplified to `MLDSA87_AVAILABLE`. Three debug-tag sites that read `_use_rust` for a "🦀/🐍" label are hardcoded to Rust.

**The cryptography library import.** The top-of-file block

```python
try:
    from cryptography.hazmat.primitives.asymmetric import ed448, x448
    from cryptography.hazmat.primitives import serialization
    ...
```

is gone, replaced by a comment recording that all crypto is now Rust-side.

### What was rescued and rewritten

**`_safe_b64decode`** was a `@staticmethod` on `OTRv4DAKE` with five callers (three inside the deleted class, two elsewhere — `_handle` paths around lines 11116 and 12497). It is lifted to a module-level function defined before `class DAKE1RateLimiter:`. All five callers repointed from `OTRv4DAKE._safe_b64decode(...)` to the bare `_safe_b64decode(...)`.

**`ClientProfile.__init__`** previously accepted legacy `ed448.Ed448PrivateKey` / `x448.X448PrivateKey` arguments and converted them to Rust handles via `isinstance` branches (a test-only path). Those branches are deleted (option B1): `ClientProfile` now accepts only `None` (generate a fresh Rust handle) or an already-constructed handle. The cryptography-library type hints on the `__init__` signature are stripped. Every runtime `ClientProfile()` call site constructs with no arguments, so nothing in production is affected.

**Four `serialization.Raw` sites removed.** `remote_long_term_pub` has held raw 57-byte Ed448 public-key bytes since v10.6.19 (Phase 5.3h-C), so the `.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)` calls in `get_fingerprint()`, `_get_remote_fp()`, and the two `pub_key_data` extraction sites were operating on raw bytes anyway (their surrounding `try/except` swallowed the `AttributeError`). Replaced with direct `bytes(...)` use. The `remote_long_term_pub` type hint changed from `Optional[ed448.Ed448PublicKey]` to `Optional[bytes]`.

### Net effect

883 lines removed from `otrv4+.py`. No Rust changes — the Rust core was already complete at the v10.6.21 state. The crypto surface of the project is now Rust (`otrv4_core`) plus two C extensions (`otr4_crypto_ext`, `otr4_ed448_ct`) slated for removal in Phase 5.3i / 5.3k. There is no OpenSSL-backed Python crypto anywhere.

### Files touched

- `otrv4+.py`: deleted `OTRv4DAKE` class and `_use_rust`/`_py_fallback` machinery; rescued `_safe_b64decode` to module scope; rewrote `ClientProfile.__init__` (B1); removed four `serialization.Raw` sites; removed the `from cryptography...` import; VERSION → `10.7`
- `README.md`: chip → v10.7; architecture box notes the library is removed; caveat about the cryptography library replaced; Quick start drops the `pip install cryptography` step
- `SECURITY.md`: known-issue 3 rewritten — the cryptography library is gone, with the v10.6.18→v10.7 removal sequence documented; memory-safety model updated
- `ROADMAP.md`: Phase 5.3h-D marked complete; 5.3i is now the largest remaining hardening item
- `FEATURES.md`: primitive table no longer lists any cryptography-library implementation
- `CHANGELOG.md`: this entry

### Build verification

```
cargo test --release --no-default-features --features pq-rust
# expected: 17 passed (5 ring_sig + 1 RFC 8032 Ed448 + 3 mldsa + 3 aead
#                      + 3 key_handles Ed448 + 2 X448)
```

`python otrv4+.py --debug` boots to the connect screen with no `NameError` or `ImportError` — the boot-check that confirms every reference to the deleted class and removed imports was caught. Live: DAKE + SMP verified over I2P.

---

## v10.6.21 — Phase 5.3h-D stage 2: X448 ratchet DH moved to Rust

**The double ratchet's X448 Diffie-Hellman now runs in the Rust core. No Python cryptography-library X448 remains in the message path.**

`RustBackedDoubleRatchet` performed its DH ratchet steps with `cryptography.x448` — `X448PrivateKey.generate()`, `.exchange()`, `X448PublicKey.from_public_bytes()` — running on every message after the first. These now use the Rust `otrv4_core` `X448KeyHandle`.

**No new Rust crypto.** `generate_x448_keypair()` and `X448KeyHandle.dh()` already existed (used by `ClientProfile` since the v10.6.12 handle work) and were already registered in `lib.rs`. Stage 2 was a Python swap plus two Rust test vectors.

### Python changes (seven edits in `RustBackedDoubleRatchet`)

- `__init__` and `from_dake_output`: `dh_ratchet_local` is now an `X448KeyHandle` from `generate_x448_keypair()`; `dh_ratchet_local_pub` from `handle.public_bytes()`.
- `_decrypt_new_dh`: receive-side and send-side DH via `handle.dh(peer_pub_bytes)`, which takes the raw 56-byte peer key directly.
- `_ratchet`: send-side forced ratchet step, same swap.
- The first-message remote-pub record stores raw 56 bytes only; `dh_ratchet_remote` (the object) is set to `None` — it was never read anywhere, every consumer uses `dh_ratchet_remote_pub` (the bytes).

### Correctness

X448 is RFC 7748 and fully deterministic — a given (clamped scalar, u-coordinate) pair has exactly one correct output. The `x448` crate clamps the scalar inside `Secret::from` (RFC 7748: `byte0 &= 252`, `byte55 |= 128`) and rejects low-order points, matching OpenSSL's behaviour. A v10.6.21 peer and an older cryptography-library peer therefore derive byte-identical DH secrets and the ratchet stays in sync.

Two Rust tests added to `key_handles.rs` as the build-time desync guard:

- `x448_rfc7748_known_answer` — the `x448` crate reproduces RFC 7748 §5.2's published X448 test vector. Since OpenSSL also implements RFC 7748, matching the vector means the two agree.
- `x448_handle_dh_is_symmetric` — two generated handles derive the same shared secret from each other.

### Files touched

- `Rust/src/key_handles.rs`: added `x448_rfc7748_known_answer` and `x448_handle_dh_is_symmetric` tests
- `Rust/Cargo.toml`: version 0.10.20 → 0.10.21
- `otrv4+.py`: seven ratchet edits; VERSION → `10.6.21`

### Build verification

```
cargo test --release --no-default-features --features pq-rust
# expected: 17 passed (15 prior + 2 X448)
```

Live: DAKE + sustained multi-message exchange both directions over I2P, across 5+ DH-ratchet epochs (DATA ratchet counter stepped 0→5). Every message decrypted clean — the proof that the Rust X448 swap is byte-correct against a live peer. The test spanned multiple I2P transport disconnects; the ratchet stayed in sync across them.

---

## v10.6.20 — Phase 5.3h-D stage 1: ClientProfile Ed448 verify moved to Rust

**The last security-critical Ed448 operation that used the Python cryptography library now runs in Rust.**

`ClientProfile.decode()` verified incoming-peer profile signatures with `ed448.Ed448PublicKey.from_public_bytes(pub).verify(sig, signed_data)`. It now calls a new Rust PyO3 function, `otrv4_core.verify_ed448_sig(pub_bytes, msg, sig_bytes) -> bool`.

### Correctness

`verify_ed448_sig` wraps `VerifyingKey::verify_raw` — the inherent pure-Ed448 verifier from `ed448-goldilocks-plus` 0.16. This is the exact counterpart of `Ed448KeyHandle::sign`, which calls `SigningKey::sign_raw`. ClientProfile signatures are produced by that same handle's `sign()` method (`encode()`, the `self.identity_key.sign(...)` call), so signer and verifier now use identical RFC 8032 pure-Ed448 framing with an empty context. A profile signed by any v10.6.x build verifies unchanged.

`verify_ed448_sig` returns `False` on a failed verification (bad signature, public key not a valid curve point) and raises `ValueError` only on structurally malformed input (wrong public-key or signature length), so the Python caller can distinguish a forged profile from malformed bytes.

### Crate API note

The `ed448-goldilocks-plus` 0.16 `VerifyingKey` is constructed via `VerifyingKey::from_bytes(&[u8; 57])`, not a `TryFrom<&[u8; 57]>` impl (the `TryFrom<PublicKeyBytes>` impl the compiler suggests is a pkcs8 wrapper). `Signature` is built from a slice via `Signature::try_from(&[u8])`, which checks length internally. Both were confirmed against the installed crate source rather than assumed.

### Files touched

- `Rust/src/key_handles.rs`: added `verify_ed448_sig` PyO3 function, a `#[cfg(test)]` module with three tests (`ed448_sign_then_verify_roundtrip`, `ed448_verify_rejects_tampered_msg`, `ed448_verify_rejects_bad_lengths`), and the `VerifyingKey` / `Signature` imports
- `Rust/src/lib.rs`: registered `verify_ed448_sig`
- `Rust/Cargo.toml`: version 0.10.19 → 0.10.20
- `otrv4+.py`: `ClientProfile.decode()` swaps to `_RustDAKE_module.verify_ed448_sig`; `_check_rust_requirements` requires it; VERSION → `10.6.20`

The `ed448` cryptography-library import was **not** removed at v10.6.20 — the legacy non-Rust DAKE paths still referenced it. It was removed at v10.7 when the dead `OTRv4DAKE` class that contained those paths was deleted.

### Build verification

```
cargo test --release --no-default-features --features pq-rust
# expected: 15 passed (12 prior + 3 key_handles Ed448)
```

Live: DAKE completes; the peer's ClientProfile signature verifies through the Rust path.

---

## v10.6.19 — Phase 5.3h, parts A2 + B + C

**Three of four production `cryptography` library use-classes retired. New Rust AEAD module. Startup migration for legacy orphan files.**

### Phase 5.3h scope reality check

Phase 5.3h was originally scoped as "one focused session, ~100-150 lines." Diagnostic showed this estimate was off by an order of magnitude: the `cryptography` library has 4 use classes (AESGCM, Ed448PublicKey, X448PrivateKey/PublicKey, serialization.Raw), totalling 40+ call sites with deep coupling to the ratchet's DH path.

v10.6.19 ships the three smaller sub-phases (A2 + B + C). The fourth (Part D — drop Ed448 verify, X448, and serialization.Raw) was multi-session and rescheduled; it shipped across v10.6.20, v10.6.21, and v10.7.

### Part A2 — legacy on-disk file cleanup

Startup migration in `main()` securely destroys orphan files from pre-`~/.otrv4plus/` builds:

- `~/.otrv4_vault` (633 bytes, no current code references it)
- `~/.otrv4_smp_secrets.json` (97 bytes, legacy SMP-secrets file at home root)
- `~/.otrv4_keys/` (legacy keys directory)

Uses the existing `_secure_file_destroy()` NIST SP 800-88r1 primitive: encrypt zeros with a fresh AES-256-GCM key, overwrite the file with ciphertext + tag, fsync, zeroize the key via `_ossl.cleanse`, then unlink. No-op for new installs.

### Part B — AES-256-GCM moved to Rust

New `Rust/src/aead.rs` exposes two PyO3 functions:

- `otrv4_core.aes256gcm_encrypt(key, nonce, plaintext, aad) -> bytes`
- `otrv4_core.aes256gcm_decrypt(key, nonce, ct_and_tag, aad) -> bytes`

Wraps the `aes-gcm` 0.10 crate. Wire-identical to `cryptography.hazmat.primitives.ciphers.aead.AESGCM`. Three live AESGCM call sites swapped: `SMPAutoRespondStorage._load/_save`, `SecureKeyStorage._encrypt_key/_decrypt_key`, and `_secure_file_destroy`. Files written by v10.6.18 decrypt cleanly under v10.6.19. Three new Rust unit tests.

### Part C — Ed448PublicKey wrap removed at six live sites

Six `Ed448PublicKey.from_public_bytes(...)` call sites (three in `RustDAKEAdapter`, three in `OTRv4IRCClient`) swapped from cryptography-library wrapping to raw bytes. `remote_identity_key` and `remote_long_term_pub` now hold raw bytes; the SHA3-512 fingerprint path uses the bytes mirror directly.

### `cryptography` library import diet

Dropped `AESGCM` (replaced by Rust) and `hashes` (confirmed unused). The `ed448` and `x448` imports remained at v10.6.19; they were removed later in Phase 5.3h-D.

### Files touched

- `Rust/src/aead.rs`: new file, ~165 lines including tests
- `Rust/src/lib.rs`: added `pub mod aead;` and two `add_function` registrations
- `Rust/Cargo.toml`: version 0.10.18 → 0.10.19
- `otrv4+.py`: AESGCM/hashes imports dropped; three AESGCM sites swapped; six Ed448PublicKey wrap sites replaced; `_check_rust_requirements` requires the aead functions; startup orphan-file migration; VERSION → `10.6.19`
- `README.md`, `SECURITY.md`, `ROADMAP.md`, `CHANGELOG.md`, `FEATURES.md`: updated

### Build verification

```
cargo test --release --no-default-features --features pq-rust
# expected: 12 passed (5 ring_sig + 1 RFC 8032 + 3 mldsa + 3 aead)
```

---

## v10.6.18 — Phase 5.3j + Phase 5.3g (ephemeral-by-design decided)

**`otr4_mldsa_ext` C extension retired; ML-DSA-87 now runs entirely on `pqcrypto-mldsa 0.1.2` via Rust PyO3 bindings.**

The Python `MLDSA87Auth` class is unchanged externally — same `PUB_BYTES = 2592`, `SIG_BYTES = 4627`, same wire-format guards across the four parse sites in `EnhancedOTR.{_handle_dake1, _handle_dake2, _handle_dake3_initiator, _handle_dake3_responder}`. Three call sites internal to the class now delegate to `_RustDAKE_module.mldsa87_keygen / mldsa87_sign / mldsa87_verify` instead of the deleted `_mldsa.mldsa87_*` C extension entry points.

The new Rust module `Rust/src/mldsa.rs` is a thin PyO3 wrapper over `pqcrypto-mldsa::mldsa87::{keypair, detached_sign, verify_detached_signature}`. Three unit tests in the same file: round-trip, tampered-message rejection, FIPS 204 byte-size assertions (2592 / 4896 / 4627).

### Wire format

Byte-identical to v10.6.17. Both v10.6.17 and v10.6.18 peers can DAKE with each other — same FIPS 204 ML-DSA-87 parameter set, same PQClean reference implementation underneath.

### Cargo.toml hardening

`pqcrypto-mldsa` is pinned to `default-features = false, features = ["std"]` to disable AVX2 and NEON SIMD code paths. Same trap that hit `pqcrypto-mlkem` in v10.6.16: the NEON path triggers `SIGILL` on Termux/aarch64 at first `mldsa87_keygen()` call.

### Phase 5.3g — ephemeral identity (DECIDED)

After consideration, OTRv4+ keeps ephemeral identities by design. Fingerprints regenerate at every launch; no persistent vault. Rationale documented in ROADMAP.md and SECURITY.md.

### Files touched
- `Rust/src/mldsa.rs`: new file, ~120 lines including tests
- `Rust/src/lib.rs`: added `pub mod mldsa;` and three `add_function` registrations
- `Rust/Cargo.toml`: pqcrypto-mldsa pinned to `default-features = false`, version 0.10.17 → 0.10.18
- `otrv4+.py`: removed `import otr4_mldsa_ext as _mldsa` block; `MLDSA87_AVAILABLE` reduced to a hardcoded `True`; three `_mldsa.*` calls in `MLDSA87Auth` swapped to `_RustDAKE_module.*`; `_check_rust_requirements` now requires `mldsa87_keygen/sign/verify`; VERSION → `10.6.18`
- `README.md`, `SECURITY.md`, `ROADMAP.md`, `FEATURES.md`: updated

### Build verification

```
cargo test --release --no-default-features --features pq-rust
# expected: 9 passed (5 ring_sig + 1 RFC 8032 + 3 mldsa)
```

---

## v10.6.17 — Phase 5.3f-narrow

**Boot-time cross-verify removed; RFC 8032 vectors now build-time gate.**

The Python boot helpers `_verify_ed448_rust_compat()` and `_verify_ring_sig_rust_compat()` are deleted. They previously generated a fresh Ed448 keypair via the cryptography library at every program start, signed a test message with both Rust and OpenSSL, and compared byte-for-byte.

Both functions and all four call sites are removed. Replacement: `Rust/src/test_vectors.rs` contains the RFC 8032 §7.4 "Blank" Ed448 vector as `const` arrays and a `#[cfg(test)]` harness that signs with `ed448-goldilocks-plus::SigningKey` and asserts byte-equality.

**Boot is faster** (saves ~200ms). Six obsolete boot-print lines no longer appear.

### Files touched
- `otrv4+.py`: deleted ~150 lines. VERSION → `10.6.17`.
- `Rust/src/test_vectors.rs`: new file, ~100 lines.
- `Rust/src/lib.rs`: added `pub mod test_vectors;`.
- `Rust/Cargo.toml`: version 0.10.16 → 0.10.17.

---

## v10.6.16 — ML-KEM migration

**`pqcrypto-kyber 0.8` (round-3 Kyber) replaced by `pqcrypto-mlkem 0.1.1` (FIPS 203 ML-KEM-1024).**

NIST finalised FIPS 203 in August 2024. The standard differs from round-3 Kyber in the Fujisaki-Okamoto domain-separator constants; algorithms and parameter sizes are otherwise identical. The `pqcrypto-mlkem` Rust API is drop-in compatible with `pqcrypto-kyber`.

### Cargo.toml carve-out

Pinned to `default-features = false, features = ["std"]` to select the portable PQClean C reference — the NEON path caused SIGILL at first `keypair()` call on Termux/aarch64.

### Wire compatibility

Wire-incompatible with v10.6.15 and earlier. Both peers must run v10.6.16+.

### Files touched
- `Rust/Cargo.toml`: dependency swap, version 0.10.14 → 0.10.16.
- `Rust/src/dake.rs`: 7 call sites renamed `pqcrypto_kyber::kyber1024::` → `pqcrypto_mlkem::mlkem1024::`.

---

## v10.6.15.5 — Cargo.toml: restore signing+pkcs8 features

**Latent silent build break exposed by `cargo clean`.**

An earlier hardening pass had set `ed448-goldilocks-plus` to `default-features = false, features = ["alloc"]`, silently dropping `signing` (which gates `SigningKey`) and `pkcs8`. The break was latent because the live `.so` kept running until a `cargo build` was forced. Fix restored `features = ["alloc", "signing", "pkcs8"]`.

---

## v10.6.15 — SMP race fix

**Tie-break by fingerprint when both peers run `/smp start` simultaneously.**

If both peers run `/smp start` near-simultaneously, each generates SMP1 locally before either receives the other's. Resolution: at SMP1 receive, if the engine is non-Idle, compare identity public bytes — lower fingerprint keeps initiator role, higher fingerprint yields, aborts its own `RustSMP`, rebuilds fresh, rebinds the secret from the `RustSMPVault`, and processes the incoming SMP1 as responder.

---

## v10.6.14 — `lazy_static` → `std::sync::LazyLock`

RustSec lists `lazy_static 1.5` as unmaintained. Replaced with stdlib `LazyLock` (stable since Rust 1.80). Three statics in `smp.rs` converted; all 31 call sites unchanged. MSRV raised to 1.80+.

---

## v10.6.13

**SMP regression fix from v10.6.12.**

v10.6.12 left seven Python call sites using the legacy `.public_key().public_bytes(...)` chain on what was now a Rust handle. One site, `EnhancedOTRSession.set_smp_secret`, read the local fingerprint through the broken chain and silently fell back to an empty bytes literal, diverging the SMP secret hash. All seven sites converted to `bytes(handle.public_bytes())`. No Rust changes.

---

## v10.6.12

**Phase 5.3e: long-term identity keys owned by Rust.**

`ClientProfile.identity_key` and `.prekey` are now `Ed448KeyHandle` and `X448KeyHandle` opaque PyO3 classes. Private bytes live inside Rust `SecretBytes<N>` (ZeroizeOnDrop). New Rust file `src/key_handles.rs` with `Ed448KeyHandle`, `X448KeyHandle`, `generate_ed448_keypair()`, `generate_x448_keypair()`. New `dake::PyDake::sign_profile_body_and_construct_with_handles` takes the handles directly. Wire-compatible with v10.6.11.

---

## v10.6.11

**Phase 5.4: Rust-only, no fallbacks, regression fix.**

OTRv4+ is now a thin Python wrapper around the `otrv4_core` Rust crate. No production codepath falls back to the C extension or the cryptography library for ring sig, Ed448 sign, DAKE, SMP, or ratchet. `_check_rust_requirements()` runs at module load and raises `ImportError` if the Rust core is missing or incomplete.

Note: the pure-Python `OTRv4DAKE` class was retained as nominal fallback code at v10.6.11, but `RustDAKEAdapter` already raised rather than constructing it — it was effectively dead from this version onward. It was formally deleted at v10.7.

---

## v10.6.10

**Phase 5.3d.** Bytearray + wipe in `RingSignature.sign()`. Contained a regression that broke DAKE3 (`_rust_ring_sign` called with a bare bytearray, rejected by PyO3). Fixed in v10.6.11.

---

## v10.6.9

**Phase 5.3c: Rust DAKE3 ring signature.** New file `src/ring_sig.rs` (~407 lines) implementing OTRv4 §4.3.3 Schnorr ring signature in pure Rust using `ed448-goldilocks-plus` and `sha3`.

---

## v10.6.8

**Phase 5.3b: dead-code disk persistence removal.** `_store_identity()` previously wrote encrypted private-key blobs to disk that nothing read back. Removed; one-shot migration overwrites and unlinks legacy `identity.ed448.bin` / `prekey.x448.bin`.

---

## v10.6.7

**Phase 5.3a-cleanup.** Added `ClientProfile.encode_unsigned()`. `RustDAKEAdapter.__init__` uses `sign_profile_body_and_construct` in a single FFI call.

---

## v10.6.6

**Phase 5.3a (Option A2): Ed448 sign via Rust.** Added `sign_profile_body_and_construct` and `ed448_sign_test` to the Rust DAKE class.

---

## v10.6.5

**Phase 5.2: `new_from_bytearrays`.** Rust constructor takes `Bound<PyByteArray>`, copies into `SecretBytes<N>`, then wipes the source bytearray in-place.

---

## v10.6.4

**Phase 5.1.** `RustDAKEAdapter.__init__` extracts identity and prekey private bytes into mutable bytearrays, wipes them after Rust copies into `SecretBytes`.

---

## v10.6.3

**Phase 4: DakeOutput opaque handle. 11/11 audit findings closed.**

DAKE session keys never cross the Python heap. The `DakeOutput` PyO3 handle holds them in a private `RefCell<Option<DakeSessionKeys>>` with no Python-visible accessor. `consume_into_ratchet()` moves them directly into the ratchet's owned `SecretBytes` fields, taking the actual `is_initiator` flag.

---

## Older versions

Earlier v10.6.x and v10.5.x focused on Rust SMP, Rust double ratchet, X448 ratchet bugs, fragment buffer collision fixes, and the C extension constant-time Ed448 path. See git history for detail.
