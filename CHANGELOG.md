# Changelog

OTRv4+ post-quantum messaging client. Solo dev project. AI-assisted (Claude). Each version live-tested between two I2P peers before commit.

---

## v10.6.13 (current)

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
