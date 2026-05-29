# Security

Threat model, known issues, and reporting.

## What OTRv4+ tries to defend against

| Adversary | Defense |
|---|---|
| Passive network eavesdropper | TLS 1.3 transport (when used over plain IRC), or I2P / Tor onion routing |
| Active MITM at first contact | SMP zero-knowledge proof out-of-band (user types same secret on both sides) |
| Long-term key compromise after the fact | Per-message forward secrecy via double ratchet; PCS via DH ratchet at 100-message / 24-hour boundaries |
| Future quantum adversary recording today | ML-KEM-1024 hybrid in DAKE; ML-DSA-87 hybrid signatures |
| Python heap inspection (post-exploitation) | Long-term private bytes live inside Rust `SecretBytes<N>` (ZeroizeOnDrop); session keys move Rust-to-Rust via the `DakeOutput` opaque handle; no Python cryptography library holds key material |
| AES-GCM nonce reuse | Counter-based nonce per ratchet step, KDF-derived; nonce never reused across messages |

## What OTRv4+ does not defend against

| Threat | Why not |
|---|---|
| Compromised endpoint at time of message | Out of scope. If the device has malware, no messaging app helps. |
| Compromised endpoint after message is sent | Skipped message keys cached for up to 1000 messages for out-of-order delivery. They are wiped on session close, not after each message. |
| Side-channel timing analysis on Python | Python is not constant-time. Rust core uses constant-time crypto via `ed448-goldilocks-plus` and `subtle`. |
| Side-channel on SMP modular exponentiation | Constant-time as of v10.7.6: SMP `modpow` uses `crypto-bigint` `DynResidue` (Montgomery form), not `num-bigint`'s variable-time `modpow`. The secret SMP exponents (blinding scalars, the secret, ZKP randomisers) no longer leak via exponentiation timing. |
| Side-channel on the Rust core | `ed448-goldilocks-plus`, `x448`, and `crypto-bigint` claim constant-time but have not been formally audited. Treat as best-effort. |
| Traffic analysis | Visible message size and timing leak metadata. Use a transport that pads (I2P with destinations does some of this; Tor does less). |
| Replay across sessions | DAKE includes both peers' fresh randomness, so a replay of an old DAKE produces a different session. Replay within a session is rejected by ratchet message counters. |
| State actor with quantum capability today | ML-KEM-1024 and ML-DSA-87 are best-current-knowledge post-quantum primitives. They are not formally proven; future cryptanalysis could break them. |

## Memory safety model (v10.7)

| Key material | Storage | Wiping |
|---|---|---|
| Long-term Ed448 identity | Rust `SecretBytes<57>` inside `Ed448KeyHandle` | `ZeroizeOnDrop` when handle is GC'd |
| Long-term X448 prekey | Rust `SecretBytes<56>` inside `X448KeyHandle` | `ZeroizeOnDrop` when handle is GC'd |
| DAKE DH secrets (dh1, dh2, dh3) | Rust heap inside `DakeState` | `ZeroizeOnDrop` when `DakeState` drops |
| Ratchet X448 ephemeral keys | Rust `SecretBytes<56>` inside `X448KeyHandle` | `ZeroizeOnDrop` when handle is GC'd |
| ML-KEM shared secret | Rust heap | Wiped after KDF derivation |
| DAKE session keys (root, chain×2, brace, mac) | Rust `DakeSessionKeys` to `DoubleRatchet::SecretBytes` via Rust-to-Rust move | `ZeroizeOnDrop` end-to-end |
| Ratchet chain / root keys | Rust `SecretBytes<32>` | `ZeroizeOnDrop` |
| Per-message keys | Derived from chain key, used once, dropped | `ZeroizeOnDrop` on `SecretBytes<32>` |
| Skipped message keys | Rust `HashMap<u64, SecretBytes<32>>` | `ZeroizeOnDrop` on values; map cleared on session close |
| SMP secret | Rust `SecretVec` inside `RustSMPVault` | `ZeroizeOnDrop` when vault drops |
| SMP exponents (a2, a3, b2, b3, r, etc.) | Rust scalars | `ZeroizeOnDrop` on the `Scalar` wrapper |

No long-term private key material appears on the Python heap as `bytes` or `bytearray` during normal session operation. As of v10.7 there is no Python cryptography library in the codebase, so no key material transits an OpenSSL-backed Python object.

## Build-time invariants

The Python module enforces these at import time via `_check_rust_requirements()`:

- `otrv4_core.RustDAKE` present with methods `new_from_bytearrays`, `sign_profile_body_and_construct`, `sign_profile_body_and_construct_with_handles`, `ed448_sign_test`, `generate_dake2_output`, `process_dake2_output`
- `otrv4_core.py_ring_sign` and `otrv4_core.py_ring_verify` present
- `otrv4_core.Ed448KeyHandle`, `otrv4_core.X448KeyHandle`, `otrv4_core.generate_ed448_keypair`, `otrv4_core.generate_x448_keypair`, `otrv4_core.verify_ed448_sig` present
- `otrv4_core.mldsa87_keygen`, `mldsa87_sign`, `mldsa87_verify` present
- `otrv4_core.aes256gcm_encrypt`, `aes256gcm_decrypt` present

Missing anything raises `ImportError` at startup with a rebuild instruction. The app cannot accidentally fall back to a less-safe code path — and as of v10.7 there is no Python-crypto fallback path to fall back to.

## Build-time invariants for crypto correctness

v10.6.17 (Phase 5.3f-narrow) replaced the previous Python-side boot-time cross-verification with Rust-side RFC 8032 Ed448 test vectors in `Rust/src/test_vectors.rs`. v10.6.21 added an RFC 7748 §5.2 X448 known-answer vector in `Rust/src/key_handles.rs`. Both are exercised by `#[cfg(test)]` harnesses.

Run before every release:

```
cargo test --release --no-default-features --features pq-rust
```

Expected: **20 tests pass** (17 prior + 3 ML-KEM tests added in v10.7.3 when the brace-KEM moved to Rust).  If `ed448_rfc8032_vectors_byte_exact` fails, the `ed448-goldilocks-plus` crate has diverged from RFC 8032.  If `x448_rfc7748_known_answer` fails, the `x448` crate has diverged from RFC 7748 and the ratchet would desync against any peer — do not ship.  If `mlkem1024_byte_sizes_match_spec` or `mlkem1024_roundtrip_shared_secret_matches` fails, the `pqcrypto-mlkem` crate has diverged from FIPS 203.  All four are build-time gates against the spec documents themselves.

Two helper functions were removed at v10.6.17: `_verify_ed448_rust_compat()` and `_verify_ring_sig_rust_compat()`.  The previous comparison against the C extension's `ring_sign` and `ring_verify` is no longer performed.  As of v10.7.5 the C extension itself has been retired (see caveat 4 below), so these comparison paths are doubly obsolete.

## Known issues and limitations

1. **Rust crypto crates are not audited.** `ed448-goldilocks-plus` 0.16 is the only viable pure-Rust Ed448, and `x448` 0.6 the X448, but neither has had a formal review. `pqcrypto-mlkem 0.1.1` (FIPS 203 ML-KEM-1024) and `pqcrypto-mldsa 0.1.2` (ML-DSA-87) are PQClean-derived reference implementations.

2. **No persistent identity vault.** Identity keys regenerate at every launch. Fingerprints change each time. Correct for ephemeral IRC nicks but unusual for typical messaging.

3. **The Python cryptography library has been fully removed (v10.7).** Earlier versions of this document listed the `cryptography` library as load-bearing in production. As of v10.7 it is no longer imported or used anywhere in the codebase. The removal was a staged sequence:
   - v10.6.18 — ML-DSA-87 moved off the `otr4_mldsa_ext` C extension to `pqcrypto-mldsa`.
   - v10.6.19 — AES-256-GCM moved from `cryptography.AESGCM` to the Rust `aes-gcm` crate; six `Ed448PublicKey.from_public_bytes` wrap sites replaced with raw bytes; `AESGCM` and `hashes` imports dropped.
   - v10.6.20 — `ClientProfile.decode()` Ed448 signature verification moved from `cryptography.Ed448PublicKey.verify` to the Rust `verify_ed448_sig` function.
   - v10.6.21 — the double ratchet's X448 Diffie-Hellman moved from `cryptography.x448` to the Rust `X448KeyHandle`.
   - v10.7 — the dead pure-Python `OTRv4DAKE` fallback class (the last `ed448`/`x448`/`serialization` consumer) was deleted, the four remaining `serialization.Raw` byte-conversion sites were removed, and the `from cryptography...` import was deleted entirely.

4. **All C extensions have been retired (v10.7.5, Phase 5.3k).**  Earlier versions of this document listed two C extensions (`otr4_crypto_ext`, `otr4_ed448_ct`) as load-bearing in production.  Both are gone, as is the long-dead `otr4_mldsa_ext` (retired at v10.6.18).  The migration was staged across several sub-phases of 5.3i, each one isolating a single C-extension surface and moving it to Rust before the next was touched:
   - **v10.7.1 (5.3i-A)** — four dead bignum wrappers (`_ct_mod_exp`, `_ct_mod_inv`, `_ct_rand_range`, `SHA3_512.hash_to_int`) deleted; `disable_core_dumps` moved to Python `resource.setrlimit`.
   - **v10.7.2 (5.3i-B)** — `_ossl.cleanse` replaced by a module-level `_secure_wipe(bytearray)` using `ctypes.memset` (dead-store-resistant, no DLL surface).
   - **v10.7.3 (5.3i-C)** — `MLKEM1024BraceKEM.keygen/encaps/decaps` migrated from `_ossl.mlkem1024_*` to Rust `pqcrypto-mlkem` via a new `mlkem.rs` PyO3 module.  After this, `otr4_crypto_ext` had no callers.
   - **v10.7.4 (5.3i-D)** — `aead.rs` migrated off the deprecated `aes-gcm` `GenericArray::from_slice` helper to `Aes256Gcm::new_from_slice` and `Nonce::from(*&[u8;12])`.  Zero-warning Rust build restored.
   - **v10.7.4 (5.3k)** — the `otr4_ed448_ct` import was deleted (it had no callers; it was loaded as a defensive ground-truth but every Ed448 operation already ran in Rust).  The `.c`/`.h`/`.so` files and `setup_otr4.py` were removed from the repository.  Seven test files in `tests/` were rewritten onto Rust `otrv4_core` (the C-extension-only `test_otr.py` was deleted; the pre-broken `test_v10_4_security_fixes.py` is unrelated and tracked separately).

   The architectural consequence: there is now a **single cryptographic implementation surface** in OTRv4+.  No second backend to drift against, no compile-time conditionals selecting between paths, no "Rust verified against C" comparison checks.  Whatever the Rust core computes is what gets transmitted on the wire; there is nothing else for a reviewer to look at.

5. **Ephemeral identity is a deliberate design choice, not a missing feature.** OTRv4+ regenerates identity keys at every launch; fingerprints do not persist across sessions. Rationale:
   - **Threat model fits ephemeral.** OTRv4+ runs over I2P for an IRC channel; the assumption is short-lived sessions, not long-term identity binding.
   - **No on-disk attack surface.** A persistent vault would create a high-value target for offline brute-force.
   - **No passphrase to forget.** Termux has no OS keyring; a vault would require a user passphrase at every launch.
   - **Aligns with privacy-oriented messaging norms.** Tor Browser, Cwtch (default), and Briar (before user opt-in) all keep identities short-lived.

   SMP trust binding is meaningful within a session. Across sessions, peers must re-verify. See ROADMAP Phase 5.3g.

6. **Single-author project, AI-assisted.** Each release is live-tested between two I2P peers but has not been reviewed by another human cryptographer. Use as a research prototype.

7. **No interop with stock OTRv4.** Wire-incompatible with `pidgin-otr4`, CoyIM, and similar implementations due to ML-DSA-87, ML-KEM-1024, and SHAKE-256 OTRv4+ additions.

8. **ClientProfile lifetime: 14 days (v10.7.5).**  Earlier versions used a 365-day expiry, which was incoherent with the ephemeral-identity design (caveat 5).  The OTRv4 spec §4.1 recommends short profile lifetimes; v10.7.5 reduces the validity to 14 days, matching `otr4j`'s default.  Because OTRv4+ regenerates identity keys at every launch, this is an upper bound on how long an *offline* peer will still accept a previously-cached profile — it is not the practical lifetime of any single key, which is hours at most.

9. **SMP modular exponentiation is constant-time (v10.7.6, Phase 5.4).**  Prior to v10.7.6, SMP used `num-bigint`'s `modpow`, whose running time depends on the exponent's bit pattern.  Because SMP exponentiates with secret values (the per-session blinding scalars, the SMP secret itself, and the ZKP randomisers), this was a timing side-channel: an attacker able to measure SMP-round timing precisely could in principle recover bits of those secrets.  v10.7.6 routes every secret-exponent `modpow` through `crypto-bigint`'s `DynResidue` (Montgomery-form modular exponentiation, constant-time in the exponent).  The MODP-3072 group (OTRv4 §5.3) is unchanged — same prime, same generator — so the wire format and spec compliance are identical; only the implementation changed.  Caveats: (a) the *public*-value arithmetic in the ZKP reconstruction (challenge/response combination) remains on `num-bigint`, which is correct because those operands are public and carry no secret-dependent timing; (b) `crypto-bigint`'s constant-time claims, like those of the other Rust crypto crates here, have not been formally audited.  The practical attack surface for this side-channel was always narrow over I2P (multi-second fragmentation latency drowns the signal), but constant-time is the correct posture regardless.

## Reporting issues

Open a GitHub issue at <https://github.com/muc111/OTRv4Plus/issues>. For anything that looks like an actual security flaw (key disclosure, signature forgery, MITM bypass, panic on adversarial input), tag the issue `security` and include reproduction steps. If you would prefer to disclose privately first, the maintainer is on I2P (see the GitHub profile for an `i2p` contact).

There is no bug bounty. The project is solo and unfunded.

## What "audit closed" means

`v10.6.3 - 11/11 audit findings closed` refers to the internal audit that drove the v10.5.x and v10.6.x development sequence. Findings were:

1. Private bytes extracted from DakeState into Python (closed at v10.6.3 via the opaque `DakeOutput` handle)
2. `is_initiator` hardcoded True in `consume_into_ratchet` (closed at v10.6.3)
3. Chain-key role-based swap done in Python before handoff (closed at v10.6.3)
4. Ratchet chain key reset bug after DH ratchet (closed in v10.6.0-ish)
5. SMP scalar arithmetic done in Python (closed at v10.5)
6. Argon2id KDF parameters too weak for SMP vault (closed at v10.5)
7. ML-KEM ciphertext byte order on the wire (closed at v10.5)
8. Fragment buffer collision when same nick sends two parallel fragmented messages (closed at v10.5)
9. SMP secret stored as Python `bytes` (closed at v10.5, now lives in `RustSMPVault`)
10. Skipped message keys not zeroized (closed at v10.5)
11. NIST SP 800-88r1 secure file destruction missing (closed at v10.5)

Phase 5.x changes since v10.6.3 are architectural hardening beyond audit scope. The audit count remains at 11/11 closed.
