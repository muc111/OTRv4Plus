# Security

Threat model, known issues, and reporting.

## What OTRv4+ tries to defend against

| Adversary | Defense |
|---|---|
| Passive network eavesdropper | TLS 1.3 transport (when used over plain IRC), or I2P / Tor onion routing |
| Active MITM at first contact | SMP zero-knowledge proof out-of-band (user types same secret on both sides) |
| Long-term key compromise after the fact | Per-message forward secrecy via double ratchet; PCS via DH ratchet at 100-message / 24-hour boundaries |
| Future quantum adversary recording today | ML-KEM-1024 hybrid in DAKE; ML-DSA-87 hybrid signatures |
| Python heap inspection (post-exploitation) | Long-term private bytes live inside Rust `SecretBytes<N>` (ZeroizeOnDrop); session keys move Rust-to-Rust via the `DakeOutput` opaque handle |
| AES-GCM nonce reuse | Counter-based nonce per ratchet step, KDF-derived; nonce never reused across messages |

## What OTRv4+ does not defend against

| Threat | Why not |
|---|---|
| Compromised endpoint at time of message | Out of scope. If the device has malware, no messaging app helps. |
| Compromised endpoint after message is sent | Skipped message keys cached for up to 1000 messages for out-of-order delivery. They are wiped on session close, not after each message. |
| Side-channel timing analysis on Python | Python is not constant-time. Rust core uses constant-time crypto via `ed448-goldilocks-plus` and `subtle`. |
| Side-channel on the Rust core | `ed448-goldilocks-plus` claims constant-time but has not been formally audited. Treat as best-effort. |
| Traffic analysis | Visible message size and timing leak metadata. Use a transport that pads (I2P with destinations does some of this; Tor does less). |
| Replay across sessions | DAKE includes both peers' fresh randomness, so a replay of an old DAKE produces a different session. Replay within a session is rejected by ratchet message counters. |
| State actor with quantum capability today | ML-KEM-1024 and ML-DSA-87 are best-current-knowledge post-quantum primitives. They are not formally proven; future cryptanalysis could break them. |

## Memory safety model (v10.6.13)

| Key material | Storage | Wiping |
|---|---|---|
| Long-term Ed448 identity | Rust `SecretBytes<57>` inside `Ed448KeyHandle` | `ZeroizeOnDrop` when handle is GC'd |
| Long-term X448 prekey | Rust `SecretBytes<56>` inside `X448KeyHandle` | `ZeroizeOnDrop` when handle is GC'd |
| DAKE DH secrets (dh1, dh2, dh3) | Rust heap inside `DakeState` | `ZeroizeOnDrop` when `DakeState` drops |
| ML-KEM shared secret | Rust heap | Wiped after KDF derivation |
| DAKE session keys (root, chain×2, brace, mac) | Rust `DakeSessionKeys` to `DoubleRatchet::SecretBytes` via Rust-to-Rust move | `ZeroizeOnDrop` end-to-end |
| Ratchet chain / root keys | Rust `SecretBytes<32>` | `ZeroizeOnDrop` |
| Per-message keys | Derived from chain key, used once, dropped | `ZeroizeOnDrop` on `SecretBytes<32>` |
| Skipped message keys | Rust `HashMap<u64, SecretBytes<32>>` | `ZeroizeOnDrop` on values; map cleared on session close |
| SMP secret | Rust `SecretVec` inside `RustSMPVault` | `ZeroizeOnDrop` when vault drops |
| SMP exponents (a2, a3, b2, b3, r, etc.) | Rust scalars | `ZeroizeOnDrop` on the `Scalar` wrapper |

No long-term private key material appears on the Python heap as `bytes` or `bytearray` during normal session operation. The boot-time cross-verify helpers generate fresh ephemeral test keys via the cryptography library, use them once, and let them be GC'd.

## Build-time invariants

The Python module enforces these at import time via `_check_rust_requirements()`:

- `otrv4_core.RustDAKE` present with methods `new_from_bytearrays`, `sign_profile_body_and_construct`, `sign_profile_body_and_construct_with_handles`, `ed448_sign_test`, `generate_dake2_output`, `process_dake2_output`
- `otrv4_core.py_ring_sign` and `otrv4_core.py_ring_verify` present
- `otrv4_core.Ed448KeyHandle`, `otrv4_core.X448KeyHandle`, `otrv4_core.generate_ed448_keypair`, `otrv4_core.generate_x448_keypair` present

Missing anything raises `ImportError` at startup with a rebuild instruction. The app cannot accidentally fall back to a less-safe code path.

## Runtime invariants (boot-time cross-verify)

Before the Rust crypto path is enabled for any session:

1. `_verify_ed448_rust_compat()` signs a test message with both Rust `ed448-goldilocks-plus` and OpenSSL Ed448 (via the cryptography library). Byte-identical signatures required.
2. `_verify_ring_sig_rust_compat()` does a two-way check: Rust signs, C extension verifies; C extension signs, Rust verifies. Both directions must pass.

If either check fails, the code raises `RuntimeError` at the first call site. No silent fallback.

## Known issues and limitations

1. **Rust crypto crates are not audited.** `ed448-goldilocks-plus` 0.16 is the only viable pure-Rust Ed448, but it has not had a formal review. `pqcrypto-kyber` 0.8 is round-3 NIST Kyber rather than the final FIPS 203 ML-KEM. A migration to `pqcrypto-mlkem` 0.2 is on the roadmap.

2. **`pqcrypto-mldsa 0.1.2`** is yanked from crates.io but is still installed in the current `Cargo.lock`. Migration to 0.2 is on the roadmap.

3. **`lazy_static 1.5`** is listed as unmaintained by RustSec. Used at one site (the SMP MODP-2048 prime initialisation). Migration to `std::sync::LazyLock` is on the roadmap. The toolchain (Rust 1.94.1) supports it.

4. **No persistent identity vault.** Identity keys regenerate at every launch. Fingerprints change each time. Correct for ephemeral IRC nicks but unusual for typical messaging.

5. **The cryptography library is still imported.** Used at boot for the cross-verify check. Production paths do not invoke it. Phase 5.3f (replacing the boot check with hardcoded RFC 8032 test vectors) would let this dependency be removed.

6. **The C extensions are still loaded.** Same as point 5. `otr4_crypto_ext`, `otr4_ed448_ct`, `otr4_mldsa_ext` serve as ground-truth references during boot. Not invoked at runtime.

7. **Single-author project, AI-assisted.** Each release is live-tested between two I2P peers but has not been reviewed by another human cryptographer. Use as a research prototype.

8. **No interop with stock OTRv4.** Wire-incompatible with `pidgin-otr4`, CoyIM, and similar implementations due to ML-DSA-87, ML-KEM-1024, and SHAKE-256 OTRv4+ additions.

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
