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

No long-term private key material appears on the Python heap as `bytes` or `bytearray` during normal session operation.

## Build-time invariants

The Python module enforces these at import time via `_check_rust_requirements()`:

- `otrv4_core.RustDAKE` present with methods `new_from_bytearrays`, `sign_profile_body_and_construct`, `sign_profile_body_and_construct_with_handles`, `ed448_sign_test`, `generate_dake2_output`, `process_dake2_output`
- `otrv4_core.py_ring_sign` and `otrv4_core.py_ring_verify` present
- `otrv4_core.Ed448KeyHandle`, `otrv4_core.X448KeyHandle`, `otrv4_core.generate_ed448_keypair`, `otrv4_core.generate_x448_keypair` present

Missing anything raises `ImportError` at startup with a rebuild instruction. The app cannot accidentally fall back to a less-safe code path.

## Build-time invariants for Ed448 correctness

v10.6.17 (Phase 5.3f-narrow) replaced the previous Python-side boot-time cross-verification with Rust-side RFC 8032 test vectors. The vectors live in `Rust/src/test_vectors.rs` and are exercised by a `#[cfg(test)]` harness.

Run before every release:

```
cargo test --release --no-default-features --features pq-rust
```

If the test fails, the Rust `ed448-goldilocks-plus` crate has diverged from RFC 8032 and the build is not safe to ship. The previous mechanism (boot-time comparison against the cryptography library and the C extension) ran this check on every startup; the new mechanism is a single build-time gate against the RFC document itself.

Two helper functions were removed: `_verify_ed448_rust_compat()` and `_verify_ring_sig_rust_compat()`. The previous comparison against the C extension's `ring_sign` and `ring_verify` is no longer performed; those C entry points remain compiled into `otr4_crypto_ext.so` but are not invoked by current Python code.

## Known issues and limitations

1. **Rust crypto crates are not audited.** `ed448-goldilocks-plus` 0.16 is the only viable pure-Rust Ed448, but it has not had a formal review. `pqcrypto-mlkem 0.1.1` (FIPS 203 ML-KEM-1024) and `pqcrypto-mldsa 0.1.2` (ML-DSA-87) are PQClean-derived reference implementations.

2. **No persistent identity vault.** Identity keys regenerate at every launch. Fingerprints change each time. Correct for ephemeral IRC nicks but unusual for typical messaging.

3. **The cryptography library is still imported and used in production.** Specifically:
   - `cryptography.hazmat.primitives.asymmetric.ed448.Ed448PublicKey.from_public_bytes` is called at three runtime sites to wrap a remote peer's raw 57-byte identity pub for the UI trust display.
   - `cryptography.hazmat.primitives.ciphers.aead.AESGCM` is used for the persistent SMP secrets store (encrypted under a key derived from the user passphrase).
   - `serialization.PrivateFormat.Raw` / `PublicFormat.Raw` is used for byte-level conversion of cryptography key objects.

   Replacing these is multi-phase work tracked on the ROADMAP.

4. **Two C extensions remain loaded and in active use in production.** `otr4_crypto_ext` (aliased `_ossl`) is invoked from 20+ runtime sites:
   - `_ossl.cleanse(buf)` for explicit memory wipe of SMP, ratchet, and identity buffers (11 call sites)
   - `_ossl.bn_mod_exp_consttime`, `_ossl.bn_mod_inverse`, `_ossl.bn_rand_range` for constant-time SMP big-number arithmetic (`num_bigint` is not constant-time)
   - `_ossl.mlkem1024_keygen`, `_ossl.mlkem1024_encaps`, `_ossl.mlkem1024_decaps` in the `MLKEM1024BraceKEM` Python class
   - `_ossl.disable_core_dumps` at boot

   `otr4_ed448_ct` is imported as a defensive ground-truth but is no longer invoked by current Python code.

   v10.6.18 retired the third C extension (`otr4_mldsa_ext`); ML-DSA-87 keygen, sign, and verify now run through `pqcrypto-mldsa 0.1.2` via Rust PyO3 bindings.  Wire format is byte-identical.  Build process no longer requires `otr4_mldsa_ext.so`.

   v10.6.19 retired the `AESGCM` and `hashes` uses of the Python `cryptography` library; AES-256-GCM now runs through `aes-gcm` 0.10 via Rust PyO3 bindings (`Rust/src/aead.rs`).  v10.6.19 also added a startup migration that securely destroys any legacy `~/.otrv4_vault` and `~/.otrv4_smp_secrets.json` files left over from pre-`~/.otrv4plus/` builds, using the existing `_secure_file_destroy` NIST SP 800-88r1 ciphertext-overwrite primitive.  Six `Ed448PublicKey.from_public_bytes(...)` wrap sites (in `RustDAKEAdapter` and `OTRv4IRCClient`) were replaced with raw-bytes handling; the SHA3-512 fingerprint computation now goes through the bytes mirror attribute rather than the cryptography library round-trip.

   `ClientProfile.decode()` at line ~2644 still uses `ed448.Ed448PublicKey.from_public_bytes(...).verify(...)` for ClientProfile signature verification on incoming peers.  Replacing this is the next sub-phase (5.3h-D); it needs a new Rust PyO3 `verify_ed448_sig(pub, msg, sig) -> bool` plus a focused test cycle since the path is security-critical.

   Remaining cryptography library uses after v10.6.19: `ed448` (one live verify site, plus legacy paths), `x448` (ratchet DH and legacy DAKE), `serialization` (~20 byte-conversion sites).  Removing the remaining two C extensions and the rest of the cryptography library is multi-phase work, broken into 5.3h-D, 5.3i, and 5.3k on the ROADMAP.

5. **Ephemeral identity is a deliberate design choice, not a missing feature.** OTRv4+ regenerates identity keys at every launch; fingerprints do not persist across sessions.  Rationale:
   - **Threat model fits ephemeral.** OTRv4+ runs over I2P for an IRC channel; the assumption is short-lived sessions, not long-term identity binding.
   - **No on-disk attack surface.** A persistent vault would create a high-value target for offline brute-force.
   - **No passphrase to forget.** Termux has no OS keyring; a vault would require a user passphrase at every launch.
   - **Aligns with privacy-oriented messaging norms.** Tor Browser, Cwtch (default), and Briar (before user opt-in) all keep identities short-lived.

   SMP trust binding is meaningful within a session.  Across sessions, peers must re-verify.  See ROADMAP Phase 5.3g.

6. **Single-author project, AI-assisted.** Each release is live-tested between two I2P peers but has not been reviewed by another human cryptographer. Use as a research prototype.

7. **No interop with stock OTRv4.** Wire-incompatible with `pidgin-otr4`, CoyIM, and similar implementations due to ML-DSA-87, ML-KEM-1024, and SHAKE-256 OTRv4+ additions.

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
