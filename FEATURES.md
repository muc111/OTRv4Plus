# OTRv4+ Feature Reference

## 1. Core OTRv4 Protocol (Spec Compliant)

| Feature | Implementation |
|---|---|
| **DAKE** | DAKE1 (Identity), DAKE2 (Auth-R), DAKE3 (Auth-I) per OTRv4 §4.2–4.3. Initiator/responder roles. Over I2P SAM: ~2m 44s handshake time. |
| **Ed448 & X448** | Long-term Ed448 identity keys (57-byte public) + ephemeral X448 keys (56-byte public). 224-bit classical security. |
| **Double Ratchet** | Chain key advancement, message key derivation, AES-256-GCM encrypt/decrypt, skipped key management, and replay detection run inside the Rust `otrv4_core` crate. Keys are `ZeroizeOnDrop` — no Python memory exposure at any point. |
| **Message encryption** | AES-256-GCM with 12-byte nonces. MAC key derived via SHA3-512. |
| **Session ID & SSID** | 8-byte SSID derived from KDF_1 (usage 0x01), used for SMP session binding. |
| **Client Profiles** | Encoded and signed Ed448+X448 keys with expiry timestamp. Strict verification — no unsigned or expired profiles accepted. |
| **Ring Signatures** | Auth-I / Auth-R Schnorr ring signatures (228 bytes) for deniable authentication. Implemented in C extension with constant-time arithmetic. |
| **Instance Tags** | Random 32-bit tags (≥ 0x100) for multi-session discrimination per peer. |
| **TLV Handling** | All OTRv4 TLVs: PADDING (0x00), DISCONNECTED (0x01), SMP messages (0x02–0x07), EXTRA_SYMMETRIC_KEY (0x09). |
| **Fragmentation** | IRC-aware fragmenter using spec format `?OTRv4\|stag\|rtag\|k\|n\|data.` with reassembly buffer (timeout 120s, max 50 fragments, SMP elevated to 100). |
| **Rekeying** | Automatic DH ratchet after 100 messages or 86400 seconds (configurable). |
| **Disconnect notification** | Sends DISCONNECTED TLV before session termination. |

---

## 2. Post-Quantum Cryptography (NIST Level 5)

| Component | Algorithm | NIST Level | Integration |
|---|---|---|---|
| **ML-KEM-1024** (FIPS 203) | Module-Lattice Key Encapsulation | Level 5 (~256-bit PQ security) | Brace KEM — rotates brace key on every DH ratchet epoch. Used in DAKE (ek in DAKE1, ct in DAKE2) and the Double Ratchet for ongoing PQ protection. |
| **ML-DSA-87** (FIPS 204) | Module-Lattice Digital Signature | Level 5 | Hybrid PQ authentication in DAKE3. Appended after Ed448 ring signature (flag byte). Provides post-quantum authentication. |

**Brace KEM rotation protocol:**

[content continues from previous version — only Section 8 changes in this update]

---

## 8. Rust Migration Status (v10.6.3)

| Component | Secret storage | Zeroization | Status |
|---|---|---|---|
| **Double ratchet** | Rust `SecretBytes<N>` / `SecretVec` | `ZeroizeOnDrop` — no Python exposure | ✅ Complete (v10.5.8) |
| **SMP state machine** | Rust `SmpState` — all exponents are `SecretVec` | `ZeroizeOnDrop` + explicit `destroy()` | ✅ Complete (v10.5.10) |
| **SMP vault** | Rust `RustSMPVault` — `SecretEntry` per slot | `ZeroizeOnDrop` per entry; `clear()` drains individually | ✅ Complete (v10.5.10) |
| **SMP passphrase entry** | Rust copies bytearray, wipes caller's buffer | `ZeroizeOnDrop` on Rust side | ✅ Complete (v10.6.1) |
| **DAKE DH secrets** (`dh1`/`dh2`/`dh3`, `mlkem_ss`) | Rust `Vec<u8>` inside `DakeState`; never crosses FFI | `Drop` zeroizes (kdf-1 input scope) | ✅ Complete (v10.6.2) |
| **DAKE session keys** (root, chain×2, brace, mac) | Rust `DakeSessionKeys` → `DakeOutput.inner: RefCell<Option<...>>` → `DoubleRatchet::SecretBytes` (Rust-to-Rust move) | `ZeroizeOnDrop` end-to-end; never `PyBytes` | ✅ **Complete (v10.6.3)** |
| **Identity keys (Ed448 / X448)** | Python `cryptography` library objects; private bytes copied into Rust at session start | Python lib lifecycle + OpenSSL cleanse | 🔜 Phase 5 |

---

## 9. Audit findings status (v10.6.3)

| Audit ID | Description | Status |
|---|---|---|
| **C1** | Test-only `RustSMPVault::load*` exposed in production | ✅ Fixed v10.6.0 |
| **C2** | `Dakeresult` exposes session keys as `Vec<u8>` getters | ✅ Fixed v10.6.3 (DakeOutput opaque handle) |
| **C3** | `process_dh_message` returns secrets to Python | ✅ Fixed v10.6.3 (consume_into_ratchet path) |
| **C4** | `RustDoubleRatchet::brace_key()` PyO3 getter leaks brace key | ✅ Fixed v10.6.0 |
| **C5** | SMP passphrase enters Python `bytes` during set_secret | ✅ Fixed v10.6.1 |
| **C6** | Rust DAKE end-to-end correctness | ✅ Fixed v10.6.2 |
| **P3** | `panic = "abort"` breaks FFI panic safety | ✅ Fixed v10.6.0 |
| **V1–V3** | Wire decoders did not bounds-check | ✅ Fixed v10.6.0 |
| **M1, M2** | `kdf_1`, `encode_header` PyO3 exports | ✅ Fixed v10.6.0 |

**Net: 11 of 11 audit findings fully closed.  The Rust→Python boundary
audit from v10.5.10 is complete.**

---

## 10. Verification commands

After building v10.6.3+, verify Phase 4 is active:

```bash
# Rust binary contains Phase 4 symbols
strings otrv4_core.so | grep -E "DakeOutput|from_dake_keys|consume_into_ratchet"

# Python can import DakeOutput
python3 -c "
import otrv4_core
print('DakeOutput class:', hasattr(otrv4_core, 'DakeOutput'))
print('PyDake.generate_dake2_output:', hasattr(otrv4_core.RustDAKE, 'generate_dake2_output'))
"
# Expected: both True
```

At runtime, after a DAKE handshake completes:

```python
ratchet = session.ratchet
print('Phase-4 ratchet:', getattr(ratchet, '_dake_output_consumed', False))
# Expected: True on a correctly-built v10.6.3 environment
```
