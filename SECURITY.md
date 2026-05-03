# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| v10.5.10+ | ✅ |
| v10.5.8–v10.5.9 | ⚠️ SMP responder did not transition to verified state |
| older | ❌ |

## Reporting a vulnerability

Use GitHub's private vulnerability reporting (Security tab → Report a vulnerability).
Do not open a public issue.

Include: description, steps to reproduce, potential impact, suggested fix (if any).
Acknowledgment within 48 hours; fix for critical issues within 14 days.

## In‑scope

- Cryptographic weaknesses (DAKE, ratchet, SMP, ring signatures)
- Key material leaks (memory, disk, network)
- Authentication bypasses
- Plaintext recovery
- Secret material crossing the Rust/Python boundary

## Out‑of‑scope

- Endpoint compromise (rooted device, malware on the device)
- I2P/Tor network‑level attacks
- Social engineering

---

## Memory‑safety status (v10.5.10)

The primary goal of v10.5.10 is that the Python GC cannot reach any SMP secret. This is now achieved.

| Component | Secret storage | Zeroization | Python exposure |
|---|---|---|---|
| **Double ratchet** | Rust `SecretBytes<N>` / `SecretVec` | Deterministic on drop / `zeroize()` | None — Python holds an opaque handle |
| **SMP passphrase** | `RustSMPVault` — Rust `Vec<u8>`, `ZeroizeOnDrop` | On `vault.clear()` or session end | Opaque `u64` handle only |
| **SMP exponents** | `SmpState` — all fields are `SecretVec`, `ZeroizeOnDrop` | Immediate via `destroy()` on abort; `ZeroizeOnDrop` on session end | None |
| **SMP transit window** | Python `bytearray` between `encode()` and `vault.store()` | Byte-by-byte overwrite in `finally` block | Microseconds — mutable, not interned |
| **DAKE DH secrets** | OpenSSL C heap during KDF | `OPENSSL_cleanse` after use | Brief `bytes` during KDF — microseconds |
| **Identity keys (Ed448/X448)** | Python OpenSSL objects (cryptography library) | No deterministic zeroization (OpenSSL heap) | Whole session lifetime — planned for Phase 4 |

### How Python is kept blind to SMP secrets

```
User types secret
        ↓
bytearray raw = secret.encode('utf-8')          ← mutable, will be wiped
        ↓
vault.store("smp_secret", bytes(raw))            ← copied into Rust Vec<u8>, ZeroizeOnDrop
        ↓
for i in range(len(raw)): raw[i] = 0            ← overwrite before GC can copy
del raw                                           ← Python ref dropped
        ↓
rust_smp.set_secret_from_vault(vault, ...)       ← SHAKE-256 + HMAC runs in Rust
        ↓
SmpState.secret: SecretVec                        ← only copy, Rust-owned
        ↓
On session end: vault.clear() → ZeroizeOnDrop fires per entry
                rust_smp.destroy() → all SecretVec fields zeroed immediately
```

Python never holds the stretched/derived secret. The stretched value is computed in Rust and stays in `SecretVec`. The KDF output never crosses the PyO3 boundary.

---

## SMP security properties (v10.5.10)

### Zero‑knowledge proof

The SMP exchange proves that both parties know a shared secret without revealing it. The four‑message Schnorr ZKP protocol (OTRv4 §5) runs entirely inside Rust using `num_bigint` and `sha3`. No Python integer holds any exponent at any point.

### Brute-force resistance

The passphrase is processed through 50,000 rounds of SHAKE‑256 before being bound to the session via HMAC‑SHA3‑512. An attacker who captures a transcript must invert this KDF for every candidate passphrase. At 50k rounds on Termux-class hardware this takes approximately 3 seconds per candidate — offline brute-force of an 8-character passphrase from a printable character set (~95^8 ≈ 6.6 × 10^15 candidates) is infeasible.

### Replay prevention

Every SMP session uses a running HMAC‑SHA3‑512 transcript accumulator keyed to the session ID. An SMP message from session A cannot be replayed into session B because the transcript MAC will not verify. Additionally `SmpState` enforces strict phase transitions — a message received out of order triggers `fail_and_zeroize()`.

### Rate limiting

After 3 failed SMP attempts the `SmpState` is permanently destroyed (`Aborted`). A new session must be established to retry. A 30-second cooldown between retries prevents rapid cycling.

### Both sides turn blue

Prior to v10.5.10 only the initiator (Alice) transitioned to `SMP_VERIFIED`. The responder (Bob) sent the SMP4 verdict but remained on the yellow security icon because Python did not check `is_verified()` after `process_smp3_generate_smp4()`. This is fixed — Rust sets the phase to `Verified` internally during SMP3 processing, and Python reads it immediately, so both sides transition to 🔵 simultaneously.

---

## Cryptographic primitives

| Primitive | Algorithm | Standard | Implementation |
|---|---|---|---|
| Key encapsulation | ML‑KEM‑1024 | FIPS 203 | `pqcrypto-kyber` (Rust) |
| Digital signatures | ML‑DSA‑87 | FIPS 204 | `pqcrypto-mldsa` (Rust) |
| Classical DH | X448 | RFC 7748 | OpenSSL EVP (C) |
| Identity signatures | Ed448 | RFC 8032 | C extension (constant-time) |
| Ring signatures | OR-proof Schnorr | OTRv4 §4.3 | C extension |
| Symmetric encryption | AES‑256‑GCM | NIST SP 800-38D | Rust `aes-gcm` |
| Hash / KDF | SHAKE‑256 / SHA3‑512 | FIPS 202 | Rust `sha3` |
| SMP ZKP hash | SHA3‑512 | FIPS 202 | Rust `sha3` |
| HMAC | HMAC‑SHA3‑512 | FIPS 198‑1 | Rust `hmac` |
| Zeroization | `Zeroize` + `ZeroizeOnDrop` | — | Rust `zeroize` crate |
| Constant-time eq | `ConstantTimeEq` | — | Rust `subtle` crate |
