# Features

What's implemented as of v10.6.17.

## Cryptography

### Primitives

| Primitive | Purpose | Implementation |
|---|---|---|
| Ed448 | Long-term identity signing | `ed448-goldilocks-plus` 0.16 (pure Rust) |
| X448 | Ephemeral DH (DAKE and ratchet) | `x448` 0.6 (pure Rust) |
| ML-KEM-1024 | Post-quantum KEM (DAKE brace key, ratchet rekey) | `pqcrypto-mlkem` 0.1.1 (FIPS 203) in DAKE; `otr4_crypto_ext` C extension in the legacy `MLKEM1024BraceKEM` Python class |
| ML-DSA-87 | Post-quantum signature (hybrid auth) | `pqcrypto-mldsa` 0.1.2 in DAKE; `otr4_mldsa_ext` C extension for the standalone `MLDSA87` Python class |
| SHAKE-256 | KDF, ring sig challenge, transcript hash | `sha3` 0.10 |
| AES-256-GCM | Message encryption | `aes-gcm` 0.10 (Rust); `cryptography.AESGCM` for the persistent SMP-secrets store |
| Argon2id | SMP secret vault KDF | `otr4_crypto_ext` C extension wrapper |
| Constant-time MODP-2048 arithmetic | SMP big-num operations | `otr4_crypto_ext` C extension (`bn_mod_exp_consttime`, etc.) |
| SHA3-512 | Fingerprint hash | `hashlib` (Python stdlib) |
| RFC 8032 Ed448 vectors | Build-time correctness gate | `src/test_vectors.rs` (Rust `#[cfg(test)]`) |

### Higher-level protocols

| Protocol | Implementation | Notes |
|---|---|---|
| OTRv4 DAKE | Rust (`src/dake.rs`) | Three-message handshake. Pure Rust state machine. |
| OTRv4 double ratchet | Rust (`src/ratchet.rs`) | DH ratchet at 100-message or 24-hour boundary. ML-KEM-1024 rekey at every DH step. |
| OTRv4 ring signature | Rust (`src/ring_sig.rs`) | Schnorr ring sig over three Ed448 keys. Pure Rust port of the C reference. |
| OTRv4 SMP | Rust (`src/smp.rs`, `src/smp_vault.rs`) | Four-step ZKP. MODP-2048 group. ZeroizeOnDrop on every exponent. |
| Ed448 / X448 long-term keys | Rust (`src/key_handles.rs`) | Opaque PyO3 handles. Private bytes never leave Rust. |

## Transport

| Transport | Status |
|---|---|
| Plain IRC over TCP | Yes |
| IRC over TLS 1.3 | Yes (default) |
| IRC over I2P SAM bridge | Yes (default on Termux) |
| IRC over Tor | Possible via `socat` or `torsocks`. Native onion transport on roadmap. |

## Client

| Feature | Status |
|---|---|
| Terminal UI with tabs | Yes |
| Multi-session (one tab per peer) | Yes |
| Protected input box (no leaking to scrollback) | Yes |
| `/otr <nick>` opportunistic DAKE start | Yes |
| `/smp <secret>` and `/smp start` SMP flow | Yes |
| `/trust <nick>` and `y` / `n` fingerprint trust | Yes |
| `/fingerprint` shows yours and theirs | Yes |
| OTRv4 message fragmentation | Yes (260 chars per fragment on I2P) |
| Out-of-order message handling | Yes (up to 1000 skipped keys cached) |
| Session resume after disconnect | No (each connect produces fresh DAKE) |
| Stable identity across launches | No (planned, see ROADMAP Phase 5.3g) |

## Memory safety guarantees

| Surface | Guarantee |
|---|---|
| DAKE DH secrets | Live in Rust `SecretBytes`. ZeroizeOnDrop. |
| DAKE session keys | Rust-to-Rust move via `DakeOutput` handle. Never marshalled to `PyBytes`. |
| Ratchet chain and root keys | Rust `SecretBytes<32>`. ZeroizeOnDrop. |
| Long-term Ed448 identity | Rust `SecretBytes<57>` inside `Ed448KeyHandle`. Public bytes only exposed. |
| Long-term X448 prekey | Rust `SecretBytes<56>` inside `X448KeyHandle`. Public bytes only exposed. |
| Per-message keys | Derived inside Rust, used once, dropped. ZeroizeOnDrop. |
| Skipped message keys | Rust `HashMap` with `SecretBytes` values. Cleared on session close. |
| SMP secret | Rust `SecretVec` inside `RustSMPVault`. ZeroizeOnDrop. |
| SMP exponents | Rust `Scalar` wrappers. ZeroizeOnDrop. |

No long-term private key material appears on the Python heap as `bytes` or `bytearray` during normal session operation.

## Build target

- Termux on Android (aarch64), Rust 1.94 or newer
- Python 3.11+
- OpenSSL 3.x — required at build time and at runtime (the C extensions link against `libssl` / `libcrypto` for AES-NI, constant-time bignum, and ML-KEM/ML-DSA primitives)

Desktop Linux works the same way. macOS not tested. Windows not supported.

## Out of scope

- File transfer
- Voice or video
- Group chat (OMEMO, MLS, Signal groups)
- Mobile push notifications
- Cross-device sync
- Identity recovery
