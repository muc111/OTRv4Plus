# Features

What's implemented as of v10.13.1.

## Cryptography

### Primitives

| Primitive | Purpose | Implementation |
|---|---|---|
| Ed448 | Long-term identity signing + ClientProfile verification | `ed448-goldilocks-plus` 0.16 (pure Rust) |
| X448 | Ephemeral DH (DAKE and ratchet) | `x448` 0.6 (pure Rust) — both the DAKE and the double-ratchet DH run on this crate as of v10.6.21 |
| ML-KEM-1024 | Post-quantum KEM (DAKE brace key, ratchet rekey, hybrid SMP binding) | `pqcrypto-mlkem` 0.1.1 (FIPS 203) — pure Rust.  v10.7.3 moved `MLKEM1024BraceKEM` off the `otr4_crypto_ext` C extension onto Rust via `src/mlkem.rs`; v10.7.4 (5.3k) deleted the C extension. |
| ML-DSA-87 | Post-quantum signature (hybrid DAKE auth + per-step hybrid SMP signatures) | `pqcrypto-mldsa` 0.1.2 (FIPS 204) — pure Rust (v10.6.18 retired the `otr4_mldsa_ext` C extension). |
| SHAKE-256 | KDF, ring sig challenge, transcript hash; also the SMP passphrase→scalar stretch on **legacy** wire version 0x02 (50,000 iterated rounds) | `sha3` 0.10 |
| AES-256-GCM | Message encryption + SMP-secrets store + secure-file-destroy | `aes-gcm` 0.10 via Rust `Rust/src/aead.rs` PyO3 bindings (v10.6.19 retired the `cryptography.AESGCM` runtime uses; v10.7.4 (5.3i-D) moved off the deprecated `from_slice` helper to `new_from_slice`). |
| Argon2id (SMP) | **The SMP passphrase→scalar derivation on wire version 0x03**, salted with the session ID and both fingerprints | `argon2` 0.5 (pure Rust) in `Rust/src/smp.rs::stretch_argon2id`, m=64 MiB / t=3 / p=4. New at v10.13.0; the 0x02 SHAKE stretch above is retained for peers that have not updated. |
| Argon2id (at rest) | The SMP-secrets file and key storage on disk | Python `argon2-cffi` in `otrv4+.py::_derive_key`, same cost parameters, **falling back to `hashlib.scrypt` when it is not installed** — that fallback prints a warning naming the reason, and `kdf_backend()` reports which one was actually used. `src/smp_vault.rs` remains an in-memory zeroizing store with no KDF in it; a table here once said otherwise. |
| SHA3-512 | Fingerprint hash | `hashlib` (Python stdlib) |
| HKDF-SHA512 | Voice key schedule (root, media keys, confirmation, endpoint tags) | Python `cryptography` — **not** the Rust core |
| X448 (voice) | Ephemeral DH for the voice key exchange | Python `cryptography` — **not** the Rust core |
| AES-256-GCM (voice media) | Per-frame media AEAD | Python `cryptography` — **not** the Rust core |
| Opus | Voice codec (16 kHz mono, 60 ms, 24 kbit/s CBR, FEC on, DTX off) | `libopus` via `ctypes` |
| RFC 8032 Ed448 vectors | Build-time correctness gate | `src/test_vectors.rs` (Rust `#[cfg(test)]`) |
| RFC 7748 X448 vector | Build-time correctness gate (ratchet desync guard) | `src/key_handles.rs` (Rust `#[cfg(test)]`) |
| FIPS 203 ML-KEM-1024 byte-size + roundtrip | Build-time correctness gate (brace KEM) | `src/mlkem.rs` (Rust `#[cfg(test)]`) |

As of **v10.7.5 (Phase 5.3k)** the **chat** path is Rust-core-only, and as of **v10.9.0** the SMP is hybrid post-quantum: every cryptographic primitive behind messaging runs inside the Rust `otrv4_core` PyO3 module.  All three C extensions (`otr4_crypto_ext`, `otr4_ed448_ct`, `otr4_mldsa_ext`) and `setup_otr4.py` have been removed from the repository.

**Voice is the exception, and this document previously did not say so.**  `otrv4plus_voice.py` uses the Python `cryptography` library for the media AES-256-GCM, the HKDF-SHA512 voice key schedule, and the X448 half of the voice key exchange.  Voice ML-KEM-1024 does go through `otrv4_core`.  So on a build with voice there are two AES-256-GCM implementations in the tree and `cryptography` is a real runtime dependency.  Consolidating the voice path onto the Rust core is open work (see [ROADMAP.md](ROADMAP.md)); until then, "no second cryptographic implementation surface" is true of chat and false of voice.

### Higher-level protocols

| Protocol | Implementation | Notes |
|---|---|---|
| OTRv4 DAKE | Rust (`src/dake.rs`) | Three-message handshake. Pure Rust state machine. The pure-Python `OTRv4DAKE` fallback was deleted in v10.7. |
| OTRv4 double ratchet | Rust (`src/ratchet.rs`) | DH ratchet at 100-message or 24-hour boundary. X448 DH and ML-KEM-1024 rekey at every DH step, both in Rust. |
| OTRv4 ring signature | Rust (`src/ring_sig.rs`) | Schnorr ring sig over three Ed448 keys. Pure Rust port of the C reference. |
| OTRv4 SMP (hybrid PQC) | Rust (`src/smp.rs`, `src/smp_vault.rs`) | Four-step Schnorr ZKP over the 3072-bit MODP group (OTRv4 §5.3) wrapped in an ML-KEM-1024 + ML-DSA-87 binding layer as of v10.9.0. Wire-versioned 0x01/0x02, no silent downgrade. ZeroizeOnDrop on every exponent and PQ key. Constant-time modular exponentiation via `crypto-bigint` `DynResidue` (v10.7.6). Forging "verified" requires breaking the discrete log, ML-KEM-1024, and ML-DSA-87 simultaneously. |
| Ed448 / X448 long-term keys | Rust (`src/key_handles.rs`) | Opaque PyO3 handles. Private bytes never leave Rust. Includes `verify_ed448_sig` for ClientProfile verification. |
| Encrypted voice | Python (`otrv4plus_voice.py`) | Hybrid X448 + ML-KEM-1024 key exchange negotiated inside the OTR channel, AES-256-GCM media with derived nonces, symmetric ratchet every 500 frames, two-phase hybrid rekey every 120 s, replay window, authenticated `MEDIAPATH` endpoint announcements. Specified in [SPEC.md §9](SPEC.md). |

A complete byte-level wire specification for all of the above — DAKE, ratchet, hybrid SMP, and the voice protocol — is in [SPEC.md](SPEC.md).

## Transport

| Transport | IRC (`otrv4+.py`) | XMPP control (`otrv4plus_xmpp.py`) | Voice media | Notes |
|---|---|---|---|---|
| Plain TCP | Yes | Yes | No | no transport privacy |
| TLS 1.3 | Yes (default) | Yes | No | works; not anonymous |
| Tor | Yes | Yes (SOCKS5, fail-closed, no DNS leak) | **No** | live-unverified for XMPP; voice over Tor is deliberately not implemented |
| I2P SAM | Yes (default on Termux) | Yes (STREAM) | **Yes** (DATAGRAM) | the only transport that carries voice |

There is no automatic downgrade between transports. A transport that cannot be
established fails closed rather than falling back to a less private one. See
[TRANSPORT_AUDIT.md](TRANSPORT_AUDIT.md).

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
| OTRv4 message fragmentation | Yes (380 B per fragment on I2P, 450 B on TLS/Tor; SMP2 is ~49 fragments on I2P) |
| Out-of-order message handling | Yes (up to 1000 skipped keys cached) |
| Session resume after disconnect | No (each connect produces fresh DAKE) |
| Stable identity across launches | **XMPP: yes** (sealed Ed448, reloaded each run). **IRC: no**, deliberate — see ROADMAP Phase 5.3g |
| Pinned peer fingerprints (TOFU) | **XMPP: yes** — pinned on first contact; a change refuses voice and needs `/trust-reset`. **IRC: no**, nothing written to disk |
| Separate state per protocol | Yes — XMPP owns `~/.otrv4plus/xmpp/`; IRC persists no trust at all |

## Encrypted voice

End-to-end encrypted calling over I2P. Implemented and live-tested between two
Android phones; still the newest and least-reviewed surface in the project.

| Feature | Status |
|---|---|
| Call gated on SMP-VERIFIED | Yes — the engine's cryptographic predicate, never a UI string |
| Hybrid media key (X448 + ML-KEM-1024) | Yes — both mandatory, neither alone suffices |
| AES-256-GCM media, nonce derived not transmitted | Yes |
| Two-way role-labelled key confirmation before audio starts | Yes |
| Symmetric ratchet within an epoch | Yes — every 500 frames (30 s at the 60 ms default) |
| Hybrid rekey mid-call | Yes — every 120 s, two-phase, commits only on confirmation |
| Replay window + out-of-order tolerance | Yes |
| Constant-rate traffic shaping (mute sends digital silence) | Yes — 279 B every 60 ms, 16.7 pkt/s |
| Signalling carried inside the OTR channel, never in the clear | Yes — dropped rather than downgraded |
| Inbound-media liveness detection | Yes (v10.12.0) — measured on authenticated frames, not arrivals |
| Authenticated endpoint recovery (`MEDIAPATH`) | Yes (v10.12.0) — tag from the committed epoch root; forgery, replay and rollback rejected |
| SAM-session-aware rebuild backoff | Yes (v10.12.0) — see [VOICE_MEDIA_PATH.md](VOICE_MEDIA_PATH.md) |
| AAudio capture/playback on Android | Yes, via `ctypes`; PulseAudio (`parec`/`pacat`) elsewhere |
| Opus in-band FEC + adaptive jitter buffer | Yes |
| Incoming-call notification with ACCEPT/DECLINE (Termux) | Yes — Termux:API notification, ringtone, FIFO actions with single-use call-bound tokens |
| Mouth-to-ear latency colour banding | Yes — ITU-T G.114 bands, `NO_COLOR` respected |
| Voice over Tor or clearnet | **No, deliberately** — I2P only, fail closed |
| Video | No |

**Measured, not claimed.** Median mouth-to-ear on the I2P path is about
**917 ms** — above G.114's 400 ms "acceptable" bound and above the 800 ms band.
That is the cost of three hops each way, not a codec problem; Opus is not the
bottleneck. A 4-hour continuous call has been sustained
([VOICE_SOAK_TEST.md](VOICE_SOAK_TEST.md)), and a Wi-Fi-to-mobile transition
recovered authenticated media in 51 s.

## Memory safety guarantees

| Surface | Guarantee |
|---|---|
| DAKE DH secrets | Live in Rust `SecretBytes`. ZeroizeOnDrop. |
| DAKE session keys | Rust-to-Rust move via `DakeOutput` handle. Never marshalled to `PyBytes`. |
| Ratchet chain and root keys | Rust `SecretBytes<32>`. ZeroizeOnDrop. |
| Ratchet X448 ephemeral keys | Rust `SecretBytes<56>` inside `X448KeyHandle`. ZeroizeOnDrop. |
| Long-term Ed448 identity | Rust `SecretBytes<57>` inside `Ed448KeyHandle`. Public bytes only exposed. |
| Long-term X448 prekey | Rust `SecretBytes<56>` inside `X448KeyHandle`. Public bytes only exposed. |
| Per-message keys | Derived inside Rust, used once, dropped. ZeroizeOnDrop. |
| Skipped message keys | Rust `HashMap` with `SecretBytes` values. Cleared on session close. |
| SMP secret | Rust `SecretVec` inside `RustSMPVault`. ZeroizeOnDrop. |
| SMP exponents | Rust `Scalar` wrappers. ZeroizeOnDrop. |
| SMP ML-KEM-1024 secret key (hybrid) | Rust heap. Wiped after decapsulation. |
| SMP ML-DSA-87 signing key (hybrid) | Rust heap. ZeroizeOnDrop. |
| SMP `pq_binding_key` (hybrid) | Rust `SecretBytes<32>`. ZeroizeOnDrop, wiped per step. |

No long-term private key material appears on the Python heap as `bytes` or `bytearray` during normal session operation, and no **chat** key material transits an OpenSSL-backed Python object.

Voice is weaker here and the table above does not cover it:

* The voice root, the directional media keys, the ML-KEM decapsulation key and every shared secret are Python `bytearray`s, overwritten in place by an explicit `zeroize()` / `_wipe()` on teardown rather than by Rust `ZeroizeOnDrop`. Explicit wiping is best-effort in CPython: a `bytearray` can be copied by the allocator before it is wiped.
* The ephemeral voice X448 **private** key is an OpenSSL-backed `cryptography` object. It is released as soon as the shared secret exists — the reference is dropped inside a `finally` — but its bytes are owned by OpenSSL and cannot be wiped from Python.

All of this material is per-call and short-lived. It is still not Rust-owned, which is the same gap as the `cryptography`-library dependency noted above and has the same fix.

## Build target

- Termux on Android (aarch64)
- **Rust 1.85 or newer.** `Cargo.toml` declares `rust-version = "1.85"`. The 1.80 in older documentation was the *language* floor; the dependency graph (edition-2024 crates, `cargo::rustc-check-cfg`) needs 1.85 and cannot even be resolved by 1.75.
- **Python 3.12 or newer.** `otrv4+.py` uses PEP 701 f-string syntax that does not parse on 3.11, so an older interpreter fails with a `SyntaxError` inside an import. `Rust/pyproject.toml` declares `requires-python = ">=3.12"`.
- No OpenSSL dependency for the Rust core — the C extensions that linked `libssl`/`libcrypto` were retired at v10.7.5 (Phase 5.3k)
- **Chat needs no Python `cryptography` package. Voice does** — see the note under *Primitives*.
- Voice additionally needs `libopus`, and Termux:API for the incoming-call notification and ringer

Desktop Linux works the same way. macOS not tested. Windows not supported.

## Out of scope

- File transfer
- **Video** (voice is implemented — see above)
- Voice over any transport other than I2P
- Group chat (OMEMO, MLS, Signal groups)
- Mobile push notifications
- Cross-device sync
- Identity recovery
