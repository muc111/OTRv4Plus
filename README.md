<p align="center">
  <img src="icon.png" width="200" alt="OTRv4+">
</p>

<h1 align="center">OTRv4+</h1>
<p align="center"><strong>Post-quantum secure messaging over IRC. Research prototype.</strong></p>

<p align="center">
<code>v10.6.13 · Rust-only crypto · Identity keys held in Rust SecretBytes · No fallbacks</code>
</p>

---

## What this is

OTRv4+ is an IRC client that implements OTRv4 with post-quantum cryptography at every layer. It runs on Termux (Android), over I2P, and uses a Rust crypto core. Python is a thin wrapper.

This is a single-author research prototype, not a finished product. The author is not a cryptographer. The Rust crypto crates it depends on (`ed448-goldilocks-plus`, `pqcrypto-kyber`, `pqcrypto-mldsa`) are not audited. Use it because you want to study or extend it, not because you need a hardened tool today.

## Architecture

```
┌─────────────────────────────────────────────┐
│  IRC transport (I2P / Tor / TLS 1.3)        │
├─────────────────────────────────────────────┤
│  Python orchestration layer                  │
│  (thin wrapper, no secrets on Python heap)  │
├─────────────────────────────────────────────┤
│  Rust core (otrv4_core)                      │
│  Ed448KeyHandle / X448KeyHandle              │
│  Double Ratchet                              │
│  DAKE state machine                          │
│  SMP state machine                           │
│  DakeOutput opaque handle                    │
│  SecretBytes / SecretVec                     │
│  ZeroizeOnDrop everywhere                    │
├─────────────────────────────────────────────┤
│  Pure-Rust crypto crates                     │
│  ed448-goldilocks-plus, sha3, aes-gcm,       │
│  pqcrypto-kyber (ML-KEM-1024),               │
│  pqcrypto-mldsa (ML-DSA-87)                  │
└─────────────────────────────────────────────┘
```

The C extensions (`otr4_crypto_ext`, `otr4_ed448_ct`, `otr4_mldsa_ext`) load at startup to serve as ground-truth references for the boot-time cross-verify check. After the check passes they are not invoked at runtime.

## Key exchange (DAKE)

Three-message handshake per OTRv4 §4.2 and §4.3. X448 ephemeral DH plus ML-KEM-1024 encapsulation. Both peers contribute entropy.

The entire DAKE, including all session-key derivation, runs in Rust. X448 DH exchanges (`dh1`, `dh2`, `dh3`), ML-KEM encap and decap, MAC over the DAKE2 wire body, Ed448 ring signature verification for DAKE3, and the KDF chain that produces `root_key`, `chain_key_send`, `chain_key_recv`, `brace_key`, and `mac_key` all run inside `otrv4_core`.

Session keys cross from DAKE into the ratchet via a Rust-only move. The `DakeOutput` PyO3 handle holds the keys in a private `RefCell<Option<DakeSessionKeys>>` with no Python-visible accessor. `consume_into_ratchet()` moves them directly into the ratchet's owned `SecretBytes` fields. Session keys are never marshalled into `PyBytes` at any point.

## Long-term identity

Ed448 and X448 identity keys are generated inside Rust at session start. The Python `ClientProfile.identity_key` and `.prekey` are opaque `Ed448KeyHandle` and `X448KeyHandle` objects. Each handle owns `SecretBytes<N>` and exposes only `public_bytes()` and the operations the protocol needs (`sign()`, `ring_sign()`, `dh()`). Private bytes are not retrievable from Python by any public method.

When the handle is garbage-collected, Rust's `ZeroizeOnDrop` runs and wipes the SecretBytes before the heap slot is reclaimed.

## Double ratchet

Chain keys advance per message via SHAKE-256 KDF. DH ratchet at rekey boundaries (100 messages or 24 hours). Fresh ML-KEM-1024 keypair generated and exchanged at every DH ratchet step. Brace key rotated with each KEM shared secret. Skipped message keys cached for out-of-order delivery (max 1000 skip).

## Authentication

Ed448 ring signatures provide deniable authentication in DAKE3. The ring signature is implemented in pure Rust using `ed448-goldilocks-plus` and `sha3` for SHAKE-256. ML-DSA-87 is appended as hybrid post-quantum auth. SMP provides out-of-band identity verification via a four-step zero-knowledge proof, all four steps in Rust with `ZeroizeOnDrop` on every exponent.

## Memory safety (v10.6.13)

| Component | Where secrets live | Python sees |
|---|---|---|
| Ratchet chain / root keys | Rust `SecretBytes<32>` | Nothing |
| Ratchet brace key | Rust `SecretBytes<32>` | Nothing |
| DAKE DH secrets | Rust heap | Nothing |
| DAKE session keys | Rust `DakeSessionKeys` to `DoubleRatchet::SecretBytes` (Rust-to-Rust move) | Nothing |
| Long-term Ed448 identity | Rust `SecretBytes<57>` inside `Ed448KeyHandle` | Public bytes only |
| Long-term X448 prekey | Rust `SecretBytes<56>` inside `X448KeyHandle` | Public bytes only |
| SMP secret | Rust `SecretVec` inside `RustSMPVault` | Nothing after `set_secret_from_vault` |
| SMP exponents | Rust scalars with `ZeroizeOnDrop` | Nothing |

Every value with `ZeroizeOnDrop` is wiped when its owning Rust object is dropped. No private key material appears on the Python heap during normal session operation.

## Build

```bash
# Termux (Android aarch64)
pkg install python rust openssl clang

cd OTRv4Plus/Rust
cargo build --release --no-default-features --features pq-rust
cp target/release/libotrv4_core.so ../otrv4_core.so

cd ..
pip install --break-system-packages cryptography
python otrv4+.py
```

A clean Rust build takes about three minutes on a modern phone.

## Testing it works

Boot two instances on different I2P endpoints. On the first instance, `/otr <peer>`. Watch for these debug lines:

```
[Ed448]    Rust ed448-goldilocks-plus byte-compatible with cryptography lib
[ring-sig] Rust ed448-goldilocks-plus matches C reference
[ClientProfile] Fresh Rust-owned identity keys
```

DAKE3 completes, fingerprints display, trust the peer, type the same SMP secret on both sides, `/smp start` on either side. SMP completes through steps 1 to 4 and you see a green session marker.

## Honest caveats

1. Single author, no external review. Code style is consistent but the choices have not been peer-reviewed.

2. Built with AI assistance (Claude). The author drove design and testing; the AI helped with implementation. Each substantive change was live-tested between two I2P peers before being committed.

3. The Rust crypto crates are not audited. `ed448-goldilocks-plus` 0.16 is the only viable pure-Rust Ed448 implementation but has no formal review. `pqcrypto-kyber` 0.8 is round-3 NIST Kyber, not the final FIPS 203 ML-KEM (a migration to `pqcrypto-mlkem` is on the roadmap).

4. Identity keys regenerate every launch. There is no persistent identity vault yet. Fingerprints change on every restart. This is correct for ephemeral IRC nicks but unusual if you are expecting an OMEMO-style stable identity.

5. The boot-time cross-verify check uses the bundled C extensions and the `cryptography` library as ground-truth references for the Rust crypto. Production paths only run in Rust, but the references must load successfully or the app refuses to start.

6. Wire-incompatible with stock OTRv4 implementations such as `pidgin-otr4` and CoyIM. The ML-DSA-87 extension, the ML-KEM-1024 brace key, and the SHAKE-256 transcript hashing are OTRv4+ additions and there is no negotiation path.

7. Cargo.toml currently pins `pqcrypto-kyber 0.8`, `pqcrypto-mldsa 0.1.2`, and `lazy_static 1.5`. RustSec advisories flag the latter two. Migration to `pqcrypto-mlkem 0.2`, `pqcrypto-mldsa 0.2`, and `std::sync::LazyLock` is planned (see ROADMAP).

## License

GPL-3.0 for the source. Commercial use requires a separate license (see COMMERCIAL-LICENSE).

## See also

- [CHANGELOG.md](CHANGELOG.md) per-version changes
- [SECURITY.md](SECURITY.md) threat model and known issues
- [FEATURES.md](FEATURES.md) full feature inventory
- [ROADMAP.md](ROADMAP.md) what's planned next
- [DEVELOPMENT.md](DEVELOPMENT.md) build environment, test plan
- [CONTRIBUTING.md](CONTRIBUTING.md) PR guidelines
- [WHY.md](WHY.md) design rationale
- [MIGRATION.md](MIGRATION.md) moving from earlier versions
