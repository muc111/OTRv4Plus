<p align="center">
  <img src="icon.png" width="200" alt="OTRv4+">
</p>

<h1 align="center">OTRv4+</h1>
<p align="center"><strong>Post-quantum secure messaging over IRC. Research prototype.</strong></p>

<p align="center">
<code>v10.6.19 · Rust crypto core · AES-GCM now pure-Rust · ML-DSA-87 now pure-Rust</code>
</p>

---

## What this is

OTRv4+ is an IRC client that implements OTRv4 with post-quantum cryptography at every layer. It runs on Termux (Android) over I2P, with a Rust crypto core wrapped by a thin Python orchestration layer.

Single-author research prototype. Not a finished product. The author is not a cryptographer. The Rust crypto crates it depends on (`ed448-goldilocks-plus`, `pqcrypto-mlkem`, `pqcrypto-mldsa`) are not audited. Use it to study or extend it, not because you need a hardened tool today.

## Quick start

For someone who wants to try it in about ten minutes on Termux (Android, aarch64).

### 1. Install dependencies

```bash
pkg install python rust openssl clang git
```

You also need I2P running on the device with the SAM bridge enabled on port 7656. The I2P Android app from F-Droid or Google Play handles this; enable "Use SAM bridge" in its settings.

### 2. Clone and build

```bash
git clone https://github.com/muc111/OTRv4Plus.git
cd OTRv4Plus

# Build the Rust crypto core (about 3 minutes on a modern phone)
cd Rust
cargo build --release --no-default-features --features pq-rust
cp target/release/libotrv4_core.so ../otrv4_core.so
cd ..

# Build the two remaining C extensions (still required, see caveat 5)
gcc -shared -fPIC -O2 -o otr4_crypto_ext.so otr4_crypto_ext.c -lssl -lcrypto
gcc -shared -fPIC -O2 -o otr4_ed448_ct.so   otr4_ed448_ct.c   -lssl -lcrypto

# Install the one remaining Python dependency
pip install --break-system-packages cryptography
```

### 3. Verify the build (recommended)

```bash
cd Rust
cargo test --release --no-default-features --features pq-rust
cd ..
```

Expected: `test result: ok. 6 passed; 0 failed`. The test that matters most is `test_vectors::tests::ed448_rfc8032_vectors_byte_exact` — if it fails, the Rust Ed448 implementation has drifted from RFC 8032 and the build is not safe to use.

### 4. Run it

```bash
PYTHONMALLOC=malloc python otrv4+.py --debug
```

You should see the banner, the I2P SAM bridge handshake, the IRC connection to `irc.postman.i2p`, an auto-join of `#otr`, and a prompt. Other users in `#otr` running the same client are available for an OTR session.

### 5. Talk to a peer

If another user is in `#otr` (their nick is `SomeNick`), type:

```
/otr SomeNick
```

This starts the OTRv4 DAKE handshake. After about three minutes of fragmenting messages across I2P, fingerprints display. Type `y` to trust. Either side then types a shared SMP secret (anything you have agreed out of band) and runs `/smp start`. SMP completes in another minute or two and you see `✅ SMP VERIFIED` in blue.

From that point, messages typed in the peer tab are end-to-end encrypted with post-quantum hybrid security.

## What success looks like

During a clean DAKE in `--debug` mode, you should see lines like:

```
[ClientProfile] Fresh Rust-owned identity keys — expires <date>
[OTR:peer] SESSION: None → PLAINTEXT | session created
[OTR:peer] ROLE: None → INITIATOR
...
[OTR:DAKE] STATE: IDLE → RECEIVED_DAKE1 | received DAKE1 (Identity)
[OTR:DAKE] STATE: RECEIVED_DAKE1 → SENT_DAKE2 | generated DAKE2 (Auth-R)
[OTR:DAKE] STATE: SENT_DAKE2 → ESTABLISHED | DAKE3 verified — hybrid (ring-sig ✓ + ML-DSA-87 ✓)
[OTR:peer] RATCHET: None → ACTIVE | ratchet: Rust (Phase-4 opaque handle; keys never in Python)
[OTR:peer] SMP: VERIFIED → STATE_UPDATED | role=responder
🔐 SMP VERIFIED — identity confirmed!
```

After that, the peer tab is green (encrypted + verified) and your typed messages are end-to-end encrypted.

## Architecture

```
┌─────────────────────────────────────────────┐
│  IRC transport (I2P / Tor / TLS 1.3)        │
├─────────────────────────────────────────────┤
│  Python orchestration layer                 │
│  (thin wrapper, no secrets on Python heap)  │
├─────────────────────────────────────────────┤
│  Rust core (otrv4_core)                     │
│  Ed448KeyHandle / X448KeyHandle             │
│  Double Ratchet                             │
│  DAKE state machine                         │
│  SMP state machine                          │
│  DakeOutput opaque handle                   │
│  SecretBytes / SecretVec                    │
│  ZeroizeOnDrop everywhere                   │
├─────────────────────────────────────────────┤
│  Pure-Rust crypto crates                    │
│  ed448-goldilocks-plus, sha3, aes-gcm,      │
│  pqcrypto-mlkem (FIPS 203 ML-KEM-1024),     │
│  pqcrypto-mldsa (FIPS 204 ML-DSA-87)        │
└─────────────────────────────────────────────┘
```

The C extensions (`otr4_crypto_ext`, `otr4_ed448_ct`) load at startup and **remain in use throughout production code**. `otr4_crypto_ext` provides constant-time big-number arithmetic for SMP, memory wiping (`cleanse`), `mlock`, and an alternate ML-KEM-1024 keygen path used by the legacy `MLKEM1024BraceKEM` Python class. The Python `cryptography` library is also imported in production for Ed448 public-key wrapping (UI-side fingerprint display) and AES-GCM (persistent SMP-secrets store). Replacing these with pure-Rust equivalents is the subject of ROADMAP phases 5.3h, 5.3i, and 5.3k and is multi-commit work.

v10.6.18 retired `otr4_mldsa_ext` (ML-DSA-87 keygen, sign, verify) in favour of `pqcrypto-mldsa 0.1.2` via the Rust `otrv4_core` module. Wire format and byte sizes are identical.

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

## Memory safety

| Component | Where secrets live | Python sees |
|---|---|---|
| Ratchet chain / root keys | Rust `SecretBytes<32>` | Nothing |
| Ratchet brace key | Rust `SecretBytes<32>` | Nothing |
| DAKE DH secrets | Rust heap | Nothing |
| DAKE session keys | Rust `DakeSessionKeys` → `DoubleRatchet::SecretBytes` (Rust-to-Rust move) | Nothing |
| Long-term Ed448 identity | Rust `SecretBytes<57>` inside `Ed448KeyHandle` | Public bytes only |
| Long-term X448 prekey | Rust `SecretBytes<56>` inside `X448KeyHandle` | Public bytes only |
| SMP secret | Rust `SecretVec` inside `RustSMPVault` | Nothing after `set_secret_from_vault` |
| SMP exponents | Rust scalars with `ZeroizeOnDrop` | Nothing |

Every value with `ZeroizeOnDrop` is wiped when its owning Rust object is dropped. No private key material appears on the Python heap during normal session operation.

## RFC 8032 build-time gate (v10.6.17)

Earlier versions ran a boot-time cross-verification that signed a test message with Rust Ed448 and the Python `cryptography` library and compared the byte output. v10.6.17 replaced that with hardcoded RFC 8032 §7.4 test vectors in `Rust/src/test_vectors.rs`. The `cargo test` harness signs each vector with `ed448-goldilocks-plus::SigningKey::sign_ctx()` and asserts byte equality with the published signature.

Run `cargo test --release --no-default-features --features pq-rust` before any release. If the test fails, do not ship the build.

## Honest caveats

1. **Single author, no external review.** Code style is consistent but design choices have not been peer-reviewed.

2. **Built with AI assistance (Claude).** The author drove design and testing; the AI helped with implementation. Each substantive change was live-tested between two I2P peers before being committed.

3. **The Rust crypto crates are not audited.** `ed448-goldilocks-plus` 0.16 is the only viable pure-Rust Ed448 implementation but has no formal review. `pqcrypto-mlkem 0.1.1` (FIPS 203 ML-KEM-1024) and `pqcrypto-mldsa 0.1.2` (ML-DSA-87) are PQClean-derived reference implementations.

4. **Ephemeral identity by design.** Identity keys regenerate at every launch. Fingerprints change on every restart. This is a deliberate threat-model choice for an I2P-based privacy IRC client, not a missing feature. Tor Browser, Cwtch (default), and Briar (before user opt-in) all keep identities short-lived for similar reasons. See ROADMAP Phase 5.3g.

5. **Two C extensions and a narrower cryptography library use are still load-bearing in production.** Despite the pure-Rust direction, the current build depends on two `.so` C extensions (`otr4_crypto_ext`, `otr4_ed448_ct`) and a subset of the Python `cryptography` library for memory wiping, constant-time SMP arithmetic, X448 ratchet operations, ClientProfile signature verification, and byte-format conversions. Dropping these is the subject of ROADMAP phases 5.3h (in progress), 5.3i, and 5.3k. v10.6.18 retired `otr4_mldsa_ext` (ML-DSA-87 is pure Rust). v10.6.19 retired the `AESGCM` and `hashes` imports from the cryptography library (AES-GCM is pure Rust) and replaced six `Ed448PublicKey.from_public_bytes` wrap sites with raw-bytes handling. Remaining cryptography library uses are `ed448.Ed448PublicKey.from_public_bytes(...).verify(...)` for `ClientProfile.decode()` signature verification (one production site), `x448` (ratchet DH and legacy DAKE), and `serialization` (~20 byte-conversion sites).

6. **Wire-incompatible with stock OTRv4.** Implementations such as `pidgin-otr4` and CoyIM cannot talk to OTRv4+. The ML-DSA-87 extension, the ML-KEM-1024 brace key, and the SHAKE-256 transcript hashing are OTRv4+ additions and there is no negotiation path.

7. **Termux/aarch64 specific build flags.** Both `pqcrypto-mlkem` and `pqcrypto-mldsa` are pinned to `default-features = false, features = ["std"]` because their NEON-optimised C paths trigger `SIGILL` on some aarch64 phones. The portable C reference is correct on any platform; the speed difference is invisible at session scale.

## License

GPL-3.0 for the source. Commercial use requires a separate license (see [COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md)).

## See also

- [CHANGELOG.md](CHANGELOG.md) per-version changes
- [SECURITY.md](SECURITY.md) threat model and known issues
- [FEATURES.md](FEATURES.md) full feature inventory
- [ROADMAP.md](ROADMAP.md) what's planned next
- [DEVELOPMENT.md](DEVELOPMENT.md) build environment, test plan
- [CONTRIBUTING.md](CONTRIBUTING.md) PR guidelines
- [WHY.md](WHY.md) design rationale
- [MIGRATION.md](MIGRATION.md) moving from earlier versions
