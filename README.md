<p align="center">
  <img src="icon.png" width="200" alt="OTRv4+">
</p>

<h1 align="center">OTRv4+</h1>
<p align="center"><strong>Post-quantum secure messaging over IRC. Research prototype.</strong></p>

<p align="center">
<code>v10.8.0 · Rust crypto core · constant-time SMP · no C extensions · TUI</code>
</p>

---

## In action

<p align="center">
  <img src="example.png" width="680" alt="OTRv4+ TUI — encrypted session with SMP verified">
</p>

<p align="center"><em>Full OTRv4 DAKE + SMP verification on Libera.chat. Blue 🔵 = identity confirmed.<br>Tab bar at the bottom — switch channels instantly with <code>/switch</code> or <code>/tab-next</code>.<br>Type <code>/tui</code> to toggle the pinned chrome on or off.</em></p>

---

## What this is

OTRv4+ is an IRC client that implements OTRv4 with post-quantum cryptography at every layer. It runs on Termux (Android) over I2P, with a Rust crypto core wrapped by a thin Python orchestration layer.

Single-author research prototype. Not a finished product. The author is not a cryptographer. The Rust crypto crates it depends on (`ed448-goldilocks-plus`, `x448`, `pqcrypto-mlkem`, `pqcrypto-mldsa`) are not audited. Use it to study or extend it, not because you need a hardened tool today.

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
```

As of v10.7.5 the project is **Rust-core-only**: there are no C extensions to compile and no Python `cryptography` dependency.  The Rust core is the single cryptographic surface.

### 3. Verify the build (recommended)

```bash
cd Rust
cargo test --release --no-default-features --features pq-rust
cd ..
```

Expected: `test result: ok. 17 passed; 0 failed`. The tests that matter most are `test_vectors::tests::ed448_rfc8032_vectors_byte_exact` (Rust Ed448 against RFC 8032) and `key_handles::tests::x448_rfc7748_known_answer` (Rust X448 against RFC 7748 §5.2). If either fails, a Rust crypto implementation has drifted from its specification and the build is not safe to use.

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
│  (thin wrapper, no secrets on Python heap,  │
│   no Python cryptography library)           │
├─────────────────────────────────────────────┤
│  Rust core (otrv4_core)                     │
│  Ed448KeyHandle / X448KeyHandle             │
│  verify_ed448_sig                           │
│  Double Ratchet (X448 DH in Rust)           │
│  DAKE state machine                         │
│  SMP state machine                          │
│  DakeOutput opaque handle                   │
│  SecretBytes / SecretVec                    │
│  ZeroizeOnDrop everywhere                   │
├─────────────────────────────────────────────┤
│  Pure-Rust crypto crates                    │
│  ed448-goldilocks-plus, x448, sha3,         │
│  aes-gcm, pqcrypto-mlkem (FIPS 203          │
│  ML-KEM-1024), pqcrypto-mldsa (FIPS 204     │
│  ML-DSA-87)                                 │
└─────────────────────────────────────────────┘
```

As of v10.7, the Python `cryptography` library has been **fully removed** from the codebase. Every Ed448, X448, AES-256-GCM, and ML-DSA-87 operation runs inside the Rust `otrv4_core` core. There is no OpenSSL-backed Python crypto in any code path.

As of v10.7.5 (Phase 5.3k) all C extensions have been retired.  The previous `otr4_crypto_ext`, `otr4_ed448_ct`, and `otr4_mldsa_ext` shared libraries are deleted from the repo and the `setup_otr4.py` build target removed.  Every cryptographic operation now runs inside the Rust `otrv4_core` module: ML-KEM-1024 (FIPS 203), ML-DSA-87 (FIPS 204), Ed448 and X448 (`ed448-goldilocks-plus`), AES-256-GCM (`aes-gcm`), and the Argon2id-class KDF that protects the SMP secret vault.  Memory wiping uses Rust `zeroize::Zeroize` on Rust-owned buffers and `ctypes.memset` for the remaining bytearrays held on the Python side.

## Key exchange (DAKE)

Three-message handshake per OTRv4 §4.2 and §4.3. X448 ephemeral DH plus ML-KEM-1024 encapsulation. Both peers contribute entropy.

The entire DAKE, including all session-key derivation, runs in Rust. X448 DH exchanges (`dh1`, `dh2`, `dh3`), ML-KEM encap and decap, MAC over the DAKE2 wire body, Ed448 ring signature verification for DAKE3, and the KDF chain that produces `root_key`, `chain_key_send`, `chain_key_recv`, `brace_key`, and `mac_key` all run inside `otrv4_core`. The pure-Python `OTRv4DAKE` fallback that earlier versions carried was deleted in v10.7; the Rust DAKE is the only DAKE implementation.

Session keys cross from DAKE into the ratchet via a Rust-only move. The `DakeOutput` PyO3 handle holds the keys in a private `RefCell<Option<DakeSessionKeys>>` with no Python-visible accessor. `consume_into_ratchet()` moves them directly into the ratchet's owned `SecretBytes` fields. Session keys are never marshalled into `PyBytes` at any point.

## Long-term identity

Ed448 and X448 identity keys are generated inside Rust at session start. The Python `ClientProfile.identity_key` and `.prekey` are opaque `Ed448KeyHandle` and `X448KeyHandle` objects. Each handle owns `SecretBytes<N>` and exposes only `public_bytes()` and the operations the protocol needs (`sign()`, `ring_sign()`, `dh()`). Private bytes are not retrievable from Python by any public method.

When the handle is garbage-collected, Rust's `ZeroizeOnDrop` runs and wipes the SecretBytes before the heap slot is reclaimed.

## Double ratchet

Chain keys advance per message via SHAKE-256 KDF. DH ratchet at rekey boundaries (100 messages or 24 hours). Fresh ML-KEM-1024 keypair generated and exchanged at every DH ratchet step. Brace key rotated with each KEM shared secret. Skipped message keys cached for out-of-order delivery (max 1000 skip).

As of v10.7, the ratchet's X448 Diffie-Hellman runs entirely in the Rust core via `X448KeyHandle`. The `x448` crate clamps the scalar per RFC 7748 and rejects low-order points, matching OpenSSL byte-for-byte; an RFC 7748 §5.2 known-answer test gates the build.

## Authentication

Ed448 ring signatures provide deniable authentication in DAKE3. The ring signature is implemented in pure Rust using `ed448-goldilocks-plus` and `sha3` for SHAKE-256. ML-DSA-87 is appended as hybrid post-quantum auth. ClientProfile signature verification on incoming peers runs through the Rust `verify_ed448_sig` function. SMP provides out-of-band identity verification via a four-step zero-knowledge proof, all four steps in Rust with `ZeroizeOnDrop` on every exponent.

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

## RFC build-time gates

Earlier versions ran a boot-time cross-verification that signed a test message with Rust Ed448 and the Python `cryptography` library and compared the byte output. v10.6.17 replaced that with hardcoded RFC 8032 §7.4 Ed448 test vectors in `Rust/src/test_vectors.rs`. v10.6.21 added an RFC 7748 §5.2 X448 known-answer vector in `Rust/src/key_handles.rs`. The `cargo test` harness exercises both and asserts byte equality with the published values.

Run `cargo test --release --no-default-features --features pq-rust` before any release. If a vector test fails, the corresponding Rust crate has drifted from its RFC and the build should not ship.

## Honest caveats

1. **Single author, no external review.** Code style is consistent but design choices have not been peer-reviewed.

2. **Built with AI assistance (Claude).** The author drove design and testing; the AI helped with implementation. Each substantive change was live-tested between two I2P peers before being committed.

3. **The Rust crypto crates are not audited.** `ed448-goldilocks-plus` 0.16 is the only viable pure-Rust Ed448 implementation but has no formal review. `x448` 0.6 is a pure-Rust X448 with no formal review. `pqcrypto-mlkem 0.1.1` (FIPS 203 ML-KEM-1024) and `pqcrypto-mldsa 0.1.2` (ML-DSA-87) are PQClean-derived reference implementations.

4. **Rust-core-only since v10.7.5.**  Every C extension (`otr4_crypto_ext`, `otr4_ed448_ct`, `otr4_mldsa_ext`) has been retired and the Python `cryptography` library was removed at v10.7.  The entire cryptographic surface of the client now lives inside the Rust `otrv4_core` PyO3 module — there is no second crypto implementation to drift against.  As of v10.7.6 (Phase 5.4) the SMP modular exponentiation is constant-time via `crypto-bigint` `DynResidue`, closing a timing side-channel on the secret SMP exponents.  See the CHANGELOG v10.6.18 → v10.7.6 sequence for the migration history.

5. **Ephemeral identity by design.** Identity keys regenerate at every launch. Fingerprints change on every restart. This is a deliberate threat-model choice for an I2P-based privacy IRC client, not a missing feature. Tor Browser, Cwtch (default), and Briar (before user opt-in) all keep identities short-lived for similar reasons. See ROADMAP Phase 5.3g.

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
