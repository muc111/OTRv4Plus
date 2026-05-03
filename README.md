<p align="center">
  <img src="icon.png" width="200" alt="OTRv4+">
</p>

<h1 align="center">OTRv4+</h1>
<p align="center"><strong>Post-quantum secure messaging over IRC — research prototype</strong></p>

---

## Architecture

OTRv4+ implements the OTRv4 specification with post-quantum cryptography at every layer. The cryptographic core is Rust. Python orchestrates the IRC client and passes opaque handles. C extensions provide constant-time Ed448 and ML-KEM operations.

```

┌─────────────────────────────────────────────┐
│  IRC transport (I2P / Tor / TLS 1.3)        │
├─────────────────────────────────────────────┤
│  Python orchestration layer                  │
│  (no secret material — opaque handles only)  │
├──────────────┬──────────────────────────────┤
│  C extensions│  Rust core (otrv4_core)       │
│  Ed448 ct    │  Double Ratchet               │
│  ML-KEM-1024 │  SMP state machine            │
│  ML-DSA-87   │  Secret vault                 │
│  Ring sigs   │  All keys ZeroizeOnDrop       │
└──────────────┴──────────────────────────────┘

```

### Key exchange (DAKE)

Three-message handshake per OTRv4 §4.2-4.3. X448 ephemeral DH + ML-KEM-1024 encapsulation. Both peers contribute entropy. No prekey server. No long-term identity that survives /quit.

### Double ratchet

Chain keys advance per message via SHAKE-256 KDF. DH ratchet at rekey boundaries (100 messages or 24 hours). Fresh ML-KEM-1024 keypair generated and exchanged at every DH ratchet step. Brace key rotated with each KEM shared secret. Skipped message keys cached for out-of-order delivery (max 1000 skip).

### Authentication

Ed448 ring signatures provide deniable authentication in DAKE3. ML-DSA-87 appended as hybrid post-quantum auth with a flag byte. Peers without ML-DSA fall back to classical only. SMP provides out-of-band identity verification via zero-knowledge proof — all four steps run in Rust with ZeroizeOnDrop on all exponents.

### Memory safety

| Component | Where secrets live | Python sees | Zeroization |
|---|---|---|---|
| Ratchet keys | Rust SecretBytes\<32\> | Nothing | ZeroizeOnDrop |
| SMP exponents | Rust SecretVec | Nothing | ZeroizeOnDrop + destroy() |
| SMP passphrase | RustSMPVault | Opaque u64 handle | vault.clear() |
| Passphrase in transit | Python bytearray (wiped) | Microseconds | Byte-by-byte overwrite |
| DAKE DH output | OpenSSL C heap | Brief bytes during KDF | OPENSSL_cleanse |

On /quit: all ratchets zeroized, C buffers cleansed, ~/.otrv4plus destroyed per NIST SP 800-88r1.

---

## Security properties

**Forward secrecy.** Per-message key erasure. DH ratchet injects fresh entropy each epoch. ML-KEM rotates with every DH ratchet, so forward secrecy remains post-quantum throughout the session — not just at handshake.

**Post-compromise security.** Compromise of one chain key exposes at most one epoch. Fresh DH and KEM at each boundary limits exposure window.

**Replay protection.** Monotonic ratchet counters. 10,000-entry seen-message cache. Transcript-bound handshake messages. SMP transcript MAC prevents cross-session replay.

**Downgrade resistance.** Fixed algorithm suite. No cipher negotiation. Client refuses to start without constant-time C extensions. Version byte checked on every message.

**Deniability.** Ed448 ring signatures. Either party can produce a valid transcript, so neither can prove to a third party what the other said. ML-DSA breaks this property when enabled — documented limitation.

---

## Honest limitations

- **No formal audit.** 295 automated tests. No third-party review. No ProVerif/TLA+ models.
- **No PQ deniability.** Standardised post-quantum ring signatures don't exist. ML-DSA signatures are non-repudiable.
- **No async messaging.** Both parties must be online. Use Signal for async.
- **Metadata visible to IRC server.** Who talks to whom, when, and message sizes. I2P/Tor hide IP but not timing.
- **Fragment count leaks message type.** DAKE produces more fragments than chat. No padding at fragment layer.
- **Passphrase transit.** SMP passphrase spends microseconds as Python bytearray before Rust vault takes ownership.
- **I2P latency.** Session setup takes 6-7 minutes. This is I2P routing, not cryptography.

---

## Session timing (real I2P measurements)

irc.postman.i2p, Termux on aarch64, SAM bridge:

| Phase | Time |
|---|---|
| DAKE handshake | ~2m 44s |
| SMP verification | ~2m 00s |
| Total to 🔵 verified | ~6m 37s |

The cryptographic computation (including 50,000-round SMP KDF) takes under 1 second. Everything else is I2P tunnel latency.

---

## Quick start

```bash
git clone https://github.com/muc111/OTRv4Plus.git && cd OTRv4Plus && chmod +x termux_install.sh && ./termux_install.sh && PYTHONMALLOC=malloc python otrv4+.py
```

Then:

```
/join #channel
/otr nickname
/smp sharedsecret
/smp start
```

Defaults to irc.postman.i2p. Auto-detects .i2p, .onion, or clearnet.

---

Commands

```
/otr <nick>       Start encrypted session
/smp <secret>     Set shared secret (never transmitted)
/smp start        Begin identity verification
/fingerprint      Show fingerprints
/trust <nick>     Trust a fingerprint
/endotr           End encrypted session
/secure           Show security level
/ignore <nick>    Ignore a user
/quit             Wipe all keys and exit
```

---

Tests

```bash
cd Rust && cargo test --release && cd ..
pip install pytest hypothesis
pytest tests/ -v
```

295 tests. 100k-message ratchet gauntlets. KEM known-answer vectors. Ring signature non-malleability. SMP full protocol flow. Property-based fuzzing via Hypothesis.

---

Building from source

Requirements: Python 3.9+, OpenSSL 3.5+, Rust toolchain, C compiler.

```bash
python setup_otr4.py build_ext --inplace
bash build_ed448.sh
cd Rust && cargo build --release --features pq-rust && cd ..
cp Rust/target/release/libotrv4_core.so .
```

Prebuilt aarch64 binaries in prebuilt/ if compilation fails.

---

Implementation status

Component Language Zeroization
Double Ratchet Rust ZeroizeOnDrop ✅
SMP Engine Rust ZeroizeOnDrop ✅
SMP Vault Rust ZeroizeOnDrop ✅
DAKE DH secrets Python/OpenSSL OPENSSL_cleanse
Identity keys Python/OpenSSL None (planned Phase 4)

---

License

GPL-3.0. Commercial licensing available.

---

"Arguing that you don't care about the right to privacy because you have nothing to hide is no different than saying you don't care about free speech because you have nothing to say." — Edward Snowden
