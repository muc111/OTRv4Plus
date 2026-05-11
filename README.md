<p align="center">
  <img src="icon.png" width="200" alt="OTRv4+">
</p>

<h1 align="center">OTRv4+</h1>
<p align="center"><strong>Post-quantum secure messaging over IRC — research prototype</strong></p>

<p align="center">
<code>v10.6.2 — Rust DAKE end-to-end functional · Audit Patch 1+2 hardening intact</code>
</p>

---

## Architecture

OTRv4+ implements the OTRv4 specification with post-quantum cryptography
at every layer.  The cryptographic core is Rust.  Python orchestrates
the IRC client and passes opaque handles where possible.  C extensions
provide constant-time Ed448 and ML-KEM operations.

```
┌─────────────────────────────────────────────┐
│  IRC transport (I2P / Tor / TLS 1.3)        │
├─────────────────────────────────────────────┤
│  Python orchestration layer                  │
│  (opaque handles for SMP secrets; brief     │
│   window for DAKE session keys — Phase 4)   │
├──────────────┬──────────────────────────────┤
│  C extensions│  Rust core (otrv4_core)       │
│  Ed448 ct    │  Double Ratchet               │
│  ML-KEM-1024 │  DAKE state machine           │
│  ML-DSA-87   │  SMP state machine            │
│  Ring sigs   │  Secret vault                 │
│              │  ZeroizeOnDrop everywhere     │
└──────────────┴──────────────────────────────┘
```

### Key exchange (DAKE)

Three-message handshake per OTRv4 §4.2-4.3.  X448 ephemeral DH +
ML-KEM-1024 encapsulation.  Both peers contribute entropy.  As of
v10.6.2 the **Rust DAKE path actually runs end-to-end with real
peers** — earlier v10.6 builds had the wrapper in place but constructor
signature mismatches caused silent fallback to Python `OTRv4DAKE` on
every session.  See CHANGELOG.md for the four crypto bugs that
prevented MAC verification once the Rust path was reachable.

X448 DH exchanges (`dh1`, `dh2`, `dh3`) and ML-KEM encap/decap happen
in Rust.  MAC over the DAKE2 wire body is computed in Rust.  Ed448
ring-signature verification for DAKE3 happens in Rust.  Session keys
(`root_key`, `chain_key_a`, `chain_key_b`, `brace_key`, `mac_key`)
cross the FFI boundary as `PyBytes` for a brief window before
`RustDoubleRatchet.from_dakeresult()` consumes them — see SECURITY.md
"Critical Exposure Window".  Phase 4 (ROADMAP) eliminates that window.

### Double ratchet

Chain keys advance per message via SHAKE-256 KDF.  DH ratchet at rekey
boundaries (100 messages or 24 hours).  Fresh ML-KEM-1024 keypair
generated and exchanged at every DH ratchet step.  Brace key rotated
with each KEM shared secret.  Skipped message keys cached for
out-of-order delivery (max 1000 skip).

### Authentication

Ed448 ring signatures provide deniable authentication in DAKE3.
ML-DSA-87 appended as hybrid post-quantum auth.  Peers without ML-DSA
fall back to classical only.  SMP provides out-of-band identity
verification via zero-knowledge proof — all four steps run in Rust
with `ZeroizeOnDrop` on all exponents.

### Memory safety

| Component | Where secrets live | Python sees | Zeroization |
|---|---|---|---|
| Ratchet keys | Rust `SecretBytes<32>` | Nothing | `ZeroizeOnDrop` |
| DAKE DH secrets | Rust heap/stack | Nothing | `ZeroizeOnDrop` |
| DAKE session keys (root, chain, brace, mac) | Rust heap → PyBytes (window) → Rust `SecretBytes` | Brief window during from_dakeresult call | aggressive zero + `consumed` flag |
| SMP exponents | Rust `SecretVec` | Nothing | `ZeroizeOnDrop` + explicit `destroy()` |
| SMP passphrase | `RustSMPVault` | Opaque `u64` handle | Rust-side bytearray wipe on entry |
| Ed448 / X448 private keys | Python `cryptography` lib, copied into Rust at session start | Yes (Python lifecycle) | OpenSSL `OPENSSL_cleanse` on lib teardown |

On `/quit`: all Rust structures drop (Zeroize), C buffers cleansed,
`~/.otrv4plus` destroyed per NIST SP 800-88r1.

---

## Security properties

**Forward secrecy.** Per-message key erasure.  DH ratchet injects
fresh entropy each epoch.  ML-KEM rotates with every DH ratchet, so
forward secrecy remains post-quantum throughout the session — not
just at handshake.

**Post-compromise security.** Compromise of one chain key exposes at
most one epoch.  Fresh DH and KEM at each boundary limits exposure
window.

**Replay protection.** Monotonic ratchet counters.  10,000-entry
seen-message cache.  Transcript-bound handshake messages.  SMP
transcript MAC prevents cross-session replay.

**Downgrade resistance.** Fixed algorithm suite.  No cipher
negotiation.  Client refuses to start without constant-time C
extensions.  Version byte checked on every message.

**Deniability.** Ed448 ring signatures.  Either party can produce a
valid transcript, so neither can prove to a third party what the
other said.  ML-DSA breaks this property when enabled — documented
limitation.

---

## Honest limitations

- **No formal audit.** 313 automated tests.  No third-party review.
  No ProVerif/TLA+ models.
- **No PQ deniability.** Standardised post-quantum ring signatures
  don't exist.  ML-DSA signatures are non-repudiable.
- **No async messaging.** Both parties must be online.  Use Signal for
  async.
- **Metadata visible to IRC server.** Who talks to whom, when, and
  message sizes.  I2P/Tor hide IP but not timing.
- **Fragment count leaks message type.** DAKE produces more fragments
  than chat.  No padding at fragment layer.
- **Critical Exposure Window.** Session keys briefly exist as PyBytes
  after DAKE2.  See SECURITY.md.  Phase 4 eliminates.
- **I2P latency.** Session setup takes 6–7 minutes.  This is I2P
  routing, not cryptography.

---

## Session timing (real I2P measurements, v10.6.2)

irc.postman.i2p, Termux on aarch64, SAM bridge:

| Phase | Time |
|---|---|
| DAKE handshake | ~2m 44s |
| SMP verification | ~2m 00s |
| Total to 🔵 verified | ~6m 37s |

The cryptographic computation (including 50,000-round SMP KDF and
the full DAKE crypto: 3× X448 DH, ML-KEM-1024 encap+decap, Ed448
ring sig, MAC) takes under 1 second total.  Everything else is I2P
tunnel latency.

---

## Quick start

```bash
git clone https://github.com/muc111/OTRv4Plus.git && cd OTRv4Plus && \
    chmod +x termux_install.sh && ./termux_install.sh && \
    PYTHONMALLOC=malloc python otrv4+.py
```

Then:

```
/join #otr
/otr <nickname>
/smp <shared-secret>
/smp start
```

Defaults to `irc.postman.i2p`.  Auto-detects `.i2p`, `.onion`, or
clearnet.

---

## Commands

```
/otr <nick>       Start encrypted session (Rust DAKE)
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

## Tests

```bash
cd Rust && cargo test --release && cd ..
pip install pytest hypothesis
pytest tests/ -v
```

313 tests.  100k-message ratchet gauntlets.  KEM known-answer vectors.
Ring-signature non-malleability checks.  SMP full protocol flow.
Property-based fuzzing via Hypothesis.

---

## Building from source

Requirements: Python 3.9+, OpenSSL 3.5+, Rust toolchain, C compiler.

```bash
python setup_otr4.py build_ext --inplace
bash build_ed448.sh
cd Rust && cargo clean && \
    cargo build --release --no-default-features --features pq-rust && \
    cd ..
cp Rust/target/release/libotrv4_core.so .
```

`cargo clean` is deliberate — see CHANGELOG.md "Build-process note"
in the v10.6.2 entry.  Cargo's incremental build can silently skip
rebuilds on non-trivial source changes.

Prebuilt aarch64 binaries in `prebuilt/` if compilation fails.

---

## Implementation status (v10.6.2)

| Component | Language | Zeroization | Test coverage |
|---|---|---|---|
| Double Ratchet | Rust | `ZeroizeOnDrop` ✅ | Python + Rust |
| DAKE engine | Rust | `ZeroizeOnDrop` ✅ + window mitigation | Python; end-to-end I2P validated |
| SMP engine | Rust | `ZeroizeOnDrop` ✅ | Python |
| SMP vault | Rust | `ZeroizeOnDrop` + `destroy()` ✅ | Python |
| Ring signatures | C ext | `OPENSSL_cleanse` | Python |
| ML-KEM-1024 | Rust (`pqcrypto-kyber`) | (vendor) | Python + Rust KAT |
| ML-DSA-87 | C ext | `OPENSSL_cleanse` | Python |
| Identity keys (Ed448 / X448) | Python `cryptography` lib → Rust | Python lib lifecycle | Python |

---

## License

GPL-3.0.  Commercial licensing available.

---

> "Arguing that you don't care about the right to privacy because you
> have nothing to hide is no different than saying you don't care about
> free speech because you have nothing to say."  — Edward Snowden
