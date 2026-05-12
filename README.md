<p align="center">
  <img src="icon.png" width="200" alt="OTRv4+">
</p>

<h1 align="center">OTRv4+</h1>
<p align="center"><strong>Post-quantum secure messaging over IRC — research prototype</strong></p>

<p align="center">
<code>v10.6.3 — 11/11 audit findings closed · Critical Exposure Window eliminated</code>
</p>

---

## Architecture

OTRv4+ implements the OTRv4 specification with post-quantum cryptography
at every layer.  The cryptographic core is Rust.  Python orchestrates
the IRC client and passes opaque handles for all session state.  C
extensions provide constant-time Ed448 and ML-KEM operations.

```
┌─────────────────────────────────────────────┐
│  IRC transport (I2P / Tor / TLS 1.3)        │
├─────────────────────────────────────────────┤
│  Python orchestration layer                  │
│  (opaque handles — secret keys never seen)  │
├──────────────┬──────────────────────────────┤
│  C extensions│  Rust core (otrv4_core)       │
│  Ed448 ct    │  Double Ratchet               │
│  ML-KEM-1024 │  DAKE state machine           │
│  ML-DSA-87   │  SMP state machine            │
│  Ring sigs   │  DakeOutput opaque handle     │
│              │  SecretBytes / SecretVec      │
│              │  ZeroizeOnDrop everywhere     │
└──────────────┴──────────────────────────────┘
```

### Key exchange (DAKE)

Three-message handshake per OTRv4 §4.2-4.3.  X448 ephemeral DH +
ML-KEM-1024 encapsulation.  Both peers contribute entropy.

As of v10.6.3, **the entire DAKE — including all session-key
derivation — happens in Rust**.  X448 DH exchanges (`dh1`, `dh2`,
`dh3`), ML-KEM encap/decap, MAC over the DAKE2 wire body, Ed448 ring
signature verification for DAKE3, and the KDF chain that produces
`root_key`, `chain_key_send`, `chain_key_recv`, `brace_key`, `mac_key`
all run inside `otrv4_core`.

The session keys cross from DAKE into the ratchet via a **Rust-only
move**: the new `DakeOutput` PyO3 handle holds the keys in a private
`RefCell<Option<DakeSessionKeys>>` with no Python-visible accessor;
`consume_into_ratchet()` moves them directly into the ratchet's
owned `SecretBytes` fields.  **Session keys are never marshalled into
`PyBytes` at any point.**

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

### Memory safety (v10.6.3)

| Component | Where secrets live | Python sees | Zeroization |
|---|---|---|---|
| Ratchet chain / root keys | Rust `SecretBytes<32>` | Nothing | `ZeroizeOnDrop` |
| Ratchet brace key | Rust `SecretBytes<32>` | Nothing | `ZeroizeOnDrop` |
| DAKE DH secrets (dh1/dh2/dh3, mlkem_ss) | Rust heap | Nothing | `ZeroizeOnDrop` |
| DAKE session keys (root, chain×2, brace, mac) | Rust `DakeSessionKeys` → `DoubleRatchet::SecretBytes` (Rust-to-Rust move) | **Nothing** | `ZeroizeOnDrop` end-to-end |
| SMP exponents | Rust `SecretVec` | Nothing | `ZeroizeOnDrop` + explicit `destroy()` |
| SMP passphrase | `RustSMPVault` (Argon2id-hashed) | Opaque `u64` handle | Rust wipes caller's bytearray |
| Ed448 / X448 long-term private keys | Python `cryptography` lib + OpenSSL C heap; private bytes copied into Rust at session start | Yes (Python object lifecycle) | OpenSSL lib teardown — Phase 5 moves into Rust |

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

**Boundary safety (v10.6.3).** Session keys are inaccessible to
Python.  An attacker with Python heap read (debugger, ptrace, core
dump, `/proc/<pid>/mem`) cannot recover root/chain/brace/mac keys.

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
- **Long-term identity keys.** Ed448 / X448 private bytes still live
  in Python `cryptography` library objects.  Phase 5 moves into Rust.
- **I2P latency.** Session setup takes 6–7 minutes.  This is I2P
  routing, not cryptography.

---

## Session timing (real I2P measurements)

irc.postman.i2p, Termux on aarch64, SAM bridge:

| Phase | Time |
|---|---|
| DAKE handshake | ~2m 44s |
| SMP verification | ~2m 00s |
| Total to 🔵 verified | ~6m 37s |

The cryptographic computation (50,000-round SMP KDF, three X448 DH,
ML-KEM-1024 encap+decap, Ed448 ring sig, MAC, AEAD setup) takes under
1 second total.  Everything else is I2P tunnel latency.

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

**Note for v10.6.3:** tests that assert on the `_rks_send`, `_rks_recv`,
`_rks_root` mirrors should check for `hasattr(ratchet,
'_dake_output_consumed')` and skip mirror-based assertions when the
ratchet was built via the Phase-4 path — those mirrors are zero
placeholders by design.

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

# Verify Phase 4 is in the binary:
strings otrv4_core.so | grep -c DakeOutput     # > 0
strings otrv4_core.so | grep -c from_dake_keys # > 0
```

`cargo clean` is deliberate.  Cargo's incremental build can silently
skip rebuilds on non-trivial source changes.  Verify via `strings` and
the marker-grep above.

Prebuilt aarch64 binaries in `prebuilt/` if compilation fails.

---

## Implementation status (v10.6.3)

| Component | Language | Zeroization | Test coverage |
|---|---|---|---|
| Double Ratchet | Rust | `ZeroizeOnDrop` ✅ | Python + Rust |
| DAKE engine | Rust | `ZeroizeOnDrop` ✅ end-to-end | Python; end-to-end I2P validated |
| DAKE → ratchet handoff | Rust-only (DakeOutput → consume_into_ratchet) | ✅ never PyBytes | Python; live-tested |
| SMP engine | Rust | `ZeroizeOnDrop` ✅ | Python |
| SMP vault | Rust | `ZeroizeOnDrop` + `destroy()` ✅ | Python |
| Ring signatures | C ext | `OPENSSL_cleanse` | Python |
| ML-KEM-1024 | Rust (`pqcrypto-kyber`) | (vendor) | Python + Rust KAT |
| ML-DSA-87 | C ext | `OPENSSL_cleanse` | Python |
| Identity keys (Ed448 / X448) | Python `cryptography` lib → Rust at session start | Python lib lifecycle | Python (Phase 5 moves to Rust) |

---

## License

GPL-3.0.  Commercial licensing available.

---

> "Arguing that you don't care about the right to privacy because you
> have nothing to hide is no different than saying you don't care about
> free speech because you have nothing to say."  — Edward Snowden
