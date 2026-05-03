# Development & History

## Why the git history looks shallow

The public GitHub repository shows only a small number of initial commits. This is because **12+ months of development happened offline and in private repositories**. Before open-sourcing, the history was squashed to remove:

- Hard-coded test credentials and I2P destination addresses
- Early experimental wire formats that would break protocol compatibility
- Debug prints containing intermediate key material
- Large binary blobs (test vectors, core dumps from sanitizer runs)

The code here is **not a quick hack** — it is the result of iterative development, repeated cross-checking against the OTRv4 spec, adversarial test-suite construction, and multiple security-motivated refactors that together removed ~1,800 lines of dead and unsafe code.

---

## Development phases

### Phase 1 — Pure Python (months 1–4)

Everything started in a single Python file. The goal was a working OTRv4 IRC client that could run on Termux/Android over I2P with no native dependencies.

- Read OTRv4 spec (draft-10) end-to-end; implemented DAKE state machine (DAKE1/DAKE2/DAKE3) with Ed448 identity signatures and X448 ephemeral exchange
- Ring signature OR-proof (Auth-I, §4.3.3) in pure Python using `cryptography` library primitives
- Double ratchet skeleton: `chain_key → msg_key` KDF, message-key skipping for out-of-order delivery, explicit rekey intervals
- ML-KEM-1024 brace injected into every root-key ratchet step
- SMP four-message ZKP flow with 3072-bit DH
- Basic terminal IRC client: single panel, raw ANSI, no tab system

**Limitation identified:** Python's `pow()` with modulus is not constant-time. Secret-dependent branching in Ed448 arithmetic was present throughout. This became the primary motivation for Phase 2.

---

### Phase 2 — Python + C extensions (months 5–12)

Performance and side-channel security forced a move to C for all secret-dependent arithmetic. Three C extensions were written and integrated:

#### otr4_crypto_ext.c

- Constant-time modular exponentiation via `BN_mod_exp_mont_consttime` (OpenSSL)
- Modular inverse via `BN_mod_inverse`
- Cryptographically random integers in range via `BN_rand_range`
- ML-KEM-1024 key generation, encapsulation, decapsulation via liboqs
- Ed448 Schnorr ring signatures (OR-proof) used in Auth-I
- Memory hardening: `OPENSSL_cleanse`, `mlock()`, `prctl(PR_SET_DUMPABLE, 0)`

The client was made to **refuse startup** if this extension is absent — there is intentionally no Python fallback for constant-time operations.

#### otr4_ed448_ct.c

Constant-time Edwards-448 point arithmetic — scalar multiplication (`gep_scalarmult`) with full Montgomery ladder, cofactor clearing, and point serialisation. A critical timing side-channel was found and fixed in `gep_scalarmult` during security review.

#### otr4_mldsa_ext.c

ML-DSA-87 signatures via OpenSSL 3.5+ EVP provider, used for post-quantum authentication layered on top of the classical Ed448 DAKE. OpenSSL 3.5+ is required — it is the first release with native PQC algorithm support.

#### IRC client maturation

- Full tabbed terminal UI: coloured nicks, security icons, unread badges, pager
- IRCv3 support: SASL PLAIN, TLS, PING watchdog, auto-reconnect, auto-join
- WHOIS, NickServ identification, 27 Club username generator
- 27 IRC commands added
- Fragment reassembly bug fixed: window expiry now based on last received fragment timestamp

**Security posture at end of Phase 2: ~9.4/10**

---

### Phase 3 — Rust cryptographic core (month 13+)

#### Track A — Rust Double Ratchet (v10.5.8, complete)

The Python double ratchet was replaced with a pure Rust implementation (`otrv4_core` crate via PyO3/maturin). Key properties:

- All chain keys, message keys, and brace keys stored in `SecretBytes<32>` with `ZeroizeOnDrop`
- Zero `unsafe` blocks — the Rust borrow checker enforces memory safety
- PyO3 boundary: Python receives opaque handles and ciphertext; no key material ever crosses to Python

#### Track B — Rust SMP Engine (v10.5.10, complete)

The Python SMP implementation was replaced with a full Rust state machine. This is the most significant security improvement since the C extension work:

**Before v10.5.10:**
- SMP exponents existed as Python `int` objects during ZKP computation
- Python `int` is immutable and GC-managed — no deterministic zeroization
- The secret was stretched and stored in Python memory for the session lifetime
- The responder (Bob) never visually transitioned to the verified state (🔵)

**After v10.5.10:**
- All exponents are `SecretVec` inside `SmpState` — `ZeroizeOnDrop` fires on every abort, failure, or session end
- `RustSMPVault` holds the raw passphrase bytes in Rust; Python holds only a random `u64` token
- `set_secret_from_vault()` runs the 50,000-round SHAKE-256 KDF entirely in Rust
- The Python `bytearray` holding the encoded passphrase is zeroed byte-by-byte before deletion
- Both the initiator and responder now correctly transition to `SMP_VERIFIED` (🔵)

**Why the SMP KDF uses canonical fingerprint ordering:**

The original v10.5.10 draft used a role byte (`0x00` for initiator, `0x01` for responder) and role-dependent fingerprint ordering in the HMAC. This caused Alice and Bob to compute different derived secrets from the same passphrase, guaranteeing SMP failure on every run. The fix was to sort fingerprints lexicographically so both sides always feed the HMAC in the same order, regardless of who initiated.

**Real-world SMP timing over I2P (from live debug logs):**

```
11:06:06  /otr StrayBlade                    ← initiator starts
11:08:50  DAKE3 verified (ring-sig + ML-DSA) ← 2m 44s for DAKE
11:09:18  fingerprint trusted (manual y/n)   ← instant
11:10:43  SMP1 received by responder         ← SMP starts
11:12:43  both sides → 🔵 SMP_VERIFIED       ← 2m 0s for SMP
──────────────────────────────────────────
Total: ~6m 37s from /otr to blue verified session
```

This latency is entirely due to I2P tunnel routing — each fragment traverses multiple encrypted hops at ~4-second intervals. The cryptographic computation itself (including the 50,000-round KDF) takes under 1 second on Termux/aarch64.

#### Track C — WeeChat plugin (in progress)

The existing Python implementation is being adapted as a WeeChat plugin, reusing the full OTRv4+ protocol stack without changes to the cryptographic layer.

---

## Use of AI assistance

Large language models (Claude) were used to generate scaffolding for the Python IRC client, terminal UI, test harnesses, and the Rust SMP migration. Cryptographic primitives — C extensions, KDF chains, DAKE state machine, ring signature proofs, and SMP ZKP steps — were not written by AI. Every AI-generated segment was reviewed line-by-line, tested against the OTRv4 spec, and subjected to the adversarial test suite.

The Rust SMP migration in v10.5.10 involved several AI-assisted iterations before reaching a correct implementation — notably the fingerprint-ordering bug (role-dependent ordering → canonical lexicographic ordering) was identified and fixed through live session testing between two Termux instances over I2P.

I am not a professional cryptographer, which is precisely why external review and responsible disclosure of vulnerabilities are actively welcomed.

---

## Why the C extensions are mandatory

The client refuses to start if any extension cannot be loaded. This is deliberate:

1. **No constant-time fallback exists in Python** — `pow(b, e, m)` is not constant-time; secret-dependent branching is unavoidable in pure Python big-integer arithmetic
2. **ML-KEM-1024 and ML-DSA are not available in pure Python** — they require OpenSSL 3.5+ (native PQC provider), accessible only via C/Rust bindings
3. **Secure memory zeroisation** — `OPENSSL_cleanse` and `mlock` are only reachable through native extensions

---

## Build instructions

### C extensions (required)

Requires OpenSSL 3.5+ — earlier versions lack native ML-KEM and ML-DSA provider support.

```bash
# Termux (Android)
pkg install openssl python clang make

# Debian/Ubuntu
sudo apt install libssl-dev python3-dev build-essential

# Build all extensions
python setup_otr4.py build_ext --inplace
bash build_ed448.sh
```

### Rust core (required)

```bash
# Termux
pkg install rust

# Desktop
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build
cd Rust && cargo build --release --features pq-rust
cp target/release/libotrv4_core.so ../ && cd ..
```

### Running tests

```bash
pip install pytest pytest-timeout hypothesis
pytest -v
```

---

## Known gaps & future work

- **PQ deniability** — no standardised post-quantum ring signature exists. When ML-DSA is used, a quantum-capable adversary can verify the signer. Accepted and documented; a lattice-based OR-proof is a long-term research goal.
- **Traffic analysis** — fragment count leaks message type (DAKE vs data message). A PADDING TLV inside the encrypted envelope would mitigate this; planned for a future protocol version.
- **Formal verification** — none yet. A ProVerif or EasyCrypt audit would strengthen assurance claims.
- **Identity keys** — Ed448/X448 private keys still live in Python OpenSSL objects. Phase 4 will move these to Rust `SecretVec`.
- **WeeChat plugin** — status bar integration and per-buffer OTR session display are in active development.

---

## Contributing

Bug reports, pull requests, and cryptanalysis are welcome. For vulnerabilities, disclose responsibly via the GitHub security advisory. For significant protocol or API changes, open an issue before submitting a PR.
