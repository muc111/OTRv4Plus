# DEVELOPMENT.md

Build environment, architecture, and test plan for OTRv4+ as of v10.13.0.

There are no C extensions to compile and no prebuilt binaries in the repository.
Everything is built from source with `cargo`. (Earlier versions used three C
extensions; they were retired at v10.7.4–v10.7.5 and are mentioned below only
for historical context.)

The **chat** path is Rust-core-only: the Python `cryptography` library was
removed from it at v10.7. The **voice** path is not — `otrv4plus_voice.py` uses
that library for the media AES-256-GCM, the HKDF-SHA512 key schedule and the
voice X448, so `pip install cryptography` is required to build or test voice.
See [SECURITY.md](SECURITY.md) caveat 11.

---

## Architecture overview

OTRv4+ has two layers:

1. **Rust core (`otrv4_core`)** — a PyO3 native module (`libotrv4_core.so`,
   copied to the project root as `otrv4_core.so`). All cryptography lives here.
   Private key material is held in Rust-owned `SecretBytes` / `SecretVec` with
   `ZeroizeOnDrop` and is never exposed to Python as `bytes`.

2. **Python orchestration (`otrv4+.py`)** — ~13,000 lines handling IRC
   connectivity, IRCv3 capability negotiation, fragment reassembly, the terminal
   UI, command parsing, and the OTR/SMP state-machine driving. It holds no
   private key material; every crypto operation is delegated to the Rust core.

The Rust crate is roughly 3,500–4,000 lines across:

| File | Responsibility |
|---|---|
| `dake.rs` | Three-message DAKE handshake state machine |
| `ratchet.rs` | Double ratchet (X448 DH + ML-KEM-1024 brace rotation) |
| `smp.rs` | Hybrid PQC Socialist Millionaire Protocol |
| `smp_vault.rs` | SMP secret storage (`ZeroizeOnDrop`) |
| `ring_sig.rs` | Ed448 Schnorr ring signature (deniable auth) |
| `mlkem.rs` | ML-KEM-1024 (FIPS 203) via `pqcrypto-mlkem` |
| `mldsa.rs` | ML-DSA-87 (FIPS 204) via `pqcrypto-mldsa` |
| `aead.rs` | AES-256-GCM via `aes-gcm` |
| `kdf.rs` | SHAKE-256 KDF, HMAC-SHA3-512, fingerprints |
| `key_handles.rs` | Opaque Ed448 / X448 key handles |
| `secure_mem.rs` | `SecretBytes` / `SecretVec`, constant-time compare |
| `header.rs`, `error.rs`, `aead.rs` | Wire headers, error types |
| `test_vectors.rs` | RFC 8032 / 7748 / FIPS KAT build-time gates |

For the byte-level protocol definition, see [SPEC.md](SPEC.md).

---

## Development history (phases)

The project moved through several architectural phases. The short version:

- **Phase 1 — pure Python + OpenSSL (months 1–4).** Earliest working versions
  used the Python `cryptography` library (OpenSSL-backed) for all EC operations.
  Chosen because OpenSSL is heavily audited.
- **Phase 2 — Python + C extensions (months 5–12, retired by v10.7.5).**
  Performance and side-channel concerns forced secret-dependent arithmetic into
  three C extensions (`otr4_crypto_ext`, `otr4_ed448_ct`, `otr4_mldsa_ext`).
  All three have since been replaced by pure-Rust equivalents and deleted;
  documented here for history only.
- **Phase 5.3 — migration to a Rust core via PyO3.** The driving requirement was
  memory safety: `ZeroizeOnDrop` on secret key material cannot be reliably
  achieved from Python. Each primitive was moved into Rust and live-tested in
  isolation before the next. The `cryptography` library was removed at v10.7;
  the last C extension at v10.7.4.
- **Phase 5.4 (v10.7.6).** SMP modular exponentiation made constant-time via
  `crypto-bigint` `DynResidue` (Montgomery form).
- **v10.9.0.** SMP made hybrid post-quantum (ML-KEM-1024 + ML-DSA-87 wrapping the
  classical Schnorr ZKP).

---

## Build

### Python version requirement

**Python 3.12 or newer is required.** This is not a preference:

```
otrv4+.py:4268  raise ValueError(f"Key component empty or too long: {s !r }")
                SyntaxError on 3.11 -- f-string: expecting '}'
```

The codebase uses a `{expr !r }` spacing style that is only legal under PEP 701
(Python 3.12+). On 3.11 or earlier `otrv4+.py` does not parse at all, so the
failure appears as a SyntaxError during import rather than as a clear version
error. `Rust/pyproject.toml` declares `requires-python = ">=3.12"` for this
reason, and `android_bridge/bootstrap.py` checks it before attempting the
import so the Android host fails with an explanatory message instead.

The Rust extension is built `abi3-py39` and would technically load on 3.9; the
constraint comes from the Python application layer, not the wheel.

### Prerequisites

On Termux (Android):

```bash
pkg install python rust clang git
```

On Debian/Ubuntu, only the Rust toolchain is required. The Rust core uses no
system libraries and needs no `-dev` packages:

```bash
sudo apt install build-essential   # only if building the Rust toolchain itself
```

Rust 1.80+ is required. Edition 2024 (used if you bump `Cargo.toml`) needs Rust
1.85+. On Termux, check with `rustc --version` and `pkg upgrade rust` if needed.

### Rust core (the only build step)

```bash
cd Rust
cargo build --release --no-default-features --features pq-rust
cp target/release/libotrv4_core.so ../otrv4_core.so
cd ..
```

The `--no-default-features --features pq-rust` flag set is **required** on
Termux/aarch64: the default AVX2/NEON-optimised code paths of `pqcrypto-mlkem`
and `pqcrypto-mldsa` cause `SIGILL` on this platform. The portable PQClean
reference path is selected instead.

---

## Test plan

```bash
cd Rust
cargo test --release --no-default-features --features pq-rust
# expected: 77 passed; 0 failed  (as of v10.13.0)
```

Expected: **65 tests pass, 0 failures.** The suite includes:

- RFC 8032 Ed448 known-answer vectors (`test_vectors.rs`)
- RFC 7748 X448 known-answer vector (`key_handles.rs`) — ratchet desync guard
- FIPS 203 ML-KEM-1024 byte-size + roundtrip + wrong-key rejection (`mlkem.rs`)
- SMP prime byte-equality (`crypto-bigint` vs `num-bigint` representations)
- Constant-time `mod_exp` small KAT + full-width cross-check against a reference
- Hybrid PQC SMP: classical roundtrip, hybrid roundtrip, mismatched secrets in
  both modes, version-mismatch rejection, ML-DSA-87 context sign/verify, wrong-
  context rejection, ML-KEM-1024 encaps/decaps roundtrip, `pq_binding_key`
  determinism
- Argon2id SMP derivation (wire `0x03`, v10.13.0): that the salt binds the
  session ID and both fingerprints, that it is role-independent, that salt
  field boundaries cannot collide, that Argon2id and the legacy SHAKE stretch
  derive different scalars, that a mixed `0x02`/`0x03` pair aborts with an
  actionable error, and a frozen vector for the `0x02` stretch cross-checked
  against an independent Python implementation

Python suite — run from the repository root, not from `tests/`, or the root-level
voice and audio suites are silently skipped:

```bash
python3.12 -m pytest -q
# expected: 1633 passed, 43 skipped, 1 xfailed   (as of v10.13.0)
```

The skips are environment-gated (no audio device, no Termux:API, no live SAM
bridge), not failures. The root-level suites — `test_voice_security.py`,
`test_audio_backend.py`, `test_voice_audio_integration.py`,
`test_mac_key_revelation.py` — contribute 239 of those tests and are *not*
under `tests/`.

Python syntax gate:

```bash
python3 -c "import ast; ast.parse(open('otrv4+.py').read()); print('AST OK')"
```

### Live testing

Unit tests do not catch protocol-level desynchronisation between two peers.
**Every release is live-tested between two concurrent sessions** (typically two
Termux instances, or one Termux + one desktop) over both TLS clearnet and I2P
SAM before commit. Several real bugs — including the v10.9.0 KEM-key-mixing
false-negative — were only discoverable this way.

For voice this is not optional. Every voice defect fixed in v10.12.0 was found
in a live call and none of them could have been: a rekey that wedged on one lost
message, a keepalive declaring a working stream dead, a media path that died
while every counter stayed healthy, and a PyO3 thread-affinity crash that needed
two concurrent DAKEs to reproduce. A green suite says the pieces are correct; it
does not say the call works.

New production invariants are mutation-tested rather than trusted to a passing
count: write the test, remove or invert the production behaviour, confirm the
test fails, restore, confirm it passes. The v10.12.0 session-hold work records
seven such mutations in its changelog entry.

Run with debug logging:

```bash
PYTHONMALLOC=malloc python otrv4+.py --debug                    # I2P default
PYTHONMALLOC=malloc python otrv4+.py -s irc.libera.chat --debug # clearnet TLS
```

`PYTHONMALLOC=malloc` is recommended so freed Python buffers are less likely to
retain sensitive data in the small-object arenas.

---

## Dependency notes

- `pqcrypto-mlkem` 0.1.1 (FIPS 203), `pqcrypto-mldsa` 0.1.2 (FIPS 204) — built
  with `default-features = false` to force the portable path on aarch64.
- `crypto-bigint` 0.5 — constant-time modular exponentiation for SMP. Promoted
  from transitive to direct dependency at v10.7.6.
- `num-bigint` — still used for public-value ZKP arithmetic and random sampling
  (no secret-dependent timing in those paths). See the known limitation in
  [SECURITY.md](SECURITY.md) regarding the ZKP scalar response.
- `ed448-goldilocks-plus` 0.16, `x448` 0.6 — pure-Rust Ed448 / X448.
- `aes-gcm` 0.10, `sha3` 0.10, `zeroize`, `subtle` — AEAD, hashing, wiping,
  constant-time comparison.

Run `cargo audit` (`cargo install cargo-audit`) on-device for the authoritative
CVE check against the live RustSec database. `cargo update -p dashmap --precise
5.5.3` is recommended.

---

## Native APK

Packaging a signed `.apk` bundling the Python interpreter and the Rust `.so` has
been investigated but is non-trivial. Termux is the supported development
environment; a native APK is future work (see [ROADMAP.md](ROADMAP.md)).
