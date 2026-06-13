# DEVELOPMENT.md

Build environment, architecture, and test plan for OTRv4+ as of v10.9.2.

OTRv4+ is **Rust-core-only**. There are no C extensions to compile and no
prebuilt binaries in the repository. Everything is built from source with
`cargo`. (Earlier versions used three C extensions and the Python `cryptography`
library; the C extensions were retired at v10.7.4–v10.7.5 and the `cryptography`
library at v10.7. They are mentioned below only for historical context.)

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
```

Expected: **30+ tests pass, 0 warnings.** The suite includes:

- RFC 8032 Ed448 known-answer vectors (`test_vectors.rs`)
- RFC 7748 X448 known-answer vector (`key_handles.rs`) — ratchet desync guard
- FIPS 203 ML-KEM-1024 byte-size + roundtrip + wrong-key rejection (`mlkem.rs`)
- SMP prime byte-equality (`crypto-bigint` vs `num-bigint` representations)
- Constant-time `mod_exp` small KAT + full-width cross-check against a reference
- Hybrid PQC SMP: classical roundtrip, hybrid roundtrip, mismatched secrets in
  both modes, version-mismatch rejection, ML-DSA-87 context sign/verify, wrong-
  context rejection, ML-KEM-1024 encaps/decaps roundtrip, `pq_binding_key`
  determinism

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
