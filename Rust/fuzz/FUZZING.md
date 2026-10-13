# Fuzzing the OTRv4Plus Rust core

cargo-fuzz (libFuzzer) harnesses for every place the core parses input it did
not produce. Added by the 2026-09 cryptographic audit (CRYPTO_AUDIT_2026-09.md).

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
cd Rust
cargo +nightly fuzz build
cargo +nightly fuzz run <target> -- -max_total_time=300
# replay one input (a crash, or a corpus file):
cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<file>
```

`corpus/`, `artifacts/` and `target/` are git-ignored. A crash found here gets
fixed in `src/`, and the input becomes a named `#[test]` beside the fix. The
crash input is not committed as a file.

| Target | Input | Invariant beyond "no panic" |
|---|---|---|
| `ratchet_header` | `RatchetHeader::decode` | accepted bytes re-encode identically |
| `ratchet_forgery` | forged header/ct/nonce/tag to `decrypt_same_dh` and `decrypt_new_dh` | a forgery never decrypts, and the genuine messages sent afterwards still do (commit-after-auth) |
| `dake1_parse` | `DakeState::process_dake1` (unauthenticated) | -- |
| `dake2_parse` | `process_dake2` after a real DAKE1 | an arbitrary DAKE2 never establishes |
| `dake3_verify` | `verify_dake3` against a recorded genuine handshake, input XOR-mutating the real DAKE3 | nothing but the recorded DAKE3 verifies |
| `ring_verify` | `ring_verify_bytes` / `ring_sign_bytes` on arbitrary keys | a bit-flipped honest signature never verifies |
| `smp_messages` | SMP1..SMP4 from the network, at each step of a real run, classical (0x01) and hybrid (0x03) | a fuzzed message never yields "verified" |
| `container_header` | `.otrv` `info` / `open_bytes` on arbitrary files | never opens without the key |

## Notes

- `smp_messages` sets the secret with `SmpState::fuzz_set_secret_scalar`,
  which only exists under `cfg(fuzzing)`. Argon2id at 64 MiB per run would
  otherwise hold the fuzzer to a few runs a second. Everything after the
  secret is the production path. The target is still slow, because every run
  does 3072-bit modular exponentiations and, for 0x03, ML-KEM/ML-DSA key
  generation. Give it long runs (hours, not minutes).
- `ring_verify` signs once per run and is slow for the same reason.
- The release profile has `overflow-checks = true` and `panic = "abort"`, so
  any arithmetic overflow the fuzzer finds is a process kill in the shipped
  build, not only in debug. `container_header` found one on its first run
  (SECURITY_ISSUES A3).
