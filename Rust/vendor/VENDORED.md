# Vendored crates (OpenMLS), and what was changed

OpenMLS lists its ciphersuites, HPKE KEMs and signature schemes as closed
enums, so a suite that is not in them cannot be used at all. The owner chose
to patch rather than to put the hybrid inside an existing code point, which
would have made the wire claim an algorithm it does not use (decision C1,
`MLS_SECURITY_HARDENING.md` §2 and §7).

| crate | version | licence | why | used in |
|---|---|---|---|---|
| `openmls_traits` | 0.6.0 | MIT, © OpenMLS Authors | adds the three private code points below | the shipped core |
| `openmls_rust_crypto` | 0.6.0 | MIT, © OpenMLS Authors | one exhaustive `match` taught the new KEM | tests only (reference provider) |

Both are wired in with `[patch.crates-io]` in `Rust/Cargo.toml` and
`Rust/mls/Cargo.toml`. `openmls` itself is NOT patched: the new suite is
declared in each leaf's capabilities instead (`Rust/mls/src/client.rs`).

## The changes, all of them

`patches/` holds the exact diff against the crates.io release of each.

- `SignatureScheme::ED448_MLDSA87 = 0xFEA1` (TLS private-use range
  0xFE00-0xFFFF): Ed448 + ML-DSA-87 composite, both must verify.
- `HpkeKemType::X448MlKem1024 = 0xF0A1`: X448 + ML-KEM-1024 with a binding
  combiner. HPKE has no private-use range; the value is unassigned.
- `Ciphersuite::MLS_256_X448MLKEM1024_AES256GCM_SHA384_ED448MLDSA87 =
  0xF0A1` (MLS private-use range 0xF000-0xFFFF, RFC 9420 §17.1), mapped to
  SHA-384, AES-256-GCM, HKDF-SHA384 and the two above.
- In `openmls_rust_crypto`: the new KEM maps to `unreachable!`, which its
  `supports()` makes unreachable (it refuses the suite first).

No cryptography is implemented in the vendored crates; the hybrid KEM and
the composite signature are `Rust/mls/src/hpke.rs` and
`Rust/mls/src/provider.rs`, on the primitives the core already uses.

## Updating

Copy the new release over the directory, re-apply the diff in `patches/`,
remove `README.md`, `CHANGELOG.md`, `.cargo_vcs_info.json`, `.cargo-ok` and
`Cargo.lock`, and run `cargo test --release` in `Rust/mls`.

The code points are private: no other MLS client understands this suite,
and this one refuses any other suite for new groups.
