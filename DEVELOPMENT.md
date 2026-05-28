# DEVELOPMENT.md — patches for v10.7.5

This file documents the targeted edits to be made to the existing `DEVELOPMENT.md` for the 5.3i + 5.3k + 10.7.5 doc pass.  Apply by hand or with the sed snippets below; do **not** wholesale-replace the file (it contains a long project history that should be preserved).

---

## Edit 1 — replace the "Phase 2 — Python + C extensions" subsection

This subsection (around lines 30–60 in the live file) currently describes the three C extensions and the lib-OpenSSL build path as if they were current.  Replace it with the historical-tense version below.

**Find:**

```
### Phase 2 — Python + C extensions (months 5–12)

Performance and side-channel security forced a move to C for all secret-dependent arithmetic. Three C extensions were written and integrated:

#### otr4_crypto_ext.c
[...rest of the existing subsection through the end of the "#### IRC client maturation" block...]
```

**Replace with:**

```
### Phase 2 — Python + C extensions (months 5–12, retired by v10.7.5)

Performance and side-channel security forced a move to C for all secret-dependent arithmetic.  Three C extensions were written and integrated.  All three have since been retired in favour of pure-Rust equivalents (Phases 5.3i, 5.3j, 5.3k, completed at v10.7.4); they are documented here for historical context only.

#### otr4_crypto_ext.c (retired v10.7.4, Phase 5.3i-C / 5.3k)

- Constant-time modular exponentiation via `BN_mod_exp_mont_consttime` (OpenSSL) — superseded by `num-bigint` in `src/smp.rs`.
- Modular inverse via `BN_mod_inverse` — superseded.
- Cryptographically random integers in range via `BN_rand_range` — superseded.
- ML-KEM-1024 key generation, encapsulation, decapsulation via liboqs — replaced at v10.7.3 by `pqcrypto-mlkem 0.1.1` (FIPS 203) in `src/mlkem.rs`.
- Ed448 Schnorr ring signatures (OR-proof) — replaced earlier by the pure-Rust ring signature in `src/ring_sig.rs`.
- Memory hardening: `OPENSSL_cleanse`, `mlock()`, `prctl(PR_SET_DUMPABLE, 0)` — replaced at v10.7.2 by `ctypes.memset` and at v10.7.1 by `resource.setrlimit(RLIMIT_CORE, (0, 0))`.

#### otr4_ed448_ct.c (retired v10.7.4, Phase 5.3k)

Constant-time Edwards-448 point arithmetic — scalar multiplication (`gep_scalarmult`) with full Montgomery ladder, cofactor clearing, and point serialisation.  A critical timing side-channel was found and fixed in `gep_scalarmult` during security review.  This extension was imported defensively as a ground-truth Ed448 implementation but, by the time 5.3k landed, a grep for `_ed448_ct.` member access in `otrv4+.py` returned empty — every Ed448 operation already ran in the Rust core (`ed448-goldilocks-plus 0.16`), so the import was simply deleted.

#### otr4_mldsa_ext.c (retired v10.6.18, Phase 5.3j)

ML-DSA-87 signatures via OpenSSL 3.5+ EVP provider, used for post-quantum authentication layered on top of the classical Ed448 DAKE.  Replaced by `pqcrypto-mldsa 0.1.2` in `src/mldsa.rs`.  The `.c` and `.so` files were left orphaned in the repo until 5.3k cleaned them up.

#### IRC client maturation

- Full tabbed terminal UI: coloured nicks, security icons, unread badges, pager.
- IRCv3 support: SASL PLAIN, TLS, PING watchdog, auto-reconnect, auto-join.
- WHOIS, NickServ identification, 27 Club username generator.
```

---

## Edit 2 — remove the C-extension build commands

Around line 153 the file currently contains:

```
# Debian/Ubuntu
sudo apt install libssl-dev python3-dev build-essential

# Build all extensions
python setup_otr4.py build_ext --inplace
bash build_ed448.sh
```

Replace with:

```
# Debian/Ubuntu (only needed if building Rust toolchain from source — the
# Rust core itself uses no system libraries and needs no apt packages
# beyond the Rust compiler).
sudo apt install build-essential
```

The `python setup_otr4.py build_ext --inplace` and `bash build_ed448.sh` lines are removed entirely.  `setup_otr4.py` was deleted at v10.7.4.  If `build_ed448.sh` is still present in your tree, it is also a relic of the C-extension era and can be removed.

---

## Edit 3 — confirm the "Rust core (required)" subsection is the only build path

Whatever subsection follows the apt block should now describe the Rust build as the **only** build step.  Suggested wording for the lead paragraph:

```
### Rust core (required, and the only build step)

OTRv4+ is Rust-core-only since v10.7.5.  There are no C extensions to compile.  The Rust build produces a single shared library (`libotrv4_core.so`, copied to the project root as `otrv4_core.so`) which `otrv4+.py` imports as a PyO3 module.

cd Rust
cargo build --release --no-default-features --features pq-rust
cp target/release/libotrv4_core.so ../otrv4_core.so

The `--no-default-features --features pq-rust` flag set is required: see the Termux/aarch64 notes elsewhere in this document for why the default AVX2/NEON-optimised paths of `pqcrypto-mlkem` / `pqcrypto-mldsa` are disabled on this platform.
```
