# Contributing to OTRv4+

Thank you for your interest. This project aims to provide a practical, post-quantum OTR implementation. All contributions — code, documentation, bug reports, and cryptanalysis — are welcome.

## Code of Conduct

Be respectful, constructive, and assume good faith. We follow the [Contributor Covenant](https://www.contributor-covenant.org/).

## Reporting bugs

- Check existing [issues](https://github.com/muc111/OTRv4Plus/issues) first
- Include: OTRv4+ version, Python version (`python --version`), OpenSSL version (`openssl version`), Rust version (`rustc --version`), operating system, and steps to reproduce
- For **security vulnerabilities**, **do not open a public issue** — use GitHub's private security advisory

## Suggesting enhancements

Open an issue with the label `enhancement`. Explain the use case and why it fits the project's scope (post-quantum OTR for IRC).

## Pull requests

1. Fork the repo and create a branch from `main`
2. Run the test suite before committing: `pytest -v -k "not 300k"` (full suite takes ~8 hours)
3. Follow existing code style:
   - Python: PEP 8, ~12,000 line single file (do not split without discussion)
   - Rust: `cargo fmt` + `cargo clippy -- -D warnings` must pass
   - C: Linux kernel style (tabs for indentation, 80-column limit)
4. One logical change per PR
5. Sign off your commits: `git commit -s`
6. Open a PR against `main` and wait for review

## Adding new features

Open an issue first to discuss. The single-file Python design is intentional — new features should be integrated there unless they require a C extension (e.g., new PQ primitive) or Rust crate (e.g., new secret type).

## Rust migration work

Rust migration contributions are especially welcome. See `ROADMAP.md` for planned phases:

- **Phase 3** — DAKE DH key derivation in Rust (currently Python `bytes` during KDF)
- **Phase 4** — Ed448/X448 long-term keys in Rust `SecretVec`
- **Phase 5** — `mlock` hardening, panic zeroization, formal boundary audit

When moving crypto logic to Rust, keep the public PyO3 API identical so all Python tests continue to pass. The pattern established in v10.5.10 (SMP migration) is the reference:

- Python passes opaque handles and wire bytes only
- All secrets are `SecretVec` or `SecretBytes<N>` with `ZeroizeOnDrop`
- No secret value crosses the PyO3 boundary outbound
- `set_*_from_vault()` patterns keep secrets in Rust throughout

## Testing

- Add tests for new functionality in `test_*.py`
- For Rust changes, add unit tests directly in `src/*.rs`
- For wire formats, add fuzzing cases in `fuzz_harnesses.py`
- Ensure no regressions: `pytest test_*.py && cd Rust && cargo test --release`

## Documentation

Update README.md, FEATURES.md, SECURITY.md, or DEVELOPMENT.md as appropriate. Keep technical language precise. The timing figures in README.md (DAKE: ~2m 44s, SMP: ~2m, total: ~6m 37s over I2P) come from real session logs and should be updated if significantly different results are observed on new hardware.

Thank you for helping make OTRv4+ better.
