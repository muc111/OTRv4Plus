# Contributing to OTRv4+

Thank you for your interest! This project aims to provide a practical, post‑quantum OTR implementation. All contributions – code, documentation, bug reports, and cryptanalysis – are welcome.

## Code of Conduct

Be respectful, constructive, and assume good faith. We follow the [Contributor Covenant](https://www.contributor-covenant.org/).

## Reporting bugs

- Check existing [issues](https://github.com/muc111/OTRv4Plus/issues) first.
- Include: OTRv4+ version, Python version (`python --version`), OpenSSL version (`openssl version`), operating system, and steps to reproduce.
- For **security vulnerabilities**, **do not open a public issue** – use GitHub’s private security advisory.

## Suggesting enhancements

Open an issue with the label `enhancement`. Explain the use case and why it fits the project’s scope (post‑quantum OTR for IRC).

## Pull requests

1. Fork the repo and create a branch from `main`.
2. Run the test suite before committing: `pytest -v -k "not 300k"` (full suite takes ~8 hours).
3. Follow existing code style:
   - Python: PEP 8, ~12,000 line single file (do not split without discussion).
   - C: Linux kernel style (tabs for indentation, 80‑column limit).
4. One logical change per PR.
5. Sign off your commits: `git commit -s` (certifies you have the right to contribute).
6. Open a PR against `main` and wait for review.

## Adding new features

Open an issue first to discuss. The single‑file Python design is intentional – new features should be integrated there unless they require a C extension (e.g., new PQ primitive).

Rust migration work is especially welcome – see `ROADMAP.md` for the planned phases. When moving crypto logic to Rust, keep the public PyO3 API identical so Python tests continue to pass.

## Testing

- Add tests for new functionality in `test_*.py`.
- For wire formats, add fuzzing cases in `fuzz_harnesses.py`.
- Ensure no regressions: `pytest test_*.py`.

## Documentation

Update the README, FEATURES.md, or DEVELOPMENT.md as needed. Keep technical language precise and jargon explained.

Thank you for helping make OTRv4+ better!
