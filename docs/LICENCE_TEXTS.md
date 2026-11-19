<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright (C) 2025-2026 muc111 -->

# Licence texts

The full text of every licence named in this repository, one file per
identifier, following the [REUSE](https://reuse.software) convention. The
tree passes `reuse lint`, and CI holds it there
(`tests/test_reuse_layout.py`).

## `LICENSES/`: what this repository's own files are under

| File | Used for |
|---|---|
| `AGPL-3.0-only.txt` | The software licence. The SPDX text, unchanged. |
| `LicenseRef-OTRv4Plus-Commercial.txt` | The commercial alternative. A verbatim copy of `LICENSE-COMMERCIAL.md`, which stays the authoritative one; a test fails if they differ. |
| `CC-BY-SA-4.0.txt` | This project's documentation (see `LICENSING.md`) |
| `Apache-2.0.txt`, `MIT.txt` | Vendored code that keeps its authors' licence (`Rust/vendor/`) |
| `LicenseRef-OTRv4Plus-Legal.txt` | The legal instruments: reproduce verbatim, do not modify |
| `LicenseRef-OTRv4Plus-NoLicense.txt` | The placeholder artwork, for which nothing is asserted (`docs/ASSETS.md`) |
| `LicenseRef-OTRv4Plus-ThirdParty.txt` | Everything under `third_party/`, which is under its authors' terms |

`LICENSE` at the root is still what a reader meets first: a short statement
of the dual licence followed by the AGPL text.

## `third_party/licences/`: texts only bundled components use

`BSD-2-Clause.txt`, `BSD-3-Clause.txt`, `BSL-1.0.txt`, `PSF-2.0.txt`,
`Unicode-3.0.txt`. No file in this repository is under them, so REUSE would
report them as unused in `LICENSES/`; they are here because `NOTICE`
reproduces them for components the builds bundle (see `NOTICE` and
`docs/LICENSING_AUDIT.md`).

## Where they come from

The SPDX texts were taken from the SPDX License List (the npm package
`spdx-license-list` 6.12.0, `spdx-full.json`; `AGPL-3.0-only.txt` by
`reuse download`). `tools/generate_notice.py` reads both directories, in that
order, so the NOTICE shipped in the APK carries the same texts wherever it is
generated.
