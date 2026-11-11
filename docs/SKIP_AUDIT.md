<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright (C) 2025-2026 muc111 -->

# Skipped tests, and where each property is actually tested

Revised 2026-11-11. The suite had 48 skips on the test wheel. The question
asked of each was the one the first version of this audit asked:

> For the security property this skipped test represents, where is that
> property tested, and does that test actually run?

The second half is new. The first version answered "complementary" for 39 of
them, naming a counterpart that runs when they skip. That was true of the
counterparts and false of the tests themselves: no CI job ever built a wheel
the skipped half could run on, so it ran nowhere. And the file that checks the
pairing, `tests/test_gated_build_is_uniform.py`, failed the first time it was
run against either wheel it was written about (see 3).

## Result

| | Before | Now |
|---|---|---|
| Skips on the test wheel | 48 | 7 |
| Tests that ran on no wheel in CI | 47 | 0 |

The 7 that remain skip on the test wheel by design and run on another wheel
in the same CI job (`.github/workflows/python.yml`):

| Wheel | Built with | Runs |
|---|---|---|
| test | `raw-key-test-api` | the whole suite |
| release | the APK's features only | `test_release_guard`, `test_gated_build_is_uniform`, live-path smoke tests |
| gates-open | `raw-key-test-api`, `test-only-kdf`, `legacy-dake-keys` | the gated internals tests and the opt-in guards |

## What was done, group by group

### 1. `seed injection is gated out of production builds (decision B1)` — 36: now run

`tests/test_android_identity.py`. Its identity key store was a Python double
that rebuilt handles from a Python-held seed through
`Ed448KeyHandle.from_seed_bytes`, which decision B1 compiled out of every
build but a test-only-kdf one. It now uses the production key store,
`RustSealedIdentityKeyStore`, so the seed never becomes a Python object in the
test either, and all 36 run on the test wheel. The Python-seed double is
deleted. One test changed what it checks: "the seed never appears in the
sealed record" became "the inner, Rust-sealed record never appears in the
outer one", because the seed is no longer visible to look for
(`test_rust_identity_sealing` test 3 asserts that it cannot be read at all).

### 2. `this interpreter parses PEP 701 f-strings` — 2: now run

`tests/test_android_failure_report.py` produced its `SyntaxError` by compiling
a PEP 701 f-string, which 3.12+ parses, so the tests never ran on the suite's
interpreter. The exception is now built directly, with the message and
position Python 3.11 gives (measured with python3.11).

### 3. `core built without test-only-kdf` — 3, and `production build: nothing to confirm` — 3: run on the gates-open wheel

`test_rust_security.py` (1) and `test_harness_audit.py` (2) read the SMP
vault back, which only a test-only-kdf build allows; `test_release_guard.py`'s
three opt-in guards confirm such a build really opened its gates. They still
skip on the test wheel and now run on the gates-open wheel.

Running them there for the first time found a broken invariant check:
`test_gated_build_is_uniform` reported a "MIXED build". Its registry listed
four module functions as compiled in by `test-only-kdf`; in fact `kdf_1` and
`encode_header` were gated `#[pyfunction]`s that `lib.rs` never registered,
and `rust_kdf_1` / `rust_encode_header` exist only as conftest shims. The two
dead Rust functions were deleted, the registry corrected, and a new test holds
every build, test or release, to exporting none of the four natively.

Running it on the release wheel for the first time found a second error: it
required `create_sealed_identity`, which is raw-key-test-only. It now requires
the production pair, `create_sealed_identity_under` / `unseal_identity_under`.

### 4. `this is the test wheel` — 1: runs on the release wheel

`test_release_guard.test_production_artifact_exposes_no_raw_key_entry_point`.
Unchanged; it already ran in the release-wheel step.

### 5. `handle_line is not in this build` — 1: replaced

`tests/test_irc_guided_smp.py` checks that no inbound path reaches the
passphrase prompt (INV-06), over a list of entry points. `handle_line` is a
desktop-bridge method the IRC source does not contain, so that case skipped
and checked nothing. It is replaced by the IRC client's real inbound entry
points (`handle_message`, `_on_chat`, `process_incoming_otr_message`,
`process_otr_payload`, `process_smp_message`), all of which pass, and a name
missing from the source now fails instead of skipping.

### 6. `downloads from PyPI; set OTR_NETWORK_TESTS=1` — 1: now run, offline

`tests/test_apk_python_hashes.py`: pip under `--require-hashes` refuses a
file whose hash is not the lock's. It now gives pip a local wheel
(`--no-index --find-links`), which pip hash-checks the same way, plus a
control run with the right hash that must succeed.

### 7. `AAudio not present on this host` — 1: now runs

`tests/test_android_audio_path.py`. `_pick_order` honours an explicit AAudio
choice whatever is loadable, so the assertion holds on every host and the skip
guarded nothing. A new test checks the automatic order with only the loader's
answer substituted: AAudio first where it loads, never tried where it does
not. Opening a real AAudio stream is still a handset check (item 10 of the
handset gate in `ANDROID_XMPP_MILESTONE.md` section 7).

## Standing rule

A skip is acceptable only when the property runs on another wheel in CI, and
the wheel that runs it is named in the skip reason or in the test's comments.
"Covered elsewhere" is a claim to check by running the elsewhere.
