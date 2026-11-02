<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial -->
<!-- Copyright (C) 2025-2026 muc111 -->
# The Python test suite — how to run it green

The authoritative configuration is **`.github/workflows/python.yml`**. That is
the one CI runs and the one a green tick means. Run it any other way and a
handful of *guard* tests will look red even though nothing is wrong — that trap
is the whole reason this file exists, so read the last section before you
report a failure.

## The configuration CI runs (and you should)

The suite imports the compiled Rust core (`otrv4_core`). Which **wheel** is
installed, and which **environment variables** are set, together decide the
result. CI does exactly this, in order:

1. **Build the test wheel** (from `Rust/`):

   ```sh
   OTRV4PLUS_ALLOW_RAW_KEY_TEST_API=1 maturin build --release \
     --features pyo3/extension-module,android-opus,mls,raw-key-test-api \
     --interpreter python3.12 --out dist
   pip install dist/*.whl
   ```

   Note the feature set: `raw-key-test-api` **yes** (known-answer and
   fixed-key tests need those entry points), `test-only-kdf` **no** (that one
   opens vault read-back / seed injection, which the release guards must see
   absent). `android-opus` is on so the APK's codec path is exercised here too.

2. **Run the whole suite** with the raw-key gate allowed and `TEST_GATES`
   **unset**:

   ```sh
   OTRV4PLUS_ALLOW_RAW_KEY_TEST_API=1 python -m pytest tests/ -q
   ```

3. **Re-check the shipping artifact.** Build the *release* wheel — the exact
   features the APK ships, **no** test gates — reinstall it, and re-run only
   the guard subset against it:

   ```sh
   maturin build --release \
     --features pyo3/extension-module,android-opus,mls \
     --interpreter python3.12 --out dist-release
   pip install --force-reinstall --no-deps dist-release/*.whl
   python -m pytest -q tests/test_release_guard.py \
     tests/test_dake3_rust_authority.py tests/test_android_diagnostics.py
   ```

Step 2 proves every protocol/transport/UI rule against a wheel whose test-only
constructors exist; step 3 proves the wheel that actually ships exposes none of
them. Both pass. There is **no intentionally-red set** in this configuration.

## The guard tests are environment-sensitive — this is by design

A small set of tests assert facts about the *installed artifact* rather than
about the protocol:

- `test_release_guard.py`
- `test_gated_build_is_uniform.py`
- `test_rust_identity_sealing.py` (the seed-accessor / seed-injection cases)
- `test_pyo3_boundary.py` (the long-term key handles expose only public material)
- `test_rust_owns_secrets.py::...::test_an_x448_handle_cannot_agree_in_python`

They read `OTRV4PLUS_ALLOW_TEST_GATES` to know what artifact to expect:

| Installed wheel | `OTRV4PLUS_ALLOW_TEST_GATES` | Guards |
|---|---|---|
| release (no gate features) | unset | **pass** — demand a clean artifact |
| test wheel (`raw-key-test-api`) | unset | **pass** — raw-key handles are a reviewed, documented set; the vault/seed gates (`test-only-kdf`) are still absent |
| test wheel **with `test-only-kdf`** | unset | **fail** — a gate-open wheel is being judged as if it were the release one |
| any gated wheel | `=1` | **pass** — assertions flip to confirm it really is the test build |

So the way to make the guards "fail" is to install a `test-only-kdf` wheel and
then run pytest with `OTRV4PLUS_ALLOW_TEST_GATES` unset (or to install the
release wheel and run the *feature* tests that need `raw-key-test-api`). That
is the guard doing its job — a gate-open wheel must not be mistaken for a
shippable one — not a bug in the suite. Match the wheel to the environment as
in the table and the whole suite is green.

## Rust

```sh
cd Rust      && cargo test --release --features mls
cd Rust/mls  && cargo test --release --features reference-interop
# the lint gate the build enforces (both crates):
cargo clippy --all-targets --all-features -- -D warnings
#   (needs OTRV4PLUS_ALLOW_TEST_GATES=1 OTRV4PLUS_ALLOW_RAW_KEY_TEST_API=1
#    OTRV4PLUS_ALLOW_LEGACY_DAKE_KEYS=1, because --all-features turns the
#    gated features on and their build.rs refuses to build without them)
```
