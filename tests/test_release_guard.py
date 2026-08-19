#!/usr/bin/env python3
"""
Release-boundary assertions for the shipped otrv4_core artifact.

Two independent controls guard the `test-only-kdf` feature, one on each side of
the build:

  1. Rust/build.rs refuses to build with the feature unless
     OTRV4PLUS_ALLOW_TEST_GATES=1 is set explicitly.  That stops the artifact
     from being produced.
  2. This module asserts that the artifact actually *installed* exposes no gated
     API.  That stops a gate-open wheel from being mistaken for a release one --
     it catches the case where a wheel was built elsewhere, or an old gate-open
     wheel is still sitting in site-packages.

Fail-closed by design: with no environment variable set, these tests demand a
clean production artifact.  A developer running against the internals-test wheel
must say so with OTRV4PLUS_ALLOW_TEST_GATES=1, which flips the assertions to
confirm the wheel really is the test build.

CI wiring: run this module with the variable UNSET against the release wheel.
It is the assertion that the release pipeline fails closed on.
"""

import os
import pytest

otrv4_core = pytest.importorskip("otrv4_core")


# Every Python-reachable name that `test-only-kdf` adds.
#
# Measured, not assumed: kdf.rs::kdf_1_py and header.rs::encode_header_py are
# also behind the feature, but lib.rs never registers them with the module, so
# they are unreachable from Python even when the feature is on.  The reachable
# surface is the two PySMPVault methods, which #[pymethods] registers
# automatically.
GATED_VAULT_METHODS = ("load", "load_by_handle")
GATED_MODULE_FUNCTIONS = ("kdf_1", "encode_header", "rust_kdf_1", "rust_encode_header")

_TEST_BUILD_EXPECTED = os.environ.get("OTRV4PLUS_ALLOW_TEST_GATES") == "1"

_WHY = (
    "RustSMPVault.load/load_by_handle read stored SMP secrets back out to "
    "Python. A distributable artifact must not expose them. If this wheel was "
    "built deliberately for the internals tests, run with "
    "OTRV4PLUS_ALLOW_TEST_GATES=1; otherwise rebuild without --features "
    "test-only-kdf."
)


def _exposed_vault_methods():
    return [m for m in GATED_VAULT_METHODS if hasattr(otrv4_core.RustSMPVault, m)]


def _exposed_module_functions():
    """Native (PyO3) gated functions only.

    tests/conftest.py monkey-patches pure-Python stand-ins for `kdf_1`,
    `rust_kdf_1` and `rust_encode_header` onto the module so some older tests
    can run.  Those are Python `function` objects and are irrelevant to what the
    compiled artifact exposes; a real PyO3 entry point is a
    `builtin_function_or_method`.  Counting the shims would fail this assertion
    on a perfectly clean release wheel.
    """
    exposed = []
    for name in GATED_MODULE_FUNCTIONS:
        obj = getattr(otrv4_core, name, None)
        if obj is None:
            continue
        if type(obj).__name__ == "builtin_function_or_method":
            exposed.append(name)
    return exposed


@pytest.mark.skipif(_TEST_BUILD_EXPECTED,
                    reason="OTRV4PLUS_ALLOW_TEST_GATES=1: this is the internals-test wheel")
def test_production_artifact_exposes_no_vault_readback():
    """A release artifact must not let Python read the SMP vault back."""
    exposed = _exposed_vault_methods()
    assert not exposed, f"RustSMPVault exposes {exposed} -- {_WHY}"


@pytest.mark.skipif(_TEST_BUILD_EXPECTED,
                    reason="OTRV4PLUS_ALLOW_TEST_GATES=1: this is the internals-test wheel")
def test_production_artifact_exposes_no_raw_kdf():
    """A release artifact must not expose the raw KDF / header encoder."""
    exposed = _exposed_module_functions()
    assert not exposed, (
        f"otrv4_core exposes {exposed}; these are test-only entry points into "
        f"crate internals and must not ship."
    )


@pytest.mark.skipif(not _TEST_BUILD_EXPECTED,
                    reason="production build: nothing to confirm")
def test_optin_build_really_is_the_test_build():
    """With the opt-in set, confirm the feature actually took effect.

    Guards against a false sense of coverage: if the variable is exported but the
    wheel was in fact built without the feature, the internals tests would skip
    silently and nobody would notice they had stopped running.
    """
    exposed = _exposed_vault_methods()
    assert exposed == list(GATED_VAULT_METHODS), (
        f"OTRV4PLUS_ALLOW_TEST_GATES=1 but RustSMPVault exposes {exposed}; "
        f"expected {list(GATED_VAULT_METHODS)}. The installed wheel is NOT the "
        f"test build -- rebuild it with --features test-only-kdf."
    )


def test_gated_surface_is_fully_enumerated():
    """The lists above must stay in step with the Rust source.

    If someone adds a new `#[cfg(feature = "test-only-kdf")]` PyO3 entry point,
    this test tells them to add it here too -- otherwise the release assertion
    silently stops covering the new hole.
    """
    import pathlib
    src = pathlib.Path(__file__).resolve().parent.parent / "Rust" / "src"
    if not src.is_dir():
        pytest.skip("Rust sources not present next to the tests")

    gated_names = set()
    for path in src.glob("*.rs"):
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        for i, line in enumerate(lines):
            if 'cfg(feature = "test-only-kdf")' not in line:
                continue
            # Look ahead for the PyO3 name this gate applies to.
            for follow in lines[i + 1:i + 8]:
                stripped = follow.strip()
                if stripped.startswith('#[pyo3(name = "'):
                    gated_names.add(stripped.split('"')[1])
                    break
                if stripped.startswith("fn ") or stripped.startswith("pub fn "):
                    gated_names.add(stripped.split("fn ", 1)[1].split("(")[0].split("<")[0].strip())
                    break

    known = set(GATED_VAULT_METHODS) | set(GATED_MODULE_FUNCTIONS)
    unknown = gated_names - known
    assert not unknown, (
        f"Rust gates PyO3 entry points this test does not know about: "
        f"{sorted(unknown)}. Add them to GATED_VAULT_METHODS or "
        f"GATED_MODULE_FUNCTIONS so the release assertion covers them."
    )
