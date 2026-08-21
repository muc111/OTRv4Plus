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

# M3 (decision 2): the legacy DAKE surface that returns session key material to
# Python as PyBytes. Behind the `legacy-dake-keys` Cargo feature, OFF by
# default, so a production artifact does not contain them at all.
GATED_DAKE_METHODS = ("generate_dake2", "process_dake2", "get_session_keys")

# Decision B1: seed injection. Behind `test-only-kdf` -- production creates
# identities in Rust and persists them with the sealing API, so nothing on the
# live path needs to hand Rust a seed.
GATED_KEY_INJECTION = {
    "Ed448KeyHandle": ("from_seed_bytes",),
    "X448KeyHandle": ("from_priv_bytes",),
}
GATED_MODULE_FUNCTIONS = ("kdf_1", "encode_header", "rust_kdf_1", "rust_encode_header")

_TEST_BUILD_EXPECTED = os.environ.get("OTRV4PLUS_ALLOW_TEST_GATES") == "1"

_WHY = (
    "RustSMPVault.load/load_by_handle read stored SMP secrets back out to "
    "Python. A distributable artifact must not expose them. If this wheel was "
    "built deliberately for the internals tests, run with "
    "OTRV4PLUS_ALLOW_TEST_GATES=1; otherwise rebuild without --features "
    "test-only-kdf."
)


def _exposed_dake_methods():
    return [m for m in GATED_DAKE_METHODS if hasattr(otrv4_core.RustDAKE, m)]


def _exposed_key_injection():
    exposed = []
    for cls_name, methods in GATED_KEY_INJECTION.items():
        cls = getattr(otrv4_core, cls_name, None)
        if cls is None:
            continue
        exposed += [f"{cls_name}.{m}" for m in methods if hasattr(cls, m)]
    return exposed


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


# ── No development credential in shippable sources ────────────────────────────

# The Phase 2/3 spec is explicit: "1337" is a development unlock sequence, and
# the production build must contain no such credential. It must never appear in
# Kotlin/Python/Rust production source, resources, assets, or the manifest.
#
# This runs now, before the unlock UI exists, so the rule is enforced from the
# first commit that could break it rather than being retrofitted after Phase 3.

_DEV_CREDENTIALS = ("1337",)

_SHIPPABLE_SUFFIXES = (".py", ".kt", ".java", ".xml", ".pro", ".kts", ".rs", ".toml")

# Directories that never reach a device.
_EXCLUDED_PARTS = {
    "tests", ".attic", "target", "build", "__pycache__", ".git",
    "androidTest", "test",
}


def _shippable_sources():
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix not in _SHIPPABLE_SUFFIXES:
            continue
        if _EXCLUDED_PARTS & set(path.relative_to(root).parts):
            continue
        yield path, root


def test_no_development_credential_in_shippable_sources():
    """No development unlock credential may sit in anything that ships."""
    offenders = []
    for path, root in _shippable_sources():
        try:
            body = path.read_text(encoding="utf-8", errors="strict")
        except (UnicodeDecodeError, OSError):
            continue
        for credential in _DEV_CREDENTIALS:
            for lineno, line in enumerate(body.splitlines(), start=1):
                if credential not in line:
                    continue
                stripped = line.strip()
                # A prose mention explaining the rule is not a credential.
                if stripped.startswith(("#", "//", "*", "<!--")):
                    continue
                offenders.append(f"{path.relative_to(root)}:{lineno}: {stripped[:80]}")
    assert not offenders, (
        "development credential found in shippable source:\n  " + "\n  ".join(offenders)
    )


def test_android_resources_carry_no_secret_looking_values():
    """strings.xml and friends are APK-readable; nothing secret may live there."""
    import pathlib, re
    root = pathlib.Path(__file__).resolve().parent.parent / "android"
    if not root.is_dir():
        pytest.skip("android project not present")

    banned_names = re.compile(
        r'name\s*=\s*"[^"]*(secret|passw|credential|seed|key|token|pin)[^"]*"',
        re.IGNORECASE)
    long_hex = re.compile(r"\b[0-9a-fA-F]{32,}\b")

    for path in root.rglob("*.xml"):
        body = path.read_text(encoding="utf-8", errors="replace")
        assert not banned_names.search(body), f"{path} declares a secret-looking resource"
        assert not long_hex.search(body), f"{path} contains a long hex literal"


# ── M3: the legacy DAKE session-key surface (decision 2) ──────────────────────

_LEGACY_DAKE_EXPECTED = os.environ.get("OTRV4PLUS_ALLOW_LEGACY_DAKE_KEYS") == "1"

_M3_WHY = (
    "These hand root/chain/brace/MAC key material to Python as PyBytes. The "
    "live path uses generate_dake2_output / process_dake2_output, which move "
    "the keys Rust-to-Rust into the ratchet through an opaque DakeOutput. "
    "Rebuild without --features legacy-dake-keys."
)


@pytest.mark.skipif(_LEGACY_DAKE_EXPECTED,
                    reason="OTRV4PLUS_ALLOW_LEGACY_DAKE_KEYS=1: legacy build")
def test_production_artifact_exposes_no_legacy_dake_session_keys():
    """A release artifact must not expose the legacy DAKE session-key APIs.

    This is the release CI assertion decision 2 requires: run it with the
    variable UNSET against the release wheel.
    """
    exposed = _exposed_dake_methods()
    assert not exposed, f"RustDAKE exposes {exposed} -- {_M3_WHY}"


@pytest.mark.skipif(_LEGACY_DAKE_EXPECTED,
                    reason="OTRV4PLUS_ALLOW_LEGACY_DAKE_KEYS=1: legacy build")
def test_production_dakeresult_exposes_no_secret_getters():
    """The Dakeresult secret getters must be compiled out, not just unused."""
    result = getattr(otrv4_core, "Dakeresult", None)
    if result is None:
        pytest.skip("Dakeresult is not exported")
    leaked = [g for g in ("root_key", "chain_key_a", "chain_key_b",
                          "brace_key", "mac_key") if hasattr(result, g)]
    assert not leaked, f"Dakeresult exposes secret getters {leaked} -- {_M3_WHY}"


@pytest.mark.skipif(not _LEGACY_DAKE_EXPECTED,
                    reason="production build: nothing to confirm")
def test_optin_legacy_build_really_is_the_legacy_build():
    """Guard against a false opt-in silently skipping the M3 assertions."""
    assert _exposed_dake_methods() == list(GATED_DAKE_METHODS), (
        "OTRV4PLUS_ALLOW_LEGACY_DAKE_KEYS=1 but the legacy surface is absent; "
        "the installed wheel is not the legacy build"
    )


# ── B1: seed injection must be absent from production ────────────────────────

@pytest.mark.skipif(_TEST_BUILD_EXPECTED,
                    reason="OTRV4PLUS_ALLOW_TEST_GATES=1: internals-test wheel")
def test_production_artifact_exposes_no_seed_injection():
    """Python must not be able to supply a chosen identity seed (decision B1)."""
    exposed = _exposed_key_injection()
    assert not exposed, (
        f"{exposed} are Python-visible. Option B keeps the seed inside Rust; "
        f"production creates identities with generate_ed448_keypair and "
        f"persists them with create_sealed_identity."
    )


def test_identity_sealing_api_is_present_in_production():
    """The B1 replacement must actually ship, or persistence silently breaks."""
    for name in ("seal_identity", "unseal_identity", "create_sealed_identity",
                 "identity_record_version"):
        assert hasattr(otrv4_core, name), f"otrv4_core is missing {name}"
