#!/usr/bin/env python3
"""INV-08, INV-15 -- Release-boundary assertions for the shipped otrv4_core artifact.

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

The third gate, `raw-key-test-api` (section R3 below), does not take the
answer from a variable alone: the artifact says what it is, and a test build
is a failure wherever a release is expected (CI, or
OTRV4PLUS_EXPECT_RELEASE_ARTIFACT=1) unless it is declared. On a developer's
machine with the test build installed, the suite is green with nothing set.
"""

import os
import pytest

otrv4_core = pytest.importorskip("otrv4_core")


# Every Python-reachable name that `test-only-kdf` adds.
#
# Measured, not assumed: the reachable surface is the two PySMPVault methods,
# which #[pymethods] registers automatically, and the key-injection
# constructors below. (kdf.rs::kdf_1_py and header.rs::encode_header_py were
# also behind the feature but never registered with the module; they were
# deleted. GATED_MODULE_FUNCTIONS stays, as names no build may export natively:
# tests/test_gated_build_is_uniform.py checks that on every build.)
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

# Directories that never reach a device. `.venv` is the project virtualenv
# Rust/build.sh creates (gitignored): third-party code, not ours.
_EXCLUDED_PARTS = {
    "tests", ".attic", "target", "build", "__pycache__", ".git",
    "androidTest", "test", ".venv",
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
    """The Dakeresult secret getters must be compiled out, not just unused.

    An unexported Dakeresult is the stronger outcome, not a reason to skip:
    Python cannot obtain or construct one, so the getters are unreachable even
    before the question of whether they were compiled in. This used to report
    as a skip, which reads in CI as "not checked" rather than "cannot happen".
    """
    result = getattr(otrv4_core, "Dakeresult", None)
    if result is None:
        assert not hasattr(otrv4_core, "Dakeresult"), \
            "Dakeresult is exported after all"
        return
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
    # The handle-based API (the DEK is a Rust `FileDek`). The raw-DEK
    # variants (seal_identity, unseal_identity, create_sealed_identity) are
    # test-build only since R3.
    for name in ("create_sealed_identity_under", "unseal_identity_under",
                 "FileDek", "identity_record_version"):
        assert hasattr(otrv4_core, name), f"otrv4_core is missing {name}"


# ── The artifact itself, not the API surface it happens to register ──────────
#
# Everything above asks Python what the module exposes. That answers the
# question that matters at runtime, but it goes through the module's
# registration table: a gated function that was compiled in but not registered
# would pass. These read the compiled object instead, so the assertion is about
# what was built rather than about what was wired up.

_GATED_SYMBOLS = {
    # symbol in the .so             feature that adds it
    "from_seed_bytes":              "test-only-kdf",
    "from_priv_bytes":              "test-only-kdf",
    "__pymethod_get_root_key__":    "legacy-dake-keys",
    "__pymethod_get_chain_key_a__": "legacy-dake-keys",
    "__pymethod_get_chain_key_b__": "legacy-dake-keys",
    "__pymethod_get_brace_key__":   "legacy-dake-keys",
    "__pymethod_get_mac_key__":     "legacy-dake-keys",
    "get_session_keys":             "legacy-dake-keys",
}


def _installed_object_file():
    """The compiled extension backing the imported otrv4_core, or None."""
    import pathlib
    pkg = getattr(otrv4_core, "__file__", None)
    if not pkg:
        return None
    for so in pathlib.Path(pkg).parent.glob("*.so"):
        return so
    return None


def _symbols_present(path):
    """Gated symbol names that appear in the object file's string table."""
    try:
        blob = path.read_bytes()
    except OSError:
        return None
    return sorted(name for name in _GATED_SYMBOLS
                  if name.encode("ascii") in blob)


@pytest.mark.skipif(_TEST_BUILD_EXPECTED or _LEGACY_DAKE_EXPECTED,
                    reason="opt-in build: the gated symbols are expected")
def test_production_object_file_contains_no_gated_symbols():
    """A release artifact must not merely hide the gated APIs -- it must not
    contain them.

    This is the artifact-level counterpart to the attribute checks above. It
    would catch a build where a gated entry point was compiled in and left
    unregistered, which every hasattr() assertion in this file would miss.
    """
    so = _installed_object_file()
    if so is None:
        pytest.skip("no compiled otrv4_core extension found next to the module")

    present = _symbols_present(so)
    if present is None:
        pytest.skip(f"could not read {so}")

    assert present == [], (
        f"{so.name} contains gated symbols {present} "
        f"(features: {sorted({_GATED_SYMBOLS[n] for n in present})}). "
        "This is not a release artifact."
    )


@pytest.mark.skipif(not (_TEST_BUILD_EXPECTED or _LEGACY_DAKE_EXPECTED),
                    reason="production build: nothing to confirm")
def test_optin_object_file_really_carries_the_gated_symbols():
    """Guard against the check above passing vacuously.

    If an opt-in build produced an artifact indistinguishable from the release
    one, the gating would be a no-op and the production assertion would be
    proving nothing.
    """
    so = _installed_object_file()
    if so is None:
        pytest.skip("no compiled otrv4_core extension found next to the module")

    present = _symbols_present(so)
    if present is None:
        pytest.skip(f"could not read {so}")

    expected_features = set()
    if _TEST_BUILD_EXPECTED:
        expected_features.add("test-only-kdf")
    if _LEGACY_DAKE_EXPECTED:
        expected_features.add("legacy-dake-keys")

    found_features = {_GATED_SYMBOLS[n] for n in present}
    assert expected_features & found_features, (
        f"opt-in build for {sorted(expected_features)} but {so.name} carries "
        f"no matching gated symbol -- the installed wheel is not that build"
    )


# ── R3: raw-key entry points (Cargo feature `raw-key-test-api`) ─────────────
#
# Python entry points that take or return raw key material. Production uses
# handles; these exist for known-answer, cross-implementation and fixed-key
# tests. OFF by default, refused by build.rs unless
# OTRV4PLUS_ALLOW_RAW_KEY_TEST_API=1.
#
# WHICH ARTIFACT IS THIS? The two older gates above take the answer from an
# environment variable: unset means "demand a release artifact". For this
# gate that rule made the suite red on every developer's machine, because
# the suite NEEDS the test build (hundreds of tests use the raw-key surface),
# so the artifact installed there is always the test build. A check that is
# red whenever the suite can run gets a variable exported to quiet it, and a
# variable exported out of habit protects nothing.
#
# So the artifact is asked. It says which test features it was compiled with
# (`otrv4_core.TEST_FEATURES`: the names joined by commas, "" for a build
# that may ship; set in Rust/src/lib.rs under the same `#[cfg]`s that add
# the surface), its surface is measured, and the two are held to each
# other. What happens then depends on where this runs:
#
#   release artifact                       the assertion runs, and passes
#   test build, declared (opt-in set)      skipped: this is the test wheel
#   test build in a pipeline, undeclared   FAILS (CI, or
#                                          OTRV4PLUS_EXPECT_RELEASE_ARTIFACT=1)
#   test build on a developer's machine    skipped, saying why, and the build
#                                          is confirmed to be the whole one
#   part of the surface                    FAILS everywhere: neither build
#   declared a test build AND a release    FAILS: both cannot hold
#
# The strictness that matters is unchanged: where an artifact is meant to
# ship, a test build is a failure, and leaving a variable out cannot skip
# it. CI builds the release wheel separately and runs this file on it with
# OTRV4PLUS_EXPECT_RELEASE_ARTIFACT=1 (.github/workflows/python.yml).

RAW_KEY_FEATURE = "raw-key-test-api"
RAW_KEY_OPT_IN_VAR = "OTRV4PLUS_ALLOW_RAW_KEY_TEST_API"
EXPECT_RELEASE_VAR = "OTRV4PLUS_EXPECT_RELEASE_ARTIFACT"
#: Set by CI systems; GitHub Actions sets both.
PIPELINE_VARS = ("GITHUB_ACTIONS", "CI")

RAW_KEY_MODULE_FUNCTIONS = (
    "py_ring_sign", "mldsa87_keygen", "mldsa87_sign",
    "aes256gcm_encrypt", "aes256gcm_decrypt",
    "mlkem1024_keygen", "mlkem1024_encaps", "mlkem1024_decaps",
    "seal_identity", "unseal_identity", "create_sealed_identity",
)
RAW_KEY_CLASS_METHODS = {
    # holds_mac_key: L1's T4 accessor, an oracle on MAC-key material.
    "RustDoubleRatchet": ("from_dakeresult", "holds_mac_key"),
    "RustDAKE": ("new_from_bytearrays", "sign_profile_body_and_construct",
                 "ed448_sign_test"),
    "RustVoiceRoot": ("from_initial_agreement", "derive_rekey", "from_bytes"),
}
# The raw-key constructors: callable with raw keys only in the test build.
RAW_KEY_CONSTRUCTORS = ("RustDoubleRatchet", "RustDAKE")

_RAW_KEY_SURFACE_SIZE = (
    len(RAW_KEY_MODULE_FUNCTIONS)
    + sum(len(methods) for methods in RAW_KEY_CLASS_METHODS.values())
    + len(RAW_KEY_CONSTRUCTORS))


def _exposed_raw_key_surface():
    exposed = [n for n in RAW_KEY_MODULE_FUNCTIONS if hasattr(otrv4_core, n)]
    for cls_name, methods in RAW_KEY_CLASS_METHODS.items():
        cls = getattr(otrv4_core, cls_name)
        exposed += [f"{cls_name}.{m}" for m in methods if hasattr(cls, m)]
    for cls_name in RAW_KEY_CONSTRUCTORS:
        try:
            getattr(otrv4_core, cls_name)(*([b""] * 6))
        except TypeError as exc:
            if ("No constructor defined" in str(exc)
                    or "cannot create" in str(exc)):
                continue
            exposed.append(f"{cls_name}()")
        except Exception:
            exposed.append(f"{cls_name}()")
    return exposed


def raw_key_artifact(exposed=None):
    """"release", "test" or "mixed": what the installed artifact IS, from what
    it exposes. Nothing here reads the environment."""
    if exposed is None:
        exposed = _exposed_raw_key_surface()
    if not exposed:
        return "release"
    if len(exposed) == _RAW_KEY_SURFACE_SIZE:
        return "test"
    return "mixed"


def declared_test_features():
    """What the artifact says it was built with, as a tuple of feature
    names; None from a core built before it could say."""
    label = getattr(otrv4_core, "TEST_FEATURES", None)
    if not isinstance(label, str):
        return None
    return tuple(name for name in label.split(",") if name)


def _in_a_pipeline(environ):
    return any(str(environ.get(name, "")).strip().lower()
               not in ("", "0", "false", "no") for name in PIPELINE_VARS)


def release_expected(environ):
    """Whether a release artifact is what this run is meant to be looking
    at: said outright, or the run is a CI pipeline."""
    return environ.get(EXPECT_RELEASE_VAR) == "1" or _in_a_pipeline(environ)


def raw_key_verdict(kind, environ):
    """("pass" | "skip" | "fail", why) for the release assertion, given what
    the artifact is and the environment it is judged in. A pure function, so
    that every row of the table in the comment above is a test below."""
    opted_in = environ.get(RAW_KEY_OPT_IN_VAR) == "1"
    if kind == "mixed":
        return "fail", (
            "the installed otrv4_core exposes PART of the raw-key surface. "
            "That is neither the release artifact nor the test build: a "
            "gate was added on one side only, or the wheel is stale. Rebuild "
            "it.")
    if opted_in and environ.get(EXPECT_RELEASE_VAR) == "1":
        return "fail", (
            f"{RAW_KEY_OPT_IN_VAR}=1 says this is the test build and "
            f"{EXPECT_RELEASE_VAR}=1 says it is the release artifact. Unset "
            f"one of them.")
    if kind == "release":
        return "pass", "a release artifact: no raw-key entry point may exist"
    if opted_in:
        return "skip", f"{RAW_KEY_OPT_IN_VAR}=1: this is the test wheel"
    if release_expected(environ):
        where = (f"{EXPECT_RELEASE_VAR}=1"
                 if environ.get(EXPECT_RELEASE_VAR) == "1"
                 else "this is a CI pipeline (%s is set)" % " or ".join(
                     PIPELINE_VARS))
        return "fail", (
            f"the installed otrv4_core is the TEST build (it exposes the "
            f"raw-key entry points) and {where}, where the artifact under "
            f"test is taken to be one that ships. If this job is meant to "
            f"test the test build, say so: {RAW_KEY_OPT_IN_VAR}=1. If it is "
            f"meant to test the release, rebuild without --features "
            f"{RAW_KEY_FEATURE}.")
    return "skip", (
        "the installed otrv4_core is the test build, on a machine that is "
        "not a CI pipeline: the release assertion does not apply to it. "
        "(test_raw_key_optin_build_really_is_the_test_build confirms it is "
        f"the whole test build. To assert a release artifact here, install "
        f"one and set {EXPECT_RELEASE_VAR}=1.)")


def _artifact_report():
    """What a failure needs to be acted on, and nothing secret: the file,
    what it says it is, the NAMES it exposes, and which variables are set."""
    exposed = _exposed_raw_key_surface()
    lines = [
        "  artifact      %s" % getattr(otrv4_core, "__file__", "?"),
        "  version       %s" % getattr(otrv4_core, "__version__", "?"),
        "  says it has   %s" % (declared_test_features(),),
        "  exposes       %d of %d raw-key entry points%s" % (
            len(exposed), _RAW_KEY_SURFACE_SIZE,
            (": " + ", ".join(exposed)) if exposed else ""),
    ]
    for name in (RAW_KEY_OPT_IN_VAR, EXPECT_RELEASE_VAR) + PIPELINE_VARS:
        lines.append("  %-38s %s" % (
            name, "set" if os.environ.get(name) else "not set"))
    return "\n".join(lines)


def test_production_artifact_exposes_no_raw_key_entry_point():
    """The release assertion. Which of the rows above applies is decided by
    `raw_key_verdict`; a release artifact always reaches the assert."""
    exposed = _exposed_raw_key_surface()
    verdict, why = raw_key_verdict(raw_key_artifact(exposed), os.environ)
    if verdict == "skip":
        pytest.skip(why)
    if verdict == "fail":
        pytest.fail(why + "\n" + _artifact_report())
    assert not exposed, (
        f"otrv4_core exposes raw-key entry points {exposed}. Production uses "
        f"handles; rebuild without --features {RAW_KEY_FEATURE}.")


def test_raw_key_optin_build_really_is_the_test_build():
    """Whenever the release assertion stands down, this one stands up: the
    artifact must then be the WHOLE test build, by its surface and by its own
    account. Otherwise the tests that need the surface would fail for the
    wrong reason, or a half-gated build would pass as "the test wheel"."""
    kind = raw_key_artifact()
    opted_in = os.environ.get(RAW_KEY_OPT_IN_VAR) == "1"
    if kind == "release" and not opted_in:
        pytest.skip("release build: nothing to confirm")
    assert kind == "test", (
        f"{RAW_KEY_OPT_IN_VAR}=1 says this is the test build, but the "
        f"installed artifact is a {kind} one.\n" + _artifact_report())
    label = declared_test_features()
    assert label is not None and RAW_KEY_FEATURE in label, (
        "the artifact exposes the raw-key surface and does not say so.\n"
        + _artifact_report())


def test_the_artifact_says_what_it_is():
    """`otrv4_core.TEST_FEATURES` is the build's own account of itself, and
    this holds it to the build: each feature named exactly when its surface
    is there. A diagnostic report prints it, and the guard above reads it."""
    label = declared_test_features()
    assert label is not None, (
        "otrv4_core has no TEST_FEATURES: the installed core predates the "
        "build label. Rebuild it.")
    # One string: no Python sequence type crosses the Rust boundary
    # (tests/test_dependency_advisories.py).
    assert isinstance(otrv4_core.TEST_FEATURES, str)
    assert otrv4_core.TEST_FEATURES == ",".join(label)
    assert len(set(label)) == len(label)
    assert set(label) <= {RAW_KEY_FEATURE, "test-only-kdf", "legacy-dake-keys"}
    kind = raw_key_artifact()
    if kind != "mixed":
        assert (RAW_KEY_FEATURE in label) == (kind == "test"), (label, kind)
    assert ("test-only-kdf" in label) == bool(_exposed_vault_methods()), label
    assert ("legacy-dake-keys" in label) == bool(_exposed_dake_methods()), label


def test_the_feature_name_is_in_the_object_file_only_when_it_is_on():
    """The label is compiled under `#[cfg]`, so a release artifact does not
    even contain the feature's name. `.github/scripts/inspect_apk.py` looks
    for that string in the APK's core; this is the same check on the host
    artifact, in both directions."""
    so = _installed_object_file()
    if so is None:
        pytest.skip("no compiled otrv4_core extension found next to the module")
    blob = so.read_bytes()
    kind = raw_key_artifact()
    if kind == "mixed":
        pytest.skip("a mixed artifact: the tests above already fail on it")
    assert (RAW_KEY_FEATURE.encode("ascii") in blob) == (kind == "test"), (
        so.name, kind)
    apk = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), ".github", "scripts", "inspect_apk.py")
    with open(apk, encoding="utf-8") as handle:
        assert 'b"%s"' % RAW_KEY_FEATURE in handle.read()


_E, _O = EXPECT_RELEASE_VAR, RAW_KEY_OPT_IN_VAR


@pytest.mark.parametrize("kind,environ,expected", [
    # A release artifact passes wherever it is.
    ("release", {}, "pass"),
    ("release", {"CI": "true", "GITHUB_ACTIONS": "true"}, "pass"),
    ("release", {_E: "1"}, "pass"),
    ("release", {_E: "1", "CI": "true"}, "pass"),
    # The test build, declared: the main CI job, and a developer who says so.
    ("test", {_O: "1"}, "skip"),
    ("test", {_O: "1", "CI": "true", "GITHUB_ACTIONS": "true"}, "skip"),
    # The test build on a developer's machine, with nothing set.
    ("test", {}, "skip"),
    ("test", {"CI": ""}, "skip"),
    ("test", {"CI": "false"}, "skip"),
    ("test", {_O: "0"}, "skip"),
    # The test build where a release is expected: red, never skipped.
    ("test", {"CI": "true"}, "fail"),
    ("test", {"GITHUB_ACTIONS": "true"}, "fail"),
    ("test", {"CI": "1"}, "fail"),
    ("test", {_E: "1"}, "fail"),
    # Contradictory declarations.
    ("test", {_E: "1", _O: "1"}, "fail"),
    ("release", {_E: "1", _O: "1"}, "fail"),
    # Neither build.
    ("mixed", {}, "fail"),
    ("mixed", {_O: "1"}, "fail"),
    ("mixed", {_E: "1"}, "fail"),
])
def test_the_raw_key_verdict_table(kind, environ, expected):
    verdict, why = raw_key_verdict(kind, environ)
    assert verdict == expected, why
    assert why and "\n" not in why


def test_a_pipeline_never_skips_the_release_assertion_by_omission():
    """In a pipeline the only way past a test build is to declare it, and
    the failure says how. Then the workflow itself: the step that tests the
    wheel that ships declares that it expects one, and does not opt in."""
    for pipeline in ({"CI": "true"}, {"GITHUB_ACTIONS": "true"},
                     {EXPECT_RELEASE_VAR: "1"}):
        verdict, why = raw_key_verdict("test", pipeline)
        assert verdict == "fail", pipeline
        assert RAW_KEY_OPT_IN_VAR in why and RAW_KEY_FEATURE in why
    workflow_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        ".github", "workflows", "python.yml")
    with open(workflow_path, encoding="utf-8") as handle:
        workflow = handle.read()
    suite = workflow[workflow.index("- name: pytest"):
                     workflow.index("- name: Failures as annotations")]
    assert f'{RAW_KEY_OPT_IN_VAR}: "1"' in suite
    release = workflow[workflow.index(
        "- name: Release wheel exposes no raw-key API"):
        workflow.index("- name: Gates-open wheel runs the gated tests")]
    assert f'{EXPECT_RELEASE_VAR}: "1"' in release
    assert RAW_KEY_OPT_IN_VAR not in release
    assert "raw-key-test-api" not in release
    assert "tests/test_release_guard.py" in release


def test_part_of_the_surface_is_neither_build():
    assert raw_key_artifact([]) == "release"
    assert raw_key_artifact(["x"] * _RAW_KEY_SURFACE_SIZE) == "test"
    for size in (1, _RAW_KEY_SURFACE_SIZE - 1, _RAW_KEY_SURFACE_SIZE + 1):
        assert raw_key_artifact(["x"] * size) == "mixed"


def test_the_build_label_cannot_name_a_feature_that_is_off():
    """Read from the Rust source: each name in `test_features()` sits
    directly under the `#[cfg]` for that same feature, and the function does
    not use `cfg!()`, which would leave every name in every binary."""
    import re
    lib = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "Rust", "src", "lib.rs")
    if not os.path.isfile(lib):
        pytest.skip("Rust sources not present next to the tests")
    with open(lib, encoding="utf-8") as handle:
        source = handle.read()
    body = source[source.index("pub fn test_features()"):]
    body = body[:body.index("\n}\n")]
    assert "cfg!(" not in body
    pairs = re.findall(
        r'#\[cfg\(feature = "([a-z-]+)"\)\]\n\s*"([a-z-]+)",', body)
    assert pairs == [("raw-key-test-api", "raw-key-test-api"),
                     ("test-only-kdf", "test-only-kdf"),
                     ("legacy-dake-keys", "legacy-dake-keys")], pairs
    assert body.count('"') == 4 * len(pairs), "a name outside a #[cfg]"
    assert 'm.add("TEST_FEATURES", test_features().join(","))' in source


def test_the_raw_key_surface_is_fully_enumerated():
    """Every item gated in Rust is listed here, so the release assertion
    covers it."""
    rust = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "Rust", "src")
    if not os.path.isdir(rust):
        pytest.skip("Rust sources not present next to the tests")
    gated = 0
    for name in os.listdir(rust):
        if name.endswith(".rs"):
            with open(os.path.join(rust, name), encoding="utf-8") as f:
                gated += f.read().count('#[cfg(feature = "raw-key-test-api")]\n')
    # +2: the PyByteArray import in dake.rs is gated on the same feature, and
    # so is the feature's own name in lib.rs's build label.
    assert gated == _RAW_KEY_SURFACE_SIZE + 2, (gated, _RAW_KEY_SURFACE_SIZE)
