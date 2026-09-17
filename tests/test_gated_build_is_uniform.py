# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Every gated capability is covered, whichever way the wheel was built.

WHAT THIS IS FOR
----------------
Several security properties are tested by a PAIR of suites, and which one runs
depends on how the Rust core was compiled:

    capability present (test-only-kdf wheel)   capability absent (release wheel)
    ----------------------------------------   --------------------------------
    tests/test_android_identity.py       (36)  tests/test_rust_identity_sealing.py
    tests/test_rust_security.py          vault  tests/test_release_guard.py
    tests/test_harness_audit.py          vault  tests/test_release_guard.py

That is a sound design -- the absent half is the security boundary working, so
it should skip rather than fail -- and it is why 42 of this suite's 46 skips
are legitimate. Each of those files says so in a comment naming its
counterpart.

WHAT THE COMMENTS CANNOT SAY
----------------------------
They assume the wheel is uniformly one thing or the other. Nothing checks it.

A MIXED wheel -- some gates compiled in, others not -- would put a capability
in the one state neither suite covers: absent, so the internals tests skip;
while `OTRV4PLUS_ALLOW_TEST_GATES=1` declares a test build, so the production
assertions that would have caught its absence skip too. Both halves stand
down, the suite reports green, and the property is tested nowhere.

That is the same shape as the three failures this project has already had --
`answer_subscription` with no caller, the Python suite with no workflow, the
licence guard skipping under the workflow meant to run it. A check that cannot
distinguish "not applicable here" from "not running any more" eventually stops
running. This one is checked.

`test_release_guard.py` already guards the two SINGLE-capability versions of
this (a declared test build whose vault or DAKE surface is missing). What is
new here is the ACROSS-capability invariant: they must all agree with each
other, not merely each with the flag.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

otrv4_core = pytest.importorskip("otrv4_core")

#: Declared by the person building the wheel. The same variable
#: `test_release_guard.py` and `test_rust_identity_sealing.py` read.
TEST_BUILD_DECLARED = os.environ.get("OTRV4PLUS_ALLOW_TEST_GATES") == "1"

def _load_release_guard():
    """Import `test_release_guard` as a module, for its lists and its helper.

    Reused rather than reimplemented. `_exposed_module_functions` encodes a
    distinction this file got wrong on its first attempt: `tests/conftest.py`
    monkey-patches pure-Python stand-ins for `kdf_1`, `rust_kdf_1` and
    `rust_encode_header` onto the module so some older tests can run, so a
    bare `hasattr` reports three gated functions "present" on a perfectly
    clean release wheel. A real PyO3 entry point is a
    `builtin_function_or_method`; a shim is a `function`.

    Writing a second copy of that rule is how the two would drift, which is
    the failure this whole file is about.
    """
    import importlib.util

    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "test_release_guard.py")
    spec = importlib.util.spec_from_file_location("_release_guard", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_GUARD = _load_release_guard()


def _module_fn_compiled_in(name):
    """Whether the COMPILED artifact exposes *name*, ignoring conftest shims."""
    return name in _GUARD._exposed_module_functions()


#: (label, probe) for every capability compiled in only by `test-only-kdf`.
#:
#: The labels match the names in `test_release_guard.GATED_*` deliberately; a
#: capability gated there and missing here would be one this file cannot speak
#: for, which `test_the_registry_matches_the_release_guard` checks.
#:
#: The vault methods and key-injection constructors use `hasattr` because they
#: are methods on PyO3 classes and conftest does not shim them; only the three
#: module-level functions need the stricter probe.
GATED = (
    ("RustSMPVault.load",
     lambda: hasattr(otrv4_core.RustSMPVault, "load")),
    ("RustSMPVault.load_by_handle",
     lambda: hasattr(otrv4_core.RustSMPVault, "load_by_handle")),
    ("Ed448KeyHandle.from_seed_bytes",
     lambda: hasattr(getattr(otrv4_core, "Ed448KeyHandle", None),
                     "from_seed_bytes")),
    ("X448KeyHandle.from_priv_bytes",
     lambda: hasattr(getattr(otrv4_core, "X448KeyHandle", None),
                     "from_priv_bytes")),
    ("kdf_1", lambda: _module_fn_compiled_in("kdf_1")),
    ("encode_header", lambda: _module_fn_compiled_in("encode_header")),
    ("rust_kdf_1", lambda: _module_fn_compiled_in("rust_kdf_1")),
    ("rust_encode_header",
     lambda: _module_fn_compiled_in("rust_encode_header")),
)


def present():
    return sorted(name for name, probe in GATED if probe())


def absent():
    return sorted(name for name, probe in GATED if not probe())


class TestTheWheelIsUniformlyOneThing:

    def test_no_capability_is_in_the_uncovered_state(self):
        """THE INVARIANT. All gated capabilities present, or all absent.

        A mixed wheel leaves whichever ones are absent covered by neither
        suite when the build is declared as a test build.
        """
        here, gone = present(), absent()
        assert not (here and gone), (
            "this wheel is a MIXED build: %d gated capabilities present (%s) "
            "and %d absent (%s).\n\n"
            "Under OTRV4PLUS_ALLOW_TEST_GATES=1 the absent ones are covered "
            "by nothing: the internals tests skip because the capability is "
            "not there, and the production assertions in test_release_guard "
            "skip because the build is declared as a test build. Build the "
            "core with all of `test-only-kdf` or none of it."
            % (len(here), ", ".join(here), len(gone), ", ".join(gone)))

    def test_the_build_matches_what_was_declared(self):
        """The flag and the artifact must agree.

        `test_release_guard` checks this for the vault and the DAKE surface
        individually. Stated once here over the whole set, because the failure
        it prevents -- a suite that skips both halves -- does not care which
        capability it was.
        """
        if TEST_BUILD_DECLARED:
            assert present(), (
                "OTRV4PLUS_ALLOW_TEST_GATES=1 declares a test build, but no "
                "gated capability is compiled in. Every internals test will "
                "skip and every production assertion will skip with it.")
        else:
            assert not present(), (
                "this wheel exposes %s but does not declare itself a test "
                "build. Either it is a release artifact that must not ship "
                "these, or the environment variable was not set."
                % ", ".join(present()))

    def test_the_registry_matches_the_release_guard(self):
        """The two lists of gated names must not drift apart.

        If a capability is gated in `test_release_guard` and unknown here,
        this file is silently not speaking for it -- which is how the gap
        above would reopen one name at a time.
        """
        guard = _GUARD

        expected = set(guard.GATED_VAULT_METHODS)
        mine = {n.split(".", 1)[1] for n, _ in GATED if n.startswith("RustSMPVault.")}
        assert expected <= mine, (
            "test_release_guard gates vault methods %s that this file does "
            "not probe" % sorted(expected - mine))

        for cls, attrs in guard.GATED_KEY_INJECTION.items():
            for attr in attrs:
                assert any(n == "%s.%s" % (cls, attr) for n, _ in GATED), (
                    "test_release_guard gates %s.%s and this file does not "
                    "probe it" % (cls, attr))

        mine_mod = {n for n, _ in GATED if "." not in n}
        missing = set(guard.GATED_MODULE_FUNCTIONS) - mine_mod
        assert not missing, (
            "test_release_guard gates module functions %s that this file "
            "does not probe" % sorted(missing))


class TestTheSealingModuleIsPresentEitherWay:
    """`create_sealed_identity` is NOT gated, and that matters.

    It is what `test_rust_identity_sealing` uses to cover the identity
    lifecycle on a release wheel, so if it were ever gated out the production
    half of that pair would vanish and the 36 skips in
    `test_android_identity` would be covered by nothing.
    """

    def test_sealing_is_compiled_in(self):
        assert hasattr(otrv4_core, "create_sealed_identity"), (
            "the Rust core has no identity sealing module, so "
            "test_rust_identity_sealing skips -- and on a release wheel "
            "test_android_identity skips too. The identity lifecycle would "
            "then be tested nowhere.")
