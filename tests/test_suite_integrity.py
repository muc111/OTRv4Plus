#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""A green run has to mean the engine ran.

WHAT WENT WRONG
===============
`conftest.py` loads `otrv4+.py` by path under the name `otrv4_`. It installed
the module object in `sys.modules` FIRST and executed it SECOND, inside a
blanket `except Exception` that printed a warning and carried on. So when the
engine failed to load for any reason at all, what stayed behind under its name
was a module that had been partly executed, or not executed at all.

That is worse than no module. `pytest.importorskip("otrv4_")` succeeds on a
shell -- the name imports -- and every test guarded by `hasattr` or a
`getattr(..., None)` then skips quietly. A run in which the product did not
load reports no failures.

It is not hypothetical. `otrv4+.py` uses PEP 701 f-strings and needs Python
>= 3.12, which `Rust/pyproject.toml` declares and CI pins; invoked with a 3.11
interpreter it raises SyntaxError at import. Measured before the fix, that run
produced `24 skipped` and a scatter of

    AttributeError: module 'otrv4_' has no attribute '_dake1_rate_limiter'

rather than one sentence naming the cause.

WHAT THIS FILE ASSERTS
======================
That the engine under test is the real one. Not "an object called otrv4_" --
the module the rest of the suite is about, carrying the pieces the security
tests drive. These are deliberately cheap identity checks, not behaviour: the
behaviour is everywhere else, and this exists so that everywhere else cannot
pass vacuously.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_the_interpreter_can_run_the_engine():
    """Stated once, so a wrong interpreter is a sentence rather than a
    SyntaxError in somebody's fixture."""
    assert sys.version_info >= (3, 12), (
        "the engine requires Python >= 3.12 (PEP 701 f-strings); "
        "Rust/pyproject.toml declares it and CI pins it")


def test_the_engine_module_is_loaded_not_stubbed():
    """The module under `otrv4_` is the engine, not a leftover shell."""
    assert "otrv4_" in sys.modules, (
        "conftest could not load the engine; every importorskip-guarded test "
        "in this suite is skipping")
    engine = sys.modules["otrv4_"]
    assert getattr(engine, "__file__", None), "otrv4_ has no source file"
    assert os.path.realpath(engine.__file__) == \
        os.path.realpath(os.path.join(ROOT, "otrv4+.py")), (
        "otrv4_ is not otrv4+.py")


@pytest.mark.parametrize("symbol", [
    # The pieces this suite's security tests actually drive. If the module
    # executed only partway, it stops somewhere in this list.
    "OTRConfig",
    "EnhancedSessionManager",
    "DAKE1RateLimiter",
    "_dake1_rate_limiter",
])
def test_the_engine_carries_the_symbols_the_suite_drives(symbol):
    engine = sys.modules.get("otrv4_")
    assert engine is not None and hasattr(engine, symbol), (
        "otrv4_ is missing %r, so it did not finish executing -- tests that "
        "guard on it are skipping rather than failing" % symbol)


def test_the_rust_core_is_the_extension_not_a_python_shim():
    """Every cryptographic test in this suite is about `otrv4_core`. A pure
    Python stand-in passing for it would make all of them meaningless."""
    import importlib.machinery
    core = pytest.importorskip("otrv4_core")
    # Two legitimate layouts. A local build puts `otrv4_core.so` on the path,
    # so the module IS the extension. A maturin wheel (what CI installs)
    # makes `otrv4_core` a package whose `__init__.py` re-exports the
    # compiled submodule `otrv4_core.otrv4_core`. Either way, the thing that
    # answers must have been loaded by the extension loader -- and in the
    # package case the symbols the suite uses must be the extension's own.
    def compiled(mod):
        return isinstance(getattr(getattr(mod, "__spec__", None), "loader",
                                  None),
                          importlib.machinery.ExtensionFileLoader)

    if compiled(core):
        return
    inner = getattr(core, "otrv4_core", None)
    assert inner is not None and compiled(inner), (
        "otrv4_core is not a compiled extension (%r); the cryptographic "
        "tests are not exercising the Rust core"
        % getattr(core, "__file__", None))
    exported = [n for n in dir(inner) if not n.startswith("_")]
    assert exported, "the compiled otrv4_core exports nothing"
    for name in exported:
        assert getattr(core, name, None) is getattr(inner, name), (
            "otrv4_core.%s is not the compiled extension's own -- the "
            "package is shadowing the Rust core with something else" % name)


def test_the_aliases_agree():
    """`otrv4_`, `otrv4plus` and `otrv4+.py` are one module. The two importable
    names are symlinks to the third, and a test importing one while another
    holds the state would be testing two engines."""
    if "otrv4plus" in sys.modules:
        assert sys.modules["otrv4plus"] is sys.modules["otrv4_"]


def test_conftest_does_not_leave_a_broken_engine_behind():
    """The fix itself, read from the source.

    Driven rather than asserted-about would mean re-running pytest in a
    subprocess against a deliberately corrupted copy of a 700 KB module, which
    costs more than it proves. What matters is that the two branches do not
    leave `sys.modules['otrv4_']` populated with something that failed.
    """
    source = open(os.path.join(ROOT, "conftest.py"), encoding="utf-8").read()
    # `rindex` for the closing bound: `_load_main()` is a substring of
    # `def _load_main():` too, and `index` would return an empty block that
    # makes every assertion below fire for the wrong reason.
    block = source[source.index("def _load_main"):source.rindex("_load_main()")]
    assert "except SyntaxError" in block, (
        "a SyntaxError in the engine's own source is being tolerated")
    assert "del sys.modules['otrv4_']" in block or \
        'del sys.modules["otrv4_"]' in block, (
        "the failed module is left in sys.modules, so importorskip succeeds "
        "on a shell")
    assert "sys.modules.pop('otrv4_', None)" in block or \
        'sys.modules.pop("otrv4_", None)' in block, (
        "the tolerated-failure branch still leaves a partly-executed module "
        "under the engine's name")
