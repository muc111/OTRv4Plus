# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""No function reads a global its module does not have.

Python only notices a missing name when the line runs, and an error branch
may never run in a test. Two such lines were found on 2026-10-24, both old:
`VoiceFrameCrypto.zeroize` (a stray `setattr(self, name, None)` in its except
branch, NameError on a path documented "never raises") and the XMPP client's
`/help` (a staticmethod reading `self`). Moving code between modules makes
this mistake easy, so every module is checked: compile it, list every
LOAD_GLOBAL its functions perform, and require each name to exist in the
imported module or in builtins.
"""
import builtins
import dis
import glob
import importlib
import os
import sys
import types

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: Modules that cannot be imported here at all (they need their host).
NEEDS_HOST = {"weechat_otrv4plus"}

#: Names a module defines at runtime in a way the check cannot see, with why.
KNOWN = {}


def _modules():
    out = []
    for path in sorted(glob.glob(os.path.join(ROOT, "client", "*.py"))):
        name = os.path.basename(path)[:-3]
        if os.path.islink(path) or name in NEEDS_HOST or not name.isidentifier():
            continue
        out.append((name, path))
    out.append(("otrv4_", os.path.join(ROOT, "client", "otrv4+.py")))   # the engine
    for pkg in ("android_bridge", "desktop_bridge"):
        for path in sorted(glob.glob(os.path.join(ROOT, pkg, "*.py"))):
            base = os.path.basename(path)[:-3]
            out.append((pkg if base == "__init__" else "%s.%s" % (pkg, base), path))
    return out


def _code_objects(code):
    yield code
    for const in code.co_consts:
        if isinstance(const, types.CodeType):
            yield from _code_objects(const)


@pytest.mark.parametrize("name,path", _modules(), ids=[n for n, _ in _modules()])
def test_every_global_a_function_reads_exists(name, path):
    try:
        module = importlib.import_module(name)
    except ImportError as exc:
        pytest.skip("cannot import here: %s" % exc)
    top = compile(open(path, encoding="utf-8").read(), path, "exec")
    have = vars(module)
    missing = set()
    for code in _code_objects(top):
        if code is top:
            continue
        for ins in dis.get_instructions(code):
            if (ins.opname == "LOAD_GLOBAL" and ins.argval not in have
                    and not hasattr(builtins, ins.argval)
                    and ins.argval not in KNOWN.get(name, ())):
                missing.add("%s (in %s)" % (ins.argval, code.co_name))
    assert not missing, "%s reads globals it does not have: %s" % (
        name, ", ".join(sorted(missing)))
