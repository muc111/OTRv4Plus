# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""No Python function in the clients or the bridge grows past LIMIT lines.

The long ones were split into named steps and families (dispatch_line was
502 lines, main 460, handle_command 443), and a function that size is where
a branch nobody tests hides. The few still over the limit are listed with
their current length as a ceiling: they may shrink, never grow, and a new
one cannot join them. When one is split, lower or remove its entry.
"""
import ast
import glob
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LIMIT = 200

#: (file, qualified name) -> ceiling, with why it is still long.
CEILING = {
    # SMP protocol handling: left whole on purpose, not restructured without
    # a reason in the protocol itself.
    ("client/otrv4+.py", "EnhancedOTRSession._enh_handle_smp_tlv"): 386,
    # The server load test: one async run whose callbacks share its state.
    ("client/otrv4plus_stresstest.py", "run"): 313,
    ("client/otrv4plus_irc.py", "EnhancedOTRv4IRCClient.handle_command"): 223,
    ("client/otrv4plus_irc.py", "_run_input_loop"): 202,
}


def _functions():
    paths = (glob.glob(os.path.join(ROOT, "client", "*.py"))
             + glob.glob(os.path.join(ROOT, "android_bridge", "*.py"))
             + glob.glob(os.path.join(ROOT, "desktop_bridge", "*.py")))
    for path in sorted(paths):
        if os.path.islink(path):
            continue
        rel = os.path.relpath(path, ROOT).replace(os.sep, "/")
        tree = ast.parse(open(path, encoding="utf-8").read())

        def walk(node, prefix):
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.ClassDef):
                    yield from walk(child, prefix + child.name + ".")
                elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    yield rel, prefix + child.name, child.end_lineno - child.lineno + 1
                    yield from walk(child, prefix + child.name + ".")
        yield from walk(tree, "")


def test_no_function_is_longer_than_the_limit_or_its_ceiling():
    over = []
    for rel, name, length in _functions():
        ceiling = CEILING.get((rel, name), LIMIT)
        if length > ceiling:
            over.append("%s %s: %d lines (limit %d)" % (rel, name, length, ceiling))
    assert not over, "split these into named steps:\n  " + "\n  ".join(over)


def test_every_ceiling_still_names_a_function_over_the_limit():
    lengths = {(rel, name): n for rel, name, n in _functions()}
    stale = [k for k in CEILING if lengths.get(k, 0) <= LIMIT]
    assert not stale, "these are now within the limit; remove them from CEILING: %s" % stale
