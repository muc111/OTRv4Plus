# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The XMPP client's commands are split into families that never overlap.

`OTRv4PlusXMPP.dispatch_line` asks each `_dispatch_*` family in turn whether
a line is one of its commands. That is only the same as one long if/elif
chain while no two families claim the same line, so every command a family
matches is run through every family here, and exactly one may take it.
"""
import ast
import inspect
from unittest import mock

import pytest

xmpp = pytest.importorskip("otrv4plus_xmpp")
CLS = xmpp.OTRv4PlusXMPP
FAMILIES = [n for n in ("_dispatch_session", "_dispatch_smp", "_dispatch_contacts",
                        "_dispatch_media", "_dispatch_calls", "_dispatch_display")]


def _commands(method):
    """Every command literal the method compares `lstrip` against."""
    tree = ast.parse(inspect.cleandoc("\n" + inspect.getsource(method)))
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare) and getattr(node.left, "id", "") == "lstrip":
            for comp in node.comparators:
                for c in ast.walk(comp):
                    if isinstance(c, ast.Constant) and isinstance(c.value, str):
                        found.add(c.value)
        if (isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "startswith"
                and getattr(node.func.value, "id", "") == "lstrip"):
            for c in ast.walk(node.args[0]):
                if isinstance(c, ast.Constant) and isinstance(c.value, str):
                    found.add(c.value + "x" if c.value.endswith(" ") else c.value)
    return {c for c in found if c.startswith("/") and c != "/"}


def _claims(family, line):
    self = mock.MagicMock()
    with mock.patch.object(xmpp.asyncio, "ensure_future"), \
            mock.patch.object(xmpp.threading, "Thread"), \
            mock.patch("builtins.print"):
        try:
            return bool(getattr(CLS, family)(self, "bob@example.i2p", line))
        except Exception:
            return True          # it entered one of its branches


def test_the_families_are_the_ones_dispatch_line_asks():
    src = inspect.getsource(CLS.dispatch_line)
    for family in FAMILIES:
        assert "self.%s" % family in src, family
    assert {n for n in vars(CLS) if n.startswith("_dispatch_")} == set(FAMILIES) | {
        "_dispatch_pending"}


@pytest.mark.filterwarnings("ignore:coroutine .* was never awaited")
def test_every_command_belongs_to_exactly_one_family():
    every = {f: _commands(getattr(CLS, f)) for f in FAMILIES}
    assert all(every.values()), every
    assert {"/call", "/smp", "/msg x", "/sendfile", "/block x", "/help"} <= set().union(*every.values())
    wrong = {}
    for owner, lines in every.items():
        for line in lines:
            takers = [f for f in FAMILIES if _claims(f, line)]
            if takers != [owner]:
                wrong[line] = takers
    assert not wrong, "commands claimed by the wrong families: %s" % wrong


def test_ordinary_text_and_unknown_commands_belong_to_none():
    for line in ("hello there", "/nosuchcommand", "/smpx", "/callx"):
        assert not [f for f in FAMILIES if _claims(f, line)], line
