# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Untrusted text reaches a terminal only through otrv4plus_sanitise.

There were two copies (otrv4+.py for IRC, otrv4plus_term.py for XMPP) and
the IRC one kept CR and LF, so a peer could forge a line of the client's own
output. These hold the single copy to what it must remove, and both clients
to using it.
"""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "client"))

from otrv4plus_sanitise import sanitise  # noqa: E402


@pytest.mark.parametrize("hostile", [
    "hi\rmallory: forged",                 # CR: overwrite the sender
    "hi\n[otr] SMP verified",              # LF: a fake status line
    "hi\r\n[otr] SMP verified",
    "hi [otr] SMP verified",          # Unicode line separator
    "hi\x85[otr] SMP verified",            # NEL
    "hi\x0b\x0c[otr] SMP verified",
])
def test_a_message_cannot_start_a_line_of_its_own(hostile):
    out = sanitise(hostile)
    assert not any(c in out for c in "\r\n\x0b\x0c\x85  ")
    assert out.startswith("hi ")


@pytest.mark.parametrize("hostile,expected", [
    ("\x1b]0;pwned\x07title", "title"),             # OSC: window title
    ("\x1b]52;c;ZXZpbA==\x1b\\clip", "clip"),       # OSC 52: clipboard
    ("\x1b[2J\x1b[Hcleared", "cleared"),            # CSI: clear, home
    ("\x1b[31mred\x1b[0m", "red"),
    ("\x1b(Bcharset", "charset"),                   # nF escape
    ("\x1bcreset", "reset"),                        # Fe: full reset
    ("\x0304,12colour\x03", "colour"),              # mIRC colour
    ("bell\x07 nul\x00 del\x7f c1\x9b", "bell nul del c1"),
])
def test_escape_sequences_and_controls_are_removed(hostile, expected):
    assert sanitise(hostile) == expected


def test_tabs_and_ordinary_text_are_kept():
    text = "café\tnaïve — 日本語 🙂"
    assert sanitise(text) == text


def test_the_cap_and_non_strings():
    assert sanitise("x" * 2000) == "x" * 512
    assert sanitise("x" * 2000, 64) == "x" * 64
    assert sanitise(12345) == "12345"


def test_both_clients_use_this_one():
    otr = pytest.importorskip("otrv4_")
    import otrv4plus_term
    assert otr._sanitise is sanitise
    assert otrv4plus_term._sanitise("a\rb", 10) == "a b"
    assert otrv4plus_term._sanitise("y" * 2000) == "y" * 1024


def test_no_other_copy_exists():
    """A second implementation is how the two drifted apart."""
    import ast
    client = os.path.join(ROOT, "client")
    for name in sorted(os.listdir(client)):
        path = os.path.join(client, name)
        if not name.endswith(".py") or os.path.islink(path):
            continue
        if name == "otrv4plus_sanitise.py":
            continue
        tree = ast.parse(open(path, encoding="utf-8").read())
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name in ("_sanitise", "sanitise"):
                body = ast.unparse(node)
                assert "re.sub" not in body, "%s:%d reimplements sanitise" % (name, node.lineno)
