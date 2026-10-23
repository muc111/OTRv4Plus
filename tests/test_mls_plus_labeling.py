# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Gate: user-facing text says MLS+, never a bare MLS.

MLS+ is to MLS what OTRv4+ is to OTRv4: RFC 9420 framing on the private
hybrid post-quantum ciphersuite 0xF0A1. A bare "MLS" in the UI suggests
RFC 9420 interoperability the app deliberately does not offer.

Allowed: "MLS+", "MLS (RFC 9420)" (a reference to the standard itself),
"standard MLS" (the thing MLS+ is not), and identifiers/wire prefixes
(?OTRv4MLS1:, MlsProvider...), which word boundaries already skip.
Comments and docstrings are not user-facing and are not scanned.
"""
import ast
import glob
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFINITION = ("**MLS+** — MLS (RFC 9420) on a hybrid post-quantum ciphersuite "
              "(`0xF0A1`, X448 + ML-KEM-1024 / Ed448 + ML-DSA-87). Not "
              "interoperable with standard MLS.")
INTEROP = ("**MLS+ is not standard MLS.** Groups use an unregistered ciphersuite "
           "(`0xF0A1`, in the IANA private-use range) and cannot be joined by Wire, Element, or any other "
           "RFC 9420 implementation.")

BARE = re.compile(r"(?<!standard )\bMLS\b(?!\+)(?!\s*\()", re.IGNORECASE)


def _bare(text):
    return [m.start() for m in BARE.finditer(text)]


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def test_the_scanner_itself():
    assert _bare("Secure group (MLS): setting up") and _bare("MLS-encrypted")
    assert not _bare("Secure group (MLS+): setting up")
    assert not _bare("MLS (RFC 9420) on a hybrid suite")
    assert not _bare("not compatible with standard MLS clients")
    assert not _bare("?OTRv4MLS1: and MlsProvider and mls_state")


def test_android_string_resources():
    bad = []
    for path in glob.glob(os.path.join(ROOT, "android", "**", "res", "values*",
                                       "strings.xml"), recursive=True):
        for n, line in enumerate(_read(path).splitlines(), 1):
            if _bare(re.sub(r"<!--.*?-->", "", line)):
                bad.append("%s:%d: %s" % (os.path.relpath(path, ROOT), n, line.strip()))
    assert not bad, "\n".join(bad)


_KT_STRING = re.compile(r'"(?:[^"\\\n]|\\.)*"')


def test_android_and_desktop_ui_strings():
    """Kotlin string literals on code lines (not comments): the labels."""
    bad = []
    roots = [os.path.join(ROOT, "android", "app", "src", "main", "java"),
             os.path.join(ROOT, "desktop", "src", "main", "kotlin")]
    for root in roots:
        for path in glob.glob(os.path.join(root, "**", "*.kt"), recursive=True):
            for n, line in enumerate(_read(path).splitlines(), 1):
                code = line.strip()
                if code.startswith(("//", "*", "/*")):
                    continue
                code = code.split(" // ", 1)[0]
                for lit in _KT_STRING.findall(code):
                    if _bare(lit):
                        bad.append("%s:%d: %s" % (os.path.relpath(path, ROOT), n, lit))
    assert not bad, "\n".join(bad)


def _docstring_ids(tree):
    ids = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                ids.add(id(first.value))
    return ids


def test_terminal_client_output():
    bad = []
    for name in ("otrv4plus_xmpp.py", "otrv4plus_sync.py", "otrv4plus_termsync.py"):
        path = os.path.join(ROOT, name)
        tree = ast.parse(_read(path))
        docs = _docstring_ids(tree)
        for node in ast.walk(tree):
            if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                    and id(node) not in docs and not node.value.startswith("?OTRv4")
                    and _bare(node.value)):
                bad.append("%s:%d: %r" % (name, node.lineno, node.value[:80]))
    assert not bad, "\n".join(bad)


def test_the_group_creation_screen_says_what_it_is():
    sections = _read(os.path.join(ROOT, "android", "app", "src", "main", "java", "org",
                                  "otrv4plus", "android", "chat", "RoomSections.kt"))
    assert ('MLS_PLUS_NOTE = "Post-quantum MLS+ (not compatible with standard '
            'MLS clients)"') in sections
    screen = _read(os.path.join(ROOT, "android", "app", "src", "main", "java", "org",
                                "otrv4plus", "android", "ui", "RoomsScreen.kt"))
    assert screen.index("RoomSections.MLS_PLUS_NOTE") > screen.index('"New encrypted group"')


def test_mls_plus_is_defined_in_the_readme_and_technical():
    readme = _read(os.path.join(ROOT, "README.md"))
    technical = _read(os.path.join(ROOT, "TECHNICAL.md"))
    assert DEFINITION in readme and DEFINITION in technical
    assert INTEROP in readme
    assert readme.index(INTEROP) > readme.index("**Known limits**")
    tech = technical.index("## Encrypted group chat (MLS)")
    assert tech < technical.index(DEFINITION) < tech + 400


def test_the_wire_format_is_untouched():
    """Labels only: the envelope and the suite stay byte-identical."""
    groups = _read(os.path.join(ROOT, "android_bridge", "groups.py"))
    assert 'ROOM_PREFIX = "?OTRv4MLS1:"' in groups
    assert "0xF0A1" in _read(os.path.join(ROOT, "TECHNICAL.md"))
