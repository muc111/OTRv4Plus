# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""A Python dict must be read with `callAttr("get", key)` from Kotlin.

Chaquopy's PyObject implements Map<String, PyObject> over the object's
ATTRIBUTES. On a dataclass, `obj.get("name")` reads the field. On a dict it
looks up an attribute called "name", finds none, and returns null -- no
exception, so every field silently decodes to its default.

That is what broke opening received files on Android: `transfers()` returns
dicts, was decoded with `row.get(...)`, and so every row had an empty state
and path. `inspect_file()` had the same defect (every file reported
"unknown"). The desktop harness cannot run Chaquopy, so only this check can
see it: for every `requireApp().callAttr("<method>")` whose Python method is
annotated to return a dict or a list of dicts, the Kotlin decoder must not
use `.get("...")`.
"""
import os
import re
import typing

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KT = os.path.join(ROOT, "android", "app", "src", "main", "java", "org",
                  "otrv4plus", "android", "bridge", "ChaquopyOtrCore.kt")

pytest.importorskip("otrv4_")
from android_bridge.app import OtrApp  # noqa: E402


def _returns_dicts(method) -> bool:
    ann = getattr(method, "__annotations__", {}).get("return")
    if ann is None:
        return False
    text = ann if isinstance(ann, str) else repr(ann)
    return "Dict" in text or "dict" in text


def _decoders():
    """(method name, the Kotlin text up to the end of its decode)."""
    src = open(KT, encoding="utf-8").read()
    for m in re.finditer(r'requireApp\(\)\.callAttr\("([a-z_]+)"', src):
        tail = src[m.end():m.end() + 1500]
        # The decode ends at the method's closing getOrDefault / blank line.
        cut = re.search(r"getOrDefault|\n\s*\n", tail)
        yield m.group(1), tail[: cut.start() if cut else len(tail)]


def test_the_scan_finds_the_decoders_it_is_about():
    names = {n for n, _ in _decoders()}
    assert {"transfers", "inspect_file", "contacts"} <= names


@pytest.mark.parametrize("name,body", list(_decoders()))
def test_a_dict_is_never_read_as_attributes(name, body):
    method = getattr(OtrApp, name, None)
    if method is None or not _returns_dicts(method):
        return
    bad = re.findall(r'\b\w+\.get\("[a-z_]+"\)', body)
    assert not bad, (
        "%s() returns a dict, but Kotlin reads it with %s -- an attribute "
        "lookup that returns null for every key. Use callAttr(\"get\", key)."
        % (name, bad))


def test_the_two_that_were_broken_now_use_dict_get():
    src = open(KT, encoding="utf-8").read()
    t = src[src.index("fun transfers(): List<FileTransferView>"):]
    t = t[:t.index("getOrDefault")]
    assert 'row.callAttr("get", "path")' in t and 'row.callAttr("get", "state")' in t
    i = src[src.index("fun inspectFile("):]
    i = i[:i.index("getOrDefault")]
    assert 'd.callAttr("get", "kind")' in i
