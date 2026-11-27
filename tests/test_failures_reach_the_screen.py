# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Every failure code the bridge emits is shown, or is deliberately quiet.

Owner, 2026-10-24: "pressed call button when it was green and nothing
happened". The bridge reported `call_not_placed`; the app showed only codes
that one of three maps knew, and dropped the rest -- twenty-odd of them,
including a failed group send and a failed verification answer. The app now
routes every code through FailureText (Kotlin), which has a sentence, a
QUIET entry with its reason, or a fallback naming the code. This test finds
every code the bridge can emit and requires a sentence or a QUIET entry, so
a new code cannot land on the fallback unnoticed.
"""
import ast
import glob
import os
import pathlib
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KT = [os.path.join(ROOT, "android", "app", "src", "main", "java", "org", "otrv4plus", "android", p)
      for p in ("chat/FailureText.kt", "chat/GroupText.kt", "crypto/CallUi.kt",
                "crypto/Verification.kt")]


def emitted_codes():
    codes = set()
    for path in glob.glob(os.path.join(ROOT, "android_bridge", "*.py")):
        tree = ast.parse(pathlib.Path(path).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = getattr(node.func, "id", getattr(node.func, "attr", ""))
            if name == "ErrorOccurred":
                for kw in node.keywords:
                    if kw.arg == "code" and isinstance(kw.value, ast.Constant):
                        codes.add(kw.value.value)
            if name == "_submit" and len(node.args) >= 3 and isinstance(node.args[2], ast.Constant):
                codes.add(node.args[2].value)
    from android_bridge import voice
    codes |= {"call_" + r for r in voice.CALL_REFUSALS}
    return codes


def test_the_scan_finds_codes():
    codes = emitted_codes()
    assert {"call_not_placed", "call_tunnel", "group_send_failed"} <= codes, codes


def test_every_code_has_a_sentence_or_a_reason_to_be_quiet():
    kt = "".join(pathlib.Path(p).read_text(encoding="utf-8") for p in KT)
    missing = sorted(c for c in emitted_codes() if '"%s"' % c not in kt)
    assert not missing, (
        "the bridge emits %s, which the app would show only as the fallback "
        "line. Give each a sentence in FailureText (or the map it belongs to), "
        "or a QUIET entry saying why it stays off the screen." % missing)


def test_chat_state_routes_every_failure_through_failure_text():
    src = pathlib.Path(os.path.join(ROOT, "android", "app", "src", "main", "java", "org", "otrv4plus",
                            "android", "chat", "ChatState.kt")).read_text(encoding="utf-8")
    block = src[src.index("is OtrEvent.Failed ->"):][:300]
    assert "FailureText.text(event.code, event.peer)" in block
    ft = pathlib.Path(KT[0]).read_text(encoding="utf-8")
    assert re.search(r"return fallback\(code\)", ft), "an unknown code would be silent"
