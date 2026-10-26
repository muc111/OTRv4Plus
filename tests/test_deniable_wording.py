# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Every surface of Make Chat Deniable and Make Group Deniable describes the
mechanism and its residuals, and states no deniability property.

Audit 2026-10-26 (docs/AUDIT_CLAIM_MATRIX.md §1, §2): L1 and F4 are
RESOLVED-CODE in docs/SECURITY_ISSUES.md, so no surface may say more. The
Android and desktop words live in one Kotlin file (`DeniableChatTest` pins
them in detail); the terminal's are its `/help`. This holds all three to
the same rule, at the source.
"""
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KOTLIN = os.path.join(ROOT, "android", "app", "src", "main", "java", "org", "otrv4plus",
                      "android", "crypto", "DeniableChat.kt")
TERMINAL = os.path.join(ROOT, "client", "otrv4plus_xmpp.py")
PROPERTY = ("pending external audit", "no longer proves", "could have forged",
            "deniable messaging", "until it does", "unlinked", "past messages are deniable")


def _strings(path):
    """The string literals of [path], joined the way the code joins them."""
    src = open(path, encoding="utf-8").read()
    return " ".join(re.findall(r'"((?:[^"\\]|\\.)*)"', src)).replace("\\n", " ")


def _flat(text):
    return re.sub(r"\s+", " ", text.replace('" + "', "").replace('" "', "")).lower()


def test_the_apps_words_state_no_property():
    words = _flat(_strings(KOTLIN))
    for phrase in PROPERTY:
        assert phrase not in words, phrase
    assert words.count("not independently reviewed.") == 2, "chat and group"


def test_the_terminal_words_state_no_property_and_name_the_residuals():
    src = open(TERMINAL, encoding="utf-8").read()
    help_text = src[src.index('"  /deniable [jid]'):src.index('"  /smp start')]
    words = _flat(" ".join(re.findall(r'"((?:[^"\\]|\\.)*)"', help_text)).replace("\\n", " "))
    for phrase in PROPERTY:
        assert phrase not in words, phrase
    for phrase in ("does not hide that you talked", "not independently reviewed",
                   "a copy made before the keys are published",
                   "a close that does not finish", "can still be proof"):
        assert phrase in words, phrase
