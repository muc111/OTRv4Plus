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
            "deniable messaging", "until it does", "unlinked", "past messages are deniable",
            # the labels (owner, 2026-10-27): the button names the mechanism
            "make chat deniable", "make group deniable", "make deniable",
            "make this chat deniable", "make this group deniable")


def _strings(path):
    """The string literals of [path]'s code (not its comments, which may
    cite an old wording on purpose), joined the way the code joins them."""
    src = open(path, encoding="utf-8").read()
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    src = re.sub(r"(?m)^\s*//.*$", "", src)
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


def test_no_source_says_offline_closing_messages_are_dropped():
    """Audit row 1.14: offline closing messages are kept in memory only, not
    dropped. The claim was corrected in the docs and the bridge, and the
    re-run of 2026-10-27 found it still in the engine's teardown docstring."""
    srcs = ["docs/SPEC.md", "docs/SECURITY_ISSUES.md", "client/otrv4+.py",
            "android_bridge/app_deniable.py", "android_bridge/app.py"]
    bad = []
    for src in srcs:
        text = re.sub(r"\s+", " ", open(os.path.join(ROOT, src), encoding="utf-8").read())
        for sentence in re.split(r"(?<=[.;])\s", text):
            low = sentence.lower()
            if re.search(r"\b(without a network|offline)\b", low) and "dropped" in low:
                bad.append("%s: %s" % (src, sentence.strip()[:160]))
    assert bad == [], "\n".join(bad)


def test_kept_closing_messages_are_always_said_to_be_in_memory():
    """Closing messages waiting for confirmation are kept in memory only:
    one written to disk would record whom a chat was made deniable with
    (TestCrashDuringClose). Audit 2026-10-27: "kept" alone read as if that
    decision had been reversed. Every sentence of the security record that
    says closing messages are kept says where."""
    docs = ("docs/SECURITY_ISSUES.md", "docs/SPEC.md", "docs/AUDIT_SUMMARY.md",
            "docs/AUDIT_THREAT_MODEL.md", "docs/DENIABILITY_LAYERS.md")
    bad = []
    for doc in docs:
        text = re.sub(r"\s+", " ", open(os.path.join(ROOT, doc), encoding="utf-8").read())
        for sentence in re.split(r"(?<=[.;|])\s", text):
            low = sentence.lower()
            if "closing" in low and re.search(r"\bkept\b", low) and "memory" not in low:
                bad.append("%s: %s" % (doc, sentence.strip()[:160]))
    assert bad == [], "\n".join(bad)
