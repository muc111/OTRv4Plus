#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""First launch shows a blank username and names nobody.

A handset showed a greyed "alice" in the username field: the field was empty
but its placeholder was a demo identity, which reads as prefilled. Production
UI must carry no demo, test or admin identity and no credential. Test
fixtures are not touched: this reads only the shipped source set.
"""

import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAIN = os.path.join(ROOT, "android", "app", "src", "main")
PKG = os.path.join(MAIN, "java", "org", "otrv4plus", "android")

DEMO_NAMES = re.compile(r'"(alice|bob|carol|dave|mallory|eve|admin|root|test|demo|user1)"',
                        re.IGNORECASE)


def _read(*parts):
    with open(os.path.join(PKG, *parts), encoding="utf-8") as fh:
        return fh.read()


def _code(text):
    """Source without comments."""
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def test_the_username_starts_blank():
    sign_in = _read("connection", "SignIn.kt")
    assert 'const val INITIAL_USERNAME = ""' in sign_in
    screen = _read("ui", "ConnectScreen.kt")
    assert "mutableStateOf(SignIn.INITIAL_USERNAME)" in screen


def test_the_hint_names_nobody():
    sign_in = _read("connection", "SignIn.kt")
    hint = re.search(r'USERNAME_HINT = "([^"]*)"', sign_in).group(1)
    assert not DEMO_NAMES.search('"%s"' % hint), hint
    assert 'placeholder = { Text("alice") }' not in _read("ui", "ConnectScreen.kt")


def test_no_production_source_carries_a_demo_identity_or_credential():
    offenders = []
    for dirpath, _dirs, files in os.walk(MAIN):
        for name in files:
            if not name.endswith((".kt", ".xml")):
                continue
            path = os.path.join(dirpath, name)
            code = _code(open(path, encoding="utf-8").read())
            # `domain="root"` is Android's backup-rule token, not a user.
            code = re.sub(r'domain="[a-z_]+"', "", code)
            for m in DEMO_NAMES.finditer(code):
                offenders.append("%s: %s" % (os.path.relpath(path, ROOT), m.group(0)))
            # A value assigned to a lower-case `password`: a real credential.
            # (EXTRA_PASSWORD = "password" is an Intent key name.)
            if re.search(r'\bpassword\s*=\s*"[^"]+"', code):
                offenders.append("%s: a literal password" % os.path.relpath(path, ROOT))
    assert offenders == [], offenders
