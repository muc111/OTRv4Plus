# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""A profile shows whose key it is and offers to check it -- from the
OTRv4+ session, never from the profile itself (owner, 2026-10-17).

A vCard is stored on the server, which can change it; a fingerprint read
from there would let a compromised server vouch for itself.
"""

import os
import sys
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
KT = os.path.join(ROOT, "android", "app", "src", "main", "java", "org",
                  "otrv4plus", "android")


def _read(*parts):
    return open(os.path.join(*parts), encoding="utf-8").read()


def _section(src, start):
    body = src[src.index(start):]
    nxt = body.find("\n@Composable", 1)
    return body if nxt < 0 else body[:nxt]


def test_android_reads_the_session_not_the_vcard():
    screen = _read(KT, "ui", "ProfileScreen.kt")
    section = _section(screen, "private fun IdentitySection(")
    assert "model.profileIdentity" in section
    assert "profileValues" not in section and "edits" not in section
    vm = _read(KT, "chat", "ChatViewModel.kt")
    load = vm[vm.index("fun loadIdentity("):]
    load = load[:load.index("fun loadProfile(")]
    assert "c.securityDetails(jid)" in load


def test_android_verify_opens_the_chat_with_the_prompt():
    main = _read(KT, "MainActivity.kt")
    assert re.search(r"onVerify = \{ who ->\s+chat\.requestVerification\(who\)\s+openChat\(who\)", main)


def test_desktop_reads_the_session_too():
    model = _read(ROOT, "desktop", "src", "main", "kotlin", "org", "otrv4plus",
                  "desktop", "AppModel.kt")
    view = model[model.index("fun viewProfile("):]
    view = view[:view.index("fun closeProfile(")]
    assert "core.securityDetails(jid)" in view
    ui = _read(ROOT, "desktop", "src", "main", "kotlin", "org", "otrv4plus",
               "desktop", "ui", "Profile.kt")
    assert "ProfileIdentity.of(model.profileIdentity)" in ui
    assert "model.verifyFromProfile(jid)" in ui


def test_the_rules_are_shared_and_tested():
    gradle = _read(ROOT, "desktop", "build.gradle.kts")
    assert '"org/otrv4plus/android/chat/ProfileIdentity.kt"' in gradle
    assert os.path.exists(os.path.join(ROOT, "android", "app", "src", "test", "java",
                                       "org", "otrv4plus", "android", "chat",
                                       "ProfileIdentityTest.kt"))


def test_the_two_checks_have_two_names():
    """Owner, 2026-10-17: comparing fingerprints must not read as SMP."""
    rules = _read(KT, "chat", "ProfileIdentity.kt")
    assert 'const val CONFIRMED = "Fingerprint confirmed"' in rules
    assert 'const val VERIFIED = "Verified (shared secret)"' in rules
    # A confirmed fingerprint alone never claims VERIFIED.
    branch = rules[rules.index("\n            details.trusted -> View("):]
    branch = branch[:branch.index("details.security == SecurityState.PLAINTEXT")]
    assert "$CONFIRMED" in branch and "$VERIFIED" not in branch


def test_they_match_asks_first_and_goes_through_the_engine():
    screen = _read(KT, "ui", "ProfileScreen.kt")
    section = _section(screen, "private fun IdentitySection(")
    assert "ProfileIdentity.CONFIRM_BODY" in section
    assert "model.confirmFingerprint(jid)" in section
    vm = _read(KT, "chat", "ChatViewModel.kt")
    confirm = vm[vm.index("fun confirmFingerprint("):]
    confirm = confirm[:confirm.index("fun loadProfile(")]
    assert "profileIdentity?.peerFingerprint" in confirm   # the session's key
    assert "c.trustPeer(jid, fp)" in confirm
    from desktop_bridge.host import APP_OPS
    assert APP_OPS["trust_peer"] == ("peer", "fingerprint")
