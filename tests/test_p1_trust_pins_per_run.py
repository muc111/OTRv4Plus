# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""P1 (docs/SECURITY_ISSUES.md): on Android and the desktop, contact pins
last one run of the app.

Found by the audit of 2026-10-26. A2 says a known contact's ML-DSA key is
pinned, and SECURITY.md that a changed fingerprint "is reported, never
auto-accepted". Both rest on `TrustDatabase`. The app engines are built
with a bare `OTRConfig()`, whose `persist_trust` is False, so their trust
database lives in memory: after the app restarts, a contact presenting
another key is a first contact again, pinned without a word. The terminal
client builds its engine with `persist_trust=True` and keeps its pins.

These tests ASSERT the residual. They fail when it is fixed, and then the
issue, A2's wording and SECURITY.md must change with them.
"""
from __future__ import annotations

import os
import tempfile

import pytest

import test_smp_end_to_end as E

otr = E.otr
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PEER = "bob@example.test"
OLD, NEW = "a" * 64, "b" * 64
IDENT, OTHER_MLDSA = b"\x01" * 57, b"\x03" * 2592
MLDSA = b"\x02" * 2592


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as fh:
        return fh.read()


def test_the_app_engines_are_built_with_a_trust_database_in_memory():
    assert otr.OTRConfig().persist_trust is False
    kotlin = _read("android", "app", "src", "main", "java", "org", "otrv4plus", "android",
                   "bridge", "ChaquopyOtrCore.kt")
    assert 'otr.callAttr("EnhancedSessionManager", otr.callAttr("OTRConfig"))' in kotlin
    host = _read("desktop_bridge", "host.py")
    assert "OtrApp(otr.EnhancedSessionManager(otr.OTRConfig()))" in host
    assert "persist_trust" not in kotlin and "persist_trust" not in host


def test_within_one_run_a_changed_key_is_refused():
    db = otr.TrustDatabase(None, persistent=False)
    assert db.check_or_pin(PEER, OLD) is False                     # first contact
    with pytest.raises(otr.TrustDatabase.FingerprintMismatchError):
        db.check_or_pin(PEER, NEW)
    db.check_or_pin_pq(PEER, IDENT, MLDSA, True)
    with pytest.raises(otr.TrustDatabase.PqIdentityRefused):
        db.check_or_pin_pq(PEER, IDENT, OTHER_MLDSA, True)


def test_residual_after_a_restart_of_the_app_a_changed_key_is_a_first_contact():
    run1 = otr.TrustDatabase(None, persistent=False)
    run1.check_or_pin(PEER, OLD)
    run1.check_or_pin_pq(PEER, IDENT, MLDSA, True)
    run2 = otr.TrustDatabase(None, persistent=False)                # the app restarted
    assert run2.check_or_pin(PEER, NEW) is False, "pinned as new, no mismatch raised"
    run2.check_or_pin_pq(PEER, IDENT, OTHER_MLDSA, True)            # no PqIdentityRefused


def test_the_terminal_keeps_its_pins_across_restarts():
    src = _read("client", "otrv4plus_xmpp.py")
    assert "persist_trust=True," in src
    path = os.path.join(tempfile.mkdtemp(), "trust.json")
    run1 = otr.TrustDatabase(path, persistent=True)
    run1.check_or_pin(PEER, OLD)
    run1.check_or_pin_pq(PEER, IDENT, MLDSA, True)
    run2 = otr.TrustDatabase(path, persistent=True)
    with pytest.raises(otr.TrustDatabase.FingerprintMismatchError):
        run2.check_or_pin(PEER, NEW)
    with pytest.raises(otr.TrustDatabase.PqIdentityRefused):
        run2.check_or_pin_pq(PEER, IDENT, OTHER_MLDSA, True)
