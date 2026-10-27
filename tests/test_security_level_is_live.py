# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""A session's security level is reported only while the session is live.

Terminal report, 2026-10-27: an app invited the terminal to a secure group,
the terminal answered y, and got "accept failed: otr_required" although it
had just printed ENCRYPTED. A session that ends (the peer published its
keys, sent DISCONNECTED, or failed) kept the level it had reached, and
`get_security_level` reported it as current. So the group code's check
passed and the send found no session; the apps' lock icon said encrypted
for a chat that was not.
"""
from __future__ import annotations

import pytest

import test_smp_end_to_end as E
from test_smp_end_to_end import pair  # noqa: F401  (fixture)

otr = E.otr
pytest.importorskip("otrv4_core")

Level = otr.UIConstants.SecurityLevel


@pytest.mark.parametrize("end", ["FINISHED", "FAILED"])
def test_an_ended_session_reports_plaintext(pair, end):
    a, b, alice, bob = pair
    assert b.get_security_level(alice) == Level.ENCRYPTED
    b.sessions[alice].transition_session(getattr(otr.SessionState, end), "ended")
    assert not b.has_encrypted_session(alice)
    assert b.get_security_level(alice) == Level.PLAINTEXT


def test_a_live_session_keeps_its_level(pair):
    a, b, alice, bob = pair
    assert b.has_encrypted_session(alice)
    assert b.get_security_level(alice) == Level.ENCRYPTED
    b.sessions[alice].security_level = Level.SMP_VERIFIED
    assert b.get_security_level(alice) == Level.SMP_VERIFIED


def test_the_level_and_the_send_check_agree(pair):
    """Whatever the state, the level says encrypted exactly when a message
    can be sent encrypted."""
    a, b, alice, bob = pair
    for state in (otr.SessionState.FINISHED,):
        b.sessions[alice].transition_session(state, "ended")
        assert (b.get_security_level(alice) != Level.PLAINTEXT) == b.has_encrypted_session(alice)
