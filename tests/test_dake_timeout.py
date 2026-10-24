# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""A DAKE left half-open expires (docs/SECURITY_ISSUES.md G1).

`RustDAKEAdapter.is_expired()` returned False unconditionally, so any caller
would have kept a half-open handshake for ever. It now counts from the first
move out of IDLE, on the monotonic clock, against `timeout` (default
UIConstants.DAKE_TIMEOUT). Only a handshake in flight can expire.
"""
import pytest

otr = pytest.importorskip("otrv4_")
DAKEState = otr.DAKEState


def _adapter():
    return otr.RustDAKEAdapter(explicit_initiator=True)


def test_the_default_is_the_documented_timeout():
    assert _adapter().timeout == otr.UIConstants.DAKE_TIMEOUT == 120.0


def test_a_handshake_in_flight_expires(monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(otr.time, "monotonic", lambda: clock[0])
    d = _adapter()
    d.generate_dake1()
    assert d.state == DAKEState.SENT_DAKE1
    clock[0] += d.timeout - 1
    assert not d.is_expired()
    clock[0] += 2
    assert d.is_expired()


def test_one_that_has_not_started_or_is_over_never_expires(monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(otr.time, "monotonic", lambda: clock[0])
    d = _adapter()
    clock[0] += 10_000
    assert not d.is_expired(), "IDLE has not started"
    d.generate_dake1()
    clock[0] += 10_000
    for state in (DAKEState.ESTABLISHED, DAKEState.FAILED):
        d._state = state
        assert not d.is_expired(), state


def test_the_wall_clock_does_not_age_a_handshake(monkeypatch):
    d = _adapter()
    d.generate_dake1()
    monkeypatch.setattr(otr.time, "time", lambda: 9e12)
    assert not d.is_expired()


def test_there_is_one_test_library():
    """G2: two divergent copies of otrv4_testlib.py loaded in collection order."""
    import glob
    import os
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    copies = [p for p in glob.glob(os.path.join(root, "**", "otrv4_testlib.py"), recursive=True)
              if ".venv" not in p and "/build/" not in p]
    assert [os.path.relpath(p, root) for p in copies] == [os.path.join("tests", "otrv4_testlib.py")]
