# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The diagnostic report shows each handshake step that arrived, and its fate.

Device report 2026-11-11: a DAKE1 was sent, and the report ended there. It
could not say whether the contact's DAKE2 never arrived or arrived and was
refused, because the bridge recorded nothing for an inbound handshake frame
and the engine logs a refused one only to its own tracer. These pin the
events that now answer that, and that they carry the message TYPE only.
"""

import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

pytest.importorskip("otrv4_core")

from android_bridge.app import OtrApp                          # noqa: E402
from android_bridge.events import SecurityState               # noqa: E402
from android_bridge.trace import TRACE                         # noqa: E402
from test_wipe_and_exit import _pair                           # noqa: E402


def _otr_events(jid_seen_as=None):
    return [e["event"] for e in TRACE.events() if e.get("component") == "otr"]


def test_the_frame_kind_is_read_from_the_type_byte_only():
    import base64
    for byte, kind in ((0x35, "dake1"), (0x36, "dake2"), (0x37, "dake3")):
        body = base64.urlsafe_b64encode(bytes([byte]) + os.urandom(40)).decode()
        assert OtrApp._dake_kind("?OTRv4 " + body + ".") == kind
    data = base64.b64encode(b"\x00\x04\x03" + os.urandom(40)).decode()
    assert OtrApp._dake_kind("?OTRv4 " + data) is None
    for other in ("hello", "?OTRv4F|1|2|3|abc", "", None, b"?OTRv4 NQ"):
        assert OtrApp._dake_kind(other) is None


def test_every_step_of_a_good_handshake_is_recorded():
    TRACE.clear()
    p = _pair()
    p.alice.start_session(p.bob_jid)
    assert p.alice.security_state(p.bob_jid) is not SecurityState.PLAINTEXT
    seen = _otr_events()
    for step in ("dake1_received", "dake2_received", "dake3_received"):
        assert step in seen, (step, seen)
    assert seen.count("session_established") == 2, seen
    assert not [e for e in seen if e.endswith("_not_accepted") or e == "receive_failed"]


def test_a_refused_dake2_is_recorded_as_not_accepted():
    """The initiator's engine refuses a DAKE2 whose MAC fails by returning
    nothing; the report must say so rather than show silence."""
    TRACE.clear()
    p = _pair()
    sent = []

    def tamper_on_the_way(peer, payload, _deliver=p.bob_wire.send):
        text = str(payload)
        if OtrApp._dake_kind(text) == "dake2":
            sent.append(text)
            text = text[:-12] + ("A" if text[-12] != "A" else "B") + text[-11:]
        _deliver(peer, text)

    p.bob_wire.send = tamper_on_the_way
    p.alice.start_session(p.bob_jid)
    assert sent, "no DAKE2 crossed the wire"
    assert p.alice.security_state(p.bob_jid) is SecurityState.PLAINTEXT
    seen = _otr_events()
    assert "dake2_received" in seen
    assert "dake2_not_accepted" in seen or "receive_failed" in seen, seen
    assert "session_established" not in seen


def test_the_events_carry_no_frame_content():
    TRACE.clear()
    p = _pair()
    p.alice.start_session(p.bob_jid)
    for e in TRACE.events():
        if e.get("component") != "otr":
            continue
        for value in (e.get("fields") or {}).values():
            assert "?OTRv4" not in str(value)
            assert len(str(value)) < 200
