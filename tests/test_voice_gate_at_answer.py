# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The SMP gate is checked again when a call is answered, on both sides.

It used to be checked only when the INVITE arrived (receiver) and when the
call was placed (caller). Verification can end in between: the OTRv4+
session may be replaced by a new handshake -- a peer restart, a recovered
DAKE -- and a replacement starts unverified. Answering, or proceeding on an
ACCEPT, on the old verdict would connect a call to keys nobody has checked.
"""
import asyncio

import pytest

V = pytest.importorskip("otrv4plus_voice")


class _Session:
    def __init__(self, state, initiator):
        self.state = state
        self.is_initiator = initiator
        self.call_id = bytes(16)
        self.transitions = []
        self.derived = False

    def try_transition(self, state):
        self.transitions.append(state)
        return True

    def responder_derive(self, *_a):
        self.derived = True
        raise AssertionError("keys were derived for an unverified peer")

    def initiator_derive(self, *_a):
        self.derived = True
        raise AssertionError("keys were derived for an unverified peer")


def _manager(session, verified):
    mgr = object.__new__(V.VoiceCallManager)
    mgr._debug, mgr._debug_t0 = False, {}
    mgr._calls = {"bob@x.i2p": session}
    mgr.signals, mgr.ended = [], []
    mgr._smp_verified = lambda peer: verified
    mgr._stop_ringing = lambda peer: None
    mgr._cancel_timeout = lambda peer: None
    mgr._signal = lambda peer, verb, fields=(): mgr.signals.append((verb, fields)) or True
    mgr._call_for = lambda peer, cid: session

    async def end_call(peer, notify_peer=True):
        mgr.ended.append(peer)
    mgr.end_call = end_call
    return mgr


def test_the_receiver_does_not_answer_a_peer_no_longer_verified(monkeypatch):
    monkeypatch.setattr(V, "_print", lambda *a, **k: None)
    s = _Session(V.CallState.RINGING, initiator=False)
    mgr = _manager(s, verified=False)
    asyncio.run(mgr.answer_call("bob@x.i2p"))
    assert not s.derived
    assert V.CallState.CONNECTING not in s.transitions
    assert mgr.signals and mgr.signals[0][0] == "REJECT"
    assert mgr.signals[0][1][1] == "unverified"
    assert mgr.ended == ["bob@x.i2p"]


def test_the_caller_does_not_proceed_on_an_accept_from_a_peer_no_longer_verified(monkeypatch):
    monkeypatch.setattr(V, "_print", lambda *a, **k: None)
    s = _Session(V.CallState.INVITING, initiator=True)
    mgr = _manager(s, verified=False)
    fields = ["00" * 16, "00" * V.VoiceKeyExchange.PUB_LEN,
              "00" * V.MLKEM_CT_LEN, "00" * V.CONFIRM_LEN]
    asyncio.run(mgr._on_accept("bob@x.i2p", fields))
    assert not s.derived
    assert mgr.signals[0][0] == "REJECT" and mgr.signals[0][1][1] == "unverified"
    assert mgr.ended == ["bob@x.i2p"]


def test_a_verified_peer_still_gets_to_key_agreement(monkeypatch):
    monkeypatch.setattr(V, "_print", lambda *a, **k: None)
    s = _Session(V.CallState.RINGING, initiator=False)
    mgr = _manager(s, verified=True)
    s.responder_derive = lambda *_a: (_ for _ in ()).throw(RuntimeError("reached"))
    s._peer_x448 = s._peer_mlkem_ek = b""
    asyncio.run(mgr.answer_call("bob@x.i2p"))
    assert V.CallState.CONNECTING in s.transitions
    assert ("REJECT", (s.call_id.hex(), "bad-kex")) in mgr.signals
