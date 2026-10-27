# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Both sides' copies of a chat go when someone publishes its keys.

Owner, 2026-10-27: "Otr chat publish keys appears to work on the client
which I pressed publish keys however the other client didn't delete the
chat history ... confirm keys published on both clients ... print a line in
chat and wipe all chat history behind this print", and the same for MLS
groups. Only on the button (owner's choice): a session also ends at sign-out
or quit, and a group's keys are also published by themselves after every
rotation, and none of that clears anything.

  * 1:1: the presser's app tells the contact's app inside the session
    (KEYS_PUBLISHED_SIGNAL), then closes it. Each side's app emits
    KeysPublished once ITS OWN closing messages for the chat are confirmed
    by its own server -- the furthest either can know.
  * Groups: once the presser's keys are out, it posts GROUP_KEYS_MARK to the
    group, and each member's app emits KeysPublished on receipt.
The apps then remove that conversation's messages from before `before_ms`
and show one line (ChatState, DeniableChatTest).
"""
from __future__ import annotations

import pytest

pytest.importorskip("otrv4_core")

import test_deniability_wire_audit as W                           # noqa: E402
from test_deniability_wire_audit import _own_rate_limiter         # noqa: E402,F401
from android_bridge.app_deniable import KEYS_PUBLISHED_SIGNAL     # noqa: E402
from android_bridge.events import KeysPublished                   # noqa: E402


class _Confirming(W.Link):
    def __init__(self, wire, jid, answer=True):
        super().__init__(wire, jid)
        self.answer = answer

    def confirm_received(self, timeout=15.0):
        return self.answer


class _Sink:
    def __init__(self):
        self.events = []

    def on_event(self, event):
        self.events.append(event)

    def published(self):
        return [e for e in self.events if isinstance(e, KeysPublished)]


def _pair(alice_confirms=True, bob_confirms=True):
    wire, alice, bob = W._pair()
    alice._transport = _Confirming(wire, W.ALICE, alice_confirms)
    bob._transport = _Confirming(wire, W.BOB, bob_confirms)
    sinks = (_Sink(), _Sink())
    alice.set_event_sink(sinks[0])
    bob.set_event_sink(sinks[1])
    return wire, alice, bob, sinks


def test_both_sides_are_told_once_their_own_server_confirms():
    wire, alice, bob, (a, b) = _pair()
    W._talk(wire, alice, bob, W.SCRIPT[:4])
    assert alice.make_chat_deniable(W.BOB, restart=False) == "made_deniable"
    [ours] = a.published()
    assert ours.peer == W.BOB and ours.by == "" and not ours.group and ours.before_ms > 0
    assert b.published() == [], "not before Bob's own keys are confirmed"
    assert bob._resend_closings_now() is True     # Bob's app's confirmation round
    [theirs] = b.published()
    assert theirs.peer == W.ALICE and theirs.by == W.ALICE and not theirs.group


def test_the_contact_is_told_inside_the_session_before_it_closes():
    wire, alice, bob, _ = _pair()
    W._talk(wire, alice, bob, W.SCRIPT[:2])
    n = len(wire.frames)
    seen = []
    real = bob.on_keys_published_signal
    bob.on_keys_published_signal = lambda peer: (
        seen.append(bob._engine.has_encrypted_session(peer)), real(peer))
    alice.make_chat_deniable(W.BOB, restart=False)
    assert seen == [True], "it arrived inside the session, before the close"
    assert all(KEYS_PUBLISHED_SIGNAL not in body for _f, _t, body in wire.frames[n:]), \
        "never on the wire in the clear"


def test_an_unconfirmed_side_is_told_when_its_server_confirms_later():
    wire, alice, bob, (a, b) = _pair(bob_confirms=False)
    W._talk(wire, alice, bob, W.SCRIPT[:4])
    alice.make_chat_deniable(W.BOB, restart=False)
    assert bob._resend_closings_now() is False and b.published() == []
    bob._transport.answer = True
    bob._resend_closings_now()
    assert len(b.published()) == 1


@pytest.mark.parametrize("ending", ["sign_out", "end_session"])
def test_an_ordinary_end_clears_nothing(ending):
    """Sign-out (or the contact ending the session) publishes keys too, and
    clears nothing on either side: only the button does."""
    wire, alice, bob, (a, b) = _pair()
    W._talk(wire, alice, bob, W.SCRIPT[:4])
    if ending == "sign_out":
        alice.shutdown()
    else:
        alice._engine.end_session(W.BOB)
        alice._send_final_revelations()
        alice.confirm_closings()
    bob._resend_closings_now()
    assert a.published() == [] and b.published() == []


def test_offline_at_the_press_the_contact_is_told_when_it_is_back():
    wire, alice, bob, (a, b) = _pair()
    W._talk(wire, alice, bob, W.SCRIPT[:4])
    alice._transport.is_connected = False
    n = len(wire.frames)
    assert alice.make_chat_deniable(W.BOB, restart=False) == "made_deniable_unconfirmed"
    assert len(wire.frames) == n and a.published() == []
    alice._transport.is_connected = True
    assert alice._resend_closings_now() is True
    assert len(a.published()) == 1
    bob._resend_closings_now()
    [theirs] = b.published()
    assert theirs.by == W.ALICE, "the message went first, with the closing messages"


def test_a_retry_round_sends_the_message_once_only():
    """A second copy is from a session the contact has closed, and their app
    would answer it by starting a new one."""
    wire, alice, bob, _ = _pair(alice_confirms=False)
    W._talk(wire, alice, bob, W.SCRIPT[:4])
    alice.make_chat_deniable(W.BOB, restart=False)
    assert all(len(e) == 4 for e in alice._closings()), "only closing messages kept"
    alice._transport.answer = True
    before = len(wire.frames)
    alice._resend_closings_now()
    assert all(f == W.ALICE for f, _t, _b in wire.frames[before:]), \
        "no handshake from Bob: nothing reached him from a closed session but closings"
