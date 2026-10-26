# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Make Chat Deniable asks the server to confirm the closing messages.

Owner (2026-10-26): add the confirmation Wipe & Exit and sign-out have to
Make Chat Deniable. The keys are only published once the closing messages
that carry them are on the wire (tests/test_deniability_wire_audit.py shows
what is lost if they are not). Here the stream stays up, so the proof is a
XEP-0199 ping to our own server after them: a server answers an IQ only after
reading every stanza before it. Unconfirmed ones are kept and sent again,
up to CLOSING_MAX_TRIES times, while the app runs. The new session does not
wait for a "yes": it starts once the server was asked, confirmed or not, and
the app says which (audit 2026-10-26).
"""
from __future__ import annotations

import asyncio
import os
import re

import pytest

slixmpp = pytest.importorskip("slixmpp")
pytest.importorskip("otrv4_core")

import otrv4plus_ping                                              # noqa: E402,F401
from android_bridge.transport import XmppTransport                 # noqa: E402
import test_deniability_wire_audit as W                            # noqa: E402
from test_deniability_wire_audit import _own_rate_limiter         # noqa: E402,F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HEADER = (b"<?xml version='1.0'?><stream:stream xmlns='jabber:client' "
          b"xmlns:stream='http://etherx.jabber.org/streams' id='s1' "
          b"from='example.test' version='1.0'><stream:features/>")


# ── the transport: a real slixmpp client, a scripted server ─────────────────

async def _confirm(answers=True, with_ping=True, budget=5.0):
    got = bytearray()

    async def handle(reader, writer):
        writer.write(HEADER)
        await writer.drain()
        while True:
            data = await reader.read(65536)
            if not data:
                break
            got.extend(data)
            for m in re.finditer(rb'<iq id="([^"]+)" type="get"', bytes(data)):
                if answers:
                    writer.write(b"<iq type='result' id='" + m.group(1)
                                 + b"' from='example.test' to='me@example.test/r'/>")
                    await writer.drain()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    client = slixmpp.ClientXMPP("me@example.test/r", "unused")
    if with_ping:
        client.register_plugin("xep_0199")
    client.enable_plaintext, client.enable_starttls, client.enable_direct_tls = True, False, False
    client.connect("127.0.0.1", server.sockets[0].getsockname()[1])
    await client.wait_until("connected", 5)
    await asyncio.sleep(0.05)
    client.event("session_start")                       # bound, as after sign-in
    client.send_message(mto="bob@example.test", mbody="CLOSING-MESSAGE")
    start = asyncio.get_running_loop().time()
    ok = await XmppTransport._confirm_received(None, client, budget)
    took = asyncio.get_running_loop().time() - start
    client.abort()
    server.close()
    return ok, bytes(got), took


def test_the_server_confirms_and_the_closing_message_came_first():
    ok, got, _took = asyncio.run(_confirm())
    assert ok
    assert 0 <= got.find(b"CLOSING-MESSAGE") < got.find(b"urn:xmpp:ping")


def test_no_answer_is_not_a_confirmation_and_costs_only_the_budget():
    ok, got, took = asyncio.run(_confirm(answers=False, budget=1.0))
    assert ok is False and b"CLOSING-MESSAGE" in got
    assert took < 3.0


def test_no_way_to_ask_is_never_read_as_yes():
    ok, _got, _took = asyncio.run(_confirm(with_ping=False))
    assert ok is False


# ── the app: confirmation before the new session, and re-sending ────────────

class _Confirming(W.Link):
    def __init__(self, wire, jid, answer=True):
        super().__init__(wire, jid)
        self.answer, self.asked = answer, []

    def confirm_received(self, timeout=15.0):
        self.asked.append(len(self.wire.frames))
        return self.answer


def _pair(answer=True):
    wire, alice, bob = W._pair()
    alice._transport = _Confirming(wire, W.ALICE, answer)
    return wire, alice, bob


# Renamed (audit 2026-10-26): it shows the order -- closing messages, the
# question, then the new handshake -- for a server that answers. It does not
# show that an unanswered question stops the new session; the residual test
# below shows that it does not.
def test_the_new_session_starts_after_the_server_is_asked():
    wire, alice, bob = _pair()
    W._talk(wire, alice, bob, W.SCRIPT[:4])
    n = len(wire.frames)
    assert alice.make_chat_deniable(W.BOB) == "made_deniable"
    [asked_at] = alice._transport.asked
    closing = [i for i in range(n, asked_at) if wire.frames[i][0] == W.ALICE]
    after = [i for i in range(asked_at, len(wire.frames)) if wire.frames[i][0] == W.ALICE]
    assert closing, "the closing messages went before the question"
    assert after and all(W._data(wire.frames[i][2]) is None for i in after[:1]), \
        "what follows is the new handshake, not data"
    assert alice._closings() == [], "confirmed: nothing kept"


def test_residual_unconfirmed_the_new_session_starts_anyway_and_the_app_says_so():
    """No answer within the budget: the old session is closed and its keys
    retired either way, the new session starts, and the result says the
    publication is not confirmed (DeniableChat.outcome shows that)."""
    wire, alice, bob = _pair(answer=False)
    W._talk(wire, alice, bob, W.SCRIPT[:4])
    n = len(wire.frames)
    assert alice.make_chat_deniable(W.BOB) == "made_deniable_unconfirmed"
    [asked_at] = alice._transport.asked
    after = [i for i in range(asked_at, len(wire.frames)) if wire.frames[i][0] == W.ALICE]
    assert asked_at > n and after, "asked, then the new handshake went anyway"
    assert alice._closings(), "the closing messages are kept for re-sending"


def test_unconfirmed_it_says_so_keeps_them_and_sends_them_again():
    wire, alice, bob = _pair(answer=False)
    lines = W._talk(wire, alice, bob, W.SCRIPT)
    assert alice.make_chat_deniable(W.BOB, restart=False) == "made_deniable_unconfirmed"
    kept = list(alice._closings())
    assert kept and all(e[2] for e in kept)
    alice._transport.answer = True
    before = len(wire.frames)
    assert alice._resend_closings_now() is True
    resent = wire.frames[before:]
    assert {body for _f, _t, body in resent} == {e[1] for e in kept}, "the same messages again"
    assert alice._closings() == []
    _keys, missing = W._audit(wire, lines)
    assert missing == []


def test_offline_at_the_press_they_go_when_it_is_back():
    wire, alice, bob = _pair()
    lines = W._talk(wire, alice, bob, W.SCRIPT)
    n = len(wire.frames)
    alice._transport.is_connected = False
    assert alice.make_chat_deniable(W.BOB, restart=False) == "made_deniable_unconfirmed"
    assert len(wire.frames) == n, "nothing could go"
    keys_now = W._revealed_on_the_wire(wire.frames)
    assert any(W._key_for(W._data(wire.frames[i][2]), keys_now) is None for i in lines)
    alice._transport.is_connected = True
    assert alice._resend_closings_now() is True
    _keys, missing = W._audit(wire, lines)
    assert missing == [], "published once back online"


def test_a_closing_message_is_given_up_after_its_tries():
    wire, alice, bob = _pair(answer=False)
    W._talk(wire, alice, bob, W.SCRIPT[:2])
    alice.make_chat_deniable(W.BOB, restart=False)
    for _ in range(alice.CLOSING_MAX_TRIES + 1):
        alice._resend_closings_now()
    assert alice._closings() == []


def test_the_ui_tick_retries_and_wipe_forgets():
    src = open(os.path.join(ROOT, "android_bridge", "connection.py"), encoding="utf-8").read()
    tick = src[src.index("    def drain_events("):src.index("    def add_contact(")]
    assert "self._app.resend_unconfirmed_closings()" in tick
    wire, alice, bob = _pair(answer=False)
    W._talk(wire, alice, bob, W.SCRIPT[:2])
    alice.make_chat_deniable(W.BOB, restart=False)
    assert alice._closings()
    alice.wipe()
    assert alice._closings() == []


def test_a_contact_offline_at_the_press_gets_it_when_they_are_back():
    """The transport refuses an OTR frame with no capable resource known
    (the contact is offline): kept, and sent once they are."""
    wire, alice, bob = _pair()
    lines = W._talk(wire, alice, bob, W.SCRIPT)
    real_send = alice._transport.send

    def unavailable(peer, payload):
        raise RuntimeError("otrv4plus_unavailable")

    alice._transport.send = unavailable
    assert alice.make_chat_deniable(W.BOB, restart=False) == "made_deniable_unconfirmed"
    assert alice._closings() and not any(e[2] for e in alice._closings())
    alice._transport.send = real_send
    assert alice._resend_closings_now() is True
    _keys, missing = W._audit(wire, lines)
    assert missing == []


# ── the terminal client: the same confirmation ──────────────────────────────

def test_the_terminal_confirms_the_same_way():
    xmpp = pytest.importorskip("otrv4plus_xmpp")

    async def run(answers):
        holder = {}
        real = XmppTransport._confirm_received

        async def as_terminal(_self, client, budget):
            holder["client"] = client
            return await xmpp.OTRv4PlusXMPP._server_confirms(client, budget)

        XmppTransport._confirm_received = as_terminal
        try:
            return await _confirm(answers=answers, budget=1.0)
        finally:
            XmppTransport._confirm_received = real

    ok, got, _ = asyncio.run(run(True))
    assert ok and got.find(b"CLOSING-MESSAGE") < got.find(b"urn:xmpp:ping")
    ok, _got, _ = asyncio.run(run(False))
    assert ok is False
    src = open(xmpp.__file__, encoding="utf-8").read()
    fn = src[src.index("    def make_deniable(self, peer):"):src.index("    def start_otr(self, peer):")]
    assert "_confirm_then_restart" in fn
    body = fn[fn.index("async def _confirm_then_restart"):]
    assert body.index("await self._server_confirms") < body.index("self.start_otr(peer)")
