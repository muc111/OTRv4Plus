# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The terminal client's outbox (owner's rules, 2026-10-04): a line to an
OTRv4+ contact waits for encryption and is sent when it is up -- the engine's
own queue used to drop it -- and a contact without OTRv4+ gets it in the clear
once seen online."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

xmpp = pytest.importorskip("otrv4plus_xmpp")
from otrv4plus_mode import OtrMode                               # noqa: E402

BOB = "bob@example.i2p"


class _Client:
    def __init__(self):
        self.sent = []
        self.started = []
        self.encrypted_ok = False
        self.boundjid = type("J", (), {"bare": "alice@example.i2p"})()
        self.otr = self
        self._otr_mode = OtrMode()
        self._encrypted = set()
        self._smp_reported = set()
        self._outbox = {}
        self._otr_capable = set()
        self._hs_started = {}
        self._hs_hist = []
        self._peer_resources = {}
        self._tui_enabled = False
        self._plain_echo = None
        self.PLAIN_ECHO_MAX_ROWS = xmpp.OTRv4PlusXMPP.PLAIN_ECHO_MAX_ROWS
        for name in ("send_user_text", "_echo_sent", "_erase_plain_echo",
                     "_echo_plain_sent", "_hold", "_handshake_eta",
                     "_presence_ready", "_flush_outbox"):
            setattr(self, name, getattr(xmpp.OTRv4PlusXMPP, name).__get__(self))
        self.OUTBOX_MAX = xmpp.OTRv4PlusXMPP.OUTBOX_MAX
        self.HANDSHAKE_TYPICAL_SECONDS = xmpp.OTRv4PlusXMPP.HANDSHAKE_TYPICAL_SECONDS

    def start_otr(self, peer):
        self.started.append(peer)
        self._hs_started[peer] = 0.0
        self._otr_mode.request(peer)

    def handle_outgoing_message(self, peer, text):
        return ("?OTRv4 ct:" + text, True) if self.encrypted_ok else (None, False)

    def send_otr_fragmented(self, peer, payload):
        self.sent.append((peer, payload))


def test_an_otrv4_contact_never_gets_plaintext_and_the_line_is_sent_later():
    c = _Client()
    c._otr_capable.add(BOB)
    c._peer_resources[BOB] = {"phone"}
    c.send_user_text(BOB, "hello")
    assert c.sent == [] and c.started == [BOB]
    c.encrypted_ok = True
    c._encrypted.add(BOB)
    c._flush_outbox(BOB)
    assert c.sent == [(BOB, "?OTRv4 ct:hello")]
    assert c._outbox == {}


def test_a_contact_not_seen_online_waits():
    c = _Client()
    c.send_user_text(BOB, "hello")
    assert c.sent == [] and c._outbox[BOB] == ["hello"]


def test_a_contact_online_without_otrv4_gets_the_waiting_lines_in_the_clear():
    c = _Client()
    c.send_user_text(BOB, "hello")
    c._peer_resources[BOB] = {"desktop"}
    c._presence_ready(BOB)
    assert c.sent == [(BOB, "hello")]


def test_a_capable_contact_online_starts_otr_from_the_lower_jid():
    c = _Client()                                     # alice < bob
    c._otr_capable.add(BOB)
    c._presence_ready(BOB)
    assert c.started == [BOB]
    other = _Client()
    other.boundjid = type("J", (), {"bare": "zed@example.i2p"})()
    other._otr_capable.add(BOB)
    other._presence_ready(BOB)
    assert other.started == []                        # the higher JID waits
