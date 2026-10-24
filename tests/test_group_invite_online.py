# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Inviting people picked from "Invite people online" (device report 2026-10-24).

The picker lists everyone the server says is online, contacts or not. A
non-contact sends us no presence, so their OTRv4+ support was never learnt, no
session started, and the invitation waited forever -- while the dialog said
"1 invitation sent". Now a non-contact is sent a contact request and the
answer says so; the invitation goes once they accept, through the same path
a contact's takes; and the screen counts only what was sent.
"""
import os
import types


from android_bridge.app import OtrApp
from android_bridge.events import SecurityState

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BOB = "bob@example.org"


class _Transport:
    def __init__(self, roster):
        self._roster = roster
        self.requests = []

    def roster(self):
        return self._roster

    def add_contact(self, jid, name=""):
        self.requests.append(jid)


def _app(roster, capability="unknown", secure=False):
    app = OtrApp.__new__(OtrApp)
    app._transport = _Transport(roster)
    app._invite_after_otr = {}
    app._outbox = {}
    app.canonical_peer = lambda p: str(p).lower()
    app.security_state = lambda p: (SecurityState.ENCRYPTED if app._secure[0]
                                    else SecurityState.PLAINTEXT)
    app._secure = [secure]
    app.ensure_otr = lambda p: capability
    app.sent = []
    app._groups = types.SimpleNamespace(
        invite=lambda room, peer: app.sent.append((room, peer)))
    return app


def test_a_non_contact_is_sent_a_contact_request_and_told_so():
    app = _app(roster=[])
    assert app.invite_when_ready("room@muc", BOB) == "waiting_for_contact"
    assert app._transport.requests == [BOB]
    assert app._invite_after_otr == {BOB: ["room@muc"]}, "still queued for when they accept"
    assert app.sent == []


def test_a_contact_who_is_offline_just_waits_no_request():
    app = _app(roster=[{"jid": BOB, "subscription": "both"}], capability="offline")
    assert app.invite_when_ready("room@muc", BOB) == "waiting_for_otr"
    assert app._transport.requests == []


def test_a_request_already_sent_is_not_sent_twice_but_still_waits():
    app = _app(roster=[{"jid": BOB, "subscription": "to"}])
    assert app.invite_when_ready("room@muc", BOB) == "waiting_for_otr"
    assert app._transport.requests == []


def test_once_the_session_is_up_the_queued_invitation_goes():
    app = _app(roster=[])
    app.invite_when_ready("room@muc", BOB)
    app._secure[0] = True                   # they accepted; OTRv4+ came up
    app._flush_outbox(BOB)
    assert app.sent == [("room@muc", BOB)]
    assert BOB not in app._invite_after_otr


def test_an_established_session_sends_at_once():
    app = _app(roster=[], secure=True)
    assert app.invite_when_ready("room@muc", BOB) == "sent"
    assert app.sent == [("room@muc", BOB)]


def test_the_screen_counts_only_what_was_sent():
    vm = open(os.path.join(ROOT, "android", "app", "src", "main", "java", "org", "otrv4plus",
                           "android", "chat", "ChatViewModel.kt"), encoding="utf-8").read()
    body = vm[vm.index("fun inviteManyToGroup"):]
    body = body[:body.index("\n    }\n")]
    assert 'outcome?.ok == true && code == "ok"' in body
    text = open(os.path.join(ROOT, "android", "app", "src", "main", "java", "org", "otrv4plus",
                             "android", "chat", "GroupText.kt"), encoding="utf-8").read()
    assert '"waiting_for_contact" ->' in text and '"waiting_for_otr" ->' in text


def test_the_controller_passes_both_waiting_codes_through():
    from android_bridge import connection_groups
    src = open(connection_groups.__file__, encoding="utf-8").read()
    assert '"waiting_for_contact"' in src
