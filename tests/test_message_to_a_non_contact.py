# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""One-tap Message to someone online who is not a contact (owner, 2026-10-25).

A non-contact sends us no presence, so their OTRv4+ support was never learnt,
no session started, and a message to them waited for ever with nothing on
screen to say why. Now the first message sends the contact request itself,
says so, and waits -- encrypted only -- for the session that follows their
accepting. Group invitations already worked this way (invite_when_ready).
"""
import io
import os

from android_bridge.app import OtrApp
from android_bridge.events import ErrorOccurred

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BOB = "bob@example.org"


class _Transport:
    def __init__(self, roster=()):
        self._roster = list(roster)
        self.requests = []
        self.sent = []

    def roster(self):
        return self._roster

    def add_contact(self, jid, name=""):
        self.requests.append(jid)

    def send(self, peer, text):
        self.sent.append((peer, text))


def _app(roster=()):
    app = OtrApp.__new__(OtrApp)
    app._transport = _Transport(roster)
    app._message_requested = set()
    app.canonical_peer = lambda p: str(p).lower()
    app.events = []
    app._emit = app.events.append
    return app


def _codes(app):
    return [e.code for e in app.events if isinstance(e, ErrorOccurred)]


def test_a_message_to_a_non_contact_asks_to_add_them_once():
    app = _app()
    app._ask_to_add_for_message(BOB)
    app._ask_to_add_for_message(BOB)
    assert app._transport.requests == [BOB], "one request, not one per message"
    assert _codes(app) == ["waiting_for_contact"]
    assert app._transport.sent == [], "nothing is sent, least of all in the clear"


def test_a_contact_whose_presence_we_see_is_not_asked_again():
    app = _app(roster=[{"jid": BOB, "subscription": "both"}])
    app._ask_to_add_for_message(BOB)
    assert app._transport.requests == [] and _codes(app) == []


def test_the_send_path_uses_it_and_still_holds_the_line():
    with io.open(os.path.join(ROOT, "android_bridge", "app.py"), encoding="utf-8") as fh:
        src = fh.read()
    branch = src[src.index('if capability in ("checking", "unknown", "offline"):'):]
    branch = branch[:branch.index("return self.SEND_QUEUED")]
    assert branch.index("self._hold(peer, body, message_id, reply_to)") < \
        branch.index("self._ask_to_add_for_message(peer)"), "held first, then the request"


def test_the_screen_says_what_happens_next():
    with io.open(os.path.join(ROOT, "android", "app", "src", "main", "java", "org", "otrv4plus",
                              "android", "chat", "FailureText.kt"), encoding="utf-8") as fh:
        text = fh.read()
    line = text[text.index('"waiting_for_contact" to'):].split("\n", 1)[0]
    assert "contact request was sent" in line and "encrypted" in line
    from android_bridge.codes import CODES
    assert "waiting_for_contact" in CODES


def test_wipe_forgets_who_was_asked():
    with io.open(os.path.join(ROOT, "android_bridge", "app_wipe.py"), encoding="utf-8") as fh:
        assert '"_message_requested", set()).clear()' in fh.read()
