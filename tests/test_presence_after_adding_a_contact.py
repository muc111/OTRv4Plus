# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The reported bug, end to end: add a contact, and presence stays "unknown".

    1. User adds a contact.
    2. Contact is successfully saved.
    3. UI still says "Presence unknown".
    4. It never changes.

`tests/test_presence_state.py` covers the model. This covers the PATH: the
roster entry, the subscription, the presence stanza, the reconnect, and what
`OtrApp.contacts()` reports at each step -- which is what the Android UI
renders.

The fix is not a different string. Step 3 is the *correct* thing to say at step
3: the server has not sent that contact's presence yet, and it will not until
they approve the request. What was broken is that nothing could ever move it
off "unknown", because the model had no way to record having been told.
"""

import pytest

import otrv4plus_presence as presence
from android_bridge.app import OtrApp, Transport
from android_bridge.events import SecurityState

ALICE = "alice@xmpp-elite.i2p"
BOB = "bob@xmpp-elite.i2p"


class Engine:
    def get_security_level(self, peer):
        return 0

    def get_smp_status(self, peer):
        return {"state": "IDLE", "verified": False, "failed": False}

    def get_smp_progress(self, peer):
        return (0, 4)


class FakeTransport(Transport):
    """A roster that behaves like the real one: an added contact appears with
    `pending_out` set until the far side answers."""

    def __init__(self):
        self.sent = []
        self.entries = []
        self.added = []

    def send(self, peer, payload):
        self.sent.append((peer, payload))

    def connect(self):
        pass

    def disconnect(self):
        pass

    def roster(self):
        return list(self.entries)

    def add_contact(self, jid, name=""):
        self.added.append(jid)
        self.entries.append({"jid": jid, "name": name,
                             "subscription": "none", "pending": True})

    def approve(self, jid):
        """The far side accepted: the server pushes an updated roster item."""
        for e in self.entries:
            if e["jid"] == jid:
                e["subscription"] = "both"
                e["pending"] = False


class Sink:
    def __init__(self):
        self.events = []

    def on_event(self, event):
        self.events.append(event)


@pytest.fixture
def app():
    engine, transport, sink = Engine(), FakeTransport(), Sink()
    return OtrApp(engine, transport, sink), transport


def _view(facade, jid):
    for c in facade.contacts():
        if c.jid == jid:
            return c
    return None


# ── the reported sequence ────────────────────────────────────────────────────

class TestAddingAContact:

    def test_the_contact_is_saved(self, app):
        facade, transport = app
        transport.add_contact(ALICE)
        assert _view(facade, ALICE) is not None, "the contact was not saved"

    def test_presence_is_unknown_immediately_after_adding(self, app):
        """CORRECT at this instant. The server has not said anything about
        them, and will not until they approve."""
        facade, transport = app
        transport.add_contact(ALICE)
        assert _view(facade, ALICE).presence == presence.UNKNOWN

    def test_it_is_not_reported_as_offline(self, app):
        """The bug. `.get(jid, False)` said offline, which is a claim about
        the peer rather than an absence of one."""
        facade, transport = app
        transport.add_contact(ALICE)
        assert _view(facade, ALICE).presence != presence.OFFLINE

    def test_a_pending_subscription_is_visible_so_the_ui_can_say_why(self, app):
        facade, transport = app
        transport.add_contact(ALICE)
        assert _view(facade, ALICE).pending is True

    def test_presence_becomes_online_when_the_server_says_so(self, app):
        """The step that could never happen. This is the whole fix."""
        facade, transport = app
        transport.add_contact(ALICE)
        transport.approve(ALICE)
        facade.note_presence(ALICE, online=True)
        view = _view(facade, ALICE)
        assert view.presence == presence.ONLINE
        assert view.online is True

    def test_and_offline_when_it_says_that(self, app):
        facade, transport = app
        transport.add_contact(ALICE)
        transport.approve(ALICE)
        facade.note_presence(ALICE, online=False)
        assert _view(facade, ALICE).presence == presence.OFFLINE

    def test_offline_is_distinguishable_from_never_heard(self, app):
        facade, transport = app
        transport.add_contact(ALICE)
        transport.add_contact(BOB)
        facade.note_presence(ALICE, online=False)
        assert _view(facade, ALICE).presence == presence.OFFLINE
        assert _view(facade, BOB).presence == presence.UNKNOWN


class TestPresenceFromAFullJid:
    """Stanzas arrive per-resource; the roster is keyed bare."""

    def test_a_resourceful_stanza_updates_the_bare_contact(self, app):
        facade, transport = app
        transport.add_contact(ALICE)
        facade.note_presence(ALICE + "/phone", online=True)
        assert _view(facade, ALICE).presence == presence.ONLINE


class TestShowReachesTheView:

    def test_an_away_peer_is_online_and_away(self, app):
        facade, transport = app
        transport.add_contact(ALICE)
        facade.note_presence(ALICE, online=True, show="away")
        view = _view(facade, ALICE)
        assert view.presence == presence.ONLINE
        assert view.presence_show == "away"


# ── the staleness defect ─────────────────────────────────────────────────────

class TestAReconnectDoesNotKeepStalePresence:

    def test_losing_the_stream_returns_everyone_to_unknown(self, app):
        facade, transport = app
        transport.add_contact(ALICE)
        facade.note_presence(ALICE, online=True)
        assert _view(facade, ALICE).presence == presence.ONLINE

        facade.note_presence_lost()

        assert _view(facade, ALICE).presence == presence.UNKNOWN, (
            "a contact still reads ONLINE after the stream carrying that "
            "knowledge died; they may have left an hour ago")

    def test_the_contact_itself_survives_the_drop(self, app):
        """Only the availability is forgotten. Losing the roster entry would
        make the user re-add everybody after a reconnect."""
        facade, transport = app
        transport.add_contact(ALICE)
        facade.note_presence(ALICE, online=True)
        facade.note_presence_lost()
        assert _view(facade, ALICE) is not None

    def test_presence_can_be_relearned_after_reconnecting(self, app):
        facade, transport = app
        transport.add_contact(ALICE)
        facade.note_presence(ALICE, online=True)
        facade.note_presence_lost()
        facade.note_presence(ALICE, online=True)
        assert _view(facade, ALICE).presence == presence.ONLINE


# ── what the discovery view will read ────────────────────────────────────────

class TestOnlinePeers:

    def test_it_lists_only_peers_believed_available(self, app):
        facade, transport = app
        facade.note_presence(ALICE, online=True)
        facade.note_presence(BOB, online=False)
        assert facade.online_peers() == [ALICE]

    def test_it_is_empty_before_anything_is_heard(self, app):
        facade, _ = app
        assert facade.online_peers() == []

    def test_presence_state_is_queryable_directly(self, app):
        facade, _ = app
        facade.note_presence(ALICE, online=True)
        assert facade.presence_state(ALICE) == presence.ONLINE
        assert facade.presence_state(BOB) == presence.UNKNOWN


# ── the guard that made this hard to see ─────────────────────────────────────

class TestContactsStillFailsSafe:
    """The per-entry guard from the earlier handset fix must survive."""

    def test_one_bad_entry_does_not_empty_the_roster(self, app):
        facade, transport = app
        transport.entries = [{"name": "no jid"}, {"jid": BOB}]
        assert [c.jid for c in facade.contacts()] == [BOB]

    def test_a_contact_with_no_presence_still_has_a_view(self, app):
        facade, transport = app
        transport.entries = [{"jid": BOB}]
        view = _view(facade, BOB)
        assert view is not None
        assert view.presence == presence.UNKNOWN
        assert view.security is SecurityState.PLAINTEXT
