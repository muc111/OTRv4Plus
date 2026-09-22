#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Removing a contact has to remove them.

WHAT REMOVAL DID
================
It took the roster entry away, and nothing else. Measured through the
controller with the transport confirming the operation:

    before remove: presence=online last_activity=True
    remove_contact: {'ok': True, 'code': 'ok', 'detail': ''}
    after remove : presence=online last_activity=True

So a contact the user had just removed went on reading ONLINE, indefinitely,
from a subscription that no longer existed. `PresenceBook.forget` has said
since it was written that "what we learned under a subscription we no longer
hold is not something we are entitled to keep showing" -- and had no caller
at all.

The Kotlin half was the same shape: `ChatState.conversations()` unions the
roster with the message store AND the locally saved list, and nothing forgot
the saved record, so the row came straight back -- now labelled "remembered
here, not confirmed by the server" -- with no way left to get rid of it.

WHAT REMOVAL MUST NOT TAKE
==========================
The session, the pinned fingerprint and the history. None of them came from
the subscription, and each is asserted below so a future "clear everything on
remove" cannot quietly take it:

  * a fingerprint is long-term identity about a PEER, and dropping it turns
    the next conversation into a fresh trust-on-first-use decision -- the
    moment this project most wants to be visible;
  * history outlives the roster entry, because deleting what was said because
    somebody was unsubscribed destroys data the user did not ask to lose;
  * a live encrypted session is not made less safe by a roster change.
"""

import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

otr = pytest.importorskip("otrv4_")
pytest.importorskip("otrv4_core")

from android_bridge.app import OtrApp, Transport                  # noqa: E402
from android_bridge.connection import ConnectionController, SamProbe  # noqa: E402
from android_bridge.events import SecurityState                   # noqa: E402
from android_bridge.settings import ConnectionProfile             # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ANDROID = os.path.join(ROOT, "android", "app", "src", "main", "java", "org",
                       "otrv4plus", "android")

PEER = "bob@example.test"
ME = "alice@example.test"


class Wire(Transport):
    """A transport that accepts roster calls and can refuse them."""

    is_connected = True

    def __init__(self):
        self.sent = []
        self.removed = []
        self.refuse = None
        self.peer_app = None
        self.peer_id = None

    def send(self, peer, payload):
        text = (payload.decode("utf-8", errors="replace")
                if isinstance(payload, (bytes, bytearray)) else str(payload))
        self.sent.append((peer, text))
        if self.peer_app is not None:
            self.peer_app.receive_message(self.peer_id, text)

    def connect(self): pass
    def disconnect(self): pass
    def roster(self): return []

    def remove_contact(self, jid):
        if self.refuse is not None:
            raise self.refuse
        self.removed.append(jid)


def _manager():
    directory = tempfile.mkdtemp()
    config = otr.OTRConfig(test_mode=True)
    for attribute, name in (("trust_db_path", "trust.json"),
                            ("smp_secrets_path", "smp.json"),
                            ("key_storage_path", "keys")):
        if hasattr(config, attribute):
            setattr(config, attribute, os.path.join(directory, name))
    return otr.EnhancedSessionManager(config=config)


class Setup:
    """An app, its controller, and the wire underneath both."""

    def __init__(self):
        self.wire = Wire()
        self.app = OtrApp(_manager(), self.wire)
        self.controller = ConnectionController(
            self.app, ConnectionProfile(jid=ME, server="server.i2p"),
            transport_factory=lambda *a, **k: self.wire,
            prober=lambda _p: SamProbe(True, "ok", "fine", "3.1"))
        self.controller._transport = self.wire


@pytest.fixture
def known():
    """A peer we have heard from and heard about."""
    otr._dake1_rate_limiter._attempts.clear()
    setup = Setup()
    setup.app.note_presence(PEER, True, "chat")
    setup.app.receive_message(PEER, "hello")
    assert setup.app.presence_state(PEER) == "online"
    return setup


class TestWhatRemovalTakes:

    def test_the_removal_reaches_the_transport(self, known):
        assert known.controller.remove_contact(PEER)["ok"] is True
        assert known.wire.removed == [PEER]

    def test_their_presence_is_forgotten(self, known):
        known.controller.remove_contact(PEER)
        assert known.app.presence_state(PEER) == "unknown", (
            "a contact who has just been removed still reads as online, from "
            "a subscription that no longer exists")

    def test_their_last_seen_is_forgotten(self, known):
        known.controller.remove_contact(PEER)
        assert known.app._last_activity.get(PEER) is None

    @pytest.mark.parametrize("spelling", [
        PEER, "Bob@Example.TEST", "bob@example.test/phone",
        "BOB@EXAMPLE.TEST/Laptop"])
    def test_any_spelling_removes_the_same_person(self, known, spelling):
        known.controller.remove_contact(spelling)
        assert known.app.presence_state(PEER) == "unknown"

    def test_removing_one_contact_does_not_touch_another(self, known):
        known.app.note_presence("carol@example.test", True, "chat")
        known.controller.remove_contact(PEER)
        assert known.app.presence_state("carol@example.test") == "online", (
            "removing one contact discarded what was known about another")


class TestARefusedRemovalChangesNothing:
    """A removal the server did not perform has changed nothing, and
    discarding the peer's presence because the request FAILED would make the
    contact list wrong in the other direction."""

    def test_a_refused_removal_keeps_the_presence(self, known):
        known.wire.refuse = RuntimeError("no")
        assert known.controller.remove_contact(PEER)["ok"] is False
        assert known.app.presence_state(PEER) == "online"

    def test_a_removal_with_no_transport_keeps_the_presence(self, known):
        known.controller._transport = None
        result = known.controller.remove_contact(PEER)
        assert result["code"] == "not_connected"
        assert known.app.presence_state(PEER) == "online"


class TestWhatRemovalMustNotTake:

    @pytest.fixture
    def encrypted(self):
        """Two bridges with a real session, and the roster call wired."""
        otr._dake1_rate_limiter._attempts.clear()
        local, remote = Setup(), Setup()
        local.wire.peer_app, local.wire.peer_id = remote.app, ME
        remote.wire.peer_app, remote.wire.peer_id = local.app, PEER
        local.app.start_session(PEER)
        assert local.app.security_state(PEER) is not SecurityState.PLAINTEXT, \
            "the fixture did not establish a session"
        return local

    def test_the_session_survives(self, encrypted):
        """A roster change does not make a live session less safe, and tearing
        it down mid-conversation would be a surprise rather than a
        protection."""
        before = encrypted.app.security_state(PEER)
        encrypted.controller.remove_contact(PEER)
        assert encrypted.app.security_state(PEER) is before
        assert encrypted.app._engine.has_session(PEER) is True

    def test_the_pinned_fingerprint_survives(self, encrypted):
        """Dropping it would turn the next conversation into a fresh
        trust-on-first-use decision."""
        engine = encrypted.app._engine
        # Pinned deliberately rather than hoping the handshake did it: the
        # point of this test is that a pin SURVIVES a removal, and a test that
        # passes because there was nothing to lose proves nothing.
        engine.trust_db.add_trust(PEER, "aa:bb:cc:dd")
        assert engine.trust_db.is_trusted(PEER, "aa:bb:cc:dd")

        before = dict(engine.trust_db.list_trusted())
        encrypted.controller.remove_contact(PEER)

        assert dict(engine.trust_db.list_trusted()) == before, (
            "removing a contact discarded a pinned fingerprint, so the next "
            "conversation becomes a fresh trust-on-first-use decision")
        assert engine.trust_db.get_trusted_fingerprint(PEER) == "aa:bb:cc:dd"

    def test_the_conversation_can_still_be_used(self, encrypted):
        """The strongest form of "the session survived": send through it."""
        encrypted.controller.remove_contact(PEER)
        before = len(encrypted.wire.sent)
        assert encrypted.app.send_message(PEER, "still here") is True
        assert len(encrypted.wire.sent) > before


class TestTheAndroidHalfForgetsTheLocalRecord:
    """Compose cannot run here, so the wiring is asserted structurally; the
    behaviour it protects -- that `conversations()` unions the saved list --
    is driven in `ChatStateTest` and `SavedContactsTest`."""

    @staticmethod
    @pytest.fixture(scope="class")
    def remove_body():
        source = open(os.path.join(ANDROID, "chat", "ChatViewModel.kt"),
                      encoding="utf-8").read()
        start = source.index("fun removeContact(")
        return source[start:source.index("\n    /**", start)]

    def test_it_forgets_the_saved_contact(self, remove_body):
        assert "savedContacts.forget(" in remove_body, (
            "the local record survives the removal, so the row comes back "
            "from the saved list with no way left to get rid of it")

    def test_it_forgets_only_on_a_confirmed_removal(self, remove_body):
        assert "if (result.ok) state.savedContacts.forget(" in remove_body, (
            "the local record is dropped whether or not the server performed "
            "the removal")

    def test_it_does_not_delete_the_history(self, remove_body):
        for destructive in ("forgetAccount", "store.clear", "messages.clear"):
            assert destructive not in remove_body, (
                "removing a contact deletes what was said; a conversation "
                "outlives the roster entry")

    def test_adding_a_contact_still_saves_only_on_success(self):
        """The mirror image, asserted here so the pair cannot drift."""
        source = open(os.path.join(ANDROID, "chat", "ChatViewModel.kt"),
                      encoding="utf-8").read()
        start = source.index("fun addContact(")
        body = source[start:source.index("\n    /**", start)]
        assert "if (result.ok) {" in body and "savedContacts.save(" in body


class TestTheSavedRecordIsReadBackCanonically:
    """`save`, `forget` and `isSaved` all key through `ChatState.bare`. A
    record read back without folding would be a key none of them can reach:
    present in the list, impossible to remove."""

    @staticmethod
    def _decode_body():
        source = open(os.path.join(ANDROID, "chat", "SavedContacts.kt"),
                      encoding="utf-8").read()
        return source[source.index("private fun decode("):]

    def test_decode_folds_the_stored_jid(self):
        assert "ChatState.bare(parts.getOrNull(0)" in self._decode_body()

    def test_a_record_without_a_jid_is_still_dropped(self):
        body = self._decode_body()
        assert 'jid.isEmpty() || !jid.contains(\'@\')' in body, (
            "a truncated vault entry can become a contact with a blank JID")
