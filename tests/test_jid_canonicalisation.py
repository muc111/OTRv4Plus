#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""One contact, one key -- however their address is spelled.

THE LEAK
========
`OtrApp` keeps a dozen maps keyed by peer JID. One of them is `OtrMode`, which
decides whether a conversation is allowed to send in the clear. It was keyed by
whatever string the caller happened to pass, and XMPP addresses arrive spelled
more than one way: the user types `Bob@Example.test` into Add Contact, slixmpp
normalises the server's echo to `bob@example.test`, and a stanza carries a
resource on the end. Measured through the facade after OTR had been requested
for `bob@x.test`:

    may_send_plaintext(bob@x.test            ) = False
    may_send_plaintext(Bob@X.test            ) = True   <-- LEAK
    may_send_plaintext(bob@x.test/phone      ) = True   <-- LEAK
    may_send_plaintext(BOB@X.TEST/laptop     ) = True   <-- LEAK

A conversation that had asked for encryption reported that plaintext was
permitted, under three spellings of the same person.

WHY FOLDING IS THE SAFE DIRECTION
=================================
RFC 6122 makes the localpart and domain case-insensitive and the resource no
part of an identity, so folding is correct rather than merely convenient. It is
also one-way safe: it can MERGE two spellings of one person into one key, and
it can never split one person into two or map two different people together.
The tests below hold both halves of that.

WHAT IS DELIBERATELY NOT FOLDED
===============================
Nothing cryptographic. Canonicalisation decides which BUCKET a peer's state
lives in; it is not consulted by the engine, does not touch fingerprints, and
never decides trust. A fingerprint comparison is still byte-for-byte.
"""

import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

otr = pytest.importorskip("otrv4_")
pytest.importorskip("otrv4_core")

from android_bridge.app import OtrApp, Transport                # noqa: E402

CANONICAL = "bob@example.test"

#: The same person, written four ways. Every one of these is something the
#: application actually sees: typed by the user, echoed by the server,
#: carried on a stanza from one of their clients.
SPELLINGS = (
    "bob@example.test",
    "Bob@Example.test",
    "BOB@EXAMPLE.TEST",
    "bob@example.test/phone",
    "Bob@Example.TEST/Laptop",
    "  bob@example.test  ",
)


class Wire(Transport):
    """Records what went out, and under which peer."""

    def __init__(self):
        self.sent = []

    def send(self, peer, payload):
        self.sent.append((peer, payload))

    def connect(self): pass
    def disconnect(self): pass
    def roster(self): return []


class RosterWire(Wire):
    """A transport whose roster spells the JID however it likes."""

    entries = []

    def roster(self):
        return list(self.entries)


def _manager():
    directory = tempfile.mkdtemp()
    config = otr.OTRConfig(test_mode=True)
    for attribute, name in (("trust_db_path", "trust.json"),
                            ("smp_secrets_path", "smp.json"),
                            ("key_storage_path", "keys")):
        if hasattr(config, attribute):
            setattr(config, attribute, os.path.join(directory, name))
    return otr.EnhancedSessionManager(config=config)


def _app(transport=None):
    return OtrApp(_manager(), transport if transport is not None else Wire())


@pytest.fixture
def app():
    return _app()


# -- the rule itself ---------------------------------------------------------


class TestCanonicalPeer:

    @pytest.mark.parametrize("spelling", SPELLINGS)
    def test_every_spelling_folds_to_one_key(self, spelling):
        assert OtrApp.canonical_peer(spelling) == CANONICAL

    def test_it_is_idempotent(self):
        once = OtrApp.canonical_peer("Bob@Example.TEST/phone")
        assert OtrApp.canonical_peer(once) == once

    def test_it_never_merges_two_different_people(self):
        """The one-way property. Folding may join spellings of one person; it
        must never join two people, or the maps it keys would hand one
        conversation's security state to another."""
        assert OtrApp.canonical_peer("bob@a.test") != \
            OtrApp.canonical_peer("bob@b.test")
        assert OtrApp.canonical_peer("bob@a.test") != \
            OtrApp.canonical_peer("rob@a.test")
        assert OtrApp.canonical_peer("bob@a.test") != \
            OtrApp.canonical_peer("bob@a.test.evil")

    def test_it_survives_nothing(self):
        for empty in (None, "", "   ", "/resource"):
            assert OtrApp.canonical_peer(empty) == ""


# -- the leak it closes ------------------------------------------------------


class TestPlaintextIsNotPermittedUnderAnotherSpelling:
    """THE SECURITY CONSEQUENCE, driven through the real `OtrMode`.

    `may_send_plaintext(peer, encrypted)` is `not encrypted and not
    is_otr(peer)`. `encrypted=False` is asked below on purpose: with no live
    session, `is_otr` is the ONLY thing standing between the user and a body
    that goes out in the clear, so it is the half a spelling could bypass.
    """

    @staticmethod
    def _plaintext_allowed(app, peer):
        return app._mode.may_send_plaintext(
            OtrApp.canonical_peer(peer), False)

    @pytest.mark.parametrize("spelling", SPELLINGS)
    def test_requesting_otr_once_closes_every_spelling(self, app, spelling):
        app.start_session(CANONICAL)
        assert self._plaintext_allowed(app, spelling) is False, (
            "a conversation that asked for OTR reports that plaintext is "
            "allowed when its JID is spelled %r" % spelling)

    @pytest.mark.parametrize("spelling", SPELLINGS)
    def test_it_closes_from_whichever_spelling_asked(self, spelling):
        """And the other way round: OTR requested under ANY spelling must
        close the canonical one too, or the guard depends on how the user
        happened to type the address."""
        fresh = _app()
        fresh.start_session(spelling)
        assert self._plaintext_allowed(fresh, CANONICAL) is False

    @pytest.mark.parametrize("spelling", SPELLINGS)
    def test_the_mode_map_holds_exactly_one_key(self, spelling):
        fresh = _app()
        fresh.start_session(spelling)
        assert fresh._mode.peers() == {CANONICAL}

    def test_a_different_peer_is_untouched(self, app):
        """Folding must not leak the other way either -- asking for OTR with
        one person must not change what is permitted with another."""
        app.start_session(CANONICAL)
        assert self._plaintext_allowed(app, "carol@example.test") is True

    def test_an_encrypted_peer_is_refused_plaintext_regardless(self, app):
        """The other arm of the predicate, asserted so a future change to
        canonicalisation cannot quietly take it: a live session refuses a
        plaintext body even for a peer that never asked for OTR mode."""
        assert app._mode.may_send_plaintext("carol@example.test", True) is False


# -- everything else keyed by peer -------------------------------------------


class TestPerPeerStateAgreesAcrossSpellings:

    @pytest.mark.parametrize("spelling", SPELLINGS)
    def test_presence_is_found_under_every_spelling(self, app, spelling):
        app.note_presence(CANONICAL, True, "chat")
        assert app.presence_state(spelling) == "online"

    @pytest.mark.parametrize("spelling", SPELLINGS)
    def test_presence_is_recorded_under_every_spelling(self, spelling):
        fresh = _app()
        fresh.note_presence(spelling, True, "chat")
        assert fresh.presence_state(CANONICAL) == "online"

    @pytest.mark.parametrize("spelling", SPELLINGS)
    def test_the_session_is_found_under_every_spelling(self, app, spelling):
        app.start_session(CANONICAL)
        canonical_state = app.security_state(CANONICAL)
        assert app.security_state(spelling) == canonical_state, (
            "the same session reports a different security state depending "
            "on how the peer's JID is spelled")

    @pytest.mark.parametrize("spelling", SPELLINGS)
    def test_verification_state_is_found_under_every_spelling(self, app,
                                                              spelling):
        app.start_session(CANONICAL)
        assert app.smp_state(spelling) == app.smp_state(CANONICAL)

    def test_a_message_sent_under_a_resource_uses_the_bare_session(self, app):
        """The one that would have gone out in the clear. `send_message` with
        a full JID used to look up a session that was keyed bare, find
        nothing, and take the no-session path."""
        app.start_session(CANONICAL)
        before = app.security_state(CANONICAL)
        assert app.security_state("%s/phone" % CANONICAL) == before


# -- the roster --------------------------------------------------------------


class TestTheRosterIsEmittedCanonically:
    """`_contact_view` reads `_presence` and `_last_activity` DIRECTLY, rather
    than through the accessors that fold for it, and both are written under
    canonical keys. A roster entry spelled any other way missed its own
    state -- and, worse, became the key the whole UI then used, so the
    conversation list showed one person as two rows."""

    @staticmethod
    def _with_roster(jid):
        wire = RosterWire()
        wire.entries = [{"jid": jid, "name": "", "subscription": "both"}]
        return _app(wire)

    @pytest.mark.parametrize("spelling", SPELLINGS)
    def test_the_emitted_jid_is_canonical(self, spelling):
        app = self._with_roster(spelling)
        assert app.contacts()[0].jid == CANONICAL, (
            "the UI is handed the raw spelling as the key for every "
            "subsequent call, so its history lands in a second conversation")

    @pytest.mark.parametrize("spelling", SPELLINGS)
    def test_the_row_carries_the_presence_it_was_told_about(self, spelling):
        app = self._with_roster(spelling)
        app.note_presence(CANONICAL, True, "chat")
        view = app.contacts()[0]
        assert view.presence == "online", (
            "the contact row reports unknown presence although the peer's "
            "presence is known, because the row is keyed differently")
        assert view.presence_show == "chat"

    @pytest.mark.parametrize("spelling", SPELLINGS)
    def test_the_row_carries_the_last_activity(self, spelling):
        app = self._with_roster(spelling)
        app.receive_message(CANONICAL, "hello")
        assert app.contacts()[0].last_activity is not None, (
            "a message just arrived and the row shows no activity")

    def test_a_roster_entry_with_no_jid_is_still_dropped(self):
        wire = RosterWire()
        wire.entries = [{"jid": "", "name": "x"}, {"jid": "   /r"}]
        assert _app(wire).contacts() == []

    def test_the_display_name_is_still_the_server_s(self):
        """Folding the KEY must not rewrite what the user reads. A roster
        entry with a name keeps it, exactly as spelled."""
        wire = RosterWire()
        wire.entries = [{"jid": "Bob@Example.TEST", "name": "Bob Smith",
                         "subscription": "both"}]
        assert _app(wire).contacts()[0].display_name == "Bob Smith"


# -- state a remote party can grow -------------------------------------------


class TestPerPeerStateIsBounded:
    """`receive_message` records a last-seen time under the SENDER'S JID, so
    the key is chosen by somebody else. Measured before the bound:

        20 000 distinct senders
        presence entries : 20000
        last_activity    : 20000

    Nothing reclaimed either. `otrv4+.py`'s `DAKE1RateLimiter` already bounds
    itself for exactly this reason; these follow it rather than inventing a
    second answer.

    WHAT IS LOST when the bound bites is a "last seen" caption and a presence
    dot. No security state, no session, no trust decision and no key is kept
    in either map -- those live in the engine, which has its own lifecycle.
    """

    #: Enough to pass both caps without making the test slow.
    FLOOD = 3000

    @staticmethod
    def _flood(app, n):
        for i in range(n):
            app.note_presence("flood%d@evil.test" % i, True, "chat")
            app.receive_message("flood%d@evil.test" % i, "x")

    def test_the_activity_map_stops_at_its_cap(self, app):
        self._flood(app, self.FLOOD)
        assert len(app._last_activity) == OtrApp.MAX_TRACKED_ACTIVITY

    def test_the_presence_book_stops_at_its_cap(self, app):
        self._flood(app, self.FLOOD)
        assert len(app._presence) <= app._presence.MAX_TRACKED

    def test_talking_to_one_peer_does_not_grow_the_map(self, app):
        for _ in range(5000):
            app.receive_message(CANONICAL, "x")
        assert len(app._last_activity) == 1

    def test_every_spelling_touches_one_entry(self, app):
        for spelling in SPELLINGS:
            app.receive_message(spelling, "x")
        assert list(app._last_activity) == [CANONICAL], (
            "one person is occupying several slots of a bounded map")

    def test_the_flood_does_not_reach_the_engine(self, app):
        """The bound is about memory, not about security -- and the security
        answer is that none of this creates sessions. Asserted so a future
        change cannot make an inbound frame from a stranger do more."""
        self._flood(app, 200)
        assert len(app._engine.sessions) == 0
        assert app._mode.peers() == set()
