# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""A contact was added, saved, and then read "presence unknown" forever.

Enforces INV-27 for availability: one account is one key in this book,
however their address is spelled.

THE BUG
-------
Presence was a `Dict[str, bool]`, read with `.get(jid, False)`. Two states for
a problem that has three: "we have never heard anything about this peer" and
"this peer is offline" were the same value.

So a contact added a moment ago -- roster entry written, subscription request
sent, everything working -- was reported with `online=False`. The Kotlin layer
will not claim knowledge it does not have, so it rendered "presence unknown",
and went on rendering it because nothing about the model could ever change.
Replacing the string with "online" would have been a lie pointing the other
way; the fix is for the model to be able to say which of the three is true.

A SECOND DEFECT BEHIND IT
-------------------------
The map was never cleared, and it lives on `OtrApp`, which outlives the
transport. After a disconnect and reconnect, a contact who had gone offline in
the meantime still read ONLINE until they happened to send another stanza.
Availability learned over a dead stream is a memory, not knowledge.

These tests execute the model. `otrv4plus_presence` has no slixmpp import and
no I/O precisely so that it can be.
"""

import pytest

import otrv4plus_presence as presence
from otrv4plus_presence import OFFLINE, ONLINE, UNKNOWN, PresenceBook

ALICE = "alice@xmpp-elite.i2p"
BOB = "bob@xmpp-elite.i2p"


@pytest.fixture
def book():
    return PresenceBook()


# ── the third state, which is the whole point ────────────────────────────────

class TestUnknownIsAState:

    def test_a_peer_never_heard_of_is_unknown(self, book):
        assert book.state(ALICE) == UNKNOWN

    def test_unknown_is_not_offline(self, book):
        """The collapse this module exists to undo. A freshly added contact
        was reported offline, which is a claim, not an absence of one."""
        assert book.state(ALICE) != OFFLINE

    def test_a_peer_who_said_offline_is_offline(self, book):
        book.note(ALICE, online=False)
        assert book.state(ALICE) == OFFLINE

    def test_the_two_are_distinguishable(self, book):
        book.note(BOB, online=False)
        assert book.state(ALICE) == UNKNOWN
        assert book.state(BOB) == OFFLINE
        assert book.state(ALICE) != book.state(BOB), (
            "never-heard and offline are the same value again, which is the "
            "original bug")

    def test_every_state_is_declared(self):
        assert set(presence.STATES) == {UNKNOWN, ONLINE, OFFLINE}


class TestOnlineAndOffline:

    def test_available_is_online(self, book):
        book.note(ALICE, online=True)
        assert book.state(ALICE) == ONLINE

    def test_a_peer_can_go_offline_again(self, book):
        book.note(ALICE, online=True)
        book.note(ALICE, online=False)
        assert book.state(ALICE) == OFFLINE

    def test_and_come_back(self, book):
        book.note(ALICE, online=False)
        book.note(ALICE, online=True)
        assert book.state(ALICE) == ONLINE

    def test_peers_are_independent(self, book):
        book.note(ALICE, online=True)
        book.note(BOB, online=False)
        assert book.state(ALICE) == ONLINE
        assert book.state(BOB) == OFFLINE


class TestTheResourceIsStripped:
    """Presence arrives per-resource; availability here is a property of the
    account. Without this the same person appears twice."""

    def test_a_full_jid_is_recorded_against_the_bare_one(self, book):
        book.note(ALICE + "/phone", online=True)
        assert book.state(ALICE) == ONLINE

    def test_two_resources_are_one_peer(self, book):
        book.note(ALICE + "/phone", online=True)
        book.note(ALICE + "/desktop", online=False)
        assert len(book) == 1

    def test_reading_by_full_jid_works_too(self, book):
        book.note(ALICE, online=True)
        assert book.state(ALICE + "/anything") == ONLINE

    def test_whitespace_does_not_create_a_second_peer(self, book):
        book.note("  " + ALICE + "  ", online=True)
        assert book.state(ALICE) == ONLINE
        assert len(book) == 1


class TestShow:

    def test_a_show_is_kept(self, book):
        book.note(ALICE, online=True, show="away")
        assert book.show(ALICE) == "away"

    def test_an_unknown_show_is_dropped_rather_than_echoed(self, book):
        book.note(ALICE, online=True, show="banana")
        assert book.show(ALICE) == ""

    def test_going_offline_clears_the_show(self, book):
        """"offline (away)" is not a thing."""
        book.note(ALICE, online=True, show="dnd")
        book.note(ALICE, online=False)
        assert book.show(ALICE) == ""

    def test_a_show_never_decides_availability(self, book):
        """The stanza type already did. A show on an unavailable stanza must
        not promote it to online."""
        book.note(ALICE, online=False, show="away")
        assert book.state(ALICE) == OFFLINE

    def test_an_unheard_peer_has_no_show(self, book):
        assert book.show(ALICE) == ""


# ── the stale-knowledge defect ───────────────────────────────────────────────

class TestTheStreamGoingTakesTheKnowledgeWithIt:

    def test_forget_all_returns_everyone_to_unknown(self, book):
        book.note(ALICE, online=True)
        book.note(BOB, online=False)
        book.forget_all()
        assert book.state(ALICE) == UNKNOWN
        assert book.state(BOB) == UNKNOWN

    def test_an_online_peer_does_not_survive_a_disconnect(self, book):
        """The reported staleness: a contact who went offline during a
        reconnect still read ONLINE until they next sent a stanza."""
        book.note(ALICE, online=True)
        book.forget_all()
        assert book.state(ALICE) != ONLINE

    def test_forget_all_clears_the_shows_too(self, book):
        book.note(ALICE, online=True, show="away")
        book.forget_all()
        assert book.show(ALICE) == ""

    def test_one_peer_can_be_forgotten_alone(self, book):
        book.note(ALICE, online=True)
        book.note(BOB, online=True)
        book.forget(ALICE)
        assert book.state(ALICE) == UNKNOWN
        assert book.state(BOB) == ONLINE

    def test_forgetting_someone_unheard_of_is_harmless(self, book):
        book.forget(ALICE)
        assert book.state(ALICE) == UNKNOWN


# ── what the discovery view reads ────────────────────────────────────────────

class TestListingWhoIsOnline:

    def test_only_online_peers_are_listed(self, book):
        book.note(ALICE, online=True)
        book.note(BOB, online=False)
        assert book.online() == (ALICE,)

    def test_an_unheard_peer_is_not_listed(self, book):
        assert book.online() == ()

    def test_it_is_derived_rather_than_stored(self, book):
        """So it cannot drift from `state`."""
        book.note(ALICE, online=True)
        assert ALICE in book.online()
        book.note(ALICE, online=False)
        assert ALICE not in book.online()

    def test_known_lists_everyone_heard_about(self, book):
        book.note(ALICE, online=True)
        book.note(BOB, online=False)
        assert set(book.known()) == {ALICE, BOB}


# ── it must not become a way to leak a contact list ──────────────────────────

class TestItDoesNotLeakPeersIntoALogLine:

    def test_repr_carries_counts_and_no_jids(self, book):
        book.note(ALICE, online=True)
        book.note(BOB, online=False)
        text = repr(book)
        assert "alice" not in text
        assert "bob" not in text
        assert "known=2" in text and "online=1" in text


class TestItSurvivesRubbish:
    """Called from the transport's loop thread on every inbound stanza."""

    def test_an_empty_peer_is_ignored(self, book):
        book.note("", online=True)
        assert len(book) == 0

    def test_none_is_ignored(self, book):
        book.note(None, online=True)
        assert len(book) == 0

    def test_reading_an_empty_peer_is_unknown(self, book):
        assert book.state("") == UNKNOWN


# ── one account, one key ─────────────────────────────────────────────────────

class TestTheCaseHalfOfTheDocumentedRule:
    """`_bare` has said "lower-cased domain-insensitively" since this module
    was written, and did not do it. Measured before the fix:

        note("alice@Host", online)
        state("alice@Host")  = online
        state("alice@host")  = unknown          <-- the same person
        forget("alice@host") -> {'alice@Host': 'online'}

    The middle line is the duplicate this module exists to prevent. The last
    is the one that matters: [PresenceBook.forget] drops what we learned under
    a subscription we no longer hold, and a spelling it did not match meant it
    dropped nothing and the application went on showing the availability of
    somebody who had revoked it.
    """

    #: The same account as the server, as the user types it, and per device.
    SPELLINGS = ("alice@xmpp-elite.i2p", "Alice@XMPP-Elite.i2p",
                 "ALICE@XMPP-ELITE.I2P", "alice@xmpp-elite.i2p/phone",
                 "Alice@XMPP-Elite.i2p/Desktop", "  alice@xmpp-elite.i2p  ")

    @pytest.mark.parametrize("spelling", SPELLINGS)
    def test_every_spelling_reads_the_same_state(self, book, spelling):
        book.note(ALICE, online=True, show="chat")
        assert book.state(spelling) == ONLINE
        assert book.show(spelling) == "chat"

    @pytest.mark.parametrize("spelling", SPELLINGS)
    def test_every_spelling_writes_the_same_entry(self, spelling):
        fresh = PresenceBook()
        fresh.note(spelling, online=True)
        assert fresh.state(ALICE) == ONLINE
        assert len(fresh) == 1, "one account is being held as two peers"

    @pytest.mark.parametrize("spelling", SPELLINGS)
    def test_forget_reaches_every_spelling(self, spelling):
        """The privacy half. A subscription revoked under one spelling has to
        drop what was learned under another, or the screen keeps showing it."""
        fresh = PresenceBook()
        fresh.note(spelling, online=True)
        fresh.forget(ALICE)
        assert fresh.state(spelling) == UNKNOWN
        assert len(fresh) == 0

    def test_two_devices_are_one_peer_not_two(self, book):
        book.note("%s/phone" % ALICE, online=True)
        book.note("%s/Desktop" % ALICE, online=False)
        assert len(book) == 1
        assert book.state(ALICE) == OFFLINE, "the later stanza did not win"

    def test_two_different_accounts_are_still_two(self, book):
        """Folding is one-way safe: it may merge spellings of one account and
        must never join two. Nothing below differs only by case."""
        book.note("alice@a.i2p", online=True)
        book.note("alice@b.i2p", online=False)
        book.note("rob@a.i2p", online=True)
        assert len(book) == 3

    def test_the_key_it_keeps_agrees_with_the_bridge(self):
        """`OtrApp.canonical_peer` folds with `casefold` and keys the bridge's
        own maps with the result. If these two disagreed, a peer's presence
        and their security state would live under different keys."""
        app = pytest.importorskip("android_bridge.app")
        fresh = PresenceBook()
        for spelling in self.SPELLINGS:
            fresh.note(spelling, online=True)
            assert list(fresh.snapshot()) == \
                [app.OtrApp.canonical_peer(spelling)]
            fresh.forget_all()


# ── it must not grow without bound ───────────────────────────────────────────

class TestTheBookIsBounded:
    """The key is chosen by somebody else.

    Every inbound presence stanza reaches `note`, under the sender's JID, so
    an unbounded map is a memory-growth path a remote party drives. Measured
    before the bound, through the Android facade: 20 000 distinct senders
    produced 20 000 entries and nothing reclaimed them.
    """

    def test_it_stops_at_the_cap(self):
        book = PresenceBook()
        for i in range(PresenceBook.MAX_TRACKED * 2):
            book.note("flood%d@evil.i2p" % i, online=True)
        assert len(book) == PresenceBook.MAX_TRACKED

    def test_the_show_map_is_pruned_with_the_state_map(self):
        """A `show` outliving the state it describes would be a slow leak the
        length check above would never notice."""
        book = PresenceBook()
        for i in range(PresenceBook.MAX_TRACKED * 2):
            book.note("flood%d@evil.i2p" % i, online=True, show="chat")
        assert len(book._show) == PresenceBook.MAX_TRACKED

    def test_a_peer_still_being_heard_from_is_not_the_one_dropped(self):
        """Eviction is least-recently-noted, so a contact the server keeps
        broadcasting survives a flood that arrives around them."""
        book = PresenceBook()
        for i in range(PresenceBook.MAX_TRACKED):
            book.note("flood%d@evil.i2p" % i, online=True)
            if i % 100 == 0:
                book.note(ALICE, online=True)       # still being heard from
        assert book.state(ALICE) == ONLINE

    def test_re_noting_a_peer_does_not_grow_the_book(self):
        book = PresenceBook()
        for _ in range(10_000):
            book.note(ALICE, online=True)
        assert len(book) == 1

    def test_the_cap_is_far_above_a_real_contact_list(self):
        """Stated so a future reduction has to argue with this line. A handset
        roster is tens to hundreds; only a flood reaches the cap."""
        assert PresenceBook.MAX_TRACKED >= 1024
