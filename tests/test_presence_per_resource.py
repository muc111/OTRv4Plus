#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""A contact is online while ANY of their resources is.

Device report, 2026-09-24: two phones mid-conversation -- OTR up, SMP
verified, messages flowing both ways -- each showed the other as "offline".
Presence was kept per bare JID, last stanza wins. Every launch signs in as a
new resource, and over I2P the server times the previous session out some
minutes later: the OLD resource's `unavailable` arrived after the NEW one's
`available`, and overwrote it.
"""

import otrv4plus_presence as P
from android_bridge.app import OtrApp


def test_an_old_resource_leaving_does_not_hide_the_new_one():
    book = P.PresenceBook()
    book.note("alice@x.i2p/old", True)
    book.note("alice@x.i2p/new", True)
    book.note("alice@x.i2p/old", False)      # the server timed the old one out
    assert book.state("alice@x.i2p") == P.ONLINE


def test_the_order_of_the_device_report():
    book = P.PresenceBook()
    book.note("alice@x.i2p/new", True, "chat")
    book.note("alice@x.i2p/old", False)      # late unavailable from before relaunch
    assert book.state("alice@x.i2p") == P.ONLINE
    assert book.show("alice@x.i2p") == "chat"


def test_offline_once_every_resource_has_gone():
    book = P.PresenceBook()
    book.note("alice@x.i2p/a", True)
    book.note("alice@x.i2p/b", True, "away")
    book.note("alice@x.i2p/b", False)
    assert book.state("alice@x.i2p") == P.ONLINE and book.show("alice@x.i2p") == ""
    book.note("alice@x.i2p/a", False)
    assert book.state("alice@x.i2p") == P.OFFLINE


def test_a_bare_unavailable_means_the_whole_account():
    book = P.PresenceBook()
    book.note("alice@x.i2p/a", True)
    book.note("alice@x.i2p/b", True)
    book.note("alice@x.i2p", False)
    assert book.state("alice@x.i2p") == P.OFFLINE


def test_unknown_until_heard_and_forget_clears_resources():
    book = P.PresenceBook()
    assert book.state("alice@x.i2p") == P.UNKNOWN
    book.note("alice@x.i2p/a", True)
    book.forget("alice@x.i2p")
    assert book.state("alice@x.i2p") == P.UNKNOWN
    book.note("alice@x.i2p/b", False)
    assert book.state("alice@x.i2p") == P.OFFLINE


def test_a_resource_flood_is_bounded():
    book = P.PresenceBook()
    for i in range(1000):
        book.note("alice@x.i2p/r%d" % i, True)
    assert len(book._resources["alice@x.i2p"]) <= P.PresenceBook.MAX_RESOURCES


def test_the_android_facade_keeps_the_resource():
    app = OtrApp.__new__(OtrApp)
    app._presence = P.PresenceBook()
    OtrApp.note_presence(app, "Alice@X.i2p/new", True)
    OtrApp.note_presence(app, "alice@x.i2p/old", False)
    assert app._presence.state("alice@x.i2p") == P.ONLINE
