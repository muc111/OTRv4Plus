# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The group-call receive watchdog (android_bridge.group_call_bridge) and the
diagnostics counters it relies on. Device report 2026-10-15: a group call
received 3 frames and then nothing, and the report printed its counters as
`peers=user-D`."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from android_bridge import group_call_bridge as G  # noqa: E402
import otrv4plus_alias  # noqa: E402


class _Calls:
    def __init__(self, peers, paused=()):
        self.peers, self.paused = list(peers), list(paused)

    def participants(self, room):
        return self.peers

    def paused_peers(self, room):
        return self.paused


class _Media:
    def __init__(self):
        self.heard = {}

    def last_heard(self, who):
        return self.heard.get(who, 0.0)


def _bridge(calls):
    b = G.GroupCallBridge.__new__(G.GroupCallBridge)
    b.calls = calls
    b._reset_watch()
    return b


def test_a_new_participant_gets_the_start_grace():
    b, m = _bridge(_Calls(["bob"])), _Media()
    assert b.silent_participants("r", m, 100.0) == []
    assert b.silent_participants("r", m, 100.0 + G.RX_START_GRACE - 1) == []
    assert b.silent_participants("r", m, 100.0 + G.RX_START_GRACE + 1) == ["bob"]


def test_audio_that_stops_is_noticed():
    b, m = _bridge(_Calls(["bob"])), _Media()
    b.silent_participants("r", m, 100.0)
    m.heard["bob"] = 105.0
    assert b.silent_participants("r", m, 105.0 + G.RX_SILENT - 1) == []
    assert b.silent_participants("r", m, 105.0 + G.RX_SILENT + 1) == ["bob"]


def test_a_paused_participant_is_not_lost():
    b, m = _bridge(_Calls(["bob"], paused=["bob"])), _Media()
    b.silent_participants("r", m, 100.0)
    assert b.silent_participants("r", m, 10_000.0) == []


def test_rebuilds_are_bounded():
    assert G.MAX_REOPENS <= 2 and G.REOPEN_GAP >= 30


def test_counters_are_not_labelled_as_people():
    book = otrv4plus_alias.AliasBook()
    assert book.field("peers", "1") == "1"
    assert book.field("jb_dropped_senders", "0") == "0"
    assert book.field("jb_senders", "2") == "2"
    # A name that happens to be digits is still a name.
    assert book.field("nick", "1234").startswith("user-")
    assert book.field("peer", "bob@x.i2p").startswith("user-")
