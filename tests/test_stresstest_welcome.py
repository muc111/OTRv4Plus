# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""--welcome: the stress test also fills the public Welcome room, to measure
presence fan-out (every join is told to everyone already there)."""
import asyncio
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import otrv4plus_stresstest as st                                   # noqa: E402


def test_the_room_name_is_the_apps():
    from android_bridge.welcome import ROOM_NAME
    assert st.WELCOME_NAME == ROOM_NAME


def test_the_options():
    p = st.build_parser()
    a = p.parse_args(["--admin", "a@x.i2p"])
    assert a.welcome is None and a.welcome_rate == 2.0
    assert p.parse_args(["--admin", "a@x.i2p", "--welcome"]).welcome == "auto"
    a = p.parse_args(["--admin", "a@x.i2p", "--welcome", "w@conference.x.i2p",
                      "--welcome-rate", "5"])
    assert (a.welcome, a.welcome_rate) == ("w@conference.x.i2p", 5.0)


class _Items:
    def __init__(self, rows):
        self.rows = rows

    def __getitem__(self, _k):
        return self

    def get_items(self):
        return self.rows


class _Disco:
    def __init__(self, rows):
        self.rows = rows

    async def get_items(self, jid, timeout):
        return _Items(self.rows)


def _client(rows):
    return {"xep_0030": _Disco(rows)}


def test_the_room_is_found_by_its_exact_name_and_never_guessed():
    muc = "conference.x.i2p"
    ok = _client([("Welcome@conference.x.i2p", None, "OTRv4Plus Welcome"),
                  ("other@conference.x.i2p", None, "OTRv4Plus Welcome (unofficial)")])
    assert asyncio.run(st._welcome_room(ok, muc)) == "welcome@conference.x.i2p"
    with pytest.raises(RuntimeError, match="no Welcome room"):
        asyncio.run(st._welcome_room(_client([]), muc))
    two = _client([("a@conference.x.i2p", None, "OTRv4Plus Welcome"),
                   ("b@conference.x.i2p", None, "OTRv4Plus Welcome")])
    with pytest.raises(RuntimeError, match="more than one"):
        asyncio.run(st._welcome_room(two, muc))


def test_each_minute_reports_joins_failures_and_join_time():
    w = st.WelcomeLoad()
    assert w.minute() == {"welcome_in": 0, "welcome_failed": 0,
                          "welcome_join_p50_s": "", "welcome_join_p95_s": ""}
    for s in (1.0, 2.0, 3.0, 4.0, 10.0):
        w.ok(s)
    w.failed += 1
    row = w.minute()
    assert row["welcome_in"] == 5 and row["welcome_failed"] == 1
    assert row["welcome_join_p50_s"] == 3.0 and row["welcome_join_p95_s"] == 10.0
    # Times are per minute; the count is the running total in the room.
    assert w.minute()["welcome_join_p50_s"] == "" and w.minute()["welcome_in"] == 5
