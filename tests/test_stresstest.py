# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The server load test's group logic, with an in-memory room (no server)."""
import random

import pytest

core = pytest.importorskip("otrv4_core")
if not hasattr(core, "RustMlsClient"):
    pytest.skip("this core was built without the mls feature", allow_module_level=True)

import otrv4plus_stresstest as st  # noqa: E402

ROOM = "stress-test@conference.x.i2p"


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def _swarm(n, interval=30.0, observers=0):
    clock = Clock()
    bots = [st.Bot(i, "stress-t-%03d@x.i2p" % i, core) for i in range(n)]
    if observers:
        for b in bots[observers:]:
            b.observe = False
    room_log, directs = [], []

    def send_room(bot, body):
        room_log.append((st.Swarm.nick(bot), body))

    def send_direct(bot, to, body):
        directs.append((bot.jid, to, body))

    sw = st.Swarm(core, ROOM, bots, send_room=send_room, send_direct=send_direct,
                  interval=interval, clock=clock, rng=random.Random(7), say=lambda _m: None)

    def pump():
        # The room reflects every body to every occupant, in order; direct
        # messages go to their one recipient.
        while room_log or directs:
            while room_log:
                nick, body = room_log.pop(0)
                for b in bots:
                    sw.on_room(b, nick, body)
            while directs:
                frm, to, body = directs.pop(0)
                sw.on_direct(sw.by_jid[to], frm, body)
    return sw, bots, clock, pump


def test_the_group_forms_in_batches_and_everyone_hears_everyone():
    sw, bots, clock, pump = _swarm(9)
    sw.create()
    waiting = bots[1:]
    while waiting:
        assert sw.add_batch(waiting[:4])
        waiting = waiting[4:]
        pump()
    assert all(b.member for b in bots)
    assert sw.stats.commits == 2 and sw.stats.join_refused == 0
    # Two minutes of chatter.
    for _ in range(240):
        clock.t += 0.5
        sw.tick()
        pump()
    s = sw.stats
    assert s.sent > 0
    assert s.delivered == s.expected, (s.delivered, s.expected)
    assert s.undecryptable == 0
    row = sw.minute_row(120, online=9)
    assert row["members"] == 9 and row["delivery_pct"] == 100.0
    assert sw.stats.sent == 0            # reset for the next minute


def test_the_chat_is_ciphertext_and_reads_like_people():
    sw, bots, clock, pump = _swarm(3)
    sw.create()
    sw.add_batch(bots[1:])
    seen = []
    orig = sw.send_room
    sw.send_room = lambda bot, body: (seen.append(body), orig(bot, body))
    pump()
    for _ in range(200):
        clock.t += 0.5
        sw.tick()
        pump()
    assert seen and all(b.startswith((st.ROOM_PREFIX, st.CHAT_PREFIX, "?OTRv4F|")) for b in seen)
    assert not any("news" in b or "Did you see" in b for b in seen)
    assert "?" in st.chatter(random.Random(1)) or "." in st.chatter(random.Random(1))


def test_observers_limit_who_decrypts():
    sw, bots, clock, pump = _swarm(5, observers=2)
    sw.create()
    sw.add_batch(bots[1:])
    pump()
    for _ in range(200):
        clock.t += 0.5
        sw.tick()
        pump()
    assert sw.stats.delivered == sw.stats.expected > 0


def test_a_non_observer_never_decrypts_chat():
    """Run of 2026-10-16: with --observers 10 every bot still decrypted
    every line, so 100 members meant ~10 000 decryptions per burst in one
    process and the run measured the laptop. Group changes are still
    processed by everyone."""
    sw, bots, clock, pump = _swarm(5, observers=2)
    sw.create()
    sw.add_batch(bots[1:])
    pump()
    calls = {b.index: 0 for b in bots}

    class Counting:
        def __init__(self, bot):
            self.bot, self.inner = bot, bot.mls

        def process(self, gid, data):
            calls[self.bot.index] += 1
            return self.inner.process(gid, data)

        def __getattr__(self, name):
            return getattr(self.inner, name)

    for b in bots:
        b.mls = Counting(b)
    for _ in range(200):
        clock.t += 0.5
        sw.tick()
        pump()
    assert sw.stats.sent > 0 and sw.stats.delivered == sw.stats.expected
    assert all(calls[b.index] == 0 for b in bots[2:]), calls
    assert calls[1] > 0


def test_the_flag_is_hidden_and_admin_only_by_design():
    import otrv4plus_xmpp
    src = open(otrv4plus_xmpp.__file__).read()
    assert '"--stresstest" in sys.argv' in src
    assert 'import_module("otrv4plus_stresstest")' in src    # not in the APK
    ap = st.build_parser()
    assert ap.parse_args(["--admin", "a@x"]).keep is False   # cleans up by default
    # Accounts come from the server's admin command, which the server
    # refuses to anyone but its admins.
    assert st.ADMIN_ADD.endswith("admin#add-user")
    assert "getpass" in open(st.__file__).read()


def test_an_older_core_without_identities_still_adds():
    """Device report (2026-10-16): the laptop's compiled core predated the
    `identities` argument and every add was refused."""
    sw, bots, clock, pump = _swarm(3)
    sw.create()

    class OldCore:
        def __init__(self, inner):
            self.inner = inner

        def add_members(self, gid, kps, **kw):
            if kw:
                raise TypeError("add_members() got an unexpected keyword argument 'identities'")
            return self.inner.add_members(gid, kps)

        def __getattr__(self, name):
            return getattr(self.inner, name)

    sw.owner.mls = OldCore(sw.owner.mls)
    assert sw.add_batch(bots[1:])
    pump()
    assert all(b.member for b in bots) and sw.old_core_warned


def test_the_runner_uses_the_apps_pacer_and_sees_bounces():
    """Run of 2026-10-16: delivery 43% with "room errors 0". The room's
    refusals arrive as type="error" (slixmpp's message_error event), which
    the old hand-made pacing never listened to, and nothing re-sent them."""
    src = open(st.__file__).read()
    assert "from android_bridge.groups import RoomPacer" in src
    assert '"message_error"' in src and ".rejected(room)" in src
    assert ".confirm(room," in src          # echoes confirm, so unechoed re-send
