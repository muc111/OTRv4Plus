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
    assert '"message_error"' in src and ".rejected(bot.room)" in src
    assert ".confirm(bot.room," in src          # echoes confirm, so unechoed re-send


def test_several_groups_add_one_at_a_time_and_add_up():
    """--groups: each room its own group, filled one person per change (the
    app adds people one at a time as they accept), and one row for all."""
    a, a_bots, clock_a, pump_a = _swarm(4)
    b, b_bots, clock_b, pump_b = _swarm(3)
    for sw, bots, pump in ((a, a_bots, pump_a), (b, b_bots, pump_b)):
        sw.create()
        for bot in bots[1:]:
            assert sw.add_batch([bot])
            pump()
        assert all(x.member for x in bots)
    assert a.stats.commits == 3 and b.stats.commits == 2
    for _ in range(240):
        clock_a.t += 0.5
        clock_b.t += 0.5
        a.tick(); pump_a()
        b.tick(); pump_b()
    row = st.combine_rows([a, b], 120, online=7, lag=0.3)
    assert row["groups"] == 2 and row["members"] == 7 and row["largest_group"] == 4
    assert row["sent"] > 0 and row["delivery_pct"] == 100.0
    assert row["harness_lag_s"] == 0.3
    assert a.stats.sent == 0 and b.stats.sent == 0          # both reset


def test_the_defaults_add_like_the_app():
    args = st.build_parser().parse_args(["--admin", "a@x"])
    assert args.batch == 1 and args.groups == 1


class TestAPacedServer:
    """mod_otrv4plus_capacity login_rate answers a crowd "busy": the bots
    retry like the apps, and the run says how many were paced."""

    def test_a_busy_answer_is_retried_until_let_in(self, monkeypatch):
        import asyncio
        import otrv4plus_stresstest as S

        class Client:
            def __init__(self):
                self.handlers = {}
                self.tries = 0
                self.presence = False

            def add_event_handler(self, name, fn):
                self.handlers.setdefault(name, []).append(fn)

            def del_event_handler(self, name, fn):
                self.handlers[name].remove(fn)

            def connect(self, host, port):
                self.tries += 1
                if self.tries < 3:
                    for fn in list(self.handlers["stream_error"]):
                        fn({"condition": "resource-constraint",
                            "text": "The server is busy letting people in."})
                else:
                    for fn in list(self.handlers["session_start"]):
                        fn(None)

            def send_presence(self):
                self.presence = True

        async def no_wait(_s):
            return None

        monkeypatch.setattr(S.asyncio, "sleep", no_wait)
        S.PACED["n"] = 0
        c = Client()
        asyncio.run(S._online(c, "127.0.0.1", 5222, timeout=1))
        assert c.tries == 3 and c.presence
        assert S.PACED["n"] == 2
        assert all(not v for v in c.handlers.values())

    def test_full_is_not_busy(self):
        import otrv4plus_stresstest as S
        assert not S._is_busy({"condition": "resource-constraint",
                               "text": "This server is full"})


def test_only_empty_rooms_of_earlier_runs_are_swept():
    """Owner, 2026-10-17: 90 rooms left by killed runs. A room with anyone
    in it may be a parallel run's, so it is kept; real rooms never match."""
    muc = "conference.x.i2p"
    rooms = [{"jid": "stress-1345de-g07@" + muc, "occupants": 0},
             {"jid": "stress-d045a4-g01@" + muc, "occupants": 3},
             {"jid": "welcome@" + muc, "occupants": 0},
             {"jid": "stress-talk@" + muc, "occupants": 0},
             {"jid": "stress-885e11-g05@other.i2p", "occupants": 0}]
    assert st._stale_stress_rooms(rooms, muc) == ["stress-1345de-g07@" + muc]


def test_the_open_files_limit_is_raised_for_big_runs(monkeypatch):
    import sys
    import types
    limits = {"now": (1024, 4096)}
    fake = types.SimpleNamespace(
        RLIMIT_NOFILE=7, RLIM_INFINITY=-1,
        getrlimit=lambda _which: limits["now"],
        setrlimit=lambda _which, value: limits.__setitem__("now", value))
    monkeypatch.setitem(sys.modules, "resource", fake)
    said = []
    st._raise_open_files(2000, said.append)
    assert limits["now"] == (2256, 4096) and said == []
    limits["now"] = (1024, 1024)            # the hard limit is too low
    st._raise_open_files(2000, said.append)
    assert said and "ulimit -n 2256" in said[0]
