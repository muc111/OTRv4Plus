# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Termux A + Termux B + Android C in ONE OTRv4Plus secure group (MLS).

WHAT RUNS FOR REAL
==================
  * Termux A and B are real `otrv4plus_xmpp.OTRv4PlusXMPP` clients (built
    without slixmpp's constructor, see xmpp_double): inbound chat goes through
    their own `_on_message` -> `_handle_otr_in_async` routing, room messages
    through `_on_groupchat`, commands through `/group ...` and `dispatch_line`.
  * Android C is a real `android_bridge.app.OtrApp`, the object the Kotlin
    app drives.
  * Every OTRv4+ session is a real `EnhancedSessionManager` DAKE, configured
    as each platform configures it; the group setup signals (invitation,
    KeyPackage, Welcome) travel inside those real encrypted sessions.
  * MLS is the real Rust core (OpenMLS via `RustMlsClient`), with the real
    `?OTRv4MLS1:` room framing and `otrv4plus_fragment` fragmentation.

WHAT IS SIMULATED
=================
The XMPP server: 1:1 chat is routed to the recipient, and a room relays every
body to every occupant in one order, the sender included (XEP-0045
reflection). Also stubbed on the Termux side: the TOFU / SMP *display* hooks
the inbound path calls, which have nothing to do with groups.

WHAT THIS IS NOT: three devices, a real XMPP server, or I2P. PHYSICAL_TEST_PLAN
§7 is the handset procedure.
"""
from __future__ import annotations

import asyncio
import collections
import concurrent.futures
import os
import tempfile
import uuid

import pytest

otr = pytest.importorskip("otrv4_")
core = pytest.importorskip("otrv4_core")
if not hasattr(core, "RustMlsClient"):
    pytest.skip("this core was built without the mls feature",
                allow_module_level=True)
slixmpp = pytest.importorskip("slixmpp")

import otrv4plus_fragment as frag                                     # noqa: E402
import otrv4plus_groups as OG                                         # noqa: E402
import otrv4plus_xmpp as X                                            # noqa: E402
from android_bridge.app import OtrApp, Transport                      # noqa: E402
from android_bridge.events import (GroupChanged, GroupInvite,         # noqa: E402
                                   RoomMessageReceived, SecurityState)
from android_bridge.groups import ROOM_PREFIX, SIGNAL_PREFIX          # noqa: E402
from xmpp_double import bare_client                                   # noqa: E402

DOMAIN = "example.test"
ROOM = "circle@conference." + DOMAIN


# ── the simulated server ─────────────────────────────────────────────────────

class Msg(dict):
    """Just enough of a slixmpp Message for the handlers under test."""

    def __init__(self, mtype, frm, body):
        super().__init__(type=mtype, body=body)
        self["from"] = slixmpp.JID(frm)
        self["delay"] = {"stamp": None}


class Server:
    def __init__(self):
        self.queue = collections.deque()
        self.nodes = {}                        # bare jid -> node
        self.rooms = {}                        # room -> {jid: nick}
        self.held = []                         # chat held back (ordering tests)
        self.hold_chat_to = None
        self.room_log = []                     # (room, nick, body)
        #: Prosody mod_muc_limits `muc_max_char_count` (default 5664): a
        #: longer room message is bounced, never relayed. None: no limit.
        self.room_char_limit = None
        self.room_bounced = []
        #: Drop the next N room messages from this jid (a rate-limit bounce).
        self.drop_room_from = None
        self.drop_room_count = 0

    def attach(self, node):
        self.nodes[node.jid] = node

    def send(self, frm, to, body, mtype):
        to = str(to).split("/", 1)[0].lower()
        if mtype == "groupchat":
            nick = self.rooms.get(to, {}).get(frm)
            if nick is None:
                return                          # not an occupant: dropped
            if self.drop_room_from == frm and self.drop_room_count > 0:
                self.drop_room_count -= 1
                self.room_bounced.append((to, nick, len(body)))
                return
            if self.room_char_limit and len(body) > self.room_char_limit:
                self.room_bounced.append((to, nick, len(body)))
                return                          # policy-violation bounce
            self.room_log.append((to, nick, body))
            for jid, _n in list(self.rooms.get(to, {}).items()):
                self.queue.append(("groupchat", jid, to, nick, body))
        else:
            item = ("chat", to, frm, None, body)
            if self.hold_chat_to == to:
                self.held.append(item)
            else:
                self.queue.append(item)

    def replay_room(self, index):
        room, nick, body = self.room_log[index]
        for jid in list(self.rooms.get(room, {})):
            self.queue.append(("groupchat", jid, room, nick, body))

    def release_held(self):
        self.hold_chat_to = None
        self.queue.extend(self.held)
        self.held = []

    async def pump(self):
        for _ in range(100000):
            if not self.queue:
                await _settle()
                if not self.queue:
                    return
                continue
            kind, to, frm, nick, body = self.queue.popleft()
            node = self.nodes.get(to)
            if node is None:
                continue
            if kind == "chat":
                node.deliver_chat(frm, body)
            else:
                node.deliver_room(frm, nick, body)
            await _settle()
        raise AssertionError("the server never went quiet")


async def _settle():
    for _ in range(200):
        me = asyncio.current_task()
        pending = [t for t in asyncio.all_tasks() if t is not me and not t.done()]
        if not pending:
            return
        await asyncio.gather(*pending, return_exceptions=True)


class Inline(concurrent.futures.Executor):
    """The OTR executor, run inline so the test is single-threaded."""

    def submit(self, fn, *args, **kwargs):
        f = concurrent.futures.Future()
        try:
            f.set_result(fn(*args, **kwargs))
        except BaseException as exc:          # noqa: BLE001
            f.set_exception(exc)
        return f


# ── Termux: the real client object ───────────────────────────────────────────

def _termux_config(directory):
    p = lambda name: os.path.join(directory, name)                    # noqa: E731
    return otr.OTRConfig(
        test_mode=True, persist_identity=True, persist_trust=True,
        trust_db_path=p("trust.json"), smp_secrets_path=p("smp_secrets.json"),
        identity_path=p("identity.sealed"), identity_dek_path=p(".identity_dek"),
        key_storage_path=p("keys"))


class FakeMuc:
    def __init__(self, server, jid):
        self.server, self.jid = server, jid
        self.configured = []

    async def join_muc_wait(self, room, nick, timeout=None, **_kw):
        self.server.rooms.setdefault(str(room), {})[self.jid] = nick

    async def set_room_config(self, room, form, timeout=None, **_kw):
        self.configured.append(str(room))

    def leave_muc(self, room, nick, *_a, **_kw):
        self.server.rooms.get(str(room), {}).pop(self.jid, None)


class FakeForms:
    def make_form(self, ftype="form", **_kw):
        return {"type": ftype}


class TermuxNode:
    def __init__(self, server, name, home):
        self.jid = "%s@%s" % (name, DOMAIN)
        self.server = server
        self.home = home
        self.printed = []
        c = bare_client(X.OTRv4PlusXMPP)
        c.otr = otr.EnhancedSessionManager(config=_termux_config(os.path.join(home, "otr")))
        c.otr.smp_guided_prompt = True
        c.boundjid = slixmpp.JID(self.jid + "/termux")
        c.peer = None
        c._probe = False
        c._blocked = set()
        c._peer_gone_at = {}
        c._rate_limit = {}
        c._file_manager = c._voice_manager = c._trade_manager = None
        c._smp_reported = set()
        c._otr_executor = Inline()
        c._frag_seq = 0
        # What dispatch_line reads before it reaches a command.
        c._secret_request = None
        c._secret_purpose = None
        c._admin_awaiting = False
        c._smp_flows = X._smpflow.SmpFlowRegistry()
        c._tip_manager = None
        # TOFU / SMP display hooks: not part of groups.
        for hook in ("_check_dake_complete", "_check_smp_secret_required",
                     "_expire_stale_smp_consent", "_report_smp"):
            setattr(c, hook, lambda *a, **k: None)
        c.send_message = lambda mto, mbody, mtype="chat", **_k: server.send(
            self.jid, mto, mbody, mtype)
        self.muc = FakeMuc(server, self.jid)
        c.plugin = {"xep_0045": self.muc, "xep_0004": FakeForms()}
        c._groups = OG.TermuxGroups(c, os.path.join(home, "groups"),
                                    printer=self.printed.append)
        c._wipe_on_exit = False
        self.client = c
        server.attach(self)

    @property
    def groups(self):
        return self.client._groups

    def open(self):
        assert self.groups.open(self.jid)

    def deliver_chat(self, frm, body):
        self.client._on_message(Msg("chat", frm + "/res", body))

    def deliver_room(self, room, nick, body):
        self.client._on_groupchat(Msg("groupchat", "%s/%s" % (room, nick), body))

    def start_otr(self, peer):
        frame, ok = self.client.otr.handle_outgoing_message(peer, "")
        assert ok and frame
        self.client.send_otr_fragmented(peer, frame if isinstance(frame, str) else frame.decode())

    async def cmd(self, line):
        assert self.client.dispatch_line(None, line) is True
        await _settle()

    def lines(self, needle):
        return [l for l in self.printed if needle in l]


# ── Android: the real OtrApp ─────────────────────────────────────────────────

class Sink:
    def __init__(self):
        self.events = []

    def on_event(self, event):
        self.events.append(event)


class AndroidNode(Transport):
    def __init__(self, server, name, home):
        self.jid = "%s@%s" % (name, DOMAIN)
        self.server = server
        self.seq = 0
        self.reasm = frag.Reassembler()
        cfg = otr.OTRConfig(test_mode=True)
        for attr, n in (("trust_db_path", "trust.json"), ("smp_secrets_path", "smp.json"),
                        ("key_storage_path", "keys")):
            setattr(cfg, attr, os.path.join(home, n))
        self.sink = Sink()
        self.app = OtrApp(otr.EnhancedSessionManager(config=cfg), self, self.sink)
        self.app.GROUP_STATE_DIR = os.path.join(home, "groups")
        server.attach(self)

    # Transport
    def send(self, peer, payload):
        parts, self.seq = frag.fragment(payload, self.seq)
        for p in parts:
            self.server.send(self.jid, peer, p, "chat")

    def send_room_message(self, room, body):
        self.server.send(self.jid, room, body, "groupchat")

    def connect(self): pass
    def disconnect(self): pass
    def roster(self): return []

    # server side
    def deliver_chat(self, frm, body):
        if frag.is_fragment(body):
            body = self.reasm.feed(frm, body)
            if body is None:
                return
        self.app.receive_message(frm, body)

    def deliver_room(self, room, nick, body):
        own = nick == self.jid.split("@")[0]
        # XmppTransport._on_groupchat: our own text is dropped, MLS kept.
        if own and not body.startswith((ROOM_PREFIX, "?OTRv4F|")):
            return
        self.app.receive_room_message(room, nick, body, 0.0, own=own)

    def accept(self, room):
        """ConnectionController.accept_group_invite: join, then accept."""
        self.server.rooms.setdefault(room, {})[self.jid] = self.jid.split("@")[0]
        self.app.note_room_joined(room)
        self.app.groups.accept(room)

    def texts(self):
        return [e.body for e in self.sink.events if isinstance(e, RoomMessageReceived)]


# ── fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def world():
    otr._dake1_rate_limiter._attempts.clear()
    root = tempfile.mkdtemp()
    tag = uuid.uuid4().hex[:6]
    server = Server()
    a = TermuxNode(server, "alice" + tag, os.path.join(root, "a"))
    b = TermuxNode(server, "bob" + tag, os.path.join(root, "b"))
    c = AndroidNode(server, "carol" + tag, os.path.join(root, "c"))
    a.open()
    b.open()
    assert c.app.open_groups(c.jid)
    w = type("W", (), {})()
    w.server, w.a, w.b, w.c, w.root = server, a, b, c, root
    yield w
    c.app.shutdown()


def run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


async def _otr_all(w):
    """Real OTRv4+ DAKEs: A-B and A-C (A invites both), B-C for completeness."""
    w.a.start_otr(w.b.jid)
    await w.server.pump()
    w.a.start_otr(w.c.jid)
    await w.server.pump()
    w.b.start_otr(w.c.jid)
    await w.server.pump()
    for x, y in ((w.a, w.b), (w.a, w.c), (w.b, w.c)):
        assert x.client.otr.has_encrypted_session(y.jid), (x.jid, y.jid)
    assert w.c.app.security_state(w.a.jid) is not SecurityState.PLAINTEXT


async def _three_member_group(w):
    await _otr_all(w)
    await w.a.cmd("/group create " + ROOM)
    assert w.a.groups.groups.is_secure(ROOM)
    assert w.a.muc.configured == [ROOM], "the instant room was not unlocked"
    await w.a.cmd("/group invite %s %s" % (ROOM, w.b.jid))
    await w.a.cmd("/group invite %s %s" % (ROOM, w.c.jid))
    await w.server.pump()
    assert w.b.lines("invites you to the secure group " + ROOM)
    assert any(isinstance(e, GroupInvite) and e.room == ROOM for e in w.c.sink.events)
    await w.b.cmd("/group accept " + ROOM)
    await w.server.pump()
    w.c.accept(ROOM)
    await w.server.pump()
    for node in (w.a.groups.groups, w.b.groups.groups, w.c.app.groups):
        assert node.is_secure(ROOM)
        assert len(node.members(ROOM)) == 3
    epochs = {w.a.groups.groups.epoch(ROOM), w.b.groups.groups.epoch(ROOM),
              w.c.app.groups.epoch(ROOM)}
    assert len(epochs) == 1, "the three members disagree on the epoch"


# ── the three-client lifecycle ───────────────────────────────────────────────

class TestThreeClients:

    def test_all_three_send_and_all_three_read(self, world):
        w = world

        async def go():
            await _three_member_group(w)
            await w.a.cmd("/group say %s hello from termux A" % ROOM)
            await w.server.pump()
            await w.b.cmd("/group say %s hello from termux B" % ROOM)
            await w.server.pump()
            assert w.c.app.send_user_text(ROOM, "hello from android C") == OtrApp.SEND_ENCRYPTED
            await w.server.pump()

        run(go())
        assert "hello from termux A" in w.c.texts()
        assert "hello from termux B" in w.c.texts()
        assert w.b.lines("hello from termux A") and w.b.lines("hello from android C")
        assert w.a.lines("hello from termux B") and w.a.lines("hello from android C")
        # The room carried ciphertext only.
        for _room, _nick, body in w.server.room_log:
            assert "hello from" not in body
            assert body.startswith((ROOM_PREFIX, "?OTRv4F|"))

    def test_the_setup_signals_never_reach_the_screen_or_the_room(self, world):
        w = world
        run(_three_member_group(w))
        for node in (w.a, w.b):
            assert not [l for l in node.printed if SIGNAL_PREFIX in l]
        assert not [b for _r, _n, b in w.server.room_log if SIGNAL_PREFIX in b]

    def test_a_large_message_is_fragmented_and_reassembled(self, world):
        w = world
        big = "x" * 30000

        async def go():
            await _three_member_group(w)
            await w.a.cmd("/group say %s %s" % (ROOM, big))
            await w.server.pump()

        run(go())
        assert any(b.startswith("?OTRv4F|") for _r, _n, b in w.server.room_log)
        assert big in w.c.texts()
        assert w.b.lines(big)

    def test_remove_member_and_the_removed_cannot_read(self, world):
        w = world

        async def go():
            await _three_member_group(w)
            await w.a.cmd("/group say %s before bob left" % ROOM)
            await w.server.pump()
            assert w.b.lines("before bob left")
            w.shown_before = w.b.groups.groups.stats.shown
            before = w.c.app.groups.epoch(ROOM)
            await w.a.cmd("/group remove %s %s" % (ROOM, w.b.jid))
            await w.server.pump()
            assert w.c.app.groups.epoch(ROOM) == before + 1
            assert len(w.a.groups.groups.members(ROOM)) == 2
            assert w.b.lines("you were removed")
            # Encrypted messaging continues between the remaining two ...
            assert w.c.app.send_user_text(ROOM, "after bob left") == OtrApp.SEND_ENCRYPTED
            await w.server.pump()
            await w.a.cmd("/group say %s also after bob left" % ROOM)
            await w.server.pump()

        run(go())
        assert w.a.lines("after bob left")
        assert "also after bob left" in w.c.texts()
        # ... and the removed member reads neither, though the room still
        # delivered both ciphertexts to it (Bob is still an occupant).
        assert w.b.jid in w.server.rooms[ROOM]
        assert not w.b.lines("after bob left")
        assert w.b.groups.groups.stats.shown == w.shown_before
        # Bob's client dropped the group's keys when the commit removed him.
        assert not w.b.groups.groups.is_secure(ROOM)
        assert sum(1 for _r, _n, b in w.server.room_log[-2:]
                   if b.startswith((ROOM_PREFIX, "?OTRv4F|"))) == 2

    def test_add_a_member_later(self, world):
        w = world

        async def go():
            await _otr_all(w)
            # Android C creates; Termux A joins; then Termux B is added later.
            w.server.rooms.setdefault(ROOM, {})[w.c.jid] = w.c.jid.split("@")[0]
            w.c.app.note_room_joined(ROOM)
            w.c.app.groups.create(ROOM)
            w.c.app.groups.invite(ROOM, w.a.jid)
            await w.server.pump()
            await w.a.cmd("/group accept " + ROOM)
            await w.server.pump()
            assert w.a.groups.groups.is_secure(ROOM)
            w.c.app.send_user_text(ROOM, "two of us")
            await w.server.pump()
            w.c.app.groups.invite(ROOM, w.b.jid)
            await w.server.pump()
            await w.b.cmd("/group accept " + ROOM)
            await w.server.pump()
            assert len(w.b.groups.groups.members(ROOM)) == 3
            await w.b.cmd("/group say %s the newcomer speaks" % ROOM)
            await w.server.pump()

        run(go())
        assert w.a.lines("two of us")
        assert not w.b.lines("two of us"), "history from before joining was shown"
        assert "the newcomer speaks" in w.c.texts()
        assert w.a.lines("the newcomer speaks")

    def test_a_welcome_slower_than_the_room_still_delivers(self, world):
        """Over I2P the Welcome (an OTRv4+ message) can arrive after the
        first application message in the room. It is held, bounded, and
        processed once the Welcome lands."""
        w = world

        async def go():
            await _otr_all(w)
            await w.a.cmd("/group create " + ROOM)
            await w.a.cmd("/group invite %s %s" % (ROOM, w.b.jid))
            await w.server.pump()
            await w.b.cmd("/group accept " + ROOM)
            w.server.hold_chat_to = w.b.jid        # the Welcome will be late
            await w.server.pump()
            await w.a.cmd("/group say %s before your welcome" % ROOM)
            await w.server.pump()
            assert not w.b.lines("before your welcome")
            w.server.release_held()
            await w.server.pump()

        run(go())
        assert w.b.lines("before your welcome")


# ── fail closed ──────────────────────────────────────────────────────────────

class TestFailClosed:

    def test_plaintext_in_a_secure_room_is_refused(self, world):
        w = world

        async def go():
            await _three_member_group(w)
            w.server.rooms[ROOM]["intruder@" + DOMAIN] = "intruder"
            w.server.send("intruder@" + DOMAIN, ROOM, "read me in the clear", "groupchat")
            await w.server.pump()

        run(go())
        for node in (w.a, w.b):
            assert not node.lines("read me in the clear")
            assert node.lines("room_plaintext_refused")
        assert "read me in the clear" not in w.c.texts()

    def test_a_secure_room_never_sends_plaintext(self, world):
        w = world

        async def go():
            await _three_member_group(w)
            n = len(w.server.room_log)
            w.a.groups.groups._client.wipe()          # MLS unusable now
            await w.a.cmd("/group say %s must not leak" % ROOM)
            await w.server.pump()
            return n

        n = run(go())
        assert len(w.server.room_log) == n, "something was posted to the room"
        assert w.a.lines("nothing was sent in the clear")

    def test_typing_into_the_room_as_a_conversation_is_mls_or_nothing(self, world):
        """The room as the active conversation: a typed line goes through
        send_user_text, which must hand it to MLS, never the 1:1 path."""
        w = world

        async def go():
            await _three_member_group(w)
            w.a.client.send_user_text(ROOM, "typed into the room")
            await w.server.pump()
            # A room joined for an invitation whose Welcome has not come:
            # refused, not sent.
            pending = "pending@conference." + DOMAIN
            w.a.groups._nicks[pending] = "alice"
            n = len(w.server.room_log)
            w.a.client.send_user_text(pending, "must not go out")
            return n

        n = run(go())
        assert "typed into the room" in w.c.texts()
        assert len(w.server.room_log) == n
        assert w.a.lines("not sent: not_a_group")
        assert not [b for _r, _n, b in w.server.room_log if "must not go out" in b]

    def test_malformed_and_tampered_frames_are_dropped(self, world):
        w = world

        async def go():
            await _three_member_group(w)
            for body in (ROOM_PREFIX + "not base64!!", ROOM_PREFIX + "QUJD",
                         ROOM_PREFIX, "?OTRv4F|x|1|2|junk"):
                w.server.send(w.c.jid, ROOM, body, "groupchat")
            await w.server.pump()

        run(go())
        for node in (w.a, w.b):
            assert not [l for l in node.printed if "not base64" in l or "QUJD" in l]
            assert node.groups.groups.stats.shown == 0

    def test_a_replayed_application_message_is_not_shown_twice(self, world):
        w = world

        async def go():
            await _three_member_group(w)
            await w.a.cmd("/group say %s once only" % ROOM)
            await w.server.pump()
            idx = len(w.server.room_log) - 1
            w.server.replay_room(idx)
            w.server.replay_room(idx)
            await w.server.pump()

        run(go())
        assert len(w.b.lines("once only")) == 1
        assert w.c.texts().count("once only") == 1

    def test_a_missed_commit_fails_closed_with_the_recovery_hint(self, world):
        w = world

        async def go():
            await _three_member_group(w)
            # B misses A's rekey commit (offline, beyond the room's history).
            occupants = w.server.rooms[ROOM]
            nick_b = occupants.pop(w.b.jid)
            await w.a.cmd("/group rekey " + ROOM)
            await w.server.pump()
            occupants[w.b.jid] = nick_b
            for i in range(OG.STALE_WARN_AFTER):
                assert w.c.app.send_user_text(ROOM, "stale %d" % i) == OtrApp.SEND_ENCRYPTED
                await w.server.pump()

        run(go())
        assert not w.b.lines("stale 0")
        assert w.b.lines("remove you and invite you again")
        assert w.a.lines("stale 0")

    def test_an_unencrypted_group_signal_is_refused(self, world, capsys):
        w = world
        w.server.send(w.c.jid, w.a.jid, SIGNAL_PREFIX + "INVITE:%s|%s" % (ROOM, "0" * 96),
                      "chat")
        run(w.server.pump())
        assert "ignoring UNENCRYPTED group setup message" in capsys.readouterr().out
        assert w.a.groups.groups.pending_invites() == []

    def test_an_ordinary_room_is_never_read_as_mls(self, world):
        w = world
        plain = "plain@conference." + DOMAIN
        w.server.rooms[plain] = {w.a.jid: "alice", w.c.jid: "carol"}
        w.server.send(w.c.jid, plain, "just chatting", "groupchat")
        w.server.send(w.c.jid, plain, ROOM_PREFIX + "QUJD", "groupchat")
        run(w.server.pump())
        assert w.a.lines("(NOT end-to-end encrypted) carol: just chatting")
        assert not w.a.lines("QUJD")
        assert w.a.groups.groups.stats.malformed == 0


# ── persistence, /quit and /wipe ─────────────────────────────────────────────

class TestProposal:

    def test_a_standalone_proposal_is_processed_not_shown(self):
        """The Rust core queues an authenticated standalone Proposal and
        reports kind "proposal" (Rust test
        `a_standalone_proposal_is_queued_then_committed`). Through the Termux
        room path it is handled -- neither shown nor counted as undecryptable,
        nor refused as plaintext."""
        class Client:
            def has_group(self, g): return True
            def group_ids(self): return [ROOM.encode()]
            def process(self, g, m): return {"kind": "proposal"}

        class Core:
            RustMlsClient = object

        printed = []
        host = type("H", (), {})()
        g = OG.TermuxGroups(host, None, printer=printed.append, core=Core())
        g.groups._client = Client()
        g.groups._account = "alice@" + DOMAIN
        g._opened = True
        g.on_room_body(ROOM, "bob", ROOM_PREFIX + "QUJD", 0.0)
        s = g.groups.stats
        assert (s.shown, s.undecryptable, s.plaintext_refused, s.malformed) == (0, 0, 0, 0)
        assert printed == []


class TestPersistenceAndWipe:

    def test_a_restart_restores_the_group(self, world):
        w = world

        async def go():
            await _three_member_group(w)
            w.a.groups.close()                       # /quit
            assert [f for f in os.listdir(os.path.join(w.a.home, "groups"))
                    if f.startswith("groups-") and f.endswith(".sealed")]
            # A new process: a fresh adapter over the same state directory.
            w.a.printed.clear()
            w.a.client._groups = OG.TermuxGroups(
                w.a.client, os.path.join(w.a.home, "groups"), printer=w.a.printed.append)
            w.a.server.rooms[ROOM].pop(w.a.jid)      # our old room presence is gone
            w.a.open()
            assert w.a.lines("1 secure group(s) restored: " + ROOM)
            await w.a.client._groups.rejoin_all()
            assert w.a.jid in w.server.rooms[ROOM]
            assert w.c.app.send_user_text(ROOM, "after your restart") == OtrApp.SEND_ENCRYPTED
            await w.server.pump()
            await w.a.cmd("/group say %s I am back" % ROOM)
            await w.server.pump()

        run(go())
        assert w.a.lines("after your restart")
        assert "I am back" in w.c.texts()

    def test_a_reconnect_rejoins_the_room(self, world):
        """After a reconnect the server has dropped our room presence even
        though we remember joining; the rejoin must happen anyway."""
        w = world

        async def go():
            await _three_member_group(w)
            w.server.rooms[ROOM].pop(w.b.jid)          # the stream dropped
            await w.b.client._groups.rejoin_all()      # _on_start runs this
            assert w.b.jid in w.server.rooms[ROOM]
            assert w.c.app.send_user_text(ROOM, "welcome back") == OtrApp.SEND_ENCRYPTED
            await w.server.pump()

        run(go())
        assert w.b.lines("welcome back")

    def test_state_is_sealed_to_this_account(self, world):
        w = world
        run(_three_member_group(w))
        w.a.groups.close()
        other = OG.TermuxGroups(w.a.client, os.path.join(w.a.home, "groups"),
                                printer=lambda *_: None)
        assert other.open("mallory@" + DOMAIN)
        assert other.groups.rooms() == []

    def _cleanup_client(self, w, monkeypatch, home):
        monkeypatch.setenv("HOME", home)
        monkeypatch.setattr(X, "XMPP_STATE_DIR", os.path.join(home, ".otrv4plus", "xmpp"))
        c = w.a.client
        c._cleaned_up = False
        c._peer_gone_task = None
        c.channel_log = None
        c._otr_executor = Inline()
        c._groups = OG.TermuxGroups(c, X._xmpp_state_path("groups"),
                                    printer=w.a.printed.append)
        assert c._groups.open(w.a.jid)
        c._groups.groups.create(ROOM)
        xdir = X.XMPP_STATE_DIR
        for name in ("trust.json", ".identity_dek", "identity.sealed"):
            with open(os.path.join(xdir, name), "w") as f:
                f.write("x")
        return c, xdir

    def test_quit_keeps_only_the_sealed_group_state(self, world, monkeypatch):
        w = world
        home = tempfile.mkdtemp()
        c, xdir = self._cleanup_client(w, monkeypatch, home)
        c.cleanup()
        gdir = os.path.join(xdir, "groups")
        kept = sorted(f for f in os.listdir(gdir) if not f.endswith(".lock"))
        assert kept[0] == "groups-" + __import__("hashlib").sha256(
            w.a.jid.encode()).hexdigest()[:20] + ".sealed", kept
        assert set(kept[1:]) <= {kept[0] + ".prev", "groups.dek"} and "groups.dek" in kept
        assert not os.path.exists(os.path.join(xdir, "trust.json")), \
            "the ordinary /quit wipe no longer ran"
        again = OG.TermuxGroups(c, gdir, printer=lambda *_: None)
        assert again.open(w.a.jid) and again.groups.is_secure(ROOM)

    def test_wipe_destroys_the_groups_and_everything_else(self, world, monkeypatch):
        w = world
        home = tempfile.mkdtemp()
        c, xdir = self._cleanup_client(w, monkeypatch, home)
        rust_client = c._groups.groups._client
        assert c.dispatch_line(None, "/wipe") is False
        c.cleanup()
        assert rust_client.wiped is True
        left = [os.path.join(d, f) for d, _s, fs in os.walk(os.path.join(home, ".otrv4plus"))
                for f in fs]
        assert left == [], left
        again = OG.TermuxGroups(c, X._xmpp_state_path("groups"), printer=lambda *_: None)
        assert again.open(w.a.jid) and again.groups.rooms() == []


# ── boundaries ───────────────────────────────────────────────────────────────

class TestBoundaries:

    def test_one_wire_format_shared_with_android(self):
        assert X.GROUP_SIGNAL_PREFIX == SIGNAL_PREFIX
        assert OG.ROOM_PREFIX == ROOM_PREFIX == "?OTRv4MLS1:"
        assert OG.SecureGroups is __import__("android_bridge.groups",
                                             fromlist=["x"]).SecureGroups

    def test_no_mls_cryptography_in_python(self):
        src = open(OG.__file__, encoding="utf-8").read()
        for banned in ("hashlib", "hmac", "cryptography", "Cipher", "AESGCM",
                       "import secrets", "nacl"):
            assert banned not in src, banned

    def test_group_plaintext_never_reaches_the_session_log(self):
        for line in ("[group %s] carol (carol@x, unverified): the plan is secret" % ROOM,
                     "[room %s] (NOT end-to-end encrypted) carol: the plan is secret" % ROOM,
                     "[group %s] me: the plan is secret" % ROOM):
            assert "secret" not in X._log_line_for_file(line)

    def test_the_termux_build_enables_mls(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        build = open(os.path.join(root, "Rust", "build.sh"), encoding="utf-8").read()
        assert '"$MATURIN" build --release --features mls' in build
        # The import check the procedure (PHYSICAL_TEST_PLAN.md 7a) relies on.
        assert 'print("otrv4_core imported OK")' in build
        assert '"yes" if mls else "NO"' in build


class TestTheAppCreatesAndTermuxJoins:
    """The device test's direction, 2026-10-02: Alice creates the group IN THE
    APP and invites a Termux user, who opened the OTRv4+ session with /otr.
    Every test above has Termux create it."""

    @pytest.mark.parametrize("limit", [None, 5664])
    def test_android_creates_termux_joins_and_both_talk(self, world, limit):
        """5664: a stock Prosody's mod_muc_limits, as on the device test's
        server -- where every MLS room fragment (6021 characters) bounced."""
        w = world
        w.server.room_char_limit = limit

        async def go():
            w.b.start_otr(w.c.jid)                 # B: /otr <alice on the app>
            await w.server.pump()
            assert w.b.client.otr.has_encrypted_session(w.c.jid)
            # The app: create (RoomsScreen "Create end-to-end encrypted group").
            w.server.rooms.setdefault(ROOM, {})[w.c.jid] = w.c.jid.split("@")[0]
            w.c.app.note_room_joined(ROOM)
            w.c.app.groups.create(ROOM)
            w.c.app.groups.invite(ROOM, w.b.jid)
            await w.server.pump()
            assert w.b.lines("invites you to the secure group " + ROOM)
            await w.b.cmd("/group accept " + ROOM)
            await w.server.pump()

        run(go())
        assert w.b.groups.groups.is_secure(ROOM), "\n".join(w.b.printed[-15:])
        assert w.c.app.send_user_text(ROOM, "hello from the app") == OtrApp.SEND_ENCRYPTED
        run(w.server.pump())
        assert w.b.lines("hello from the app")
        run(w.b.cmd("/group say %s hello from termux" % ROOM))
        run(w.server.pump())
        assert "hello from termux" in w.c.texts()
        assert w.server.room_bounced == []


def test_room_fragments_fit_a_stock_prosody():
    """Every room fragment, header included, under mod_muc_limits' default
    5664 characters, for the largest frame a group posts (a commit adding a
    member: ~40 KB)."""
    payload = ROOM_PREFIX + "A" * 40439
    parts, _ = frag.fragment(payload, 0, frag.ROOM_FRAGMENT)
    assert max(len(p) for p in parts) < 5664
    r = frag.Reassembler()
    out = [r.feed("room/nick", p) for p in parts]
    assert out[-1] == payload and all(o is None for o in out[:-1])
    # One-to-one chat is unchanged.
    assert max(len(p) for p in frag.fragment(payload, 0)[0]) > 5664



class TestALostCommitIsSentAgain:
    """Device test, 2026-10-02: the creator's commit adding a member bounced
    off the server. MLS held it pending -- every send refused, "message not
    sent" -- and the member never got a Welcome. Nothing ever sent it again."""

    def _setup(self, w):
        async def go():
            w.b.start_otr(w.c.jid)
            await w.server.pump()
            w.server.rooms.setdefault(ROOM, {})[w.c.jid] = w.c.jid.split("@")[0]
            w.c.app.note_room_joined(ROOM)
            w.c.app.groups.create(ROOM)
            w.c.app.groups.invite(ROOM, w.b.jid)
            await w.server.pump()
            # Every fragment of the coming commit is bounced.
            w.server.drop_room_from = w.c.jid
            w.server.drop_room_count = 1000
            await w.b.cmd("/group accept " + ROOM)
            await w.server.pump()
        run(go())
        assert w.server.room_bounced, "the commit was not posted at all"
        assert not w.b.groups.groups.is_secure(ROOM)
        assert w.c.app.groups._client.has_pending_commit(ROOM.encode())
        w.server.drop_room_count = 0

    def _finish(self, w):
        run(w.server.pump())
        assert w.b.groups.groups.is_secure(ROOM), "\n".join(w.b.printed[-10:])
        assert w.c.app.send_user_text(ROOM, "after the resend") == OtrApp.SEND_ENCRYPTED
        run(w.server.pump())
        assert w.b.lines("after the resend")

    def test_a_bounce_notice_sends_it_again(self, world):
        w = world
        self._setup(w)
        w.c.app.groups.on_room_rejected(ROOM)      # what the transport reports
        self._finish(w)

    def test_trying_to_send_sends_it_again(self, world):
        w = world
        self._setup(w)
        from android_bridge.groups import GroupError
        with pytest.raises(GroupError) as exc:
            w.c.app.groups.send(ROOM, "blocked")
        assert exc.value.code == "commit_pending"
        self._finish(w)

    def test_rejoining_the_room_sends_it_again(self, world):
        w = world
        self._setup(w)
        w.c.app.groups.on_room_rejoined(ROOM)
        self._finish(w)

    def test_resends_are_bounded(self, world):
        w = world
        self._setup(w)
        w.server.drop_room_count = 1000
        sent = [w.c.app.groups.resend_pending_commit(ROOM, "t") for _ in range(6)]
        assert sent.count(True) == w.c.app.groups.MAX_COMMIT_RESENDS


class TestTermuxSendsRoomFragmentsOnItsLoop:
    """RoomPacer sends from a timer thread; slixmpp's queue is not
    thread-safe, so TermuxGroups hands an off-loop send to the loop."""

    def test_off_loop_send_goes_through_call_soon_threadsafe(self):
        import threading

        calls = []

        class Loop:
            def is_running(self):
                return True

            def call_soon_threadsafe(self, fn):
                calls.append("threadsafe")
                fn()

        class Host:
            loop = Loop()
            sent = []

            def send_message(self, mto, mbody, mtype):
                self.sent.append((mto, mtype))

        g = OG.TermuxGroups.__new__(OG.TermuxGroups)
        g.host = Host()
        t = threading.Thread(target=g._send_room, args=(ROOM, "x"))
        t.start()
        t.join()
        assert calls == ["threadsafe"] and g.host.sent == [(ROOM, "groupchat")]


class TestAutomaticRekey:
    """Post-compromise security without anybody typing /group rekey: after
    AUTO_REKEY_MESSAGES sends (or AUTO_REKEY_SECONDS) the sender's client
    self-updates. Everyone moves to the new epoch and keeps reading."""

    def _group(self, w):
        async def go():
            w.b.start_otr(w.c.jid)
            await w.server.pump()
            w.server.rooms.setdefault(ROOM, {})[w.c.jid] = w.c.jid.split("@")[0]
            w.c.app.note_room_joined(ROOM)
            w.c.app.groups.create(ROOM)
            w.c.app.groups.invite(ROOM, w.b.jid)
            await w.server.pump()
            await w.b.cmd("/group accept " + ROOM)
            await w.server.pump()
        run(go())
        assert w.b.groups.groups.is_secure(ROOM)

    def test_the_sender_rekeys_after_enough_messages(self, world, monkeypatch):
        from android_bridge.groups import SecureGroups
        monkeypatch.setattr(SecureGroups, "AUTO_REKEY_MESSAGES", 3)
        w = world
        self._group(w)
        start = w.c.app.groups.epoch(ROOM)
        for i in range(3):
            assert w.c.app.send_user_text(ROOM, "m%d" % i) == OtrApp.SEND_ENCRYPTED
            run(w.server.pump())
        assert w.c.app.groups.epoch(ROOM) == start + 1
        assert w.b.groups.groups.epoch(ROOM) == start + 1
        assert w.c.app.send_user_text(ROOM, "after the rekey") == OtrApp.SEND_ENCRYPTED
        run(w.server.pump())
        assert w.b.lines("after the rekey") and w.b.lines("m2")

    def test_the_sender_rekeys_after_enough_time(self, world, monkeypatch):
        from android_bridge.groups import SecureGroups
        w = world
        self._group(w)
        start = w.c.app.groups.epoch(ROOM)
        monkeypatch.setattr(SecureGroups, "AUTO_REKEY_SECONDS", 0)
        assert w.c.app.send_user_text(ROOM, "late") == OtrApp.SEND_ENCRYPTED
        run(w.server.pump())
        assert w.c.app.groups.epoch(ROOM) == start + 1 == w.b.groups.groups.epoch(ROOM)

    def test_no_rekey_while_a_commit_is_pending(self, world, monkeypatch):
        from android_bridge.groups import SecureGroups
        monkeypatch.setattr(SecureGroups, "AUTO_REKEY_MESSAGES", 1)
        w = world
        self._group(w)
        g = w.c.app.groups
        g._unconfirmed[ROOM] = [b"x", 0]                 # ours, not yet back
        before = g.epoch(ROOM)
        g._maybe_rekey(ROOM)
        assert not g._client.has_pending_commit(ROOM.encode())
        assert g.epoch(ROOM) == before
