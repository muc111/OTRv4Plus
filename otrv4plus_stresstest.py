# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Load test for YOUR OWN Prosody server: simulated users in one MLS group.

Owner request (2026-10-16): "a secret --stresstest flag ... generate accounts,
an e2ee group chat, invite each automated tester into the group, each user
chats to the others ... run for 60 or 120 minutes to see how the server
performs ... only a server admin can stress test".

    python3 otrv4plus_xmpp.py --stresstest --admin alice@otrv4plus.i2p \\
        --users 60 --minutes 60

ONLY A SERVER ADMIN CAN RUN IT, AND THE SERVER ENFORCES THAT. Accounts are
created with the XEP-0133 "add-user" command, which Prosody runs for its
admins only; anybody else is refused by the server itself, not by this file.
The admin's password is asked for, never taken from the command line or kept.
Every account it makes is deleted again at the end ("delete-user") unless
--keep is given; the room is not persistent and goes when the last bot leaves.

WHAT IT DOES
  1. Signs in as the admin and checks the server lists the admin commands.
  2. Creates --users accounts (stress-<run>-<n>, random passwords, in memory).
  3. Each bot connects to Prosody DIRECTLY (default 127.0.0.1:5222 -- run
     this on the server machine): the point is to load Prosody, not to build
     hundreds of I2P tunnels, which would load i2pd instead.
  4. Bot 0 creates a secure group (MLS, the app's own hybrid post-quantum
     suite) in a new room; the others are added in batches (--batch) every
     --ramp seconds, so you can see where things start to degrade. Commits
     go through the room and Welcomes through the server as direct messages,
     fragmented exactly as the app does.
  5. Every member posts every --interval seconds on average (jittered): a
     short line about a made-up news story, MLS-encrypted, so the server only
     ever carries ciphertext. Nothing is fetched from the internet.
  6. Once a minute: members, messages, deliveries, latency (send -> decrypt),
     refusals and disconnects, printed and appended to a CSV file.

KNOWN LIMIT IT WILL FIND: a Welcome carries the whole ratchet tree, ~9.4 KB
per member with this suite, and the core refuses MLS messages over 1 MiB --
so joins stop at roughly 100 members. The run reports it as it happens.

Not part of the app: the APK does not ship this file.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import csv
import getpass
import ipaddress
import json
import random
import secrets
import ssl
import statistics
import sys
import time
from typing import Callable, Dict, List, Optional

import otrv4plus_fragment as _fragment

ROOM_PREFIX = "?OTRv4MLS1:"
WELCOME_PREFIX = "?OTRv4MLSW:"
ADMIN_ADD = "http://jabber.org/protocol/admin#add-user"
ADMIN_DELETE = "http://jabber.org/protocol/admin#delete-user"
COMMANDS_NODE = "http://jabber.org/protocol/commands"
#: The core's batch limit for one add (MAX_BATCH in Rust/src/mls_group.rs).
MAX_BATCH = 64
#: Room pacing, the app's (android_bridge/groups.py RoomPacer settings).
ROOM_BURST = 10
ROOM_INTERVAL = 0.25
ROOM_SLOW_INTERVAL = 2.2

#: Made-up news, so the chat reads like people talking; nothing is fetched.
_TOPICS = [
    "the new tram line opening next spring", "the storm forecast for the weekend",
    "the city council's budget vote", "the local football derby result",
    "rising rents in the old town", "the solar farm planned on the hill",
    "the museum's free entry week", "the bridge repairs closing the north road",
    "the record heat in the south", "the new library opening hours",
    "the train strike on Thursday", "the school meals funding row",
    "the river clean-up volunteers", "the night bus trial",
    "the farmers' market moving indoors", "the hospital waiting times report",
]
_TAKES = [
    "Did you see the piece on {t}?", "Anyone following {t}?",
    "Honestly not surprised about {t}.", "My neighbour says {t} is overblown.",
    "Reading up on {t} now, more detail than I expected.",
    "Interesting angle on {t} in today's paper.",
    "Not sure the coverage of {t} tells the whole story.",
    "Good news for once: {t}.",
]


def chatter(rng: random.Random) -> str:
    return rng.choice(_TAKES).format(t=rng.choice(_TOPICS))


def percentile(values: List[float], p: float) -> float:
    if not values:
        return 0.0
    v = sorted(values)
    k = max(0, min(len(v) - 1, int(round(p / 100.0 * (len(v) - 1)))))
    return v[k]


class Stats:
    """What a minute looked like. Counts only; no message content."""

    def __init__(self):
        self.reset()
        self.joined_total = 0
        self.join_refused = 0
        self.join_refused_at: Optional[int] = None

    def reset(self):
        self.sent = 0
        self.delivered = 0
        self.expected = 0
        self.latency: List[float] = []
        self.commits = 0
        self.commit_failures = 0
        self.room_errors = 0
        self.undecryptable = 0
        self.disconnects = 0


class Bot:
    """One simulated user: an MLS client and a way to talk to the server."""

    def __init__(self, index: int, jid: str, core):
        self.index = index
        self.jid = jid
        self.mls = core.RustMlsClient(jid.encode())
        self.member = False
        self.reasm = _fragment.Reassembler()
        self.frag_seq = 0
        self.observe = True             # decrypts application messages
        self.next_post = 0.0


class Swarm:
    """The group, the chatter and the measurements, independent of XMPP.

    [send_room](bot, body) posts one room body; [send_direct](bot, to_jid, body)
    one direct message. The XMPP runner and the tests supply them.
    """

    def __init__(self, core, room: str, bots: List[Bot], *,
                 send_room: Callable[[Bot, str], None],
                 send_direct: Callable[[Bot, str, str], None],
                 interval: float = 120.0, clock: Callable[[], float] = time.time,
                 rng: Optional[random.Random] = None, say: Callable[[str], None] = print):
        self.core = core
        self.room = room
        self.gid = room.encode()
        self.bots = bots
        self.by_jid = {b.jid: b for b in bots}
        self.send_room = send_room
        self.send_direct = send_direct
        self.interval = max(5.0, float(interval))
        self.clock = clock
        self.rng = rng or random.SystemRandom()
        self.say = say
        self.stats = Stats()
        self.owner = bots[0]
        self.pending_adds: List[Bot] = []     # added, Welcome not yet sent
        self.old_core_warned = False
        self.seq = 0

    # -- the group --------------------------------------------------------

    def create(self) -> None:
        self.owner.mls.create_group(self.gid)
        self.owner.member = True
        self.stats.joined_total = 1
        self.owner.next_post = self.clock() + self.rng.uniform(0, self.interval)

    def members(self) -> List[Bot]:
        return [b for b in self.bots if b.member]

    def add_batch(self, batch: List[Bot]) -> bool:
        """Bot 0 adds [batch]: the commit goes to the room. Returns False if
        the owner is still waiting for its previous commit."""
        if not batch or self.owner.mls.has_pending_commit(self.gid):
            return False
        kps = [bytes(b.mls.key_package()) for b in batch]
        try:
            try:
                commit = bytes(self.owner.mls.add_members(
                    self.gid, kps, identities=[b.jid.encode() for b in batch]))
            except TypeError:
                # An older compiled core (no identity check on add): fine for a
                # load test, where every KeyPackage is our own bot's. Device
                # report (2026-10-16): the laptop's core predated `identities`.
                if not self.old_core_warned:
                    self.old_core_warned = True
                    self.say("[stress] note: this machine's otrv4_core is older than "
                             "the code (no identity check on add); rebuild it to "
                             "match. Continuing.")
                commit = bytes(self.owner.mls.add_members(self.gid, kps))
        except Exception as exc:
            self.stats.commit_failures += 1
            self.say("[stress] add refused by the core: %s" % str(exc)[:80])
            return False
        self.pending_adds = list(batch)
        self._post(self.owner, base64.b64encode(commit).decode())
        return True

    def _post(self, bot: Bot, b64: str) -> None:
        parts, bot.frag_seq = _fragment.fragment(ROOM_PREFIX + b64, bot.frag_seq,
                                                 _fragment.ROOM_FRAGMENT)
        for part in parts:
            self.send_room(bot, part)

    # -- inbound ----------------------------------------------------------

    @staticmethod
    def nick(bot: Bot) -> str:
        return "u%03d" % bot.index

    def on_room(self, bot: Bot, sender_nick: str, body: str) -> None:
        """[bot] received [body] from the room (its own reflections too)."""
        own = sender_nick == self.nick(bot)
        if own and bot is not self.owner:
            return                  # our own chat: MLS cannot read it back
        whole = body
        if _fragment.is_fragment(body):
            whole = bot.reasm.feed(sender_nick, body)
            if whole is None:
                return
        if not whole.startswith(ROOM_PREFIX) or not bot.member:
            return
        try:
            mls = base64.b64decode(whole[len(ROOM_PREFIX):])
        except Exception:
            return
        try:
            ev = bot.mls.process(self.gid, mls)
        except Exception:
            # From before this bot joined, or out of order: counted. (The
            # owner's own chat reflected back is not a failure.)
            if not own:
                self.stats.undecryptable += 1
            return
        kind = ev.get("kind")
        if kind == "commit":
            if bot is self.owner:
                self.stats.commits += 1
                welcome = ev.get("welcome")
                if welcome is not None and self.pending_adds:
                    self._send_welcomes(bytes(welcome))
        elif kind == "application" and bot.observe:
            try:
                msg = json.loads(bytes(ev.get("plaintext")).decode())
                self.stats.delivered += 1
                self.stats.latency.append(max(0.0, self.clock() - float(msg["t"])))
            except Exception:
                pass

    def _send_welcomes(self, welcome: bytes) -> None:
        payload = WELCOME_PREFIX + base64.b64encode(welcome).decode()
        for b in self.pending_adds:
            parts, self.owner.frag_seq = _fragment.fragment(
                payload, self.owner.frag_seq, _fragment.MAX_FRAGMENT)
            for part in parts:
                self.send_direct(self.owner, b.jid, part)
        self.pending_adds = []

    def on_direct(self, bot: Bot, sender: str, body: str) -> None:
        whole = body
        if _fragment.is_fragment(body):
            whole = bot.reasm.feed(sender, body)
            if whole is None:
                return
        if not whole.startswith(WELCOME_PREFIX) or bot.member:
            return
        try:
            bot.mls.join(base64.b64decode(whole[len(WELCOME_PREFIX):]))
        except Exception as exc:
            self.stats.join_refused += 1
            if self.stats.join_refused_at is None:
                self.stats.join_refused_at = len(self.members())
                self.say("[stress] JOIN REFUSED at %d members: %s"
                         % (len(self.members()), str(exc)[:80]))
            return
        bot.member = True
        self.stats.joined_total += 1
        bot.next_post = self.clock() + self.rng.uniform(0, self.interval)

    # -- chatter ----------------------------------------------------------

    def tick(self) -> None:
        """Members whose turn it is post one line."""
        now = self.clock()
        members = self.members()
        observers = sum(1 for b in members if b.observe)
        for bot in members:
            if now < bot.next_post:
                continue
            bot.next_post = now + self.rng.uniform(0.5, 1.5) * self.interval
            if bot.mls.has_pending_commit(self.gid):
                continue
            self.seq += 1
            text = json.dumps({"t": now, "s": self.seq, "m": chatter(self.rng)})
            try:
                ct = bytes(bot.mls.encrypt(self.gid, text.encode()))
            except Exception:
                continue
            self.stats.sent += 1
            # Everyone who decrypts, except the sender itself.
            self.stats.expected += max(0, observers - (1 if bot.observe else 0))
            self._post(bot, base64.b64encode(ct).decode())

    def minute_row(self, elapsed: float, online: int) -> Dict[str, object]:
        s = self.stats
        row = {
            "elapsed_min": round(elapsed / 60.0, 1),
            "members": len(self.members()), "online": online,
            "sent": s.sent, "delivered": s.delivered, "expected": s.expected,
            "delivery_pct": round(100.0 * s.delivered / s.expected, 1) if s.expected else 100.0,
            "lat_p50_s": round(percentile(s.latency, 50), 2),
            "lat_p95_s": round(percentile(s.latency, 95), 2),
            "lat_max_s": round(max(s.latency), 2) if s.latency else 0.0,
            "commits": s.commits, "commit_failures": s.commit_failures,
            "room_errors": s.room_errors, "undecryptable": s.undecryptable,
            "disconnects": s.disconnects, "join_refused": s.join_refused,
        }
        s.reset()
        return row


# -- XMPP -------------------------------------------------------------------

def _loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host == "localhost"


def _client(jid: str, password: str, host: str):
    import slixmpp
    c = slixmpp.ClientXMPP(jid, password)
    for plugin in ("xep_0030", "xep_0045", "xep_0004", "xep_0050", "xep_0199"):
        c.register_plugin(plugin)
    if _loopback(host):
        # The server's certificate names its .i2p domain, not 127.0.0.1. Only
        # ever relaxed for a loopback connection on this machine.
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        c.ssl_context = ctx
    return c


async def _online(c, host: str, port: int, timeout: float = 60.0) -> None:
    ready = asyncio.get_running_loop().create_future()
    c.add_event_handler("session_start",
                        lambda _e: ready.done() or ready.set_result(True))
    c.add_event_handler("failed_auth",
                        lambda _e: ready.done() or ready.set_exception(
                            RuntimeError("authentication failed")))
    c.connect(host, port)
    await asyncio.wait_for(ready, timeout)
    c.send_presence()


async def _command(c, node: str, fields: Dict[str, object]) -> None:
    domain = c.boundjid.domain
    cmds = c["xep_0050"]
    first = await cmds.send_command(domain, node, action="execute", timeout=60)
    form = first["command"]["form"]
    submit = c["xep_0004"].make_form(ftype="submit")
    for var, field in form.get_fields().items():
        if var in fields:
            submit.add_field(var=var, ftype=field["type"], value=fields[var])
        elif var:
            submit.add_field(var=var, ftype=field["type"], value=field["value"])
    done = await cmds.send_command(domain, node, action="complete", payload=submit,
                                   sessionid=first["command"]["sessionid"], timeout=60)
    note = done["command"]["notes"]
    if note and any(kind == "error" for kind, _t in note):
        raise RuntimeError("server refused: %s" % note)


async def _is_admin(c) -> bool:
    items = await c["xep_0030"].get_items(jid=c.boundjid.domain, node=COMMANDS_NODE,
                                          timeout=60)
    return any(str(node) == ADMIN_ADD for _j, node, _n in items["disco_items"].get_items())


async def _muc_service(c) -> str:
    items = await c["xep_0030"].get_items(jid=c.boundjid.domain, timeout=60)
    for jid, _node, _name in items["disco_items"].get_items():
        try:
            info = await c["xep_0030"].get_info(jid=jid, timeout=30)
            for cat, typ, _l, _n in info["disco_info"]["identities"]:
                if cat == "conference" and typ == "text":
                    return str(jid)
        except Exception:
            continue
    raise RuntimeError("no MUC service found; pass --muc")


async def run(args) -> int:
    import otrv4_core as core
    say = print
    admin_jid = args.admin
    password = getpass.getpass("Password for %s: " % admin_jid)
    admin = _client(admin_jid, password, args.host)
    del password
    say("[stress] signing in as %s via %s:%d ..." % (admin_jid, args.host, args.port))
    await _online(admin, args.host, args.port)
    if not await _is_admin(admin):
        say("[stress] %s is not an administrator of this server (it does not "
            "list the XEP-0133 add-user command). Stopping." % admin_jid)
        admin.disconnect()
        return 2
    domain = admin.boundjid.domain
    muc = args.muc or await _muc_service(admin)
    run_id = secrets.token_hex(3)
    room = "stress-%s@%s" % (run_id, muc)
    csv_path = args.csv or "stresstest-%s.csv" % time.strftime("%Y%m%d-%H%M%S")
    say("[stress] run %s: %d users, room %s, %d min, CSV %s"
        % (run_id, args.users, room, args.minutes, csv_path))

    # 1. accounts
    creds = []
    for i in range(args.users):
        jid = "stress-%s-%03d@%s" % (run_id, i, domain)
        pw = secrets.token_urlsafe(18)
        await _command(admin, ADMIN_ADD, {"accountjid": jid, "password": pw,
                                          "password-verify": pw})
        creds.append((jid, pw))
        if (i + 1) % 25 == 0:
            say("[stress] %d accounts created" % (i + 1))

    bots = [Bot(i, jid, core) for i, (jid, _pw) in enumerate(creds)]
    if args.observers and args.observers < len(bots):
        for b in bots[args.observers:]:
            b.observe = False
    clients = {}
    swarm: Optional[Swarm] = None

    # Room pieces are paced like the app's RoomPacer: a burst of ROOM_BURST,
    # then one every ROOM_INTERVAL s, slowing to ROOM_SLOW_INTERVAL s for a
    # bot the room has pushed back on. Without it this would only measure
    # the server's flood limit.
    queues: Dict[str, asyncio.Queue] = {}
    slow: Dict[str, bool] = {}

    def send_room(bot: Bot, body: str) -> None:
        q = queues.get(bot.jid)
        if q is None:
            q = queues[bot.jid] = asyncio.Queue()
            asyncio.get_running_loop().create_task(drain(bot, q))
        q.put_nowait(body)

    async def drain(bot: Bot, q: asyncio.Queue) -> None:
        burst = ROOM_BURST
        while True:
            body = await q.get()
            c = clients.get(bot.jid)
            if c is not None:
                c.send_message(mto=room, mbody=body, mtype="groupchat")
            if q.empty():
                burst = ROOM_BURST
                continue
            if burst > 0 and not slow.get(bot.jid):
                burst -= 1
                continue
            await asyncio.sleep(ROOM_SLOW_INTERVAL if slow.get(bot.jid) else ROOM_INTERVAL)

    def send_direct(bot: Bot, to: str, body: str) -> None:
        clients[bot.jid].send_message(mto=to, mbody=body, mtype="chat")

    def wire(bot: Bot, c) -> None:
        def on_group(msg):
            if msg["type"] == "error":
                swarm.stats.room_errors += 1
                slow[bot.jid] = True
                return
            if str(msg["from"].bare) == room and msg["body"]:
                swarm.on_room(bot, msg["from"].resource, msg["body"])

        def on_chat(msg):
            if msg["type"] in ("chat", "normal") and msg["body"]:
                swarm.on_direct(bot, str(msg["from"].bare), msg["body"])
        c.add_event_handler("groupchat_message", on_group)
        c.add_event_handler("message", on_chat)
        c.add_event_handler("disconnected",
                            lambda _e: setattr(swarm.stats, "disconnects",
                                               swarm.stats.disconnects + 1))

    swarm = Swarm(core, room, bots, send_room=send_room, send_direct=send_direct,
                  interval=args.interval, say=say)
    try:
        # 2. connect and join, a few at a time
        sem = asyncio.Semaphore(max(1, args.connect_concurrency))

        async def bring_up(bot: Bot, pw: str, create: bool = False):
            async with sem:
                c = _client(bot.jid, pw, args.host)
                wire(bot, c)
                await _online(c, args.host, args.port)
                await c["xep_0045"].join_muc_wait(room, Swarm.nick(bot), timeout=60)
                if create:
                    # A new room is locked until its creator submits a
                    # configuration: the empty form takes the defaults.
                    form = c["xep_0004"].make_form(ftype="submit")
                    await c["xep_0045"].set_room_config(room, form, timeout=60)
                clients[bot.jid] = c
        await bring_up(bots[0], creds[0][1], create=True)
        await asyncio.gather(*(bring_up(b, pw) for b, (_j, pw)
                               in zip(bots[1:], creds[1:])))
        say("[stress] %d users online in %s" % (len(clients), room))

        # 3. the group, ramped
        swarm.create()
        waiting = bots[1:]
        start = time.time()
        next_add = start
        next_row = start + 60
        end = start + args.minutes * 60
        with open(csv_path, "w", newline="") as fh:
            writer = None
            while time.time() < end:
                now = time.time()
                if waiting and now >= next_add and not swarm.pending_adds:
                    batch, rest = waiting[:args.batch], waiting[args.batch:]
                    if swarm.add_batch(batch):
                        waiting = rest
                        next_add = now + args.ramp
                swarm.tick()
                if now >= next_row:
                    online = sum(1 for c in clients.values() if c.is_connected())
                    row = swarm.minute_row(now - start, online)
                    if writer is None:
                        writer = csv.DictWriter(fh, fieldnames=list(row))
                        writer.writeheader()
                    writer.writerow(row)
                    fh.flush()
                    say("[stress] %(elapsed_min)5.1f min  members %(members)3d  online "
                        "%(online)3d  sent %(sent)4d  delivered %(delivery_pct)5.1f%%  "
                        "latency p50 %(lat_p50_s).2fs p95 %(lat_p95_s).2fs  "
                        "commits %(commits)d  room errors %(room_errors)d  "
                        "disconnects %(disconnects)d" % row)
                    next_row += 60
                await asyncio.sleep(0.5)
        say("[stress] done. Joins refused: %d%s" % (
            swarm.stats.join_refused,
            "" if swarm.stats.join_refused_at is None
            else " (first at %d members)" % swarm.stats.join_refused_at))
    finally:
        for c in clients.values():
            try:
                c.disconnect()
            except Exception:
                pass
        if not args.keep:
            say("[stress] deleting %d accounts ..." % len(creds))
            for jid, _pw in creds:
                try:
                    await _command(admin, ADMIN_DELETE, {"accountjids": [jid]})
                except Exception as exc:
                    say("[stress] could not delete %s: %s" % (jid, str(exc)[:60]))
        for b in bots:
            try:
                b.mls.wipe()
            except Exception:
                pass
        creds.clear()
        admin.disconnect()
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="otrv4plus_xmpp.py --stresstest",
        description="Load-test YOUR OWN Prosody server (server admins only).")
    ap.add_argument("--admin", required=True, help="a server admin's JID")
    ap.add_argument("--users", type=int, default=50, help="simulated users (default 50)")
    ap.add_argument("--minutes", type=float, default=60, help="run length (default 60)")
    ap.add_argument("--interval", type=float, default=120,
                    help="average seconds between one user's messages (default 120)")
    ap.add_argument("--batch", type=int, default=16,
                    help="users added to the group per commit (default 16, max %d)" % MAX_BATCH)
    ap.add_argument("--ramp", type=float, default=60,
                    help="seconds between batches (default 60)")
    ap.add_argument("--observers", type=int, default=0,
                    help="only the first N users decrypt chat (saves this machine's CPU; "
                         "0 = all)")
    ap.add_argument("--host", default="127.0.0.1", help="Prosody c2s host (default 127.0.0.1)")
    ap.add_argument("--port", type=int, default=5222)
    ap.add_argument("--muc", help="MUC service (found by disco if omitted)")
    ap.add_argument("--connect-concurrency", type=int, default=10)
    ap.add_argument("--csv", help="where to write the per-minute numbers")
    ap.add_argument("--keep", action="store_true",
                    help="keep the test accounts afterwards (default: delete them)")
    return ap


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if not 1 <= args.batch <= MAX_BATCH:
        print("--batch must be 1..%d" % MAX_BATCH)
        return 2
    if args.users < 2:
        print("--users must be at least 2")
        return 2
    try:
        return asyncio.run(run(args))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
