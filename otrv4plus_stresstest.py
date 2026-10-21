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
--keep is given, and each group's room is destroyed (it is also created
not persistent, so a killed run's rooms go when the last bot leaves). Empty
stress rooms that earlier runs left behind are removed at the start and end
(needs mod_otrv4plus_moderation's "List all rooms").

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

  7. With --welcome, every bot also joins the server's public Welcome room
     (the one the apps join to see who is online), --welcome-rate a second,
     during the measured run. Each minute's row adds how many are in it,
     failed joins, and how long a join took (p50/p95: until the room's
     whole occupant list had arrived). This measures PRESENCE fan-out:
     each join is told to everyone already there, so the cost grows with
     the square of the room. REAL USERS IN WELCOME SEE THE BOTS JOIN AND
     LEAVE -- run it when nobody depends on the room.

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
#: Chat lines get their own prefix so a non-observer can skip them without
#: decrypting (run of 2026-10-16: every bot decrypted every line in this one
#: process, ~10 000 MLS decryptions per 25 s at 100 members, and the run
#: measured the laptop, not Prosody). Group changes keep ROOM_PREFIX: every
#: member must process those.
CHAT_PREFIX = "?OTRv4MLSC:"
WELCOME_PREFIX = "?OTRv4MLSW:"
ADMIN_ADD = "http://jabber.org/protocol/admin#add-user"
ADMIN_DELETE = "http://jabber.org/protocol/admin#delete-user"
COMMANDS_NODE = "http://jabber.org/protocol/commands"
#: The core's batch limit for one add (MAX_BATCH in Rust/src/mls_group.rs).
MAX_BATCH = 64

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
        self.lag_max = 0.0                  # this process's event-loop stall
        self.lost = 0                       # pieces the pacer gave up on


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
        self.room = ""                  # its group's room (the runner sets it)
        self.swarm = None


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

    def _post(self, bot: Bot, b64: str, prefix: str = ROOM_PREFIX) -> None:
        parts, bot.frag_seq = _fragment.fragment(prefix + b64, bot.frag_seq,
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
        if not bot.member:
            return
        if whole.startswith(CHAT_PREFIX):
            if not bot.observe and not own:
                return              # not measured: no need to decrypt it
            body64 = whole[len(CHAT_PREFIX):]
        elif whole.startswith(ROOM_PREFIX):
            body64 = whole[len(ROOM_PREFIX):]
        else:
            return
        try:
            mls = base64.b64decode(body64)
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
            self._post(bot, base64.b64encode(ct).decode(), CHAT_PREFIX)

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
            "harness_lag_s": round(s.lag_max, 2), "lost": s.lost,
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


#: Sign-ins the server asked to retry (mod_otrv4plus_capacity login_rate).
PACED = {"n": 0}


def _is_busy(stanza) -> bool:
    try:
        return (str(stanza["condition"]) == "resource-constraint"
                and "busy" in str(stanza["text"] or "").lower())
    except Exception:
        return False


async def _online(c, host: str, port: int, timeout: float = 60.0,
                  retry_for: float = 900.0) -> None:
    """Sign [c] in. A server pacing sign-ins (login_rate) answers a crowd
    "busy"; like the apps, retry after a randomised pause until let in."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + retry_for
    while True:
        ready = loop.create_future()
        busy = loop.create_future()

        def started(_e):
            ready.done() or ready.set_result(True)

        def refused(_e):
            ready.done() or ready.set_exception(RuntimeError("authentication failed"))

        def stream_error(stanza):
            if _is_busy(stanza):
                busy.done() or busy.set_result(True)

        c.add_event_handler("session_start", started)
        c.add_event_handler("failed_auth", refused)
        c.add_event_handler("stream_error", stream_error)
        try:
            c.connect(host, port)
            await asyncio.wait({ready, busy}, timeout=timeout,
                               return_when=asyncio.FIRST_COMPLETED)
        finally:
            c.del_event_handler("session_start", started)
            c.del_event_handler("failed_auth", refused)
            c.del_event_handler("stream_error", stream_error)
        if ready.done():
            ready.result()
            break
        if busy.done() and loop.time() < deadline:
            PACED["n"] += 1
            await asyncio.sleep(1 + secrets.randbelow(4000) / 1000)
            continue
        raise asyncio.TimeoutError("not signed in within %ds" % timeout)
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


def _why(exc: BaseException) -> str:
    """A failed command, said without the stanza (which str() of a slixmpp
    error is, cut to nothing useful: run of 2026-10-18 printed 300 lines of
    "<iq id=... type=set to=otr")."""
    name = type(exc).__name__
    if name in ("IqTimeout", "TimeoutError"):
        return "no answer from the server"
    try:
        condition = exc.iq["error"]["condition"]
        if condition:
            text = exc.iq["error"]["text"] or ""
            return condition + (": " + text if text else "")
    except Exception:
        pass
    if isinstance(exc, RuntimeError):
        return str(exc)[:120]
    return name


async def _admin_back(admin, host: str, port: int, say) -> bool:
    """Sign the admin in again if its session has gone. Run of 2026-10-18:
    the admin account's phone signed in mid-run, the server (one session
    per account) ended the test's admin session, and every delete-user at
    the end failed: 300 accounts left behind."""
    try:
        if admin.is_connected() and admin.authenticated:
            return True
    except Exception:
        pass
    say("[stress] the admin's session had ended (signed in somewhere else? "
        "the server allows one session per account) -- signing in again")
    try:
        await _online(admin, host, port)
        return True
    except Exception as exc:
        say("[stress] could not sign the admin in again: %s" % _why(exc))
        return False


#: Prosody shell line that removes every stress account, for when the run
#: could not (one line, in `sudo prosodyctl shell`).
CLEANUP_HINT = ('> local um = require "core.usermanager" local d = "%s" local l = {} '
                'for u in um.users(d) do if u:match("^stress%%-%%x+%%-%%d+$") then '
                'l[#l+1] = u end end for _, u in ipairs(l) do um.delete_user(u, d) end '
                'return #l .. " stress accounts deleted"')


class ServerSampler:
    """Prosody's CPU and memory, read from /proc on this machine (the run is
    on the server). Owner (2026-10-18): "did we record the peak usage?" --
    the run measured the bots, not the server. Sampled every few seconds;
    each minute's row gets that minute's peak and average, and the end of
    the run says the peak. Nothing if Prosody is not found here."""

    def __init__(self):
        import os
        self._os = os
        self._tick = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
        self.pid = self._find()
        self._last = None
        self.minute_cpu: List[float] = []
        self.minute_rss = 0.0
        self.peak_cpu = 0.0
        self.peak_rss = 0.0

    def _find(self) -> Optional[int]:
        try:
            for name in self._os.listdir("/proc"):
                if not name.isdigit():
                    continue
                try:
                    with open("/proc/%s/cmdline" % name, "rb") as fh:
                        cmd = fh.read().replace(b"\0", b" ")
                except OSError:
                    continue
                if b"prosody" in cmd and b"prosodyctl" not in cmd and b"lua" in cmd:
                    return int(name)
        except OSError:
            pass
        return None

    def sample(self) -> None:
        if self.pid is None:
            return
        try:
            with open("/proc/%d/stat" % self.pid) as fh:
                fields = fh.read().rsplit(")", 1)[1].split()
            cpu_s = (int(fields[11]) + int(fields[12])) / float(self._tick)
            rss = 0.0
            with open("/proc/%d/status" % self.pid) as fh:
                for line in fh:
                    if line.startswith("VmRSS:"):
                        rss = int(line.split()[1]) / 1024.0
        except (OSError, ValueError, IndexError):
            self.pid = self._find()
            self._last = None
            return
        now = time.time()
        if self._last is not None and now > self._last[0]:
            pct = 100.0 * (cpu_s - self._last[1]) / (now - self._last[0])
            self.minute_cpu.append(pct)
            self.peak_cpu = max(self.peak_cpu, pct)
        self._last = (now, cpu_s)
        self.minute_rss = max(self.minute_rss, rss)
        self.peak_rss = max(self.peak_rss, rss)

    def minute(self) -> Dict[str, object]:
        cpu = self.minute_cpu
        out = {"prosody_cpu_avg_pct": round(sum(cpu) / len(cpu), 1) if cpu else "",
               "prosody_cpu_peak_pct": round(max(cpu), 1) if cpu else "",
               "prosody_rss_mib": round(self.minute_rss, 1) if self.pid else ""}
        self.minute_cpu, self.minute_rss = [], 0.0
        return out


#: mod_otrv4plus_moderation's "List all rooms" (hidden ones too).
LIST_ROOMS = "https://otrv4plus.i2p/protocol/admin#list-rooms"


def _stale_stress_rooms(rooms: List[Dict[str, object]], muc: str) -> List[str]:
    """Rooms an earlier run left behind: named like ours, on this service,
    and EMPTY. A room with anyone in it may belong to a run still going
    (STRESS_TEST.md suggests two processes for big runs), so it is kept."""
    import re
    # stress-<run>-gNN, and stress-<run> from runs before --groups.
    pattern = re.compile(r"^stress-[0-9a-f]{6}(-g\d+)?@" + re.escape(muc) + r"$")
    out = []
    for room in rooms:
        jid = str(room.get("jid", "")).lower()
        try:
            occupants = int(room.get("occupants") or 0)
        except (TypeError, ValueError):
            occupants = 1
        if pattern.match(jid) and occupants == 0:
            out.append(jid)
    return out


async def _sweep_leftover_rooms(c, muc: str, say) -> int:
    """Destroy stress rooms earlier runs left behind (owner, 2026-10-17: 90
    of them, from runs killed before their own clean-up). Needs the server's
    "List all rooms" command (mod_otrv4plus_moderation); without it nothing
    is touched and the run says so. Server admins own every room, so the
    admin account may destroy them."""
    try:
        first = await c["xep_0050"].send_command(c.boundjid.domain, LIST_ROOMS,
                                                 action="execute", timeout=60)
        field = first["command"]["form"].get_fields().get("rooms")
        lines = field["value"] if field is not None else []
        if isinstance(lines, str):
            lines = lines.split("\n")
        rooms = []
        for line in lines or []:
            try:
                rooms.append(json.loads(line))
            except ValueError:
                continue
    except Exception:
        say("[stress] leftover rooms not checked: the server has no \"List all "
            "rooms\" command (install mod_otrv4plus_moderation)")
        return 0
    stale = _stale_stress_rooms(rooms, muc)
    for jid in stale:
        try:
            await c["xep_0045"].destroy(jid, "left over from an earlier stress test",
                                        timeout=30)
        except Exception as exc:
            say("[stress] could not destroy %s: %s" % (jid, _why(exc)))
    if stale:
        say("[stress] removed %d empty room(s) left by earlier runs" % len(stale))
    return len(stale)


def _raise_open_files(users: int, say) -> None:
    """One socket per user, plus Python's own: 2,000 users pass Linux's
    default limit of 1,024 open files. Raised to the hard limit if needed."""
    try:
        import resource
    except ImportError:
        return
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    need = users + 256
    if soft >= need:
        return
    target = need if hard == resource.RLIM_INFINITY else min(need, hard)
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (max(soft, target), hard))
    except (ValueError, OSError):
        pass
    soft = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
    if soft < need:
        say("[stress] warning: only %d open files allowed for %d users; run "
            "`ulimit -n %d` first" % (soft, users, need))


async def _is_admin(c) -> bool:
    items = await c["xep_0030"].get_items(jid=c.boundjid.domain, node=COMMANDS_NODE,
                                          timeout=60)
    return any(str(node) == ADMIN_ADD for _j, node, _n in items["disco_items"].get_items())


WELCOME_NAME = "OTRv4Plus Welcome"   # android_bridge.welcome.ROOM_NAME


async def _welcome_room(c, muc: str) -> str:
    """The Welcome room on [muc], found the way the apps find it: listed,
    with exactly the app's name. Never created here."""
    items = await c["xep_0030"].get_items(jid=muc, timeout=60)
    found = sorted({str(jid).split("/")[0].lower()
                    for jid, _node, name in items["disco_items"].get_items()
                    if str(name or "").strip() == WELCOME_NAME})
    if len(found) != 1:
        raise RuntimeError("%s Welcome room on %s; open the app once (it creates it) "
                           "or pass --welcome ROOM_JID"
                           % ("no" if not found else "more than one", muc))
    return found[0]


class WelcomeLoad:
    """Bots joining the Welcome room, and how long each join took."""

    def __init__(self):
        self.joined = 0
        self.failed = 0
        self._times: List[float] = []

    def ok(self, seconds: float) -> None:
        self.joined += 1
        self._times.append(seconds)

    def minute(self) -> Dict[str, object]:
        t = sorted(self._times)
        self._times = []

        def pct(q):
            return round(t[min(len(t) - 1, int(q * len(t)))], 2) if t else ""
        return {"welcome_in": self.joined, "welcome_failed": self.failed,
                "welcome_join_p50_s": pct(0.5), "welcome_join_p95_s": pct(0.95)}


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
    say("[stress] keep %s signed out everywhere else until the run ends: the "
        "server allows one session per account, and the run needs this one "
        "to delete its accounts at the end" % admin_jid)
    muc = args.muc or await _muc_service(admin)
    welcome = None
    if args.welcome:
        welcome = (args.welcome if args.welcome != "auto"
                   else await _welcome_room(admin, muc))
        say("[stress] bots will also join the Welcome room %s, %.1f a second. "
            "People in it will see them come and go." % (welcome, args.welcome_rate))
    _raise_open_files(args.users, say)
    if not args.keep:
        await _sweep_leftover_rooms(admin, muc, say)
    run_id = secrets.token_hex(3)
    n_groups = max(1, min(args.groups, args.users // 2))
    rooms = ["stress-%s-g%02d@%s" % (run_id, g, muc) for g in range(n_groups)]
    csv_path = args.csv or "stresstest-%s.csv" % time.strftime("%Y%m%d-%H%M%S")
    say("[stress] run %s: %d users in %d group(s) of ~%d, %g min, CSV %s"
        % (run_id, args.users, n_groups, args.users // n_groups, args.minutes, csv_path))

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
    # Users dealt round-robin into the groups; the first of each owns it.
    members_of = [[b for b in bots if b.index % n_groups == g] for g in range(n_groups)]
    for g, group in enumerate(members_of):
        for k, b in enumerate(group):
            b.room = rooms[g]
            # --observers is per group: its first N users decrypt the chat.
            b.observe = not args.observers or k < args.observers
    clients = {}
    swarms: List[Swarm] = []
    lag = [0.0]

    # Room pieces go through the app's own RoomPacer, one per bot as the app
    # has one per account: fast until the room bounces something, then slow,
    # re-sending whatever the room refused or never echoed. Run of
    # 2026-10-16: a hand-made copy of the pacing never saw the room's
    # bounces (they arrive as type="error", not as groupchat) and never
    # re-sent, so refused pieces were silently lost and the run reported
    # "room errors 0" while delivering 43%.
    from android_bridge.groups import RoomPacer, SecureGroups
    loop = asyncio.get_running_loop()
    pacers: Dict[str, RoomPacer] = {}

    def pacer_for(bot: Bot) -> RoomPacer:
        p = pacers.get(bot.jid)
        if p is None:
            def send(to_room: str, body: str, _bot=bot) -> None:
                c = clients.get(_bot.jid)
                if c is not None:
                    c.send_message(mto=to_room, mbody=body, mtype="groupchat")

            def gave_up(_room: str, _bot=bot) -> None:
                _bot.swarm.stats.lost += 1

            p = pacers[bot.jid] = RoomPacer(
                send, burst=SecureGroups.ROOM_BURST,
                interval=SecureGroups.ROOM_INTERVAL,
                slow_burst=SecureGroups.ROOM_SLOW_BURST,
                slow_interval=SecureGroups.ROOM_SLOW_INTERVAL,
                on_error=gave_up,
                schedule=lambda delay, fn: loop.call_later(delay, fn))
        return p

    def send_room(bot: Bot, body: str) -> None:
        pacer_for(bot).post(bot.room, [body])

    def send_direct(bot: Bot, to: str, body: str) -> None:
        clients[bot.jid].send_message(mto=to, mbody=body, mtype="chat")

    def wire(bot: Bot, c) -> None:
        def on_group(msg):
            if str(msg["from"].bare) == bot.room and msg["body"]:
                if msg["from"].resource == Swarm.nick(bot):
                    pacer_for(bot).confirm(bot.room, msg["body"])   # our echo
                bot.swarm.on_room(bot, msg["from"].resource, msg["body"])

        def on_error(msg):
            # The room refused something (Prosody's mod_muc_limits answers
            # "resource-constraint"): slow down and send it again.
            if str(msg["from"].bare) == bot.room:
                bot.swarm.stats.room_errors += 1
                pacer_for(bot).rejected(bot.room)

        def on_chat(msg):
            if msg["type"] in ("chat", "normal") and msg["body"]:
                bot.swarm.on_direct(bot, str(msg["from"].bare), msg["body"])

        def on_gone(_e):
            bot.swarm.stats.disconnects += 1
        c.add_event_handler("groupchat_message", on_group)
        c.add_event_handler("message", on_chat)
        c.add_event_handler("message_error", on_error)
        c.add_event_handler("disconnected", on_gone)

    for g, group in enumerate(members_of):
        sw = Swarm(core, rooms[g], group, send_room=send_room, send_direct=send_direct,
                   interval=args.interval, say=say)
        swarms.append(sw)
        for b in group:
            b.swarm = sw
    try:
        # 2. connect and join, a few at a time; the owners first, so each
        # room exists and is configured before anyone else walks in.
        sem = asyncio.Semaphore(max(1, args.connect_concurrency))

        async def bring_up(bot: Bot, pw: str, create: bool = False):
            async with sem:
                c = _client(bot.jid, pw, args.host)
                wire(bot, c)
                await _online(c, args.host, args.port)
                await c["xep_0045"].join_muc_wait(bot.room, Swarm.nick(bot), timeout=60)
                if create:
                    # A new room is locked until its creator submits a
                    # configuration: the empty form takes the defaults.
                    # Not persistent, whatever the server's default: the
                    # room should go when the run does (it is also
                    # destroyed at the end; this covers a killed run).
                    form = c["xep_0004"].make_form(ftype="submit")
                    form.add_field(var="FORM_TYPE", ftype="hidden",
                                   value="http://jabber.org/protocol/muc#roomconfig")
                    form.add_field(var="muc#roomconfig_persistentroom",
                                   ftype="boolean", value=False)
                    await c["xep_0045"].set_room_config(bot.room, form, timeout=60)
                clients[bot.jid] = c
        pw_of = dict(creds)
        await asyncio.gather(*(bring_up(sw.owner, pw_of[sw.owner.jid], create=True)
                               for sw in swarms))
        others = [b for b in bots if b is not b.swarm.owner]
        await asyncio.gather(*(bring_up(b, pw_of[b.jid]) for b in others))
        say("[stress] %d users online in %d room(s)%s" % (
            len(clients), len(swarms),
            ", %d sign-ins paced by the server" % PACED["n"] if PACED["n"] else ""))

        # 3. the groups, filled the way the app fills them: one person per
        # change as they accept, several together only when they accept
        # while a change is still out (--batch caps that).
        for sw in swarms:
            sw.create()
        waiting = {id(sw): [b for b in sw.bots if b is not sw.owner] for sw in swarms}
        start = time.time()
        next_add = {id(sw): start + args.ramp * k / max(1, len(swarms))
                    for k, sw in enumerate(swarms)}
        next_row = start + 60
        end = start + args.minutes * 60
        server = ServerSampler()
        if server.pid is None:
            say("[stress] Prosody's process is not visible from here: no server "
                "CPU/memory in the numbers (run this on the server)")
        next_sample = start
        wl = WelcomeLoad() if welcome else None
        if wl is not None:
            async def into_welcome():
                gap = 1.0 / max(0.01, args.welcome_rate)
                for b in bots:
                    c = clients.get(b.jid)
                    if c is None or not c.is_connected():
                        wl.failed += 1
                        continue

                    async def one(c=c, b=b):
                        t0 = time.time()
                        try:
                            await c["xep_0045"].join_muc_wait(welcome, Swarm.nick(b), timeout=180)
                            wl.ok(time.time() - t0)
                        except Exception:
                            wl.failed += 1
                    asyncio.ensure_future(one())
                    await asyncio.sleep(gap)
            asyncio.ensure_future(into_welcome())
        with open(csv_path, "w", newline="") as fh:
            writer = None
            while time.time() < end:
                now = time.time()
                if now >= next_sample:
                    server.sample()
                    next_sample = now + 5
                for sw in swarms:
                    todo = waiting[id(sw)]
                    if todo and now >= next_add[id(sw)] and not sw.pending_adds:
                        batch, rest = todo[:args.batch], todo[args.batch:]
                        if sw.add_batch(batch):
                            waiting[id(sw)] = rest
                            next_add[id(sw)] = now + args.ramp
                    sw.tick()
                if now >= next_row:
                    online = sum(1 for c in clients.values() if c.is_connected())
                    row = combine_rows(swarms, now - start, online, lag[0])
                    row.update(server.minute())
                    if wl is not None:
                        row.update(wl.minute())
                    lag[0] = 0.0
                    if writer is None:
                        writer = csv.DictWriter(fh, fieldnames=list(row))
                        writer.writeheader()
                    writer.writerow(row)
                    fh.flush()
                    say("[stress] %(elapsed_min)5.1f min  members %(members)4d "
                        "(largest group %(largest_group)3d)  online %(online)4d  "
                        "sent %(sent)4d  delivered %(delivery_pct)5.1f%%  "
                        "latency p50 %(lat_p50_s).2fs p95 %(lat_p95_s).2fs  "
                        "commits %(commits)d  room errors %(room_errors)d  lost %(lost)d  "
                        "undecryptable %(undecryptable)d  disconnects %(disconnects)d  "
                        "harness lag %(harness_lag_s).1fs" % row
                        + ("  prosody cpu %s%% (peak %s%%) mem %s MiB" % (
                            row["prosody_cpu_avg_pct"], row["prosody_cpu_peak_pct"],
                            row["prosody_rss_mib"]) if server.pid else "")
                        + ("  welcome %s in (failed %s, join p50 %ss p95 %ss)" % (
                            row["welcome_in"], row["welcome_failed"],
                            row["welcome_join_p50_s"], row["welcome_join_p95_s"])
                           if wl is not None else ""))
                    next_row += 60
                before = time.time()
                await asyncio.sleep(0.5)
                # More than the 0.5 s asked for: this process was too busy to
                # run its loop. Several seconds means the numbers above
                # measure this machine's bots, not the server.
                lag[0] = max(lag[0], time.time() - before - 0.5)
        refused = sum(sw.stats.join_refused for sw in swarms)
        firsts = [sw.stats.join_refused_at for sw in swarms
                  if sw.stats.join_refused_at is not None]
        say("[stress] done. Joins refused: %d%s" % (
            refused, " (first at %d members)" % min(firsts) if firsts else ""))
        if server.pid:
            say("[stress] Prosody peak: %.0f%% of one core, %.0f MiB memory "
                "(sampled every 5 s)" % (server.peak_cpu, server.peak_rss))
    finally:
        if not args.keep:
            # Destroy each room while its owner is still signed in; servers
            # that make rooms persistent by default would otherwise keep
            # them after every account is gone.
            for sw in swarms:
                c = clients.get(sw.owner.jid)
                if c is None:
                    continue
                try:
                    await c["xep_0045"].destroy(sw.room, "stress test finished",
                                                timeout=30)
                except Exception as exc:
                    say("[stress] could not destroy %s: %s" % (sw.room, _why(exc)))
        for c in clients.values():
            try:
                c.disconnect()
            except Exception:
                pass
        if not args.keep and creds:
            say("[stress] deleting %d accounts ..." % len(creds))
            failed, in_a_row = 0, 0
            admin_ok = await _admin_back(admin, args.host, args.port, say)
            for jid, _pw in creds:
                if not admin_ok:
                    failed += 1
                    continue
                try:
                    await _command(admin, ADMIN_DELETE, {"accountjids": [jid]})
                    in_a_row = 0
                except Exception as exc:
                    failed += 1
                    in_a_row += 1
                    if in_a_row <= 3:
                        say("[stress] could not delete %s: %s" % (jid, _why(exc)))
                    if in_a_row == 3:
                        # Most likely the session went again: once more.
                        admin_ok = await _admin_back(admin, args.host, args.port, say)
                    elif in_a_row >= 10:
                        admin_ok = False
            if failed:
                say("[stress] %d accounts were NOT deleted. Remove them with this one "
                    "line in `sudo prosodyctl shell`:" % failed)
                say(CLEANUP_HINT % domain)
            else:
                say("[stress] all %d accounts deleted" % len(creds))
        for b in bots:
            try:
                b.mls.wipe()
            except Exception:
                pass
        creds.clear()
        if not args.keep:
            # Our own rooms whose destroy failed above (their owner had
            # dropped): empty now that every bot is gone.
            try:
                if await _admin_back(admin, args.host, args.port, say):
                    await _sweep_leftover_rooms(admin, muc, say)
            except Exception:
                pass
        admin.disconnect()
    return 0


def combine_rows(swarms: List["Swarm"], elapsed: float, online: int,
                 lag: float) -> Dict[str, object]:
    """One minute's row across every group (and each group's stats reset)."""
    latency: List[float] = []
    for sw in swarms:
        latency.extend(sw.stats.latency)
    rows = [sw.minute_row(elapsed, online) for sw in swarms]
    total = {k: sum(r[k] for r in rows) for k in (
        "members", "sent", "delivered", "expected", "commits", "commit_failures",
        "room_errors", "undecryptable", "disconnects", "join_refused", "lost")}
    return {
        "elapsed_min": round(elapsed / 60.0, 1),
        "groups": len(swarms),
        "members": total["members"],
        "largest_group": max(r["members"] for r in rows),
        "online": online,
        "sent": total["sent"], "delivered": total["delivered"],
        "expected": total["expected"],
        "delivery_pct": (round(100.0 * total["delivered"] / total["expected"], 1)
                         if total["expected"] else 100.0),
        "lat_p50_s": round(percentile(latency, 50), 2),
        "lat_p95_s": round(percentile(latency, 95), 2),
        "lat_max_s": round(max(latency), 2) if latency else 0.0,
        "commits": total["commits"], "commit_failures": total["commit_failures"],
        "room_errors": total["room_errors"], "lost": total["lost"],
        "undecryptable": total["undecryptable"], "disconnects": total["disconnects"],
        "join_refused": total["join_refused"], "harness_lag_s": round(lag, 2),
    }


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="otrv4plus_xmpp.py --stresstest",
        description="Load-test YOUR OWN Prosody server (server admins only).")
    ap.add_argument("--admin", required=True, help="a server admin's JID")
    ap.add_argument("--users", type=int, default=50, help="simulated users (default 50)")
    ap.add_argument("--minutes", type=float, default=60, help="run length (default 60)")
    ap.add_argument("--interval", type=float, default=120,
                    help="average seconds between one user's messages (default 120)")
    ap.add_argument("--groups", type=int, default=1,
                    help="split the users into this many groups, each its own room "
                         "(default 1)")
    ap.add_argument("--batch", type=int, default=1,
                    help="most users added in one change (default 1, like the app, "
                         "which adds people one at a time as they accept; max %d)"
                         % MAX_BATCH)
    ap.add_argument("--ramp", type=float, default=10,
                    help="seconds between adds in each group (default 10)")
    ap.add_argument("--observers", type=int, default=0,
                    help="in each group, only the first N users decrypt chat (saves "
                         "this machine's CPU; 0 = all)")
    ap.add_argument("--host", default="127.0.0.1", help="Prosody c2s host (default 127.0.0.1)")
    ap.add_argument("--port", type=int, default=5222)
    ap.add_argument("--muc", help="MUC service (found by disco if omitted)")
    ap.add_argument("--welcome", nargs="?", const="auto", default=None, metavar="ROOM",
                    help="also join every bot to the public Welcome room (found by its "
                         "name, or give its JID) to measure presence load. People in "
                         "the room see the bots")
    ap.add_argument("--welcome-rate", type=float, default=2.0,
                    help="Welcome joins a second with --welcome (default 2)")
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
