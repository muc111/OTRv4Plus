# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""OTRv4Plus secure groups: MLS over an XMPP room, set up over OTRv4+.

WHO DOES WHAT
=============
  * Rust (`otrv4_core.RustMlsClient`) is the whole of the group's security:
    keys, epochs, membership, encryption, authentication, replay and epoch
    checks, and the sealed state at rest. Nothing here decides whether a
    message is authentic; this module only moves bytes and reports results.
  * The ROOM (XEP-0045) is transport and ordering only. Everything a secure
    group puts in it is an MLS message -- handshake messages too
    (PURE_CIPHERTEXT wire format) -- so the room and its server see
    ciphertext, sizes and nicknames, never text.
  * An OTRv4+ 1:1 session carries the setup: the invitation, the invitee's
    KeyPackage, and the Welcome. That is what binds a member's MLS key to a
    person: the KeyPackage arrives over a session the DAKE authenticated,
    and if that session is SMP-verified the member is shown as verified.

IDENTITY BINDING IS NOT MEMBERSHIP
==================================
MLS proves a message came from the holder of a leaf's signing key. It does
not prove the leaf's credential ("bob@server") names the person you think.
A member is `verified` here only when their MLS fingerprint (SHA-384 of the
signature public key) was received over an SMP-verified OTRv4+ session with
that same JID. Everyone else in the group is shown by name, unverified.

WIRE
====
Room body:      ?OTRv4MLS1:<base64 MLS message>       (fragmented if large)
Over OTRv4+:    ?OTRv4-MLS:INVITE:<room>|<our fingerprint hex>
                ?OTRv4-MLS:KP:<room>|<base64 KeyPackage>
                ?OTRv4-MLS:WELCOME:<room>|<base64 Welcome>|<our fingerprint hex>
                (the fingerprint as of the Welcome: our signing key is per
                group and rotates, so it may differ from the INVITE's. Both
                come over the same OTRv4+ session. Older clients omit it, and
                the INVITE's is used.)
                ?OTRv4-MLS:DECLINE:<room>

NO PLAINTEXT FALLBACK
=====================
In a secure room, a body that is not an MLS frame is never shown and never
sent: `send` raises rather than posting text, and an inbound plaintext body
is dropped and reported (`room_plaintext_refused`). A frame that does not
decrypt -- history from before we joined, a replay, a stale epoch, a
tampered message -- is dropped and counted, never shown.
"""

from __future__ import annotations

import base64
import binascii
import collections
import json
import os
import re
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

import otrv4plus_fragment as _fragment

from .events import (ErrorOccurred, GroupChanged, GroupInvite,
                     RoomMessageReceived, SecurityState)

__all__ = ["SecureGroups", "GroupError", "ROOM_PREFIX", "SIGNAL_PREFIX",
           "is_group_signal", "is_room_frame"]

ROOM_PREFIX = "?OTRv4MLS1:"
SIGNAL_PREFIX = "?OTRv4-MLS:"

#: Bounds on what a peer or a room can make us hold.
MAX_ROOM_LEN = 256
MAX_FRAME_B64 = 2 * 1024 * 1024
MAX_PENDING_INVITES = 32
INVITE_TTL = 30 * 60.0
MAX_MEMBERS_PER_ADD = 16

_ROOM_RE = re.compile(r"^[^\s@/|]{1,128}@[^\s@/|]{1,120}$")
_FP_RE = re.compile(r"^[0-9a-f]{96}$")


class GroupError(RuntimeError):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(code)
        self.code = code
        self.detail = detail


def is_group_signal(body: str) -> bool:
    return isinstance(body, str) and body.startswith(SIGNAL_PREFIX)


def is_room_frame(body: str) -> bool:
    return isinstance(body, str) and body.startswith(ROOM_PREFIX)


def _b64e(data: bytes) -> str:
    return base64.b64encode(bytes(data)).decode("ascii")


def _b64d(text: str) -> bytes:
    if len(text) > MAX_FRAME_B64:
        raise ValueError("frame too large")
    return base64.b64decode(text.encode("ascii"), validate=True)


def _room_ok(room: str) -> bool:
    return (isinstance(room, str) and len(room) <= MAX_ROOM_LEN
            and bool(_ROOM_RE.match(room)))


@dataclass
class _Invite:
    peer: str
    fingerprint: str
    at: float
    accepted: bool = False


@dataclass
class _Outgoing:
    """An invitation we sent and have not yet turned into a member."""
    room: str
    at: float


@dataclass
class _Stats:
    shown: int = 0
    undecryptable: int = 0
    plaintext_refused: int = 0
    malformed: int = 0


def _env_int(name: str, default: int, low: int, high: int) -> int:
    """A configuration knob from the environment, clamped; the default when
    unset or unreadable (never an error at import)."""
    try:
        value = int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default
    return max(low, min(high, value))


class _PacedRoom:
    """One room's pacing state (RoomPacer's, under its lock)."""

    __slots__ = ("queue", "tokens", "at", "slow_until", "strikes",
                 "requeued_at", "inflight", "armed", "check_armed")

    def __init__(self, now: float, burst: int):
        #: [part, attempts] still to send, oldest first.
        self.queue: collections.deque = collections.deque()
        self.tokens = float(burst)
        self.at = now
        #: Slow until this time (a rejection); fast after it.
        self.slow_until = 0.0
        #: Rejections so far; each doubles the next slow period.
        self.strikes = 0
        self.requeued_at = -1e18
        #: part -> (sent at, attempts): sent, not yet seen back from the room.
        self.inflight: "collections.OrderedDict[str, Tuple[float, int]]" = \
            collections.OrderedDict()
        self.armed = False
        self.check_armed = False


class RoomPacer:
    """Room fragments out as fast as the server takes them, and no faster.

    A room reflects every message to its sender (XEP-0045), so each piece
    sent is held as IN FLIGHT until its own echo comes back (`confirm`).

      * FAST by default: `burst` pieces at once, then one per `interval`.
        On a server that allows it a commit adding a member (~11 pieces)
        is out in about a second.
      * A REJECTION (`rejected`, e.g. Prosody's mod_muc_limits bouncing a
        message) switches that room to SLOW (`slow_burst`, one per
        `slow_interval`, under mod_muc_limits' defaults) and puts every
        piece still in flight back at the front of the queue. The room
        stays slow for `slow_for` seconds, doubled per further rejection up
        to `max_slow_for`, then tries fast again.
      * A piece not echoed within `echo_timeout` (bounced without a notice,
        or lost) is sent again. Each piece goes at most `max_attempts`
        times; then the room is reported (`on_error`).

    Sending a piece twice is harmless: the receiver's reassembler takes the
    same fragment again, and MLS drops a replayed message or a stale
    commit. Order is kept: a later frame never overtakes an earlier one's
    remaining pieces.

    `interval <= 0` sends everything at once with no tracking (tests, and
    servers without a limit). `schedule(delay, fn)` runs `fn` later; the
    default is a daemon timer thread, so `send` must be safe to call from
    another thread.
    """

    MAX_INFLIGHT = 512
    #: Rejections this close to the last re-queue are for pieces of the
    #: same burst, already re-queued: they keep the room slow, nothing more.
    REJECT_SETTLE = 5.0

    def __init__(self, send: Callable[[str, str], None], *, burst: int,
                 interval: float, on_error: Callable[[str], None],
                 slow_burst: int = 3, slow_interval: float = 2.2,
                 slow_for: float = 300.0, max_slow_for: float = 3600.0,
                 echo_timeout: float = 20.0, max_attempts: int = 3,
                 clock: Callable[[], float] = time.monotonic,
                 schedule: Optional[Callable[[float, Callable[[], None]], Any]] = None):
        self._send = send
        self._burst = max(1, int(burst))
        self._interval = float(interval)
        self._slow_burst = max(1, int(slow_burst))
        self._slow_interval = max(float(slow_interval), self._interval, 0.001)
        self._slow_for = float(slow_for)
        self._max_slow_for = max(float(max_slow_for), self._slow_for)
        self._echo_timeout = float(echo_timeout)
        self._max_attempts = max(1, int(max_attempts))
        self._on_error = on_error
        self._clock = clock
        self._schedule = schedule or self._timer
        self._lock = threading.RLock()
        self._rooms: Dict[str, _PacedRoom] = {}
        self._closed = False

    @staticmethod
    def _timer(delay: float, fn: Callable[[], None]) -> Any:
        t = threading.Timer(delay, fn)
        t.daemon = True
        t.start()
        return t

    def _room(self, room: str) -> _PacedRoom:
        state = self._rooms.get(room)
        if state is None:
            state = self._rooms[room] = _PacedRoom(self._clock(), self._burst)
        return state

    # -- what callers see -----------------------------------------------------

    def post(self, room: str, parts: List[str]) -> None:
        if self._interval <= 0:
            for part in parts:
                self._send(room, part)
            return
        with self._lock:
            if self._closed:
                return
            self._room(room).queue.extend([part, 0] for part in parts)
        self._pump(room)

    def pending(self, room: str) -> int:
        """Pieces for `room` not yet sent (in flight ones are sent)."""
        with self._lock:
            state = self._rooms.get(room)
            return len(state.queue) if state else 0

    def in_flight(self, room: str) -> int:
        with self._lock:
            state = self._rooms.get(room)
            return len(state.inflight) if state else 0

    def is_slow(self, room: str) -> bool:
        with self._lock:
            state = self._rooms.get(room)
            return bool(state) and self._clock() < state.slow_until

    def confirm(self, room: str, part: str) -> bool:
        """Our own piece came back from the room: it was delivered."""
        with self._lock:
            state = self._rooms.get(room)
            if state is None:
                return False
            return state.inflight.pop(part, None) is not None

    def rejected(self, room: str) -> None:
        """The server bounced a message to `room`: slow down, send again."""
        if self._interval <= 0:
            return
        with self._lock:
            if self._closed:
                return
            state = self._room(room)
            now = self._clock()
            if now - state.requeued_at < self.REJECT_SETTLE:
                state.slow_until = max(state.slow_until,
                                       now + self._slow_period(state))
                return
            state.strikes += 1
            state.slow_until = now + self._slow_period(state)
            state.tokens = 0.0       # the server's bucket is empty too
            state.at = now
            state.requeued_at = now
            self._requeue(room, state, list(state.inflight))
        self._pump(room)

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._rooms.clear()

    # -- inside -----------------------------------------------------------------

    def _slow_period(self, state: _PacedRoom) -> float:
        return min(self._max_slow_for,
                   self._slow_for * (2 ** max(0, min(state.strikes - 1, 16))))

    def _requeue(self, room: str, state: _PacedRoom, parts: List[str]) -> None:
        """Put `parts` (in flight) back at the front, oldest first. Called
        with the lock held; a piece out of attempts is given up."""
        again = []
        failed = False
        for part in parts:
            _sent, attempts = state.inflight.pop(part)
            if attempts >= self._max_attempts:
                failed = True
                continue
            again.append([part, attempts])
        state.queue.extendleft(reversed(again))
        if failed:
            self._schedule(0, lambda: self._on_error(room))

    def _take_token(self, state: _PacedRoom) -> Tuple[bool, float]:
        now = self._clock()
        slow = now < state.slow_until
        burst = self._slow_burst if slow else self._burst
        interval = self._slow_interval if slow else self._interval
        tokens = min(float(burst), state.tokens + (now - state.at) / interval)
        if tokens >= 1.0:
            state.tokens, state.at = tokens - 1.0, now
            return True, interval
        state.tokens, state.at = tokens, now
        return False, interval * (1.0 - tokens)

    def _pump(self, room: str) -> None:
        while True:
            with self._lock:
                if self._closed:
                    return
                state = self._rooms.get(room)
                if state is None or not state.queue:
                    return
                ok, wait = self._take_token(state)
                if not ok:
                    if not state.armed:
                        state.armed = True
                        self._schedule(max(wait, 0.001), lambda: self._fire(room))
                    return
                part, attempts = state.queue.popleft()
                state.inflight.pop(part, None)
                state.inflight[part] = (self._clock(), attempts + 1)
                while len(state.inflight) > self.MAX_INFLIGHT:
                    state.inflight.popitem(last=False)
                if not state.check_armed:
                    state.check_armed = True
                    self._schedule(self._echo_timeout, lambda: self._expire(room))
            try:
                self._send(room, part)
            except Exception:
                with self._lock:
                    # The stream is gone: the rest of a set is useless, and a
                    # commit is posted again by its owner after a rejoin.
                    state.queue.clear()
                    state.inflight.clear()
                self._on_error(room)
                return

    def _fire(self, room: str) -> None:
        with self._lock:
            state = self._rooms.get(room)
            if state is not None:
                state.armed = False
        self._pump(room)

    def _expire(self, room: str) -> None:
        """Pieces sent `echo_timeout` ago and never echoed go again."""
        with self._lock:
            if self._closed:
                return
            state = self._rooms.get(room)
            if state is None:
                return
            state.check_armed = False
            now = self._clock()
            late = [part for part, (sent, _n) in state.inflight.items()
                    if now - sent >= self._echo_timeout]
            if late:
                self._requeue(room, state, late)
            if state.inflight:
                oldest = min(sent for sent, _n in state.inflight.values())
                state.check_armed = True
                self._schedule(max(0.001, oldest + self._echo_timeout - now),
                               lambda: self._expire(room))
        if late:
            self._pump(room)


class SecureGroups:
    """Every secure group this account is in, and the setup traffic for them.

    Construction does no I/O. `open(account)` creates or reopens the MLS state
    for an account; until then every operation raises `not_ready`.
    """

    STATE_NAME = "groups.sealed"
    DEK_NAME = "groups.dek"

    #: RoomPacer settings. Fast (10 at once, then 4 a second) until the
    #: server bounces something, then slow -- under mod_muc_limits' defaults
    #: (0.5 events/s) -- for 5 minutes, doubling per further bounce up to an
    #: hour. Tests set ROOM_INTERVAL to 0, which sends at once
    #: (tests/conftest.py).
    ROOM_BURST = 10
    ROOM_INTERVAL = 0.25
    ROOM_SLOW_BURST = 3
    ROOM_SLOW_INTERVAL = 2.2
    ROOM_SLOW_FOR = 300.0
    #: A piece of ours not echoed by the room in this long is sent again.
    ROOM_ECHO_TIMEOUT = 20.0
    #: How many times one of our commits is posted again when it does not
    #: come back from the room (bounced, or lost across a reconnect).
    MAX_COMMIT_RESENDS = 3
    #: Automatic rekey (MLS self-update) for post-compromise security: after
    #: this many messages we sent, or this long since our own last commit,
    #: whichever comes first. Checked after a send, never while a commit of
    #: ours is pending or still going out. Defaults per the owner's hardening
    #: specification (MLS_SECURITY_HARDENING.md §4): 50 messages / 30 min.
    #: A self-update in a 4-member group is ~22 KB (8 room fragments).
    AUTO_REKEY_MESSAGES = _env_int("OTRV4PLUS_MLS_REKEY_MESSAGES", 50, 1, 100000)
    AUTO_REKEY_SECONDS = _env_int("OTRV4PLUS_MLS_REKEY_SECONDS", 30 * 60, 60, 30 * 86400)
    #: A member whose leaf has not been refreshed by a commit of theirs for
    #: this long is removed by the next member that notices (owner decision
    #: U1: 72 h, MLS_SECURITY_HARDENING.md §4). Online members refresh at
    #: least every AUTO_REKEY_SECONDS through `maintain`, so only a member
    #: that has been away this long is affected; they are re-invited over
    #: OTRv4+ to come back. 0 turns it off.
    IDLE_REMOVE_SECONDS = 3600 * _env_int("OTRV4PLUS_MLS_IDLE_REMOVE_HOURS", 72, 0, 24 * 365)
    #: Nothing is judged idle until we have been in the room this long: a
    #: reconnect first replays the commits we missed.
    IDLE_GRACE_SECONDS = 600
    #: How often `maintain` runs by itself (timed rekey, idle removal).
    #: 0: never by itself (tests call `maintain` directly).
    MAINTAIN_SECONDS = 300

    def __init__(self, *,
                 send_room: Callable[[str, str], None],
                 send_private: Callable[[str, str], None],
                 emit: Callable[[Any], None],
                 peer_security: Callable[[str], SecurityState],
                 state_dir: Optional[str] = None,
                 core: Any = None,
                 clock: Callable[[], float] = time.time):
        self._send_room = send_room
        self._send_private = send_private
        self._emit = emit
        self._peer_security = peer_security
        self._state_dir = state_dir
        self._core = core
        self._clock = clock
        self._lock = threading.RLock()
        self._client = None
        self._dek = None
        self._account = ""
        #: room -> {jid: fingerprint hex} learned over OTRv4+, and whether
        #: that session was SMP-verified when it arrived.
        self._bound: Dict[str, Dict[str, Tuple[str, bool]]] = {}
        self._invites: Dict[str, _Invite] = {}        # room -> invitation to us
        self._outgoing: Dict[Tuple[str, str], _Outgoing] = {}  # (room, peer)
        self._awaiting_welcome: Dict[str, str] = {}   # room -> inviter
        self._welcome_for: Dict[str, List[str]] = {}  # room -> invitees of our pending add
        #: room -> [(peer, verified)] waiting for our add-commit to land.
        self._pending_binding: Dict[str, List[Tuple[str, bool]]] = {}
        self._frag_seq = 0
        self._reassembler = _fragment.Reassembler()
        self.stats = _Stats()
        self._wiped = False
        #: room -> [commit bytes, times re-sent]: our commit, posted and not
        #: yet seen back from the room. MLS holds it pending, which refuses
        #: every send, until it lands -- so it is kept to post again.
        self._unconfirmed: Dict[str, List[Any]] = {}
        #: room -> [messages sent since our last commit, time of that commit].
        self._since_rekey: Dict[str, List[float]] = {}
        #: room -> {member identity: when a commit of theirs last refreshed
        #: their leaf (or they joined)} -- what idle removal judges.
        self._activity: Dict[str, Dict[str, float]] = {}
        #: room -> [(peer, KeyPackage, verified)] that arrived while one of our
        #: commits was pending; added once it settles.
        self._queued_kps: Dict[str, List[Tuple[str, bytes, bool]]] = {}
        self._settled_from = 0.0
        self._maintain_timer: Any = None
        self._pacer = RoomPacer(
            send_room, burst=self.ROOM_BURST, interval=self.ROOM_INTERVAL,
            slow_burst=self.ROOM_SLOW_BURST,
            slow_interval=self.ROOM_SLOW_INTERVAL,
            slow_for=self.ROOM_SLOW_FOR, echo_timeout=self.ROOM_ECHO_TIMEOUT,
            on_error=lambda room: self._emit(
                ErrorOccurred(peer=room, code="group_send_failed")))

    # -- lifecycle ----------------------------------------------------------

    def _core_module(self):
        if self._core is None:
            import otrv4_core as core
            self._core = core
        return self._core

    @property
    def available(self) -> bool:
        return hasattr(self._core_module(), "RustMlsClient")

    def _paths(self) -> Tuple[Optional[str], Optional[str]]:
        if not self._state_dir:
            return None, None
        return (os.path.join(self._state_dir, self.STATE_NAME),
                os.path.join(self._state_dir, self.DEK_NAME))

    def open(self, account: str) -> None:
        """Create or reopen this account's MLS state.

        Reopened only under the same account: the account is bound into the
        sealed blob, so another account's state refuses to open, and is then
        left alone rather than overwritten -- it is not ours to destroy.
        """
        with self._lock:
            if self._wiped:
                raise GroupError("wiped")
            core = self._core_module()
            if not hasattr(core, "RustMlsClient"):
                raise GroupError("groups_unavailable",
                                 "this build has no group encryption")
            account = str(account or "").strip().lower()
            if not account:
                raise GroupError("no_account")
            state_path, dek_path = self._paths()
            client = None
            if state_path and dek_path:
                os.makedirs(self._state_dir, mode=0o700, exist_ok=True)
                self._dek = core.FileDek.load_or_create(dek_path)
                if os.path.exists(state_path):
                    with open(state_path, "rb") as f:
                        blob = f.read()
                    try:
                        client = core.RustMlsClient.open_sealed(
                            self._dek, account.encode(), blob)
                    except Exception:
                        client = None
                        self._emit(ErrorOccurred(peer=None, code="groups_state_unreadable"))
                        # Kept aside, not deleted: it may be another account's.
                        os.replace(state_path, state_path + ".unopened")
            if client is None:
                client = core.RustMlsClient(account.encode())
            self._client = client
            self._account = account
            self._load_app_state()
            self._settled_from = self._clock()
        self._arm_maintenance()

    def _need(self):
        if self._wiped:
            raise GroupError("wiped")
        if self._client is None:
            raise GroupError("not_ready", "groups are not open for an account")
        return self._client

    # -- our bookkeeping, sealed with the MLS state --------------------------
    #
    # Who we bound over OTRv4+, invitations in flight, our commit waiting for
    # the room, when members last refreshed their leaves. Sealed inside the
    # MLS state blob (AES-256-GCM, bound to the account), so a restart in the
    # middle of an invitation or a commit picks up where it was, and a
    # member verified over SMP is still verified after it.

    _APP_STATE_VERSION = 1

    def _store_app_state(self) -> None:
        client = self._client
        if client is None or not hasattr(client, "set_app_data"):
            return
        state = {
            "v": self._APP_STATE_VERSION,
            "bound": {r: {j: [fp, bool(v)] for j, (fp, v) in m.items()}
                      for r, m in self._bound.items()},
            "invites": {r: [i.peer, i.fingerprint, i.at, i.accepted]
                        for r, i in self._invites.items()},
            "outgoing": [[r, p, o.at] for (r, p), o in self._outgoing.items()],
            "awaiting": dict(self._awaiting_welcome),
            "welcome_for": {r: list(p) for r, p in self._welcome_for.items()},
            "pending_binding": {r: [[p, bool(v)] for p, v in l]
                                for r, l in self._pending_binding.items()},
            "unconfirmed": {r: [_b64e(bytes(e[0])), int(e[1])]
                            for r, e in self._unconfirmed.items()},
            "since_rekey": {r: [int(e[0]), float(e[1])]
                            for r, e in self._since_rekey.items()},
            "activity": {r: dict(m) for r, m in self._activity.items()},
        }
        try:
            client.set_app_data(json.dumps(state, separators=(",", ":")).encode())
        except Exception:
            self._emit(ErrorOccurred(peer=None, code="groups_state_too_large"))

    def _load_app_state(self) -> None:
        """Our bookkeeping back from the sealed state. It was sealed by us,
        but is still read field by field: a part that does not parse is
        dropped, never trusted."""
        client = self._client
        if client is None or not hasattr(client, "app_data"):
            return
        try:
            raw = bytes(client.app_data())
            state = json.loads(raw.decode()) if raw else {}
        except Exception:
            state = {}
        if not isinstance(state, dict) or state.get("v") != self._APP_STATE_VERSION:
            return

        def section(name):
            value = state.get(name)
            return value if isinstance(value, (dict, list)) else {}

        def each(name, fn):
            items = section(name)
            for item in (items.items() if isinstance(items, dict) else items):
                try:
                    fn(item)
                except Exception:
                    pass

        each("bound", lambda kv: self._bound.setdefault(str(kv[0]), {}).update(
            {str(j): (str(v[0]), bool(v[1])) for j, v in kv[1].items()}))
        each("invites", lambda kv: self._invites.__setitem__(str(kv[0]), _Invite(
            peer=str(kv[1][0]), fingerprint=str(kv[1][1]), at=float(kv[1][2]),
            accepted=bool(kv[1][3]))))
        each("outgoing", lambda v: self._outgoing.__setitem__(
            (str(v[0]), str(v[1])), _Outgoing(room=str(v[0]), at=float(v[2]))))
        each("awaiting", lambda kv: self._awaiting_welcome.__setitem__(
            str(kv[0]), str(kv[1])))
        each("welcome_for", lambda kv: self._welcome_for.__setitem__(
            str(kv[0]), [str(p) for p in kv[1]]))
        each("pending_binding", lambda kv: self._pending_binding.__setitem__(
            str(kv[0]), [(str(p), bool(v)) for p, v in kv[1]]))
        each("unconfirmed", lambda kv: self._unconfirmed.__setitem__(
            str(kv[0]), [_b64d(str(kv[1][0])), int(kv[1][1])]))
        each("since_rekey", lambda kv: self._since_rekey.__setitem__(
            str(kv[0]), [int(kv[1][0]), float(kv[1][1])]))
        each("activity", lambda kv: self._activity.__setitem__(
            str(kv[0]), {str(j): float(t) for j, t in kv[1].items()}))
        self._expire()

    def save(self) -> None:
        """Seal the state to disk, atomically. No-op without a state dir."""
        with self._lock:
            state_path, _ = self._paths()
            if not state_path or self._client is None or self._wiped:
                return
            self._store_app_state()
            blob = self._client.seal(self._dek, self._account.encode())
            tmp = state_path + ".tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                os.write(fd, bytes(blob))
                os.fsync(fd)
            finally:
                os.close(fd)
            os.replace(tmp, state_path)

    def close(self) -> None:
        """An ordinary exit: seal the state to disk, then zeroize every group
        secret held in memory. The sealed files are KEPT, so the groups reopen
        on the next start (`open`). Wipe & Exit is `wipe`, not this.

        Used by the terminal client's /quit. The Android app never exits
        this way: its only teardown of group state is Wipe & Exit."""
        with self._lock:
            if self._wiped:
                return
            try:
                self.save()
            finally:
                if self._client is not None:
                    try:
                        self._client.wipe()
                    except Exception:
                        pass
                if self._dek is not None:
                    try:
                        self._dek.zeroize()
                    except Exception:
                        pass
                self._client = None
                self._dek = None
                self._stop_maintenance()
                self._activity.clear()
                self._queued_kps.clear()
                self._invites.clear()
                self._outgoing.clear()
                self._awaiting_welcome.clear()
                self._welcome_for.clear()
                self._pending_binding.clear()
                self._reassembler.clear()

    def wipe(self) -> None:
        """Wipe & Exit: every group secret destroyed, state files removed."""
        with self._lock:
            self._wiped = True
            if self._client is not None:
                try:
                    self._client.wipe()
                except Exception:
                    pass
            if self._dek is not None:
                try:
                    self._dek.zeroize()
                except Exception:
                    pass
            state_path, dek_path = self._paths()
            for path in (state_path, dek_path,
                         state_path and state_path + ".tmp",
                         state_path and state_path + ".unopened"):
                if path and os.path.exists(path):
                    try:
                        os.remove(path)
                    except OSError:
                        pass
            self._invites.clear()
            self._outgoing.clear()
            self._awaiting_welcome.clear()
            self._welcome_for.clear()
            self._pending_binding.clear()
            self._bound.clear()
            self._reassembler.clear()
            self._unconfirmed.clear()
            self._since_rekey.clear()
            self._activity.clear()
            self._queued_kps.clear()
            self._stop_maintenance()
            self._pacer.close()

    @property
    def wiped(self) -> bool:
        return self._wiped

    # -- queries ------------------------------------------------------------

    def is_secure(self, room: str) -> bool:
        with self._lock:
            if self._client is None or self._wiped:
                return False
            return bool(self._client.has_group(room.encode()))

    def rooms(self) -> List[str]:
        with self._lock:
            if self._client is None or self._wiped:
                return []
            return sorted(g.decode() for g in self._client.group_ids())

    def own_fingerprint(self, room: str) -> str:
        """Our fingerprint in `room`: every group has its own signing key,
        replaced by each of our rekeys."""
        return bytes(self._need().own_fingerprint(room.encode())).hex()

    def members(self, room: str) -> List[Dict[str, Any]]:
        """Each member: jid, fingerprint, verified, and whether it is us."""
        with self._lock:
            client = self._need()
            out = []
            bound = self._bound.get(room, {})
            for ident in client.members(room.encode()):
                jid = bytes(ident).decode(errors="replace")
                fp = bytes(client.member_fingerprint(room.encode(), bytes(ident))).hex()
                known = bound.get(jid)
                out.append({
                    "jid": jid,
                    "fingerprint": fp,
                    "me": jid == self._account,
                    "verified": bool(known and known[0] == fp and known[1]),
                    "bound": bool(known and known[0] == fp),
                })
            return out

    def epoch(self, room: str) -> int:
        return int(self._need().epoch(room.encode()))

    #: MLS ciphersuite code points (MLS_SECURITY_HARDENING.md §2).
    SUITE_HYBRID = 0xF0A1
    SUITE_PQ_ONLY = 0x0907

    def suite(self, room: str) -> str:
        """"hybrid" (X448+ML-KEM-1024 / Ed448+ML-DSA-87, every group made
        since rc.27) or "pq-only" (ML-KEM-1024 / ML-DSA-87, a group made
        before). A pq-only group keeps working but takes no new members."""
        client = self._need()
        if not hasattr(client, "ciphersuite"):
            return "pq-only"
        code = int(client.ciphersuite(room.encode()))
        return "hybrid" if code == self.SUITE_HYBRID else "pq-only"

    def awaiting_welcome(self, room: str) -> bool:
        """Whether we accepted an invitation to `room` and await its Welcome."""
        with self._lock:
            return room in self._awaiting_welcome

    def pending_invites(self) -> List[Dict[str, Any]]:
        with self._lock:
            self._expire()
            return [{"room": r, "peer": i.peer, "accepted": i.accepted}
                    for r, i in sorted(self._invites.items())]

    # -- creating and inviting ---------------------------------------------

    def create(self, room: str) -> None:
        """Make `room` a secure group, with us its only member."""
        if not _room_ok(room):
            raise GroupError("bad_room")
        with self._lock:
            client = self._need()
            try:
                client.create_group(room.encode())
            except ValueError:
                raise GroupError("group_exists")
            self._since_rekey[room] = [0, self._clock()]
            self._activity[room] = {self._account: self._clock()}
            self.save()
        self._emit(GroupChanged(peer=room, change="created",
                                epoch=self.epoch(room)))

    def _require_otr(self, peer: str) -> bool:
        """The setup channel must be an encrypted OTRv4+ session. Returns
        whether it is SMP-verified."""
        level = self._peer_security(peer)
        if level not in (SecurityState.ENCRYPTED, SecurityState.FINGERPRINT,
                         SecurityState.SMP_VERIFIED):
            raise GroupError("otr_required",
                             "an encrypted OTRv4+ session with this contact is needed")
        return level == SecurityState.SMP_VERIFIED

    def invite(self, room: str, peer: str) -> None:
        """Invite `peer` over our OTRv4+ session with them."""
        # The KeyPackage that answers this is matched on (room, peer) as the
        # app reports the sender: bare and lower-case. An invite stored under
        # the address as typed ("Bob@…", or with a resource) never matched,
        # and the answer was dropped as uninvited.
        peer = str(peer or "").strip().split("/", 1)[0].lower()
        with self._lock:
            client = self._need()
            if not client.has_group(room.encode()):
                raise GroupError("not_a_group")
            if self.suite(room) != "hybrid":
                raise GroupError("legacy_group",
                                 "this group uses the earlier post-quantum-only "
                                 "suite and cannot take new members; create a "
                                 "new group (hybrid X448+ML-KEM-1024)")
            self._require_otr(peer)
            fp = bytes(client.own_fingerprint(room.encode())).hex()
            self._outgoing[(room, peer)] = _Outgoing(room=room, at=self._clock())
            self.save()
        self._send_private(peer, "%sINVITE:%s|%s" % (SIGNAL_PREFIX, room, fp))
        self._emit(GroupChanged(peer=room, change="invite_sent", detail=peer))

    def accept(self, room: str) -> None:
        """Answer an invitation: send a KeyPackage to the inviter over OTRv4+."""
        with self._lock:
            self._expire()
            inv = self._invites.get(room)
            if inv is None:
                raise GroupError("no_invite")
            self._require_otr(inv.peer)
            kp = bytes(self._need().key_package())
            inv.accepted = True
            self._awaiting_welcome[room] = inv.peer
            self.save()
        self._send_private(inv.peer, "%sKP:%s|%s" % (SIGNAL_PREFIX, room, _b64e(kp)))

    def decline(self, room: str) -> None:
        with self._lock:
            inv = self._invites.pop(room, None)
            self._awaiting_welcome.pop(room, None)
        if inv is not None:
            try:
                self._send_private(inv.peer, "%sDECLINE:%s" % (SIGNAL_PREFIX, room))
            except Exception:
                pass

    def _expire(self) -> None:
        now = self._clock()
        for room in [r for r, i in self._invites.items() if now - i.at > INVITE_TTL]:
            self._invites.pop(room, None)
            self._awaiting_welcome.pop(room, None)
        for key in [k for k, o in self._outgoing.items() if now - o.at > INVITE_TTL]:
            self._outgoing.pop(key, None)

    # -- the OTRv4+ side channel -------------------------------------------

    def on_signal(self, peer: str, body: str) -> None:
        """A `?OTRv4-MLS:` message that arrived INSIDE an OTRv4+ session.

        The caller has already decrypted it; this re-checks that the session
        is encrypted anyway, so nothing unauthenticated can drive a join."""
        try:
            verified = self._require_otr(peer)
        except GroupError:
            self._emit(ErrorOccurred(peer=peer, code="group_signal_unencrypted"))
            return
        rest = body[len(SIGNAL_PREFIX):]
        kind, _, arg = rest.partition(":")
        try:
            if kind == "INVITE":
                self._on_invite(peer, arg, verified)
            elif kind == "KP":
                self._on_key_package(peer, arg, verified)
            elif kind == "WELCOME":
                self._on_welcome(peer, arg, verified)
            elif kind == "DECLINE":
                self._on_decline(peer, arg)
            else:
                self.stats.malformed += 1
        except GroupError as exc:
            self._emit(GroupChanged(peer=arg.partition("|")[0][:MAX_ROOM_LEN],
                                    change="refused", detail=exc.code))

    def _on_invite(self, peer: str, arg: str, verified: bool) -> None:
        room, _, fp = arg.partition("|")
        if not _room_ok(room) or not _FP_RE.match(fp):
            self.stats.malformed += 1
            return
        with self._lock:
            self._need()
            self._expire()
            if self.is_secure(room):
                return                          # already a member
            if room not in self._invites and len(self._invites) >= MAX_PENDING_INVITES:
                raise GroupError("too_many_invites")
            self._invites[room] = _Invite(peer=peer, fingerprint=fp, at=self._clock())
            self._bound.setdefault(room, {})[peer] = (fp, verified)
        self._emit(GroupInvite(peer=peer, room=room, verified=verified))

    def _on_key_package(self, peer: str, arg: str, verified: bool) -> None:
        room, _, b64 = arg.partition("|")
        with self._lock:
            client = self._need()
            if (room, peer) not in self._outgoing:
                # We did not invite them: a KeyPackage alone never adds anyone.
                raise GroupError("uninvited_key_package")
            if not client.has_group(room.encode()):
                raise GroupError("not_a_group")
            try:
                kp = _b64d(b64)
            except (ValueError, binascii.Error):
                raise GroupError("malformed")
            if client.has_pending_commit(room.encode()):
                # One of our commits (a rekey, another add) is out: add them
                # once it settles, rather than refuse an invitee who did
                # everything right.
                queued = self._queued_kps.setdefault(room, [])
                if len(queued) < MAX_PENDING_INVITES:
                    queued.append((peer, kp, verified))
                return
            try:
                commit = bytes(client.add_members(room.encode(), [kp]))
            except ValueError as exc:
                raise GroupError("add_refused", str(exc)[:80])
            self._outgoing.pop((room, peer), None)
            self._welcome_for.setdefault(room, []).append(peer)
            # Bound when the commit lands, from the group's own record of the
            # leaf this KeyPackage made -- see `_on_commit`.
            self._pending_binding.setdefault(room, []).append((peer, verified))
            self.save()
        self._post_commit(room, commit)

    def _add_queued(self, room: str) -> None:
        """Add the invitees whose KeyPackages waited for our commit."""
        with self._lock:
            queued = self._queued_kps.pop(room, [])
            client = self._client
            if not queued or client is None or self._wiped:
                return
            try:
                commit = bytes(client.add_members(room.encode(),
                                                  [kp for _p, kp, _v in queued]))
            except Exception:
                for peer, _kp, _v in queued:
                    self._outgoing.pop((room, peer), None)
                    self._emit(GroupChanged(peer=room, change="refused",
                                            detail="add_refused"))
                return
            for peer, _kp, verified in queued:
                self._outgoing.pop((room, peer), None)
                self._welcome_for.setdefault(room, []).append(peer)
                self._pending_binding.setdefault(room, []).append((peer, verified))
            self.save()
        self._post_commit(room, commit)

    def _on_welcome(self, peer: str, arg: str, verified: bool) -> None:
        room, _, rest = arg.partition("|")
        b64, _, sent_fp = rest.partition("|")
        if sent_fp and not _FP_RE.match(sent_fp):
            raise GroupError("malformed")
        with self._lock:
            client = self._need()
            if self._awaiting_welcome.get(room) != peer:
                raise GroupError("unsolicited_welcome")
            inv = self._invites.get(room)
            try:
                welcome = _b64d(b64)
            except (ValueError, binascii.Error):
                raise GroupError("malformed")
            try:
                gid = bytes(client.join(welcome)).decode(errors="replace")
            except ValueError:
                raise GroupError("welcome_refused")
            if gid != room:
                client.forget_group(gid.encode())
                raise GroupError("welcome_for_another_room")
            # THE BINDING CHECK. The inviter told us their fingerprint over
            # OTRv4+; the group must hold that key for them. If it does not,
            # somebody else's group was presented under their name.
            try:
                held = bytes(client.member_fingerprint(room.encode(), peer.encode())).hex()
            except ValueError:
                held = ""
            # The key the inviter holds NOW (sent with the Welcome, over the
            # same OTRv4+ session as the invite): it may have rotated since
            # the invite. An older client sends none; the invite's is used.
            expected = sent_fp or (inv.fingerprint if inv is not None else "")
            if inv is None or not expected or held != expected:
                client.forget_group(room.encode())
                raise GroupError("inviter_fingerprint_mismatch")
            if sent_fp:
                self._bound.setdefault(room, {})[peer] = (sent_fp, verified)
            self._invites.pop(room, None)
            self._awaiting_welcome.pop(room, None)
            now = self._clock()
            self._since_rekey[room] = [0, now]
            self._activity[room] = {bytes(m).decode(errors="replace"): now
                                    for m in client.members(room.encode())}
            self.save()
            epoch = int(client.epoch(room.encode()))
        self._emit(GroupChanged(peer=room, change="joined", epoch=epoch))

    def _on_decline(self, peer: str, room: str) -> None:
        with self._lock:
            had = self._outgoing.pop((room, peer), None)
        if had is not None:
            self._emit(GroupChanged(peer=room, change="invite_declined", detail=peer))

    # -- the room -----------------------------------------------------------

    def _post(self, room: str, mls: bytes) -> None:
        payload = ROOM_PREFIX + _b64e(mls)
        parts, self._frag_seq = _fragment.fragment(
            payload, self._frag_seq, _fragment.ROOM_FRAGMENT)
        self._pacer.post(room, parts)

    def _post_commit(self, room: str, commit: bytes) -> None:
        """Post one of OUR commits and keep it until it comes back."""
        with self._lock:
            self._unconfirmed[room] = [bytes(commit), 0]
            self.save()               # a restart now still has it to re-send
        self._post(room, commit)

    def resend_pending_commit(self, room: str, reason: str = "") -> bool:
        """Post our unconfirmed commit for `room` again. True if it was.

        Safe to repeat: a commit that did land is stale to every member and
        dropped; one that did not is the only way the group moves on (MLS
        refuses every send while it is pending). Bounded by
        MAX_COMMIT_RESENDS."""
        with self._lock:
            entry = self._unconfirmed.get(room)
            client = self._client
            if entry is None or client is None or self._wiped:
                return False
            try:
                pending = bool(client.has_pending_commit(room.encode()))
            except Exception:
                pending = True
            if not pending:
                self._unconfirmed.pop(room, None)
                return False
            if entry[1] >= self.MAX_COMMIT_RESENDS:
                return False
            if self._pacer.pending(room) or self._pacer.in_flight(room):
                return False         # its pieces are still going out
            entry[1] += 1
            commit = entry[0]
        self._emit(GroupChanged(peer=room, change="commit_resent",
                                detail=reason[:40]))
        self._post(room, commit)
        return True

    def on_room_rejected(self, room: str) -> None:
        """The server bounced a message to `room` (e.g. mod_muc_limits)."""
        if not self.is_secure(room):
            return
        self._emit(ErrorOccurred(peer=room, code="room_message_rejected"))
        # Slow this room down and send again what it has not echoed. That
        # covers our commit too; resend_pending_commit is the fallback when
        # nothing of it is left in flight (e.g. pacing off).
        self._pacer.rejected(room)
        if not self._pacer.in_flight(room):
            self.resend_pending_commit(room, "rejected")

    def on_room_rejoined(self, room: str) -> None:
        """We are in `room` again after a reconnect: a commit lost with the
        old stream goes out again (the room's history replay may also bring
        it back, which settles it first)."""
        self._settled_from = self._clock()
        self.resend_pending_commit(room, "rejoined")

    def send(self, room: str, text: str) -> None:
        """Encrypt and post. Raises; never falls back to plaintext."""
        if not text:
            return
        with self._lock:
            client = self._need()
            if not client.has_group(room.encode()):
                raise GroupError("not_a_group")
            try:
                ct = bytes(client.encrypt(room.encode(), text.encode("utf-8")))
            except ValueError as exc:
                code = "commit_pending" if "pending" in str(exc) else "encrypt_refused"
                if code == "commit_pending":
                    # The group is waiting for our own change to come back
                    # from the room. Nudge it rather than leave it stuck.
                    resend = True
                else:
                    resend = False
                err = GroupError(code)
            else:
                err = None
        if err is not None:
            if resend:
                self.resend_pending_commit(room, "send_blocked")
            raise err
        self._post(room, ct)
        self._maybe_rekey(room)

    def _maybe_rekey(self, room: str, count: bool = True) -> bool:
        """Self-update once enough messages or time have passed (see
        AUTO_REKEY_*). Best effort: a refusal is reported, never raised into
        the send that triggered it. True if a rekey was posted."""
        with self._lock:
            entry = self._since_rekey.setdefault(room, [0, self._clock()])
            if count:
                entry[0] += 1
            due = (entry[0] >= self.AUTO_REKEY_MESSAGES
                   or self._clock() - entry[1] >= self.AUTO_REKEY_SECONDS)
            client = self._client
            if not due or client is None or self._wiped:
                return False
            try:
                if client.has_pending_commit(room.encode()):
                    return False
            except Exception:
                return False
            if room in self._unconfirmed or self._pacer.pending(room):
                return False
        try:
            self.rekey(room)
        except Exception:
            self._emit(ErrorOccurred(peer=room, code="group_rekey_failed"))
            return False
        # Counted from now; confirmed (and reset again) when it lands.
        with self._lock:
            self._since_rekey[room] = [0, self._clock()]
        self._emit(GroupChanged(peer=room, change="rekeyed",
                                epoch=self.epoch(room)))
        return True

    # -- maintenance: timed rekey, idle members --------------------------------

    def _arm_maintenance(self) -> None:
        if self.MAINTAIN_SECONDS <= 0:
            return
        with self._lock:
            if self._wiped or self._client is None or self._maintain_timer is not None:
                return
            timer = threading.Timer(self.MAINTAIN_SECONDS, self._maintain_tick)
            timer.daemon = True
            self._maintain_timer = timer
        timer.start()

    def _stop_maintenance(self) -> None:
        timer, self._maintain_timer = self._maintain_timer, None
        if timer is not None:
            try:
                timer.cancel()
            except Exception:
                pass

    def _maintain_tick(self) -> None:
        with self._lock:
            self._maintain_timer = None
        try:
            self.maintain()
        except Exception:
            pass
        self._arm_maintenance()

    def maintain(self) -> List[str]:
        """Housekeeping for every group, at most one commit each:

          * members whose leaf nobody has seen refreshed for
            IDLE_REMOVE_SECONDS are removed;
          * otherwise our leaf is refreshed (rekey) once AUTO_REKEY_SECONDS
            have passed since our last commit, even if we sent nothing --
            this is also what tells the others we are still here.

        Returns what was done, as "rekey:<room>" / "removed:<room>"."""
        done = []
        for room in self.rooms():
            # A removal commit refreshes our path too, so it goes first.
            if self._remove_idle(room):
                done.append("removed:" + room)
            elif self._maybe_rekey(room, count=False):
                done.append("rekey:" + room)
        return done

    def _remove_idle(self, room: str) -> bool:
        if self.IDLE_REMOVE_SECONDS <= 0:
            return False
        with self._lock:
            client = self._client
            if client is None or self._wiped:
                return False
            now = self._clock()
            if now - self._settled_from < self.IDLE_GRACE_SECONDS:
                return False
            try:
                if client.has_pending_commit(room.encode()):
                    return False
                members = [bytes(m).decode(errors="replace")
                           for m in client.members(room.encode())]
            except Exception:
                return False
            if room in self._unconfirmed or self._pacer.pending(room):
                return False
            seen = self._activity.setdefault(room, {})
            for m in members:
                seen.setdefault(m, now)        # first sight starts the clock
            for gone in [m for m in seen if m not in members]:
                seen.pop(gone, None)
            idle = sorted(m for m in members if m != self._account
                          and now - seen[m] > self.IDLE_REMOVE_SECONDS)
            if not idle:
                return False
            try:
                commit = bytes(client.remove_members(
                    room.encode(), [m.encode() for m in idle]))
            except Exception:
                self._emit(ErrorOccurred(peer=room, code="group_remove_failed"))
                return False
            self.save()
        self._post_commit(room, commit)
        self._emit(GroupChanged(peer=room, change="idle_removed",
                                detail=",".join(idle)[:200]))
        return True

    def remove(self, room: str, member: str) -> None:
        with self._lock:
            client = self._need()
            try:
                commit = bytes(client.remove_members(room.encode(), [member.encode()]))
            except ValueError as exc:
                raise GroupError("remove_refused", str(exc)[:80])
            self.save()
        self._post_commit(room, commit)

    def rekey(self, room: str) -> None:
        """A fresh leaf key for us (post-compromise security)."""
        with self._lock:
            commit = bytes(self._need().self_update(room.encode()))
            self.save()
        self._post_commit(room, commit)

    def leave(self, room: str) -> None:
        """Forget the group and every secret for it, here.

        MLS has no self-removal a member can complete alone: the others still
        list us until one of them commits our removal. What this guarantees
        is local -- we can no longer read the group."""
        with self._lock:
            self._need().forget_group(room.encode())
            self._bound.pop(room, None)
            self.save()
        self._emit(GroupChanged(peer=room, change="left"))

    def on_room_body(self, room: str, nick: str, body: str, timestamp: float = 0.0,
                     own: bool = False) -> bool:
        """A body from a secure room. Returns True if it was ours to handle.

        Plain rooms return False and the caller treats them as before."""
        if not self.is_secure(room):
            return False
        if own:
            self._pacer.confirm(room, body)
        if _fragment.is_fragment(body):
            whole = self._reassembler.feed("%s/%s" % (room, nick), body)
            if whole is None:
                return True
            body = whole
        if not is_room_frame(body):
            # NEVER shown: a secure room has no plaintext.
            self.stats.plaintext_refused += 1
            if not own:
                self._emit(ErrorOccurred(peer=room, code="room_plaintext_refused"))
            return True
        try:
            mls = _b64d(body[len(ROOM_PREFIX):])
        except (ValueError, binascii.Error):
            self.stats.malformed += 1
            return True
        with self._lock:
            client = self._need()
            try:
                ev = client.process(room.encode(), mls)
            except ValueError:
                # History from before we joined, a replay, a stale epoch, a
                # tampered frame, or our own application message reflected
                # back (a sender cannot decrypt its own MLS message).
                if not own:
                    self.stats.undecryptable += 1
                return True
            except RuntimeError:
                self.stats.undecryptable += 1
                return True
            kind = ev.get("kind")
            if kind == "application":
                sender = bytes(ev["sender"]).decode(errors="replace")
                text = bytes(ev["plaintext"]).decode("utf-8", errors="replace")
                fp = bytes(client.member_fingerprint(room.encode(), bytes(ev["sender"]))).hex()
                known = self._bound.get(room, {}).get(sender)
                verified = bool(known and known[0] == fp and known[1])
                self.stats.shown += 1
                event = RoomMessageReceived(peer=room, sender=nick, body=text,
                                            timestamp=timestamp, encrypted=True,
                                            sender_identity=sender, verified=verified)
            elif kind == "commit":
                event = self._on_commit(room, ev)
                settled = bool(ev.get("ours") or ev.get("dropped_ours"))
            else:
                event = None
        if event is not None:
            self._emit(event)
        if kind == "commit" and settled and self._queued_kps.get(room):
            self._add_queued(room)
        return True

    def _on_commit(self, room: str, ev: Dict[str, Any]) -> Optional[Any]:
        client = self._client
        epoch = int(ev.get("epoch", 0))
        now = self._clock()
        seen = self._activity.setdefault(room, {})
        committer = bytes(ev.get("committer") or b"").decode(errors="replace")
        if committer:
            seen[committer] = now
        # A member replaced their signing key with their own update, signed
        # by the old one: a binding we hold for the old key carries over.
        # Anything else (a new leaf under an old name) is NOT carried.
        for who, old, new in ev.get("rekeyed") or []:
            ident = bytes(who).decode(errors="replace")
            seen[ident] = now
            held = self._bound.get(room, {}).get(ident)
            if held is not None and held[0] == bytes(old).hex():
                self._bound[room][ident] = (bytes(new).hex(), held[1])

        if ev.get("ours") or ev.get("dropped_ours"):
            # Landed, or superseded by somebody else's: nothing to re-send.
            self._unconfirmed.pop(room, None)
        if ev.get("ours"):
            # Our leaf key is fresh as of this epoch.
            self._since_rekey[room] = [0, self._clock()]
        if ev.get("removed_us"):
            self._bound.pop(room, None)
            self._activity.pop(room, None)
            self._queued_kps.pop(room, None)
            self.save()
            return GroupChanged(peer=room, change="removed_us", epoch=epoch)
        if ev.get("dropped_ours"):
            self._welcome_for.pop(room, None)
            self._pending_binding.pop(room, None)
            self.save()
            self._emit(GroupChanged(peer=room, change="commit_lost", epoch=epoch))
        welcome = ev.get("welcome")
        invitees = self._welcome_for.pop(room, []) if ev.get("ours") else []
        own_fp = ""
        if welcome is not None:
            try:
                own_fp = bytes(client.own_fingerprint(room.encode())).hex()
            except Exception:
                own_fp = ""
        bindings = self._pending_binding.pop(room, []) if ev.get("ours") else []
        for peer, verified in bindings:
            try:
                fp = bytes(client.member_fingerprint(room.encode(), peer.encode())).hex()
                self._bound.setdefault(room, {})[peer] = (fp, verified)
            except ValueError:
                pass
            seen[peer] = now
        self.save()
        if welcome is not None:
            for peer in invitees:
                try:
                    self._send_private(peer, "%sWELCOME:%s|%s|%s"
                                       % (SIGNAL_PREFIX, room, _b64e(bytes(welcome)),
                                          own_fp))
                except Exception:
                    self._emit(ErrorOccurred(peer=peer, code="group_welcome_send_failed"))
            return GroupChanged(peer=room, change="member_added", epoch=epoch)
        return GroupChanged(peer=room, change="epoch", epoch=epoch)
