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
                ?OTRv4-MLS:ROOMPW:<room>|<base64 room password>   (only when
                the room has one; right after the INVITE, so the invitee can
                enter a password-protected room. A separate signal: an older
                client counts it as unknown and goes on.)
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
import hashlib
import collections
import json
import os
import re
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

import otrv4plus_actions as _actions
import otrv4plus_fragment as _fragment

from .trace import TRACE as _TRACE
from .events import KeysPublished
from .events import (ErrorOccurred, GroupChanged, GroupInvite, MessageChanged,
                     QueuedSent, RoomMessageReceived, SecurityState)

__all__ = ["SecureGroups", "GroupError", "ROOM_PREFIX", "SIGNAL_PREFIX",
           "is_group_signal", "is_room_frame"]

ROOM_PREFIX = "?OTRv4MLS1:"
SIGNAL_PREFIX = "?OTRv4-MLS:"
#: A group message saying "I pressed Publish Group Keys and my keys are out"
#: (F4): each member removes the group's messages from before it. Behind the
#: group verification prefix on purpose, as REVEAL_MAGIC is: an app from
#: before it hands it to the verification handler, which drops anything that
#: is not its JSON, rather than showing it as a line.
GROUP_KEYS_MARK = "\x00OTRv4GV1:keys-published"
#: Posted to the group by its creator just before Delete removes everyone:
#: each member's app ends its copy on it, if MLS says the creator sent it.
#: Behind the verification prefix, as GROUP_KEYS_MARK, so an older app drops it.
GROUP_DELETED_MARK = "\x00OTRv4GV1:group-deleted"
#: Sent by the creator over each member's OTRv4+ session when it deletes the
#: group: `GROUP_DELETED_SIGNAL + room`. A client that does not know it
#: counts it as malformed and drops it.
GROUP_DELETED_SIGNAL = SIGNAL_PREFIX + "DELETED:"

#: Bounds on what a peer or a room can make us hold.
MAX_ROOM_LEN = 256
MAX_FRAME_B64 = 2 * 1024 * 1024
MAX_PENDING_INVITES = 32
INVITE_TTL = 30 * 60.0
#: How long, and how often at most, an unconfirmed Welcome is sent again.
WELCOME_TTL = 24 * 3600.0
WELCOME_RESEND_EVERY = 120.0
WELCOME_MAX_SENDS = 20
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
    #: We already hold this group: accepting replaces our copy (a device
    #: whose group stopped working, invited back by a member).
    rejoin: bool = False
    #: The room's password, sent by the inviter over the same OTRv4+
    #: session (ROOMPW). Memory only: never in the saved state.
    password: str = ""


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
    #: Corrections/deletions refused: not by the author of their target.
    wrong_author: int = 0


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
                 "requeued_at", "inflight", "armed", "check_armed", "volatile")

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
        #: Pieces the room must not keep in its history (file data).
        self.volatile: set = set()


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
                 send_volatile: Optional[Callable[[str, str], None]] = None,
                 slow_burst: int = 3, slow_interval: float = 2.2,
                 slow_for: float = 300.0, max_slow_for: float = 3600.0,
                 echo_timeout: float = 20.0, max_attempts: int = 3,
                 clock: Callable[[], float] = time.monotonic,
                 schedule: Optional[Callable[[float, Callable[[], None]], Any]] = None):
        self._send = send
        #: Sends a piece with a no-store hint (XEP-0334), so the room keeps it
        #: out of its history: see SecureGroups.send_bulk.
        self._send_volatile = send_volatile or send
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

    def post(self, room: str, parts: List[str], volatile: bool = False) -> None:
        if self._interval <= 0:
            send = self._send_volatile if volatile else self._send
            for part in parts:
                send(room, part)
            return
        with self._lock:
            if self._closed:
                return
            state = self._room(room)
            state.queue.extend([part, 0] for part in parts)
            if volatile:
                state.volatile.update(parts)
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
            state.volatile.discard(part)
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
                state.volatile.discard(part)
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
                send = self._send_volatile if part in state.volatile else self._send
            try:
                send(room, part)
            except Exception:
                with self._lock:
                    # The stream is gone: the rest of a set is useless, and a
                    # commit is posted again by its owner after a rejoin.
                    state.queue.clear()
                    state.inflight.clear()
                    state.volatile.clear()
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
    #: specification (docs/MLS_SECURITY_HARDENING.md §4): 50 messages / 30 min.
    #: A self-update in a 4-member group is ~22 KB (8 room fragments).
    AUTO_REKEY_MESSAGES = _env_int("OTRV4PLUS_MLS_REKEY_MESSAGES", 50, 1, 100000)
    AUTO_REKEY_SECONDS = _env_int("OTRV4PLUS_MLS_REKEY_SECONDS", 30 * 60, 60, 30 * 86400)
    #: F4 (epochal signatures): a signing key a rekey retired is published to
    #: the group this long after the rekey landed -- by `maintain` -- so what
    #: it signed can no longer be proven ours. "Make Group Deniable" publishes
    #: as soon as its rekey lands. Never the key in use.
    REVEAL_DELAY_SECONDS = _env_int("OTRV4PLUS_MLS_REVEAL_SECONDS", 10 * 60, 0, 30 * 86400)
    #: A member whose leaf has not been refreshed by a commit of theirs for
    #: this long is removed by the next member that notices (owner decision
    #: U1: 72 h, docs/MLS_SECURITY_HARDENING.md §4). Online members refresh at
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
                 clock: Callable[[], float] = time.time,
                 send_room_volatile: Optional[Callable[[str, str], None]] = None):
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
        #: room -> {jid: fingerprint hex} whose group verification FAILED on
        #: that key: one attempt per key (owner, 2026-10-25), kept until the
        #: creator removes them; a new key (invited again) starts clean.
        self._failed: Dict[str, Dict[str, str]] = {}
        #: room -> {jid: [denials, last denied at]}: the creator's "Deny" to a
        #: request to join (owner, 2026-10-25), kept so a pest's next request
        #: waits 15 minutes, doubling with each denial (OtrApp.entry_wait).
        self._entry_denied: Dict[str, Dict[str, list]] = {}
        #: room -> {message id: MLS identity of its author}, bounded, memory
        #: only (the UI keeps the author with each stored message).
        self._authors: Dict[str, "collections.OrderedDict[str, str]"] = {}
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
        #: room -> when a rekey of ours last retired a key not yet published (F4).
        self._retired_at: Dict[str, float] = {}
        #: Rooms whose retired keys go as soon as every member is past the
        #: rotation (F4); kept until none wait.
        self._reveal_now: set = set()
        #: room -> who removed us from it (the committer of the commit that
        #: did): a "group deleted" notice from them ends it here too.
        self._removed_by: Dict[str, str] = {}
        #: room -> when we pressed Publish Group Keys (ms): once those keys
        #: are out, GROUP_KEYS_MARK tells the members, and each removes what
        #: came before it.
        self._history_due: Dict[str, int] = {}
        #: Rooms owing an acknowledgement of another member's rotation (F4)
        #: that could not go yet (a commit of ours was pending).
        self._ack_owed: set = set()
        #: room -> {member identity: when a commit of theirs last refreshed
        #: their leaf (or they joined)} -- what idle removal judges.
        self._activity: Dict[str, Dict[str, float]] = {}
        #: room -> [(peer, KeyPackage, verified)] that arrived while one of our
        #: commits was pending; added once it settles.
        self._queued_kps: Dict[str, List[Tuple[str, bytes, bool]]] = {}
        self._settled_from = 0.0
        #: room -> 0.0 while we are not (back) in its room, then the time its
        #: history counts as applied. A message sent before then is encrypted
        #: for an epoch the others have left, and they drop it -- the first
        #: message after a re-login was lost (device test, 2026-10-05). So it
        #: is held, and sent when the group is in sync.
        self._syncing: Dict[str, float] = {}
        self._held: Dict[str, List[str]] = {}
        self._sync_timers: Dict[str, Any] = {}
        self._maintain_timer: Any = None
        self._lock_fd: Optional[int] = None
        self._adopted_from: Optional[str] = None
        #: Group calls (android_bridge.group_call): control messages travel
        #: as MLS application messages with CALL_PREFIX and go here, never
        #: to the chat; the epoch listener hears about every commit.
        #: (room, invitee) -> [WELCOME signal, first sent, times sent]:
        #: re-sent until the invitee answers JOINED (or WELCOME_TTL passes).
        self._welcome_out: Dict[Tuple[str, str], List[Any]] = {}
        self._call_handler: Optional[Callable[[str, str, bool, str], None]] = None
        #: Group verification (android_bridge.group_verify), the same way.
        self._verify_handler: Optional[Callable[[str, str, bool, str], None]] = None
        #: Group files (android_bridge.group_files), the same way.
        self._file_handler: Optional[Callable[[str, str, bool, str], None]] = None
        self._epoch_listener: Optional[Callable[[str], None]] = None
        #: Further listeners for every commit (group verification).
        self._epoch_listeners: List[Callable[[str], None]] = []
        self._pacer = RoomPacer(
            send_room, burst=self.ROOM_BURST, interval=self.ROOM_INTERVAL,
            send_volatile=send_room_volatile,
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

    def _paths(self, account: Optional[str] = None) -> Tuple[Optional[str], Optional[str]]:
        """(sealed state, DEK). The state is ONE FILE PER ACCOUNT, named by a
        hash of it (no address in a file name): one file for the device let
        a second account on the same phone (the app signed in as someone
        else, Termux run as B then C) find the first one's state, fail to
        open it and set it aside -- and the next switch overwrite what was
        set aside, losing the first account's groups."""
        if not self._state_dir:
            return None, None
        account = account if account is not None else self._account
        name = self.STATE_NAME
        if account:
            digest = hashlib.sha256(account.encode()).hexdigest()[:20]
            name = "groups-%s.sealed" % digest
        return (os.path.join(self._state_dir, name),
                os.path.join(self._state_dir, self.DEK_NAME))

    def _candidates(self, state_path: str) -> List[str]:
        """Files that may hold this account's state, best first: its own
        file, its last good copy, then the old one-per-device file and any
        state set aside by earlier versions (each is tried, and adopted only
        if it opens under THIS account)."""
        out = [state_path, state_path + ".prev"]
        legacy = os.path.join(self._state_dir, self.STATE_NAME)
        out += [legacy, legacy + ".unopened"]
        try:
            out += sorted(os.path.join(self._state_dir, f)
                          for f in os.listdir(self._state_dir)
                          if f.startswith(self.STATE_NAME + ".unopened."))
        except OSError:
            pass
        return [p for p in out if os.path.isfile(p)]

    def _take_lock(self, state_path: str) -> None:
        """One running client per account's state. Two (a client left
        running and a new one, or a reconnect racing a timer) would each
        save their own copy over the other's."""
        if self._lock_fd is not None:
            return
        try:
            import fcntl
        except ImportError:                 # not POSIX: no lock, as before
            return
        fd = os.open(state_path + ".lock", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            raise GroupError("state_in_use",
                             "another client for this account is running "
                             "and holds its group state; close it first")
        self._lock_fd = fd

    def _release_lock(self) -> None:
        fd, self._lock_fd = self._lock_fd, None
        if fd is not None:
            try:
                os.close(fd)                # closing releases the flock
            except OSError:
                pass

    def open(self, account: str) -> None:
        """Create or reopen this account's MLS state.

        Already open for this account (a reconnect): nothing to do -- the
        state in memory is the newest. A state file that does not open under
        this account is left where it is, never renamed or overwritten: it
        may be another account's."""
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
            if self._client is not None and self._account == account:
                return
            if self._client is not None:
                self.close()                 # another account: seal and let go
            state_path, dek_path = self._paths(account)
            client = None
            restored: List[str] = []
            if state_path and dek_path:
                os.makedirs(self._state_dir, mode=0o700, exist_ok=True)
                self._take_lock(state_path)
                self._dek = core.FileDek.load_or_create(dek_path)
                reasons = []
                for path in self._candidates(state_path):
                    try:
                        with open(path, "rb") as f:
                            blob = f.read()
                        client = core.RustMlsClient.open_sealed(
                            self._dek, account.encode(), blob)
                    except Exception as exc:
                        # Rust's refusal text names the check, never data.
                        reasons.append("%s: %s" % (os.path.basename(path),
                                                   str(exc)[:80]))
                        client = None
                        continue
                    if path != state_path:
                        self._adopted_from = os.path.basename(path)
                    break
                if client is None and os.path.isfile(state_path):
                    self._emit(ErrorOccurred(peer=None, code="groups_state_unreadable",
                                             detail="; ".join(reasons)[:300]))
                    # Kept, under a name nothing else writes to.
                    os.replace(state_path, "%s.unopened.%d" % (state_path, int(time.time())))
            if client is None:
                client = core.RustMlsClient(account.encode())
            self._client = client
            self._account = account
            self._load_app_state()
            self._settled_from = self._clock()
            # Restored groups: their rooms are not joined yet.
            restored = self._room_ids()
            for room in restored:
                self._syncing[room] = 0.0
            if getattr(self, "_adopted_from", None):
                self.save()                  # now under this account's own name
        # Says, before anything else, which rooms are secure groups and that
        # they are catching up -- the app showed a restored group as "Not
        # encrypted" until something happened in it (device test).
        for room in restored:
            self._emit(GroupChanged(peer=room, change="syncing"))
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
            "failed": {r: dict(m) for r, m in self._failed.items() if m},
            "entry_denied": {r: {j: [int(v[0]), float(v[1])] for j, v in m.items()}
                             for r, m in self._entry_denied.items() if m},
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
            "welcome_out": [[r, p, e[0], float(e[1]), int(e[2])]
                            for (r, p), e in self._welcome_out.items()],
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
        each("entry_denied", lambda kv: self._entry_denied.setdefault(str(kv[0]), {}).update(
            {str(j): [int(v[0]), float(v[1])] for j, v in kv[1].items()}))
        each("failed", lambda kv: self._failed.setdefault(str(kv[0]), {}).update(
            {str(j): str(fp) for j, fp in kv[1].items()}))
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
        each("welcome_out", lambda v: self._welcome_out.__setitem__(
            (str(v[0]), str(v[1])), [str(v[2]), float(v[3]), int(v[4])]))
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
            blob = bytes(self._client.seal(self._dek, self._account.encode()))
            # A temporary name of our own, so two writers (should there ever
            # be two) cannot interleave inside one file; then the previous
            # good state is kept as .prev and the new one replaces it --
            # each step an atomic rename.
            tmp = "%s.%d.%d.tmp" % (state_path, os.getpid(), threading.get_ident())
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                view = memoryview(blob)
                while view:
                    view = view[os.write(fd, view):]
                os.fsync(fd)
            finally:
                os.close(fd)
            if os.path.exists(state_path):
                os.replace(state_path, state_path + ".prev")
            os.replace(tmp, state_path)

    def close(self) -> None:
        """An ordinary exit: seal the state to disk, then zeroize every group
        secret held in memory. The sealed files are KEPT, so the groups reopen
        on the next start (`open`). Wipe & Exit is `wipe`, not this.

        Used by the terminal client's /quit, and by the app's sign-out
        (`OtrApp.shutdown`): until rc.38 the app never closed its groups, so
        their lock stayed held and signing in again on the same phone found
        the state "in use" (device test, 2026-10-05)."""
        for timer in list(self._sync_timers.values()):
            try:
                timer.cancel()
            except Exception:
                pass
        self._sync_timers.clear()
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
                self._account = ""
                self._release_lock()
                self._stop_maintenance()
                self._activity.clear()
                self._queued_kps.clear()
                self._invites.clear()
                self._outgoing.clear()
                self._awaiting_welcome.clear()
                self._welcome_for.clear()
                self._welcome_out.clear()
                self._pending_binding.clear()
                self._authors.clear()
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
            # Every account's state, its last good copy, anything set aside,
            # temporaries, locks and the key: all of it, not just ours.
            self._release_lock()
            if self._state_dir and os.path.isdir(self._state_dir):
                for name in os.listdir(self._state_dir):
                    if name.startswith("groups"):
                        try:
                            os.remove(os.path.join(self._state_dir, name))
                        except OSError:
                            pass
            self._invites.clear()
            self._outgoing.clear()
            self._awaiting_welcome.clear()
            self._welcome_for.clear()
            self._welcome_out.clear()
            self._pending_binding.clear()
            self._bound.clear()
            self._failed.clear()
            self._entry_denied.clear()
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
            failed = self._failed.get(room, {})
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
                    "failed": failed.get(jid) == fp and not (known and known[0] == fp and known[1]),
                })
            return out

    def epoch(self, room: str) -> int:
        return int(self._need().epoch(room.encode()))

    # -- group calls (android_bridge.group_call) ------------------------------

    @property
    def account(self) -> str:
        return self._account

    @property
    def is_open(self) -> bool:
        """Whether an account's MLS state is open, so signals can be handled."""
        return self._client is not None and not self._wiped

    def set_verify_handler(self, fn: Optional[Callable[[str, str, bool, str], None]]) -> None:
        self._verify_handler = fn

    def member_fingerprint(self, room: str, member: str) -> str:
        """The group key the group holds for `member` now (hex)."""
        with self._lock:
            return bytes(self._need().member_fingerprint(
                room.encode(), member.encode())).hex()

    def mark_member_verified(self, room: str, member: str,
                             expected_fp: Optional[str] = None) -> bool:
        """A group verification (shared-passphrase SMP over the member's
        current group key) succeeded with `member` -- ours, or vouched for
        by the group's creator. With `expected_fp` (a vouch), only if that is
        the key the group holds for them now: a vouch for a replaced key binds
        nothing. Returns whether `member` is now verified."""
        with self._lock:
            client = self._need()
            try:
                fp = bytes(client.member_fingerprint(room.encode(), member.encode())).hex()
            except ValueError:
                return False                 # not a member (any more)
            if expected_fp is not None and expected_fp.lower() != fp:
                return False
            before = self._bound.get(room, {}).get(member)
            self._bound.setdefault(room, {})[member] = (fp, True)
            self._failed.get(room, {}).pop(member, None)
            if before != (fp, True):
                self.save()
        if before != (fp, True):
            self._emit(GroupChanged(peer=room, change="member_verified", detail=member))
        return True

    def mark_member_failed(self, room: str, member: str,
                           expected_fp: Optional[str] = None) -> bool:
        """`member`'s group verification failed (the passphrase did not
        match) on the key the group holds for them now -- ours, or said by
        the creator. Not over a key already verified. Returns whether it
        was recorded."""
        with self._lock:
            client = self._need()
            try:
                fp = bytes(client.member_fingerprint(room.encode(), member.encode())).hex()
            except ValueError:
                return False
            if expected_fp is not None and expected_fp.lower() != fp:
                return False
            known = self._bound.get(room, {}).get(member)
            if known and known[0] == fp and known[1]:
                return False
            book = self._failed.setdefault(room, {})
            if book.get(member) == fp:
                return True
            book[member] = fp
            self.save()
        return True

    def entry_denial(self, room: str, jid: str) -> Tuple[int, float]:
        """How often the creator denied `jid`'s request to join, and when
        last: (0, 0.0) for never."""
        with self._lock:
            held = self._entry_denied.get(room, {}).get(jid)
            return (int(held[0]), float(held[1])) if held else (0, 0.0)

    def deny_entry(self, room: str, jid: str, at: float) -> int:
        """One more denial of `jid`, at `at`. Returns how many now."""
        with self._lock:
            book = self._entry_denied.setdefault(room, {})
            count = int(book.get(jid, [0, 0.0])[0]) + 1
            book[jid] = [count, float(at)]
            self.save()
            return count

    def clear_entry_denial(self, room: str, jid: str) -> None:
        with self._lock:
            if self._entry_denied.get(room, {}).pop(jid, None) is not None:
                self.save()

    #: How far `coordinator` looks for the lowest occupied leaf.
    MAX_LEAF_SEARCH = 4096

    def coordinator(self, room: str) -> str:
        """The group's creator: the member at the first MLS leaf (the
        longest-standing member once the creator has left). "" if unknown.

        Read from the tree by leaf, lowest first. It was the first name of
        `members()`, which Rust returns sorted: so the "creator" was whoever
        sorted first, and a creator called "dontlook" with a member called
        "charlie" was not the creator (device report, 2026-10-27: Delete on
        the creator's phone removed nobody)."""
        try:
            with self._lock:
                client = self._need()
                if not client.members(room.encode()):
                    return ""
                # Leaves are filled lowest first and freed in place; after
                # removals the survivors can sit high, so the search goes up
                # to the tree's bound, and stops at the first one.
                for leaf in range(self.MAX_LEAF_SEARCH):
                    try:
                        who = client.member_at(room.encode(), leaf)
                    except Exception:
                        continue
                    return bytes(who).decode(errors="replace")
                return ""
        except Exception:
            return ""

    def set_file_handler(self, fn: Optional[Callable[[str, str, bool, str], None]]) -> None:
        self._file_handler = fn

    def set_call_handler(self, fn: Optional[Callable[[str, str, bool, str], None]]) -> None:
        self._call_handler = fn

    def set_epoch_listener(self, fn: Optional[Callable[[str], None]]) -> None:
        self._epoch_listener = fn

    def add_epoch_listener(self, fn: Callable[[str], None]) -> None:
        """Another listener for every commit (the calls keep the first)."""
        if fn not in self._epoch_listeners:
            self._epoch_listeners.append(fn)

    def send_control(self, room: str, text: str) -> None:
        """A call control message: encrypted and posted like a message, and
        recognised (by its prefix) and never shown at the other end."""
        from .group_call import CALL_PREFIX
        from .group_files import FILE_PREFIX
        from .group_verify import VERIFY_PREFIX
        if not text.startswith((CALL_PREFIX, VERIFY_PREFIX, FILE_PREFIX)):
            raise GroupError("bad_control")
        self.send(room, text)

    #: `send_bulk` refuses (the caller tries again later) while this many
    #: room pieces are still waiting to go out, so a file never queues ahead
    #: of more than a few seconds of chat, commits and call control.
    BULK_BACKLOG = 24

    def send_bulk(self, room: str, text: str) -> bool:
        """Bulk data (a group file's pieces): encrypted like a message, but
        sent only when the group can take it at once, and posted with a
        no-store hint so the room keeps it out of its history -- which holds
        the commits a returning member needs to catch up, and must not be
        pushed out by a file. Never held: False means "not now", and the
        caller sends the same piece again later."""
        from .group_files import FILE_PREFIX
        if not text.startswith(FILE_PREFIX):
            raise GroupError("bad_control")
        self._sync_check(room)
        with self._lock:
            client = self._need()
            if not client.has_group(room.encode()):
                raise GroupError("not_a_group")
            if (room in self._syncing or self._held.get(room)
                    or self._pacer.pending(room) >= self.BULK_BACKLOG):
                return False
            try:
                if client.has_pending_commit(room.encode()):
                    return False
                ct = bytes(client.encrypt(room.encode(), text.encode("utf-8")))
            except ValueError:
                return False
        payload = ROOM_PREFIX + _b64e(ct)
        parts, self._frag_seq = _fragment.fragment(
            payload, self._frag_seq, _fragment.ROOM_FRAGMENT)
        self._pacer.post(room, parts, volatile=True)
        self._maybe_rekey(room)
        return True

    def group_voice(self, room: str, call_id: bytes):
        """Media keys for a call, from this epoch's MLS exporter (Rust)."""
        with self._lock:
            return self._need().group_voice(room.encode(), bytes(call_id))

    def group_voice_rekey(self, room: str, voice) -> bool:
        with self._lock:
            return bool(self._need().group_voice_rekey(room.encode(), voice))

    def member_identity(self, room: str, leaf: int) -> str:
        with self._lock:
            return bytes(self._need().member_at(room.encode(), int(leaf))).decode(
                errors="replace")

    def member_identities(self, room: str) -> List[str]:
        with self._lock:
            return [bytes(m).decode(errors="replace")
                    for m in self._need().members(room.encode())]

    #: MLS ciphersuite code points (docs/MLS_SECURITY_HARDENING.md §2).
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
        # Device report (2026-10-16): a password-protected group's invitee
        # could not enter its room ("not_authorized"). The password goes the
        # same way as the invitation: inside the OTRv4+ session.
        try:
            password = str(self.room_password_source(room) or "")
        except Exception:
            password = ""
        if password:
            self._send_private(peer, "%sROOMPW:%s|%s" % (
                SIGNAL_PREFIX, room, _b64e(password.encode("utf-8"))))
        self._emit(GroupChanged(peer=room, change="invite_sent", detail=peer))

    #: Where `invite` reads a room's password; set by the app (the
    #: transport remembers the passwords of rooms it entered, in memory).
    room_password_source: Callable[[str], str] = staticmethod(lambda _room: "")

    def invite_password(self, room: str) -> str:
        """The password the inviter sent for [room], or ""."""
        with self._lock:
            inv = self._invites.get(room)
            return inv.password if inv is not None else ""

    def _on_room_password(self, peer: str, arg: str) -> None:
        room, _, b64 = arg.partition("|")
        try:
            password = _b64d(b64).decode("utf-8")
        except (ValueError, binascii.Error, UnicodeDecodeError):
            self.stats.malformed += 1
            return
        with self._lock:
            inv = self._invites.get(room)
            # Only from the member who invited us to that room.
            if inv is None or inv.peer != peer or len(password) > 256:
                return
            inv.password = password

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
        # Said at once (device report, 2026-10-16): the room was shown as an
        # ordinary, unencrypted room until the Welcome arrived. "joining"
        # marks it as a secure group being set up; "joined" follows.
        self._emit(GroupChanged(peer=room, change="joining"))

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
            if self._awaiting_welcome.pop(room, None) is not None:
                self._emit(GroupChanged(peer=room, change="join_expired"))
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
            elif kind == "JOINED":
                self._on_joined(peer, arg)
            elif kind == "DECLINE":
                self._on_decline(peer, arg)
            elif kind == "FP":
                self._on_fingerprint(peer, arg, verified)
            elif kind == "ROOMPW":
                self._on_room_password(peer, arg)
            elif kind == "DELETED":
                self._on_deleted(peer, arg)
            else:
                self.stats.malformed += 1
        except GroupError as exc:
            self._emit(GroupChanged(peer=arg.partition("|")[0][:MAX_ROOM_LEN],
                                    change="refused", detail=exc.code))

    # -- verifying members (for group calls) -------------------------------
    #
    # A member is "verified" in a group when we hold their group key as they
    # sent it to us over an SMP-verified OTRv4+ session. That used to happen
    # only between inviter and invitee, at invitation time: SMP done later,
    # or with any other member, never reached the group, so a call (verified
    # members only) was impossible for most pairs (owner question,
    # 2026-10-10). Now each side sends its group key for every group the two
    # share, over their 1:1 session, when SMP between them succeeds, or on
    # `verify_members`; the key must match the one the group holds for them.

    def share_fingerprint(self, peer: str) -> List[str]:
        """Send our group key, for every group `peer` and we are both in,
        over our OTRv4+ session with them. Returns those rooms."""
        peer = str(peer or "").strip().split("/", 1)[0].lower()
        with self._lock:
            client = self._client
            if client is None or self._wiped:
                return []
            shared = []
            for g in client.group_ids():
                room = bytes(g).decode(errors="replace")
                try:
                    idents = [bytes(m).decode(errors="replace")
                              for m in client.members(g)]
                except Exception:
                    continue
                if peer in idents and peer != self._account:
                    shared.append((room, bytes(client.own_fingerprint(g)).hex()))
        sent = []
        for room, fp in shared:
            try:
                self._send_private(peer, "%sFP:%s|%s" % (SIGNAL_PREFIX, room, fp))
                sent.append(room)
            except GroupError:
                break                       # no OTRv4+ session: nothing goes
        return sent

    def on_peer_verified(self, peer: str) -> None:
        """SMP with `peer` succeeded: a key of theirs we already hold (from
        their invitation) counts as verified now, and we send ours."""
        peer = str(peer or "").strip().split("/", 1)[0].lower()
        changed = []
        with self._lock:
            client = self._client
            if client is None or self._wiped:
                return
            for room, book in self._bound.items():
                known = book.get(peer)
                if not known or known[1]:
                    continue
                try:
                    now = bytes(client.member_fingerprint(room.encode(), peer.encode())).hex()
                except ValueError:
                    continue
                if now == known[0]:
                    book[peer] = (known[0], True)
                    changed.append(room)
            if changed:
                self.save()
        for room in changed:
            self._emit(GroupChanged(peer=room, change="member_verified", detail=peer))
        self.share_fingerprint(peer)

    def verify_members(self, room: str) -> Dict[str, str]:
        """Send our key for `room` to each member over OTRv4+. Returns
        member -> "verified" (already) / "sent" / "no_session"."""
        out: Dict[str, str] = {}
        for m in self.members(room):
            if m["me"]:
                continue
            if m["verified"]:
                out[m["jid"]] = "verified"
            elif room in self.share_fingerprint(m["jid"]):
                out[m["jid"]] = "sent"
            else:
                out[m["jid"]] = "no_session"
        return out

    def _on_fingerprint(self, peer: str, arg: str, verified: bool) -> None:
        room, _, fp = arg.partition("|")
        if not _room_ok(room) or not _FP_RE.match(fp):
            self.stats.malformed += 1
            return
        with self._lock:
            client = self._need()
            if not client.has_group(room.encode()):
                return                      # not ours (or not yet): ignored
            try:
                held = bytes(client.member_fingerprint(room.encode(), peer.encode())).hex()
            except ValueError:
                raise GroupError("not_a_member")
            if held != fp:
                # The group holds another key for them than the one they sent
                # over OTRv4+: never bound. (A rekey in flight resolves itself;
                # they send again on their next verification.)
                raise GroupError("member_fingerprint_mismatch")
            before = self._bound.get(room, {}).get(peer)
            self._bound.setdefault(room, {})[peer] = (fp, bool(verified))
            if before != (fp, bool(verified)):
                self.save()
            new = before != (fp, bool(verified))
        if new:
            self._emit(GroupChanged(peer=room,
                                    change="member_verified" if verified else "member_bound",
                                    detail=peer))

    def _on_invite(self, peer: str, arg: str, verified: bool) -> None:
        room, _, fp = arg.partition("|")
        if not _room_ok(room) or not _FP_RE.match(fp):
            self.stats.malformed += 1
            return
        with self._lock:
            self._need()
            self._expire()
            # Already a member here. It used to be dropped without a word, so
            # the inviter waited and nothing showed (device test,
            # 2026-10-05): a member who invites us again sees us as gone --
            # our copy is behind, or they never saw our last change. Shown,
            # and accepting replaces our copy of the group.
            rejoin = self.is_secure(room)
            if room not in self._invites and len(self._invites) >= MAX_PENDING_INVITES:
                raise GroupError("too_many_invites")
            self._invites[room] = _Invite(peer=peer, fingerprint=fp, at=self._clock(),
                                          rejoin=rejoin)
            if not rejoin:
                self._bound.setdefault(room, {})[peer] = (fp, verified)
        if rejoin:
            self._emit(GroupChanged(peer=room, change="reinvited", detail=peer))
        self._emit(GroupInvite(peer=peer, room=room, verified=verified))

    def _on_deleted(self, peer: str, room: str) -> None:
        """The group's creator deleted it and says so over our OTRv4+
        session (GROUP_DELETED_SIGNAL): for a member who was not in the room
        when the removal and the room's destroy went by (offline, or
        reconnecting), so nothing else would ever tell them. Only from the
        creator -- the member at the tree's first leaf -- or from whoever
        removed us by commit; anyone else is refused."""
        room = str(room or "").strip().lower()[:MAX_ROOM_LEN]
        if not room:
            raise GroupError("malformed")
        peer = str(peer or "").split("/", 1)[0].lower()
        with self._lock:
            client = self._client
            held = client is not None and client.has_group(room.encode())
        if held:
            if peer != self.coordinator(room):
                raise GroupError("not_the_creator")
            self.on_room_destroyed(room)            # emits "deleted"
            return
        if self._removed_by.get(room) == peer:
            # Removed already (the commit came through); the room goes
            # from the list too.
            self._removed_by.pop(room, None)
            self._emit(GroupChanged(peer=room, change="deleted"))
            return
        raise GroupError("not_a_group")

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
            if not self._kp_names(client, kp, peer):
                # A KeyPackage naming someone other than the JID whose
                # authenticated session delivered it: never added (it would
                # also have removed that person's real leaf).
                self._outgoing.pop((room, peer), None)
                raise GroupError("key_package_identity")
            if client.has_pending_commit(room.encode()):
                # One of our commits (a rekey, another add) is out: add them
                # once it settles, rather than refuse an invitee who did
                # everything right.
                queued = self._queued_kps.setdefault(room, [])
                if len(queued) < MAX_PENDING_INVITES:
                    queued.append((peer, kp, verified))
                return
            try:
                commit = bytes(client.add_members(room.encode(), [kp],
                                                  identities=[peer.encode()]))
            except ValueError as exc:
                raise GroupError("add_refused", str(exc)[:80])
            self._outgoing.pop((room, peer), None)
            self._welcome_for.setdefault(room, []).append(peer)
            # Bound when the commit lands, from the group's own record of the
            # leaf this KeyPackage made -- see `_on_commit`.
            self._pending_binding.setdefault(room, []).append((peer, verified))
            self.save()
        self._post_commit(room, commit)

    @staticmethod
    def _kp_names(client, kp: bytes, peer: str) -> bool:
        """Whether KeyPackage [kp] names [peer] (ASCII case aside). Rust
        checks again when adding (`add_members(identities=...)`)."""
        reader = getattr(type(client), "key_package_identity", None)
        if reader is None:
            return True                     # older core: Rust's own check decides
        try:
            who = bytes(reader(kp)).decode("utf-8", errors="strict")
        except Exception:
            return False
        return who.lower() == peer.lower() and bool(peer)

    def _add_queued(self, room: str) -> None:
        """Add the invitees whose KeyPackages waited for our commit."""
        with self._lock:
            queued = self._queued_kps.pop(room, [])
            client = self._client
            if not queued or client is None or self._wiped:
                return
            try:
                commit = bytes(client.add_members(room.encode(),
                                                  [kp for _p, kp, _v in queued],
                                                  identities=[p.encode() for p, _k, _v in queued]))
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
            if (self._awaiting_welcome.get(room) != peer
                    and client.has_group(room.encode())):
                # A Welcome sent again after we had joined: say so once more.
                ack = True
            elif self._awaiting_welcome.get(room) != peer:
                raise GroupError("unsolicited_welcome")
            else:
                ack = False
        if ack:
            self._send_joined(peer, room)
            return
        with self._lock:
            client = self._need()
            inv = self._invites.get(room)
            try:
                welcome = _b64d(b64)
            except (ValueError, binascii.Error):
                raise GroupError("malformed")
            if inv is not None and inv.rejoin and client.has_group(room.encode()):
                # Invited back and accepted: our old copy of the group goes,
                # the Welcome brings the current one.
                client.forget_group(room.encode())
                for book in (self._syncing, self._held, self._unconfirmed,
                             self._queued_kps):
                    book.pop(room, None)
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
        self._send_joined(peer, room)
        self._emit(GroupChanged(peer=room, change="joined", epoch=epoch))

    def _send_joined(self, peer: str, room: str) -> None:
        try:
            self._send_private(peer, "%sJOINED:%s" % (SIGNAL_PREFIX, room))
        except Exception:
            pass                    # the inviter sends the Welcome again

    def _on_joined(self, peer: str, room: str) -> None:
        with self._lock:
            had = self._welcome_out.pop((room, peer), None)
            if had is not None:
                self.save()

    def resend_welcomes(self, force: bool = False) -> int:
        """Send again every Welcome not yet confirmed (JOINED). Called on a
        reconnect (force) and from `maintain`. Returns how many went."""
        now = self._clock()
        due = []
        with self._lock:
            for key, entry in list(self._welcome_out.items()):
                body, first, sent = entry
                if now - first > WELCOME_TTL or sent >= WELCOME_MAX_SENDS:
                    self._welcome_out.pop(key, None)
                    self._emit(ErrorOccurred(peer=key[1], code="group_welcome_unconfirmed"))
                    continue
                if force or now - entry[1] >= WELCOME_RESEND_EVERY * sent:
                    entry[2] = sent + 1
                    due.append((key[1], body))
        for peer, body in due:
            try:
                self._send_private(peer, body)
            except Exception:
                pass
        return len(due)

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

    #: After the room is joined again, how long its history replay (the
    #: commits made while we were away) is given to be applied before held
    #: messages go.
    SYNC_SETTLE_SECONDS = 3.0
    MAX_HELD = 100

    def mark_syncing(self, room: Optional[str] = None) -> None:
        """We are out of `room` (every room, by default) until
        `on_room_rejoined`: messages typed meanwhile are held."""
        with self._lock:
            rooms = [room] if room else self._room_ids()
            fresh = [r for r in rooms if r not in self._syncing]
            for r in rooms:
                self._syncing[r] = 0.0
        for r in fresh:
            self._emit(GroupChanged(peer=r, change="syncing"))

    def is_syncing(self, room: str) -> bool:
        self._sync_check(room)
        with self._lock:
            return room in self._syncing

    def _room_ids(self) -> List[str]:
        client = self._client
        if client is None:
            return []
        try:
            return [bytes(g).decode() for g in client.group_ids()]
        except Exception:
            return list(self._bound)

    def _sync_check(self, room: str) -> None:
        """Send what was held once the room's history has had its time."""
        with self._lock:
            until = self._syncing.get(room)
            if until is None or until == 0.0 or self._clock() < until:
                return
            self._syncing.pop(room, None)
            held = self._held.pop(room, [])
        sent = 0
        for text in held:
            try:
                if self.send(room, text) == "sent":
                    sent += 1
            except GroupError:
                self._emit(ErrorOccurred(peer=room, code="group_send_failed"))
        self._emit(GroupChanged(peer=room, change="synced",
                                detail=str(sent) if sent else ""))
        if sent:
            self._emit(QueuedSent(peer=room, count=sent, encrypted=True))

    def on_room_rejoined(self, room: str) -> None:
        """We are in `room` again after a reconnect: a commit lost with the
        old stream goes out again (the room's history replay may also bring
        it back, which settles it first), and held messages go once the
        history has been applied."""
        self._settled_from = self._clock()
        with self._lock:
            settle = self.SYNC_SETTLE_SECONDS
            if room in self._syncing:
                self._syncing[room] = self._clock() + max(settle, 1e-9)
        self.resend_pending_commit(room, "rejoined")
        self.resend_welcomes(force=True)
        if settle <= 0:
            self._sync_check(room)
            return
        old = self._sync_timers.pop(room, None)
        if old is not None:
            old.cancel()
        timer = threading.Timer(settle + 0.05, self._sync_check, args=(room,))
        timer.daemon = True
        self._sync_timers[room] = timer
        timer.start()

    def send(self, room: str, text: str) -> str:
        """Encrypt and post: "sent". While the group is not in sync (its room
        not joined again yet, or its history not applied): held, "held".
        Raises; never falls back to plaintext."""
        if not text:
            return "sent"
        self._sync_check(room)
        with self._lock:
            client = self._need()
            if not client.has_group(room.encode()):
                raise GroupError("not_a_group")
            # Out of sync, or earlier lines still waiting (order is kept).
            if room in self._syncing or self._held.get(room):
                held = self._held.setdefault(room, [])
                if len(held) >= self.MAX_HELD:
                    raise GroupError("too_many_held")
                held.append(text)
                first = len(held) == 1
            else:
                first = None
        if first is not None:
            if first:
                self._emit(GroupChanged(peer=room, change="held"))
            return "held"
        with self._lock:
            client = self._need()
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
                # A change of ours (a member added or removed, a rekey) is on
                # its way through the room; MLS sends nothing until it lands.
                # The line waits and goes then -- it was "not sent" (device
                # test, 2026-10-10).
                with self._lock:
                    held = self._held.setdefault(room, [])
                    if len(held) >= self.MAX_HELD:
                        raise GroupError("too_many_held")
                    held.append(text)
                    first = len(held) == 1
                if first:
                    self._emit(GroupChanged(peer=room, change="held_change"))
                self.resend_pending_commit(room, "send_blocked")
                return "held"
            raise err
        self._post(room, ct)
        self._maybe_rekey(room)
        return "sent"

    def _flush_held(self, room: str) -> None:
        """Send what waited for a group change to land (not while syncing:
        `_sync_check` does that)."""
        with self._lock:
            client = self._client
            if (room in self._syncing or not self._held.get(room) or client is None
                    or client.has_pending_commit(room.encode())):
                return
            held = self._held.pop(room, [])
        sent = 0
        for i, text in enumerate(held):
            try:
                outcome = self.send(room, text)
            except GroupError:
                self._emit(ErrorOccurred(peer=room, code="group_send_failed"))
                continue
            if outcome == "held":
                # Another change got in first: the rest wait behind it.
                with self._lock:
                    self._held.setdefault(room, []).extend(held[i + 1:])
                break
            sent += 1
        if sent:
            self._emit(QueuedSent(peer=room, count=sent, encrypted=True))

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
            if not due or client is None or self._wiped or room in self._syncing:
                # Not while out of sync: a commit on an old epoch is lost.
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
        self.resend_welcomes()
        done = []
        for room in self.rooms():
            self._sync_check(room)
            if room in self._syncing:
                continue                    # no commit from an old epoch
            self._flush_held(room)
            self._send_ack(room)
            if self._publish_due(room):
                done.append("published:" + room)
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
        self.remove_many(room, [member])

    def remove_many(self, room: str, members: List[str]) -> None:
        """Remove members, in one commit. The creator's (owner, 2026-10-25:
        "excluded and kicked from group by creator"); anyone else is refused
        here, before anything is sent."""
        members = [m for m in dict.fromkeys(members) if m and m != self._account]
        if not members:
            return
        with self._lock:
            client = self._need()
            if self.coordinator(room) != self._account:
                raise GroupError("only_the_creator_removes")
            try:
                commit = bytes(client.remove_members(
                    room.encode(), [m.encode() for m in members]))
            except ValueError as exc:
                raise GroupError("remove_refused", str(exc)[:80])
            book = self._failed.get(room, {})
            for m in members:
                book.pop(m, None)
            self.save()
        self._post_commit(room, commit)

    def is_creator(self, room: str) -> bool:
        """Whether this account is the group's creator (`coordinator`)."""
        return bool(self._account) and self.coordinator(room) == self._account

    def announce_deleted(self, room: str) -> bool:
        """The creator is about to delete [room]: say so in the group
        (GROUP_DELETED_MARK), before the removal, so every member in the room
        ends its copy at once. Creator only. Whether it went."""
        if not self.is_creator(room):
            return False
        with self._lock:
            client = self._client
            if client is None or self._wiped or not client.has_group(room.encode()):
                return False
            try:
                wire = bytes(client.encrypt(room.encode(), GROUP_DELETED_MARK.encode()))
            except ValueError:
                return False                       # a commit of ours is pending
        self._post(room, wire)
        _TRACE.record("groups", "deleted_announced", "info")
        return True

    def remove_everyone(self, room: str) -> List[str]:
        """Every other member removed, in one commit: the first step of the
        creator deleting the group (owner, 2026-10-26: "must remove everyone
        from group before deletion"). Each member's copy then ends by MLS --
        its keys open nothing posted afterwards -- not only by the room
        going away. Creator only (`remove_many`). Returns who."""
        others = sorted(m["jid"] for m in self.members(room) if m["jid"] != self._account)
        self.remove_many(room, others)
        return others

    def commit_confirmed(self, room: str) -> bool:
        """No commit of ours for [room] is still waiting to come back from
        the room (`_post_commit`)."""
        with self._lock:
            return room not in self._unconfirmed

    def remove_failed(self, room: str) -> List[str]:
        """Remove everyone whose verification failed, in one commit."""
        failed = sorted(m["jid"] for m in self.members(room) if m.get("failed"))
        self.remove_many(room, failed)
        return failed

    def rekey(self, room: str) -> None:
        """A fresh leaf key for us (post-compromise security)."""
        with self._lock:
            commit = bytes(self._need().self_update(room.encode()))
            self.save()
        self._post_commit(room, commit)

    def make_deniable(self, room: str) -> str:
        """"Publish Group Keys" (F4, epochal signatures): rotate our signing
        key now, and publish the retired keys -- this one and any earlier --
        as soon as every other member has acknowledged the rotation
        (`keys_waiting`); a member still in the old epoch would otherwise
        accept a message signed with a published key. After that, any member
        could have produced what those keys signed. Returns "rotating".
        Refused while a change of ours is still on its way."""
        with self._lock:
            client = self._need()
            if not client.has_group(room.encode()):
                raise GroupError("not_a_group")
            if client.has_pending_commit(room.encode()) or room in self._unconfirmed:
                raise GroupError("commit_pending")
            self._reveal_now.add(room)
            self._history_due[room] = int(time.time() * 1000)
        try:
            self.rekey(room)
        except ValueError:
            with self._lock:
                self._reveal_now.discard(room)
                self._history_due.pop(room, None)
            raise GroupError("commit_pending")
        return "rotating"

    def publish_retired(self, room: str) -> int:
        """Post our retired signing keys for [room] to the room (F4): one
        message per few keys, each built and encrypted in Rust -- the private
        keys never reach Python. Returns how many messages went."""
        sent = 0
        while sent < 8:
            with self._lock:
                client = self._client
                if client is None or self._wiped or not client.has_group(room.encode()):
                    return sent
                try:
                    wire = client.reveal_retired(room.encode())
                except ValueError:
                    return sent                       # a commit of ours is pending
                if wire is None:
                    # Nothing more that every member is past. Keys still
                    # waiting keep their time and their request.
                    if not int(client.retired_count(room.encode())):
                        self._retired_at.pop(room, None)
                        self._reveal_now.discard(room)
                    if sent:
                        self.save()
                    break
            self._post(room, bytes(wire))
            sent += 1
        if sent:
            # What a device test reads (PHYSICAL_TEST_PLAN §8): a count only.
            _TRACE.record("groups", "keys_published_ours", "info", messages=sent)
            self._emit(GroupChanged(peer=room, change="keys_published_ours"))
        self._mark_history(room)
        return sent

    def _mark_history(self, room: str) -> None:
        """Publish Group Keys pressed and every key of ours out: tell the
        members (GROUP_KEYS_MARK), and remove what came before here too."""
        with self._lock:
            due = self._history_due.get(room)
            client = self._client
            if due is None or client is None or self._wiped:
                return
            if not client.has_group(room.encode()):
                self._history_due.pop(room, None)
                return
            if int(client.retired_count(room.encode())):
                return                          # some still wait for members
            try:
                wire = bytes(client.encrypt(room.encode(), GROUP_KEYS_MARK.encode()))
            except ValueError:
                return                          # a commit of ours is pending
            self._history_due.pop(room, None)
        self._post(room, wire)
        self._emit(KeysPublished(peer=room, before_ms=due, group=True, by=""))

    def keys_waiting(self, room: str) -> List[str]:
        """Who our retired keys for [room] wait for (F4): members not yet
        known to be past the rotation. Empty when nothing waits."""
        with self._lock:
            client = self._client
            if client is None or self._wiped or not client.has_group(room.encode()):
                return []
            return [bytes(w).decode(errors="replace") for w in client.awaiting(room.encode())]

    def _send_ack(self, room: str) -> None:
        """Post an owed acknowledgement of another member's rotation (F4).
        Kept owed while a commit of ours is pending; any later epoch is
        past the rotation too."""
        with self._lock:
            client = self._client
            if room not in self._ack_owed or client is None or self._wiped:
                return
            if not client.has_group(room.encode()):
                self._ack_owed.discard(room)
                return
            try:
                wire = bytes(client.acknowledge(room.encode()))
            except ValueError:
                return                            # a commit of ours is pending
            self._ack_owed.discard(room)
        self._post(room, wire)

    def _after_ack(self, room: str) -> None:
        """A member acknowledged: keys may now be publishable."""
        if room in self._reveal_now:
            self.publish_retired(room)
        else:
            self._publish_due(room)

    def _publish_due(self, room: str) -> bool:
        """`maintain`'s part of F4: publish once REVEAL_DELAY_SECONDS have
        passed since a rekey of ours retired a key."""
        with self._lock:
            client = self._client
            if client is None or self._wiped:
                return False
            try:
                waiting = int(client.retired_count(room.encode()))
            except Exception:
                return False
            if not waiting:
                self._retired_at.pop(room, None)
                return False
            since = self._retired_at.setdefault(room, self._clock())
            if self._clock() - since < self.REVEAL_DELAY_SECONDS:
                return False
        return self.publish_retired(room) > 0

    def leave(self, room: str) -> None:
        """Forget the group and every secret for it, here.

        MLS has no self-removal a member can complete alone: the others still
        list us until one of them commits our removal. What this guarantees
        is local -- we can no longer read the group."""
        with self._lock:
            self._need().forget_group(room.encode())
            self._bound.pop(room, None)
            self._failed.pop(room, None)
            self._entry_denied.pop(room, None)
            self.save()
        self._emit(GroupChanged(peer=room, change="left"))

    def on_room_destroyed(self, room: str) -> bool:
        """The group's room was deleted (by its owner, XEP-0045 destroy; or
        found gone when we came back). The group ends here: its keys are
        forgotten, as on leaving. False if `room` is no secure group of ours."""
        with self._lock:
            client = self._client
            if client is None or self._wiped or not client.has_group(room.encode()):
                return False
            client.forget_group(room.encode())
            for book in (self._bound, self._failed, self._entry_denied, self._syncing, self._held, self._unconfirmed,
                         self._queued_kps, self._since_rekey, self._activity, self._retired_at):
                book.pop(room, None)
            self.save()
        self._emit(GroupChanged(peer=room, change="deleted"))
        return True

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
            control = None
            ended_by_creator = False
            vcontrol = None
            fcontrol = None
            if kind == "application":
                sender = bytes(ev["sender"]).decode(errors="replace")
                text = bytes(ev["plaintext"]).decode("utf-8", errors="replace")
                fp = bytes(client.member_fingerprint(room.encode(), bytes(ev["sender"]))).hex()
                known = self._bound.get(room, {}).get(sender)
                verified = bool(known and known[0] == fp and known[1])
            if kind == "application" and text == GROUP_DELETED_MARK:
                # The creator is deleting the group: our copy ends now, said
                # in the group itself before the removal (owner, 2026-10-27).
                # Only from the creator; MLS authenticated the sender.
                ended_by_creator = sender == self.coordinator(room)
                if not ended_by_creator:
                    self.stats.malformed += 1
                event = None
            elif kind == "application" and text == GROUP_KEYS_MARK:
                # A member pressed Publish Group Keys and its keys are out:
                # what we have of the group until now goes. Never shown.
                event = KeysPublished(peer=room, before_ms=int(time.time() * 1000),
                                      group=True, by=sender)
            elif kind == "application" and text.startswith("\x00OTRv4GC1:"):
                # A call control message: to the call manager, never shown.
                control = (sender, verified, text[len("\x00OTRv4GC1:"):])
                event = None
            elif kind == "application" and text.startswith("\x00OTRv4GV1:"):
                # Group verification: to its handler, never shown.
                vcontrol = (sender, verified, text[len("\x00OTRv4GV1:"):])
                event = None
            elif kind == "application" and text.startswith("\x00OTRv4GF1:"):
                # A group file's offer or piece: to its handler, never shown.
                fcontrol = (sender, verified, text[len("\x00OTRv4GF1:"):])
                event = None
            elif kind == "application" and text.startswith(_actions.GROUP_PREFIX):
                # A typed message with its id, or a reply / correction /
                # deletion / reaction: all inside MLS.
                event = self._group_message(room, nick, sender, verified, timestamp, text)
            elif kind == "application":
                self.stats.shown += 1
                event = RoomMessageReceived(peer=room, sender=nick, body=text,
                                            timestamp=timestamp, encrypted=True,
                                            sender_identity=sender, verified=verified)
            elif kind == "commit":
                event = self._on_commit(room, ev)
                settled = bool(ev.get("ours") or ev.get("dropped_ours"))
                rekeyed = [bytes(who).decode(errors="replace")
                           for who, _old, _new in ev.get("rekeyed") or []]
                if ev.get("ours") and self._account in rekeyed:
                    self._retired_at.setdefault(room, self._clock())
                if not ev.get("removed_us") and any(w != self._account for w in rekeyed):
                    # Another member rotated: tell them we are past it (F4).
                    self._ack_owed.add(room)
            elif kind == "keys_revealed":
                # A member published retired signing keys (F4). Checked in
                # Rust; only fingerprints come out. Not shown: it happens
                # after every rekey.
                published = len(ev.get("fingerprints") or [])
                event = (GroupChanged(peer=room, change="keys_published",
                                      detail=bytes(ev["sender"]).decode(errors="replace"))
                         if published else None)
            elif kind == "acknowledged":
                event = None                      # recorded in Rust; never shown
            else:
                event = None
        if ended_by_creator:
            _TRACE.record("groups", "deleted_by_creator", "info")
            self.on_room_destroyed(room)            # emits "deleted"
            return True
        if event is not None:
            self._emit(event)
        if kind == "commit" and settled and self._queued_kps.get(room):
            self._add_queued(room)
        if kind == "commit":
            self._flush_held(room)
        if kind == "commit":
            self._send_ack(room)
        if kind == "commit" and ev.get("ours") and room in self._reveal_now:
            self.publish_retired(room)
        if kind == "acknowledged" or (kind == "application" and not own):
            self._after_ack(room)
        if vcontrol is not None and self._verify_handler is not None:
            try:
                self._verify_handler(room, *vcontrol)
            except Exception:
                self._emit(ErrorOccurred(peer=room, code="verify_control_failed"))
        if fcontrol is not None and self._file_handler is not None:
            try:
                self._file_handler(room, *fcontrol)
            except Exception:
                self._emit(ErrorOccurred(peer=room, code="file_control_failed"))
        if control is not None and self._call_handler is not None:
            try:
                self._call_handler(room, *control)
            except Exception:
                self._emit(ErrorOccurred(peer=room, code="call_control_failed"))
        if kind == "commit" and self._epoch_listener is not None:
            try:
                self._epoch_listener(room)
            except Exception:
                self._emit(ErrorOccurred(peer=room, code="call_rekey_failed"))
        if kind == "commit":
            for listener in list(self._epoch_listeners):
                try:
                    listener(room)
                except Exception:
                    self._emit(ErrorOccurred(peer=room, code="epoch_listener_failed"))
        return True

    #: Per group, the message ids seen and who (MLS identity) wrote each.
    MAX_AUTHORS = 4000

    def _group_message(self, room: str, nick: str, sender: str, verified: bool,
                       timestamp: float, text: str):
        """One MLS-authenticated envelope (otrv4plus_actions) -> its event.

        [sender] is the identity MLS authenticated (the leaf's credential).
        A correction or deletion is passed on only when its target, if this
        session saw it, was written by that SAME identity; the UI checks
        again against what it stored. Malformed: dropped, never shown."""
        got = _actions.decode_group_message(text)
        if got is None or not sender:
            self.stats.malformed += 1
            return None
        meta, body = got
        authors = self._authors.setdefault(room, collections.OrderedDict())
        action = meta["action"]
        if action in ("edit", "retract"):
            author = authors.get(meta["target"])
            if author is not None and author.lower() != sender.lower():
                self.stats.wrong_author += 1
                return None
        if action:
            if action == "edit" and not body.strip():
                return None
            self.stats.shown += 1
            return MessageChanged(peer=room, action=action, target_id=meta["target"],
                                  body=body if action == "edit" else "",
                                  emojis=tuple(meta["emojis"]), outgoing=False,
                                  source="live", sender=nick, sender_identity=sender)
        if meta["id"] in authors:
            return None                       # the same message again
        authors[meta["id"]] = sender
        while len(authors) > self.MAX_AUTHORS:
            authors.popitem(last=False)
        if not body:
            return None
        self.stats.shown += 1
        return RoomMessageReceived(peer=room, sender=nick, body=body,
                                   timestamp=timestamp, encrypted=True,
                                   sender_identity=sender, verified=verified,
                                   message_id=meta["id"], reply_to=meta["reply"])

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
            self._removed_by[room] = committer.split("/", 1)[0].lower()
            inv = self._invites.get(room)
            if inv is not None and inv.rejoin and inv.accepted:
                # Invited back and accepted: the inviter's add replaces our
                # old leaf in the same commit (Rust add_members), so our OLD
                # copy sees itself removed -- that is the replacement, not
                # somebody removing us. The Welcome brings the new copy.
                # Bindings are kept: the other members' keys do not change,
                # so whom we verified stays verified (device test,
                # 2026-10-11: "you were removed" on a laptop nobody removed).
                self._queued_kps.pop(room, None)
                self.save()
                return GroupChanged(peer=room, change="replaced", epoch=epoch,
                                    detail=inv.peer)
            self._bound.pop(room, None)
            self._failed.pop(room, None)
            self._entry_denied.pop(room, None)
            self._activity.pop(room, None)
            self._queued_kps.pop(room, None)
            self.save()
            # A device test reads this (a deleted group still listed on a
            # member, 2026-10-27): the removal arrived, before or without the
            # room's destroy (`muc room_destroyed`).
            _TRACE.record("groups", "removed_us", "info", epoch=epoch)
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
            body = "%sWELCOME:%s|%s|%s" % (SIGNAL_PREFIX, room, _b64e(bytes(welcome)), own_fp)
            for peer in invitees:
                # Kept until the invitee says JOINED: a Welcome lost on the
                # way (a dropped connection, the peer briefly offline) is
                # sent again, instead of leaving them waiting for ever.
                self._welcome_out[(room, peer)] = [body, self._clock(), 1]
                try:
                    self._send_private(peer, body)
                except Exception:
                    self._emit(ErrorOccurred(peer=peer, code="group_welcome_send_failed"))
            self.save()
            return GroupChanged(peer=room, change="member_added", epoch=epoch)
        return GroupChanged(peer=room, change="epoch", epoch=epoch)
