# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Group voice calls in a secure (MLS) group: MLS_SECURITY_HARDENING.md §5, M5.

What this module decides, and where each guarantee comes from:

  * KEYS: from the group's MLS exporter, per epoch, per sender, inside Rust
    (`RustGroupVoice`, `Rust/mls/src/group_voice.rs`). AES-256-GCM frames,
    nonce = epoch || counter, a ratchet every 500 frames -- as 1:1 voice.
    Python never holds a media key.
  * ROTATION: every commit moves the call to the new epoch's keys; the
    member that started the call also forces a self-update every
    REKEY_SECONDS (120 s, as 1:1 voice) while the call is up. The commit
    landing in the room is the confirmation: every member that processed it
    is in the same epoch. The previous epoch's keys are kept GRACE_SECONDS
    for frames already in flight, then destroyed.
  * WHO IS IN THE CALL: only members we hold an SMP-verified binding for
    (the same rule as "verified" in the group). Control messages travel as
    MLS application messages, so they are encrypted, authenticated to a
    group member, and never shown as chat. A join from an unverified member
    is refused and reported; their frames are dropped, and nothing is sent
    to them.
  * TRANSPORT: I2P datagrams, a full mesh (each sends to each), so at most
    MAX_PARTICIPANTS. The transport is supplied by the caller
    (`send_datagram(destination, packet)`); this module never opens a
    socket, and never uses anything but the destinations members announced
    inside the group.

THE SAME STRUCTURE AS A 1:1 CALL (owner requirement, 2026-10-10):

  |                     | 1:1 call (voice.rs)        | group call (group_voice.rs) |
  |---------------------|----------------------------|-----------------------------|
  | frame cipher        | AES-256-GCM                | AES-256-GCM                 |
  | nonce               | epoch || counter, derived  | epoch || counter, derived   |
  | in-call ratchet     | every 500 frames (30 s)    | every 500 frames (30 s)     |
  | replay window       | 256 frames                 | 256 frames                  |
  | frame size          | padded to one fixed slot   | the same padding (pad_opus) |
  | fresh keys          | X448 + ML-KEM-1024 rekey,  | a new MLS epoch (its keys   |
  |                     | every 120 s                | reach each member by X448 + |
  |                     |                            | ML-KEM-1024 HPKE), forced   |
  |                     |                            | every 120 s by the caller   |
  | who may be in it    | an SMP-verified peer       | members SMP-verified in the |
  |                     |                            | group (group passphrase or  |
  |                     |                            | 1:1 SMP), nobody else       |
  | transport           | I2P datagrams              | I2P datagrams, full mesh    |

The only difference is where a fresh key comes from: a 1:1 call runs its own
hybrid exchange; a group call takes it from the group's epoch, which every
commit renews with the same hybrid KEM. Keys never leave Rust in either.

Not done here: audio capture, Opus, mixing (`mix` is a helper) and the call
screen -- those belong to each client.
"""
from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .events import ErrorOccurred, GroupChanged

__all__ = ["CALL_PREFIX", "GroupCalls", "mix"]

#: Prefix of a call control message inside the MLS plaintext. Starts with a
#: NUL so nothing a person types can collide with it.
CALL_PREFIX = "\x00OTRv4GC1:"
MAX_PARTICIPANTS = 5
REKEY_SECONDS = 120.0
GRACE_SECONDS = 2.0
#: An unanswered ring is forgotten after this long.
RING_SECONDS = 60.0
MAX_DEST_LEN = 1024
MAX_CONTROL_LEN = 2048


@dataclass
class _Call:
    room: str
    call_id: str                       # 32 hex characters
    starter: str                       # identity of who rang
    joined: bool = False
    rang_at: float = 0.0
    voice: Any = None                  # RustGroupVoice once joined
    #: identity -> I2P destination, verified participants only.
    peers: Dict[str, str] = field(default_factory=dict)
    last_rekey: float = 0.0
    drop_previous_at: float = 0.0


def mix(frames: List[bytes]) -> bytes:
    """Sum 16-bit little-endian PCM frames, clipped. Shorter frames are
    padded with silence."""
    if not frames:
        return b""
    import array
    n = max(len(f) for f in frames) // 2
    out = array.array("i", [0]) * n
    for f in frames:
        pcm = array.array("h")
        pcm.frombytes(f[: (len(f) // 2) * 2])
        for i, v in enumerate(pcm):
            out[i] += v
    clipped = array.array("h", (max(-32768, min(32767, v)) for v in out))
    return clipped.tobytes()


class GroupCalls:
    """Calls in this account's secure groups. One active call at a time.

    `groups` is the account's SecureGroups. `send_datagram(dest, packet)`
    sends one media packet over I2P. `local_destination()` is our datagram
    destination (public part). `on_audio(room, identity, frame)` receives
    decrypted frames. `emit` takes GroupChanged / ErrorOccurred events.
    """

    MAX_PARTICIPANTS = MAX_PARTICIPANTS
    REKEY_SECONDS = REKEY_SECONDS
    GRACE_SECONDS = GRACE_SECONDS

    def __init__(self, groups: Any, *,
                 send_datagram: Callable[[str, bytes], None],
                 local_destination: Callable[[], str],
                 on_audio: Callable[[str, str, bytes], None],
                 emit: Callable[[Any], None],
                 clock: Callable[[], float] = time.time):
        self._groups = groups
        self._send_datagram = send_datagram
        self._local_destination = local_destination
        self._on_audio = on_audio
        self._emit = emit
        self._clock = clock
        self._lock = threading.RLock()
        self._calls: Dict[str, _Call] = {}      # room -> call
        self._active: Optional[str] = None      # room of the joined call
        #: Paused: we stay in the call and hear it, but send no audio.
        self._paused = False
        groups.set_call_handler(self._on_control)
        groups.set_epoch_listener(self._on_epoch)

    # -- what the user does ---------------------------------------------------

    def start(self, room: str) -> str:
        """Ring the group. Returns the call id. We join at once."""
        with self._lock:
            if self._active is not None:
                raise ValueError("call_in_progress")
            verified = self._verified_members(room)
            if not verified:
                raise ValueError("no_verified_member")
            call_id = os.urandom(16).hex()
            call = _Call(room=room, call_id=call_id, starter=self._me(),
                         rang_at=self._clock())
            self._calls[room] = call
        self._control(room, {"t": "ring", "call": call_id})
        self.join(room)
        return call_id

    def join(self, room: str) -> None:
        with self._lock:
            call = self._calls.get(room)
            if call is None:
                raise ValueError("no_call")
            if self._active not in (None, room):
                raise ValueError("call_in_progress")
            if not call.joined:
                call.voice = self._groups.group_voice(room, bytes.fromhex(call.call_id))
                call.joined = True
                call.last_rekey = self._clock()
                self._active = room
        self._control(room, {"t": "join", "call": call.call_id,
                             "dest": self._local_destination()})
        self._emit(GroupChanged(peer=room, change="call_joined", detail=call.call_id[:8]))

    def hangup(self, room: str) -> None:
        with self._lock:
            call = self._calls.pop(room, None)
            if self._active == room:
                self._active = None
                self._paused = False
        if call is None:
            return
        if call.joined:
            try:
                self._control(room, {"t": "leave", "call": call.call_id})
            except Exception:
                pass
        if call.voice is not None:
            call.voice.zeroize()
        self._emit(GroupChanged(peer=room, change="call_ended", detail=call.call_id[:8]))

    def active(self) -> Optional[str]:
        """The room of the call we are in, if any."""
        with self._lock:
            return self._active

    def pause(self, on: Optional[bool] = None) -> bool:
        """Stop (or resume) sending our audio; we stay in the call and keep
        hearing it. `on` None toggles. Returns whether we are paused now."""
        with self._lock:
            room = self._active
            if room is None:
                raise ValueError("no_call")
            self._paused = (not self._paused) if on is None else bool(on)
            paused = self._paused
        self._emit(GroupChanged(peer=room, change="call_paused" if paused else "call_resumed"))
        return paused

    @property
    def paused(self) -> bool:
        return self._paused

    def participants(self, room: str) -> List[str]:
        with self._lock:
            call = self._calls.get(room)
            return sorted(call.peers) if call else []

    def ringing(self) -> List[Dict[str, str]]:
        with self._lock:
            now = self._clock()
            return [{"room": c.room, "from": c.starter, "call": c.call_id}
                    for c in self._calls.values()
                    if not c.joined and now - c.rang_at < RING_SECONDS]

    # -- media ------------------------------------------------------------------

    def send_audio(self, frame: bytes) -> int:
        """Seal one frame and send it to every participant. Returns how many."""
        with self._lock:
            room = self._active
            call = self._calls.get(room) if room else None
            if call is None or call.voice is None or self._paused:
                return 0
            packet = bytes(call.voice.seal(frame))
            dests = list(call.peers.values())
        for dest in dests:
            try:
                self._send_datagram(dest, packet)
            except Exception:
                pass
        return len(dests)

    def on_datagram(self, packet: bytes) -> bool:
        """One media packet from the network. True if it was played."""
        with self._lock:
            room = self._active
            call = self._calls.get(room) if room else None
            if call is None or call.voice is None:
                return False
            try:
                sender, frame = call.voice.open(packet)
            except ValueError:
                return False
            try:
                who = self._groups.member_identity(room, int(sender))
            except Exception:
                return False
            if who not in call.peers:
                return False                 # not a verified participant
        self._on_audio(room, who, bytes(frame))
        return True

    # -- time -------------------------------------------------------------------

    def tick(self) -> None:
        """Call about once a second: drops a previous epoch after the grace
        period, and has the starter force a rekey every REKEY_SECONDS."""
        with self._lock:
            room = self._active
            call = self._calls.get(room) if room else None
            if call is None or call.voice is None:
                return
            now = self._clock()
            if call.drop_previous_at and now >= call.drop_previous_at:
                call.voice.drop_previous()
                call.drop_previous_at = 0.0
            due = (call.starter == self._me()
                   and now - call.last_rekey >= self.REKEY_SECONDS)
            if due:
                call.last_rekey = now
        if due:
            try:
                self._groups.rekey(room)
            except Exception:
                self._emit(ErrorOccurred(peer=room, code="call_rekey_failed"))

    # -- from the group ---------------------------------------------------------

    def _on_epoch(self, room: str) -> None:
        with self._lock:
            call = self._calls.get(room)
            if call is None or call.voice is None:
                return
            try:
                moved = self._groups.group_voice_rekey(room, call.voice)
            except Exception:
                self._emit(ErrorOccurred(peer=room, code="call_rekey_failed"))
                return
            if moved:
                call.last_rekey = self._clock()
                call.drop_previous_at = self._clock() + self.GRACE_SECONDS
            # Somebody may have been removed: they leave the call too.
            members = set(self._groups.member_identities(room))
            for who in [p for p in call.peers if p not in members]:
                call.peers.pop(who, None)

    def _on_control(self, room: str, sender: str, verified: bool, payload: str) -> None:
        if len(payload) > MAX_CONTROL_LEN:
            return
        try:
            msg = json.loads(payload)
        except ValueError:
            return
        if not isinstance(msg, dict):
            return
        kind, call_id = msg.get("t"), msg.get("call")
        if not isinstance(call_id, str) or len(call_id) != 32 or not all(
                c in "0123456789abcdef" for c in call_id):
            return
        if sender == self._me():
            return
        with self._lock:
            call = self._calls.get(room)
            if kind == "ring":
                # A new call replaces an old one we never joined: the record
                # of an unanswered (or ended) ring used to stay forever, and
                # every later ring in that room was ignored.
                if call is None or (not call.joined and call.call_id != call_id):
                    self._calls[room] = _Call(room=room, call_id=call_id, starter=sender,
                                              rang_at=self._clock())
                    ring = True
                else:
                    ring = False
            elif call is None or call.call_id != call_id:
                return
        if kind == "ring":
            if ring:
                self._emit(GroupChanged(peer=room, change="call_ringing",
                                        detail=sender[:200]))
            return
        if kind == "join":
            dest = msg.get("dest")
            if not isinstance(dest, str) or not dest or len(dest) > MAX_DEST_LEN:
                return
            if not verified:
                self._emit(GroupChanged(peer=room, change="call_refused_unverified",
                                        detail=sender[:200]))
                return
            with self._lock:
                if sender not in call.peers and len(call.peers) + 1 >= self.MAX_PARTICIPANTS:
                    full = True
                else:
                    call.peers[sender] = dest
                    full = False
                joined = call.joined
            if full:
                self._emit(ErrorOccurred(peer=room, code="call_full"))
                return
            self._emit(GroupChanged(peer=room, change="call_participant", detail=sender[:200]))
            if joined:
                # They may have missed our join: say it again, once per joiner.
                self._control(room, {"t": "here", "call": call_id,
                                     "dest": self._local_destination()})
        elif kind == "here":
            dest = msg.get("dest")
            if verified and isinstance(dest, str) and 0 < len(dest) <= MAX_DEST_LEN:
                with self._lock:
                    if sender in call.peers or len(call.peers) + 1 < self.MAX_PARTICIPANTS:
                        call.peers[sender] = dest
        elif kind == "leave":
            with self._lock:
                call.peers.pop(sender, None)
                # The caller hung up before we answered: stop ringing.
                if not call.joined and sender == call.starter:
                    self._calls.pop(room, None)
            self._emit(GroupChanged(peer=room, change="call_participant_left",
                                    detail=sender[:200]))

    # -- inside -------------------------------------------------------------------

    def _me(self) -> str:
        return self._groups.account

    def _verified_members(self, room: str) -> List[str]:
        return [m["jid"] for m in self._groups.members(room)
                if m["verified"] and not m["me"]]

    def _control(self, room: str, msg: Dict[str, Any]) -> None:
        self._groups.send_control(room, CALL_PREFIX + json.dumps(msg, separators=(",", ":")))
