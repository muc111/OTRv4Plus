# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Files in a secure (MLS) group, the same in the app and in Termux.

WHERE EACH GUARANTEE COMES FROM
===============================
  * ENCRYPTION AND AUTHENTICITY: every offer and every piece is an MLS
    application message (hybrid suite: X448 + ML-KEM-1024, Ed448 + ML-DSA-87),
    exactly like a chat line. Only the group's members can read it, each
    piece is signed by the member who sent it, and the server sees ciphertext
    and sizes. No new cryptography: this module only cuts a file into
    pieces, puts it back together and checks it.
  * INTEGRITY: the offer carries the file's SHA-256 and size; a received file
    is kept only if both match, read back from disk. A piece of the wrong
    length, a piece from anyone but the offer's sender, or a piece of an
    offer we did not accept is dropped.
  * WHO: a file is sent only when EVERY other member is verified (by the
    group passphrase or 1:1 SMP) -- the 1:1 rule ("verify before sending a
    file") for everyone the group would deliver it to. An offer from an
    unverified member is refused. A member who is not verified joining while
    a file is still going out stops it.
  * THE ROOM'S HISTORY: pieces carry a no-store hint (XEP-0334), so the room
    does not keep them; its history holds the commits a returning member
    needs, and a file must not push those out (`SecureGroups.send_bulk`).

THE TRANSFER
============
The sender posts OFFER and waits. A member's ACCEPT starts the pieces, which
the room delivers once to every member; whoever did not accept ignores them.
A member that accepts later, or missed pieces (a commit by somebody else can
move the group to a new epoch under a piece in flight), asks with NEED and
the sender posts those pieces again. A member that has the whole file, and
its hash matches, says GOT. The sender keeps the file in memory for
OFFER_SECONDS after the offer, then forgets it.

Wire (inside the MLS plaintext, after FILE_PREFIX), JSON:
    {"t":"offer","id":<32 hex>,"name":<str>,"size":<int>,"chunks":<int>,"sha":<64 hex>}
    {"t":"accept","id":...}         a member will take it
    {"t":"data","id":...,"i":<index>,"d":<base64 piece>}
    {"t":"need","id":...,"i":[<index>, ...]}
    {"t":"got","id":...}            received and verified
    {"t":"cancel","id":...}         the sender stopped it

States and reasons are `otrv4plus_filetransfer.TransferState` and
`TransferReason` codes, so both clients show a group file the way they show a
1:1 one.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set

from .events import ErrorOccurred, FileTransferChanged

__all__ = ["FILE_PREFIX", "GroupFiles", "GroupFileOutcome"]

#: Prefix of a group file message inside the MLS plaintext. Starts with a NUL
#: so nothing a person types can collide with it.
FILE_PREFIX = "\x00OTRv4GF1:"
#: Plaintext bytes per piece. A piece is ~32 KB of base64, ~50 KB as an MLS
#: message in the room: 13 room stanzas.
CHUNK = 24 * 1024
#: The largest group file. A room carries roughly 12 KB/s at best (the
#: pacer's fast rate) and far less while a server limits it.
MAX_BYTES = 16 * 1024 * 1024
MAX_CHUNKS = -(-MAX_BYTES // CHUNK)
#: How long the sender keeps a file to answer late ACCEPTs and NEEDs.
OFFER_SECONDS = 30 * 60.0
#: Without a new piece for this long, a receiver asks for what is missing.
#: Generous: a piece is 13 room stanzas, and a rate-limited room sends one
#: about every 2 s.
STALL_SECONDS = 90.0
#: NEEDs without a single new piece in between before a receiver gives up.
MAX_NEEDS = 5
#: Indices asked for in one NEED.
NEED_BATCH = 64
#: Pieces offered to the group per transfer per tick (`send_bulk` refuses
#: early when the room is busy).
PIECES_PER_TICK = 4
MAX_INCOMING = 16
MAX_CONTROL_LEN = 64 * 1024
MAX_NAME_LEN = 255

_HEX = set("0123456789abcdef")


def _hex(value: Any, length: int) -> bool:
    return isinstance(value, str) and len(value) == length and set(value) <= _HEX


class GroupFileOutcome:
    """What `send` did, as the codes `android_bridge.files.FileOutcome` uses
    (Kotlin's `TransferUi.refusal` maps them), plus two of its own."""

    STARTED = "started"
    UNVERIFIED = "unverified"          # some other member is not verified
    BAD_FILE = "bad_file"              # unreadable, empty, or over MAX_BYTES
    UNAVAILABLE = "unavailable"
    CANNOT_SCRUB = "cannot_scrub"
    NOT_A_GROUP = "not_a_group"
    NO_MEMBERS = "no_members"          # nobody else in the group


@dataclass
class _Out:
    room: str
    tid: str
    name: str
    data: bytearray
    chunks: int
    at: float
    state: str = "waiting"
    reason: str = ""
    next_index: int = 0
    resend: List[int] = field(default_factory=list)
    accepted_by: Set[str] = field(default_factory=set)
    got: Set[str] = field(default_factory=set)


@dataclass
class _In:
    room: str
    tid: str
    sender: str
    name: str
    size: int
    chunks: int
    sha: str
    at: float
    state: str = "offered"
    reason: str = ""
    tmp: str = ""
    have: Set[int] = field(default_factory=set)
    last_progress: float = 0.0
    needs: int = 0
    path: str = ""


class GroupFiles:
    """Group files for one account. `groups` is its SecureGroups.

    `seal_at_rest`: a received file rests as an `.otrv` container sealed by
    Rust (Android), or as the plain file in the private directory (Termux),
    the same choice `FileTransferManager` makes for 1:1 files.
    `schedule(delay, fn)` runs `tick` again later; tests pass one that does
    nothing and call `tick` themselves.
    """

    OFFER_SECONDS = OFFER_SECONDS
    STALL_SECONDS = STALL_SECONDS
    FINISHED_KEPT = 16

    def __init__(self, groups: Any, *, emit: Callable[[Any], None],
                 seal_at_rest: bool = False,
                 clock: Callable[[], float] = time.time,
                 schedule: Optional[Callable[[float, Callable[[], None]], Any]] = None):
        self._groups = groups
        self._emit = emit
        self._seal = bool(seal_at_rest)
        self._clock = clock
        self._schedule = schedule or self._timer
        self._lock = threading.RLock()
        self._out: Dict[str, _Out] = {}
        self._in: Dict[str, _In] = {}
        self._finished: Dict[str, Dict[str, Any]] = {}
        self._ticking = False
        groups.set_file_handler(self._on_control)

    @staticmethod
    def _timer(delay: float, fn: Callable[[], None]) -> Any:
        t = threading.Timer(delay, fn)
        t.daemon = True
        t.start()
        return t

    # -- what the user does ---------------------------------------------------

    def send(self, room: str, path: str, strip_metadata: bool = False) -> str:
        """Offer [path] to the group. Returns a GroupFileOutcome code.

        [strip_metadata] is the user's answer to "remove hidden information?"
        (the app's dialog, Termux's y/n). A format that cannot be checked is
        refused rather than sent as-is, as for 1:1."""
        try:
            members = self._groups.members(room)
        except Exception:
            return GroupFileOutcome.NOT_A_GROUP
        others = [m for m in members if not m.get("me")]
        if not others:
            return GroupFileOutcome.NO_MEMBERS
        if not all(m.get("verified") for m in others):
            return GroupFileOutcome.UNVERIFIED
        real = os.path.abspath(os.path.expanduser(path or ""))
        if not os.path.isfile(real):
            return GroupFileOutcome.BAD_FILE
        sent_path = real
        if strip_metadata:
            from . import metadata as _metadata
            if not _metadata.examine_file(real).can_scrub:
                return GroupFileOutcome.CANNOT_SCRUB
            import otrv4plus_filetransfer as ft
            sent_path = _metadata.scrub_file(real, ft.staging_dir())
        try:
            size = os.path.getsize(sent_path)
            if size <= 0 or size > MAX_BYTES:
                return GroupFileOutcome.BAD_FILE
            with open(sent_path, "rb") as fh:
                data = bytearray(fh.read(MAX_BYTES + 1))
        except OSError:
            return GroupFileOutcome.BAD_FILE
        finally:
            if sent_path != real:
                _discard(sent_path)
                try:
                    os.rmdir(os.path.dirname(sent_path))
                except OSError:
                    pass
        if len(data) != size:
            return GroupFileOutcome.BAD_FILE
        name = _sanitise(os.path.basename(real))
        tid = os.urandom(16).hex()
        chunks = -(-size // CHUNK)
        out = _Out(room=room, tid=tid, name=name, data=data, chunks=chunks,
                   at=self._clock())
        with self._lock:
            self._out[tid] = out
        try:
            self._control(room, {"t": "offer", "id": tid, "name": name, "size": size,
                                 "chunks": chunks,
                                 "sha": hashlib.sha256(bytes(data)).hexdigest()})
        except Exception:
            with self._lock:
                self._out.pop(tid, None)
            _zero(data)
            return GroupFileOutcome.UNAVAILABLE
        self._changed_out(out)
        self._arm()
        return GroupFileOutcome.STARTED

    def accept(self, tid: str) -> bool:
        with self._lock:
            inc = self._in.get(tid)
            if inc is None or inc.state != "offered":
                return False
            try:
                inc.tmp = _incoming_file(tid)
            except OSError:
                return False
            inc.state = "accepted"
            inc.last_progress = self._clock()
        self._changed_in(inc)
        try:
            self._control(inc.room, {"t": "accept", "id": tid})
        except Exception:
            pass
        self._arm()
        return True

    def decline(self, tid: str) -> bool:
        """Local only: the others go on receiving it."""
        with self._lock:
            inc = self._in.get(tid)
            if inc is None or inc.state != "offered":
                return False
        self._end_in(inc, "declined")
        return True

    def cancel(self, tid: str) -> bool:
        """Stop sending ours (and tell the group), or stop receiving one."""
        with self._lock:
            out = self._out.get(tid)
            inc = self._in.get(tid) if out is None else None
        if out is not None:
            try:
                self._control(out.room, {"t": "cancel", "id": tid})
            except Exception:
                pass
            self._end_out(out, "cancelled", "by_us")
            return True
        if inc is not None:
            self._end_in(inc, "cancelled", "by_us")
            return True
        return False

    def knows(self, tid: str) -> bool:
        with self._lock:
            return tid in self._out or tid in self._in

    def transfers(self) -> List[Dict[str, Any]]:
        """Rows in the shape `FileBridge.transfers` gives Kotlin, plus `from`
        (the member who sent it) and `group`."""
        with self._lock:
            rows = [self._row_out(o) for o in self._out.values()]
            rows += [self._row_in(i) for i in self._in.values()]
            live = {r["id"] for r in rows}
            rows += [dict(r) for k, r in self._finished.items() if k not in live]
        return rows

    def close(self) -> None:
        """Forget everything (sign-out, Wipe & Exit). Nothing is sent."""
        with self._lock:
            outs, ins = list(self._out.values()), list(self._in.values())
            self._out.clear()
            self._in.clear()
            self._finished.clear()
        for out in outs:
            _zero(out.data)
        for inc in ins:
            if inc.tmp:
                _discard(inc.tmp)

    # -- time -------------------------------------------------------------------

    def tick(self) -> None:
        now = self._clock()
        with self._lock:
            outs, ins = list(self._out.values()), list(self._in.values())
        for out in outs:
            if now - out.at >= self.OFFER_SECONDS:
                if out.got:
                    self._end_out(out, "delivered")
                elif out.accepted_by:
                    self._end_out(out, "failed", "lost_chunk")
                else:
                    self._end_out(out, "cancelled", "expired")
                continue
            if out.state in ("accepted", "sent") and not self._still_verified(out.room):
                try:
                    self._control(out.room, {"t": "cancel", "id": out.tid})
                except Exception:
                    pass
                self._end_out(out, "cancelled", "unverified_member")
                continue
            self._pump(out)
        for inc in ins:
            if inc.state == "offered" and now - inc.at >= self.OFFER_SECONDS:
                self._end_in(inc, "cancelled", "expired")
            elif inc.state == "accepted" and now - inc.last_progress >= self.STALL_SECONDS:
                if inc.needs >= MAX_NEEDS:
                    self._end_in(inc, "failed", "lost_chunk")
                    continue
                missing = [i for i in range(inc.chunks) if i not in inc.have][:NEED_BATCH]
                inc.needs += 1
                inc.last_progress = now
                try:
                    self._control(inc.room, {"t": "need", "id": inc.tid, "i": missing})
                except Exception:
                    pass

    def _arm(self) -> None:
        with self._lock:
            if self._ticking or not (self._out or self._in):
                return
            self._ticking = True
        self._schedule(1.0, self._ticked)

    def _ticked(self) -> None:
        with self._lock:
            self._ticking = False
        try:
            self.tick()
        except Exception:
            pass
        self._arm()

    def _pump(self, out: _Out) -> None:
        for _ in range(PIECES_PER_TICK):
            with self._lock:
                if out.tid not in self._out or out.state not in ("accepted", "sent"):
                    return
                if out.resend:
                    index, again = out.resend[0], True
                elif out.next_index < out.chunks:
                    index, again = out.next_index, False
                else:
                    return
                piece = bytes(out.data[index * CHUNK:(index + 1) * CHUNK])
            text = FILE_PREFIX + json.dumps(
                {"t": "data", "id": out.tid, "i": index,
                 "d": base64.b64encode(piece).decode("ascii")}, separators=(",", ":"))
            try:
                if not self._groups.send_bulk(out.room, text):
                    return                       # the room is busy: next tick
            except Exception:
                return
            with self._lock:
                if again:
                    out.resend.pop(0)
                else:
                    out.next_index += 1
                done = out.next_index >= out.chunks and not out.resend
                moved = done and out.state == "accepted"
                if moved:
                    out.state = "sent"
            if moved:
                self._changed_out(out)
            if done:
                return

    # -- from the group ---------------------------------------------------------

    def _on_control(self, room: str, sender: str, verified: bool, payload: str) -> None:
        if len(payload) > MAX_CONTROL_LEN:
            return
        try:
            msg = json.loads(payload)
        except ValueError:
            return
        if not isinstance(msg, dict) or not _hex(msg.get("id"), 32):
            return
        if sender == getattr(self._groups, "account", None):
            return
        kind, tid = msg.get("t"), msg["id"]
        if kind == "offer":
            self._on_offer(room, sender, verified, tid, msg)
            return
        with self._lock:
            out = self._out.get(tid)
            inc = self._in.get(tid)
        if out is not None and out.room == room:
            if kind == "accept":
                with self._lock:
                    first = not out.accepted_by
                    out.accepted_by.add(sender)
                    if out.state == "waiting":
                        out.state = "accepted"
                    elif not first:
                        # Late: what is already out goes again for them.
                        have = set(out.resend)
                        out.resend += [i for i in range(out.next_index) if i not in have]
                        if out.state == "sent" and out.resend:
                            out.state = "accepted"
                self._changed_out(out)
                self._arm()
            elif kind == "need":
                wanted = msg.get("i")
                if not isinstance(wanted, list):
                    return
                with self._lock:
                    have = set(out.resend)
                    for i in wanted[:NEED_BATCH]:
                        if isinstance(i, int) and 0 <= i < out.next_index and i not in have:
                            out.resend.append(i)
                            have.add(i)
                    if out.state == "sent" and out.resend:
                        out.state = "accepted"
                self._arm()
            elif kind == "got":
                # Counted (`delivered_to`); the file is still kept until
                # OFFER_SECONDS for a member that accepts late.
                with self._lock:
                    out.got.add(sender)
                self._changed_out(out)
            return
        if inc is None or inc.room != room or sender != inc.sender:
            return
        if kind == "cancel":
            if inc.state in ("offered", "accepted"):
                self._end_in(inc, "cancelled", "by_peer")
        elif kind == "data" and inc.state == "accepted":
            self._on_piece(inc, msg)

    def _on_offer(self, room: str, sender: str, verified: bool, tid: str,
                  msg: Dict[str, Any]) -> None:
        if not verified:
            self._emit(ErrorOccurred(peer=room, code="group_file_unverified"))
            return
        size, chunks, sha, name = msg.get("size"), msg.get("chunks"), msg.get("sha"), msg.get("name")
        if (not isinstance(size, int) or isinstance(size, bool) or not 0 < size <= MAX_BYTES
                or chunks != -(-size // CHUNK) or not _hex(sha, 64)
                or not isinstance(name, str) or len(name) > MAX_NAME_LEN):
            return
        with self._lock:
            if tid in self._in or tid in self._finished or len(self._in) >= MAX_INCOMING:
                return
            inc = _In(room=room, tid=tid, sender=sender, name=_sanitise(name),
                      size=size, chunks=chunks, sha=sha, at=self._clock())
            self._in[tid] = inc
        self._changed_in(inc)
        self._arm()

    def _on_piece(self, inc: _In, msg: Dict[str, Any]) -> None:
        index, data = msg.get("i"), msg.get("d")
        if (not isinstance(index, int) or isinstance(index, bool)
                or not 0 <= index < inc.chunks or not isinstance(data, str)):
            return
        try:
            piece = base64.b64decode(data.encode("ascii"), validate=True)
        except (ValueError, binascii.Error):
            return
        expected = CHUNK if index < inc.chunks - 1 else inc.size - CHUNK * (inc.chunks - 1)
        if len(piece) != expected:
            return
        with self._lock:
            if index in inc.have or inc.state != "accepted":
                return
            try:
                fd = os.open(inc.tmp, os.O_WRONLY)
                try:
                    os.pwrite(fd, piece, index * CHUNK)
                finally:
                    os.close(fd)
            except OSError:
                failed = True
            else:
                failed = False
                inc.have.add(index)
                inc.last_progress = self._clock()
                inc.needs = 0
            complete = not failed and len(inc.have) == inc.chunks
        if failed:
            self._end_in(inc, "failed", "transport")
            return
        if complete:
            self._finish(inc)
        # Progress is read from `transfers()`; an event per piece would only
        # be noise for the UI's event stream.

    def _finish(self, inc: _In) -> None:
        """Keep the file only if its size and hash match, read back."""
        try:
            if os.path.getsize(inc.tmp) != inc.size:
                raise ValueError("size")
            digest = hashlib.sha256()
            with open(inc.tmp, "rb") as fh:
                for block in iter(lambda: fh.read(1 << 20), b""):
                    digest.update(block)
            if digest.hexdigest() != inc.sha:
                raise ValueError("hash")
            final = _commit(inc.tmp, inc.name, self._seal)
        except Exception:
            self._end_in(inc, "failed", "verify_failed")
            return
        inc.tmp = ""
        inc.path = final
        self._end_in(inc, "received")
        try:
            self._control(inc.room, {"t": "got", "id": inc.tid})
        except Exception:
            pass

    # -- inside -------------------------------------------------------------------

    def _still_verified(self, room: str) -> bool:
        try:
            return all(m.get("verified") for m in self._groups.members(room)
                       if not m.get("me"))
        except Exception:
            return False

    def _control(self, room: str, msg: Dict[str, Any]) -> None:
        self._groups.send_control(room, FILE_PREFIX + json.dumps(msg, separators=(",", ":")))

    def _end_out(self, out: _Out, state: str, reason: str = "") -> None:
        with self._lock:
            if self._out.pop(out.tid, None) is None:
                return
            out.state, out.reason = state, reason
            self._keep(self._row_out(out))
        _zero(out.data)
        self._changed_out(out)

    def _end_in(self, inc: _In, state: str, reason: str = "") -> None:
        with self._lock:
            if self._in.pop(inc.tid, None) is None:
                return
            inc.state, inc.reason = state, reason
            self._keep(self._row_in(inc))
        if inc.tmp:
            _discard(inc.tmp)
            inc.tmp = ""
        self._changed_in(inc)

    def _keep(self, row: Dict[str, Any]) -> None:
        self._finished[row["id"]] = row
        while len(self._finished) > self.FINISHED_KEPT:
            self._finished.pop(next(iter(self._finished)))

    def _row_out(self, out: _Out) -> Dict[str, Any]:
        return {"id": out.tid, "peer": out.room, "group": True, "from": "",
                "filename": out.name, "size": len(out.data) if out.data else 0,
                "outgoing": True, "accepted": bool(out.accepted_by),
                "cancelled": out.state == "cancelled",
                "progress": (out.next_index / out.chunks) if out.chunks else 0.0,
                "state": out.state, "reason": out.reason, "path": "",
                "accepted_by": len(out.accepted_by), "delivered_to": len(out.got)}

    def _row_in(self, inc: _In) -> Dict[str, Any]:
        return {"id": inc.tid, "peer": inc.room, "group": True, "from": inc.sender,
                "filename": inc.name, "size": inc.size, "outgoing": False,
                "accepted": inc.state not in ("offered", "declined"),
                "cancelled": inc.state == "cancelled",
                "progress": (len(inc.have) / inc.chunks) if inc.chunks else 0.0,
                "state": inc.state, "reason": inc.reason,
                "path": inc.path if inc.state == "received" else ""}

    def _changed_out(self, out: _Out) -> None:
        self._emit(FileTransferChanged(peer=out.room, transfer_id=out.tid,
                                       filename=out.name, size=len(out.data),
                                       outgoing=True, state=out.state,
                                       reason=out.reason))

    def _changed_in(self, inc: _In) -> None:
        self._emit(FileTransferChanged(peer=inc.room, transfer_id=inc.tid,
                                       filename=inc.name, size=inc.size,
                                       outgoing=False, state=inc.state,
                                       reason=inc.reason))


def _sanitise(name: str) -> str:
    import otrv4plus_filetransfer as ft
    return ft.sanitise_filename(name)


def _incoming_file(tid: str) -> str:
    """A private, empty partial file for a group file we accepted."""
    import otrv4plus_filetransfer as ft
    path = os.path.join(ft.incoming_dir(),
                        "group-%s-%s.part" % (tid, os.urandom(8).hex()))
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    return path


def _commit(tmp: str, name: str, seal: bool) -> str:
    """Into the received directory, the way 1:1 files are: sealed by Rust
    (Android) or moved atomically (Termux)."""
    import otrv4plus_filetransfer as ft
    os.chmod(tmp, 0o600)
    if seal:
        final = ft.unique_path(ft.state_dir(), name + ft.CONTAINER_SUFFIX)
        ft._core.otrv_seal_file(ft.at_rest_dek(), tmp, final)
        ft._shred(tmp)
    else:
        final = ft.unique_path(ft.state_dir(), name)
        os.replace(tmp, final)
    return final


def _discard(path: str) -> None:
    try:
        import otrv4plus_filetransfer as ft
        ft._shred(path)
    except Exception:
        pass
    try:
        os.unlink(path)
    except OSError:
        pass


def _zero(data: bytearray) -> None:
    """Overwrite in place (a same-length slice assignment reuses the buffer)."""
    data[:] = bytes(len(data))
