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
                ?OTRv4-MLS:WELCOME:<room>|<base64 Welcome>
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


class SecureGroups:
    """Every secure group this account is in, and the setup traffic for them.

    Construction does no I/O. `open(account)` creates or reopens the MLS state
    for an account; until then every operation raises `not_ready`.
    """

    STATE_NAME = "groups.sealed"
    DEK_NAME = "groups.dek"

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

    def _need(self):
        if self._wiped:
            raise GroupError("wiped")
        if self._client is None:
            raise GroupError("not_ready", "groups are not open for an account")
        return self._client

    def save(self) -> None:
        """Seal the state to disk, atomically. No-op without a state dir."""
        with self._lock:
            state_path, _ = self._paths()
            if not state_path or self._client is None or self._wiped:
                return
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

    def own_fingerprint(self) -> str:
        return bytes(self._need().own_fingerprint()).hex()

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
            self._require_otr(peer)
            fp = bytes(client.own_fingerprint()).hex()
            self._outgoing[(room, peer)] = _Outgoing(room=room, at=self._clock())
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
        self._post(room, commit)

    def _on_welcome(self, peer: str, arg: str, verified: bool) -> None:
        room, _, b64 = arg.partition("|")
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
            if inv is None or held != inv.fingerprint:
                client.forget_group(room.encode())
                raise GroupError("inviter_fingerprint_mismatch")
            self._invites.pop(room, None)
            self._awaiting_welcome.pop(room, None)
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
        for part in parts:
            self._send_room(room, part)

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
                raise GroupError(code)
        self._post(room, ct)

    def remove(self, room: str, member: str) -> None:
        with self._lock:
            client = self._need()
            try:
                commit = bytes(client.remove_members(room.encode(), [member.encode()]))
            except ValueError as exc:
                raise GroupError("remove_refused", str(exc)[:80])
            self.save()
        self._post(room, commit)

    def rekey(self, room: str) -> None:
        """A fresh leaf key for us (post-compromise security)."""
        with self._lock:
            commit = bytes(self._need().self_update(room.encode()))
            self.save()
        self._post(room, commit)

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
            else:
                event = None
        if event is not None:
            self._emit(event)
        return True

    def _on_commit(self, room: str, ev: Dict[str, Any]) -> Optional[Any]:
        client = self._client
        epoch = int(ev.get("epoch", 0))
        if ev.get("removed_us"):
            self._bound.pop(room, None)
            self.save()
            return GroupChanged(peer=room, change="removed_us", epoch=epoch)
        if ev.get("dropped_ours"):
            self._welcome_for.pop(room, None)
            self._pending_binding.pop(room, None)
            self.save()
            self._emit(GroupChanged(peer=room, change="commit_lost", epoch=epoch))
        welcome = ev.get("welcome")
        invitees = self._welcome_for.pop(room, []) if ev.get("ours") else []
        bindings = self._pending_binding.pop(room, []) if ev.get("ours") else []
        for peer, verified in bindings:
            try:
                fp = bytes(client.member_fingerprint(room.encode(), peer.encode())).hex()
                self._bound.setdefault(room, {})[peer] = (fp, verified)
            except ValueError:
                pass
        self.save()
        if welcome is not None:
            for peer in invitees:
                try:
                    self._send_private(peer, "%sWELCOME:%s|%s"
                                       % (SIGNAL_PREFIX, room, _b64e(bytes(welcome))))
                except Exception:
                    self._emit(ErrorOccurred(peer=peer, code="group_welcome_send_failed"))
            return GroupChanged(peer=room, change="member_added", epoch=epoch)
        return GroupChanged(peer=room, change="epoch", epoch=epoch)
