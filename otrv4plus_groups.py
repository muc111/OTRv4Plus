# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""OTRv4Plus secure groups (MLS) for the terminal XMPP client.

WHAT THIS IS
============
The terminal client's half of the SAME secure groups the Android app has, so
Termux users and Android users can sit in one MLS group:

    Termux A --+                                       +-- Android C
               +-- XMPP room: ?OTRv4MLS1:<base64> -----+
    Termux B --+    setup over OTRv4+: ?OTRv4-MLS:...  +

NOTHING HERE IS CRYPTOGRAPHY, AND NOTHING HERE IS A SECOND WIRE FORMAT.
Every group operation goes through `android_bridge.groups.SecureGroups` --
the class the Android app uses, unchanged -- which in turn calls the Rust
core's `RustMlsClient` (OpenMLS). Keys, epochs, membership, encryption,
authentication, replay and epoch checks, and the sealed state at rest are all
in Rust. `SecureGroups` owns the room framing, fragmentation, the OTRv4+ setup
signals, the SMP binding and the fail-closed rules. This module only:

  * joins, creates and leaves the XMPP room (XEP-0045) the way the Android
    transport does -- an instant room, our nick = our JID's localpart;
  * hands every room body to `SecureGroups.on_room_body`, our own reflection
    included (a commit learns it won the epoch by coming back);
  * carries the setup signals inside the terminal client's OTRv4+ sessions,
    exactly as `OtrApp._send_group_signal` does -- never in the clear, never a
    handshake started on their behalf;
  * prints what `SecureGroups` reports.

FAIL CLOSED
===========
A secure room has no plaintext. `send` raises rather than posting text; an
inbound plaintext body in a secure room is refused and reported; a frame that
does not decrypt is dropped and counted, and after a few the user is told
their group state may be behind and how to recover (remove and re-invite --
MLS has no resynchronisation here, and none is invented).

PERSISTENCE (terminal only)
===========================
The sealed group state lives in `~/.otrv4plus/xmpp/groups/` and is sealed by
Rust under a device key file beside it, exactly as on Android. An ordinary
/quit KEEPS it (`close`: sealed, then zeroized in memory); /wipe destroys it
with everything else (`wipe`). Android's Wipe & Exit is untouched.
"""
from __future__ import annotations

import asyncio
import os
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

import otrv4plus_fragment as _fragment
from android_bridge.events import (ErrorOccurred, GroupChanged, GroupInvite,
                                   RoomMessageReceived, SecurityState,
                                   security_state_from_level)
from android_bridge.groups import (ROOM_PREFIX, SIGNAL_PREFIX, GroupError,
                                   SecureGroups, is_group_signal, is_room_frame)

__all__ = ["TermuxGroups", "HELP", "is_group_signal", "ROOM_PREFIX",
           "SIGNAL_PREFIX"]

#: Frames for a room we have accepted an invitation to, but whose Welcome has
#: not arrived yet (it travels over OTRv4+, which over I2P can be slower than
#: the room). Bounded, and dropped if the Welcome does not come.
PREJOIN_MAX = 64
PREJOIN_TTL = 600.0
#: After this many undecryptable frames in a row, say what it means.
STALE_WARN_AFTER = 3
#: How long a room join may take (a cold I2P tunnel is slow).
JOIN_TIMEOUT = 120

HELP = """\
  Secure groups (MLS; the room sees ciphertext only):
  /group create <room@service>          new room + MLS group, you its only member
  /group invite <room> <jid>            invite over your OTRv4+ session with them
  /group invites                        invitations waiting for you
  /group accept <room>                  join the room and answer the invitation
  /group decline <room>
  /group say <room> <text>              send an encrypted message to the group
  /group members <room>                 members, fingerprints, verified or not
  /group remove <room> <jid>            remove a member (new epoch)
  /group rekey <room>                   fresh key for you (post-compromise)
  /group leave <room>                   forget the group's keys here and leave
  /group list                           your secure groups
  /wipe                                 destroy ALL local state (groups too) and exit"""


def _canon(jid: str) -> str:
    """A bare JID, lower case -- the same key `SecureGroups` and the OTR engine
    use for a peer."""
    return str(jid or "").strip().split("/", 1)[0].lower()


class TermuxGroups:
    """Secure groups for one terminal client (`host`: an OTRv4PlusXMPP).

    The host provides: `otr` (the EnhancedSessionManager), `send_message`
    (slixmpp), `send_otr_fragmented`, and slixmpp's plugin lookup. `printer`
    is the terminal's `print` (whose session log redacts message bodies).
    """

    def __init__(self, host: Any, state_dir: Optional[str],
                 printer: Callable[..., None] = print, *, core: Any = None,
                 clock: Callable[[], float] = time.time):
        self.host = host
        self._print = printer
        self._clock = clock
        self.groups = SecureGroups(send_room=self._send_room,
                                   send_private=self._send_private,
                                   emit=self._on_event,
                                   peer_security=self._peer_security,
                                   state_dir=state_dir, core=core, clock=clock)
        self._nicks: Dict[str, str] = {}               # room -> our nick in it
        self._prejoin: Dict[str, List[Tuple[float, str, str, float, bool]]] = {}
        self._stale_run: Dict[str, int] = {}
        self._rejected_said: Dict[str, float] = {}     # room -> when we said so
        self._opened = False

    # -- lifecycle ----------------------------------------------------------

    @property
    def available(self) -> bool:
        try:
            return self.groups.available
        except Exception:
            return False

    def open(self, account: str) -> bool:
        """Open (or reopen, after a restart) this account's groups."""
        try:
            self.groups.open(_canon(account))
        except GroupError as exc:
            if exc.code == "groups_unavailable":
                self._print("[group] this build of the Rust core has no group "
                            "encryption (rebuild with: maturin develop "
                            "--release --features mls)")
            else:
                self._print("[group] could not open group state (%s)" % exc.code)
            return False
        self._opened = True
        rooms = self.groups.rooms()
        if rooms:
            self._print("[group] %d secure group(s) restored: %s"
                        % (len(rooms), ", ".join(rooms)))
        return True

    def close(self) -> None:
        """/quit: seal to disk, zeroize in memory, keep the files."""
        try:
            self.groups.close()
        except Exception:
            pass

    def wipe(self) -> None:
        """/wipe: every group secret destroyed and the state files removed."""
        try:
            self.groups.wipe()
        except Exception:
            pass
        self._prejoin.clear()
        self._nicks.clear()

    # -- what SecureGroups needs from this client ---------------------------

    def _peer_security(self, peer: str) -> SecurityState:
        """The engine's level for this peer, the same mapping the Android
        bridge uses. Anything unreadable is PLAINTEXT (fail safe)."""
        try:
            return security_state_from_level(
                self.host.otr.get_security_level(_canon(peer)))
        except Exception:
            return SecurityState.PLAINTEXT

    def _send_private(self, peer: str, text: str) -> None:
        """Inside an encrypted OTRv4+ session or not at all -- the rule
        `OtrApp._send_group_signal` enforces on Android."""
        peer = _canon(peer)
        engine = self.host.otr
        has = getattr(engine, "has_encrypted_session", None)
        if has is None or not has(peer):
            raise GroupError("otr_required")
        frame, should_send = engine.handle_outgoing_message(peer, text)
        if not (should_send and frame):
            raise GroupError("otr_required")
        self.host.send_otr_fragmented(
            peer, frame if isinstance(frame, str) else frame.decode("utf-8"))

    def _send_room(self, room: str, body: str) -> None:
        # Paced fragments (RoomPacer) are sent from a timer thread, and
        # slixmpp's send queue is not thread-safe: hand those to the loop.
        loop = getattr(self.host, "loop", None)
        send = lambda: self.host.send_message(mto=room, mbody=body,  # noqa: E731
                                              mtype="groupchat")
        if loop is not None and loop.is_running():
            try:
                running = asyncio.get_running_loop()
            except RuntimeError:
                running = None
            if running is not loop:
                loop.call_soon_threadsafe(send)
                return
        send()

    # -- inbound --------------------------------------------------------------

    def on_signal(self, peer: str, text: str) -> None:
        """A `?OTRv4-MLS:` body that arrived INSIDE an OTRv4+ session (the
        caller decrypted it). Never shown as chat."""
        if not self._opened:
            self._print("[group] group setup message from %s ignored: groups "
                        "are not open" % _canon(peer)[:64])
            return
        try:
            self.groups.on_signal(_canon(peer), text)
        except GroupError as exc:
            self._print("[group] setup message from %s refused (%s)"
                        % (_canon(peer)[:64], exc.code))

    def on_groupchat(self, stanza: Any) -> None:
        """slixmpp's `groupchat_message`, read the way the Android transport
        reads it (`XmppTransport._on_groupchat`)."""
        try:
            sender = stanza["from"]
            room = _canon(str(sender.bare))
            nick = str(sender.resource or "")
            body = stanza["body"] or ""
        except Exception:
            return
        if not body or not nick:
            return
        own = nick == self._nicks.get(room)
        # Our own reflection is dropped -- except MLS frames and fragments,
        # which a commit needs to learn it won the epoch.
        if own and not body.startswith((ROOM_PREFIX, "?OTRv4F|")):
            return
        stamp = 0.0
        try:
            delay = stanza["delay"]["stamp"]
            if delay:
                stamp = delay.timestamp()
        except Exception:
            stamp = 0.0
        self.on_room_body(room, nick, body, stamp or self._clock(), own=own)

    def on_room_body(self, room: str, nick: str, body: str, timestamp: float,
                     own: bool = False) -> None:
        room = _canon(room)
        if not self._opened:
            return
        before = self.groups.stats.undecryptable
        shown_before = self.groups.stats.shown
        try:
            handled = self.groups.on_room_body(room, nick, body, timestamp, own=own)
        except GroupError:
            return
        if handled:
            if self.groups.stats.undecryptable > before:
                self._note_undecryptable(room)
            elif self.groups.stats.shown > shown_before:
                self._stale_run.pop(room, None)
            return
        # NOT a secure group here (yet).
        if body.startswith((ROOM_PREFIX, "?OTRv4F|")):
            if self.groups.awaiting_welcome(room):
                self._hold_prejoin(room, nick, body, timestamp, own)
            # An MLS frame in a room we are not in the group of: never shown.
            return
        if own:
            return
        # An ordinary room message. Never treated as MLS; labelled as what it
        # is. (Termux joins rooms only for secure groups, so this is a room
        # whose group we have not joined yet.)
        self._print("[room %s] (NOT end-to-end encrypted) %s: %s"
                    % (room[:64], nick[:48], body[:1024]))

    def _hold_prejoin(self, room, nick, body, timestamp, own) -> None:
        now = self._clock()
        held = [h for h in self._prejoin.get(room, []) if now - h[0] < PREJOIN_TTL]
        if len(held) < PREJOIN_MAX:
            held.append((now, nick, body, timestamp, own))
        self._prejoin[room] = held

    def _flush_prejoin(self, room: str) -> None:
        held = self._prejoin.pop(room, [])
        now = self._clock()
        for at, nick, body, timestamp, own in held:
            if now - at < PREJOIN_TTL:
                self.on_room_body(room, nick, body, timestamp, own=own)

    def _note_undecryptable(self, room: str) -> None:
        n = self._stale_run.get(room, 0) + 1
        self._stale_run[room] = n
        if n == STALE_WARN_AFTER:
            self._print(
                "[group %s] %d messages in a row could not be decrypted. They "
                "may be from before you joined, or your group state is behind "
                "(missed changes while offline). Nothing undecryptable is "
                "shown. If it continues, ask a member to remove you and "
                "invite you again." % (room[:64], n))

    # -- events from SecureGroups ------------------------------------------

    def _on_event(self, ev: Any) -> None:
        p = self._print
        if isinstance(ev, RoomMessageReceived):
            mark = "verified" if ev.verified else "unverified"
            p("[group %s] %s (%s, %s): %s"
              % (ev.peer[:64], ev.sender[:48], (ev.sender_identity or "")[:96],
                 mark, ev.body))
        elif isinstance(ev, GroupInvite):
            p("[group] %s invites you to the secure group %s (%s). "
              "/group accept %s  or  /group decline %s"
              % (ev.peer, ev.room, "SMP-verified" if ev.verified else
                 "NOT SMP-verified", ev.room, ev.room))
        elif isinstance(ev, GroupChanged):
            change = ev.change
            detail = (" " + ev.detail) if getattr(ev, "detail", "") else ""
            epoch = (" (epoch %s)" % ev.epoch) if getattr(ev, "epoch", None) is not None else ""
            p("[group %s] %s%s%s" % (ev.peer[:64], change, detail, epoch))
            if change == "joined":
                self._flush_prejoin(ev.peer)
            elif change == "idle_removed":
                p("[group %s] removed after 72 hours without a key update "
                  "(device away): %s. Re-invite them over OTRv4+ "
                  "(/group invite) to bring them back."
                  % (ev.peer[:64], (ev.detail or "")[:200]))
            elif change == "removed_us":
                p("[group %s] you were removed: new messages in this group can "
                  "no longer be read here." % ev.peer[:64])
        elif isinstance(ev, ErrorOccurred):
            p("[group] warning: %s%s" % (ev.code, (" (%s)" % ev.peer[:64]) if ev.peer else ""))

    # -- the room (XEP-0045) ------------------------------------------------

    def _nick(self) -> str:
        try:
            return str(self.host.boundjid.user) or "member"
        except Exception:
            return "member"

    async def _join(self, room: str, *, create: bool) -> None:
        muc = self.host.plugin["xep_0045"]
        nick = self._nick()
        await muc.join_muc_wait(room, nick, timeout=JOIN_TIMEOUT)
        self._nicks[room] = nick
        if create:
            # XEP-0045 §10.1.2 instant room: accept the defaults, or the room
            # stays locked and nobody else can enter. As on Android.
            form = self.host.plugin["xep_0004"].make_form(ftype="submit")
            await muc.set_room_config(room, form, timeout=JOIN_TIMEOUT)

    def _leave_muc(self, room: str) -> None:
        nick = self._nicks.pop(room, None)
        if nick:
            try:
                self.host.plugin["xep_0045"].leave_muc(room, nick)
            except Exception:
                pass

    async def rejoin_all(self) -> None:
        """After (re)connecting: back into the room of every group we hold, so
        its traffic reaches us. Always a fresh join -- after a reconnect the
        server has dropped our old room presence even though we remember it.
        The room's history may carry changes made while we were away; they are
        processed in order, and anything that does not fit our state is
        refused, never shown."""
        for room in self.groups.rooms():
            try:
                await self._join(room, create=False)
            except Exception as exc:
                self._print("[group %s] could not rejoin the room (%s)"
                            % (room[:64], type(exc).__name__))
                continue
            # A commit of ours lost with the old stream goes out again.
            self.groups.on_room_rejoined(room)

    def on_room_rejected(self, room: str) -> bool:
        """The server bounced our message to `room`. True when it is one of
        our secure groups (and the caller need say nothing more)."""
        room = _canon(room)
        if not (self._opened and self.groups.is_secure(room)):
            return False
        # A fast burst into a limited room bounces several pieces at once:
        # say it once a minute, not once per piece.
        now = self._clock()
        if now - self._rejected_said.get(room, -1e18) >= 60:
            self._rejected_said[room] = now
            self._print("[group %s] the server refused group messages (rate "
                        "limit); slowing down for this room and sending them "
                        "again. If this repeats, the room's server limits are "
                        "too low for MLS (Prosody: raise or remove muc_limits "
                        "on the conference component)." % room[:64])
        self.groups.on_room_rejected(room)
        return True

    def owns_room(self, jid: str) -> bool:
        """Whether `jid` is a room this client joined (for a secure group)."""
        room = _canon(jid)
        return room in self._nicks or (self._opened and self.groups.is_secure(room))

    def say(self, room: str, text: str) -> None:
        """Typed text for a room: MLS-encrypted, or refused. Never plaintext."""
        room = _canon(room)
        if not text:
            return
        try:
            self.groups.send(room, text)
        except GroupError as exc:
            self._print("[group %s] not sent: %s -- nothing was sent in the "
                        "clear" % (room[:64], exc.code))
            return
        self._print("[group %s] me: %s" % (room[:64], text))

    # -- commands -----------------------------------------------------------

    async def command(self, rest: str) -> None:
        """`/group <verb> ...`. Every failure is reported, none falls back."""
        parts = rest.split(None, 2)
        verb = parts[0].lower() if parts else "help"
        arg1 = _canon(parts[1]) if len(parts) > 1 else ""
        arg2 = parts[2] if len(parts) > 2 else ""
        p = self._print
        if verb in ("help", "?"):
            p(HELP)
            return
        if not self._opened:
            p("[group] groups are not open (not connected yet, or this build "
              "has no MLS)")
            return
        try:
            if verb == "create" and arg1:
                await self._create(arg1)
            elif verb == "invite" and arg1 and arg2:
                self.groups.invite(arg1, _canon(arg2))
            elif verb == "invites":
                inv = self.groups.pending_invites()
                p("[group] invitations: %s" % (", ".join(
                    "%s from %s%s" % (i["room"], i["peer"],
                                      " (accepted)" if i["accepted"] else "")
                    for i in inv) or "none"))
            elif verb == "accept" and arg1:
                await self._accept(arg1)
            elif verb == "decline" and arg1:
                self.groups.decline(arg1)
                p("[group %s] declined" % arg1)
            elif verb == "say" and arg1 and arg2:
                self.say(arg1, arg2)
            elif verb == "members" and arg1:
                for m in self.groups.members(arg1):
                    p("[group %s] %s%s  %s  %s"
                      % (arg1, m["jid"], " (you)" if m["me"] else "",
                         "verified" if m["verified"] else "unverified",
                         m["fingerprint"][:32]))
                suite = self.groups.suite(arg1)
                p("[group %s] epoch %d, suite %s" % (
                    arg1, self.groups.epoch(arg1),
                    "hybrid X448+ML-KEM-1024 / Ed448+ML-DSA-87" if suite == "hybrid"
                    else "PQ-only ML-KEM-1024 / ML-DSA-87 (made before rc.27: "
                         "re-create it to add members)"))
            elif verb == "remove" and arg1 and arg2:
                self.groups.remove(arg1, _canon(arg2))
                p("[group %s] removal of %s committed" % (arg1, _canon(arg2)))
            elif verb == "rekey" and arg1:
                self.groups.rekey(arg1)
            elif verb == "leave" and arg1:
                self.groups.leave(arg1)
                self._leave_muc(arg1)
            elif verb == "list":
                p("[group] secure groups: %s"
                  % (", ".join(self.groups.rooms()) or "none"))
            else:
                p(HELP)
        except GroupError as exc:
            p("[group] %s failed: %s%s" % (verb, exc.code,
                                          (" (%s)" % exc.detail) if exc.detail else ""))

    async def _create(self, room: str) -> None:
        """Room first, then the group -- and if the group step fails the room
        is left rather than kept as a plaintext room (as on Android)."""
        try:
            await self._join(room, create=True)
        except Exception as exc:
            self._leave_muc(room)
            self._print("[group] could not create the room %s (%s)"
                        % (room[:64], type(exc).__name__))
            return
        try:
            self.groups.create(room)
        except GroupError:
            self._leave_muc(room)
            raise

    async def _accept(self, room: str) -> None:
        """Join the room, then answer the invitation over OTRv4+."""
        try:
            await self._join(room, create=False)
        except Exception as exc:
            self._print("[group] could not join the room %s (%s)"
                        % (room[:64], type(exc).__name__))
            return
        try:
            self.groups.accept(room)
        except GroupError:
            self._leave_muc(room)
            raise
        self._print("[group %s] invitation accepted; waiting for the Welcome"
                    % room[:64])
