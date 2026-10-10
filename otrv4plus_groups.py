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
import otrv4plus_muc as _muc
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
#: The `/group` verbs; any other first word is read as a room name.
VERBS = frozenset(("help", "?", "create", "invite", "invites", "accept", "decline",
                   "say", "members", "verify", "smp", "sendkeys", "remove", "rekey",
                   "leave", "delete", "call", "answer", "hangup", "pause", "calls",
                   "list"))

HELP = """\
  Secure groups (MLS; the room sees ciphertext only). <room> can be just its
  name (mls3), <jid> just the user name (bob): your server is filled in.
  /group create <room>                  new room + MLS group, you its only member
  /group invite <room> <jid>            invite over your OTRv4+ session with them
  /group invites                        invitations waiting for you
  /group accept <room>                  join the room and answer the invitation
  /group decline <room>
  /group say <room> <text>              send an encrypted message to the group
  /group <room> [text]                  switch to the group (and send text)
  /to <room or user>                    talk to a group or a contact: then just type
  /group members <room>                 members, fingerprints, verified or not
  /group verify <room>                  verify every member with the group
                                        passphrase (also /smp in a group); only
                                        verified members are in group calls
  /group sendkeys <room>                send your group key to each member (verified
                                        once you have done 1:1 /smp with them)
  /group remove <room> <jid>            remove a member (new epoch)
  /group rekey <room>                   fresh key for you (post-compromise)
  /group leave <room>                   forget the group's keys here and leave
  /group delete <room>                  delete the group for everyone (its creator)
  /group list                           your secure groups
  /group call <room>                    start a group voice call (verified members)
  /group answer <room>                  join a call you were rung for
  /group hangup  (or /hangup)           leave the call (its keys are destroyed)
  /group pause   (or /pause)            stop/resume sending your audio, stay in it
  /group calls                          calls ringing, and who is in yours
  /wipe                                 destroy ALL local state (groups too) and exit"""


def _room_was_created(join_result: Any) -> bool:
    """Whether `join_muc_wait`'s answer says the join created the room
    (XEP-0045 status 201)."""
    try:
        own = join_result[0] if isinstance(join_result, tuple) else join_result
        return 201 in {int(c) for c in own["muc"]["status_codes"]}
    except Exception:
        return False


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
        #: Group voice (android_bridge.group_call + otrv4plus_groupcall),
        #: made on first use so a client that never calls opens nothing.
        self._invite_after_otr: Dict[str, List[str]] = {}
        self._calls = None
        self._media = None
        self._call_tick = None
        self._rejected_said: Dict[str, float] = {}     # room -> when we said so
        #: What a bare y/n answers: (kind, room, when asked); kind is
        #: "invite" or "verify".
        self._prompt: Optional[Tuple[str, str, float]] = None
        #: Group verification with the group's passphrase (group calls).
        from android_bridge.group_verify import GroupVerify
        self.verify = GroupVerify(self.groups, emit=self._on_event,
                                  core=core, clock=clock)
        #: Calls from a verified member are joined without asking (owner
        #: design, 2026-10-10); /pause and /hangup are the way out.
        self.auto_join_calls = True
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
            elif exc.code == "state_in_use":
                self._print("[group] another otrv4plus client for this account "
                            "is still running and holds its secure groups. Quit "
                            "it (or: pkill -f otrv4plus_xmpp) and start again.")
            else:
                self._print("[group] could not open group state (%s)" % exc.code)
            return False
        self._opened = True
        # Listen for calls now, not on this client's first /group call: the
        # call handler is what hears a ring, and until rc.48 it was only set
        # up by a call command -- so a Termux client that had not made one
        # dropped every ring (an app's call showed "in call" with nobody
        # joining). Same as the app (group_call_bridge).
        self._group_calls()
        rooms = self.groups.rooms()
        if rooms:
            self._print("[group] %d secure group(s) restored: %s"
                        % (len(rooms), ", ".join(rooms)))
            if len(rooms) == 1:
                self._activate(rooms[0], only_if_idle=True)
            else:
                self._print("[group] /to <name> to talk in one of them")
        return True

    def close(self) -> None:
        """/quit: seal to disk, zeroize in memory, keep the files."""
        self._hangup()
        try:
            self.groups.close()
        except Exception:
            pass

    def wipe(self) -> None:
        """/wipe: every group secret destroyed and the state files removed."""
        self._hangup()
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
        # A delayed message is the room's history, replayed on joining.
        self.on_room_body(room, nick, body, stamp or self._clock(), own=own,
                          history=bool(stamp))

    def on_room_body(self, room: str, nick: str, body: str, timestamp: float,
                     own: bool = False, history: bool = False) -> None:
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
                # History from before we joined (or already processed) can
                # never decrypt: expected, not a sign the state is behind.
                if not history:
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
                # Held before our Welcome: from before we joined.
                self.on_room_body(room, nick, body, timestamp, own=own, history=True)

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
            self._activate(ev.peer, only_if_idle=True)
        elif isinstance(ev, GroupInvite):
            # Answered with a bare y or n (owner request, 2026-10-10): the
            # same kind of question as an SMP request, and only an exact
            # y/yes/n/no answers it -- anything else is typed as usual.
            self._prompt = ("invite", ev.room, self._clock())
            p("[group] %s invites you to the secure group %s (%s). "
              "Join? [y/n]   (or later: /group accept %s)"
              % (ev.peer, ev.room, "SMP-verified" if ev.verified else
                 "NOT SMP-verified", ev.room.split("@", 1)[0]))
        elif isinstance(ev, GroupChanged):
            change = ev.change
            detail = (" " + ev.detail) if getattr(ev, "detail", "") else ""
            epoch = (" (epoch %s)" % ev.epoch) if getattr(ev, "epoch", None) is not None else ""
            if change not in ("syncing", "synced", "held", "reinvited", "deleted",
                              "member_verified", "member_bound", "held_change",
                              "verify_started", "verify_running", "verify_progress",
                              "verify_finished", "member_verify_failed",
                              "group_verified", "call_paused", "call_resumed"):
                p("[group %s] %s%s%s" % (ev.peer[:64], change, detail, epoch))
            if change == "joined":
                self._flush_prejoin(ev.peer)
                self._activate(ev.peer)
            elif change == "syncing":
                p("[group %s] syncing with the group..." % ev.peer[:64])
            elif change == "deleted":
                p("[group %s] the group was deleted (its room is gone); its "
                  "keys are gone from this device" % ev.peer[:64])
                self._nicks.pop(ev.peer, None)
            elif change == "reinvited":
                p("[group %s] %s invites you again, but this device is already "
                  "in the group. If the group stopped working here, "
                  "/group accept %s replaces this device's copy with the "
                  "current one; otherwise ignore it."
                  % (ev.peer[:64], (ev.detail or "")[:96], ev.peer[:64]))
            elif change == "member_verified":
                p("[group %s] %s is verified in this group (group calls with "
                  "them are possible)" % (ev.peer[:64], (ev.detail or "")[:96]))
            elif change == "member_bound":
                p("[group %s] %s's group key received over OTRv4+, not yet "
                  "SMP-verified: /smp with them to verify"
                  % (ev.peer[:64], (ev.detail or "")[:96]))
            elif change == "held_change":
                p("[group %s] a group change is landing: what you type waits "
                  "and goes encrypted right after" % ev.peer[:64])
            elif change == "held":
                p("[group %s] the group is still syncing: what you type waits "
                  "and goes encrypted once it is in sync (a few seconds)"
                  % ev.peer[:64])
            elif change == "synced":
                p("[group %s] in sync%s" % (
                    ev.peer[:64], (": %s waiting message(s) sent" % ev.detail)
                    if ev.detail else ""))
            elif change == "call_ringing":
                caller = (ev.detail or "")[:96]
                if self.auto_join_calls and self._is_verified(ev.peer, caller):
                    p("[group call %s] %s is calling: joining (you are both "
                      "verified). /pause to mute yourself, /hangup to leave."
                      % (ev.peer[:64], caller))
                    asyncio.ensure_future(self._call(ev.peer, start=False))
                else:
                    p("[group call %s] %s is calling. /group answer %s"
                      % (ev.peer[:64], caller, ev.peer[:64]))
            elif change == "call_paused":
                p("[group call %s] paused: you hear the call, nobody hears you. "
                  "/pause again to talk" % ev.peer[:64])
            elif change == "call_resumed":
                p("[group call %s] talking again" % ev.peer[:64])
            elif change == "verify_started":
                if (ev.detail or "") != self.groups.account:
                    self._prompt = ("verify", ev.peer, self._clock())
                    p("[group %s] %s started verifying the group with its "
                      "passphrase. Join? [y/n]  (or /group verify %s)"
                      % (ev.peer[:64], (ev.detail or "")[:96],
                         ev.peer.split("@", 1)[0]))
            elif change == "verify_running":
                p("[group %s] checking the passphrase with %s..."
                  % (ev.peer[:64], (ev.detail or "")[:96]))
                self._print_verify_bar(ev.peer)
                self._arm_verify_ticker()
            elif change == "verify_progress":
                self._print_verify_bar(ev.peer)
            elif change == "verify_finished":
                pr = self.verify.progress(ev.peer)
                p("[group %s] verification finished. Verified: %s.%s%s"
                  % (ev.peer[:64], ", ".join(pr["verified"]) or "nobody",
                     (" Excluded -- the passphrase did not match, not in group "
                      "calls: %s." % ", ".join(pr["excluded"])) if pr["excluded"] else "",
                     (" /group call %s -- the verified join automatically."
                      % ev.peer.split("@", 1)[0]) if pr["verified"] else ""))
            elif change == "member_verify_failed":
                p("[group %s] %s: the passphrases did not match -- not verified, "
                  "and not in group calls" % (ev.peer[:64], (ev.detail or "")[:96]))
            elif change == "group_verified":
                p("[group %s] every member is verified. /group call %s -- everyone "
                  "verified joins automatically" % (ev.peer[:64],
                                                    ev.peer.split("@", 1)[0]))
            elif change == "call_refused_unverified":
                p("[group call %s] %s tried to join but is not SMP-verified by "
                  "you: not in your call" % (ev.peer[:64], (ev.detail or "")[:96]))
            elif change == "idle_removed":
                p("[group %s] removed after 72 hours without a key update "
                  "(device away): %s. Re-invite them over OTRv4+ "
                  "(/group invite) to bring them back."
                  % (ev.peer[:64], (ev.detail or "")[:200]))
            elif change == "removed_us":
                p("[group %s] you were removed: new messages in this group can "
                  "no longer be read here." % ev.peer[:64])
        elif isinstance(ev, ErrorOccurred):
            if ev.code == "groups_state_unreadable":
                p("[group] a saved group state on this device did not open for "
                  "this account and was kept aside (%s). Groups held in it "
                  "need a new invitation." % (getattr(ev, "detail", "") or "no detail")[:300])
                return
            p("[group] warning: %s%s" % (ev.code, (" (%s)" % ev.peer[:64]) if ev.peer else ""))

    # -- invitations: OTRv4+ first, by itself ------------------------------------

    def _invite(self, room: str, peer: str) -> None:
        """Invite over OTRv4+; with no session yet, start one and invite
        when it is up (no separate /otr needed)."""
        try:
            self.groups.invite(room, peer)
            self._print("[group %s] invitation sent to %s over OTRv4+" % (room[:64], peer))
            return
        except GroupError as exc:
            if exc.code != "otr_required":
                raise
        self._invite_after_otr.setdefault(peer, [])
        if room not in self._invite_after_otr[peer]:
            self._invite_after_otr[peer].append(room)
        self._print("[group %s] no OTRv4+ session with %s yet: starting one; the "
                    "invitation goes when it is ready (usually 1-2 min over I2P)"
                    % (room[:64], peer))
        start = getattr(self.host, "start_otr", None)
        if start is not None:
            start(peer)

    def on_otr_ready(self, peer: str) -> None:
        """OTRv4+ with `peer` is up: send the invitations that waited."""
        for room in self._invite_after_otr.pop(_canon(peer), []):
            try:
                self.groups.invite(room, _canon(peer))
                self._print("[group %s] invitation sent to %s over OTRv4+"
                            % (room[:64], _canon(peer)))
            except GroupError as exc:
                self._print("[group %s] invitation to %s failed: %s"
                            % (room[:64], _canon(peer), exc.code))

    # -- group voice calls ----------------------------------------------------

    def _group_calls(self):
        if self._calls is None:
            from android_bridge.group_call import GroupCalls
            self._calls = GroupCalls(
                self.groups,
                send_datagram=lambda dest, packet: (
                    self._media.send_datagram(dest, packet) if self._media else None),
                local_destination=lambda: self._media.destination if self._media else "",
                on_audio=lambda room, who, frame: (
                    self._media.on_audio(room, who, frame) if self._media else None),
                emit=self._on_event, clock=self._clock)
        return self._calls

    async def _call(self, room: str, *, start: bool) -> None:
        # Terminal-only (microphone, speaker, its own SAM session); loaded by
        # name so the APK, which ships this module but has no terminal
        # command line, does not have to carry it.
        import importlib
        _gc = importlib.import_module("otrv4plus_groupcall")
        calls = self._group_calls()
        if self._media is None:
            self._print("[group call] building an I2P datagram tunnel "
                        "(this can take a minute)...")
            media = _gc.GroupCallMedia(
                loop=self.host.loop,
                sam_host=getattr(self.host, "_voice_sam_host", "127.0.0.1"),
                sam_port=getattr(self.host, "_voice_sam_port", 7656),
                printer=self._print)
            try:
                await media.open()
            except Exception as exc:
                media.close()
                self._print("[group call] could not open an I2P datagram "
                            "session: %s" % str(exc)[:120])
                return
            self._media = media
        try:
            if start:
                calls.start(room)
            else:
                calls.join(room)
        except ValueError as exc:
            self._print("[group call] %s" % {
                "no_verified_member": "nobody in this group is SMP-verified by "
                                      "you; verify members over OTRv4+ first",
                "call_in_progress": "you are already in a call (/group hangup)",
                "no_call": "nobody is calling in that group",
            }.get(str(exc), str(exc)))
            return
        try:
            self._media.start_audio(calls)
        except Exception as exc:
            self._print("[group call] audio unavailable: %s" % str(exc)[:120])
        if self._call_tick is None:
            self._call_tick = self.host.loop.call_later(1.0, self._tick_calls)

    def _tick_calls(self) -> None:
        self._call_tick = None
        if self._calls is None:
            return
        try:
            self._calls.tick()
        except Exception:
            pass
        if self._media is not None:
            self._call_tick = self.host.loop.call_later(1.0, self._tick_calls)

    # -- verification progress ------------------------------------------------

    VERIFY_TICK = 15.0

    @staticmethod
    def verify_bar(pr: Dict[str, Any], width: int = 20) -> str:
        """`[########------------] 2/5 · ~1m30s left · 2 verified, ...`"""
        total = pr["total"] or 1
        filled = int(width * pr["done"] / total)
        line = "[%s%s] %d/%d" % ("#" * filled, "-" * (width - filled),
                                 pr["done"], pr["total"])
        if pr["running"] or pr["waiting"]:
            eta = int(pr["eta"])
            line += " · ~%dm%02ds left" % (eta // 60, eta % 60)
        parts = ["%d verified" % len(pr["verified"])]
        if pr["excluded"]:
            parts.append("%d excluded (wrong passphrase)" % len(pr["excluded"]))
        if pr["running"]:
            parts.append("%d checking" % len(pr["running"]))
        if pr["waiting"]:
            parts.append("%d not joined yet" % len(pr["waiting"]))
        return line + " · " + ", ".join(parts)

    def _print_verify_bar(self, room: str) -> None:
        try:
            pr = self.verify.progress(room)
        except Exception:
            return
        if pr["total"]:
            self._print("[group %s] verify %s" % (room[:64], self.verify_bar(pr)))

    def _arm_verify_ticker(self) -> None:
        loop = getattr(self.host, "loop", None)
        if loop is None or getattr(self, "_verify_tick", None) is not None:
            return

        def tick():
            self._verify_tick = None
            busy = False
            for room in self.verify.active_rooms():
                pr = self.verify.progress(room)
                if pr["running"]:
                    busy = True
                    self._print_verify_bar(room)
            if busy:
                self._verify_tick = loop.call_later(self.VERIFY_TICK, tick)

        try:
            self._verify_tick = loop.call_later(self.VERIFY_TICK, tick)
        except Exception:
            self._verify_tick = None

    def _is_verified(self, room: str, who: str) -> bool:
        try:
            return any(m["jid"] == who and m["verified"]
                       for m in self.groups.members(room))
        except Exception:
            return False

    def in_call(self) -> bool:
        return self._calls is not None and self._calls.active() is not None

    def pause_call(self) -> None:
        if not self.in_call():
            self._print("[group call] you are not in a group call")
            return
        self._calls.pause()

    def _hangup(self) -> None:
        calls = self._calls
        if calls is not None:
            for room in self.groups.rooms():
                calls.hangup(room)
        if self._media is not None:
            self._media.close()
            self._media = None
        if self._call_tick is not None:
            self._call_tick.cancel()
            self._call_tick = None

    # -- the room (XEP-0045) ------------------------------------------------

    def _nick(self) -> str:
        try:
            return str(self.host.boundjid.user) or "member"
        except Exception:
            return "member"

    async def _join(self, room: str, *, create: bool,
                    rejoin: bool = False) -> bool:
        """Enter `room`. True when this join CREATED it (XEP-0045 status 201)."""
        muc = self.host.plugin["xep_0045"]
        nick = self._nick()
        joined = await muc.join_muc_wait(room, nick, timeout=JOIN_TIMEOUT)
        self._nicks[room] = nick
        created = _room_was_created(joined)
        if create or (created and not rejoin):
            # XEP-0045 §10.1.2: a room we created stays locked, and nobody
            # else can enter, until we configure it.
            await self._configure(room)
        return created

    async def _configure(self, room: str) -> None:
        """Persistent, so the room (and the commits in its history) outlives
        a moment when every member is offline. A service that refuses
        persistence still gets the defaults: never left locked."""
        muc = self.host.plugin["xep_0045"]
        forms = self.host.plugin["xep_0004"]
        form = forms.make_form(ftype="submit")
        form.add_field(var="FORM_TYPE", ftype="hidden",
                       value="http://jabber.org/protocol/muc#roomconfig")
        form.add_field(var="muc#roomconfig_persistentroom", ftype="boolean",
                       value=True)
        # Listed, and marked as an encrypted group, so it shows in a room
        # list (with a group icon in the app) rather than only by address.
        form.add_field(var="muc#roomconfig_publicroom", ftype="boolean",
                       value=True)
        form.add_field(var="muc#roomconfig_roomdesc", ftype="text-single",
                       value=_muc.SECURE_GROUP_DESC)
        try:
            await muc.set_room_config(room, form, timeout=JOIN_TIMEOUT)
        except Exception:
            await muc.set_room_config(room, forms.make_form(ftype="submit"),
                                      timeout=JOIN_TIMEOUT)
        # Read it back: a service that ignores or refuses the field accepts
        # the form all the same, and the room then vanishes -- with the group's
        # history -- the first time every member is offline at once.
        persistent = False
        try:
            info = await self.host.plugin["xep_0030"].get_info(
                jid=room, timeout=JOIN_TIMEOUT)
            persistent = "muc_persistent" in {
                str(f) for f in info["disco_info"]["features"]}
        except Exception:
            persistent = False
        if not persistent:
            self._print("[group %s] warning: the server would not keep this room "
                        "while everyone is offline -- when the last member leaves "
                        "it is deleted and the group must be made again. The "
                        "server's admin can allow it (Prosody: "
                        "muc_room_default_persistent = true)." % room[:64])

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
        # Held until each room is back and its history applied (see
        # SecureGroups.mark_syncing).
        self.groups.mark_syncing()
        for room in self.groups.rooms():
            try:
                created = await self._join(room, create=False, rejoin=True)
            except Exception as exc:
                self._print("[group %s] could not rejoin the room (%s)"
                            % (room[:64], type(exc).__name__))
                continue
            if created:
                # The room is gone: secure groups' rooms are persistent
                # (rc.33), so it was deleted -- by its owner while we were
                # away. Our join just made an empty one; it is taken down
                # again and the group ends here too.
                await self._destroy_quietly(room)
                self.groups.on_room_destroyed(room)
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

    async def _destroy_quietly(self, room: str) -> None:
        try:
            await self.host.plugin["xep_0045"].destroy(
                room, reason="secure group deleted", timeout=JOIN_TIMEOUT)
        except Exception:
            self._leave_muc(room)
        self._nicks.pop(room, None)

    async def _delete(self, room: str) -> None:
        """Delete the group for everyone: the room is destroyed (only its
        owner -- the group's creator -- may), which tells every member in it;
        a member who was away finds it gone when they come back. Then our
        own copy goes."""
        if not self.groups.is_secure(room):
            self._print("[group] %s is not one of your secure groups" % room[:64])
            return
        try:
            await self.host.plugin["xep_0045"].destroy(
                room, reason="secure group deleted", timeout=JOIN_TIMEOUT)
        except Exception as exc:
            text = str(getattr(exc, "condition", "") or exc)
            if "forbidden" in text or "not-allowed" in text:
                self._print("[group %s] only the group's creator (the room's "
                            "owner) can delete it. /group leave %s leaves it "
                            "for you." % (room[:64], room[:64]))
            else:
                self._print("[group %s] the room was not deleted (%s)"
                            % (room[:64], type(exc).__name__))
            return
        self._nicks.pop(room, None)
        self.groups.on_room_destroyed(room)
        if getattr(self.host, "peer", None) == room:
            self.host.peer = None

    def owns_room(self, jid: str) -> bool:
        """Whether `jid` is a room this client joined (for a secure group)."""
        room = _canon(jid)
        return room in self._nicks or (self._opened and self.groups.is_secure(room))

    # -- names: "mls3" and "bob" are enough ------------------------------------

    def _domain(self) -> str:
        try:
            return str(self.host.boundjid.domain or "").lower()
        except Exception:
            return ""

    def contact(self, name: str) -> str:
        """`bob` -> `bob@<our server>`. A full address is kept as it is."""
        name = _canon(name)
        if not name or "@" in name:
            return name
        domain = self._domain()
        return "%s@%s" % (name, domain) if domain else name

    def known_rooms(self) -> List[str]:
        known = set(self._nicks)
        if self._opened:
            known.update(self.groups.rooms())
            try:
                known.update(i["room"] for i in self.groups.pending_invites())
            except Exception:
                pass
        return sorted(known)

    def room(self, name: str, *, new: bool = False) -> str:
        """`mls3` -> the one group (or invitation) of that name, or for a new
        room `mls3@<the conference service>`. A full address is kept."""
        name = _canon(name)
        if not name or "@" in name:
            return name
        known = self.known_rooms()
        if not new:
            for match in ([r for r in known if r.split("@", 1)[0] == name],
                          [r for r in known if r.split("@", 1)[0].startswith(name)]):
                if len(match) == 1:
                    return match[0]
                if len(match) > 1:
                    raise GroupError("ambiguous_room", ", ".join(match)[:300])
        services = [r.split("@", 1)[1] for r in known]
        if services:
            service = max(set(services), key=services.count)
        elif self._domain():
            service = "conference." + self._domain()
        else:
            raise GroupError("room_needs_full_address")
        return "%s@%s" % (name, service)

    def _activate(self, room: str, *, only_if_idle: bool = False) -> None:
        """Make the group the conversation what is typed goes to."""
        set_conv = getattr(self.host, "set_conversation", None)
        if set_conv is None:
            return
        current = getattr(self.host, "peer", None)
        if current and (only_if_idle or _canon(current) == _canon(room)):
            return
        set_conv(room)

    def say(self, room: str, text: str) -> None:
        """Typed text for a room: MLS-encrypted, or refused. Never plaintext."""
        room = _canon(room)
        if not text:
            return
        try:
            outcome = self.groups.send(room, text)
        except GroupError as exc:
            self._print("[group %s] not sent: %s -- nothing was sent in the "
                        "clear" % (room[:64], exc.code))
            return
        if outcome == "held":
            self._print("[group %s] me (waiting -- sent as soon as the group is "
                        "ready): %s" % (room[:64], text))
            return
        self._print("[group %s] me: %s" % (room[:64], text))

    # -- commands -----------------------------------------------------------

    async def command(self, rest: str) -> None:
        """`/group <verb> ...`. Every failure is reported, none falls back."""
        parts = rest.split(None, 2)
        verb = parts[0].lower() if parts else "help"
        p = self._print
        if verb in ("help", "?"):
            p(HELP)
            return
        if not self._opened:
            p("[group] groups are not open (not connected yet, or this build "
              "has no MLS)")
            return
        try:
            if verb not in VERBS:
                # "/group mls3" switches to it; "/group mls3 hello" says it.
                room = self.room(parts[0])
                if room not in self.known_rooms():
                    p("[group] no secure group called %s. /group list shows yours"
                      % parts[0][:64])
                    return
                text = rest.split(None, 1)[1] if len(parts) > 1 else ""
                if text:
                    self.say(room, text)
                else:
                    self._activate(room)
                return
            arg1 = (self.room(parts[1], new=(verb == "create"))
                    if len(parts) > 1 else "")
            arg2 = parts[2] if len(parts) > 2 else ""
            if verb == "create" and arg1:
                await self._create(arg1)
            elif verb == "invite" and arg1 and arg2:
                self._invite(arg1, self.contact(arg2))
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
            elif verb in ("verify", "smp") and arg1:
                self.start_verify(arg1)
            elif verb == "sendkeys" and arg1:
                result = self.groups.verify_members(arg1)
                for jid, status in sorted(result.items()):
                    p("[group %s] %s: %s" % (arg1[:64], jid, {
                        "verified": "verified",
                        "sent": "key sent; verified once you and they have done "
                                "/smp (do it now if you have not)",
                        "no_session": "no OTRv4+ session: /otr %s, then /smp"
                                      % jid.split("@", 1)[0],
                    }[status]))
                if not result:
                    p("[group %s] nobody else is in the group" % arg1[:64])
            elif verb == "remove" and arg1 and arg2:
                self.groups.remove(arg1, self.contact(arg2))
                p("[group %s] removal of %s committed" % (arg1, self.contact(arg2)))
            elif verb == "rekey" and arg1:
                self.groups.rekey(arg1)
            elif verb == "leave" and arg1:
                self.groups.leave(arg1)
                self._leave_muc(arg1)
            elif verb == "delete" and arg1:
                await self._delete(arg1)
            elif verb == "call" and arg1:
                await self._call(arg1, start=True)
            elif verb == "answer" and arg1:
                await self._call(arg1, start=False)
            elif verb == "hangup":
                self._hangup()
            elif verb == "pause":
                self.pause_call()
            elif verb == "calls":
                calls = self._group_calls()
                for r in calls.ringing():
                    p("[group call] %s is calling in %s  (/group answer %s)"
                      % (r["from"], r["room"], r["room"]))
                for room in self.groups.rooms():
                    who = calls.participants(room)
                    if who:
                        p("[group call %s] with %s" % (room, ", ".join(who)))
            elif verb == "list":
                p("[group] secure groups: %s"
                  % (", ".join(self.groups.rooms()) or "none"))
            else:
                p(HELP)
        except GroupError as exc:
            p("[group] %s failed: %s%s" % (verb, exc.code,
                                          (" (%s)" % exc.detail) if exc.detail else ""))

    #: How long a y/n stays the answer to an invitation.
    PROMPT_SECONDS = 600.0

    def pending_prompt(self) -> Optional[str]:
        """The room a bare y/n would answer now, if any."""
        if self._prompt is None or not self._opened:
            return None
        kind, room, at = self._prompt
        if self._clock() - at > self.PROMPT_SECONDS:
            self._prompt = None
            return None
        if kind == "invite" and not any(
                i["room"] == room and not i["accepted"]
                for i in self.groups.pending_invites()):
            self._prompt = None
            return None
        if kind == "verify" and self.verify.pending(room) is None:
            self._prompt = None
            return None
        return room

    def answer_prompt(self, answer: str) -> bool:
        """`y`/`yes`/`n`/`no` for what was asked. True if it was an answer."""
        room = self.pending_prompt()
        word = answer.strip().lower()
        if room is None or word not in ("y", "yes", "n", "no"):
            return False
        kind = self._prompt[0]
        self._prompt = None
        yes = word in ("y", "yes")
        if kind == "invite":
            asyncio.ensure_future(self.command(
                "%s %s" % ("accept" if yes else "decline", room)))
        elif yes:
            self._ask_passphrase(room)       # armed by THIS user's "y"
        else:
            self._print("[group %s] not verifying now; /group verify %s later"
                        % (room[:64], room.split("@", 1)[0]))
        return True

    # -- the group passphrase (group verification, for calls) ---------------

    #: Marks the host's hidden one-line read as a group passphrase.
    PASSPHRASE_TAG = "\x00group-passphrase:"

    def _ask_passphrase(self, room: str, *, creating: bool = False) -> None:
        """Hide the next line and take it as the group passphrase for `room`.
        LOCAL ONLY: called from the user's own command or their own y."""
        host = self.host
        host._secret_request = self.PASSPHRASE_TAG + ("new:" if creating else "") + room
        host._secret_purpose = "group"
        hidden = False
        mask = getattr(host, "_mask_next_input", None)
        if mask is not None:
            try:
                hidden = bool(mask(True))
            except Exception:
                hidden = False
        if creating:
            self._print("[group %s] set the group passphrase now (8+ characters; "
                        "tell the members in person, never in a chat). Members "
                        "type it to verify; only verified members are in group "
                        "calls. Type it on the next line%s, or press Enter (or "
                        "type a command) to skip." % (room[:64],
                                                    " (hidden)" if hidden else ""))
        else:
            self._print("[group %s] type the group passphrase on the next line%s:"
                        % (room[:64], " (hidden)" if hidden else ""))

    def passphrase_entered(self, tag: str, line: str) -> None:
        """The hidden line the user typed after `_ask_passphrase`."""
        rest = tag[len(self.PASSPHRASE_TAG):]
        creating = rest.startswith("new:")
        room = rest[len("new:"):] if creating else rest
        secret = bytearray(line.rstrip("\r\n").encode("utf-8"))
        if not secret:
            self._print("[group %s] no passphrase set%s" % (
                room[:64], ("; /group verify %s sets one later"
                            % room.split("@", 1)[0]) if creating else ""))
            return
        try:
            if creating:
                self.verify.set_passphrase(room, secret)
                self._print("[group %s] passphrase set. When the members have "
                            "joined: /group verify %s (or /smp in the group)"
                            % (room[:64], room.split("@", 1)[0]))
                return
            self.verify.start(room, secret)
        except ValueError as exc:
            self._print("[group %s] %s" % (room[:64], {
                "passphrase_too_short": "the passphrase must be 8 characters or more",
                "passphrase_too_long": "the passphrase is too long",
            }.get(str(exc), str(exc))))
            return
        finally:
            for i in range(len(secret)):
                secret[i] = 0
        self._print("[group %s] verifying with every member who joins, using "
                    "the passphrase..." % room[:64])

    def start_verify(self, room: str) -> None:
        """`/group verify <room>` or `/smp` in a group: with the passphrase
        set at creation, or asked for now."""
        if not self.groups.is_secure(room):
            self._print("[group] %s is not one of your secure groups" % room[:64])
            return
        if self.verify.has_passphrase(room) and self.verify.pending(room) is None:
            try:
                self.verify.start(room)
                self._print("[group %s] verifying every member with the group "
                            "passphrase; they are asked to type it" % room[:64])
                return
            except ValueError:
                pass
        self._ask_passphrase(room)

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
        self._activate(room)
        self._ask_passphrase(room, creating=True)

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
