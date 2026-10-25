# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""OtrApp's rooms: which are joined, their messages, entry requests, and the
secure groups (MLS+) that ride on them.

A mixin of OtrApp (app.py). The group cryptography is groups.py; the
server side of a room is transport_rooms.py."""
from __future__ import annotations

import json
import os
import threading
from typing import Any, List

import otrv4plus_actions as _actions

from .app_base import BridgeError, _new_message_id
from .events import (ErrorOccurred, GroupEntryRequested, MessageChanged,
                     RoomMessageAcked, RoomMessageReceived)
from .groups import GroupError, SecureGroups
from .trace import TRACE as _TRACE


class RoomChatMixin:
    """Rooms and secure groups. Mixed into OtrApp."""

    # -- rooms -----------------------------------------------------------------

    def note_room_joined(self, room: str) -> None:
        """We are in [room]: its text is group chat from now on. A join
        completing on the loop thread after a wipe began records nothing."""
        if self._wiped:
            return
        room = self.canonical_peer(room)
        if room in self._knocking:
            return
        self._rooms.add(room)
        # A secure group whose own commit was lost with the old stream: post
        # it again now we are back in the room. Off this thread -- it is the
        # transport's loop thread, and a room send from it would wait on
        # itself.
        groups = getattr(self, "_groups", None)
        if groups is not None and getattr(groups, "on_room_rejoined", None):
            threading.Thread(target=self._quietly, args=(groups.on_room_rejoined, room),
                             name="group-rejoin", daemon=True).start()

    def note_knocking(self, room: str, on: bool) -> None:
        """We are about to be (or have stopped being) in [room] only to ask
        its members for an invitation: see ConnectionController.
        request_group_entry."""
        room = self.canonical_peer(room)
        if on:
            self._knocking.add(room)
        else:
            self._knocking.discard(room)
            self._rooms.discard(room)

    #: A request to be invited, posted in an encrypted group's room.
    ENTRY_REQUEST_PREFIX = "?OTRv4Plus-ASK:"
    #: The same requester in the same room is shown at most once per hour.
    ENTRY_REQUEST_EVERY = 3600.0
    #: Replayed history older than this is not shown at all.
    ENTRY_REQUEST_MAX_AGE = 24 * 3600.0

    def _entry_requested(self, room: str, body: str, timestamp: float,
                         own: bool, item: Any) -> None:
        """A request to be invited (ENTRY_REQUEST_PREFIX + {"jid": ...}).
        Shown to members as an address and two buttons; nothing happens
        unless one of them taps Invite."""
        if own:
            return
        try:
            data = json.loads(body[len(self.ENTRY_REQUEST_PREFIX):][:600])
            raw = str(data.get("jid", ""))
            jid = self.canonical_peer(raw)
        except Exception:
            return
        if "/" in raw:
            # A bare address or nothing: an invitation goes to an account.
            return
        local, _, domain = jid.partition("@")
        if (not local or not domain or len(jid) > 320 or "/" in jid
                or any(c.isspace() or ord(c) < 32 for c in jid)):
            return
        if jid == self._own_bare():
            return
        now = self._clock()
        live = item is None or getattr(item, "source", "live") == "live"
        if not live and timestamp and now - timestamp > self.ENTRY_REQUEST_MAX_AGE:
            return
        key = (room, jid)
        if now - self._entry_seen.get(key, 0.0) < self.ENTRY_REQUEST_EVERY:
            return
        self._entry_seen[key] = now
        self._emit(GroupEntryRequested(peer=room, requester=jid, live=live))

    def note_room_rejected(self, room: str, condition: str = "") -> None:
        """The server bounced a message we sent to `room`. For a secure group
        that may be our commit, which is posted again (off the loop thread,
        as above)."""
        if self._wiped:
            return
        room = self.canonical_peer(room)
        groups = getattr(self, "_groups", None)
        if groups is not None and room in self._rooms:
            threading.Thread(target=self._quietly, args=(groups.on_room_rejected, room),
                             name="group-rejected", daemon=True).start()

    @staticmethod
    def _quietly(fn, *args) -> None:
        try:
            fn(*args)
        except Exception:
            pass

    def note_room_left(self, room: str) -> None:
        self._rooms.discard(self.canonical_peer(room))

    def forget_rooms(self) -> None:
        """The stream went; so did every room membership it carried."""
        self._rooms.clear()
        self._handshake_seen.clear()

    def is_room(self, peer: str) -> bool:
        return self.canonical_peer(peer) in self._rooms

    def joined_room_list(self) -> List[str]:
        return sorted(self._rooms)

    def _refuse_room(self, peer: str, code: str) -> None:
        """Rooms get no OTR, no SMP, no calls and no files.

        OTR is a two-party protocol: a DAKE sent into a room would be read by
        every occupant and answered by none of them, or by the wrong one.
        """
        if peer in self._rooms:
            raise BridgeError(code, "rooms are not end-to-end encrypted")

    def _room_refs(self):
        refs = getattr(self, "_room_refs_table", None)
        if refs is None:
            import otrv4plus_roomsync as _rs
            refs = self._room_refs_table = _rs.RoomRefs()
        return refs

    def receive_room_message(self, room: str, nick: str, body: str,
                             timestamp: float = 0.0, own: bool = False,
                             item: Any = None) -> None:
        """A room message from the transport. Emitted as its own event type,
        never as `MessageReceived`: nothing downstream may confuse a room's
        plaintext with a peer's decrypted text.

        A SECURE GROUP's room goes to `SecureGroups` and nowhere else: what
        comes out is MLS-decrypted text or nothing, never the raw body. `own`
        marks the room reflecting our own message back, which MLS needs (it
        is how a commit learns it won) and a plain room does not show."""
        room = self.canonical_peer(room)
        if room not in self._rooms or room in self._knocking:
            return
        groups = self._groups
        secure = groups is not None and groups.is_secure(room)
        if secure:
            # A group this device holds now: any earlier "no keys" verdict
            # was history that arrived before the keys did.
            self._keyless_groups.discard(room)
        if secure and body.startswith(self.ENTRY_REQUEST_PREFIX):
            self._entry_requested(room, body, timestamp, own, item)
            return
        if item is not None and (item.action or not body) and secure:
            # A plaintext action on a secure group's message is not
            # authenticated: ignored, never applied.
            return
        if not secure and item is not None and self._plain_room_item(room, nick, body,
                                                                      timestamp, own, item):
            return
        if groups is not None:
            try:
                if groups.on_room_body(room, nick, body, timestamp, own=own):
                    return
            except GroupError:
                return
        if body.startswith(("?OTRv4MLS1:", "?OTRv4F|")):
            # An ENCRYPTED GROUP whose keys this device does not hold (never
            # joined, or its saved state was lost). Its ciphertext is never
            # shown as a message, and the room is never treated as plain:
            # sending into it is refused (`send_user_text`).
            #
            # Not while the keys may still come (device report, 2026-10-25:
            # the banner said "no keys" over a working, padlocked group). The
            # room replays its history on join, before the Welcome is
            # processed, and before the groups open at sign-in; that
            # ciphertext is dropped quietly, and the verdict waits for a
            # message that arrives once the groups are open and no join is
            # pending.
            if groups is None or not groups.is_open or groups.awaiting_welcome(room):
                return
            if room not in self._keyless_groups:
                self._keyless_groups.add(room)
                self._emit(ErrorOccurred(peer=room, code="group_keys_missing"))
            return
        if own:
            return
        self._emit(RoomMessageReceived(peer=room, sender=nick, body=body,
                                       timestamp=timestamp))

    def _group_action(self, room: str, action: str, target_id: str, body: str,
                      emojis: Any, message_id: str) -> str:
        """A correction, deletion or reaction in a SECURE GROUP: an MLS
        application message (otrv4plus_actions envelope), never plaintext.
        Every member checks that the MLS-authenticated sender of a correction
        or deletion is the author of its target."""
        if action == "edit" and not (body or "").strip():
            return self.SEND_FAILED
        message_id = message_id if _actions.valid_id(message_id) else _new_message_id()
        try:
            env = _actions.encode_group_message(
                _actions.encode_meta(message_id, **{action: target_id},
                                     emojis=_actions.clean_emojis(list(emojis or []))),
                body if action == "edit" else "")
            outcome = self._groups.send(room, env)
        except Exception:
            return self.SEND_FAILED
        return self.SEND_QUEUED if outcome == "held" else self.SEND_ENCRYPTED

    def _room_action(self, room: str, action: str, target_id: str, body: str,
                     emojis: Any, message_id: str) -> str:
        """A correction, deletion or reaction in a PLAIN room, with the
        standard elements. A correction names the message's own id
        (XEP-0308); a deletion or reaction names the room's (XEP-0424/-0444)."""
        if room in self._keyless_groups:
            return self.SEND_FAILED
        send = getattr(self._transport, "send_room_message", None)
        if send is None:
            return self.SEND_FAILED
        emojis = _actions.clean_emojis(list(emojis or []))
        if action == "edit":
            if not (body or "").strip():
                return self.SEND_FAILED
            target, text = self._room_refs().own_id_of(room, target_id), body
        elif action == "retract":
            target, text = target_id, _actions.RETRACT_FALLBACK
        else:
            target, text = target_id, None
        message_id = message_id if _actions.valid_id(message_id) else _new_message_id()
        try:
            send(room, text, message_id=message_id,
                 elements=_actions.action_elements(action, target, emojis))
        except Exception:
            return self.SEND_FAILED
        return self.SEND_PLAINTEXT

    def _plain_room_item(self, room: str, nick: str, body: str, timestamp: float,
                         own: bool, item: Any) -> bool:
        """A plain room message with its ids (otrv4plus_roomsync). True if it
        was handled here (an echo, an action, or a message with ids)."""
        refs = self._room_refs()
        refs.remember(room, item.own_id, item.ref)
        if not refs.first_time(item):
            return True
        if own and item.source == "live":
            # The room's id for a message we sent: say so, show nothing.
            # (Our own from its history or archive is shown: see
            # XmppTransport._on_groupchat.)
            if item.own_id and item.stanza_id:
                self._emit(RoomMessageAcked(peer=room, message_id=item.own_id,
                                            stanza_id=item.stanza_id))
            return True
        if item.action:
            self._emit(MessageChanged(
                peer=room, action=item.action, target_id=refs.resolve(room, item.target),
                body=body if item.action == "edit" else "",
                emojis=tuple(item.emojis), outgoing=own, source=item.source,
                sender="" if own else nick))
            return True
        if not body or body.startswith(("?OTRv4MLS1:", "?OTRv4F|")):
            return False
        self._emit(RoomMessageReceived(
            peer=room, sender=nick, body=body, timestamp=timestamp,
            message_id=item.ref, reply_to=refs.resolve(room, item.reply) if item.reply else "",
            source=item.source, own=own))
        return True

    # -- secure groups (MLS) ---------------------------------------------------

    #: Where the sealed group state lives: the Python home, which on Android
    #: is app-private storage and is removed by Wipe & Exit's storage stage.
    GROUP_STATE_DIR = "~/.otrv4plus/groups"

    @property
    def groups(self) -> SecureGroups:
        if self._groups is None:
            self._groups = SecureGroups(
                send_room=self._send_room_body,
                send_room_volatile=self._send_room_body_volatile,
                send_private=self._send_group_signal,
                emit=self._emit,
                peer_security=self.security_state,
                state_dir=os.path.expanduser(self.GROUP_STATE_DIR),
                clock=self._clock)
            # A password-protected group's room: its password goes to an
            # invitee with the invitation (groups.ROOMPW).
            self._groups.room_password_source = self._room_password
        return self._groups

    def _room_password(self, room: str) -> str:
        source = getattr(self._transport, "room_password", None)
        try:
            return str(source(room) or "") if source is not None else ""
        except Exception:
            return ""

    def open_groups(self, account: str) -> bool:
        """Open this account's secure groups. False when this build has no
        group encryption, which the UI reports rather than hiding."""
        try:
            self.groups.open(self.canonical_peer(account))
        except GroupError as exc:
            _TRACE.record("groups", "open_failed", "warning", code=exc.code)
            # Said on screen, not only traced (device report, 2026-10-25:
            # group invitations to the desktop showed nothing at all). With
            # the groups closed every invitation is refused on arrival, so the
            # reason -- usually another copy of the app holding this
            # account's group state -- has to be visible.
            if exc.code in ("state_in_use", "groups_unavailable"):
                self._emit(ErrorOccurred(peer=None, code=exc.code))
            return False
        # Group verification (the group passphrase) and group calls: built
        # now, so a verification or a ring that arrives first is not lost.
        if self._group_verify is None:
            from .group_verify import GroupVerify
            self._group_verify = GroupVerify(self._groups, emit=self._emit,
                                             clock=self._clock)
        if self._group_calls is None:
            try:
                from .group_call_bridge import GroupCallBridge
                self._group_calls = GroupCallBridge(
                    self, sam=lambda: self.sam_endpoint, emit=self._emit)
            except Exception:
                _TRACE.record("groups", "group_calls_unavailable", "warning")
        if self._group_files is None:
            from .group_files import GroupFiles
            # Sealed at rest like a 1:1 file: the same viewer opens both.
            self._group_files = GroupFiles(self._groups, emit=self._emit,
                                           seal_at_rest=True, clock=self._clock)
        return True

    #: Where the I2P SAM bridge is; set by the controller from the profile.
    sam_endpoint = ("127.0.0.1", 7656)

    @property
    def group_verify(self):
        if self._group_verify is None:
            raise GroupError("not_ready")
        return self._group_verify

    @property
    def group_calls(self):
        if self._group_calls is None:
            raise GroupError("group_calls_unavailable")
        return self._group_calls

    def _send_room_body(self, room: str, body: str) -> None:
        sender = getattr(self._transport, "send_room_message", None)
        if sender is None:
            raise GroupError("no_transport")
        sender(room, body)

    def _send_room_body_volatile(self, room: str, body: str) -> None:
        """A group file's piece: with the room's no-store hint (XEP-0334)."""
        sender = getattr(self._transport, "send_room_message", None)
        if sender is None:
            raise GroupError("no_transport")
        sender(room, body, volatile=True)

    def _send_group_signal(self, peer: str, text: str) -> None:
        """Group setup goes inside an encrypted OTRv4+ session or not at all:
        never plaintext, and never a handshake started on its behalf."""
        has = getattr(self._engine, "has_encrypted_session", None)
        if has is None or not has(peer):
            raise GroupError("otr_required")
        frame, should_send = self._engine.handle_outgoing_message(peer, text)
        if not (should_send and frame):
            raise GroupError("otr_required")
        self._send_protocol_or_raise(peer, frame, "group_send_failed")
