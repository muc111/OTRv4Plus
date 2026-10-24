# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The controller's rooms: discovery, joining and creating them, entry
requests, destroying (as owner or as server admin), bookmarks and
rejoining after a reconnect.

A mixin of ConnectionController (connection.py)."""
from __future__ import annotations

import json
import threading
from typing import Any, Dict, Optional

import otrv4plus_muc as _muc

from .trace import TRACE as _TRACE


class RoomsControlMixin:
    """Rooms. Mixed into ConnectionController."""

    def discover_rooms(self, service: str) -> Dict[str, Any]:
        """The rooms a MUC service advertises.

        Only the public ones. A room configured as hidden is absent by design,
        so an empty list is a fact about what is advertised rather than
        evidence that a service has no rooms -- which is why the UI also
        offers joining a room by address.
        """
        result = self._muc_call("discover_rooms", service)
        return self._with_held_groups(self._with_admin_rooms(result, service), service)

    def _with_admin_rooms(self, result: Dict[str, Any], service: str) -> Dict[str, Any]:
        """A server admin sees every room, hidden ones too, from the server's own
        admin command (mod_otrv4plus_moderation "List all rooms"). Anyone else --
        or a server without the module -- gets the public listing unchanged.
        """
        if not result.get("ok"):
            return result
        transport = self._transport
        if not self._is_server_admin():
            return result
        try:
            code, _detail, value = transport.moderation("rooms")
        except Exception:
            return result
        if code != "ok" or not value or not value.get("available") or value.get("refused"):
            return result
        rooms = list(result.get("value") or [])
        by_jid = {str(r.get("jid", "")).lower(): r for r in rooms}
        suffix = "@" + str(service).lower()
        for item in value.get("rooms") or []:
            jid = str(item.get("jid", "")).lower()
            if not jid.endswith(suffix) or len(jid) > 320:
                continue
            row = by_jid.get(jid)
            if row is None:
                row = {"jid": jid, "name": str(item.get("name", ""))[:200],
                       "occupants": item.get("occupants"), "secure": False,
                       "claims_secure": str(item.get("description", "")).strip()
                       == _muc.SECURE_GROUP_DESC,
                       "password": bool(item.get("password"))}
                rooms.append(row)
                by_jid[jid] = row
            row["hidden"] = bool(item.get("hidden"))
        return dict(result, value=rooms)

    def _with_held_groups(self, result: Dict[str, Any], service: str) -> Dict[str, Any]:
        """Groups this account holds are secure whatever the listing says, and
        are listed even when the service hides their room (a room made before
        rooms were created public). Only rooms on this service.

        "secure" means HELD here -- keys on this device. A room's own
        description saying it is a group is only "claims_secure": anybody can
        write that description."""
        if not result.get("ok"):
            return result
        groups = getattr(self._app, "groups", None)
        try:
            held = [str(r).lower() for r in (groups.rooms() if groups else [])]
        except Exception:
            held = []
        rooms = list(result.get("value") or [])
        listed = {str(r.get("jid", "")).lower() for r in rooms}
        for room in rooms:
            if str(room.get("jid", "")).lower() in held:
                room["secure"] = True
        suffix = "@" + str(service).lower()
        for room in sorted(held):
            if room.endswith(suffix) and room not in listed:
                rooms.append({"jid": room, "name": "", "occupants": None,
                              "secure": True, "claims_secure": True,
                              "password": False})
        return dict(result, value=rooms)

    def _rejoin_secure_rooms(self) -> None:
        """Re-enter every secure group's room after a (re)connect, in the
        background.

        A dropped stream takes every room membership with it (forget_rooms).
        Without rejoining, a secure group's sends fail and our own pending commit
        never comes back, so MLS refuses every later send and a new member never
        gets their Welcome. Rejoining also replays the room's recent history,
        which applies any commit that landed while we were away. Same as the
        terminal client.
        """
        groups = getattr(self._app, "groups", None)
        rooms_of = getattr(groups, "rooms", None)
        if rooms_of is None:
            return
        try:
            rooms = list(rooms_of())
        except Exception:
            return
        if not rooms:
            return
        nick = self._profile.jid.split("@", 1)[0]
        # Until each room is joined again and its history applied, what is
        # typed is held: sent now it would be encrypted for an epoch the
        # others may have left, and lost.
        mark = getattr(groups, "mark_syncing", None)
        if mark is not None:
            mark()

        def run():
            ok = 0
            for room in rooms:
                try:
                    joined = self.join_room(room, nick)
                    taken = getattr(self._transport, "take_recreated", None)
                    if joined.get("ok") and taken is not None and taken(room):
                        # Gone while we were away: secure groups' rooms are
                        # persistent, so its owner deleted it. The empty room
                        # our join made is taken down and the group ends.
                        self.destroy_room(room, "secure group deleted")
                        self._on_room_destroyed(room)
                        continue
                    if joined.get("code") == "room_gone":
                        # Deleted while we were away, and the service keeps
                        # its tombstone: the join is refused with <gone/>.
                        # The group ends here too, instead of failing at
                        # every reconnect.
                        self._on_room_destroyed(room)
                        continue
                    if joined.get("ok") or joined.get("code") == "already_in_room":
                        ok += 1
                        rejoined = getattr(groups, "on_room_rejoined", None)
                        if rejoined is not None:
                            rejoined(room)
                except Exception:
                    pass
            _TRACE.record("groups", "rooms_rejoined", "info" if ok == len(rooms)
                          else "warning", rejoined=ok, total=len(rooms))

        threading.Thread(target=run, name="secure-room-rejoin",
                         daemon=True).start()

    def join_room(self, room: str, nick: str,
                  password: str = "") -> Dict[str, Any]:
        """Enter a room, and report what we are in it."""
        problem = _muc.validate_room(room) or _muc.validate_nick(nick)
        if problem is not None:
            return {"ok": False, "code": problem[0], "detail": problem[1],
                    "value": None}
        result = self._noting_room(self._muc_call("join_room", room, nick, password),
                                   room, joined=True)
        if result.get("ok"):
            # Every device of this account joins it too (XEP-0402).
            self._bookmark(room, nick, password, keep=True)
        return result

    def create_room(self, room: str, nick: str,
                    password: str = "") -> Dict[str, Any]:
        """Create a room and unlock it. See `XmppTransport.create_room`.

        [password], when given, makes the room password-protected; the
        transport confirms the service applied it. Not retained or traced
        here -- `_muc_call` records the operation and its code only.
        """
        problem = _muc.validate_room(room) or _muc.validate_nick(nick)
        if problem is None and password:
            problem = _muc.validate_room_password(password)
        if problem is not None:
            return {"ok": False, "code": problem[0], "detail": problem[1],
                    "value": None}
        args = (room, nick, password) if password else (room, nick)
        result = self._noting_room(self._muc_call("create_room", *args),
                                   room, joined=True)
        if result.get("ok"):
            self._bookmark(room, nick, password, keep=True)
        return result

    def leave_room(self, room: str, nick: str) -> Dict[str, Any]:
        result = self._noting_room(self._muc_call("leave_room", room, nick),
                                   room, joined=False)
        self._bookmark(room, nick, "", keep=False)
        return result

    def request_group_entry(self, room: str) -> Dict[str, Any]:
        """Ask the members of an encrypted group we are not in to invite us.

        An encrypted group is invite-only: the room lets anyone in, but its
        messages are MLS and only an invitation (sent over OTR by a member)
        gives the keys. So we step into the room for a moment, post ONE
        request carrying our address, and leave. Members' apps show "X asks
        to join" with Invite and Dismiss; nothing happens unless one taps
        Invite. Not bookmarked, not remembered, and while we are in the room
        for this, nothing it says reaches the app (`note_knocking`)."""
        problem = _muc.validate_room(room)
        if problem is not None:
            return {"ok": False, "code": problem[0], "detail": problem[1], "value": None}
        if self._transport is None:
            return {"ok": False, "code": "network",
                    "detail": "Connect before using rooms.", "value": None}
        if self._is_group_room(room):
            return {"ok": False, "code": "already_member",
                    "detail": "You are already in this group.", "value": None}
        bare = self._profile.jid.split("/", 1)[0].lower()
        nick = bare.split("@", 1)[0]
        body = self._app.ENTRY_REQUEST_PREFIX + json.dumps({"jid": bare})
        if self._app.is_room(room):
            # In it already (it was a plain room to this device): just ask.
            try:
                self._transport.send_room_message(room, body)
            except Exception:
                return {"ok": False, "code": "send_failed",
                        "detail": "The request could not be sent. Try again.",
                        "value": None}
            return {"ok": True, "code": "ok", "detail": "", "value": None}
        self._app.note_knocking(room, True)
        try:
            joined = self._muc_call("join_room", room, nick, "")
            if not joined.get("ok"):
                if joined.get("code") == "not_authorized":
                    return dict(joined, detail="This group's room has a password. "
                                "Ask one of its members to invite you.")
                return joined
            try:
                self._transport.send_room_message(room, body)
            except Exception:
                return {"ok": False, "code": "send_failed",
                        "detail": "The request could not be sent. Try again.",
                        "value": None}
            finally:
                if joined.get("ok"):
                    self._muc_call("leave_room", room, nick)
            return {"ok": True, "code": "ok", "detail": "", "value": None}
        finally:
            self._app.note_knocking(room, False)

    #: What a refused destroy means. The service's generic sentences for these
    #: codes are about joining ("you may be banned"), which is not what
    #: happened: XEP-0045 10.9 lets only the room's owner destroy it, and
    #: Prosody counts its server admins as owners of every room.
    DESTROY_REFUSED = ("Only the room's owner (whoever created it) or a server "
                       "admin can delete it for everyone, and the server did not "
                       "count this account as either. Leave it instead.")

    def destroy_room(self, room: str, reason: str = "") -> Dict[str, Any]:
        """Delete a room. Owners only, and the SERVICE is what enforces it."""
        result = self._noting_room(self._muc_call("destroy_room", room, reason),
                                   room, joined=False)
        if not result.get("ok") and result.get("code") in ("forbidden", "not_allowed",
                                                            "not_authorized"):
            result = self._destroy_as_admin(room, reason) or dict(
                result, detail=self.DESTROY_REFUSED)
        if not result.get("ok") and result.get("code") in ("room_gone", "item_not_found"):
            # Already deleted: Prosody keeps a destroyed room as a tombstone
            # (31 days by default) and answers a destroy of it with <gone/>.
            # That is the outcome asked for, not a failure. An admin also
            # removes the tombstone from the server's room list.
            if result.get("code") == "room_gone":
                self._destroy_as_admin(room, reason)
            result = {"ok": True, "code": "ok", "value": None,
                      "detail": "That room was already deleted."}
        if result.get("ok"):
            self._bookmark(room, "", "", keep=False)
        return result

    #: An admin whose server has not got the destroy-room command yet.
    DESTROY_NEEDS_MODULE = ("The server refused this as an owner delete, and its "
                            "moderation module is too old to delete rooms for an "
                            "admin. On the server, run install-server-limits.sh "
                            "again and restart Prosody.")

    def _is_server_admin(self) -> bool:
        """Whether this account administers its server, asked for THIS stream
        (the transport forgets on reconnect, which over I2P is frequent). Asked
        once per stream, cached after.
        """
        transport = self._transport
        if getattr(transport, "_server_admin", None) is True:
            return True
        try:
            code, _detail, value = transport.server_admin()
        except Exception:
            return False
        return code == "ok" and value is True

    def _destroy_as_admin(self, room: str, reason: str) -> Optional[Dict[str, Any]]:
        """The server refused the owner destroy, but we are its admin: use the
        admin command (mod_otrv4plus_moderation "Destroy a room"). Needed because
        Prosody does not count an admin as owner of other people's rooms. None
        when we are not an admin -- the refusal then stands; otherwise what the
        admin command said.
        """
        if not self._is_server_admin():
            return None
        try:
            code, detail, value = self._transport.moderation("destroy", room, 0, reason)
        except Exception:
            return None
        if code != "ok" or not value:
            _TRACE.record("muc", "destroy_room", "warning", result="admin_" + str(code))
            return {"ok": False, "code": code, "value": None, "from_admin": True,
                    "detail": detail or self.DESTROY_REFUSED}
        if not value.get("available"):
            _TRACE.record("muc", "destroy_room", "warning", result="admin_no_command")
            return {"ok": False, "code": "forbidden", "value": None, "from_admin": True,
                    "detail": self.DESTROY_NEEDS_MODULE}
        if value.get("refused"):
            _TRACE.record("muc", "destroy_room", "warning", result="admin_refused")
            return {"ok": False, "code": "forbidden", "value": None, "from_admin": True,
                    "detail": str(value.get("message") or "") or self.DESTROY_REFUSED}
        _TRACE.record("muc", "destroy_room", "info", result="ok_as_admin")
        return self._noting_room({"ok": True, "code": "ok", "detail": "", "value": None},
                                 room, joined=False)

    # -- bookmarks (XEP-0402) and rooms that forgot us (XEP-0410) -------------

    def _bookmarkable(self, room: str) -> bool:
        """Plain rooms only: never a secure group (its room is nothing
        without this device's MLS state) and never the Welcome room (joined
        by itself on every sign-in)."""
        room = str(room).lower()
        if self._is_group_room(room):
            return False
        from . import welcome as _welcome
        return not room.startswith(_welcome.ROOM_LOCALPART + "@")

    def _bookmark(self, room: str, nick: str, password: str, keep: bool) -> None:
        transport = getattr(self, "_transport", None)
        if transport is None or getattr(self, "_app", None) is None:
            return
        try:
            if not self._bookmarkable(room):
                return
        except Exception:
            return
        call = getattr(transport, "bookmark_room" if keep else "unbookmark_room", None)
        if call is None:
            return
        if keep:
            have = getattr(transport, "bookmark_for", lambda r: None)(room)
            if have and have.get("nick") == nick and have.get("password") == password:
                return
        args = (room, nick, password) if keep else (room,)

        def run():
            try:
                code, _detail, _value = call(*args)
                _TRACE.record("muc", "bookmark" if keep else "unbookmark",
                              "info" if code in ("ok", "unsupported") else "warning",
                              code=code)
            except Exception:
                pass
        threading.Thread(target=run, name="otr-bookmark", daemon=True).start()

    def _join_bookmarked_rooms(self) -> None:
        """Join, in the background, every room this account's bookmarks
        say to (rooms joined on another device, or before a reconnect)."""
        transport = self._transport
        marks = getattr(transport, "bookmarks", None)
        if marks is None:
            return
        try:
            wanted = [m for m in marks() if m.get("autojoin")]
        except Exception:
            return
        default_nick = self._profile.jid.split("@", 1)[0]

        def run():
            for mark in wanted:
                room = mark["room"]
                if not self._bookmarkable(room) or self._app.is_room(room):
                    continue
                password = getattr(transport, "room_password", lambda r: "")(room)
                try:
                    self.join_room(room, mark.get("nick") or default_nick, password)
                except Exception:
                    pass
        threading.Thread(target=run, name="otr-autojoin", daemon=True).start()

    def _on_room_lost(self, room: str) -> None:
        """The room says we are not in it (XEP-0410): join it again, as
        whoever we were, so its messages (and a secure group's commits)
        reach us again."""
        transport = self._transport
        nicks = getattr(transport, "_room_nicks", {}) or {}
        nick = nicks.get(str(room).lower()) or self._profile.jid.split("@", 1)[0]
        password = getattr(transport, "room_password", lambda r: "")(room)
        try:
            self._app.note_room_left(room)
        except Exception:
            pass
        self.join_room(room, nick, password)
