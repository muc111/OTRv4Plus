# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The controller's secure groups (MLS+) and group calls: create, invite,
accept, verify, leave and delete, and the call in a group.

A mixin of ConnectionController (connection.py), which the apps call; it
forwards to OtrApp's groups (groups.py) on the worker."""
from __future__ import annotations

from typing import Any, Dict

from .groups import GroupError as GroupErrorAlias
from .trace import TRACE as _TRACE


class GroupsControlMixin:
    """Secure groups and group calls. Mixed into ConnectionController."""

    # -- secure groups (MLS over a room; see android_bridge.groups) --------

    def _group_call(self, fn, *args) -> Dict[str, Any]:
        from .groups import GroupError  # noqa: F811
        try:
            value = fn(*args)
        except GroupError as exc:
            return {"ok": False, "code": exc.code, "detail": exc.detail, "value": None}
        except Exception as exc:
            code = getattr(exc, "code", None)
            if isinstance(code, str) and code:
                return {"ok": False, "code": code,
                        "detail": str(getattr(exc, "detail", ""))[:200], "value": None}
            return {"ok": False, "code": "group_failed",
                    "detail": type(exc).__name__, "value": None}
        return {"ok": True, "code": "ok", "detail": "", "value": value}

    def _is_group_room(self, room: str) -> bool:
        """A room that is (or is about to be) a secure group's."""
        groups = getattr(self._app, "groups", None)
        if groups is None:
            return False
        room = str(room).lower()
        try:
            return bool(room in self._creating_groups or groups.is_secure(room)
                        or groups.awaiting_welcome(room)
                        or any(i["room"] == room for i in groups.pending_invites()))
        except Exception:
            return False

    _creating_groups: "set" = set()

    def create_secure_group(self, room: str, password: str = "",
                            passphrase: str = "") -> Dict[str, Any]:
        """A new room that is an OTRv4Plus secure group from its first message.

        The room is created first, then the MLS group. If the MLS step fails
        the room is left rather than kept as a plaintext room the user thinks
        is secure."""
        nick = self._profile.jid.split("@", 1)[0]
        self._creating_groups = self._creating_groups | {str(room).lower()}
        try:
            made = (self.create_room(room, nick, password) if password
                    else self.create_room(room, nick))
        finally:
            self._creating_groups = self._creating_groups - {str(room).lower()}
        if not made.get("ok"):
            return made
        result = self._group_call(self._app.groups.create, room)
        if not result["ok"]:
            self.leave_room(room, nick)
            return result
        if passphrase:
            # The group passphrase: kept in memory for this group's first
            # verification; never stored or sent.
            secret = bytearray(passphrase.encode("utf-8"))
            try:
                self._app.group_verify.set_passphrase(room, secret)
            except (ValueError, GroupErrorAlias) as exc:
                result = dict(result, code=str(getattr(exc, "code", exc)),
                              detail="The group was created; its passphrase was "
                                     "not set (8 characters or more).")
        return result

    # -- group verification (the group passphrase) and group calls -----------

    def start_group_verify(self, room: str, passphrase: str = "") -> Dict[str, Any]:
        """Verify every member with the group passphrase (or the one set at
        creation when `passphrase` is empty: "passphrase_needed" if none)."""
        secret = bytearray(passphrase.encode("utf-8")) if passphrase else None

        def go():
            try:
                return self._app.group_verify.start(room, secret)
            except ValueError as exc:
                raise GroupErrorAlias(str(exc))
        return self._group_call(go)

    def group_verify_state(self, room: str) -> Dict[str, Any]:
        """{"members": {jid: verified|failed|running|waiting|not_verified},
        "all_verified": bool, "started_by": jid of a run we have not joined,
        "coordinator": who starts verifying, "can_start": whether we may}."""
        def go():
            v = self._app.group_verify
            pending = v.pending(room)
            pr = v.progress(room)
            return {"members": v.status(room), "all_verified": v.all_verified(room),
                    "started_by": pending["starter"] if pending else "",
                    "active": pr["active"], "done": pr["done"], "total": pr["total"],
                    "eta": pr["eta"], "excluded": pr["excluded"],
                    "coordinator": v.coordinator(room), "can_start": v.may_start(room)}
        return self._group_call(go)

    def set_group_call_auto_join(self, allowed: bool) -> Dict[str, Any]:
        """The app sets this from the microphone permission."""
        def go():
            self._app.group_calls.auto_join = bool(allowed)
            return bool(allowed)
        return self._group_call(go)

    def start_group_call(self, room: str) -> Dict[str, Any]:
        return self._group_call_outcome(lambda: self._app.group_calls.start(room))

    def join_group_call(self, room: str) -> Dict[str, Any]:
        return self._group_call_outcome(lambda: self._app.group_calls.join(room))

    def pause_group_call(self) -> Dict[str, Any]:
        def go():
            try:
                return self._app.group_calls.pause()
            except ValueError as exc:
                raise GroupErrorAlias(str(exc))
        return self._group_call(go)

    def hangup_group_call(self) -> Dict[str, Any]:
        return self._group_call(lambda: self._app.group_calls.hangup())

    def group_call_state(self, room: str) -> Dict[str, Any]:
        return self._group_call(lambda: self._app.group_calls.status(room))

    def _group_call_outcome(self, fn) -> Dict[str, Any]:
        def go():
            code = fn()
            if code != "ok":
                raise GroupErrorAlias(code)
            return code
        return self._group_call(go)

    def invite_to_group(self, room: str, peer: str) -> Dict[str, Any]:
        """Invite over OTRv4+; if there is no session with them yet, one is
        started and the invite goes when it is up (value "waiting_for_otr")."""
        result = self._group_call(self._app.invite_when_ready, room, peer)
        if result.get("ok") and result.get("value") in ("waiting_for_otr",
                                                        "waiting_for_contact"):
            result["code"] = result["value"]
        return result

    def accept_group_invite(self, room: str, password: str = "") -> Dict[str, Any]:
        """Join the room, then answer the invitation over OTRv4+.

        A password-protected room uses the password the inviter sent with the
        invitation, or [password] when the user typed one. Without either,
        `group_password_needed` asks the UI to prompt, rather than the join
        failing with "not_authorized"."""
        nick = self._profile.jid.split("@", 1)[0]
        try:
            pw = password or self._app.groups.invite_password(room)
        except Exception:
            pw = password
        joined = self.join_room(room, nick, pw) if pw else self.join_room(room, nick)
        if not joined.get("ok"):
            if joined.get("code") == "not_authorized":
                return dict(joined, code="group_password_needed",
                            detail=("This group's room has a password. Enter it "
                                    "(ask whoever invited you)." if not pw else
                                    "That password was not accepted. Try again."))
            return joined
        return self._group_call(self._app.groups.accept, room)

    def decline_group_invite(self, room: str) -> Dict[str, Any]:
        return self._group_call(self._app.groups.decline, room)

    def remove_group_member(self, room: str, member: str) -> Dict[str, Any]:
        return self._group_call(self._app.groups.remove, room, member)

    def remove_failed_group_members(self, room: str) -> Dict[str, Any]:
        """The creator removes everyone whose verification failed, in one
        commit (owner, 2026-10-25). `value`: who was removed."""
        return self._group_call(self._app.groups.remove_failed, room)

    def _on_room_not_persistent(self, room: str) -> None:
        """The service will delete this secure group's room when the last
        member leaves. Said on screen: the group would otherwise vanish the
        first time everybody is offline, with no clue why."""
        try:
            from .events import ErrorOccurred
            self._app._emit(ErrorOccurred(peer=room, code="room_not_persistent",
                                          detail=""))
        except Exception:
            pass

    def _on_room_destroyed(self, room: str) -> None:
        """The room is gone (its owner destroyed it, XEP-0045 <destroy>, or a
        rejoin found it gone). Device report, 2026-10-24: other members were
        left in it. Every room, secure or plain, is forgotten here -- by the
        bridge and by the transport, so nothing sends to it or rejoins it (a
        join would create it again) -- and the app is told to remove it."""
        room = str(room or "").split("/", 1)[0].lower()
        if not room:
            return
        secure = False
        groups = getattr(self._app, "groups", None)
        if groups is not None:
            try:
                secure = bool(groups.on_room_destroyed(room))   # emits "deleted"
            except Exception:
                _TRACE.record("groups", "destroy_handling_failed", "warning")
        try:
            self._app._rooms.discard(room)
        except Exception:
            pass
        forget = getattr(self._transport, "forget_room", None)
        if forget is not None:
            try:
                forget(room)
            except Exception:
                pass
        _TRACE.record("muc", "room_destroyed", "info", secure=secure)
        if not secure:
            try:
                from .events import GroupChanged
                self._app._emit(GroupChanged(peer=room, change="room_deleted"))
            except Exception:
                pass

    def delete_secure_group(self, room: str) -> Dict[str, Any]:
        """Delete a secure group for everyone: destroy its room (the service
        allows only the owner, the group's creator), which tells the members
        in it; one who was away finds it gone on return. Then our copy goes."""
        result = self.destroy_room(room, "secure group deleted")
        if result.get("ok"):
            self._on_room_destroyed(room)
        elif (result.get("code") in ("forbidden", "not_allowed")
              and not result.get("from_admin")):
            # The service's refusal of a destroy is about ownership; its
            # generic sentence for "forbidden" ("banned") is not. (What the
            # admin route said, when it ran, is kept.)
            result = dict(result, detail="Only the group's creator (the room's "
                          "owner) can delete it for everyone. Leave it instead "
                          "to remove it from this phone.")
        elif result.get("code") == "item_not_found":
            # Already gone on the server: end our copy too.
            self._on_room_destroyed(room)
            result = dict(result, ok=True, code="ok",
                          detail="The group's room was already gone; removed here.")
        return result

    def leave_secure_group(self, room: str) -> Dict[str, Any]:
        """Forget the group's keys here, then leave the room."""
        result = self._group_call(self._app.groups.leave, room)
        self.leave_room(room, self._profile.jid.split("@", 1)[0])
        return result

    def verify_group_members(self, room: str) -> Dict[str, Any]:
        """Send our group key to each member over OTRv4+ (see
        SecureGroups.verify_members). `detail` says who still needs SMP."""
        result = self._group_call(self._app.groups.verify_members, room)
        if not result.get("ok"):
            return result
        status = result.get("value") or {}
        need_smp = sorted(j for j, s in status.items() if s == "sent")
        no_session = sorted(j for j, s in status.items() if s == "no_session")
        parts = []
        if need_smp:
            parts.append("Your key went to %s; you are verified with each of them "
                         "once you have done SMP together (Verify in their chat)."
                         % ", ".join(need_smp))
        if no_session:
            parts.append("No encrypted session yet with %s: open their chat, then "
                         "verify with SMP." % ", ".join(no_session))
        if not parts:
            parts.append("Every member is verified: group calls are possible.")
        result["detail"] = " ".join(parts)
        result["value"] = None
        return result

    def group_members(self, room: str) -> Dict[str, Any]:
        return self._group_call(self._app.groups.members, room)

    def group_invites(self) -> Dict[str, Any]:
        return self._group_call(self._app.groups.pending_invites)

    def secure_groups(self) -> Dict[str, Any]:
        return self._group_call(self._app.groups.rooms)
