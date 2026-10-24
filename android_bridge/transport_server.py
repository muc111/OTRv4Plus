# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""What this account may do on its server, over the XMPP transport.

A mixin of XmppTransport (transport.py): whether the server archives
history, whether we are its admin, room moderation and bans, this
account's other signed-in sessions, changing the password, and our
standing in each room."""
from __future__ import annotations

import asyncio
import json
import time
from typing import Any, Dict

import otrv4plus_muc as _muc

from .trace import TRACE as _TRACE
from .transport_base import CALL_TIMEOUT, CONNECT_TIMEOUT


class ServerMixin:
    """Server-side abilities of this account. Mixed into XmppTransport."""

    #: disco#info features that bear on deleting history from a SERVER.
    #: Read, never acted on: see `archive_support`.
    ARCHIVE_FEATURES = {
        "urn:xmpp:mam:2": "mam",                       # XEP-0313 archive
        "urn:xmpp:mam:1": "mam",
        "urn:xmpp:message-retract:1": "retract",       # XEP-0424
        "urn:xmpp:message-retract:0": "retract",
        "urn:xmpp:message-moderate:1": "moderate",     # XEP-0425 (rooms)
        "urn:xmpp:message-moderate:0": "moderate",
    }

    def archive_support(self, jid: str = "") -> "tuple[str, str, dict]":
        """What [jid] -- our own account when empty, or a room -- advertises
        about keeping and deleting history.

        A QUESTION, NOT A CAPABILITY. No XEP lets a client delete a server's
        message archive: XEP-0313 (MAM) defines query only; XEP-0424
        retraction asks the other side's clients to hide one message by its
        archive id, which this app does not record; XEP-0425 moderation is
        per message and for room moderators. So this reports, and "Delete
        chat" tells the user what the server said, instead of implying the
        server's copy went with the local one.
        """
        return self._room_call(self._archive_support(jid))

    async def _archive_support(self, jid: str):
        target = jid or str(self._client.boundjid.bare)
        info = await self._client["xep_0030"].get_info(
            jid=target, timeout=CALL_TIMEOUT)
        found = {"mam": False, "retract": False, "moderate": False}
        for feature in info["disco_info"]["features"]:
            key = self.ARCHIVE_FEATURES.get(str(feature))
            if key:
                found[key] = True
        return found

    def room_standing(self, room: str, nick: str) -> "tuple[str, str, dict]":
        """Our affiliation and role in a room we are already in."""
        try:
            return ("ok", _muc.CODES["ok"], self._room_standing(room, nick))
        except Exception as exc:
            code, detail = _muc.classify(exc)
            return (code, detail, {})

    def owned_rooms(self) -> "tuple[str, str, list]":
        """The rooms we are in that the service lets us delete: those it
        reports us as OWNER of (the creator; Prosody reports a server admin
        as owner too): only they get a Delete button, since it fails for
        anyone else. Read from the room roster: no network, and a room we are
        not in is never listed."""
        try:
            owned = []
            for room, nick in list(getattr(self, "_room_nicks", {}).items()):
                try:
                    if self._room_standing(room, nick).get("destroy"):
                        owned.append(room)
                except Exception:
                    continue
            return ("ok", _muc.CODES["ok"], sorted(owned))
        except Exception as exc:
            code, detail = _muc.classify(exc)
            return (code, detail, [])

    #: XEP-0133 (service administration) command nodes. A server lists
    #: them in its ad-hoc commands (XEP-0050) only to its admins.
    ADMIN_COMMAND_PREFIX = "http://jabber.org/protocol/admin#"

    def server_admin(self) -> "tuple[str, str, bool]":
        """Whether this account administers its server, so the UI can offer
        moderation (e.g. deleting other people's rooms). Read from the
        server's command list (Prosody's mod_admin_adhoc lists XEP-0133
        commands to admins only); asked once per connection. The service
        still decides every destroy."""
        cached = getattr(self, "_server_admin", None)
        if cached is not None:
            return ("ok", _muc.CODES["ok"], cached)
        code, detail, value = self._room_call(self._ask_server_admin())
        if code == "ok":
            self._server_admin = bool(value)
            return (code, detail, bool(value))
        return (code, detail, False)

    async def _ask_server_admin(self) -> bool:
        disco = self._client["xep_0030"]
        domain = str(self._client.boundjid.domain)
        items = await disco.get_items(jid=domain,
                                      node="http://jabber.org/protocol/commands",
                                      timeout=CALL_TIMEOUT)
        return any(str(node or "").startswith(self.ADMIN_COMMAND_PREFIX)
                   for _jid, node, _name in items["disco_items"].get_items())

    # -- moderation (server admins; prosody/mod_otrv4plus_moderation.lua) ----
    #
    # Ban for N days or for good, and unban, from a user's profile: XEP-0050
    # commands the SERVER offers to its admins only; this side never decides
    # who is one.

    MODERATION_NS = "https://otrv4plus.i2p/protocol/admin#"

    @property
    def banned_text(self) -> str:
        return getattr(self, "_banned", "")

    def moderation(self, op: str, account: str = "", days: int = 0,
                   reason: str = "") -> "tuple[str, str, dict]":
        """Run one moderation command: "status", "ban", "unban", "rooms" or
        "destroy" (`account` is then the room).

        value: {"available": bool, "banned": bool, "until": int (0 = for
        good, -1 = not banned), "message": str, "rooms": [dict]}."""
        return self._room_call(self._moderation(op, account, days, reason))

    async def _moderation(self, op, account, days, reason):
        client = self._client
        domain = str(client.boundjid.domain)
        items = await client["xep_0030"].get_items(
            jid=domain, node=self.COMMANDS_NODE, timeout=CALL_TIMEOUT)
        offered = {str(node) for _jid, node, _name in items["disco_items"].get_items()}
        node = self.MODERATION_NS + {"status": "ban-status", "ban": "ban-user",
                                     "unban": "unban-user", "rooms": "list-rooms",
                                     "destroy": "destroy-room"}[op]
        out = {"available": node in offered, "banned": False, "until": -1,
               "message": "", "rooms": [], "refused": False}
        if not out["available"]:
            out["message"] = ("The server does not offer moderation to this "
                              "account (an admin needs mod_otrv4plus_moderation "
                              "on the server).")
            return out
        values = {"accountjid": account}
        if op == "ban":
            values.update(days=str(int(days)), reason=reason[:200])
        elif op == "destroy":
            # `account` carries the room's address for this one.
            values = {"roomjid": account, "reason": reason[:200]}
        done = await self._run_command(domain, node, values if op != "rooms" else None)
        command = done["command"]
        notes = command["notes"] or []
        for kind, text in notes:
            # The server's own sentence (mod_otrv4plus_moderation's): shown
            # to the admin who asked, never traced.
            out["message"] = str(text)[:300]
            if kind == "error":
                out["refused"] = True
                return out
        try:
            fields = command["form"].get_fields()
        except Exception:
            fields = {}
        if "banned" in fields:
            out["banned"] = str(fields["banned"]["value"]).lower() in ("1", "true")
            raw = str(fields["until"]["value"] or "") if "until" in fields else ""
            out["until"] = int(raw) if raw.isdigit() and out["banned"] else -1
        if "rooms" in fields:
            lines = fields["rooms"]["value"] or []
            if isinstance(lines, str):
                lines = lines.split("\n")
            for line in lines:
                try:
                    out["rooms"].append(json.loads(line))
                except Exception:
                    continue
        return out

    async def _run_command(self, domain, node, values):
        """Execute an ad-hoc command; fill its form from `values` (None: no
        form expected) and complete it."""
        commands = self._client["xep_0050"]
        first = await commands.send_command(domain, node, action="execute",
                                            timeout=CALL_TIMEOUT)
        if values is None or first["command"]["status"] == "completed":
            return first
        form = first["command"]["form"]
        submit = self._client["xep_0004"].make_form(ftype="submit")
        for var, field in form.get_fields().items():
            if not var:
                continue
            value = values.get(var, field["value"])
            submit.add_field(var=var, ftype=field["type"], value=value)
        return await commands.send_command(
            domain, node, action="complete", payload=submit,
            sessionid=first["command"]["sessionid"], timeout=CALL_TIMEOUT)

    # -- our account signed in somewhere else ---------------------------------
    #
    # One account, one device. XMPP lets an account have several resources
    # at once, and the server sends each of them the
    # others' presence (RFC 6121 4.2.2 / 4.4.2), so another session of OUR
    # account is visible here without asking anyone. What a client can do is
    # say so, and -- for a server admin -- end it (XEP-0133). Stopping it for
    # good is the server's job: see docs/SECURITY_SESSIONS.md.

    END_SESSION_NODE = ADMIN_COMMAND_PREFIX + "end-user-session"

    def _note_own_session(self, stanza, online: bool) -> bool:
        """Track a presence from another resource of our own account.

        Returns True when the stanza was one. Only full JIDs of the SAME bare
        JID, other than this session's resource, are counted."""
        try:
            full = str(stanza["from"])
        except Exception:
            return False
        bare, _, resource = full.partition("/")
        own_bare = self._profile.jid.split("/", 1)[0].lower()
        if not resource or bare.lower() != own_bare:
            return False
        if resource == self._own_resource():
            return False
        sessions = self.__dict__.setdefault("_own_sessions", {})
        before = len(sessions)
        if online:
            sessions.setdefault(resource, time.time())
        else:
            sessions.pop(resource, None)
        if len(sessions) != before:
            # A count only: a resource name can identify a device.
            _TRACE.record("account", "other_sessions", "warning" if sessions
                          else "info", count=len(sessions))
        return True

    def other_sessions(self) -> "tuple[str, str, list]":
        """Other sessions of our account the server told us about, oldest
        first: [{"resource", "since"}]. Since is when WE saw it (epoch s)."""
        if not self.is_connected:
            return ("network", _muc.CODES["network"], [])
        sessions = dict(getattr(self, "_own_sessions", {}) or {})
        out = [{"resource": r, "since": int(t)} for r, t in
               sorted(sessions.items(), key=lambda kv: kv[1])]
        return ("ok", _muc.CODES["ok"], out)

    def end_other_sessions(self) -> "tuple[str, str, int]":
        """Sign out every OTHER session of our account (server admins only).

        XEP-0133 end-user-session with each other session's FULL JID, never
        the bare one: Prosody ends only the named resource when one is given,
        and every session -- this one too -- for a bare JID. Ours is never in
        the list. The server decides whether we may; a non-admin is refused.
        Does not stop them signing in again: that needs a new password."""
        sessions = dict(getattr(self, "_own_sessions", {}) or {})
        own = self._own_resource()
        bare = self._profile.jid.split("/", 1)[0]
        targets = ["%s/%s" % (bare, r) for r in sessions if r and r != own]
        if not targets:
            return ("ok", _muc.CODES["ok"], 0)
        code, detail, value = self._room_call(self._end_sessions(targets))
        _TRACE.record("account", "end_other_sessions",
                      "info" if code == "ok" else "warning", code=code,
                      count=len(targets))
        if code == "ok":
            for t in targets:
                sessions.pop(t.partition("/")[2], None)
            self._own_sessions = sessions
            return (code, detail, len(targets))
        return (code, detail, 0)

    #: What each refusal of a password change means (XEP-0077 §3.3).
    PASSWORD_REFUSALS = {
        "not-authorized": ("refused", "The server does not let this account "
                           "change its password. Ask the server's admin."),
        "forbidden": ("refused", "The server does not let this account "
                      "change its password. Ask the server's admin."),
        "not-allowed": ("refused", "The server does not let this account "
                        "change its password. Ask the server's admin."),
        "not-acceptable": ("not_acceptable", "The server did not accept that "
                           "password. Try a longer one."),
        "bad-request": ("not_acceptable", "The server did not accept that "
                        "password. Try a longer one."),
        "service-unavailable": ("unsupported", "This server does not offer "
                                "password changes (Prosody: mod_register)."),
        "feature-not-implemented": ("unsupported", "This server does not "
                                    "offer password changes (Prosody: "
                                    "mod_register)."),
    }

    def change_password(self, current_password: str,
                        new_password: str) -> "tuple[str, str, None]":
        """Change this account's password on the server (XEP-0077 §3.3).

        [current_password] is checked here, in constant time, against the one
        this stream signed in with, and is never sent: XEP-0077 trusts the
        signed-in stream, so without this anyone at an unlocked device could
        lock its owner out. The new password goes only to the server, over the
        stream already encrypted to it. Neither is traced. On success it
        replaces the one this transport signs in with on a reconnect; the
        caller saves it wherever else it is remembered.
        """
        import hmac
        from otrv4plus_registration import MIN_PASSWORD
        if not self.is_connected:
            return ("network", _muc.CODES["network"], None)
        if not hmac.compare_digest((current_password or "").encode(),
                                   (self._password or "").encode()):
            return ("wrong_current", "That is not your current password.", None)
        if len(new_password or "") < MIN_PASSWORD:
            return ("not_acceptable", "The new password must be at least %d "
                    "characters." % MIN_PASSWORD, None)
        code, detail = "ok", "Password changed."
        try:
            loop = self._ensure_loop()
            future = asyncio.run_coroutine_threadsafe(
                self._change_password(new_password), loop)
            future.result(timeout=CALL_TIMEOUT + 5)
        except BaseException as exc:
            cond = ""
            try:
                cond = str(exc.iq["error"]["condition"] or "")
            except Exception:
                pass
            if cond in self.PASSWORD_REFUSALS:
                code, detail = self.PASSWORD_REFUSALS[cond]
            elif type(exc).__name__ in ("IqTimeout", "TimeoutError"):
                code, detail = "timeout", _muc.CODES["timeout"]
            else:
                code, detail = "unknown", ("The password was not changed "
                                           "(%s)." % (cond or "no answer"))
        _TRACE.record("account", "change_password",
                      "info" if code == "ok" else "warning", code=code)
        if code == "ok":
            self._password = new_password
            client = self._client
            if client is not None:
                try:
                    client.password = new_password
                except Exception:
                    pass
        return (code, detail, None)

    async def _change_password(self, new_password: str) -> None:
        # Built by hand: the signed-in client does not load slixmpp's
        # xep_0077, whose stream-feature handler belongs to account creation
        # (`_enable_registration`) and must not touch a sign-in.
        from slixmpp.xmlstream import ET
        client = self._client
        ns = "jabber:iq:register"
        query = ET.Element("{%s}query" % ns)
        ET.SubElement(query, "{%s}username" % ns).text = client.boundjid.user
        ET.SubElement(query, "{%s}password" % ns).text = new_password
        iq = client.Iq()
        iq["type"] = "set"
        iq["to"] = client.boundjid.domain
        iq.append(query)
        await iq.send(timeout=CALL_TIMEOUT)

    async def _end_sessions(self, targets: "list[str]") -> int:
        client = self._client
        domain = str(client.boundjid.domain)
        commands = client["xep_0050"]
        first = await commands.send_command(
            domain, self.END_SESSION_NODE, action="execute",
            timeout=CALL_TIMEOUT)
        form = first["command"]["form"]
        submit = client["xep_0004"].make_form(ftype="submit")
        for var, field in form.get_fields().items():
            if var == "accountjids":
                submit.add_field(var=var, ftype="jid-multi", value=targets)
            elif var:
                submit.add_field(var=var, ftype=field["type"],
                                 value=field["value"])
        done = await commands.send_command(
            domain, self.END_SESSION_NODE, action="complete", payload=submit,
            sessionid=first["command"]["sessionid"], timeout=CALL_TIMEOUT)
        notes = done["command"]["notes"] or []
        if any(kind == "error" for kind, _text in notes):
            raise PermissionError("end-user-session refused")
        return len(targets)

    def joined_rooms(self) -> "tuple[str, str, list]":
        """The rooms this session is in, as slixmpp has them."""
        try:
            rooms = self._client["xep_0045"].get_joined_rooms()
            return ("ok", _muc.CODES["ok"], [str(r) for r in rooms])
        except Exception as exc:
            code, detail = _muc.classify(exc)
            return (code, detail, [])

    def _room_standing(self, room: str, nick: str) -> Dict[str, Any]:
        """Read affiliation and role out of slixmpp's room roster.

        Both, always, and never one inferred from the other: they are
        different questions -- see `otrv4plus_muc` -- and an owner who joined
        as a visitor cannot speak.
        """
        muc = self._client["xep_0045"]

        def prop(name):
            try:
                return str(muc.get_jid_property(room, nick, name) or "")
            except Exception:
                return ""

        affiliation = prop("affiliation") or _muc.NONE
        role = prop("role") or _muc.NO_ROLE
        rights = _muc.privileges(affiliation, role)
        out = rights.as_dict()
        out["room"] = str(room)
        out["nick"] = str(nick)
        return out

    def _room_call(self, coro) -> "tuple[str, str, Any]":
        """Run a room operation and classify whatever it does.

        Every failure becomes a `(code, detail)` from `otrv4plus_muc`, and the
        detail is chosen from that module's table rather than built from the
        exception -- a MUC error stringifies to something carrying the room,
        the service and the nickname.

        NOT `_run`. That one flattens every exception into
        `TransportError("unexpected_error", type(exc).__name__)`, which is
        right for a send and destroys exactly what matters here: the condition
        inside the stanza is how "that nickname is taken" is told apart from
        "you are banned", and a type name is neither.
        """
        if not self.is_connected:
            coro.close()
            return ("network", _muc.CODES["network"], None)
        try:
            loop = self._ensure_loop()
            future = asyncio.run_coroutine_threadsafe(coro, loop)
            value = future.result(timeout=CONNECT_TIMEOUT)
        except TimeoutError:
            # Builtin TimeoutError: nothing raised, the work simply never
            # finished. Cancelled rather than abandoned, so a join nobody is
            # waiting on stops occupying the room's presence.
            future.cancel()
            return ("timeout", _muc.CODES["timeout"], None)
        except BaseException as exc:
            # BaseException for CancelledError, which does not derive from
            # Exception on the asyncio side. `classify` is total.
            code, detail = _muc.classify(exc)
            return (code, detail, None)
        return ("ok", _muc.CODES["ok"], value)
