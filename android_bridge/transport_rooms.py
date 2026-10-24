# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Rooms over the XMPP transport: finding, joining, creating, leaving and
destroying them, and their messages and occupants.

A mixin of XmppTransport (transport.py). Ordinary MUC rooms only; a secure
group's encryption is groups.py, which rides on these rooms."""
from __future__ import annotations

import asyncio
import time
from typing import Callable, Dict, Optional

import otrv4plus_muc as _muc

from .trace import TRACE as _TRACE
from .transport_base import _log, CONNECT_TIMEOUT, CALL_TIMEOUT, TransportError



def _room_was_created(join_result) -> bool:
    """Whether `join_muc_wait`'s answer says the join created the room
    (XEP-0045 status 201)."""
    try:
        own = join_result[0] if isinstance(join_result, tuple) else join_result
        codes = own["muc"]["status_codes"]
        return 201 in {int(c) for c in codes}
    except Exception:
        return False


def _room_occupant_count(info) -> Optional[int]:
    """`muc#roominfo_occupants` from a room's disco#info, or None.

    Read from the XML rather than through a form plugin, so it works whether
    or not XEP-0128 is registered. Only a plain non-negative integer is
    accepted; anything else is "not given"."""
    try:
        xml = info["disco_info"].xml
    except Exception:
        try:
            xml = info.xml
        except Exception:
            return None
    for form in xml.iter("{jabber:x:data}x"):
        for field in form.iter("{jabber:x:data}field"):
            if field.get("var") != "muc#roominfo_occupants":
                continue
            value = field.find("{jabber:x:data}value")
            text = (value.text or "").strip() if value is not None else ""
            if text.isdigit() and len(text) <= 7:
                return int(text)
            return None
    return None


def _occupant_jid(real: str) -> str:
    """A room occupant's real JID, bare and folded, or "" when the room did
    not reveal one or it is not a plausible address."""
    bare = str(real or "").split("/", 1)[0].strip().lower()
    if not bare or len(bare) > 320 or bare.count("@") != 1 or any(c.isspace() for c in bare):
        return ""
    local, _, domain = bare.partition("@")
    return bare if local and domain and "." in domain else ""


class RoomsMixin:
    """Room discovery, membership, messages and occupants. Mixed into XmppTransport."""

    def set_room_rejected_handler(self,
                                  handler: Optional[Callable[[str, str], None]]) -> None:
        """`handler(room, condition)` when the server bounces a message we
        sent to a room we are in (see `_on_message_error`)."""
        self._on_room_rejected = handler

    def set_room_handler(self, handler: Optional[Callable[..., None]]) -> None:
        """`handler(room, nick, body, timestamp)` for each room message."""
        self._on_room_message = handler

    def set_room_joined_handler(self,
                                handler: Optional[Callable[[str], None]]) -> None:
        """`handler(room)` when a join succeeds, BEFORE any of that room's
        messages are delivered. The app registers the room here, so nothing
        the room sends on arrival can reach it as an unknown room."""
        self._on_room_joined = handler

    #: Messages held per joining room. A room's history on join is bounded by
    #: the service (Prosody: 20 by default); this caps a hostile one.
    MAX_HELD_ROOM_MESSAGES = 200

    @staticmethod
    def _room_key(room) -> str:
        return str(room).split("/", 1)[0].strip().lower()

    def _held(self) -> Dict[str, list]:
        # getattr: several tests build a transport without __init__.
        held = getattr(self, "_joining", None)
        if held is None:
            held = self._joining = {}
        return held

    def _begin_join(self, room) -> None:
        """Hold this room's messages until `_end_join`. Idempotent."""
        self._held().setdefault(self._room_key(room), [])

    def _end_join(self, room, ok: bool) -> None:
        """Finish a join. On success: register the room with the app (on
        this, the loop thread), THEN deliver what arrived meanwhile, in
        order. On failure: drop it -- we are not in that room."""
        held = self._held().pop(self._room_key(room), None)
        if not ok:
            return
        handler = getattr(self, "_on_room_joined", None)
        if handler is not None:
            try:
                handler(str(room))
            except Exception:
                _log.warning("the room-joined handler raised")
        for args, kwargs in held or ():
            self._deliver_room_message(*args, **kwargs)
        # Then what the room archived while we were away (XEP-0313).
        after = getattr(self, "_room_after_join", None)
        if after is not None:
            after(str(room))

    def _deliver_room_message(self, *args, **kwargs) -> None:
        if getattr(self, "_on_room_message", None) is None:
            return
        try:
            try:
                self._on_room_message(*args, **kwargs)
            except TypeError:
                # A handler that predates room ids takes no `item`.
                if "item" not in kwargs:
                    raise
                item = kwargs.get("item")
                kwargs = {k: v for k, v in kwargs.items() if k != "item"}
                # Never an action shown as if it were text.
                if args[2] and not getattr(item, "action", ""):
                    self._on_room_message(*args, **kwargs)
        except Exception:
            _log.warning("the room message handler raised")

    @classmethod
    def _clean(cls, text: str, limit: int) -> str:
        """Drop control characters (other than newline and tab) and cap length.

        A nickname and a body are chosen by other people. Neither may carry
        a bidi override or a terminal escape into a screen that renders it.
        """
        out = []
        for ch in str(text or "")[:limit]:
            code = ord(ch)
            if ch in "\n\t" or (code >= 0x20 and code != 0x7F
                                  and not 0x202A <= code <= 0x202E
                                  and not 0x2066 <= code <= 0x2069):
                out.append(ch)
        return "".join(out)

    def _our_nick(self, room: str) -> str:
        """Our nickname in *room*, or "".

        slixmpp keeps it as `our_nicks[pfrom][room]` -- TWO levels, with
        pfrom None for a client -- and the room key may be a JID or a string
        in whatever case it was joined with. Reading one level (as this
        did) always found nothing, so our own reflected room messages were
        shown again as if somebody else had sent them: "hello" from Alice,
        on Alice's phone. The nickname we joined with is also recorded here
        on every successful join, as the first answer.
        """
        want = str(room).split("/", 1)[0].lower()
        mine = getattr(self, "_room_nicks", {}).get(want)
        try:
            table = self._client["xep_0045"].our_nicks
        except Exception:
            return mine or ""

        def scan(mapping):
            for key, value in dict(mapping or {}).items():
                if isinstance(value, dict):
                    found = scan(value)
                    if found:
                        return found
                elif str(key).split("/", 1)[0].lower() == want and value:
                    return str(value)
            return ""

        try:
            # slixmpp's current nickname wins: the service may have changed it.
            return scan(table) or mine or ""
        except Exception:
            return mine or ""

    def _on_groupchat(self, stanza) -> None:
        """One room message, up to the handler. Our own echo is dropped.

        XEP-0045 §7.2.3 reflects every message back to its sender. The UI
        already shows what we sent, so the reflection would be a duplicate.
        A subject change carries no body and is skipped.
        """
        if self._on_room_message is None:
            return
        try:
            sender = stanza["from"]
            room = str(sender.bare)
            nick = self._clean(str(sender.resource), self.MAX_NICK)
            body = self._clean(stanza["body"] or "", self.MAX_ROOM_BODY)
        except Exception:
            _log.warning("could not read a room message")
            return
        if not body or not nick:
            return
        own = nick == self._our_nick(room)
        # A <delay> on a room message is the room replaying its history as
        # we join (XEP-0045 §7.2.15): "history", not news. Read from the XML:
        # slixmpp's stanza["delay"] needs the xep_0203 plugin, which is not
        # loaded, and silently reads as no delay at all.
        stamp = 0.0
        try:
            delay = stanza.xml.find("{urn:xmpp:delay}delay")
        except Exception:
            delay = None
        history = delay is not None
        if history:
            import otrv4plus_roomsync as _RS
            stamp = _RS.parse_stamp(delay.get("stamp") or "") or 0.0
        try:
            item = self._room_item(stanza.xml, "history" if history else "live")
        except Exception:
            item = None
        # Our own LIVE reflection is not shown again -- except a secure
        # group's MLS frames, which need it: a commit learns it won the epoch
        # by coming back first (android_bridge.groups). A plain one goes up
        # only to say which id the room gave our message (its stanza-id),
        # which is what reactions and deletions in a room name.
        #
        # Our own message in the room's HISTORY is not an echo: it is what we
        # said before this session (before signing out, or on another device),
        # so it is shown and our corrections in it applied.
        if own and not history and not body.startswith(("?OTRv4MLS1:", "?OTRv4F|")):
            if item is not None and item.own_id and item.stanza_id:
                self._room_route(room, nick, "", item.when, True, item)
            return
        if own:
            args, kwargs = (room, nick, body, stamp or time.time()), {"own": True}
        else:
            args, kwargs = (room, nick, body, stamp or time.time()), {}
        if item is not None:
            kwargs["item"] = item
        held = self._held().get(self._room_key(room))
        if held is not None:
            # Our join is still completing: hold it, bounded, for _end_join.
            if len(held) < self.MAX_HELD_ROOM_MESSAGES:
                held.append((args, kwargs))
            return
        self._deliver_room_message(*args, **kwargs)

    def send_room_message(self, room: str, body: Optional[str], volatile: bool = False,
                          message_id: str = "", elements=None) -> None:
        """Send plaintext to a room we are in. Raises TransportError.

        `volatile`: with a no-store hint (XEP-0334), so the room keeps it out
        of its history (a secure group's file pieces). `message_id`: the id
        (and XEP-0359 origin-id) a person's message carries, so replies,
        corrections and reactions can name it. `elements`: a plain room
        action's XEP elements (otrv4plus_actions); `body` may then be None
        (a reaction has none)."""
        if not self.is_connected:
            raise TransportError("not_connected", "not connected")
        self._send_now(self._send_room(room, body, volatile, message_id, elements),
                       CALL_TIMEOUT)

    async def _send_room(self, room: str, body: Optional[str], volatile: bool = False,
                         message_id: str = "", elements=None) -> None:
        if not volatile and not message_id and not elements:
            self._client.send_message(mto=room, mbody=body, mtype="groupchat")
            return
        msg = self._client.make_message(mto=room, mbody=body, mtype="groupchat")
        if message_id:
            msg["id"] = message_id
        for el in self._room_extras(message_id, elements):
            msg.xml.append(el)
        if volatile:
            msg.append(_muc.no_store_hint())
        msg.send()

    def room_occupants(self, room: str) -> "tuple[str, str, list]":
        """Who is in a room: `[{nick, role, affiliation}]`, moderators first."""
        return self._room_call(self._room_occupants(room))

    async def _room_occupants(self, room: str):
        muc = self._client["xep_0045"]
        order = {_muc.MODERATOR: 0, _muc.PARTICIPANT: 1, _muc.VISITOR: 2}
        people = []
        for nick in list(muc.get_roster(room) or []):
            def prop(name, nick=nick):
                try:
                    return str(muc.get_jid_property(room, nick, name) or "")
                except Exception:
                    return ""
            people.append({
                "nick": self._clean(nick, self.MAX_NICK),
                "role": prop("role") or _muc.NO_ROLE,
                "affiliation": prop("affiliation") or _muc.NONE,
                # The real address, ONLY when the room service revealed it
                # in their presence (a non-anonymous room such as Welcome,
                # or to a moderator). Never derived from the nickname, which
                # anyone can choose. "" otherwise, and the apps then offer
                # no Add or Message for that person.
                "jid": _occupant_jid(prop("jid")),
            })
        people.sort(key=lambda p: (order.get(p["role"], 3), p["nick"].casefold()))
        return people

    def discover_rooms(self, service: str) -> "tuple[str, str, list]":
        """The public rooms a MUC service lists.

        Only the public ones: disco#items is what a service chooses to
        advertise, and a room configured as hidden is absent by design. An
        empty list is not evidence that a service has no rooms.
        """
        return self._room_call(self._discover_rooms(service))

    #: Rooms whose occupant count is asked for, and how many at once. One
    #: disco#info per room: bounded so a service listing thousands of rooms
    #: costs a few seconds, not a flood.
    ROOM_INFO_LIMIT = 100
    ROOM_INFO_PARALLEL = 8
    ROOM_INFO_TIMEOUT = 8

    async def _discover_rooms(self, service: str):
        disco = self._client["xep_0030"]
        items = await disco.get_items(jid=service, timeout=CALL_TIMEOUT)
        rooms = [{"jid": str(jid), "name": str(name or ""), "occupants": None,
                  "secure": False, "claims_secure": False, "password": False}
                 for jid, _node, name in items["disco_items"].get_items()]
        # XEP-0045 §6.4: disco#info on a room carries a muc#roominfo form
        # with `muc#roominfo_occupants`. Optional for the service, so a room
        # whose count is not given shows none -- never a guessed zero.
        gate = asyncio.Semaphore(self.ROOM_INFO_PARALLEL)

        async def count(room):
            async with gate:
                try:
                    info = await disco.get_info(
                        jid=room["jid"], timeout=self.ROOM_INFO_TIMEOUT)
                    room["occupants"] = _room_occupant_count(info)
                    # What kind of room it is, from the same answer: an
                    # encrypted group (its marker), and whether it has a
                    # password -- shown as icons in the list.
                    try:
                        xml = info["disco_info"].xml
                    except Exception:
                        xml = getattr(info, "xml", None)
                    if xml is not None:
                        # The description is the room's own CLAIM: anybody
                        # can create a room that says it is an encrypted
                        # group. Only a group this account holds is "secure"
                        # (connection._with_held_groups); the claim is shown
                        # as a claim.
                        room["claims_secure"], room["password"] = _muc.room_kind(xml)
                except Exception:
                    pass

        await asyncio.gather(*(count(r) for r in rooms[:self.ROOM_INFO_LIMIT]))
        # Occupied rooms first, then the service's own order.
        order = {id(r): i for i, r in enumerate(rooms)}
        rooms.sort(key=lambda r: (-(r["occupants"] or 0), order[id(r)]))
        return rooms

    def join_room(self, room: str, nick: str,
                  password: str = "") -> "tuple[str, str, dict]":
        """Enter a room, and report what we are in it.

        The privileges come back with the join because they are in the
        presence the service sends us on arrival, and asking for them
        separately would be a second round trip for something we already have.
        """
        return self._room_call(self._join_room(room, nick, password))

    async def _join_room(self, room: str, nick: str, password: str):
        muc = self._client["xep_0045"]
        # ALREADY IN IT. A join presence from an account that is already an
        # occupant is, to the service, a presence update: Prosody runs its
        # password check only for a NEW occupant, so it succeeds with no
        # password -- which read as "joined without being asked". Say what is
        # true instead: we are in it already.
        try:
            joined = {str(r).lower() for r in (muc.get_joined_rooms() or ())}
        except Exception:
            joined = set()
        if str(room).lower() in joined:
            raise TransportError("already_in_room", "already in this room")
        # PASSWORD FIRST. The room's disco#info says whether it is
        # password-protected (muc_passwordprotected). Asking for the
        # password before joining makes the prompt appear whatever the
        # service would do with a password-less join. If the room will not
        # answer disco, the join goes ahead and the service decides.
        if not password and await self._room_wants_password(room):
            raise TransportError("not_authorized", "this room needs a password")
        await self._join_muc(room, nick, password)
        # Kept (memory only) for a rejoin after the room forgets us (XEP-0410).
        self.remember_room_password(room, password)
        self._room_nicks[str(room).split("/", 1)[0].lower()] = nick
        return self._room_standing(room, nick)

    async def _room_wants_password(self, room: str) -> bool:
        try:
            info = await self._client["xep_0030"].get_info(
                jid=room, timeout=CALL_TIMEOUT)
            return "muc_passwordprotected" in {
                str(f) for f in info["disco_info"]["features"]}
        except Exception:
            return False

    async def _join_muc(self, room: str, nick: str, password: str = ""):
        """`join_muc_wait`, plus ANY error presence from the room.

        slixmpp recognises a join refusal only when the error presence
        echoes `<x xmlns='http://jabber.org/protocol/muc'/>`. A service that
        omits it (RFC 6120 allows that) left the join waiting for its full
        timeout and then reported a timeout -- never "wrong password". The
        room's error presence is caught here as well, and raised as the
        PresenceError slixmpp would have raised.
        """
        muc = self._client["xep_0045"]
        loop = asyncio.get_event_loop()
        refused = loop.create_future()
        bare = str(room).split("/", 1)[0].lower()

        def on_error(pres):
            try:
                if str(pres["from"]).split("/", 1)[0].lower() == bare and \
                        not refused.done():
                    refused.set_result(pres)
            except Exception:
                pass

        add = getattr(self._client, "add_event_handler", None)
        remove = getattr(self._client, "del_event_handler", None)
        if add is not None:
            add("presence_error", on_error)
        self._begin_join(room)
        ok = False
        join = asyncio.ensure_future(muc.join_muc_wait(
            room, nick, password=password or None, timeout=CONNECT_TIMEOUT))
        try:
            done, _ = await asyncio.wait(
                [join, refused], timeout=CONNECT_TIMEOUT,
                return_when=asyncio.FIRST_COMPLETED)
            if join in done:
                result = join.result()
                ok = True
                if _room_was_created(result):
                    await self._unlock_new_room(room)
                    self._recreated = self._recreated | {str(room).split("/", 1)[0].lower()}
                return result
            join.cancel()
            if refused in done:
                from slixmpp.exceptions import PresenceError
                raise PresenceError(refused.result())
            raise TimeoutError()
        finally:
            self._end_join(room, ok)
            if not refused.done():
                refused.cancel()
            if remove is not None:
                try:
                    remove("presence_error", on_error)
                except Exception:
                    pass

    #: Called with a room address; True when a room we create (or that a
    #: rejoin re-creates) must be persistent -- a secure group's room. Set by
    #: the controller; None: every room keeps the service's defaults.
    persist_room = None

    #: Rooms a join CREATED (status 201). For a secure group's room on a
    #: rejoin that means it had been deleted; the controller asks.
    _recreated: "set" = set()

    def take_recreated(self, room: str) -> bool:
        """Whether our last join of `room` created it (asked once)."""
        room = str(room).split("/", 1)[0].lower()
        if room in self._recreated:
            self._recreated = self._recreated - {room}
            return True
        return False

    #: Called with a room address when its owner destroyed it (XEP-0045
    #: §10.9). Set by the controller.
    room_destroyed = None

    #: Called with a room address when a secure group's room was asked to be
    #: persistent and the service did not make it so: it will be deleted the
    #: moment the last member leaves. Set by the controller.
    room_not_persistent = None

    async def _check_persistent(self, room: str) -> None:
        """Read the room back (disco#info `muc_persistent`) and report one the
        service did not keep. Accepting the form proves nothing: a service
        that ignores or refuses the field says nothing about it."""
        persistent = False
        try:
            info = await self._client["xep_0030"].get_info(
                jid=room, timeout=CALL_TIMEOUT)
            persistent = "muc_persistent" in {
                str(f) for f in info["disco_info"]["features"]}
        except Exception:
            persistent = False
        if not persistent:
            _TRACE.record("muc", "room_not_persistent", "warning")
            hook = self.room_not_persistent
            if hook is not None:
                try:
                    hook(str(room).lower())
                except Exception:
                    pass

    def _persistent_form(self, room: str):
        form = self._client["xep_0004"].make_form(ftype="submit")
        persist = self.persist_room
        try:
            wanted = bool(persist is not None and persist(str(room).lower()))
        except Exception:
            wanted = False
        form.add_field(var="FORM_TYPE", ftype="hidden", value=self.ROOMCONFIG)
        # Listed: a room the app makes is one people are meant to find in the
        # service's room list. A service whose policy keeps it hidden still
        # creates it.
        form.add_field(var="muc#roomconfig_publicroom", ftype="boolean", value=True)
        if wanted:
            # A secure group's room outlives its occupants: when everybody is
            # offline at once a non-persistent room is destroyed, with the
            # commits in its history, and the first member back re-creates
            # it empty.
            form.add_field(var="muc#roomconfig_persistentroom",
                           ftype="boolean", value=True)
            # Marked, so a room list can show it as an encrypted group.
            form.add_field(var="muc#roomconfig_roomdesc", ftype="text-single",
                           value=_muc.SECURE_GROUP_DESC)
        return form, wanted

    async def _configure_new_room(self, room: str, form=None) -> None:
        """Submit the configuration of a room we just created; a service that
        refuses persistence still gets the defaults, so the room is never
        left locked."""
        muc = self._client["xep_0045"]
        if form is None:
            form, wanted = self._persistent_form(room)
        else:
            wanted = False
        try:
            await muc.set_room_config(room, form, timeout=CALL_TIMEOUT)
        except Exception:
            # A service that refuses a field (public, persistent, the
            # description) still gets the plain defaults: the room is never
            # left locked, and never fails to exist over a listing setting.
            await muc.set_room_config(
                room, self._client["xep_0004"].make_form(ftype="submit"),
                timeout=CALL_TIMEOUT)
        if wanted:
            await self._check_persistent(room)

    async def _unlock_new_room(self, room: str) -> None:
        """A join that CREATED the room (status 201): it stays locked, and
        nobody else can enter, until its owner -- us -- configures it. Seen
        when every member had left a secure group's room and one came back."""
        try:
            await self._configure_new_room(room)
        except Exception:
            pass

    def create_room(self, room: str, nick: str,
                    password: str = "") -> "tuple[str, str, dict]":
        """Create a room and accept the service's default configuration.

        XEP-0045 §10.1.2's "instant room": joining a room that does not exist
        creates it in a locked state, and an owner who sends the empty
        configuration form unlocks it. WITHOUT THAT SECOND STEP THE ROOM STAYS
        LOCKED -- the creator is in it and nobody else can get in, which looks
        exactly like a room that works until somebody is invited.

        The alternative, a full configuration form, is a screen of checkboxes
        in front of somebody who asked for a room. It can come later; a room
        that exists is the thing being asked for here.

        PASSWORD. With [password], the submitted form sets exactly two
        XEP-0045 fields -- `muc#roomconfig_passwordprotectedroom` and
        `muc#roomconfig_roomsecret` -- and the room's disco#info is then read
        back. A service that accepted the form but did not protect the room
        would leave an OPEN room the user believes is closed, so that room is
        destroyed and the create reported as failed (`password_not_applied`).
        The password is never logged, traced or kept here. A room password
        controls who may ENTER; it is not end-to-end encryption -- the server
        still reads the room.
        """
        return self._room_call(self._create_room(room, nick, password))

    ROOMCONFIG = "http://jabber.org/protocol/muc#roomconfig"

    async def _create_room(self, room: str, nick: str, password: str = ""):
        # Messages are held from the join until the room is known to be kept:
        # a room destroyed below for want of its password is never
        # registered with the app, so nothing it said is shown.
        self._begin_join(room)
        ok = False
        try:
            result = await self._create_room_held(room, nick, password)
            ok = True
            return result
        finally:
            self._end_join(room, ok)

    async def _create_room_held(self, room: str, nick: str, password: str = ""):
        muc = self._client["xep_0045"]
        await muc.join_muc_wait(room, nick, timeout=CONNECT_TIMEOUT)
        # The empty form. `set_room_config` with a form carrying no fields is
        # the "accept the defaults" submission §10.1.2 describes. A secure
        # group's room asks to be persistent as well.
        if password:
            # The persistent field too, so a password-protected secure group's
            # room also outlives its occupants.
            form, wanted = self._persistent_form(room)
            form.add_field(var="muc#roomconfig_passwordprotectedroom",
                           ftype="boolean", value=True)
            form.add_field(var="muc#roomconfig_roomsecret",
                           ftype="text-private", value=password)
            try:
                await muc.set_room_config(room, form, timeout=CALL_TIMEOUT)
            except Exception:
                # Refused over a listing or keeping field: the password is
                # what must not be lost, so it goes again on its own (and is
                # read back below either way).
                form = self._client["xep_0004"].make_form(ftype="submit")
                form.add_field(var="FORM_TYPE", ftype="hidden", value=self.ROOMCONFIG)
                form.add_field(var="muc#roomconfig_passwordprotectedroom",
                               ftype="boolean", value=True)
                form.add_field(var="muc#roomconfig_roomsecret",
                               ftype="text-private", value=password)
                await muc.set_room_config(room, form, timeout=CALL_TIMEOUT)
            if wanted:
                await self._check_persistent(room)
        else:
            await self._configure_new_room(room)
        self._room_nicks[str(room).split("/", 1)[0].lower()] = nick
        if password:
            # Kept (memory only): for a rejoin, and for the invitations of a
            # password-protected secure group (groups.ROOMPW).
            self.remember_room_password(room, password)
        if password:
            protected = False
            try:
                info = await self._client["xep_0030"].get_info(
                    jid=room, timeout=CALL_TIMEOUT)
                protected = "muc_passwordprotected" in {
                    str(f) for f in info["disco_info"]["features"]}
            except Exception:
                protected = False
            if not protected:
                try:
                    await muc.destroy(room, reason="password could not be set",
                                      timeout=CALL_TIMEOUT)
                except Exception:
                    pass
                raise TransportError(
                    "password_not_applied",
                    "the service did not password-protect the room")
        return self._room_standing(room, nick)

    def leave_room(self, room: str, nick: str) -> "tuple[str, str, dict]":
        """Leave a room. The room continues to exist without us."""
        return self._room_call(self._leave_room(room, nick))

    async def _leave_room(self, room: str, nick: str):
        muc = self._client["xep_0045"]
        # No nickname from the caller -- "Delete and leave" on the chat list,
        # which never saw the join -- means the one this session joined with.
        # Not joined this session: there is no presence to withdraw, and the
        # server has already dropped us with the old stream.
        nick = nick or self._our_nick(room)
        if nick:
            muc.leave_muc(room, nick)
        getattr(self, "_room_nicks", {}).pop(str(room).split("/", 1)[0].lower(), None)
        return {}

    def forget_room(self, room: str) -> None:
        """Drop what this session keeps about a room that no longer exists:
        our nick in it (what rejoins and room sends key on) and its
        recreated mark. The service already removed us."""
        room = str(room).split("/", 1)[0].lower()
        getattr(self, "_room_nicks", {}).pop(room, None)
        self._recreated = self._recreated - {room}

    def destroy_room(self, room: str,
                     reason: str = "") -> "tuple[str, str, dict]":
        """Delete a room. OWNERS ONLY, and the service is what enforces it.

        `otrv4plus_muc.privileges` is what stops the button being offered to
        somebody who cannot; this does not check, deliberately. A client-side
        permission check that disagreed with the service would be a second
        opinion in a place with no way to be right, and the one that matters
        is the service's.
        """
        return self._room_call(self._destroy_room(room, reason))

    async def _destroy_room(self, room: str, reason: str):
        await self._client["xep_0045"].destroy(room, reason=reason,
                                               timeout=CALL_TIMEOUT)
        return {}
