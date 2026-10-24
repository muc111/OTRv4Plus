# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The OTRv4Plus Welcome room over the XMPP transport: joining it, creating
it on a server that has none, and what the UI shows of it.

A mixin of XmppTransport (transport.py). The room's rules (who is listed,
what it is for) are welcome.py."""
from __future__ import annotations

import asyncio

import otrv4plus_address as _address
import otrv4plus_muc as _muc

from . import welcome as _welcome
from .trace import TRACE as _TRACE
from .transport_base import _log, CALL_TIMEOUT, TransportError


class WelcomeMixin:
    """The Welcome room. Mixed into XmppTransport."""

    # -- the OTRv4Plus Welcome room ---------------------------------------------

    def start_welcome(self, nick: str) -> None:
        """Find and join the Welcome room in the background. Never blocks.

        Called once the stream is up. Joining is an I2P round trip plus the
        room's presences; the caller must not wait for it.
        """
        if not self.is_connected or not nick:
            return
        try:
            loop = self._ensure_loop()
            asyncio.run_coroutine_threadsafe(self._welcome_flow(nick), loop)
        except Exception:
            self._welcome.failed("unexpected_error")

    async def _welcome_flow(self, nick: str) -> None:
        """disco the server -> its MUC services -> their public rooms ->
        the one named ROOM_NAME -> its disco#info -> join. Nothing else is
        asked of anybody: no occupant is queried, no JID is tried."""
        self._welcome.searching()
        try:
            services = await self._discover_services()
            rooms = {}
            for service in services:
                if service.get("category") != "conference":
                    continue
                try:
                    rooms[service["jid"]] = await self._discover_rooms(
                        service["jid"])
                except Exception:
                    rooms[service["jid"]] = []
            room, reason = _welcome.find_room(services, rooms)
            if (room is None and reason == _welcome.NOT_FOUND
                    and _address.shipped_server_address(
                        _address.jid_domain(self._profile.jid))):
                # The project's own server: its operator wants the Welcome
                # room there, so the first account to arrive creates it,
                # as the earlier app did. On any other server the user is
                # asked first (create_welcome), because the room shows every
                # occupant's address.
                _TRACE.record("welcome", "auto_create", "info")
                try:
                    await self._create_welcome(nick)
                    return
                except TransportError as exc:
                    if exc.code != "welcome_address_taken":
                        raise
                    # Another client created it a moment ago and the listing
                    # had not caught up: look again, once.
                    rooms = {s["jid"]: await self._discover_rooms(s["jid"])
                             for s in services
                             if s.get("category") == "conference"}
                    room, reason = _welcome.find_room(services, rooms)
            if room is None:
                self._welcome.not_found(reason)
                _TRACE.record("welcome", reason, "info")
                return
            info = await self._client["xep_0030"].get_info(
                jid=room, timeout=CALL_TIMEOUT)
            features = [str(f) for f in info["disco_info"]["features"]]
            self._welcome.joining(room, features, nick)
            muc = self._client["xep_0045"]
            try:
                await self._join_muc(room, nick)
            except Exception as exc:
                code, _detail = _muc.classify(exc)
                if code != "conflict":
                    raise
                # Our nickname is taken (another of our own resources, or
                # somebody else). One retry with a random suffix: this picks
                # OUR name, it does not probe anybody else's.
                import secrets as _secrets
                nick = "%s-%s" % (nick, _secrets.token_hex(2))
                self._welcome.nick = nick
                await self._join_muc(room, nick)
            self._welcome.joined(nick)
            self._room_nicks[str(room).lower()] = nick
            self._notify_welcome(room)
            # Occupants whose presence arrived before our own self-presence
            # are already in slixmpp's room roster; read them from there.
            for other in list(muc.get_roster(room) or []):
                if other == nick:
                    continue
                real = muc.get_jid_property(room, other, "jid") or ""
                self._welcome.occupant(other, str(real), True)
            _TRACE.record("welcome", "joined", "info",
                          anonymity=self._welcome.props.get("anonymity"))
        except Exception as exc:
            code, _detail = _muc.classify(exc)
            self._welcome.failed(code)
            _TRACE.record("welcome", "failed", "warning", code=code)

    def create_welcome(self, nick: str) -> "tuple[str, str, dict]":
        """Create the OTRv4Plus Welcome room, when the server has none.

        Only on the user's explicit request (the app asks first and says
        what the room reveals). Refuses when a room with ROOM_NAME already
        exists (it is joined instead) or when the chosen address is taken by
        some other room (never taken over). After creating, the room's
        disco#info is read back and every setting the server did NOT apply
        is reported -- a Prosody may refuse `persistent` or `public` to an
        ordinary account, and a room that is not public cannot be found by
        anybody else.

        value: {"room", "created": bool, "missing": [descriptions]}.
        """
        return self._room_call(self._create_welcome(nick))

    async def _create_welcome(self, nick: str):
        disco = self._client["xep_0030"]
        services = await self._discover_services()
        muc_services = [s for s in services if s.get("category") == "conference"]
        if not muc_services:
            raise TransportError("unsupported", "this server offers no rooms")
        rooms = {}
        for service in muc_services:
            try:
                rooms[service["jid"]] = await self._discover_rooms(service["jid"])
            except Exception:
                rooms[service["jid"]] = []
        existing, _reason = _welcome.find_room(muc_services, rooms)
        if existing is not None:
            # Somebody made it since we last looked: join, do not create.
            await self._welcome_flow(nick)
            return {"room": existing, "created": False, "missing": []}
        room = "%s@%s" % (_welcome.ROOM_LOCALPART, muc_services[0]["jid"])
        try:
            await disco.get_info(jid=room, timeout=CALL_TIMEOUT)
            taken = True
        except Exception:
            taken = False
        if taken:
            raise TransportError(
                "welcome_address_taken",
                "a room already uses that address under another name")
        muc = self._client["xep_0045"]
        await self._join_muc(room, nick)
        form = self._client["xep_0004"].make_form(ftype="submit")
        form.add_field(var="FORM_TYPE", ftype="hidden", value=self.ROOMCONFIG)
        for var, ftype, value in _welcome.ROOM_CONFIG:
            form.add_field(var=var, ftype=ftype, value=value)
        await muc.set_room_config(room, form, timeout=CALL_TIMEOUT)
        self._room_nicks[room.lower()] = nick
        missing = []
        features = []
        try:
            info = await disco.get_info(jid=room, timeout=CALL_TIMEOUT)
            features = [str(f) for f in info["disco_info"]["features"]]
            missing = _welcome.missing_features(features)
        except Exception:
            missing = [why for _f, why in _welcome.REQUIRED_FEATURES]
        self._welcome.joining(room, features, nick)
        self._welcome.joined(nick)
        self._notify_welcome(room)
        _TRACE.record("welcome", "created", "info", missing=len(missing))
        return {"room": room, "created": True, "missing": missing}

    def set_welcome_handler(self, handler) -> None:
        """`handler(room)` once the Welcome room is joined, so the app treats
        its traffic as room chat (and delivers it) like any joined room."""
        self._on_welcome = handler

    def _notify_welcome(self, room: str) -> None:
        handler = getattr(self, "_on_welcome", None)
        if handler is None:
            return
        try:
            handler(room)
        except Exception:
            _log.warning("the welcome handler raised")

    def welcome_view(self) -> dict:
        """The Welcome room's state and discoverable people, for the UI."""
        return self._welcome.view(self._profile.jid)
