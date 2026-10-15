# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The transport's half of room ids, room actions and room history.

Mixed into `XmppTransport`. What a room message means -- which message an
action names, who may change what -- is the app's (`OtrApp`), with
`otrv4plus_roomsync`; this only reads stanzas and asks the room's archive.
"""
from __future__ import annotations

import asyncio
import logging
import xml.etree.ElementTree as ET
from typing import List, Optional

import otrv4plus_roomsync as RS
import otrv4plus_sync as S

_log = logging.getLogger(__name__)


class RoomSyncMixin:

    def _room_item(self, xml: ET.Element, source: str = "live") -> Optional[RS.RoomItem]:
        try:
            return RS.parse_room_message(xml, source)
        except Exception:
            return None

    def _room_route(self, room: str, nick: str, body: str, stamp: float,
                    own: bool, item: Optional[RS.RoomItem]) -> None:
        """Deliver, or hold while the room's join completes (as
        `_on_groupchat` does)."""
        args, kwargs = (room, nick, body, stamp), {"item": item}
        if own:
            kwargs["own"] = True
        held = self._held().get(self._room_key(room))
        if held is not None:
            if len(held) < self.MAX_HELD_ROOM_MESSAGES:
                held.append((args, kwargs))
            return
        self._deliver_room_message(*args, **kwargs)

    def _on_room_bodiless(self, xml: ET.Element) -> None:
        """A room reaction (it has no body, so the room plugin never sees it)."""
        item = self._room_item(xml)
        if item is None or item.action != "react":
            return
        nick = self._clean(item.nick, self.MAX_NICK)
        if not nick or nick == self._our_nick(item.room):
            return
        self._room_route(item.room, nick, "", item.when, False, item)

    # -- the room's archive (XEP-0313 on a MUC) ------------------------------------

    def _room_after_join(self, room: str) -> None:
        loop = getattr(self, "_loop", None)
        if loop is None:
            return
        try:
            if self._on_loop_thread():
                loop.create_task(self._room_catch_up(room))
            else:
                asyncio.run_coroutine_threadsafe(self._room_catch_up(room), loop)
        except Exception:
            _log.warning("could not start a room's history")

    async def _room_catch_up(self, room: str) -> int:
        """What the room archived after our cursor for it (its newest page
        the first time). Delivered like live messages, marked "archive"."""
        room = str(room).split("/", 1)[0].lower()
        if RS.MUC_MAM not in await self._features(room):
            return 0
        st = self._sync()
        key = RS.room_cursor_key(self._own_bare_jid(), room)
        cursor = st["cursor"]
        last = cursor.get(key)
        plan = S.archive_plan(last)
        delivered = 0
        for _ in range(S.MAX_PAGES):
            page, fin_last, complete = await self._archive_page(plan, room=room)
            ours = self._our_nick(room)
            for _archive_id, item in page:
                nick = self._clean(item.nick, self.MAX_NICK)
                body = self._clean(item.body or "", self.MAX_ROOM_BODY)
                if not nick or (not body and not item.action):
                    continue
                self._room_route(room, nick, body, item.when, nick == ours, item)
                delivered += 1
            newest = fin_last or (page[-1][0] if page else "")
            if newest:
                cursor.set(key, newest)
            if not last or complete or not page or not newest:
                break
            plan = {"max": S.PAGE, "after": newest}
        return delivered

    # -- sending -------------------------------------------------------------------

    @staticmethod
    def _room_extras(message_id: str, elements: Optional[List[ET.Element]]) -> List[ET.Element]:
        extras: List[ET.Element] = []
        if message_id:
            origin = ET.Element("{%s}origin-id" % S.NS["sid"])
            origin.set("id", message_id)
            extras.append(origin)
        extras.extend(elements or [])
        return extras
