# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Group-chat (XEP-0045 room) messages: their ids, their actions, the room's
archive.

Owner (2026-10-14/15): everything Conversations does. In a ROOM that means
replies, corrections, deletion for everyone and reactions, and the room's
own history when you join.

TWO IDS PER ROOM MESSAGE
========================
  * the sender's own id (the stanza id / XEP-0359 origin-id), which a
    CORRECTION names (XEP-0308: the id of the message as it was sent);
  * the ROOM's id for it (XEP-0359 stanza-id with by = the room), which a
    DELETION and a REACTION name in a room (XEP-0424 §5, XEP-0444 §4).

The app knows each message by one reference: the room's id when the room
gave one, otherwise the sender's. `RoomRefs` remembers which sender id goes
with which room id, so a correction naming the first finds the message the
app knows by the second, and ours can name the original.

TRUST
=====
A plain room is plaintext and the room is in charge of it: it assigns
nicknames, ids and timestamps, and could forge any of them. The actions are
exactly as trustworthy as the text, and the same author rule applies as in
a one-to-one chat: a correction or deletion only applies to a message from
the same nickname. A stanza-id is taken only from the room itself (by =
the room's JID). A SECURE GROUP (MLS) never takes any of these from the
room: its messages are authenticated inside MLS, and an unauthenticated
plaintext action on one of its messages is ignored.
"""
from __future__ import annotations

import time
import xml.etree.ElementTree as ET
from collections import OrderedDict
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

import otrv4plus_actions as _actions
from otrv4plus_sync import NS, _bare, _child, _message_children, _q, \
    is_protocol_body, parse_stamp

__all__ = ["RoomItem", "parse_room_message", "parse_room_archive", "RoomRefs",
           "room_cursor_key", "MUC_MAM"]

#: Rooms that keep an archive say so with this feature.
MUC_MAM = NS["mam"]
MAX_ID = 128
OCCUPANT_ID = "urn:xmpp:occupant-id:0"


@dataclass(frozen=True)
class RoomItem:
    room: str
    nick: str
    body: str
    when: float
    source: str = "live"            # "live" or "archive"
    origin_id: str = ""
    message_id: str = ""
    stanza_id: str = ""             # the ROOM's id (by == room) only
    occupant_id: str = ""
    action: str = ""
    target: str = ""
    emojis: tuple = ()
    reply: str = ""

    @property
    def own_id(self) -> str:
        """The sender's id: what a correction names."""
        return self.origin_id or self.message_id

    @property
    def ref(self) -> str:
        """How the app knows the message: the room's id first."""
        return self.stanza_id or self.own_id


def parse_room_message(msg: ET.Element, source: str = "live",
                       when: Optional[float] = None) -> Optional[RoomItem]:
    """A type="groupchat" <message> from room/nick -> RoomItem, or None (a
    subject change, a message from the room itself, anything else)."""
    if msg is None or not str(msg.tag).endswith("message"):
        return None
    if msg.get("type") != "groupchat":
        return None
    sender = msg.get("from") or ""
    if "/" not in sender:
        return None
    room, nick = sender.split("/", 1)
    room = _bare(room)
    if not room or not nick:
        return None
    body_el = _message_children(msg, "body")
    body = (body_el.text or "") if body_el is not None else ""
    stamp = None
    delay = _child(msg, "delay", "delay")
    if delay is not None:
        stamp = parse_stamp(delay.get("stamp") or "")
    stanza_id = ""
    for sid in msg.findall(_q("sid", "stanza-id")):
        if _bare(sid.get("by") or "") == room:
            stanza_id = (sid.get("id") or "")[:MAX_ID]
            break
    origin = _child(msg, "sid", "origin-id")
    occupant = msg.find("{%s}occupant-id" % OCCUPANT_ID)
    act = ({"action": "", "target": "", "emojis": [], "reply": ""}
           if is_protocol_body(body) else _actions.parse_action(msg))
    return RoomItem(
        room=room, nick=nick[:128], body=body,
        when=stamp if stamp is not None else (when if when is not None else time.time()),
        source=source, stanza_id=stanza_id,
        origin_id=((origin.get("id") or "")[:MAX_ID] if origin is not None else ""),
        message_id=(msg.get("id") or "")[:MAX_ID],
        occupant_id=((occupant.get("id") or "")[:MAX_ID] if occupant is not None else ""),
        action=act["action"], target=act["target"], emojis=tuple(act["emojis"]),
        reply=act["reply"],
    )


def parse_room_archive(xml: ET.Element, room: str, query_id: str
                       ) -> Optional[Tuple[str, RoomItem]]:
    """One MAM result from a ROOM's archive -> (archive id, RoomItem).

    Only from the room itself, only for our query. The archive id IS the
    room's stanza-id for the message (XEP-0313 §5.1.2)."""
    room = _bare(room)
    if _bare(xml.get("from") or "") != room:
        return None
    result = xml.find(_q("mam", "result"))
    if result is None or (result.get("queryid") or "") != query_id:
        return None
    archive_id = (result.get("id") or "")[:MAX_ID]
    fwd = result.find("{urn:xmpp:forward:0}forwarded")
    if fwd is None:
        return None
    inner = fwd.find(_q("client", "message"))
    if inner is None:
        inner = fwd.find("message")
    stamp = None
    delay = fwd.find(_q("delay", "delay"))
    if delay is not None:
        stamp = parse_stamp(delay.get("stamp") or "")
    item = parse_room_message(inner, "archive", stamp)
    if item is None or item.room != room:
        return None
    if not item.stanza_id and archive_id:
        from dataclasses import replace
        item = replace(item, stanza_id=archive_id)
    if stamp is not None:
        from dataclasses import replace
        item = replace(item, when=stamp)
    return archive_id, item


class RoomRefs:
    """Per room: the sender's id <-> the room's id, and what has been seen.
    Bounded; in memory only."""

    LIMIT = 2000

    def __init__(self) -> None:
        self._own_to_ref: Dict[str, "OrderedDict[str, str]"] = {}
        self._ref_to_own: Dict[str, "OrderedDict[str, str]"] = {}
        self._seen: Dict[str, "OrderedDict[str, None]"] = {}

    @staticmethod
    def _put(table: dict, room: str, key: str, value) -> None:
        bucket = table.setdefault(room, OrderedDict())
        bucket[key] = value
        bucket.move_to_end(key)
        while len(bucket) > RoomRefs.LIMIT:
            bucket.popitem(last=False)

    def remember(self, room: str, own_id: str, ref: str) -> None:
        room = _bare(room)
        if own_id and ref and own_id != ref:
            self._put(self._own_to_ref, room, own_id, ref)
            self._put(self._ref_to_own, room, ref, own_id)

    def resolve(self, room: str, any_id: str) -> str:
        """The app's reference for a message named by either id."""
        return self._own_to_ref.get(_bare(room), {}).get(any_id, any_id)

    def own_id_of(self, room: str, ref: str) -> str:
        """The sender's id for a message the app knows by [ref]."""
        return self._ref_to_own.get(_bare(room), {}).get(ref, ref)

    def first_time(self, item: RoomItem) -> bool:
        """False for a message already seen (live, then in the archive)."""
        keys = [k for k in (item.stanza_id, item.own_id) if k]
        if not keys:
            return True
        bucket = self._seen.setdefault(item.room, OrderedDict())
        if any(k in bucket for k in keys):
            return False
        for k in keys:
            bucket[k] = None
        while len(bucket) > self.LIMIT:
            bucket.popitem(last=False)
        return True

    def forget(self) -> None:
        self._own_to_ref.clear()
        self._ref_to_own.clear()
        self._seen.clear()


def room_cursor_key(account: str, room: str) -> str:
    """The ArchiveCursor key for one room of one account (hashed there)."""
    return "%s|room|%s" % (_bare(account), _bare(room))
