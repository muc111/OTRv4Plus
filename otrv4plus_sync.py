# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Multi-device XMPP: message ids, carbons, the server archive, receipts.

Owner (2026-10-14): "of course we must add message carbons and server side
message history xep-0313 and anything else conversations app uses".

Shared by the app (android_bridge.transport, which the desktop drives too)
and the terminal client, so the two cannot drift apart on any rule below.
It reads stanzas as XML (ElementTree), never through slixmpp's stanza
plugins, so the rules are tested here without a server.

WHAT EACH XEP DOES HERE
=======================
XEP-0359 Unique and Stable Stanza IDs
    Every message this device sends carries an `origin-id` (the same value
    as its `id`), so its copies -- a carbon, the archive -- are recognised
    as the same message. A `stanza-id` is TRUSTED ONLY when its `by` is our
    own bare JID: anyone can put a stanza-id in a message, only our server's
    is a fact about our archive (XEP-0359 §8).

XEP-0280 Message Carbons
    Copies of what our other devices send and receive. A carbon is accepted
    only from our own bare JID (XEP-0280 §11: otherwise any contact could
    forge "you said ..."). PLAINTEXT ONLY reaches the screen from a carbon:
    an OTR frame belongs to the session on the device it was meant for, and
    feeding a copy to this device's engine would be a replay. Our own OTR
    traffic is marked `<private/>` + `<no-copy/>` so the server does not
    copy it in the first place.

XEP-0313 Message Archive Management
    On connect, what this account sent and received while this device was
    away: the newest page on first use, then everything after the last id
    seen. As with carbons, only plaintext is shown. OTR ciphertext is marked
    `<no-permanent-store/>` (XEP-0334), so a server honouring hints does not
    archive it; a frame that is there anyway is skipped -- replaying it into
    a forward-secret session can only fail, or worse, look like a broken
    session and start a needless handshake.

XEP-0184 Message Delivery Receipts / XEP-0333 Chat Markers
    "Delivered" and "Read" ticks. Requested on every message we send;
    answered only to contacts in the roster (as Conversations does), so a
    stranger cannot learn when this device is online by asking for a
    receipt. Read markers can be switched off.

XEP-0085 Chat State Notifications
    "typing...". Sent only to roster contacts, and can be switched off.

WHAT THE SERVER LEARNS
======================
None of the above adds message content to what the server sees: ids,
receipts, markers and chat states are metadata the server could already
infer from timing. Plaintext was always readable by the server; the archive
stores what it already had. Encrypted traffic is asked not to be stored.
"""

from __future__ import annotations

import collections
import calendar
import hashlib
import json
import os
import re
import tempfile
import time
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass, replace
from typing import Any, Dict, List, Optional, Tuple

__all__ = [
    "NS", "Item", "parse_message", "unwrap_carbon", "parse_archive_result",
    "classify", "SHOW_IN", "SHOW_OUT", "ENGINE", "SKIP", "ELSEWHERE",
    "Seen", "ArchiveCursor", "new_message_id", "strip_whitespace_tag",
    "otr_hints", "user_message_extras", "is_protocol_body",
    "parse_stamp", "receipt_of", "marker_of", "chat_state_of",
    "CHAT_STATES", "archive_plan", "FIRST_PAGE", "PAGE", "MAX_PAGES",
]

NS = {
    "client": "jabber:client",
    "carbons": "urn:xmpp:carbons:2",
    "forward": "urn:xmpp:forward:0",
    "delay": "urn:xmpp:delay",
    "sid": "urn:xmpp:sid:0",
    "hints": "urn:xmpp:hints",
    "receipts": "urn:xmpp:receipts",
    "markers": "urn:xmpp:chat-markers:0",
    "chatstates": "http://jabber.org/protocol/chatstates",
    "mam": "urn:xmpp:mam:2",
}

CHAT_STATES = ("active", "composing", "paused", "inactive", "gone")

#: What becomes of one message (see `classify`).
ENGINE = "engine"        # live 1:1 traffic: the OTR engine decides, as before
SHOW_IN = "show_in"      # plaintext someone sent us, from a copy: show it
SHOW_OUT = "show_out"    # plaintext we sent from another device: show it
ELSEWHERE = "elsewhere"  # an OTR frame meant for another device: never shown
SKIP = "skip"            # nothing to show (no body, a protocol query, ...)

#: The longest body taken from a carbon or the archive. The same bound the
#: transport applies to live 1:1 bodies (XmppTransport.MAX_DIRECT_BODY).
MAX_BODY = 64 * 1024


def _q(ns: str, tag: str) -> str:
    return "{%s}%s" % (NS[ns], tag)


def _bare(jid: str) -> str:
    return (jid or "").split("/", 1)[0].strip().lower()


def new_message_id() -> str:
    """A fresh id for a message we send: random, so it says nothing about
    who sent it or when (a counter would)."""
    return uuid.uuid4().hex


def parse_stamp(text: str) -> Optional[float]:
    """XEP-0082 date-time -> epoch seconds, or None if it is not one."""
    if not text:
        return None
    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d+)?"
                 r"(Z|[+-]\d{2}:\d{2})$", text.strip())
    if not m:
        return None
    y, mo, d, h, mi, s = (int(m.group(i)) for i in range(1, 7))
    try:
        epoch = calendar.timegm((y, mo, d, h, mi, s, 0, 0, 0))
    except (ValueError, OverflowError):
        return None
    if m.group(7):
        epoch += float("0" + m.group(7))
    zone = m.group(8)
    if zone != "Z":
        sign = 1 if zone[0] == "+" else -1
        epoch -= sign * (int(zone[1:3]) * 3600 + int(zone[4:6]) * 60)
    return float(epoch)


#: The OTR whitespace tag (OTR v2/v3/v4 base tag), which a plaintext message
#: may carry to say "I speak OTR". The engine strips it from live traffic; a
#: copy from a carbon or the archive never meets the engine, so it is
#: stripped here instead of being shown as trailing spaces and tabs.
_WS_BASE = " \t  \t\t\t\t \t \t \t  "
_WS_TAG = re.compile(re.escape(_WS_BASE) + r"(?:[ \t]{8})*")


def strip_whitespace_tag(body: str) -> str:
    return _WS_TAG.sub("", body or "")


def is_protocol_body(body: str) -> bool:
    """OTR traffic of any version (a frame, a fragment, a query, an error).
    Never something a person typed, so never shown from a copy."""
    return isinstance(body, str) and body.lstrip().startswith("?OTR")


@dataclass(frozen=True)
class Item:
    """One chat message, however it arrived."""

    direction: str            # "in" (to us) or "out" (from this account)
    peer: str                 # the other party's bare JID, lower case
    body: str
    when: float               # epoch seconds: the delay stamp, else now
    source: str               # "live", "carbon" or "archive"
    stanza_id: str = ""       # our server's archive id (trusted only)
    origin_id: str = ""       # the sender's own id for it
    message_id: str = ""      # the stanza's id attribute
    full_jid: str = ""        # the other party's full JID, if known
    mtype: str = "chat"
    receipt_request: bool = False
    markable: bool = False

    @property
    def ref(self) -> str:
        """The id to dedupe and reply to: the sender's own id first (it is
        the same on every copy), then the server's archive id."""
        return self.origin_id or self.message_id or self.stanza_id


def _child(el: ET.Element, ns: str, tag: str) -> Optional[ET.Element]:
    return el.find(_q(ns, tag))


def _message_children(el: ET.Element, tag: str) -> Optional[ET.Element]:
    """A <message> child in either the client or the default namespace
    (forwarded stanzas are written both ways)."""
    found = el.find(_q("client", tag))
    if found is None:
        found = el.find(tag)
    return found


def parse_message(msg: ET.Element, own_bare: str, source: str = "live",
                  when: Optional[float] = None) -> Optional[Item]:
    """An <message> element -> Item, or None if it is not a 1:1 message.

    `own_bare` decides the direction: from us is "out", anything else "in".
    """
    if msg is None or not str(msg.tag).endswith("message"):
        return None
    own = _bare(own_bare)
    mtype = msg.get("type") or "normal"
    if mtype not in ("chat", "normal"):
        return None
    sender, to = msg.get("from") or "", msg.get("to") or ""
    if _bare(sender) == own and own:
        direction, other = "out", to
    else:
        direction, other = "in", sender
    peer = _bare(other)
    if not peer or peer == own:
        return None
    body_el = _message_children(msg, "body")
    body = (body_el.text or "") if body_el is not None else ""
    stamp = None
    delay = _child(msg, "delay", "delay")
    if delay is not None:
        stamp = parse_stamp(delay.get("stamp") or "")
    stanza_id = ""
    for sid in msg.findall(_q("sid", "stanza-id")):
        # XEP-0359 §8: only our own server's stanza-id is a fact.
        if _bare(sid.get("by") or "") == own and own:
            stanza_id = (sid.get("id") or "")[:128]
            break
    origin = _child(msg, "sid", "origin-id")
    return Item(
        direction=direction, peer=peer, body=body,
        when=stamp if stamp is not None else (when if when is not None else time.time()),
        source=source, stanza_id=stanza_id,
        origin_id=((origin.get("id") or "")[:128] if origin is not None else ""),
        message_id=(msg.get("id") or "")[:128],
        full_jid=other if "/" in other else "",
        mtype=mtype,
        receipt_request=_child(msg, "receipts", "request") is not None,
        markable=_child(msg, "markers", "markable") is not None,
    )


def unwrap_carbon(outer: ET.Element, own_bare: str) -> Optional[Item]:
    """A XEP-0280 carbon -> the Item it carries, or None.

    None unless the wrapper is FROM OUR OWN BARE JID (or, as servers do,
    has no from at all, which means our own server). A carbon from anyone
    else is a forgery attempt and is dropped (XEP-0280 §11)."""
    sender = outer.get("from")
    if sender is not None and _bare(sender) != _bare(own_bare):
        return None
    for kind in ("received", "sent"):
        wrap = _child(outer, "carbons", kind)
        if wrap is None:
            continue
        fwd = _child(wrap, "forward", "forwarded")
        if fwd is None:
            return None
        inner = _message_children(fwd, "message")
        if inner is None:
            return None
        delay = _child(fwd, "delay", "delay")
        stamp = parse_stamp(delay.get("stamp") or "") if delay is not None else None
        item = parse_message(inner, own_bare, source="carbon", when=stamp)
        if item is None:
            return None
        # The direction must agree with the wrapper: a "sent" carbon of a
        # message that is not from us is malformed (or a trick), and so is
        # a "received" one that is.
        if (kind == "sent") != (item.direction == "out"):
            return None
        return item
    return None


def parse_archive_result(msg: ET.Element, own_bare: str,
                         query_id: str = "") -> Optional[Tuple[str, Item]]:
    """A XEP-0313 <result> message -> (archive id, Item), or None.

    Accepted only from our own archive: the wrapper from our bare JID or
    absent, and (when given) the query id we asked with."""
    sender = msg.get("from")
    if sender is not None and _bare(sender) != _bare(own_bare):
        return None
    result = _child(msg, "mam", "result")
    if result is None:
        return None
    if query_id and result.get("queryid") not in (None, query_id):
        return None
    archive_id = (result.get("id") or "")[:128]
    fwd = _child(result, "forward", "forwarded")
    if fwd is None or not archive_id:
        return None
    inner = _message_children(fwd, "message")
    delay = _child(fwd, "delay", "delay")
    stamp = parse_stamp(delay.get("stamp") or "") if delay is not None else None
    item = parse_message(inner, own_bare, source="archive", when=stamp)
    if item is None:
        return None
    if not item.stanza_id:
        item = replace(item, stanza_id=archive_id)
    return archive_id, item


def classify(item: Item) -> str:
    """What to do with one message (ENGINE, SHOW_IN, SHOW_OUT, ELSEWHERE, SKIP).

    Live traffic is the engine's to judge, exactly as before this module
    existed. Copies (carbons, the archive) are shown only as plaintext."""
    if item.source == "live":
        return ENGINE if item.direction == "in" else SKIP
    body = item.body or ""
    if not body.strip():
        return SKIP
    if is_protocol_body(body):
        return ELSEWHERE
    if len(body) > MAX_BODY:
        return SKIP
    return SHOW_OUT if item.direction == "out" else SHOW_IN


class Seen:
    """Ids already handled, so a message that arrives live, as a carbon and
    from the archive is shown once. Bounded: it only has to outlive the
    overlap between those paths."""

    def __init__(self, size: int = 4096):
        self._ids: "collections.OrderedDict[str, None]" = collections.OrderedDict()
        self._size = size

    def _keys(self, item: Item) -> List[str]:
        keys = []
        if item.stanza_id:
            keys.append("s:" + item.stanza_id)
        if item.origin_id:
            keys.append("o:%s:%s" % (item.peer, item.origin_id))
        elif item.message_id:
            keys.append("m:%s:%s:%s" % (item.peer, item.direction, item.message_id))
        return keys

    def first_time(self, item: Item) -> bool:
        """True the first time any id of [item] is seen; records them all."""
        keys = self._keys(item)
        fresh = not any(k in self._ids for k in keys)
        for k in keys:
            self._ids[k] = None
            self._ids.move_to_end(k)
        while len(self._ids) > self._size:
            self._ids.popitem(last=False)
        return fresh


class ArchiveCursor:
    """The last archive id this device has seen, per account, on disk.

    Only an opaque id and a time -- no contact, no content. The account is
    stored as a hash, so the file does not even say whose it is."""

    def __init__(self, path: str):
        self._path = path

    @staticmethod
    def _key(account: str) -> str:
        return hashlib.sha256(_bare(account).encode()).hexdigest()[:32]

    def _load(self) -> Dict[str, Any]:
        try:
            with open(self._path, encoding="utf-8") as fh:
                data = json.load(fh)
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def get(self, account: str) -> str:
        entry = self._load().get(self._key(account))
        if isinstance(entry, dict) and isinstance(entry.get("last"), str):
            return entry["last"][:128]
        return ""

    def set(self, account: str, archive_id: str) -> None:
        if not archive_id:
            return
        data = self._load()
        data[self._key(account)] = {"last": archive_id[:128], "at": int(time.time())}
        directory = os.path.dirname(self._path) or "."
        os.makedirs(directory, mode=0o700, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".cursor-", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh)
            os.chmod(tmp, 0o600)
            os.replace(tmp, self._path)
        except OSError:
            try:
                os.unlink(tmp)
            except OSError:
                pass

    def forget(self) -> None:
        try:
            os.unlink(self._path)
        except OSError:
            pass


#: The first sync on a device: this many of the newest archived messages.
FIRST_PAGE = 50
#: Later syncs: pages of this size after the cursor, at most MAX_PAGES.
PAGE = 100
MAX_PAGES = 20


def archive_plan(cursor: str) -> Dict[str, Any]:
    """The RSM for the first query: the newest page if there is no cursor,
    otherwise what came after it."""
    if not cursor:
        return {"max": FIRST_PAGE, "before": ""}
    return {"max": PAGE, "after": cursor}


def otr_hints() -> List[ET.Element]:
    """For an OTR frame: not copied to our other devices, not archived.
    (Offline storage still holds it for a contact who is briefly away.)"""
    return [ET.Element(_q("carbons", "private")),
            ET.Element(_q("hints", "no-copy")),
            ET.Element(_q("hints", "no-permanent-store"))]


def user_message_extras(message_id: str, receipts: bool = True,
                        chat_states: bool = True) -> List[ET.Element]:
    """For a message a person typed: its origin-id, the requests for a
    delivery receipt and a read marker, and (when chat states are on) the
    <active/> that ends a "typing..." on the other side."""
    out = []
    origin = ET.Element(_q("sid", "origin-id"))
    origin.set("id", message_id)
    out.append(origin)
    if receipts:
        out.append(ET.Element(_q("receipts", "request")))
        out.append(ET.Element(_q("markers", "markable")))
    if chat_states:
        out.append(ET.Element(_q("chatstates", "active")))
    return out


def receipt_of(msg: ET.Element) -> str:
    """The id a XEP-0184 <received/> acknowledges, or ''."""
    el = _child(msg, "receipts", "received")
    return (el.get("id") or "")[:128] if el is not None else ""


def marker_of(msg: ET.Element) -> Tuple[str, str]:
    """(marker, id) of a XEP-0333 marker, or ('', '')."""
    for name in ("displayed", "received", "acknowledged"):
        el = _child(msg, "markers", name)
        if el is not None and el.get("id"):
            return name, el.get("id")[:128]
    return "", ""


def chat_state_of(msg: ET.Element) -> str:
    for name in CHAT_STATES:
        if _child(msg, "chatstates", name) is not None:
            return name
    return ""
