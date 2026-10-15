# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The account's server-side state: blocking, room bookmarks, room presence.

A mixin for `XmppTransport`, next to `android_bridge.sync`:

  * XEP-0191 blocking (+ XEP-0377 reporting): block a JID on the SERVER, so
    nothing from it reaches any of our devices; optionally report it to the
    server's operator as spam or abuse;
  * XEP-0402 bookmarks: the rooms this account is in, private to the
    account, joined on every device and after every reconnect;
  * XEP-0410 self-ping: every few minutes, ask each room whether we are
    still in it, and rejoin when the room says we are not.

The XML is `otrv4plus_sync`'s (shared with the terminal client). Every
public method answers `(code, detail, value)` like the room calls, and
never raises.
"""
from __future__ import annotations

import asyncio
import logging
import xml.etree.ElementTree as ET
from typing import Any, Callable, Dict, List, Optional

import otrv4plus_sync as S

from .trace import TRACE as _TRACE

_log = logging.getLogger("otrv4plus.bridge.account_sync")

#: How often each joined room is asked whether we are still in it.
SELF_PING_SECONDS = 600.0
SELF_PING_TIMEOUT = 90


class AccountSyncMixin:
    """Mixed into XmppTransport. Uses `_client`, `_room_call`, `_room_nicks`,
    `_loop` and `_own_bare_jid` (from SyncMixin)."""

    def _acct(self) -> Dict[str, Any]:
        st = getattr(self, "_account_state", None)
        if st is None:
            st = self._account_state = {
                "blocking": False, "blocked": set(), "bookmarks_private": False,
                "bookmarks": {}, "room_lost": None, "ping_task": None,
                "passwords": {},
            }
        return st

    # -- features, on connect (called from SyncMixin._sync_after_session) ------

    async def _account_after_session(self, server_features: List[str],
                                     own_features: List[str]) -> None:
        st = self._acct()
        st["blocking"] = S.NS["blocking"] in server_features
        # Private bookmarks need publish-options honoured (whitelist access).
        st["bookmarks_private"] = (
            "http://jabber.org/protocol/pubsub#publish-options" in own_features)
        if st["blocking"]:
            try:
                await self._fetch_blocklist()
            except Exception:
                _TRACE.record("account", "blocklist_failed", "warning")
        try:
            await self._fetch_bookmarks()
        except Exception:
            _TRACE.record("account", "bookmarks_failed", "warning")
        self._start_self_ping()

    def _install_account_handlers(self, client) -> None:
        """Another of our devices blocked or unblocked someone: the server
        pushes it here, and the list follows."""
        try:
            from slixmpp.xmlstream.handler import Callback
            from slixmpp.xmlstream.matcher import MatchXPath
        except Exception:
            return
        for tag in ("block", "unblock"):
            try:
                client.register_handler(Callback(
                    "OTRv4Plus blocking push " + tag,
                    MatchXPath("{jabber:client}iq/{%s}%s" % (S.NS["blocking"], tag)),
                    self._on_blocking_push))
            except Exception:
                pass

    def _on_blocking_push(self, iq) -> None:
        try:
            if iq["type"] != "set":
                return
            sender = str(iq["from"] or "").split("/", 1)[0].lower()
            if sender and sender != self._own_bare_jid():
                return                     # only our own server may push
            xml = iq.xml
            jids = S.parse_blocklist(xml)
            blocked = self._acct()["blocked"]
            if xml.find("{%s}block" % S.NS["blocking"]) is not None:
                blocked.update(jids)
            elif not jids:
                blocked.clear()            # an empty unblock: everyone
            else:
                blocked.difference_update(jids)
            iq.reply().send()
        except Exception:
            _log.warning("could not apply a blocking push")

    # -- blocking -----------------------------------------------------------------

    async def _fetch_blocklist(self) -> List[str]:
        iq = self._client.make_iq_get()
        iq.xml.append(ET.Element("{%s}blocklist" % S.NS["blocking"]))
        result = await iq.send(timeout=60)
        jids = S.parse_blocklist(result.xml)
        self._acct()["blocked"] = set(jids)
        return jids

    async def _blocking(self, action: str, jid: str, report: str = "") -> List[str]:
        if not self._acct()["blocking"]:
            raise _Unsupported()
        iq = self._client.make_iq_set()
        iq.xml.append(S.blocking_payload(action, [jid], report))
        await iq.send(timeout=60)
        bare = jid.split("/", 1)[0].lower()
        if action == "block":
            self._acct()["blocked"].add(bare)
        else:
            self._acct()["blocked"].discard(bare)
        return sorted(self._acct()["blocked"])

    # -- Wipe & Exit, opt-in: delete the account on the server (XEP-0077) ------

    #: Never longer than this: a wipe must not wait on a slow tunnel.
    ACCOUNT_DELETE_TIMEOUT = 10.0

    async def _remove_account(self, timeout: float) -> None:
        iq = self._client.make_iq_set()
        query = ET.SubElement(iq.xml, "{jabber:iq:register}query")
        ET.SubElement(query, "{jabber:iq:register}remove")
        await iq.send(timeout=timeout)

    def delete_account(self, timeout: Optional[float] = None) -> str:
        """Ask the server to delete this account (XEP-0077 §3.2), over the
        session already authenticated -- no stored password is needed.

        "deleted"     the server confirmed it;
        "unconfirmed" no answer in time (it may still have done it: servers
                      close the stream right after deleting);
        "refused"     the server said no (not allowed, not supported);
        "offline"     not connected: nothing was asked.
        Never raises."""
        if not self.is_connected:
            return "offline"
        limit = float(timeout or self.ACCOUNT_DELETE_TIMEOUT)
        try:
            self._send_now(self._remove_account(limit), limit + 2)
        except Exception as exc:
            name = type(exc).__name__
            if "IqError" in name:
                _TRACE.record("wipe", "account_delete_refused", "warning")
                return "refused"
            _TRACE.record("wipe", "account_delete_unconfirmed", "warning", error=name)
            return "unconfirmed"
        _TRACE.record("wipe", "account_deleted", "info")
        return "deleted"

    def block_contact(self, jid: str, report: str = "") -> "tuple[str, str, Any]":
        """Block [jid] on the server; [report] "spam"/"abuse" also reports it."""
        if not self._acct()["blocking"] and self.is_connected:
            return ("unsupported", "This server does not support blocking.", None)
        return self._room_call(self._blocking("block", jid, report))

    def unblock_contact(self, jid: str) -> "tuple[str, str, Any]":
        if not self._acct()["blocking"] and self.is_connected:
            return ("unsupported", "This server does not support blocking.", None)
        return self._room_call(self._blocking("unblock", jid))

    def blocked_contacts(self) -> List[str]:
        return sorted(self._acct()["blocked"])

    def blocking_supported(self) -> bool:
        return bool(self._acct()["blocking"])

    # -- bookmarks ------------------------------------------------------------------

    async def _fetch_bookmarks(self) -> List[Dict[str, Any]]:
        iq = self._client.make_iq_get(ito=self._own_bare_jid())
        iq.xml.append(S.bookmarks_query())
        try:
            result = await iq.send(timeout=60)
        except Exception:
            # No node yet is item-not-found: no bookmarks, not a failure.
            self._acct()["bookmarks"] = {}
            return []
        marks = S.parse_bookmarks(result.xml)
        self._acct()["bookmarks"] = {m["room"]: m for m in marks}
        return marks

    def bookmarks(self) -> List[Dict[str, Any]]:
        return [dict(m, password=bool(m.get("password")))
                for m in self._acct()["bookmarks"].values()]

    def bookmark_for(self, room: str) -> Optional[Dict[str, Any]]:
        mark = self._acct()["bookmarks"].get(str(room).lower())
        return dict(mark) if mark else None

    async def _publish_bookmark(self, room: str, nick: str, password: str,
                                autojoin: bool) -> None:
        if not self._acct()["bookmarks_private"]:
            raise _Unsupported()
        iq = self._client.make_iq_set(ito=self._own_bare_jid())
        iq.xml.append(S.bookmark_publish(room, nick=nick, password=password,
                                         autojoin=autojoin))
        await iq.send(timeout=60)
        self._acct()["bookmarks"][room.lower()] = {
            "room": room.lower(), "name": "", "autojoin": autojoin,
            "nick": nick, "password": password}

    async def _retract_bookmark(self, room: str) -> None:
        iq = self._client.make_iq_set(ito=self._own_bare_jid())
        iq.xml.append(S.bookmark_retract(room))
        await iq.send(timeout=60)
        self._acct()["bookmarks"].pop(room.lower(), None)

    def bookmark_room(self, room: str, nick: str, password: str = "",
                      autojoin: bool = True) -> "tuple[str, str, Any]":
        """Remember [room] for every device of this account (privately)."""
        if not self._acct()["bookmarks_private"]:
            return ("unsupported", "This server cannot keep bookmarks private.", None)
        return self._room_call(self._publish_bookmark(room, nick, password, autojoin))

    def unbookmark_room(self, room: str) -> "tuple[str, str, Any]":
        if room.lower() not in self._acct()["bookmarks"]:
            return ("ok", "", None)
        return self._room_call(self._retract_bookmark(room))

    # -- XEP-0410 self-ping -----------------------------------------------------------

    def set_room_lost_handler(self, handler: Optional[Callable[[str], None]]) -> None:
        """`handler(room)` when a room says we are no longer in it."""
        self._acct()["room_lost"] = handler

    def remember_room_password(self, room: str, password: str) -> None:
        """For a rejoin after the room forgot us. Memory only."""
        if password:
            self._acct()["passwords"][str(room).lower()] = password

    def room_password(self, room: str) -> str:
        acct = self._acct()
        return acct["passwords"].get(str(room).lower()) or \
            (acct["bookmarks"].get(str(room).lower()) or {}).get("password", "")

    def _start_self_ping(self) -> None:
        loop = getattr(self, "_loop", None)
        st = self._acct()
        if loop is None or (st["ping_task"] is not None and not st["ping_task"].done()):
            return
        try:
            st["ping_task"] = loop.create_task(self._self_ping_loop())
        except Exception:
            pass

    def _stop_self_ping(self) -> None:
        task = self._acct()["ping_task"]
        self._acct()["ping_task"] = None
        if task is not None and not task.done():
            try:
                task.cancel()
            except Exception:
                pass

    async def _self_ping_loop(self) -> None:
        while getattr(self, "is_connected", False):
            await asyncio.sleep(SELF_PING_SECONDS)
            for room, nick in list(getattr(self, "_room_nicks", {}).items()):
                if not getattr(self, "is_connected", False):
                    return
                verdict = await self.self_ping(room, nick)
                if verdict == S.NOT_JOINED:
                    _TRACE.record("account", "room_forgot_us", "warning")
                    handler = self._acct()["room_lost"]
                    if handler is not None:
                        try:
                            # Off the loop thread: the handler rejoins, which
                            # waits on this loop.
                            await asyncio.get_event_loop().run_in_executor(
                                None, handler, room)
                        except Exception:
                            pass

    async def self_ping(self, room: str, nick: str) -> str:
        try:
            from slixmpp.exceptions import IqError, IqTimeout
        except Exception:
            return S.UNKNOWN
        iq = self._client.make_iq_get(ito="%s/%s" % (room, nick))
        iq.xml.append(ET.Element("{%s}ping" % S.NS["ping"]))
        try:
            await iq.send(timeout=SELF_PING_TIMEOUT)
            return S.self_ping_verdict(None)
        except IqError as exc:
            try:
                return S.self_ping_verdict(str(exc.iq["error"]["condition"]))
            except Exception:
                return S.UNKNOWN
        except IqTimeout:
            return S.UNKNOWN
        except Exception:
            return S.UNKNOWN


class _Unsupported(Exception):
    """The server does not offer what was asked for."""
