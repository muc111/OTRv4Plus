# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The transport's half of multi-device XMPP (see otrv4plus_sync).

A mixin for `XmppTransport`, kept apart so the rules are in one place:

  * every message this device sends gets an id and, for something a person
    typed, asks for a delivery receipt and a read marker (XEP-0359, -0184,
    -0333); OTR frames are kept off our other devices and out of the
    archive (XEP-0280 private, XEP-0334 hints);
  * carbons are switched on and their copies handed up (XEP-0280);
  * on connect, the server archive since this device last looked is read
    (XEP-0313);
  * receipts, read markers and "typing..." are reported and answered
    (XEP-0184, -0333, -0085), answered only to contacts who already see our
    presence;
  * the app says when it is in the background (XEP-0352).

Everything reaches the app through ONE handler, `set_sync_handler(fn)`,
called as `fn(kind, **fields)` on the transport's loop thread:

    fn("message", item=Item)           a copy to show (SHOW_IN / SHOW_OUT)
    fn("receipt", peer=, message_id=)  delivered
    fn("marker", peer=, message_id=, marker=)
    fn("chat_state", peer=, state=)
    fn("synced", count=)               the archive catch-up finished

Nothing here touches the OTR engine. Live 1:1 traffic still goes through
`on_payload` exactly as before; only copies are new, and copies of OTR
traffic are never handed to anything.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
import xml.etree.ElementTree as ET
from typing import Any, Callable, Dict, List, Optional

import otrv4plus_sync as S

from .trace import TRACE as _TRACE

_log = logging.getLogger("otrv4plus.bridge.sync")

NS_RSM = "http://jabber.org/protocol/rsm"

#: Where the archive cursor lives (one small file for every account on
#: this device; see otrv4plus_sync.ArchiveCursor).
CURSOR_PATH = "~/.otrv4plus/sync/archive-cursor.json"

#: A chat state is sent at most this often per contact (seconds), except
#: that a change of state always goes.
CHAT_STATE_GAP = 10.0

#: How long the archive query may take before it is abandoned. I2P is slow;
#: an archive that does not answer is not a reason to hold anything up.
ARCHIVE_TIMEOUT = 90


class SyncMixin:
    """Mixed into XmppTransport. Expects `_client`, `_profile`, `_loop`,
    `_send_now`, `_on_loop_thread` and `_caps` from it."""

    #: Switched by the user (Settings): "typing..." and read markers. Delivery
    #: receipts are always answered (to contacts who see our presence), as
    #: the terminal client always has.
    send_chat_states = True
    send_read_markers = True

    # -- state ----------------------------------------------------------------

    def _sync(self) -> Dict[str, Any]:
        st = getattr(self, "_sync_state", None)
        if st is None:
            st = self._sync_state = {
                "handler": None, "seen": S.Seen(), "queries": {},
                "carbons": False, "mam": False, "last_state": {},
                "cursor": S.ArchiveCursor(os.path.expanduser(CURSOR_PATH)),
                "active": True,
            }
        return st

    def set_sync_handler(self, handler: Optional[Callable[..., None]]) -> None:
        self._sync()["handler"] = handler

    def _sync_emit(self, kind: str, **fields: Any) -> None:
        handler = self._sync()["handler"]
        if handler is None:
            return
        try:
            handler(kind, **fields)
        except Exception:
            _log.warning("the sync handler raised")

    def set_privacy(self, chat_states: bool, read_markers: bool) -> None:
        self.send_chat_states = bool(chat_states)
        self.send_read_markers = bool(read_markers)

    def sync_status(self) -> Dict[str, Any]:
        st = self._sync()
        return {"carbons": st["carbons"], "archive": st["mam"],
                "csi": bool(self._csi()), "active": st["active"]}

    def _own_bare_jid(self) -> str:
        client = getattr(self, "_client", None)
        try:
            return str(client.boundjid.bare).lower()
        except Exception:
            return str(getattr(self._profile, "jid", "") or "").split("/", 1)[0].lower()

    # -- who may learn what ------------------------------------------------------

    def _sees_our_presence(self, bare: str) -> bool:
        """True for a contact with a presence subscription FROM us (they
        already see when we are online): receipts, markers and chat states
        go to them and to nobody else, so a stranger cannot learn when this
        device is in use by asking for a receipt."""
        client = getattr(self, "_client", None)
        try:
            roster = client.client_roster
            if bare not in roster:
                return False
            return roster[bare]["subscription"] in ("from", "both")
        except Exception:
            return False

    # -- outbound ------------------------------------------------------------------

    def _build(self, to: str, body: Optional[str], extras: List[ET.Element],
               message_id: str = ""):
        client = self._client
        make = getattr(client, "make_message", None)
        if make is None:
            return None
        msg = make(mto=to, mbody=body, mtype="chat")
        for el in extras:
            msg.xml.append(el)
        if message_id:
            msg["id"] = message_id
        return msg

    def _send_stanzas(self, peer: str, parts: List[str], message_id: str = "",
                      otr: bool = False) -> None:
        """One stanza per part, with the ids and hints this module adds.
        Falls back to a bare send_message where the client cannot build a
        stanza (a test double)."""
        client = self._client
        last = len(parts) - 1
        for i, part in enumerate(parts):
            extras: List[ET.Element] = []
            if otr:
                extras += S.otr_hints()
            mid = ""
            if message_id and i == last:
                extras += S.user_message_extras(
                    message_id, receipts=True, chat_states=self.send_chat_states)
                mid = message_id
            msg = self._build(peer, part, extras, mid) if extras else None
            if msg is None:
                client.send_message(mto=peer, mbody=part, mtype="chat")
            else:
                msg.send()

    def send_receipt(self, to: str, message_id: str) -> None:
        if not message_id:
            return
        el = ET.Element("{%s}received" % S.NS["receipts"])
        el.set("id", message_id)
        self._send_extra(to, [el])

    def send_marker(self, to: str, message_id: str, marker: str = "displayed") -> None:
        if not message_id or marker not in ("received", "displayed", "acknowledged"):
            return
        el = ET.Element("{%s}%s" % (S.NS["markers"], marker))
        el.set("id", message_id)
        self._send_extra(to, [el])

    def send_chat_state(self, peer: str, state: str) -> bool:
        """Tell [peer] we are typing (or stopped). Only to a contact who sees
        our presence, only when switched on, and not more than once per
        CHAT_STATE_GAP for the same state. Returns whether it went."""
        bare = (peer or "").split("/", 1)[0].lower()
        if state not in S.CHAT_STATES or not self.send_chat_states:
            return False
        if not getattr(self, "is_connected", False) or not self._sees_our_presence(bare):
            return False
        last = self._sync()["last_state"]
        before = last.get(bare)
        now = time.monotonic()
        if before and before[0] == state and now - before[1] < CHAT_STATE_GAP:
            return False
        last[bare] = (state, now)
        target = bare
        try:
            pinned = self._caps.target(bare)
            if pinned:
                target = pinned
        except Exception:
            pass
        self._send_extra(target, [ET.Element("{%s}%s" % (S.NS["chatstates"], state))],
                         hints=True)
        return True

    def _send_extra(self, to: str, extras: List[ET.Element], hints: bool = True) -> None:
        """A body-less message carrying [extras] (a receipt, a marker, a
        chat state). Not archived, not stored offline: it means nothing later."""
        if hints:
            extras = extras + [ET.Element("{%s}no-store" % S.NS["hints"])]

        async def go():
            msg = self._build(to, None, extras)
            if msg is not None:
                msg.send()
        try:
            self._send_now(go(), 30)
        except Exception:
            _log.warning("could not send a receipt or chat state")

    # -- XEP-0352 client state ---------------------------------------------------

    def _csi(self):
        client = getattr(self, "_client", None)
        try:
            plugin = client["xep_0352"]
            return plugin if getattr(plugin, "enabled", False) else None
        except Exception:
            return None

    def set_client_active(self, active: bool) -> None:
        """The app is on screen (True) or in the background (False). The
        server may then hold back presence floods and chat states until the
        user is back (Prosody mod_csi), which saves battery and radio."""
        st = self._sync()
        if st["active"] == bool(active):
            return
        st["active"] = bool(active)
        plugin = self._csi()
        if plugin is None:
            return

        async def go():
            if active:
                plugin.send_active()
            else:
                plugin.send_inactive()
        try:
            self._send_now(go(), 30)
        except Exception:
            pass

    # -- inbound ---------------------------------------------------------------

    def _install_sync_handler(self, client) -> None:
        """One handler for EVERY message, body or not: slixmpp's own
        "message" event only fires for messages with a body, and receipts,
        markers, chat states, carbons and archive results have none."""
        try:
            from slixmpp.xmlstream.handler import Callback
            from slixmpp.xmlstream.matcher import MatchXPath
        except Exception:
            return
        try:
            client.register_handler(Callback(
                "OTRv4Plus sync", MatchXPath("{jabber:client}message"),
                self._on_any_message))
        except Exception:
            _log.warning("could not install the sync handler")

    def _on_any_message(self, stanza) -> None:
        try:
            xml = stanza.xml
        except Exception:
            return
        own = self._own_bare_jid()
        try:
            if xml.find("{%s}result" % S.NS["mam"]) is not None:
                self._on_archive_result(xml, own)
                return
            if (xml.find("{%s}received" % S.NS["carbons"]) is not None
                    or xml.find("{%s}sent" % S.NS["carbons"]) is not None):
                self._on_carbon(xml, own)
                return
            if xml.get("type") in ("groupchat", "error"):
                return
            sender = (xml.get("from") or "").split("/", 1)[0].lower()
            if not sender or sender == own:
                return
            receipt = S.receipt_of(xml)
            if receipt:
                self._sync_emit("receipt", peer=sender, message_id=receipt)
            marker, mid = S.marker_of(xml)
            if marker:
                self._sync_emit("marker", peer=sender, message_id=mid, marker=marker)
            state = S.chat_state_of(xml)
            if state:
                self._sync_emit("chat_state", peer=sender, state=state)
        except Exception:
            _log.warning("could not read a message's sync elements")

    def _on_carbon(self, xml: ET.Element, own: str) -> None:
        item = S.unwrap_carbon(xml, own)
        if item is None:
            _TRACE.record("sync", "carbon_refused", "warning")
            return
        kind = S.classify(item)
        if kind == S.ELSEWHERE:
            # An OTR frame for another of our devices. Never the engine's.
            _TRACE.record("sync", "carbon_otr_elsewhere", "info")
            return
        if kind not in (S.SHOW_IN, S.SHOW_OUT):
            return
        if not self._sync()["seen"].first_time(item):
            return
        self._sync_emit("message", item=item)

    # -- live messages (called from the transport's _on_message) ---------------

    def live_item(self, stanza) -> Optional[S.Item]:
        """The sync view of a live 1:1 message, recorded as seen so its
        copies (carbon, archive) are not shown again."""
        try:
            item = S.parse_message(stanza.xml, self._own_bare_jid(), "live")
        except Exception:
            return None
        if item is not None:
            self._sync()["seen"].first_time(item)
        return item

    def after_live(self, item: Optional[S.Item], shown: bool) -> None:
        """Answer a receipt request once the app has actually taken the
        message (`shown`: decrypted, or plaintext stored)."""
        if item is None or not shown or not item.receipt_request:
            return
        if not item.message_id or not self._sees_our_presence(item.peer):
            return
        self.send_receipt(item.full_jid or item.peer, item.message_id)

    # -- carbons and the archive, on connect ------------------------------------

    def _start_sync(self) -> None:
        loop = getattr(self, "_loop", None)
        if loop is None:
            return
        try:
            if self._on_loop_thread():
                loop.create_task(self._sync_after_session())
            else:
                asyncio.run_coroutine_threadsafe(self._sync_after_session(), loop)
        except Exception:
            _log.warning("could not start the sync")

    async def _features(self, jid: str) -> List[str]:
        try:
            info = await self._client["xep_0030"].get_info(jid=jid, timeout=60)
            return [str(f) for f in info["disco_info"]["features"]]
        except Exception:
            return []

    async def _sync_after_session(self) -> None:
        client = self._client
        if client is None:
            return
        st = self._sync()
        own = self._own_bare_jid()
        try:
            server = str(client.boundjid.domain)
        except Exception:
            server = own.split("@", 1)[-1]
        server_features = await self._features(server)
        own_features = await self._features(own)
        if S.NS["carbons"] in server_features:
            try:
                iq = client.make_iq_set()
                iq.xml.append(ET.Element("{%s}enable" % S.NS["carbons"]))
                await iq.send(timeout=60)
                st["carbons"] = True
                _TRACE.record("sync", "carbons_enabled", "info")
            except Exception:
                _TRACE.record("sync", "carbons_refused", "warning")
        # Blocking, bookmarks and room self-ping (android_bridge.account_sync).
        after = getattr(self, "_account_after_session", None)
        if after is not None:
            try:
                await after(server_features, own_features)
            except Exception:
                _TRACE.record("sync", "account_sync_failed", "warning")
            self._sync_emit("account")
        if S.NS["mam"] in own_features:
            st["mam"] = True
            try:
                count = await self._catch_up(own)
                self._sync_emit("synced", count=count)
            except Exception as exc:
                _TRACE.record_exception("sync", "archive_failed", exc)

    async def _catch_up(self, own: str) -> int:
        """Read the archive after the cursor (or its newest page, the first
        time). Returns how many messages were handed up."""
        st = self._sync()
        cursor = st["cursor"]
        last = cursor.get(own)
        plan = S.archive_plan(last)
        shown = 0
        for _ in range(S.MAX_PAGES):
            page, fin_last, complete = await self._archive_page(plan)
            for archive_id, item in page:
                kind = S.classify(item)
                if kind in (S.SHOW_IN, S.SHOW_OUT) and st["seen"].first_time(item):
                    self._sync_emit("message", item=item)
                    shown += 1
            newest = fin_last or (page[-1][0] if page else "")
            if newest:
                cursor.set(own, newest)
            # The first sync on a device takes the newest page only.
            if not last or complete or not page or not newest:
                break
            plan = {"max": S.PAGE, "after": newest}
        _TRACE.record("sync", "archive_read", "info", count=shown)
        return shown

    async def _archive_page(self, plan: Dict[str, Any]):
        client = self._client
        iq = client.make_iq_set()
        query_id = iq["id"]
        q = ET.SubElement(iq.xml, "{%s}query" % S.NS["mam"])
        q.set("queryid", query_id)
        rsm = ET.SubElement(q, "{%s}set" % NS_RSM)
        ET.SubElement(rsm, "{%s}max" % NS_RSM).text = str(plan["max"])
        if "before" in plan:
            before = ET.SubElement(rsm, "{%s}before" % NS_RSM)
            if plan["before"]:
                before.text = plan["before"]
        if plan.get("after"):
            ET.SubElement(rsm, "{%s}after" % NS_RSM).text = plan["after"]
        collected: List[Any] = []
        self._sync()["queries"][query_id] = collected
        try:
            result = await iq.send(timeout=ARCHIVE_TIMEOUT)
        finally:
            self._sync()["queries"].pop(query_id, None)
        fin = result.xml.find("{%s}fin" % S.NS["mam"])
        complete = fin is not None and fin.get("complete") in ("true", "1")
        fin_last = ""
        if fin is not None:
            el = fin.find("{%s}set/{%s}last" % (NS_RSM, NS_RSM))
            if el is not None and el.text:
                fin_last = el.text.strip()[:128]
        own = self._own_bare_jid()
        page = []
        for xml in collected:
            got = S.parse_archive_result(xml, own, query_id)
            if got is not None:
                page.append(got)
        return page, fin_last, complete

    def _on_archive_result(self, xml: ET.Element, own: str) -> None:
        result = xml.find("{%s}result" % S.NS["mam"])
        sender = xml.get("from")
        if sender is not None and sender.split("/", 1)[0].lower() != own:
            return
        query_id = result.get("queryid") or ""
        bucket = self._sync()["queries"].get(query_id)
        if bucket is not None and len(bucket) < 10 * S.PAGE:
            bucket.append(xml)

    def forget_sync(self) -> None:
        """Wipe & Exit: the cursor goes with everything else."""
        try:
            self._sync()["cursor"].forget()
        except Exception:
            pass
