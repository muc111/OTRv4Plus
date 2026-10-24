# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The terminal client's carbons, history, blocking, replies and reactions.

The same rules as the app (otrv4plus_sync, otrv4plus_actions), printed:

  * our OTR frames are kept off our other devices and out of the server's
    archive (an outbound stanza filter adds the hints to every one);
  * carbons: what our other devices send and receive in PLAINTEXT is shown
    as "[other device] ..."; OTR frames for them never are;
  * history: on connect, plaintext from the archive since this device last
    looked, as "[history] ..." (at most a page the first time);
  * /block <jid> [spam], /unblock <jid>, /blocked -- on the server
    (XEP-0191, with a XEP-0377 report);
  * /reply <text>, /edit <text>, /retract, /react <emoji>: reply to their
    last message, correct or delete your last one, react to their last one.
    Inside OTR when the conversation is encrypted (MESSAGE_META), the
    standard XEPs when it is plaintext, never in the clear to a
    conversation that asked for OTR.

Mixed into OTRv4PlusXMPP. Every method tolerates a client built without
__init__ (the test doubles), and nothing here touches key material.
"""
from __future__ import annotations

import asyncio
import collections
import os
import sys
import xml.etree.ElementTree as ET
from typing import Any, Dict, Optional

import otrv4plus_actions as A
import otrv4plus_sync as S

#: How many recent messages per contact are remembered for /reply, /edit.
RECENT = 32


class TermSyncMixin:

    def _tsync(self) -> Dict[str, Any]:
        st = getattr(self, "_tsync_state", None)
        if st is None:
            st = self._tsync_state = {
                "stash": {}, "recent": {}, "seen": S.Seen(), "queries": {},
                "blocking": False, "blocked": set(), "installed": False,
            }
        return st

    # -- setup ------------------------------------------------------------------

    def _ts_install(self) -> None:
        st = self._tsync()
        if st["installed"]:
            return
        st["installed"] = True
        A.install(getattr(self, "otr", None))
        try:
            self.add_filter("out", self._ts_out_filter)
        except Exception:
            pass
        try:
            from slixmpp.xmlstream.handler import Callback
            from slixmpp.xmlstream.matcher import MatchXPath
            self.register_handler(Callback(
                "OTRv4Plus terminal sync", MatchXPath("{jabber:client}message"),
                self._ts_on_any))
        except Exception:
            pass

    def _ts_out_filter(self, stanza):
        """Every outgoing OTR frame: not copied to our other devices, not
        archived (XEP-0280 private, XEP-0334 hints). Returns it unchanged
        otherwise -- a filter that returns None drops the stanza."""
        try:
            xml = stanza.xml
            if xml.tag.endswith("message"):
                body = xml.find("{jabber:client}body")
                text = body.text if body is not None else ""
                if text and text.startswith("?OTRv4") and \
                        xml.find("{%s}private" % S.NS["carbons"]) is None:
                    for el in S.otr_hints():
                        xml.append(el)
        except Exception:
            pass
        return stanza

    def _ts_own(self) -> str:
        try:
            return str(self.boundjid.bare).lower()
        except Exception:
            return ""

    async def _ts_after_session(self) -> None:
        """Carbons on, the blocking list, then the archive since last time."""
        own = self._ts_own()
        try:
            server = str(self.boundjid.domain)
        except Exception:
            return
        server_features = await self._ts_features(server)
        own_features = await self._ts_features(own)
        if S.NS["carbons"] in server_features:
            try:
                iq = self.make_iq_set()
                iq.xml.append(ET.Element("{%s}enable" % S.NS["carbons"]))
                await iq.send(timeout=60)
                print("[sync] messages from your other devices will show here too")
            except Exception:
                pass
        if S.NS["blocking"] in server_features:
            self._tsync()["blocking"] = True
            try:
                iq = self.make_iq_get()
                iq.xml.append(ET.Element("{%s}blocklist" % S.NS["blocking"]))
                result = await iq.send(timeout=60)
                self._tsync()["blocked"] = set(S.parse_blocklist(result.xml))
            except Exception:
                pass
        if S.NS["mam"] in own_features:
            try:
                await self._ts_history(own)
            except Exception:
                pass

    async def _ts_features(self, jid: str):
        try:
            info = await self.plugin["xep_0030"].get_info(jid=jid, timeout=60)
            return [str(f) for f in info["disco_info"]["features"]]
        except Exception:
            return []

    # -- the archive -----------------------------------------------------------------

    def _ts_cursor(self) -> S.ArchiveCursor:
        state = getattr(sys.modules.get(type(self).__module__), "_xmpp_state_path", None)
        path = state("archive-cursor.json") if state else os.path.expanduser(
            "~/.otrv4plus/xmpp/archive-cursor.json")
        return S.ArchiveCursor(path)

    async def _ts_history(self, own: str) -> None:
        cursor = self._ts_cursor()
        last = cursor.get(own)
        plan = S.archive_plan(last)
        shown = 0
        for _ in range(S.MAX_PAGES):
            iq = self.make_iq_set()
            qid = iq["id"]
            q = ET.SubElement(iq.xml, "{%s}query" % S.NS["mam"], {"queryid": qid})
            rsm = ET.SubElement(q, "{http://jabber.org/protocol/rsm}set")
            ET.SubElement(rsm, "{http://jabber.org/protocol/rsm}max").text = str(plan["max"])
            if "before" in plan:
                ET.SubElement(rsm, "{http://jabber.org/protocol/rsm}before")
            if plan.get("after"):
                ET.SubElement(rsm, "{http://jabber.org/protocol/rsm}after").text = plan["after"]
            bucket = self._tsync()["queries"].setdefault(qid, [])
            try:
                result = await iq.send(timeout=90)
            finally:
                self._tsync()["queries"].pop(qid, None)
            page = [g for g in (S.parse_archive_result(x, own, qid) for x in bucket) if g]
            for _aid, item in page:
                if S.classify(item) in (S.SHOW_IN, S.SHOW_OUT) and \
                        self._tsync()["seen"].first_time(item):
                    self._ts_print_copy(item, "[history]")
                    shown += 1
            fin = result.xml.find("{%s}fin" % S.NS["mam"])
            el = fin.find("{http://jabber.org/protocol/rsm}set/{http://jabber.org/protocol/rsm}last") \
                if fin is not None else None
            newest = (el.text or "").strip() if el is not None and el.text else \
                (page[-1][0] if page else "")
            if newest:
                cursor.set(own, newest)
            if not last or not page or (fin is not None and fin.get("complete") == "true"):
                break
            plan = {"max": S.PAGE, "after": newest}
        if shown:
            print("[history] %d message(s) from while this device was away" % shown)

    # -- inbound copies, plaintext actions ----------------------------------------------

    def _ts_on_any(self, stanza) -> None:
        try:
            xml = stanza.xml
            own = self._ts_own()
            result = xml.find("{%s}result" % S.NS["mam"])
            if result is not None:
                sender = xml.get("from")
                if sender is None or sender.split("/", 1)[0].lower() == own:
                    bucket = self._tsync()["queries"].get(result.get("queryid") or "")
                    if bucket is not None and len(bucket) < 10 * S.PAGE:
                        bucket.append(xml)
                return
            if xml.find("{%s}received" % S.NS["carbons"]) is not None or \
                    xml.find("{%s}sent" % S.NS["carbons"]) is not None:
                item = S.unwrap_carbon(xml, own)
                if item is not None and S.classify(item) in (S.SHOW_IN, S.SHOW_OUT) \
                        and self._tsync()["seen"].first_time(item):
                    self._ts_print_copy(item, "[other device]")
                return
            if xml.get("type") in ("groupchat", "error"):
                return
            if xml.find("{urn:xmpp:message-retract:1}retract") is not None or \
                    xml.find("{urn:xmpp:reactions:0}reactions") is not None:
                item = S.parse_message(xml, own, "live")
                if item is not None and item.action in ("retract", "react") and \
                        item.direction == "in" and self._tsync()["seen"].first_time(item):
                    self._ts_show_action(item.peer, item.action, item.target, "",
                                         list(item.emojis))
        except Exception:
            pass

    def _ts_print_copy(self, item: S.Item, tag: str) -> None:
        from otrv4plus_term import _sanitise
        if item.action:
            self._ts_show_action(item.peer, item.action, item.target, item.body,
                                 list(item.emojis), mine=item.direction == "out", tag=tag)
            return
        body = _sanitise(S.strip_whitespace_tag(item.body))
        who = "you -> %s" % _sanitise(item.peer, 128) if item.direction == "out" \
            else _sanitise(item.peer, 128)
        print("%s [plain] %s: %s" % (tag, who, body))
        self._ts_remember(item.peer, item.ref, item.body, item.direction == "out")

    # -- MESSAGE_META inside OTR ----------------------------------------------------------

    def _ts_on_meta(self, peer: str, value: bytes) -> None:
        meta = A.decode_meta(value)
        if meta is not None:
            self._tsync()["stash"][str(peer).lower()] = meta

    def _ts_decrypt(self, peer, body):
        """Decrypt and take the frame's MESSAGE_META in one step, on the OTR
        worker, so the next frame cannot overwrite it in between."""
        stash = self._tsync()["stash"]
        stash.pop(str(peer).lower(), None)
        with A.receiving(self._ts_on_meta):
            out = self.otr.handle_incoming_message(peer, body)
        return out, stash.pop(str(peer).lower(), None)

    def _ts_encrypt(self, peer: str, text: str, reply: str = ""):
        """(frame, should_send, id) for a typed line: with MESSAGE_META when a
        session is up, otherwise exactly what handle_outgoing_message does."""
        mid = S.new_message_id()
        send_meta = getattr(self.otr, "send_text_with_tlv", None)
        if send_meta is not None:
            try:
                frame = send_meta(peer, text, A.META_TLV, A.encode_meta(mid, reply=reply))
            except Exception:
                frame = None
            if frame:
                return frame, True, mid
        frame, should = self.otr.handle_outgoing_message(peer, text)
        return frame, should, ""

    # -- remembered messages, for /reply /edit /retract /react ----------------------

    def _ts_remember(self, peer: str, mid: str, text: str, mine: bool) -> None:
        if not mid:
            return
        recent = self._tsync()["recent"].setdefault(
            str(peer).lower(), collections.deque(maxlen=RECENT))
        recent.append({"id": mid, "text": text, "mine": mine})

    def _ts_find(self, peer: str, mid: str) -> Optional[Dict[str, Any]]:
        for m in reversed(self._tsync()["recent"].get(str(peer).lower(), ())):
            if m["id"] == mid:
                return m
        return None

    def _ts_last(self, peer: str, mine: bool) -> Optional[Dict[str, Any]]:
        for m in reversed(self._tsync()["recent"].get(str(peer).lower(), ())):
            if m["mine"] == mine:
                return m
        return None

    def _ts_reply_prefix(self, peer: str, reply: str) -> str:
        from otrv4plus_term import _sanitise
        if not reply:
            return ""
        target = self._ts_find(peer, reply)
        quote = _sanitise((target or {}).get("text", "an earlier message"))[:50]
        return '(re: "%s") ' % quote

    def _ts_show_action(self, peer: str, action: str, target: str, body: str,
                        emojis, mine: bool = False, tag: str = "") -> None:
        """Print what a correction, deletion or reaction did. The author
        rule: a correction or deletion only applies to that author's own
        message."""
        from otrv4plus_term import _sanitise
        who = "you" if mine else _sanitise(peer, 128)
        m = self._ts_find(peer, target)
        snippet = _sanitise((m or {}).get("text", "a message"))[:50]
        prefix = (tag + " ") if tag else ""
        if action in ("edit", "retract") and m is not None and m["mine"] != mine:
            print("%s[ignored] %s tried to change a message they did not write"
                  % (prefix, who))
            return
        if action == "edit":
            if m is not None:
                m["text"] = body
            print('%s[edited] %s: %s   (was: "%s")' % (prefix, who, _sanitise(body), snippet))
        elif action == "retract":
            if m is not None:
                m["text"] = "(deleted)"
            print('%s[deleted] %s deleted a message: "%s"' % (prefix, who, snippet))
        elif action == "react":
            shown = " ".join(_sanitise(e, 32) for e in emojis) or "(removed)"
            print('%s[reaction] %s %s on: "%s"' % (prefix, who, shown, snippet))

    # -- commands -----------------------------------------------------------------------

    TS_HELP = (
        "  /reply <text>        reply to their last message (quoted)\n"
        "  /edit <text>         correct your last message\n"
        "  /retract             delete your last message for everyone\n"
        "  /react <emoji>       react to their last message (/react - removes)\n"
        )

    def _ts_command(self, line: str, peer: Optional[str]) -> bool:
        """Handle a sync/action command. True if it was one."""
        word, _, rest = line.strip().partition(" ")
        rest = rest.strip()
        if word == "/blocked":
            server = sorted(self._tsync()["blocked"])
            if server:
                print("[block] on the server: %s" % ", ".join(server))
            return False                   # the client's own list follows
        if word in ("/block", "/unblock"):
            parts = rest.split()
            if not parts:
                return False               # the client's own usage line
            jid = parts[0]
            report = "spam" if word == "/block" and parts[1:2] == ["spam"] else ""
            # This session first, exactly as /block always did ...
            local = getattr(self, "block_peer" if word == "/block" else "unblock_peer", None)
            if local is not None:
                local(jid)
            # ... then the server, for every device (XEP-0191).
            if self._tsync()["blocking"]:
                try:
                    asyncio.get_running_loop()
                    asyncio.ensure_future(self._ts_block_server(
                        word, jid.split("/", 1)[0].lower(), report))
                except RuntimeError:
                    pass                   # no loop (a test): this session only
            return True
        if word not in ("/reply", "/edit", "/retract", "/react"):
            return False
        if not peer:
            print("[action] open a conversation first (/to <jid>)")
            return True
        peer = str(peer).split("/", 1)[0].lower()
        if word == "/reply":
            target = self._ts_last(peer, mine=False)
            if not rest or target is None:
                print("[reply] usage: /reply <text> (replies to their last message)")
                return True
            self._ts_send_action(peer, "reply", target["id"], rest)
        elif word == "/edit":
            target = self._ts_last(peer, mine=True)
            if not rest or target is None:
                print("[edit] usage: /edit <new text> (corrects your last message)")
                return True
            self._ts_send_action(peer, "edit", target["id"], rest)
        elif word == "/retract":
            target = self._ts_last(peer, mine=True)
            if target is None:
                print("[retract] you have not sent anything here yet")
                return True
            self._ts_send_action(peer, "retract", target["id"], "")
        else:
            target = self._ts_last(peer, mine=False)
            if target is None or not rest:
                print("[react] usage: /react <emoji> (on their last message; - removes)")
                return True
            emojis = [] if rest == "-" else A.clean_emojis(rest.split())
            self._ts_send_action(peer, "react", target["id"], "", emojis)
        return True

    def _ts_send_action(self, peer: str, action: str, target: str, text: str,
                        emojis=None) -> None:
        from otrv4plus_term import _sanitise
        mid = S.new_message_id()
        encrypted = peer in getattr(self, "_encrypted", ())
        if encrypted:
            send_meta = getattr(self.otr, "send_text_with_tlv", None)
            kw = {"reply": target} if action == "reply" else {action: target}
            try:
                frame = send_meta(peer, text, A.META_TLV,
                                  A.encode_meta(mid, emojis=emojis, **kw)) if send_meta else None
            except Exception:
                frame = None
            if not frame:
                print("[%s] could not encrypt it; nothing was sent" % action)
                return
            self.send_otr_fragmented(peer, frame if isinstance(frame, str) else frame.decode())
        else:
            mode = getattr(self, "_otr_mode", None)
            if mode is None or not mode.may_send_plaintext(peer, False) or \
                    peer in getattr(self, "_otr_capable", ()):
                print("[%s] not sent: this conversation is waiting for encryption" % action)
                return
            try:
                msg = self.make_message(mto=peer, mbody=(
                    text if action in ("edit", "reply") else
                    A.RETRACT_FALLBACK if action == "retract" else None), mtype="chat")
                origin = ET.Element("{%s}origin-id" % S.NS["sid"], {"id": mid})
                msg.xml.append(origin)
                for el in A.action_elements(action, target, emojis):
                    msg.xml.append(el)
                msg["id"] = mid
                msg.send()
            except Exception as exc:
                print("[%s] send failed: %s" % (action, _sanitise(str(exc), 120)))
                return
        if action == "reply":
            self._ts_remember(peer, mid, text, True)
            print("%s %s%s" % ("[otr] you:" if encrypted else "[plain] you:",
                               self._ts_reply_prefix(peer, target), _sanitise(text)))
        else:
            self._ts_show_action(peer, action, target, text, emojis or [], mine=True)

    async def _ts_block_server(self, word: str, jid: str, report: str) -> None:
        """The same on the server (XEP-0191): every device of the account, and
        they stop seeing our presence; optionally reported as spam."""
        from otrv4plus_term import _sanitise
        st = self._tsync()
        try:
            iq = self.make_iq_set()
            iq.xml.append(S.blocking_payload(word[1:], [jid], report))
            await iq.send(timeout=60)
        except Exception as exc:
            print("[block] the server refused: %s" % _sanitise(str(exc), 120))
            return
        if word == "/block":
            st["blocked"].add(jid)
            print("[block] %s is blocked on every device of this account%s"
                  % (jid, " and reported as spam" if report else ""))
        else:
            st["blocked"].discard(jid)
            print("[block] the server has unblocked %s" % jid)
