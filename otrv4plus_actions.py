# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Message actions: correct, delete for everyone, react, reply.

Owner (2026-10-14): "anything else conversations app uses".

TWO CARRIERS, ONE MEANING
=========================
In an ENCRYPTED conversation every typed message carries a MESSAGE_META TLV
(0x0021) inside the OTRv4 payload: its own id, and -- for an action -- the
id of the message it acts on. Inside the encrypted, authenticated payload
the server can neither read, forge nor redirect any of it: "Bob corrected
message 7" is as authentic as Bob's text, and names the message Bob's own
client named. An older client ignores the TLV (unknown TLVs MUST be
ignored) and simply shows the text, which for a correction or a reply is
the right fallback.

In a PLAINTEXT conversation the standard elements are used, so it works
with any XMPP client (Conversations, Gajim, Dino, ...):

    XEP-0308  <replace id='...' xmlns='urn:xmpp:message-correct:0'/>
    XEP-0424  <retract id='...' xmlns='urn:xmpp:message-retract:1'/>
    XEP-0444  <reactions id='...' xmlns='urn:xmpp:reactions:0'><reaction>..</reaction></reactions>
    XEP-0461  <reply id='...' to='...' xmlns='urn:xmpp:reply:0'/>

They are as trustworthy as plaintext is -- the server could forge them, as
it could forge the text -- and are never put on an encrypted message, where
they would tell the server what was done to which message.

THE RULES BOTH CARRIERS SHARE (enforced where the message is shown)
-------------------------------------------------------------------
  * a correction or a deletion only ever applies to a message by the SAME
    author it came from;
  * a reaction replaces that person's previous reactions on the message
    (XEP-0444 §3.2); an empty set removes them;
  * ids are opaque, bounded, and never shown.
"""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

__all__ = ["META_TLV", "encode_meta", "decode_meta", "ACTIONS",
           "action_elements", "parse_action", "valid_id", "clean_emojis",
           "RETRACT_FALLBACK"]

#: OTRv4TLV.MESSAGE_META in the engine.
META_TLV = 0x0021
MAX_META = 2048
MAX_ID = 128
MAX_EMOJI = 16
MAX_EMOJI_LEN = 32

ACTIONS = ("edit", "retract", "react")

NS = {
    "correct": "urn:xmpp:message-correct:0",
    "retract": "urn:xmpp:message-retract:1",
    "reactions": "urn:xmpp:reactions:0",
    "reply": "urn:xmpp:reply:0",
    "fallback": "urn:xmpp:fallback:0",
    "hints": "urn:xmpp:hints",
}

RETRACT_FALLBACK = ("This person attempted to retract a previous message, "
                    "but it's unsupported by your client.")

_ID = re.compile(r"^[A-Za-z0-9._:+/=-]{1,%d}$" % MAX_ID)


def valid_id(value: Any) -> bool:
    return isinstance(value, str) and bool(_ID.match(value))


def clean_emojis(values: Any) -> List[str]:
    """At most MAX_EMOJI distinct short strings with no control characters."""
    out: List[str] = []
    if not isinstance(values, (list, tuple)):
        return out
    for v in values:
        if not isinstance(v, str):
            continue
        v = v.strip()
        if not v or len(v) > MAX_EMOJI_LEN or any(ord(c) < 32 for c in v):
            continue
        if v not in out:
            out.append(v)
        if len(out) >= MAX_EMOJI:
            break
    return out


# -- the encrypted carrier (TLV 0x0021) ----------------------------------------

def encode_meta(message_id: str, edit: str = "", retract: str = "",
                react: str = "", emojis: Optional[List[str]] = None,
                reply: str = "") -> bytes:
    """The MESSAGE_META value for one message. At most one action."""
    if not valid_id(message_id):
        raise ValueError("bad message id")
    meta: Dict[str, Any] = {"v": 1, "id": message_id}
    chosen = [k for k, v in (("edit", edit), ("retract", retract), ("react", react)) if v]
    if len(chosen) > 1:
        raise ValueError("one action per message")
    for key, value in (("edit", edit), ("retract", retract), ("react", react),
                       ("reply", reply)):
        if value:
            if not valid_id(value):
                raise ValueError("bad target id")
            meta[key] = value
    if react:
        meta["emoji"] = clean_emojis(emojis or [])
    raw = json.dumps(meta, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(raw) > MAX_META:
        raise ValueError("meta too large")
    return raw


def decode_meta(value: bytes) -> Optional[Dict[str, Any]]:
    """A MESSAGE_META value -> {"id", "action", "target", "emojis", "reply"},
    or None if it is malformed (then the message is shown as plain text)."""
    if not isinstance(value, (bytes, bytearray)) or len(value) > MAX_META:
        return None
    try:
        meta = json.loads(bytes(value).decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(meta, dict) or meta.get("v") != 1 or not valid_id(meta.get("id")):
        return None
    out: Dict[str, Any] = {"id": meta["id"], "action": "", "target": "",
                           "emojis": [], "reply": ""}
    actions = [a for a in ACTIONS if a in meta]
    if len(actions) > 1:
        return None
    if actions:
        target = meta[actions[0]]
        if not valid_id(target):
            return None
        out["action"], out["target"] = actions[0], target
        if actions[0] == "react":
            out["emojis"] = clean_emojis(meta.get("emoji"))
    if "reply" in meta:
        if not valid_id(meta["reply"]):
            return None
        out["reply"] = meta["reply"]
    return out


# -- the plaintext carrier (standard XEPs) ---------------------------------------

def action_elements(action: str, target: str, emojis: Optional[List[str]] = None,
                    reply_to_jid: str = "") -> List[ET.Element]:
    """The XEP elements for a plaintext action (or a reply)."""
    if not valid_id(target):
        raise ValueError("bad target id")
    if action == "edit":
        return [ET.Element("{%s}replace" % NS["correct"], {"id": target})]
    if action == "retract":
        fb = ET.Element("{%s}fallback" % NS["fallback"], {"for": NS["retract"]})
        return [ET.Element("{%s}retract" % NS["retract"], {"id": target}), fb,
                ET.Element("{%s}store" % NS["hints"])]
    if action == "react":
        el = ET.Element("{%s}reactions" % NS["reactions"], {"id": target})
        for e in clean_emojis(emojis or []):
            ET.SubElement(el, "{%s}reaction" % NS["reactions"]).text = e
        return [el, ET.Element("{%s}store" % NS["hints"])]
    if action == "reply":
        attrs = {"id": target}
        if reply_to_jid:
            attrs["to"] = reply_to_jid
        return [ET.Element("{%s}reply" % NS["reply"], attrs)]
    raise ValueError(action)


def parse_action(msg: ET.Element) -> Dict[str, Any]:
    """{"action", "target", "emojis", "reply"} from a plaintext message's
    XEP elements (all empty when it carries none). Malformed ones are
    ignored, never half-applied."""
    out: Dict[str, Any] = {"action": "", "target": "", "emojis": [], "reply": ""}
    found = []
    el = msg.find("{%s}replace" % NS["correct"])
    if el is not None and valid_id(el.get("id")):
        found.append(("edit", el.get("id"), []))
    el = msg.find("{%s}retract" % NS["retract"])
    if el is not None and valid_id(el.get("id")):
        found.append(("retract", el.get("id"), []))
    el = msg.find("{%s}reactions" % NS["reactions"])
    if el is not None and valid_id(el.get("id")):
        found.append(("react", el.get("id"),
                      clean_emojis([r.text or "" for r in
                                    el.findall("{%s}reaction" % NS["reactions"])])))
    if len(found) == 1:
        out["action"], out["target"], out["emojis"] = found[0]
    el = msg.find("{%s}reply" % NS["reply"])
    if el is not None and valid_id(el.get("id")):
        out["reply"] = el.get("id")
    return out
