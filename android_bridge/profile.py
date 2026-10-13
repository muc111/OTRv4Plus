# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The XMPP profile (vcard-temp, XEP-0054): read, edit, sanitise.

vcard-temp is what Prosody's `vcard` module serves and what nearly every
XMPP client reads. A profile is text somebody else wrote, so it is treated
like the avatar: a FIXED set of fields, each with a length cap and a shape,
and everything else dropped.

  * Only the fields in FIELDS are read or written. Any other element -- a
    PHOTO, a KEY, an unknown extension -- is ignored on the way in and never
    written on the way out. (Pictures are XEP-0084, android_bridge.avatar.)
  * Control and formatting characters are removed, including the Unicode
    bidi overrides that make "gpj.exe" display as "exe.jpg". Newlines survive
    only in the note. Text is NFC-normalised.
  * Shaped fields are checked: a birthday is YYYY-MM-DD, a phone number is
    digits and + ( ) - space, an e-mail has one @ and no spaces, a web
    address is http(s) and is shown as text, never as a link.
  * Lengths are capped, and so is the number of characters overall.

PRIVACY. On Prosody (mod_vcard) any user of the server can read any other
user's vcard-temp; it is not limited to contacts. The app says so where the
profile is edited.
"""
from __future__ import annotations

import re
import unicodedata
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple

__all__ = ["FIELDS", "NS", "clean_field", "clean_profile", "from_vcard",
           "to_vcard"]

NS = "vcard-temp"
_Q = "{%s}" % NS

#: (key, label, element path under <vCard/>, max length, multi-line)
FIELDS: List[Tuple[str, str, str, int, bool]] = [
    ("fn", "Full name", "FN", 100, False),
    ("given", "First name", "N/GIVEN", 60, False),
    ("family", "Last name", "N/FAMILY", 60, False),
    ("nickname", "Nickname", "NICKNAME", 60, False),
    ("bday", "Birthday (YYYY-MM-DD)", "BDAY", 10, False),
    ("email", "E-mail", "EMAIL/USERID", 120, False),
    ("tel", "Phone", "TEL/NUMBER", 32, False),
    ("url", "Web site", "URL", 200, False),
    ("org", "Organisation", "ORG/ORGNAME", 100, False),
    ("title", "Job title", "TITLE", 100, False),
    ("role", "Role", "ROLE", 100, False),
    ("locality", "Town / city", "ADR/LOCALITY", 80, False),
    ("region", "Region", "ADR/REGION", 80, False),
    ("country", "Country", "ADR/CTRY", 80, False),
    ("desc", "About me", "DESC", 1000, True),
]
_BY_KEY = {f[0]: f for f in FIELDS}
#: The whole profile, every field together.
MAX_TOTAL = 3000

_BDAY = re.compile(r"\d{4}-\d{2}-\d{2}")
_TEL = re.compile(r"[0-9+()\- ]{3,32}")
_EMAIL = re.compile(r"[^@\s<>\"']{1,64}@[^@\s<>\"']{1,120}")
_URL = re.compile(r"https?://[^\s<>\"']{1,190}", re.IGNORECASE)


def clean_field(key: str, value) -> str:
    """One field's value, sanitised; "" when it is not acceptable."""
    spec = _BY_KEY.get(key)
    if spec is None:
        return ""
    _key, _label, _path, limit, multiline = spec
    text = unicodedata.normalize("NFC", str(value or ""))
    kept = []
    for ch in text:
        if ch == "\n" and multiline:
            kept.append(ch)
            continue
        if ch in "\r\t\n":
            kept.append(" ")
            continue
        # Cc: control characters. Cf: format characters, which include the
        # bidi overrides (U+202A-202E, U+2066-2069) and zero-width joiners.
        # Cs/Co/Cn: surrogates, private use, unassigned.
        if unicodedata.category(ch) in ("Cc", "Cf", "Cs", "Co", "Cn"):
            continue
        kept.append(ch)
    text = "".join(kept)
    if multiline:
        text = "\n".join(" ".join(line.split()) for line in text.split("\n"))
        text = re.sub(r"\n{3,}", "\n\n", text).strip()
    else:
        text = " ".join(text.split())
    text = text[:limit]
    if not text:
        return ""
    if key == "bday" and not _BDAY.fullmatch(text):
        return ""
    if key == "tel" and not _TEL.fullmatch(text):
        return ""
    if key == "email" and not _EMAIL.fullmatch(text):
        return ""
    if key == "url" and not _URL.fullmatch(text):
        return ""
    return text


def clean_profile(values: Dict) -> Dict[str, str]:
    """Every known field, sanitised; unknown keys dropped; total capped."""
    out: Dict[str, str] = {}
    total = 0
    for key, *_rest in FIELDS:
        value = clean_field(key, (values or {}).get(key, ""))
        if not value:
            continue
        if total + len(value) > MAX_TOTAL:
            break
        out[key] = value
        total += len(value)
    return out


def from_vcard(element: Optional[ET.Element]) -> Dict[str, str]:
    """A received <vCard xmlns='vcard-temp'/> as a clean profile."""
    if element is None:
        return {}
    raw: Dict[str, str] = {}
    for key, _label, path, _limit, _multi in FIELDS:
        node = element
        for part in path.split("/"):
            node = node.find(_Q + part) if node is not None else None
        if node is not None and node.text:
            raw[key] = node.text[:4096]
    return clean_profile(raw)


def to_vcard(values: Dict) -> ET.Element:
    """A clean profile as <vCard xmlns='vcard-temp'/>, for publishing."""
    clean = clean_profile(values)
    vcard = ET.Element(_Q + "vCard")
    parents: Dict[str, ET.Element] = {}
    for key, _label, path, _limit, _multi in FIELDS:
        value = clean.get(key)
        if not value:
            continue
        parts = path.split("/")
        if len(parts) == 1:
            ET.SubElement(vcard, _Q + parts[0]).text = value
            continue
        parent = parents.get(parts[0])
        if parent is None:
            parent = parents[parts[0]] = ET.SubElement(vcard, _Q + parts[0])
            # vcard-temp type flags the major clients expect.
            if parts[0] == "EMAIL":
                ET.SubElement(parent, _Q + "INTERNET")
            elif parts[0] == "TEL":
                ET.SubElement(parent, _Q + "VOICE")
            elif parts[0] == "ADR":
                ET.SubElement(parent, _Q + "HOME")
        ET.SubElement(parent, _Q + parts[1]).text = value
    return vcard
