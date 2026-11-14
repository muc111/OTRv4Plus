# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Parsing an XEP-0077 registration CAPTCHA challenge, with no network in it.

A server that wants a CAPTCHA to create an account answers the registration
GET with a data form (XEP-0004) whose FORM_TYPE is `urn:xmpp:captcha`
(XEP-0158). The form carries:

  * one visible field the user must fill (an OCR field, usually `ocr`),
    with a XEP-0221 `<media/>` element pointing at the challenge image;
  * the image itself as a XEP-0231 bits-of-binary `<data xmlns='urn:xmpp:bob'>`
    object (base64, inline in the stanza), referenced by a `cid:` URI;
  * hidden fields (`FORM_TYPE`, `challenge`, `sid`, `from`, ...) that the
    submission must echo back unchanged.

THE ONE SECURITY RULE HERE
--------------------------
The image is rendered ONLY from an inline bits-of-binary object carried in
the stanza the server already sent us over the connection we already have.
A `<uri>` with an `http(s)`/`ftp` scheme -- a media element pointing at some
third-party web server -- is REFUSED, never fetched: fetching it would leak
the user's IP to that host and turn a registration form into a tracking
beacon. `cid:` (bits-of-binary) is the only accepted scheme, and only when
its data is present inline.

This module is pure: it turns the registration query's XML into a
`Challenge` (or says why it can't), and builds the field map a submission
must carry. The live stream flow that uses it is in
`transport_registration.py`; keeping the parsing here means every rule is a
unit test rather than something only a live CAPTCHA server could exercise.
"""
from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field as _dc_field
from typing import Dict, List, Optional, Tuple
from xml.etree import ElementTree as ET

_REGISTER = "jabber:iq:register"
_XDATA = "jabber:x:data"
_MEDIA = "urn:xmpp:media-element"       # XEP-0221
_BOB = "urn:xmpp:bob"                    # XEP-0231
_CAPTCHA_FORM_TYPE = "urn:xmpp:captcha"

#: The field vars XEP-0158 defines for a challenge answer. The presence of
#: any of them (or a media element) marks the field the user must fill.
_ANSWER_VARS = ("ocr", "qa", "audio_recog", "picture_q", "picture_recog",
                "speech_q", "speech_recog", "video_q", "video_recog")

#: Image types we will render, told by the file's own first bytes.
#:
#: The UI hands these bytes to the platform's image decoder, which picks a
#: codec by looking at the data and ignores any type we were told. So the
#: declared type restricts nothing: a server could say "image/png" and send
#: WebP, HEIF, BMP, ICO or a camera raw file, and reach that codec on a phone
#: whose owner has only tapped "create account". Those codecs are where
#: image-borne exploits have lived. Only the three formats a CAPTCHA is ever
#: made in get through, and the type reported onward is the one found.
_IMAGE_TYPES = ("image/png", "image/jpeg", "image/gif")
_MAGIC = ((b"\x89PNG\r\n\x1a\n", "image/png"),
          (b"\xff\xd8\xff", "image/jpeg"),
          (b"GIF87a", "image/gif"),
          (b"GIF89a", "image/gif"))


def sniff_image(data: bytes) -> Optional[str]:
    """The type the bytes are, or None if not one we show."""
    for magic, kind in _MAGIC:
        if data[:len(magic)] == magic:
            return kind
    return None

#: A hard cap on the inline image: a registration challenge is a few KB. This
#: stops a hostile or broken server making the bridge hold megabytes, and
#: bounds what crosses the FFI to the UI.
MAX_IMAGE_BYTES = 256 * 1024


class CaptchaError(Exception):
    """A challenge that cannot be honoured safely. `code` is one of the
    registration vocabulary codes so the Register screen can render it."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(detail or code)
        self.code = code
        self.detail = detail


@dataclass
class Challenge:
    """A CAPTCHA the user can be shown and can answer.

    `hidden` are the fields the submission must echo back verbatim;
    `answer_var` is the field the user's text goes in. `image_bytes` and
    `image_mime` are the inline challenge image. `instructions` is the
    server's prompt, if any (safe to show; it is the server's own text).

    `fields` maps every field the form declared to its XEP-0004 type
    (`text-single`, `text-private`, `hidden`, ...), and `required` is the set
    of vars the form marked `<required/>`. They let the submission be built
    from the server's own form -- filling username/password where the server
    put them as form fields, not assuming one server's layout -- so the same
    code works whatever the server software is."""
    answer_var: str
    hidden: Dict[str, List[str]]
    image_bytes: bytes
    image_mime: str
    instructions: str = ""
    sid: str = ""
    fields: Dict[str, str] = _dc_field(default_factory=dict)
    required: frozenset = frozenset()

    def image_base64(self) -> str:
        return base64.b64encode(self.image_bytes).decode("ascii")


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _ns(tag: str) -> str:
    return tag[1:].split("}", 1)[0] if tag.startswith("{") else ""


def _as_element(query) -> Optional[ET.Element]:
    """Accept an ElementTree element, bytes, or str of the <query> (or a
    wrapping <iq>). Returns the jabber:iq:register query element, or None."""
    el = query
    if isinstance(query, (bytes, bytearray, str)):
        data = query.encode("utf-8") if isinstance(query, str) else bytes(query)
        # XMPP forbids DTDs (RFC 6120 11.1), so a document carrying one is
        # refused unread: no entity can be declared, let alone expanded.
        if b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
            return None
        try:
            el = ET.fromstring(data)
        except ET.ParseError:
            return None
    if not hasattr(el, "tag"):
        return None
    if _ns(el.tag) == _REGISTER and _local(el.tag) == "query":
        return el
    # A whole <iq>: find the register query inside it.
    for child in el.iter():
        if _ns(child.tag) == _REGISTER and _local(child.tag) == "query":
            return child
    return None


def _form(query: ET.Element) -> Optional[ET.Element]:
    for child in query:
        if _ns(child.tag) == _XDATA and _local(child.tag) == "x":
            return child
    return None


def _field_values(field: ET.Element) -> List[str]:
    out = []
    for child in field:
        if _local(child.tag) == "value":
            out.append(child.text or "")
    return out


def _form_type(form: ET.Element) -> str:
    for field in form:
        if _local(field.tag) == "field" and field.get("var") == "FORM_TYPE":
            vals = _field_values(field)
            return vals[0] if vals else ""
    return ""


def is_captcha_query(query) -> bool:
    """Whether a registration query is a CAPTCHA challenge (vs. a plain
    username/password form). Cheap; does not extract the image."""
    el = _as_element(query)
    if el is None:
        return False
    form = _form(el)
    if form is None:
        return False
    if _form_type(form) == _CAPTCHA_FORM_TYPE:
        return True
    names = {f.get("var") for f in form if _local(f.tag) == "field"}
    return bool(names & set(_ANSWER_VARS))


def _collect_bob(query: ET.Element) -> Dict[str, Tuple[str, bytes]]:
    """Every inline bits-of-binary object in the stanza, by cid -> (type,
    bytes). Malformed base64 is skipped rather than raised on."""
    out: Dict[str, Tuple[str, bytes]] = {}
    for node in query.iter():
        if _ns(node.tag) == _BOB and _local(node.tag) == "data":
            cid = node.get("cid") or ""
            mime = (node.get("type") or "").lower()
            raw = (node.text or "").strip()
            if not cid or not raw:
                continue
            try:
                data = base64.b64decode(raw, validate=True)
            except (binascii.Error, ValueError):
                continue
            out[cid] = (mime, data)
    return out


def _answer_field(form: ET.Element) -> Optional[ET.Element]:
    """The field the user must fill: a known answer var, or the first field
    carrying a media element."""
    fields = [f for f in form if _local(f.tag) == "field"]
    by_var = {f.get("var"): f for f in fields}
    for var in _ANSWER_VARS:
        if var in by_var:
            return by_var[var]
    for f in fields:
        for child in f:
            if _ns(child.tag) == _MEDIA and _local(child.tag) == "media":
                return f
    return None


def _image_from_field(field: ET.Element, bob: Dict[str, Tuple[str, bytes]]
                      ) -> Tuple[str, bytes]:
    """The inline image a field's <media> points at. Raises CaptchaError if
    the only image offered is an external URL (refused) or none is inline."""
    saw_external = False
    for media in field:
        if not (_ns(media.tag) == _MEDIA and _local(media.tag) == "media"):
            continue
        for uri in media:
            if _local(uri.tag) != "uri":
                continue
            mime = (uri.get("type") or "").lower()
            target = (uri.text or "").strip()
            scheme = target.split(":", 1)[0].lower() if ":" in target else ""
            if scheme == "cid":
                cid = target[4:]
                if cid in bob:
                    found_mime, data = bob[cid]
                    return (found_mime or mime or "image/png", data)
            elif scheme in ("http", "https", "ftp"):
                saw_external = True
    if saw_external:
        raise CaptchaError(
            "registration_captcha_external",
            "This server's CAPTCHA image is hosted on a web page, which the "
            "app will not fetch (it would reveal your address). Register on "
            "the server's web page instead. Your password was not sent.")
    raise CaptchaError(
        "registration_captcha_unsupported",
        "This server's CAPTCHA did not include an image the app can show. "
        "Register on the server's web page instead. Your password was not "
        "sent.")


def extract_challenge(query) -> Challenge:
    """Turn a registration CAPTCHA query into a `Challenge`.

    Raises `CaptchaError` (with a registration code) when the challenge
    cannot be shown safely: an external-URL image, an image type we do not
    render, an oversized image, or a form we cannot read. Never fetches
    anything.
    """
    el = _as_element(query)
    if el is None:
        raise CaptchaError("registration_protocol_error",
                           "The server's registration reply could not be read.")
    form = _form(el)
    if form is None:
        raise CaptchaError("registration_protocol_error",
                           "The server's CAPTCHA form could not be read.")
    field = _answer_field(form)
    if field is None or not field.get("var"):
        raise CaptchaError("registration_captcha_unsupported",
                           "The server's CAPTCHA form had no answer field.")
    bob = _collect_bob(el)
    _declared, data = _image_from_field(field, bob)
    if len(data) > MAX_IMAGE_BYTES:
        raise CaptchaError("registration_captcha_unsupported",
                           "The server's CAPTCHA image was too large to show.")
    mime = sniff_image(data)
    if mime is None:
        raise CaptchaError("registration_captcha_unsupported",
                           "The server's CAPTCHA image is in a format the app "
                           "does not show. Register on its web page instead.")

    hidden: Dict[str, List[str]] = {}
    fields: Dict[str, str] = {}
    required = set()
    instructions = ""
    sid = ""
    for f in form:
        if _local(f.tag) != "field":
            continue
        var = f.get("var")
        if not var:
            continue
        ftype = f.get("type") or "text-single"
        fields[var] = ftype
        if any(_local(c.tag) == "required" for c in f):
            required.add(var)
        if ftype == "hidden":
            hidden[var] = _field_values(f)
            if var == "sid":
                vals = _field_values(f)
                sid = vals[0] if vals else ""
    # XEP-0231 also carries sid on the <data> element; fall back to it.
    for node in el.iter():
        if _ns(node.tag) == _BOB and _local(node.tag) == "data" and not sid:
            sid = ""  # cid, not sid; left blank when the form had none
    for child in form:
        if _local(child.tag) in ("instructions", "title"):
            instructions = (child.text or "").strip() or instructions
    if not instructions:
        # XEP-0077 allows the prompt at the query level, outside the data
        # form (XEP-0004 allows it inside); take whichever the server used.
        for child in el:
            if _local(child.tag) == "instructions":
                instructions = (child.text or "").strip() or instructions
    return Challenge(answer_var=field.get("var"), hidden=hidden,
                     image_bytes=data, image_mime=mime,
                     instructions=instructions, sid=sid,
                     fields=fields, required=frozenset(required))


#: Fields the submission fills itself. Anything else the form REQUIRES (an
#: e-mail address, a real name, ...) cannot be answered from the Register
#: screen, so such a form is treated as "more than a username and password".
_FILLABLE = frozenset({"username", "password"})


def missing_required(challenge: Challenge) -> List[str]:
    """Required fields the app cannot fill: not hidden (those are echoed), not
    the answer field, not username/password. A non-empty list means the form
    asks for more than the app can provide, so the caller should refuse with
    `registration_fields_required` rather than submit an incomplete form (which
    a server answers with an error the user cannot act on)."""
    out = []
    for var in challenge.required:
        if (var in challenge.hidden or var == challenge.answer_var
                or var in _FILLABLE):
            continue
        out.append(var)
    return out


def submission_fields(challenge: Challenge, answer: str,
                      username: Optional[str] = None,
                      password: Optional[str] = None) -> Dict[str, List[str]]:
    """The var -> values map a CAPTCHA submission must carry: every hidden
    field echoed back verbatim, the user's answer in the answer field, and --
    only where the server's own form declared them as fields -- the username
    and password. A server that reads the credentials from the data form
    (ejabberd's mod_register does) then finds them; one that reads the
    `<username>`/`<password>` sub-elements (which the caller also sends) is
    unaffected. The format therefore follows the server's form rather than
    assuming a particular server's layout."""
    fields: Dict[str, List[str]] = {k: list(v) for k, v in challenge.hidden.items()}
    fields[challenge.answer_var] = [answer]
    if username is not None and "username" in challenge.fields:
        fields["username"] = [username]
    if password is not None and "password" in challenge.fields:
        fields["password"] = [password]
    return fields
