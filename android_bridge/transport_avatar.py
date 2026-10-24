# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Profile pictures (XEP-0084) and the public profile over the XMPP
transport: fetching others', publishing and removing ours.

A mixin of XmppTransport (transport.py). What a picture may be (size,
format, what is stripped) is avatar.py; the profile fields are profile.py."""
from __future__ import annotations

import asyncio
from typing import Dict

import otrv4plus_muc as _muc

from . import avatar as _avatar
from . import profile as _profile
from .trace import TRACE as _TRACE
from .transport_base import CALL_TIMEOUT, TransportError


#: Error conditions with which a server that has no PEP (XEP-0163) refuses
#: an avatar publish -- Prosody without "pep" in modules_enabled.
PEP_MISSING = frozenset({"feature-not-implemented", "service-unavailable",
                         "item-not-found"})

#: Each of an avatar publish's two server round trips, the first carrying the
#: picture (about 20 KB of base64) up an I2P tunnel, which can be slow on a
#: fresh tunnel.
AVATAR_TIMEOUT = 120.0


def _avatar_publish_error(exc: BaseException) -> "TransportError":
    """What an avatar publish failure was, while the exception still says.

    Classified inside the coroutine: `_run` turns any exception that reaches
    it into "unexpected_error", which would hide the server's answer."""
    if isinstance(exc, TransportError):
        return exc
    if isinstance(exc, (asyncio.TimeoutError, TimeoutError)) or \
            type(exc).__name__ == "IqTimeout":
        return TransportError("timeout", "the server did not answer in time")
    cond = _muc._condition_of(exc)
    if cond in PEP_MISSING:
        return TransportError("pep_unavailable", cond)
    if cond:
        return TransportError("avatar_server_refused", cond)
    return TransportError("unexpected_error", type(exc).__name__)


class AvatarMixin:
    """Avatars and the profile. Mixed into XmppTransport."""

    # -- avatars (XEP-0084) ----------------------------------------------------

    _AVATAR_META = "{urn:xmpp:avatar:metadata}"
    _AVATAR_DATA = "{urn:xmpp:avatar:data}data"

    def _on_avatar_metadata(self, msg) -> None:
        """A contact announced an avatar. Fetched only if acceptable (PNG,
        within the size limits); see android_bridge.avatar."""
        try:
            jid = str(msg["from"]).split("/", 1)[0].lower()
            meta = next(msg.xml.iter(self._AVATAR_META + "metadata"), None)
            if not jid or meta is None:
                return
            infos = [dict(el.attrib) for el in
                     meta.iter(self._AVATAR_META + "info")][:16]
        except Exception:
            return
        wanted = self._avatars.note_metadata(jid, infos)
        if wanted:
            asyncio.ensure_future(self._fetch_avatar(jid, wanted))

    async def _fetch_avatar(self, jid: str, avatar_id: str) -> None:
        try:
            iq = await self._client["xep_0084"].retrieve_avatar(
                jid, avatar_id, timeout=CALL_TIMEOUT)
            el = next(iq.xml.iter(self._AVATAR_DATA), None)
            text = (el.text or "") if el is not None else ""
        except Exception:
            _TRACE.record("avatar", "fetch_failed", "info", peer=jid)
            return
        if len(text) > _avatar.MAX_B64_CHARS:
            _TRACE.record("avatar", "refused", "warning", peer=jid,
                          reason="too_large")
            return
        # Decoding is pure Python and can take a moment for a 256x256
        # image: off the loop thread, so the stream does not stall.
        loop = asyncio.get_event_loop()
        ok = await loop.run_in_executor(None, self._avatars.note_data,
                                        jid, avatar_id, text)
        _TRACE.record("avatar", "stored" if ok else "refused",
                      "info" if ok else "warning", peer=jid)

    def avatar_ids(self) -> Dict[str, str]:
        """Bare JID -> avatar id (SHA-1), for every avatar held."""
        return self._avatars.ids()

    def avatar(self, jid: str):
        """The decoded avatar for `jid` (android_bridge.avatar.Avatar) or None."""
        return self._avatars.get(jid)

    def publish_avatar(self, png: bytes) -> None:
        """Publish our own avatar. `png` must pass the same checks as any
        received avatar (android_bridge.avatar.decode_png). Raises
        TransportError."""
        if not self.is_connected:
            raise TransportError("not_connected", "not connected")
        png = bytes(png)
        try:
            if len(png) > _avatar.MAX_BYTES:
                raise _avatar.AvatarError("too_large")
            # Any picture the app made, fitted to our limits here: square,
            # at most OWN_SIZE, at most TARGET_BYTES.
            png = _avatar.fit(png)
        except _avatar.AvatarError as exc:
            raise TransportError("avatar_refused", exc.code)
        # Two round trips, each with its own AVATAR_TIMEOUT, and a little
        # over for the loop. Failures are already classified (see
        # _avatar_publish_error): a server without PEP (XEP-0163) is
        # "pep_unavailable", any other refusal names its condition.
        #
        # Some servers or I2P paths will not carry a stanza this size. After
        # an unanswered try a much smaller copy (SMALL_SIZE, a few KB) is sent
        # at once if the stream is still up, or on the next attempt if it
        # dropped; the result says which happened.
        self.avatar_sent_small = False
        dropped_before = getattr(self, "_disconnects", 0)
        small_first = getattr(self, "_avatar_small_next", False)
        first = _avatar.shrink(png) if small_first else png
        try:
            self._publish_avatar_png(first)
            self.avatar_sent_small = small_first and len(first) < len(png)
            return
        except TransportError as exc:
            if exc.code != "timeout":
                raise
            dropped = getattr(self, "_disconnects", 0) != dropped_before
            _TRACE.record("avatar", "publish_unanswered", "warning",
                          bytes=len(first), dropped=dropped,
                          small=small_first)
            self._avatar_small_next = True
            if small_first or dropped or not self.is_connected:
                raise TransportError("timeout", "dropped" if dropped else "no_answer")
        small = _avatar.shrink(png)
        if len(small) >= len(png):
            raise TransportError("timeout", "no_answer")
        self._publish_avatar_png(small)
        self.avatar_sent_small = True
        _TRACE.record("avatar", "published_small", "info", bytes=len(small))

    #: True when the last successful publish was the smaller copy.
    avatar_sent_small = False

    def _publish_avatar_png(self, png: bytes) -> None:
        w, h, _rgba = _avatar.decode_png(png)
        self._run(self._publish_avatar(png, w, h), 2 * AVATAR_TIMEOUT + 10)
        self._avatars.set_own(self._profile.jid, png)

    @staticmethod
    def _avatar_info(avatar_id: str, png: bytes, w: int, h: int) -> Dict[str, str]:
        """The XEP-0084 <info/> attributes, as text: slixmpp's serializer
        raises a TypeError on numbers here, and the metadata stanza would
        silently never be sent."""
        return {"id": avatar_id, "type": _avatar.PNG_TYPE, "bytes": str(len(png)),
                "width": str(w), "height": str(h)}

    async def _publish_avatar(self, png: bytes, w: int, h: int) -> None:
        import hashlib
        plugin = self._client["xep_0084"]
        # XEP-0084: the id IS the SHA-1 of the image -- a name, not security.
        avatar_id = hashlib.sha1(png, usedforsecurity=False).hexdigest()
        try:
            await plugin.publish_avatar(png, timeout=AVATAR_TIMEOUT)
            await plugin.publish_avatar_metadata(
                [self._avatar_info(avatar_id, png, w, h)], timeout=AVATAR_TIMEOUT)
        except Exception as exc:
            raise _avatar_publish_error(exc) from None

    # -- the XMPP profile (vcard-temp, XEP-0054) --------------------------------

    def get_profile(self, jid: str = "") -> Dict[str, str]:
        """`jid`'s profile (ours when empty), sanitised by
        android_bridge.profile. {} when there is none. Raises TransportError."""
        if not self.is_connected:
            raise TransportError("not_connected", "not connected")
        return self._run(self._get_profile(jid), CALL_TIMEOUT)

    async def _get_profile(self, jid: str) -> Dict[str, str]:
        iq = self._client.Iq()
        iq["type"] = "get"
        if jid:
            iq["to"] = str(jid).split("/", 1)[0]
        iq.append(_profile.ET.Element("{%s}vCard" % _profile.NS))
        try:
            reply = await iq.send(timeout=CALL_TIMEOUT)
        except Exception as exc:
            cond = ""
            try:
                cond = exc.iq["error"]["condition"]
            except Exception:
                pass
            if cond == "item-not-found":
                return {}
            raise TransportError("profile_unavailable", cond or type(exc).__name__)
        element = next(reply.xml.iter("{%s}vCard" % _profile.NS), None)
        return _profile.from_vcard(element)

    def set_profile(self, values: Dict[str, str]) -> Dict[str, str]:
        """Publish our profile; returns what was actually published (after
        sanitising). Raises TransportError."""
        if not self.is_connected:
            raise TransportError("not_connected", "not connected")
        clean = _profile.clean_profile(values)
        self._run(self._set_profile(clean), CALL_TIMEOUT)
        return clean

    async def _set_profile(self, clean: Dict[str, str]) -> None:
        iq = self._client.Iq()
        iq["type"] = "set"
        iq.append(_profile.to_vcard(clean))
        await iq.send(timeout=CALL_TIMEOUT)

    def remove_avatar(self) -> None:
        """Stop publishing our avatar (empty metadata). Raises TransportError."""
        if not self.is_connected:
            raise TransportError("not_connected", "not connected")
        self._run(self._remove_avatar(), CALL_TIMEOUT)
        self._avatars.forget(self._profile.jid)

    async def _remove_avatar(self) -> None:
        await self._client["xep_0084"].stop(timeout=CALL_TIMEOUT)
