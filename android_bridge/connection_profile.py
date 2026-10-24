# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The controller's profile pictures and public profile.

A mixin of ConnectionController (connection.py): the apps' calls for
avatars and profile fields, forwarded to the transport on the worker."""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from .trace import TRACE as _TRACE


class ProfileControlMixin:
    """Avatars and the profile. Mixed into ConnectionController."""

    # -- avatars --------------------------------------------------------------

    def avatar_ids(self) -> Dict[str, str]:
        """Bare JID -> avatar id, for every avatar held. Cheap: the app polls
        it and fetches pixels only for an id it has not drawn yet."""
        ids = getattr(self._transport, "avatar_ids", None)
        if ids is None:
            return {}
        try:
            return dict(ids())
        except Exception:
            return {}

    def avatar_pixels(self, jid: str) -> Optional[Dict[str, Any]]:
        """{id, width, height, rgba} for `jid`, or None.

        `rgba` is raw pixels, 4 bytes each -- the app turns them into the
        int array Bitmap.createBitmap(int[], ...) takes, so the picture is
        built from numbers and no image decoder of the platform reads the
        file a peer sent (android_bridge.avatar)."""
        get = getattr(self._transport, "avatar", None)
        if get is None:
            return None
        try:
            avatar = get(jid)
        except Exception:
            return None
        if avatar is None:
            return None
        import base64
        rgba = bytes(avatar.rgba)
        # Base64 TEXT for Kotlin (android.util.Base64 -- a text decoder, not
        # an image decoder), plus the raw bytes for Python callers.
        return {"id": avatar.id, "width": avatar.width,
                "height": avatar.height, "rgba": rgba,
                "rgba_b64": base64.b64encode(rgba).decode("ascii")}

    def avatar_index(self) -> List[str]:
        """`avatar_ids` as "jid<TAB>id" strings: a plain list of strings is
        the one shape the Kotlin side reads everywhere."""
        return ["%s\t%s" % (jid, aid) for jid, aid in sorted(self.avatar_ids().items())]

    def set_avatar(self, png) -> Dict[str, Any]:
        """Publish our avatar: PNG bytes the app made (scaled, re-encoded)."""
        transport = self._transport
        if transport is None or not hasattr(transport, "publish_avatar"):
            return {"ok": False, "code": "not_connected",
                    "detail": "Connect first.", "value": None}
        try:
            transport.publish_avatar(bytes(png))
        except Exception as exc:
            # TransportError carries `code` and `detail`; anything else is
            # named by its type only.
            code = getattr(exc, "code", None) or type(exc).__name__
            # The condition (an XMPP error name) or exception type: never
            # identifying, and what the next report needs.
            _TRACE.record("avatar", "publish_failed", "warning", code=code,
                          detail=str(getattr(exc, "detail", ""))[:64])
            if code == "pep_unavailable":
                detail = ("This server does not store profile pictures (it has "
                          "no PEP service). Its admin can turn it on -- "
                          "Prosody: add \"pep\" to modules_enabled.")
            elif code == "avatar_refused":
                detail = ("The picture could not be used (%s)."
                          % getattr(exc, "detail", ""))
            elif code == "timeout" and getattr(exc, "detail", "") == "dropped":
                detail = ("The connection to the server dropped while the "
                          "picture was being sent: the server or the I2P path "
                          "would not carry it. Try again once reconnected -- "
                          "a smaller copy is sent next time.")
            elif code == "timeout":
                detail = ("The server did not answer in time over I2P, even "
                          "for a smaller copy. Its log will say why (Prosody: "
                          "look for \"pep\" or \"stanza size\" at that time). "
                          "Try again in a minute.")
            elif code == "avatar_server_refused":
                cond = str(getattr(exc, "detail", ""))[:64]
                if cond in ("not-acceptable", "policy-violation",
                            "resource-constraint"):
                    detail = ("The server refused the picture as too large or "
                              "not allowed (%s)." % cond)
                elif cond in ("forbidden", "not-authorized", "not-allowed"):
                    detail = ("The server does not let this account store a "
                              "picture (%s). Its admin can check the PEP "
                              "settings." % cond)
                else:
                    detail = "The server refused the picture (%s)." % cond
            else:
                # Named, so a report says what happened.
                detail = ("The picture could not be published (%s)."
                          % (getattr(exc, "detail", "") or code))
            return {"ok": False, "code": code, "detail": detail, "value": None}
        _TRACE.record("avatar", "published", "info")
        if getattr(transport, "avatar_sent_small", False):
            return {"ok": True, "code": "ok", "value": None,
                    "detail": "Your picture is updated (sent smaller, 48 x 48: "
                              "the full size got no answer over I2P)."}
        return {"ok": True, "code": "ok", "detail": "", "value": None}

    def set_avatar_b64(self, text: str) -> Dict[str, Any]:
        """`set_avatar` for the Kotlin side, which passes base64 text (the
        one byte transport this bridge uses everywhere)."""
        import base64
        import binascii
        from . import avatar as _avatar_mod
        text = str(text or "")
        if len(text) > _avatar_mod.MAX_B64_CHARS:
            return {"ok": False, "code": "avatar_refused",
                    "detail": "The picture is too large.", "value": None}
        try:
            png = base64.b64decode(text, validate=True)
        except (binascii.Error, ValueError):
            return {"ok": False, "code": "avatar_refused",
                    "detail": "The picture could not be read.", "value": None}
        return self.set_avatar(png)

    def remove_avatar(self) -> Dict[str, Any]:
        transport = self._transport
        if transport is None or not hasattr(transport, "remove_avatar"):
            return {"ok": False, "code": "not_connected",
                    "detail": "Connect first.", "value": None}
        try:
            transport.remove_avatar()
        except Exception as exc:
            return {"ok": False, "code": getattr(exc, "code", "unexpected_error"),
                    "detail": "The picture could not be removed.", "value": None}
        return {"ok": True, "code": "ok", "detail": "", "value": None}

    # -- the XMPP profile ----------------------------------------------------

    def profile_fields(self) -> List[str]:
        """The editable fields, as "key<TAB>label<TAB>maxlen<TAB>multiline".
        The app builds its form from this, so the two cannot drift."""
        from . import profile as _p
        return ["%s\t%s\t%d\t%d" % (k, label, limit, 1 if multi else 0)
                for k, label, _path, limit, multi in _p.FIELDS]

    def profile_get_json(self, jid: str = "") -> Dict[str, Any]:
        """{ok, code, detail, value: JSON object of fields}. `jid` empty =
        our own. Everything in `value` has been sanitised."""
        import json
        transport = self._transport
        if transport is None or not hasattr(transport, "get_profile"):
            return {"ok": False, "code": "not_connected",
                    "detail": "Connect first.", "value": None}
        try:
            values = transport.get_profile(str(jid or ""))
        except Exception as exc:
            code = getattr(exc, "code", None) or type(exc).__name__
            _TRACE.record("profile", "get_failed", "warning", code=code)
            return {"ok": False, "code": code,
                    "detail": "The profile could not be read.", "value": None}
        return {"ok": True, "code": "ok", "detail": "",
                "value": json.dumps(values, ensure_ascii=False)}

    def profile_set_json(self, text: str) -> Dict[str, Any]:
        """Publish our profile from a JSON object of fields. Returns what was
        published (sanitised), as JSON."""
        import json
        transport = self._transport
        if transport is None or not hasattr(transport, "set_profile"):
            return {"ok": False, "code": "not_connected",
                    "detail": "Connect first.", "value": None}
        try:
            values = json.loads(str(text or "{}")[:20000])
            if not isinstance(values, dict):
                raise ValueError("not an object")
        except ValueError:
            return {"ok": False, "code": "bad_request",
                    "detail": "The profile could not be read.", "value": None}
        try:
            published = transport.set_profile(values)
        except Exception as exc:
            code = getattr(exc, "code", None) or type(exc).__name__
            _TRACE.record("profile", "set_failed", "warning", code=code)
            return {"ok": False, "code": code,
                    "detail": "The profile could not be saved.", "value": None}
        _TRACE.record("profile", "published", "info", fields=len(published))
        return {"ok": True, "code": "ok", "detail": "",
                "value": json.dumps(published, ensure_ascii=False)}
