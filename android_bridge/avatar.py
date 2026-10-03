# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""User avatars (XEP-0084), received without trusting a single byte of them.

THE THREAT
==========
An avatar is an image chosen by somebody else and fetched automatically,
before the user has done anything. Image decoders are among the most
exploited code on a phone -- a crafted PNG, JPEG or WebP aimed at the
platform's native decoder (Skia, libpng, libjpeg, libwebp) is exactly how
"zero-click" attacks have reached phones. So the rule here is:

    NO NATIVE IMAGE DECODER EVER SEES A PEER'S BYTES.

HOW
===
* PNG only. XEP-0084 makes image/png the one format every client must
  support, so a peer that publishes anything has a PNG to offer. Anything
  else is not fetched.
* Bounded before anything is decoded: at most MAX_BYTES of data and
  MAX_DIMENSION pixels a side, declared in the metadata (checked before the
  fetch) and again in the image itself (checked before decompression).
* The data must hash to its published id (SHA-1, XEP-0084): what was
  announced is what is decoded.
* Decoded HERE, in pure Python, by `decode_png`: every chunk length and CRC
  checked, 8-bit non-interlaced images only, no unknown critical chunk, and
  zlib output capped at exactly the size the header implies -- a
  decompression bomb stops at a few hundred kilobytes. What leaves this
  module is raw RGBA pixels; the app builds its bitmap from those numbers
  (Bitmap.createBitmap from an int array), never from the file.
* Anything that fails is dropped silently and the app shows the contact's
  initial. Nothing about the failure is shown to the sender.

Our OWN avatar is the user's own picture: the app scales it to OWN_SIZE and
re-encodes it as PNG (dropping any metadata), and it must pass the same
`decode_png` before it is published.

Decoded avatars are held in memory only (AvatarBook), so Wipe & Exit and
an account switch leave nothing behind.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import struct
import threading
import zlib
from collections import OrderedDict
from typing import Dict, List, Optional, Tuple

__all__ = ["AvatarError", "Avatar", "decode_png", "AvatarBook",
           "MAX_BYTES", "MAX_DIMENSION", "OWN_SIZE", "PNG_TYPE"]

#: Largest avatar accepted, in bytes. Real avatars are a few kilobytes; the
#: app publishes OWN_SIZE x OWN_SIZE.
MAX_BYTES = 64 * 1024
#: Largest width or height accepted.
MAX_DIMENSION = 256
#: The size the app scales its own avatar to before publishing.
OWN_SIZE = 96
PNG_TYPE = "image/png"
#: base64 of MAX_BYTES, with slack for line breaks a server may add.
MAX_B64_CHARS = (MAX_BYTES + 2) // 3 * 4 + 1024
#: How many contacts' avatars are kept.
MAX_AVATARS = 512

_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_SHA1_HEX = frozenset("0123456789abcdef")
#: colour type -> channels, for 8-bit samples.
_CHANNELS = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}


class AvatarError(ValueError):
    """Why an image was refused. `code` is stable; nothing is shown."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class Avatar:
    __slots__ = ("id", "width", "height", "rgba")

    def __init__(self, id: str, width: int, height: int, rgba: bytes):
        self.id, self.width, self.height, self.rgba = id, width, height, rgba


def _chunks(data: bytes):
    """(type, body) for each chunk, every length and CRC checked."""
    if len(data) > MAX_BYTES:
        raise AvatarError("too_large")
    if not data.startswith(_SIGNATURE):
        raise AvatarError("not_png")
    pos = len(_SIGNATURE)
    end = len(data)
    while pos < end:
        if end - pos < 12:
            raise AvatarError("truncated")
        length, = struct.unpack(">I", data[pos:pos + 4])
        ctype = data[pos + 4:pos + 8]
        if length > end - pos - 12:
            raise AvatarError("truncated")
        if not all(65 <= c <= 90 or 97 <= c <= 122 for c in ctype):
            raise AvatarError("bad_chunk")
        body = data[pos + 8:pos + 8 + length]
        crc, = struct.unpack(">I", data[pos + 8 + length:pos + 12 + length])
        if zlib.crc32(ctype + body) & 0xFFFFFFFF != crc:
            raise AvatarError("bad_crc")
        pos += 12 + length
        if ctype == b"IEND" and pos != end:
            # Checked BEFORE the end is yielded: a caller stops reading at
            # IEND, so anything appended (a polyglot payload) would otherwise
            # pass unseen.
            raise AvatarError("data_after_end")
        yield ctype, body
        if ctype == b"IEND":
            return
    raise AvatarError("no_end")


def _paeth(a: int, b: int, c: int) -> int:
    p = a + b - c
    pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    return b if pb <= pc else c


def decode_png(data: bytes) -> Tuple[int, int, bytes]:
    """(width, height, RGBA bytes) for an acceptable PNG, else AvatarError.

    Pure Python and bounded: this is the only code that reads a peer's image.
    """
    data = bytes(data)
    header = None
    palette: Optional[bytes] = None
    trns: Optional[bytes] = None
    idat: List[bytes] = []
    seen_idat = False
    idat_done = False          # IDAT chunks must be consecutive (PNG §5.6)
    for index, (ctype, body) in enumerate(_chunks(data)):
        if index == 0:
            if ctype != b"IHDR" or len(body) != 13:
                raise AvatarError("no_header")
            w, h, depth, colour, comp, filt, interlace = struct.unpack(">IIBBBBB", body)
            if not (1 <= w <= MAX_DIMENSION and 1 <= h <= MAX_DIMENSION):
                raise AvatarError("too_big")
            if depth != 8 or colour not in _CHANNELS:
                raise AvatarError("unsupported_format")
            if comp != 0 or filt != 0 or interlace != 0:
                raise AvatarError("unsupported_format")
            header = (w, h, colour)
            continue
        if ctype == b"IHDR":
            raise AvatarError("bad_chunk")
        if ctype == b"PLTE":
            if palette is not None or seen_idat or len(body) % 3 or not 3 <= len(body) <= 768:
                raise AvatarError("bad_palette")
            palette = body
        elif ctype == b"tRNS":
            if seen_idat:
                raise AvatarError("bad_chunk")
            trns = body
        elif ctype == b"IDAT":
            if idat_done:
                raise AvatarError("bad_chunk")
            seen_idat = True
            idat.append(body)
            continue
        elif ctype == b"IEND":
            break
        elif 65 <= ctype[0] <= 90:
            # An unknown CRITICAL chunk: the spec says a decoder that does not
            # know it must not show the image.
            raise AvatarError("unknown_critical_chunk")
        # Anything after the image data ends it; ancillary chunks are ignored.
        if seen_idat:
            idat_done = True
    if header is None or not idat:
        raise AvatarError("no_image_data")
    w, h, colour = header
    channels = _CHANNELS[colour]
    if colour == 3 and palette is None:
        raise AvatarError("bad_palette")
    stride = w * channels
    expected = h * (stride + 1)
    inflater = zlib.decompressobj()
    try:
        raw = inflater.decompress(b"".join(idat), expected)
        if inflater.unconsumed_tail or len(raw) != expected:
            raise AvatarError("bad_image_data")
        if inflater.flush(1):
            raise AvatarError("bad_image_data")
    except zlib.error:
        raise AvatarError("bad_image_data")

    # Unfilter (PNG §9), bytes-per-pixel = channels for 8-bit samples.
    out = bytearray(h * stride)
    prev = bytearray(stride)
    bpp = channels
    pos = 0
    for y in range(h):
        ftype = raw[pos]
        line = bytearray(raw[pos + 1:pos + 1 + stride])
        pos += 1 + stride
        if ftype == 0:
            pass
        elif ftype == 1:
            for i in range(bpp, stride):
                line[i] = (line[i] + line[i - bpp]) & 0xFF
        elif ftype == 2:
            for i in range(stride):
                line[i] = (line[i] + prev[i]) & 0xFF
        elif ftype == 3:
            for i in range(stride):
                left = line[i - bpp] if i >= bpp else 0
                line[i] = (line[i] + ((left + prev[i]) >> 1)) & 0xFF
        elif ftype == 4:
            for i in range(stride):
                left = line[i - bpp] if i >= bpp else 0
                upleft = prev[i - bpp] if i >= bpp else 0
                line[i] = (line[i] + _paeth(left, prev[i], upleft)) & 0xFF
        else:
            raise AvatarError("bad_filter")
        out[y * stride:(y + 1) * stride] = line
        prev = line

    # To RGBA.
    n = w * h
    rgba = bytearray(n * 4)
    if colour == 6:
        rgba[:] = out
    elif colour == 2:
        rgba[0::4], rgba[1::4], rgba[2::4] = out[0::3], out[1::3], out[2::3]
        rgba[3::4] = b"\xff" * n
    elif colour == 0:
        rgba[0::4] = rgba[1::4] = rgba[2::4] = out
        rgba[3::4] = b"\xff" * n
    elif colour == 4:
        rgba[0::4] = rgba[1::4] = rgba[2::4] = out[0::2]
        rgba[3::4] = out[1::2]
    else:  # palette
        entries = len(palette) // 3
        alpha = trns or b""
        table = []
        for i in range(256):
            if i < entries:
                r, g, b = palette[3 * i:3 * i + 3]
                a = alpha[i] if i < len(alpha) else 255
                table.append(bytes((r, g, b, a)))
            else:
                table.append(None)
        for i, index in enumerate(out):
            entry = table[index]
            if entry is None:
                raise AvatarError("bad_palette")
            rgba[4 * i:4 * i + 4] = entry
    return w, h, bytes(rgba)


def _clean_id(value) -> str:
    text = str(value or "").strip().lower()
    if len(text) != 40 or not set(text) <= _SHA1_HEX:
        return ""
    return text


class AvatarBook:
    """Who has which avatar, decoded. Memory only; bounded; thread-safe."""

    def __init__(self, limit: int = MAX_AVATARS):
        self._limit = limit
        self._lock = threading.Lock()
        self._avatars: "OrderedDict[str, Avatar]" = OrderedDict()
        self._wanted: Dict[str, str] = {}          # jid -> id announced

    @staticmethod
    def _key(jid: str) -> str:
        return str(jid or "").strip().split("/", 1)[0].lower()

    def note_metadata(self, jid: str, infos) -> Optional[str]:
        """An avatar announcement. Returns the id to fetch, or None.

        `infos` is a list of dicts (id, type, bytes, width, height). Only a
        PNG within the limits is wanted; an empty list means "no avatar"."""
        key = self._key(jid)
        if not key:
            return None
        chosen = ""
        for info in list(infos or [])[:16]:
            try:
                if str(info.get("type", "")).strip().lower() != PNG_TYPE:
                    continue
                size = int(info.get("bytes") or 0)
                width = int(info.get("width") or 0)
                height = int(info.get("height") or 0)
            except (TypeError, ValueError, AttributeError):
                continue
            if not 0 < size <= MAX_BYTES:
                continue
            if width > MAX_DIMENSION or height > MAX_DIMENSION:
                continue
            chosen = _clean_id(info.get("id"))
            if chosen:
                break
        with self._lock:
            if not infos:
                self._avatars.pop(key, None)
                self._wanted.pop(key, None)
                return None
            if not chosen:
                return None
            have = self._avatars.get(key)
            if have is not None and have.id == chosen:
                return None
            self._wanted[key] = chosen
            return chosen

    def note_data(self, jid: str, avatar_id: str, b64_text: str) -> bool:
        """The fetched item. Stored only if it is what was announced and
        decodes within every limit."""
        key = self._key(jid)
        avatar_id = _clean_id(avatar_id)
        with self._lock:
            if not key or not avatar_id or self._wanted.get(key) != avatar_id:
                return False
        text = str(b64_text or "")
        if len(text) > MAX_B64_CHARS:
            return False
        try:
            data = base64.b64decode("".join(text.split()), validate=True)
        except (binascii.Error, ValueError):
            return False
        if hashlib.sha1(data).hexdigest() != avatar_id:
            return False
        try:
            w, h, rgba = decode_png(data)
        except AvatarError:
            return False
        self._store(key, Avatar(avatar_id, w, h, rgba))
        return True

    def set_own(self, jid: str, png: bytes) -> Avatar:
        """Our own avatar, after the same checks as anybody's."""
        w, h, rgba = decode_png(png)
        avatar = Avatar(hashlib.sha1(bytes(png)).hexdigest(), w, h, rgba)
        self._store(self._key(jid), avatar)
        return avatar

    def _store(self, key: str, avatar: Avatar) -> None:
        with self._lock:
            self._wanted.pop(key, None)
            self._avatars[key] = avatar
            self._avatars.move_to_end(key)
            while len(self._avatars) > self._limit:
                self._avatars.popitem(last=False)

    def forget(self, jid: str) -> None:
        with self._lock:
            self._avatars.pop(self._key(jid), None)
            self._wanted.pop(self._key(jid), None)

    def ids(self) -> Dict[str, str]:
        with self._lock:
            return {k: v.id for k, v in self._avatars.items()}

    def get(self, jid: str) -> Optional[Avatar]:
        with self._lock:
            return self._avatars.get(self._key(jid))

    def clear(self) -> None:
        with self._lock:
            self._avatars.clear()
            self._wanted.clear()
