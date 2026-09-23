# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Take the photograph's story off the photograph.

WHY THIS EXISTS
===============
A picture from a phone camera carries where it was taken to a few metres,
when, on what device, and often a thumbnail of the frame before it was
cropped. Android can now send files over an encrypted, SMP-verified,
I2P-routed session (see `android_bridge.files`), and sending a photo that way
with its EXIF intact would be encrypting the message and attaching the
answer.

WHY HERE, AND WHY NO LIBRARY
============================
Here, because the bytes pass through Python on their way to the transfer
engine anyway, and because Python is where this can be driven against real
files in the test suite rather than asserted about in Kotlin this container
cannot compile.

No library, because removing segments from a container is small and exactly
specifiable, and the Android build carries a dependency LICENCE guard: "one
copyleft dependency in the shipped graph ... makes the COMMERCIAL half of the
dual licence unsellable". Pure standard library keeps this out of that
question entirely.

WHAT IS REMOVED, AND WHAT IS KEPT
=================================
Removed -- circumstances, not pixels:
  JPEG  APP1 (Exif incl. GPS and the embedded thumbnail; XMP),
        APP13 (Photoshop IRB, which carries IPTC), COM comments.
  PNG   tEXt, zTXt, iTXt, eXIf, tIME.

Kept -- removing them damages the image and protects nobody:
  JPEG  APP0 (JFIF density/structure), APP2 (ICC colour profile), all
        quantisation, Huffman, frame and scan data.
  PNG   every critical chunk and every colour/transparency chunk.

WHAT IT DOES NOT CLAIM
======================
It is not a general sanitiser. A format it does not recognise, or a file
whose structure does not parse, comes back BYTE-IDENTICAL and is reported as
unscrubbable -- so the UI says "the app cannot check this" rather than
implying a guarantee. Returning the input as though it had been cleaned would
be the worst of the possible behaviours, so it never partially rewrites.
"""

from __future__ import annotations

import os
import struct
import tempfile
from dataclasses import dataclass

__all__ = ["Finding", "examine", "scrub", "scrub_file", "kind_of"]

JPEG = "jpeg"
PNG = "png"
UNKNOWN = "unknown"

_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"

#: APP1 (Exif, XMP), APP13 (Photoshop IRB / IPTC), COM.
#: APP0 (JFIF) and APP2 (ICC) are absent on purpose -- see the module docs.
_STRIPPED_JPEG = frozenset({0xE1, 0xED, 0xFE})

#: Circumstance chunks. Critical and colour chunks are absent on purpose.
_STRIPPED_PNG = frozenset({b"tEXt", b"zTXt", b"iTXt", b"eXIf", b"tIME"})

#: Files larger than this are not read into memory to be examined. The
#: transfer engine's own limit is the real ceiling; this is only so an
#: examination cannot be the thing that exhausts a phone's memory.
MAX_EXAMINE_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True)
class Finding:
    """What examining a file found."""

    kind: str
    carries_metadata: bool
    metadata_bytes: int

    @property
    def can_scrub(self) -> bool:
        return self.kind != UNKNOWN

    def as_dict(self) -> dict:
        return {"kind": self.kind,
                "carries_metadata": self.carries_metadata,
                "metadata_bytes": self.metadata_bytes,
                "can_scrub": self.can_scrub}


def kind_of(data: bytes) -> str:
    if len(data) >= 3 and data[:3] == b"\xff\xd8\xff":
        return JPEG
    if data[:8] == _PNG_MAGIC:
        return PNG
    return UNKNOWN


def scrub(data: bytes) -> bytes:
    """*data* without its metadata, or unchanged if it cannot be parsed."""
    kind = kind_of(data)
    if kind == JPEG:
        return _scrub_jpeg(data)
    if kind == PNG:
        return _scrub_png(data)
    return data


def examine(data: bytes) -> Finding:
    kind = kind_of(data)
    if kind == UNKNOWN:
        return Finding(UNKNOWN, False, 0)
    cleaned = scrub(data)
    if cleaned is data:
        # Recognised by its magic but did not parse: treat as unknown rather
        # than promise a scrub that would silently do nothing.
        return Finding(UNKNOWN, False, 0)
    removed = len(data) - len(cleaned)
    return Finding(kind, removed > 0, max(0, removed))


def examine_file(path: str) -> Finding:
    try:
        if os.path.getsize(path) > MAX_EXAMINE_BYTES:
            return Finding(UNKNOWN, False, 0)
        with open(path, "rb") as handle:
            return examine(handle.read())
    except OSError:
        return Finding(UNKNOWN, False, 0)


def scrub_file(path: str) -> str:
    """A scrubbed copy of *path*, alongside it, or *path* itself.

    ALONGSIDE, in the same directory: on Android that is the app's own cache,
    where the SAF copy was staged, so the cleaned copy never lands anywhere
    shared. Same basename, so the peer sees the name the user picked. Written
    to a temporary name and renamed, so a half-written copy is never what
    gets sent.

    Returns *path* unchanged when there is nothing to remove or the format is
    not understood -- the caller can tell by comparing.
    """
    try:
        if os.path.getsize(path) > MAX_EXAMINE_BYTES:
            return path
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError:
        return path
    cleaned = scrub(data)
    if cleaned is data or cleaned == data:
        return path
    directory = tempfile.mkdtemp(prefix="scrubbed-",
                                 dir=os.path.dirname(os.path.abspath(path)))
    target = os.path.join(directory, os.path.basename(path))
    fd, tmp = tempfile.mkstemp(dir=directory)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(cleaned)
        os.chmod(tmp, 0o600)
        os.replace(tmp, target)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        return path
    return target


# -- JPEG --------------------------------------------------------------------

def _scrub_jpeg(data: bytes) -> bytes:
    out = bytearray(data[:2])                     # SOI
    i = 2
    n = len(data)
    while i + 3 < n:
        if data[i] != 0xFF:
            return data
        marker = data[i + 1]
        if marker == 0xFF:                        # fill byte
            i += 1
            continue
        if marker == 0xDA:                        # start of scan: image data
            out += data[i:]
            return bytes(out)
        if marker in (0x01, 0xD8) or 0xD0 <= marker <= 0xD7:
            out += data[i:i + 2]
            i += 2
            continue
        length = (data[i + 2] << 8) | data[i + 3]
        if length < 2 or i + 2 + length > n:
            return data
        if marker not in _STRIPPED_JPEG:
            out += data[i:i + 2 + length]
        i += 2 + length
    return data                                   # no scan: not what it claimed


# -- PNG ---------------------------------------------------------------------

def _scrub_png(data: bytes) -> bytes:
    out = bytearray(data[:8])
    i = 8
    n = len(data)
    while i + 12 <= n:
        (length,) = struct.unpack(">I", data[i:i + 4])
        end = i + 12 + length
        if end > n:
            return data
        ctype = data[i + 4:i + 8]
        if ctype not in _STRIPPED_PNG:
            out += data[i:end]
        i = end
        if ctype == b"IEND":
            return bytes(out)
    return data
