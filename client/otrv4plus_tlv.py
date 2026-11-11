# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The OTRv4 TLV record (type, length, value) carried inside encrypted
data messages, and the base64 decoding every OTRv4 frame body goes through.

Moved out of otrv4+.py unchanged (2026-11-11). The engine re-exports it as
`OTRv4TLV`.
"""
import base64
import os
import secrets
import struct
from typing import List, Tuple


class OTRv4TLV:
    """Single TLV (Type-Length-Value) record inside an OTRv4 encrypted message.

    Wire format:  uint16 type  |  uint16 length  |  byte[length] value
    All multi-byte fields are big-endian (network byte order).

    TLV type 0x0000 (PADDING) MUST be silently discarded by receivers.
    Unknown TLV types MUST be silently ignored (forward compatibility).
    """

    __slots__ = ("type", "value")

    PADDING = 0x0000
    DISCONNECTED = 0x0001
    SMP_MSG_1 = 0x0002
    SMP_MSG_2 = 0x0003
    SMP_MSG_3 = 0x0004
    SMP_MSG_4 = 0x0005
    SMP_ABORT = 0x0006
    SMP_MSG_1Q = 0x0007
    EXTRA_SYMMETRIC_KEY = 0x0009

    #: v10.21.0: /tip -- a Monero address relayed between two SMP-verified
    #: peers.  Above the OTRv4-allocated range (0x0000-0x0009) so it cannot
    #: collide with a future spec type, and forward-compatible by the rule at
    #: the top of this class: a peer that does not know it ignores it.
    TIP = 0x0020

    #: rc.65: MESSAGE META -- the id of a typed message, and what it does to
    #: an earlier one (a correction, a deletion for everyone, a reaction, a
    #: reply), carried INSIDE the encrypted, authenticated payload so the
    #: server can neither forge nor redirect them. Same forward-compatibility
    #: rule: an older peer ignores it and shows the text, if any.
    MESSAGE_META = 0x0021

    SMP_TYPES = frozenset({SMP_MSG_1, SMP_MSG_2, SMP_MSG_3, SMP_MSG_4, SMP_ABORT, SMP_MSG_1Q})

    # Optional SMP_ABORT payload naming WHY the abort happened.
    #
    # The TLV payload was always empty and receivers ignored it, so adding a
    # reason is additive: an older peer drops it exactly as before. It exists
    # because "aborted" collapsed three different situations into one message
    # -- the peer has no secret configured, the peer has the wrong secret, or
    # something genuinely failed -- and only the first is fixed by the user
    # typing a command.
    #
    # It is a DIAGNOSTIC, never a predicate. Nothing branches on it beyond the
    # wording of a line printed locally: it is attacker-controlled text like
    # any other field a peer sends.
    SMP_ABORT_NO_SECRET = b"NOSECRET"

    # The user was asked and said no.  Distinct from NOSECRET, which means
    # nobody was asked because nothing was configured.  Same rules apply: a
    # diagnostic that chooses local wording, never a security predicate.
    SMP_ABORT_DECLINED = b"DECLINED"

    def __init__(self, tlv_type: int, value: bytes = b""):
        if not (0 <= tlv_type <= 0xFFFF):
            raise ValueError(f"TLV type out of range: {tlv_type :#06x}")
        if len(value) > 65535:
            raise ValueError(f"TLV value too large: {len (value )} bytes (max 65535)")
        self.type = tlv_type
        self.value = bytes(value)

    def encode(self) -> bytes:
        """Serialize to wire bytes: uint16 type + uint16 length + value."""
        return struct.pack("!HH", self.type, len(self.value)) + self.value

    @classmethod
    def decode_one(cls, data: bytes, offset: int = 0) -> Tuple["OTRv4TLV", int]:
        """Decode one TLV from *data* at *offset*.  Returns (tlv, next_offset).

        Raises ValueError on truncated or malformed input.
        """
        if offset + 4 > len(data):
            raise ValueError(
                f"TLV header truncated at offset {offset } " f"(need 4, have {len (data )-offset })"
            )
        tlv_type, length = struct.unpack_from("!HH", data, offset)
        end = offset + 4 + length
        if end > len(data):
            raise ValueError(
                f"TLV value truncated: type=0x{tlv_type :04x} "
                f"declares {length } bytes but only {len (data )-offset -4 } available"
            )
        return cls(tlv_type, data[offset + 4 : end]), end

    @classmethod
    def decode_all(cls, data: bytes) -> List["OTRv4TLV"]:
        """Decode all TLVs from *data*.  Raises ValueError on malformed stream."""
        tlvs: List["OTRv4TLV"] = []
        offset = 0
        while offset < len(data):
            tlv, offset = cls.decode_one(data, offset)
            tlvs.append(tlv)
        return tlvs

    @classmethod
    def encode_all(cls, tlvs: List["OTRv4TLV"]) -> bytes:
        return b"".join(t.encode() for t in tlvs)

    @classmethod
    def random_padding(cls, min_bytes: int = 8, max_bytes: int = 72) -> "OTRv4TLV":
        """Create a PADDING TLV with random content for traffic analysis resistance."""
        pad_len = secrets.randbelow(max_bytes - min_bytes + 1) + min_bytes
        return cls(cls.PADDING, os.urandom(pad_len))

    def __repr__(self) -> str:
        _NAMES = {
            0: "PADDING",
            1: "DISCONNECTED",
            2: "SMP_MSG_1",
            3: "SMP_MSG_2",
            4: "SMP_MSG_3",
            5: "SMP_MSG_4",
            6: "SMP_ABORT",
            7: "SMP_MSG_1Q",
            8: "EXTRA_SYMMETRIC_KEY",
            0x0020: "TIP",
        }
        name = _NAMES.get(self.type, f"UNKNOWN(0x{self .type :04x})")
        return f"OTRv4TLV({name }, {len (self .value )} bytes)"


def _safe_b64decode(data: str) -> bytes:
    """Safely decode base64 with padding.

    v10.7 (Phase 5.3h-D): rescued to module scope from the deleted
    pure-Python OTRv4DAKE class.  Every caller now uses the bare
    _safe_b64decode(...) function name.
    """
    try:
        data = str(data).strip()
        if not data:
            raise ValueError("Empty base64 data")

        data = "".join(data.split())

        if "[" in data and "]" in data:
            end_bracket = data.rfind("]")
            if end_bracket != -1:
                data = data[end_bracket + 1 :].strip()

        # OTRv4 DATA frames are terminated with a trailing '.' (the encode path
        # emits  "?OTRv4 <b64url>." ).  DAKE frames have no terminator.  Strip
        # any trailing dots here so every caller can pass the raw frame body
        # without having to know whether this particular message type is dotted.
        data = data.rstrip(".")

        # A url-safe base64 body stripped of '=' padding can only be 0, 2 or 3
        # (mod 4) characters long.  A length of 1 (mod 4) is impossible for any
        # valid encoding and is the fingerprint of a body that was decoded with
        # the STANDARD alphabet (which silently discards '-' and '_').  Fail
        # loudly instead of letting the b64decode fallback swallow real chars.
        if len(data) % 4 == 1:
            raise ValueError(
                f"corrupt base64: {len (data )} chars is 1 (mod 4); "
                "url-safe '-'/'_' were likely dropped by a standard-alphabet decode"
            )

        try:
            padding_needed = -len(data) % 4
            if padding_needed:
                data = data + "=" * padding_needed
            return base64.urlsafe_b64decode(data)
        except Exception:
            data = data.replace("-", "+").replace("_", "/")
            padding_needed = -len(data) % 4
            if padding_needed:
                data = data + "=" * padding_needed
            return base64.b64decode(data)
    except Exception as e:
        try:
            import re as _re

            # Normalise url-safe alphabet to standard BEFORE stripping, so that
            # '-'/'_' become '+'/'/' rather than being discarded by b64decode.
            data = data.replace("-", "+").replace("_", "/")
            data = _re.sub(r"[^A-Za-z0-9+/=]", "", data)
            padding_needed = -len(data) % 4
            if padding_needed:
                data = data + "=" * padding_needed
            return base64.b64decode(data)
        except Exception as e2:
            raise ValueError(f"Base64 decode failed: {e }, also: {e2 }")
