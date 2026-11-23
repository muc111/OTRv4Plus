# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The OTRv4+ data message on the wire, for the terminal clients.

* `BinaryReader` -- a bounds-checked reader for the binary encodings.
* `OTRv4DataMessage` -- encode and decode a data message: header, ratchet
  keys, the post-quantum brace KEM fields, ciphertext and MAC. A message
  from a different wire revision raises `ProtocolVersionError`, not a MAC
  failure (see that class for why).
* `OTRv4Payload` -- the plaintext inside: text plus TLV records, and the
  registry of TLV handlers (`register_tlv_handler`).
* Instance tags (`_generate_instance_tag`) and the ML-KEM-1024 wire sizes
  (`MLKEM1024BraceKEM`).

The cryptography is not here: keys, encryption and MACs are in the Rust
core. Moved out of otrv4+.py, which re-exports every name.
"""
import os
import secrets
import struct
from typing import Callable, Dict, List, Optional

import otrv4plus_debug as _debug
from otrv4plus_tlv import OTRv4TLV


class MLKEM1024BraceKEM:
    """ML-KEM-1024 (FIPS 203) wire sizes for the OTRv4 post-quantum brace KEM.

    Sizes only. The brace KEM runs entirely in the Rust core
    (`otrv4_core.MlKem1024Keypair`, `RustDoubleRatchet.brace_encapsulate` /
    `brace_decapsulate`), so its decapsulation key and shared secret never
    become Python objects. This class used to wrap the raw
    `mlkem1024_keygen` / `encaps` / `decaps` primitives and hand the shared
    secret back as Python bytes; nothing in production used it, and a
    Python-side key holder that nothing uses is only somewhere for a future
    change to put a secret. The primitives remain in the core for
    known-answer tests, which call them directly.
    """

    EK_BYTES = 1568
    CT_BYTES = 1568
    SS_BYTES = 32


class ProtocolVersionError(ValueError):
    """The peer speaks a different OTRv4+ wire revision.

    C1. Subclasses ValueError deliberately: every existing `except ValueError`
    handler around decode() keeps working, while callers that need to tell a
    version mismatch from a cryptographic failure can catch this specifically.

    This exists because the two failure modes were previously indistinguishable.
    A peer on an older build would pass the version check (the constant had not
    been incremented for a breaking change), then fail MAC verification, and the
    user would be shown "message may be forged or replayed" for what was really
    a version mismatch -- an alarming and wrong diagnosis on a security-relevant
    path.
    """


class BinaryReader:
    """Safe structured binary parser with strict bounds checking and specific exceptions."""

    def __init__(self, data: bytes):
        if not isinstance(data, bytes):
            raise TypeError(f"Expected bytes, got {type (data )}")
        self.data = data
        self.offset = 0
        self.length = len(data)

    def remaining(self) -> int:
        return self.length - self.offset

    def ensure(self, needed: int) -> None:
        """Ensure at least needed bytes remain."""
        remaining = self.remaining()
        if remaining < needed:
            raise ValueError(f"Truncated: need {needed } bytes, have {remaining }")

    def read_uint8(self) -> int:
        try:
            self.ensure(1)
            val = self.data[self.offset]
            self.offset += 1
            return val
        except IndexError as e:
            raise ValueError(f"Failed to read uint8: {e }")
        except ValueError:
            # Truncation is EXPECTED on untrusted input. ensure() raises
            # ValueError; the bare `except Exception` below would convert it
            # to RuntimeError, which decode() does not catch and no caller
            # expects. read_bytes() already re-raises; the integer readers
            # must behave identically or a short header escapes as an
            # "unexpected error" instead of a clean parse failure.
            raise
        except Exception as e:
            raise RuntimeError(f"Unexpected error reading uint8: {e }")

    def read_uint16(self) -> int:
        try:
            self.ensure(2)
            val = struct.unpack(">H", self.data[self.offset : self.offset + 2])[0]
            self.offset += 2
            return val
        except struct.error as e:
            raise ValueError(f"Failed to unpack uint16: {e }")
        except ValueError:
            raise  # truncation: see read_uint8
        except Exception as e:
            raise RuntimeError(f"Unexpected error reading uint16: {e }")

    def read_uint32(self) -> int:
        try:
            self.ensure(4)
            val = struct.unpack(">I", self.data[self.offset : self.offset + 4])[0]
            self.offset += 4
            return val
        except struct.error as e:
            raise ValueError(f"Failed to unpack uint32: {e }")
        except ValueError:
            raise  # truncation: see read_uint8
        except Exception as e:
            raise RuntimeError(f"Unexpected error reading uint32: {e }")

    def read_uint64(self) -> int:
        try:
            self.ensure(8)
            val = struct.unpack(">Q", self.data[self.offset : self.offset + 8])[0]
            self.offset += 8
            return val
        except struct.error as e:
            raise ValueError(f"Failed to unpack uint64: {e }")
        except ValueError:
            raise  # truncation: see read_uint8
        except Exception as e:
            raise RuntimeError(f"Unexpected error reading uint64: {e }")

    def read_bytes(self, length: int) -> bytes:
        try:
            if length < 0:
                raise ValueError(f"Negative length: {length }")
            self.ensure(length)
            val = self.data[self.offset : self.offset + length]
            self.offset += length
            return val
        except IndexError as e:
            raise ValueError(f"Failed to read {length } bytes: {e }")
        except ValueError:
            # Truncation is an EXPECTED condition on untrusted input, not an
            # internal error. ensure() raises ValueError; the bare `except
            # Exception` below used to convert it to RuntimeError, which
            # OTRv4DataMessage.decode does not catch — so a short message
            # escaped as "Unexpected error" instead of a clean parse failure.
            raise
        except Exception as e:
            raise RuntimeError(f"Unexpected error reading bytes: {e }")

    def read_mpi(self) -> bytes:
        """Read MPI: uint32 length followed by bytes."""
        try:
            length = self.read_uint32()
            if length == 0:
                return b""
            if length > 1024 * 1024:
                raise ValueError(f"MPI too large: {length }")
            return self.read_bytes(length)
        except ValueError as e:
            raise ValueError(f"Invalid MPI: {e }")
        except Exception as e:
            raise RuntimeError(f"Unexpected error reading MPI: {e }")

    def read_varbytes(self) -> bytes:
        """Read varbytes: uint32 length followed by bytes."""
        return self.read_mpi()

    def expect_end(self) -> None:
        """Ensure no trailing bytes remain."""
        if self.offset != self.length:
            raise ValueError(f"Trailing bytes: {self .length -self .offset } remaining")


def _generate_instance_tag() -> int:
    """Random 32-bit instance tag in [0x100, 0xFFFFFFFF] per OTRv4 spec §4.1.

    Two independent CSPRNG reads XOR'd together. Output is at least as strong
    as the stronger source even if one RNG is compromised.
    """
    while True:
        a = int.from_bytes(secrets.token_bytes(4), "big")
        b = int.from_bytes(os.urandom(4), "big")
        tag = a ^ b
        if 0x100 <= tag <= 0xFFFFFFFF:
            return tag


#: Handlers for the non-protocol TLV types, keyed by type.
#:
#: The engine routes DISCONNECTED, the SMP types and EXTRA_SYMMETRIC_KEY
#: itself; anything else is a feature, and a feature does not belong in the
#: session state machine.  A client registers here and gets called with
#: `(peer, value)` for its type, on any session, once the payload has been
#: decrypted and authenticated.
#:
#: Deliberately NOT a general extension point.  `register_tlv_handler`
#: refuses any type outside `_HANDLER_TLV_TYPES`, so this cannot become the
#: way arbitrary protocol gets bolted onto a session -- which is how a
#: forwarding hook turns into an unreviewed second protocol.
_TLV_HANDLERS: Dict[int, Callable[[str, bytes], None]] = {}

#: The only types a client may register for: TIP (0x0020) and MESSAGE_META
#: (0x0021, ids/corrections/deletions/reactions/replies -- otrv4plus_actions).
_HANDLER_TLV_TYPES = frozenset({0x0020, 0x0021})


def register_tlv_handler(tlv_type: int, handler: Callable[[str, bytes], None]) -> None:
    """Route inbound TLVs of `tlv_type` to `handler(peer, value)`.

    Raises for a type the engine owns, or one nobody has thought about.
    """
    if tlv_type not in _HANDLER_TLV_TYPES:
        raise ValueError(
            "TLV type 0x%04x is not open to handlers (allowed: %s)"
            % (tlv_type, ", ".join("0x%04x" % t
                                   for t in sorted(_HANDLER_TLV_TYPES))))
    _TLV_HANDLERS[tlv_type] = handler


def clear_tlv_handlers() -> None:
    """Drop every registered handler.  For teardown and for tests."""
    _TLV_HANDLERS.clear()


class OTRv4Payload:
    """Encodes / decodes the cleartext payload inside an OTRv4 DATA message.

    Per spec §4.4.3 the decrypted payload has the structure:
        human_readable_message  (UTF-8, may be empty)
        0x00                    (NULL separator - only present when TLVs follow)
        TLV*                    (zero or more TLV records)

    PADDING TLVs (type 0x0000) in received messages are silently discarded.
    Unknown TLV types are silently ignored (forward compatibility per spec).
    """

    __slots__ = ("text", "tlvs")

    def __init__(self, text: str = "", tlvs: Optional[List["OTRv4TLV"]] = None):
        self.text = text or ""
        self.tlvs: List[OTRv4TLV] = list(tlvs) if tlvs else []

    def encode(self, add_padding: bool = True) -> bytes:
        """Encode to bytes for encryption.

        If *add_padding* is True (default), appends a random PADDING TLV to
        resist traffic-analysis attacks by blurring plaintext length.
        """
        text_bytes = self.text.encode("utf-8") if self.text else b""
        tlvs = list(self.tlvs)
        if add_padding:
            tlvs.append(OTRv4TLV.random_padding())
        if tlvs:
            return text_bytes + b"\x00" + OTRv4TLV.encode_all(tlvs)
        return text_bytes

    @classmethod
    def decode(cls, data: bytes) -> "OTRv4Payload":
        """Decode from decrypted bytes.  PADDING TLVs are silently dropped."""
        null_pos = data.find(b"\x00")
        if null_pos == -1:
            return cls(data.decode("utf-8", errors="replace"), [])

        text = data[:null_pos].decode("utf-8", errors="replace")
        tlv_bytes = data[null_pos + 1 :]

        if not tlv_bytes:
            return cls(text, [])

        all_tlvs = OTRv4TLV.decode_all(tlv_bytes)
        non_padding = [t for t in all_tlvs if t.type != OTRv4TLV.PADDING]
        return cls(text, non_padding)


class OTRv4DataMessage:
    """OTRv4 DATA message wire format (spec §4.4.3)."""

    # OTRv4+ data-message wire revision.
    #
    # 0x0004 -> 0x0005 (C1): the MKmac fix changed this message's wire
    # behaviour in two incompatible ways.
    #
    #   1. The MAC value differs. MKmac is now KDF(0x14, MKenc, 64) per OTRv4
    #      4.4.2, replacing sha3_512(session_id || ratchet_id || msg_num). Same
    #      field, same offset, different value.
    #   2. REVEALED_MAC_KEY_LEN widened 32 -> 64, changing the byte layout of
    #      any message carrying revealed keys.
    #
    # Both ends must run the same revision. The version field is read and
    # checked in decode() before any key material is touched, so a mismatch
    # surfaces as ProtocolVersionError rather than as a MAC failure.
    #
    # Only THIS layer is incremented. The ClientProfile/DAKE format did not
    # change, so OTRConstants.PROTOCOL_VERSION stays at 4 -- bumping it would
    # falsely signal a handshake change and invalidate profiles needlessly.
    PROTOCOL_VERSION = 0x0005
    TYPE = 0x03
    ECDH_LEN = 56
    NONCE_LEN = 12
    MAC_LEN = 64
    REVEALED_MAC_KEY_LEN = 64   # OTRv4 §4.4.2 MKmac
    FLAG_IGNORE_UNREADABLE = 0x01

    def __init__(self):
        self.sender_tag: int = 0
        self.receiver_tag: int = 0
        self.flags: int = 0
        self.prev_chain_len: int = 0
        self.ratchet_id: int = 0
        self.message_id: int = 0
        self.ecdh_pub: bytes = b""
        self.dh_pub: Optional[bytes] = None
        self.kem_ek: Optional[bytes] = None
        self.kem_ct: Optional[bytes] = None
        self.nonce: bytes = b""
        self.ciphertext: bytes = b""
        self.mac: bytes = b""
        self.revealed_mac_keys: List[bytes] = []
        #: L1: the encoded field exactly as the Rust ratchet produced it
        #: (uint32 count || keys). Set on send, so the retired keys never
        #: exist in Python as a list of key objects; wins over the list.
        self.revealed_field: Optional[bytes] = None

    #: Keys one message may carry: the decoder's limit (and Rust's
    #: REVEAL_FIELD_MAX).
    MAX_REVEALED_KEYS = 2000

    @classmethod
    def check_revealed_field(cls, field: bytes) -> bytes:
        """`field` is a well-formed revealed_mac_keys field, or ValueError."""
        if len(field) < 4:
            raise ValueError("revealed-key field shorter than its count")
        n = struct.unpack("!I", field[:4])[0]
        if n > cls.MAX_REVEALED_KEYS or len(field) != 4 + n * cls.REVEALED_MAC_KEY_LEN:
            raise ValueError("revealed-key field does not match its count")
        return bytes(field)

    @classmethod
    def parse_revealed_field(cls, field: bytes) -> List[bytes]:
        """The keys a field publishes, as any third party reads them off the
        wire. Public data: used by tests and by a verifier, never on send."""
        cls.check_revealed_field(field)
        n = struct.unpack("!I", field[:4])[0]
        size = cls.REVEALED_MAC_KEY_LEN
        return [bytes(field[4 + i * size:4 + (i + 1) * size]) for i in range(n)]

    def _auth_header(self) -> bytes:
        """Bytes from protocol version through nonce (the authenticatable region)."""
        try:
            if len(self.ecdh_pub) != self.ECDH_LEN:
                raise ValueError(f"ECDH key must be {self .ECDH_LEN } bytes")
            if len(self.nonce) != self.NONCE_LEN:
                raise ValueError(f"Nonce must be {self .NONCE_LEN } bytes")
            buf = bytearray()
            buf += struct.pack("!HB", self.PROTOCOL_VERSION, self.TYPE)
            buf += struct.pack("!II", self.sender_tag, self.receiver_tag)
            buf += struct.pack("!B", self.flags)
            buf += struct.pack("!III", self.prev_chain_len, self.ratchet_id, self.message_id)
            buf += self.ecdh_pub
            if self.dh_pub is not None:
                if len(self.dh_pub) != self.ECDH_LEN:
                    raise ValueError(f"DH key must be {self .ECDH_LEN } bytes")
                buf += b"\x01" + self.dh_pub
            else:
                buf += b"\x00"

            if self.kem_ek is not None:
                if len(self.kem_ek) != MLKEM1024BraceKEM.EK_BYTES:
                    raise ValueError(f"KEM ek must be {MLKEM1024BraceKEM .EK_BYTES } bytes")
                buf += b"\x01" + self.kem_ek
            else:
                buf += b"\x00"
            if self.kem_ct is not None:
                if len(self.kem_ct) != MLKEM1024BraceKEM.CT_BYTES:
                    raise ValueError(f"KEM ct must be {MLKEM1024BraceKEM .CT_BYTES } bytes")
                buf += b"\x01" + self.kem_ct
            else:
                buf += b"\x00"
            buf += self.nonce
            return bytes(buf)
        except (struct.error, TypeError, ValueError) as e:
            raise ValueError(f"Failed to build auth header: {e }")

    def auth_region(self) -> bytes:
        """The public bytes the outer MAC covers:
        auth_header || uint32(len(ciphertext)) || ciphertext."""
        try:
            ah = self._auth_header()
            return ah + struct.pack("!I", len(self.ciphertext)) + self.ciphertext
        except (TypeError, ValueError, struct.error) as e:
            raise ValueError(f"Failed to build MAC region: {e }")

    def compute_mac(self, mac_key) -> bytes:
        """SHA3-512(MKmac || auth_region), computed in Rust.

        `mac_key` is the ratchet's `MessageMacKey` handle: the key stays in
        Rust, and this only frames the public region it covers.
        """
        return bytes(mac_key.seal(self.auth_region()))

    def verify_mac(self, mac_key) -> bool:
        """Constant-time MAC check, in Rust, against the `MessageMacKey`."""
        try:
            if len(self.mac) != self.MAC_LEN:
                return False
            return bool(mac_key.verify(self.auth_region(), self.mac))
        except (TypeError, ValueError, AttributeError) as e:
            if _debug.FLAGS.debug:
                print("[OTRv4DataMessage] MAC verification failed")
            return False
        except Exception:
            return False

    def encode(self) -> bytes:
        """Encode the complete DATA message to bytes for base64 transport."""
        try:
            ah = self._auth_header()
            ct_blk = struct.pack("!I", len(self.ciphertext)) + self.ciphertext
            mac = self.mac if len(self.mac) == self.MAC_LEN else b"\x00" * self.MAC_LEN
            if self.revealed_field is not None:
                return ah + ct_blk + mac + self.check_revealed_field(self.revealed_field)
            keys = struct.pack("!I", len(self.revealed_mac_keys))
            for k in self.revealed_mac_keys:
                # L1: 64 bytes per OTRv4 §4.4.2. Was 32, which silently
                # dropped every spec-sized key the engine produced.
                if len(k) != self.REVEALED_MAC_KEY_LEN:
                    raise ValueError(
                        f"Revealed MAC key must be {self .REVEALED_MAC_KEY_LEN } "
                        f"bytes, got {len (k )}")
                keys += k
            return ah + ct_blk + mac + keys
        except (struct.error, TypeError, ValueError) as e:
            raise ValueError(f"Failed to encode message: {e }")

    @classmethod
    def looks_like_data_frame(cls, decoded: bytes) -> bool:
        """True if `decoded` begins with this build's data-message header.

        Five call sites used to sniff the first three bytes as the literals
        0x00, 0x04, TYPE. When C1 moved PROTOCOL_VERSION from 0x0004 to
        0x0005 the encoder started emitting 00 05 03 and every one of those
        checks silently stopped matching -- so an encrypted data message fell
        through to the message-type branch, matched nothing, and was dropped
        with "unknown message type: 0" and no error to the user. SMP was the
        first thing to hit it because SMP is the first data message a session
        sends. Grepping for PROTOCOL_VERSION did not find them, because none
        of them referenced it.

        Deriving the bytes from the constant is what stops that recurring: a
        future revision changes one number and every classifier follows.
        """
        if len(decoded) < 3:
            return False
        return (decoded[0] == (cls.PROTOCOL_VERSION >> 8)
                and decoded[1] == (cls.PROTOCOL_VERSION & 0xFF)
                and decoded[2] == cls.TYPE)

    @classmethod
    def decode(cls, data: bytes) -> "OTRv4DataMessage":
        """Decode raw bytes into an OTRv4DataMessage.  Raises ValueError on errors."""
        try:
            r = BinaryReader(data)
            msg = cls()

            ver = r.read_uint16()
            if ver != cls.PROTOCOL_VERSION:
                # Checked before anything reads key material, so a mismatched
                # peer never reaches MAC verification and is never reported as
                # a forgery. Strict equality: no downgrade is accepted and the
                # pre-0x0005 MAC construction is never evaluated.
                raise ProtocolVersionError(
                    f"OTRv4+ wire revision mismatch: peer sent 0x{ver :04x}, "
                    f"this build speaks 0x{cls .PROTOCOL_VERSION :04x}. "
                    f"This is a version mismatch, NOT a forgery or replay. "
                    f"Both endpoints must run the same build."
                )
            mtype = r.read_uint8()
            if mtype != cls.TYPE:
                raise ValueError(
                    f"Wrong message type: 0x{mtype :02x} (expected 0x{cls .TYPE :02x})"
                )

            msg.sender_tag = r.read_uint32()
            msg.receiver_tag = r.read_uint32()
            msg.flags = r.read_uint8()
            msg.prev_chain_len = r.read_uint32()
            msg.ratchet_id = r.read_uint32()
            msg.message_id = r.read_uint32()
            msg.ecdh_pub = r.read_bytes(cls.ECDH_LEN)

            dh_flag = r.read_uint8()
            if dh_flag == 0x01:
                msg.dh_pub = r.read_bytes(cls.ECDH_LEN)
            elif dh_flag != 0x00:
                raise ValueError(f"Invalid DH flag byte: 0x{dh_flag :02x}")

            kem_ek_flag = r.read_uint8()
            if kem_ek_flag == 0x01:
                msg.kem_ek = r.read_bytes(MLKEM1024BraceKEM.EK_BYTES)
            elif kem_ek_flag != 0x00:
                raise ValueError(f"Invalid KEM ek flag: 0x{kem_ek_flag :02x}")

            kem_ct_flag = r.read_uint8()
            if kem_ct_flag == 0x01:
                msg.kem_ct = r.read_bytes(MLKEM1024BraceKEM.CT_BYTES)
            elif kem_ct_flag != 0x00:
                raise ValueError(f"Invalid KEM ct flag: 0x{kem_ct_flag :02x}")

            msg.nonce = r.read_bytes(cls.NONCE_LEN)
            ct_len = r.read_uint32()
            msg.ciphertext = r.read_bytes(ct_len)
            msg.mac = r.read_bytes(cls.MAC_LEN)

            num_keys = r.read_uint32()
            if num_keys > 2000:
                raise ValueError(f"Implausible revealed key count: {num_keys }")
            for _ in range(num_keys):
                msg.revealed_mac_keys.append(
                    r.read_bytes(cls.REVEALED_MAC_KEY_LEN))

            return msg
        except ProtocolVersionError:
            # C1: must NOT be re-wrapped. The whole point of the typed error is
            # that a caller can tell a wire-revision mismatch from a
            # cryptographic failure; flattening it back to a generic ValueError
            # here would restore exactly the ambiguity it exists to remove.
            raise
        except (ValueError, struct.error, TypeError) as e:
            raise ValueError(f"Failed to decode message: {e }")
