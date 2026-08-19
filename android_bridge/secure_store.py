"""Versioned authenticated at-rest storage for OTRv4+ on Android.

Scope note (Phase 2 vs Phase 4)
-------------------------------
This module implements the *record format* and the *interfaces*.  It does NOT
implement key custody.  Producing the data-encryption key -- unwrapping it from
an Android Keystore/StrongBox-held wrapping key after an Argon2id-derived KEK
opens it -- is Phase 4 and is represented here only by the abstract
`DekProvider`.  There is deliberately no production `DekProvider` in this
package: a caller that does not supply one gets an exception, not a default.

That is the point.  The Phase 2 instruction is explicit that a temporary
plaintext implementation must not be invented and then accidentally allowed into
production, so the hole is left open and fail-closed rather than plugged with
something that works.

Record format
-------------
    version(1) || key_id(4, big-endian) || nonce(12) || ciphertext || tag(16)

The tag is appended to the ciphertext by the AEAD, so the trailing 16 bytes of
`ciphertext||tag` are the tag.  AAD binds the framing to the record's identity:

    AAD = version(1) || key_id(4) || record_type || 0x00
                     || schema_version(2) || 0x00 || record_id

Binding record_type, record_id and schema_version means a sealed blob cannot be
moved between record types, renamed, or replayed against a different schema: the
tag check fails.  Binding key_id means a record cannot be silently attributed to
a different key generation.

Nonce policy
------------
Deterministic per-key counter, not `random(12)`.

The Rust AEAD is stateless and delegates nonce uniqueness to its caller (prior
audit item M4).  A random 96-bit nonce carries a birthday bound that a message
database will approach; a counter does not.  The counter is persisted next to
the key generation by the `DekProvider`, and `key_id` increments whenever the
key rotates, which resets the counter space.

If a provider cannot guarantee the counter survives process death, it must
report a fresh `key_id` at every start (see `DekProvider.begin_epoch`), which
trades key-rotation churn for a guarantee that no nonce is ever reused.
"""

from __future__ import annotations

import abc
import struct
from typing import Optional

__all__ = [
    "SealedStore",
    "AesGcmSealedStore",
    "DekProvider",
    "DekHandle",
    "SealError",
    "UnsealError",
    "NonceExhausted",
    "RECORD_VERSION",
]

RECORD_VERSION = 1

_NONCE_LEN = 12
_TAG_LEN = 16
_KEY_ID_LEN = 4
_HEADER_LEN = 1 + _KEY_ID_LEN + _NONCE_LEN

# 2^64 records under one key would be absurd; cap far below the GCM counter
# limit so exhaustion is a clean error rather than a wrap.
_MAX_COUNTER = (1 << 48) - 1


class SealError(RuntimeError):
    """Sealing failed.  Never carries plaintext or key material."""


class UnsealError(RuntimeError):
    """Unsealing failed: wrong key, wrong AAD, corrupt or truncated record.

    Deliberately undifferentiated.  A caller cannot learn *why* a record failed
    to open, so a tampered record and a wrong-key record are indistinguishable.
    """


class NonceExhausted(SealError):
    """The counter space for this key generation is used up; rotate the key."""


class DekHandle(abc.ABC):
    """An opaque reference to a 256-bit data-encryption key.

    The key bytes are NOT an attribute of this object as far as callers are
    concerned.  `_use` is the single internal access point, so that a Phase 4
    implementation backed by Android Keystore -- where the key genuinely cannot
    be read -- can satisfy the same interface by performing the operation
    instead of surrendering the key.
    """

    @property
    @abc.abstractmethod
    def key_id(self) -> int:
        """Monotonic generation number for this key.  Changes on rotation."""

    @abc.abstractmethod
    def _seal(self, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        """Return ciphertext||tag."""

    @abc.abstractmethod
    def _open(self, nonce: bytes, ciphertext_and_tag: bytes, aad: bytes) -> bytes:
        """Return plaintext, or raise on any authentication failure."""

    @abc.abstractmethod
    def next_counter(self) -> int:
        """Return a counter value never previously used under this key_id."""


class DekProvider(abc.ABC):
    """Supplies the current data-encryption key.

    Phase 4 implements this over Android Keystore/StrongBox:

        unlock credential -> Argon2id -> KEK -> unwrap Keystore-held DEK -> handle

    The credential is an authentication input, never the key itself, so it can be
    changed by re-wrapping the same DEK without re-encrypting any user data.
    """

    @abc.abstractmethod
    def current(self) -> DekHandle:
        """Return the DEK handle for new writes."""

    @abc.abstractmethod
    def for_key_id(self, key_id: int) -> DekHandle:
        """Return the handle for an older generation, to read existing records.

        Raise `UnsealError` if that generation is not available -- callers must
        not be able to distinguish "key retired" from "record corrupt".
        """

    def begin_epoch(self) -> None:
        """Called once at process start.

        A provider that cannot persist its nonce counter across process death
        must rotate `key_id` here, so counters never restart under a key that has
        already used them.
        """
        return None


def _build_aad(version: int, key_id: int, record_type: str,
               schema_version: int, record_id: str) -> bytes:
    """Bind the record's identity into the authentication tag.

    record_type and record_id are NUL-terminated rather than concatenated so
    that ("ab", "c") and ("a", "bc") produce different AAD.  Without the
    separators an attacker who controls one field could shift the boundary and
    make one record authenticate as another.
    """
    if "\x00" in record_type or "\x00" in record_id:
        raise SealError("record_type/record_id must not contain NUL")
    return (
        bytes([version])
        + struct.pack(">I", key_id)
        + record_type.encode("utf-8") + b"\x00"
        + struct.pack(">H", schema_version) + b"\x00"
        + record_id.encode("utf-8")
    )


class SealedStore(abc.ABC):
    """Persist authenticated, encrypted records."""

    @abc.abstractmethod
    def seal(self, record_type: str, record_id: str, schema_version: int,
             plaintext: bytes) -> bytes:
        """Return a self-describing sealed record."""

    @abc.abstractmethod
    def unseal(self, record_type: str, record_id: str, schema_version: int,
               blob: bytes) -> bytes:
        """Return the plaintext, or raise `UnsealError`."""


class AesGcmSealedStore(SealedStore):
    """AES-256-GCM records, keyed by a `DekProvider`.

    The AEAD itself is the Rust core's `aes256gcm_encrypt`/`aes256gcm_decrypt`
    (the same implementation the DAKE and ratchet use).  No cryptographic
    primitive is implemented here -- this class only frames, binds AAD, and
    manages nonces.
    """

    def __init__(self, dek_provider: DekProvider):
        if dek_provider is None:
            raise SealError(
                "AesGcmSealedStore requires a DekProvider. There is no default: "
                "key custody is supplied by the platform (Phase 4: Android "
                "Keystore/StrongBox), never by this module."
            )
        self._dek = dek_provider
        self._dek.begin_epoch()

    def seal(self, record_type: str, record_id: str, schema_version: int,
             plaintext: bytes) -> bytes:
        handle = self._dek.current()
        counter = handle.next_counter()
        if counter > _MAX_COUNTER:
            raise NonceExhausted("counter space exhausted for this key_id; rotate")

        # 12-byte nonce: 4 zero bytes || 8-byte big-endian counter.  Unique per
        # (key_id, counter) and never reused because the counter is monotonic
        # and key_id changes on rotation.
        nonce = b"\x00" * 4 + struct.pack(">Q", counter)
        aad = _build_aad(RECORD_VERSION, handle.key_id, record_type,
                         schema_version, record_id)
        try:
            ct_and_tag = handle._seal(nonce, plaintext, aad)
        except Exception as exc:               # never leak plaintext detail
            raise SealError(f"seal failed: {type(exc).__name__}") from None
        return bytes([RECORD_VERSION]) + struct.pack(">I", handle.key_id) + nonce + ct_and_tag

    def unseal(self, record_type: str, record_id: str, schema_version: int,
               blob: bytes) -> bytes:
        if not isinstance(blob, (bytes, bytearray)) or len(blob) < _HEADER_LEN + _TAG_LEN:
            raise UnsealError("record malformed")
        blob = bytes(blob)

        version = blob[0]
        if version != RECORD_VERSION:
            # Readable-but-unknown version is still a failure: refuse rather
            # than guess at a framing we do not know.
            raise UnsealError("record malformed")

        key_id = struct.unpack(">I", blob[1:1 + _KEY_ID_LEN])[0]
        nonce = blob[1 + _KEY_ID_LEN:_HEADER_LEN]
        ct_and_tag = blob[_HEADER_LEN:]

        handle = self._dek.for_key_id(key_id)
        aad = _build_aad(version, key_id, record_type, schema_version, record_id)
        try:
            return handle._open(nonce, ct_and_tag, aad)
        except UnsealError:
            raise
        except Exception:
            # Undifferentiated on purpose -- see UnsealError.
            raise UnsealError("record failed authentication") from None
