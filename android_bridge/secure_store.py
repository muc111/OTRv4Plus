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
A fresh 96-bit nonce from the OS CSPRNG for every encryption operation, as the
product specification requires.  `os.urandom` is used, which on Android is
`getrandom(2)`.

Uniqueness is enforced by design rather than left to chance.  The Rust AEAD is
stateless and delegates nonce uniqueness to its caller (prior audit item M4), so
the obligation lands here:

  * NIST SP 800-38D §8.3 bounds random-nonce AES-GCM at 2^32 invocations under
    one key.  `MAX_RECORDS_PER_KEY` is set to that bound, and `seal` raises
    `KeyRotationRequired` on reaching it rather than quietly continuing.  At
    2^32 records the collision probability is about 2^-33.
  * `key_id` identifies the key generation, so rotation gives a fresh nonce
    space and old records stay readable under their original key.
  * `tests/test_android_identity.py` asserts nonce uniqueness across bulk seals
    and asserts that two seals of identical plaintext differ.

An earlier draft of this module used a deterministic counter.  That was changed
to match the specification: the counter is retained ONLY to enforce the rotation
bound above, and never contributes to the nonce.
"""

from __future__ import annotations

import abc
import os
import struct
from typing import Optional

__all__ = [
    "SealedStore",
    "AesGcmSealedStore",
    "DekProvider",
    "DekHandle",
    "SealError",
    "UnsealError",
    "KeyRotationRequired",
    "NonceExhausted",
    "RECORD_VERSION",
]

RECORD_VERSION = 1

_NONCE_LEN = 12
_TAG_LEN = 16
_KEY_ID_LEN = 4
_HEADER_LEN = 1 + _KEY_ID_LEN + _NONCE_LEN

# NIST SP 800-38D §8.3: with random nonces, AES-GCM is bounded to 2^32
# invocations per key.  Reaching it is a clean, loud error demanding rotation --
# never a silent continuation past the analysed bound.
MAX_RECORDS_PER_KEY = 1 << 32


class SealError(RuntimeError):
    """Sealing failed.  Never carries plaintext or key material."""


class UnsealError(RuntimeError):
    """Unsealing failed: wrong key, wrong AAD, corrupt or truncated record.

    Deliberately undifferentiated.  A caller cannot learn *why* a record failed
    to open, so a tampered record and a wrong-key record are indistinguishable.
    """


class KeyRotationRequired(SealError):
    """This key generation has reached its record limit; rotate before sealing.

    Raised at the NIST SP 800-38D random-nonce bound of 2^32 records per key.
    Deliberately fatal to the seal: continuing past the analysed bound would
    make the collision probability an unmeasured quantity.
    """


# Retained under the old name so existing callers keep working.
NonceExhausted = KeyRotationRequired


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
        """Count one more record sealed under this key_id, and return the total.

        This is a usage meter for the rotation bound in `MAX_RECORDS_PER_KEY`.
        It does NOT contribute to the nonce -- nonces come from the CSPRNG.
        """


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
        records = handle.next_counter()
        if records > MAX_RECORDS_PER_KEY:
            raise KeyRotationRequired(
                "key generation has reached the NIST SP 800-38D random-nonce "
                "bound of 2^32 records; rotate the key before sealing more"
            )

        # Fresh 96-bit nonce from the OS CSPRNG for every operation, per the
        # product specification.  os.urandom is getrandom(2) on Android.
        nonce = os.urandom(_NONCE_LEN)
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
