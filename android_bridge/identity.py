"""Long-term identity lifecycle for the Android product.

Background: why this module needs a decision
--------------------------------------------
OTRv4+ shipped with *ephemeral* identity by deliberate design (ROADMAP Phase
5.3g): `ClientProfile.__init__` documents "Keys are ALWAYS generated fresh -- no
saved profile file is consulted", and `_store_identity()` is a no-op.  The
Android product requires the opposite (approved decision B1): a stable
fingerprint that survives restart, process death, reboot and app update.

There is a concrete obstacle in the way, and it is a security boundary rather
than an inconvenience:

    `generate_ed448_keypair()` creates the seed INSIDE Rust and there is no
    PyO3 accessor that returns it.  `expose_seed_slice()` is `pub(crate)`.
    A key generated the production way therefore CANNOT be persisted.

The only reconstruction path is `Ed448KeyHandle.from_seed_bytes(seed)`, whose
own docstring calls itself "test/internal use; production calls
generate_ed448_keypair instead so the seed is never observed from Python at
all."  So persistence requires a seed that Python has held.

Two ways to resolve it:

  A. Generate the seed in Python, seal it, reconstruct with `from_seed_bytes`.
     Works today with no Rust change.  Costs the documented property that
     private key bytes never appear on the Python heap: the seed is on the heap
     at creation and again at every load, and CPython gives no reliable
     zeroization for it.

  B. Seal and unseal INSIDE Rust -- an additive `storage.rs` exposing something
     like `seal_ed448_handle(handle, dek) -> bytes` and
     `unseal_ed448_handle(blob, dek) -> Ed448KeyHandle`.  Only ciphertext
     crosses the boundary; the seed never enters Python at any point.  Needs new
     (additive, non-primitive) Rust.

B is the architecturally correct answer and is what the Phase 1 report proposed.
A is not safe to adopt silently, so this module does NOT choose: it defines
`IdentityKeyStore` as the swap point, and both options implement it.  The Phase 2
deliverable is the interface plus a test double; the production implementation
is a Phase 4 item pending that decision.

What this module guarantees regardless of which is chosen
--------------------------------------------------------
  * The seed never reaches disk unsealed -- persistence goes through a
    `SealedStore`, which is authenticated AES-256-GCM.
  * There is no default `IdentityKeyStore`.  Constructing an `IdentityManager`
    without one raises; nothing silently falls back to plaintext.
  * The public fingerprint is stable across reload, and is derived from the
    public key only.
  * A tampered or truncated identity record is rejected, not partially loaded.
"""

from __future__ import annotations

import abc
import hashlib
from typing import Optional, Tuple

from .secure_store import SealedStore, UnsealError

__all__ = [
    "IdentityKeyStore",
    "IdentityManager",
    "IdentityRecord",
    "IdentityError",
    "CorruptIdentity",
    "fingerprint_of",
    "IDENTITY_RECORD_TYPE",
    "IDENTITY_SCHEMA_VERSION",
]

IDENTITY_RECORD_TYPE = "otr.identity"
IDENTITY_SCHEMA_VERSION = 1
_DEFAULT_RECORD_ID = "primary"


class IdentityError(RuntimeError):
    """Identity could not be created or loaded."""


class CorruptIdentity(IdentityError):
    """The stored identity record did not authenticate, or is unusable.

    Raised for tampering, truncation, wrong key, and structurally invalid
    contents alike -- the caller learns that the identity is unusable, not why.
    """


def fingerprint_of(identity_pub_bytes: bytes) -> str:
    """SHA3-512 fingerprint of a 57-byte Ed448 public key, hex, lowercase.

    Matches the derivation the Rust core uses (`kdf::fingerprint_sha3_512`), so a
    fingerprint shown by the Android UI is the same value the engine reports.
    Public input only -- this never touches private material.
    """
    if not isinstance(identity_pub_bytes, (bytes, bytearray)) or len(identity_pub_bytes) != 57:
        raise IdentityError("identity public key must be 57 bytes")
    return hashlib.sha3_512(bytes(identity_pub_bytes)).hexdigest()


class IdentityRecord:
    """A loaded identity.  Carries handles and public data, never secrets."""

    __slots__ = ("identity_handle", "prekey_handle", "identity_pub", "prekey_pub", "created_at")

    def __init__(self, identity_handle, prekey_handle,
                 identity_pub: bytes, prekey_pub: bytes, created_at: int):
        self.identity_handle = identity_handle
        self.prekey_handle = prekey_handle
        self.identity_pub = bytes(identity_pub)
        self.prekey_pub = bytes(prekey_pub)
        self.created_at = int(created_at)

    @property
    def fingerprint(self) -> str:
        return fingerprint_of(self.identity_pub)

    def __repr__(self) -> str:            # never render key material
        return f"<IdentityRecord fp={self.fingerprint[:16]}... created={self.created_at}>"


class IdentityKeyStore(abc.ABC):
    """The swap point between resolutions A and B described in the module docstring.

    An implementation converts between "a live pair of Rust key handles" and "an
    opaque blob safe to hand to a SealedStore".  How it does that -- and in
    particular whether a seed ever exists as a Python object -- is entirely the
    implementation's business.
    """

    @abc.abstractmethod
    def create(self) -> Tuple[object, object, bytes]:
        """Create a fresh identity.

        Returns (identity_handle, prekey_handle, serialized) where `serialized`
        is opaque bytes that `restore` can turn back into the same handles.
        """

    @abc.abstractmethod
    def restore(self, serialized: bytes) -> Tuple[object, object]:
        """Rebuild (identity_handle, prekey_handle) from `create`'s output.

        Raise `CorruptIdentity` if the input is not usable.
        """


class IdentityManager:
    """Create-once / load-thereafter identity with a stable fingerprint.

        first run    -> create() -> serialize -> seal -> store
        later runs   -> load -> unseal -> restore() -> same fingerprint

    `store` and `key_store` are both required.  There is no default for either,
    so an incompletely wired build fails loudly instead of quietly persisting
    something readable.
    """

    def __init__(self, store: SealedStore, key_store: IdentityKeyStore,
                 record_id: str = _DEFAULT_RECORD_ID):
        if store is None:
            raise IdentityError(
                "IdentityManager requires a SealedStore; identity material is "
                "never written unsealed."
            )
        if key_store is None:
            raise IdentityError(
                "IdentityManager requires an IdentityKeyStore. See the module "
                "docstring: whether the seed may exist in Python is an open "
                "security decision, so there is deliberately no default."
            )
        self._store = store
        self._key_store = key_store
        self._record_id = record_id
        self._loaded: Optional[IdentityRecord] = None

    # -- persistence -----------------------------------------------------------

    def _seal_and_persist(self, serialized: bytes, created_at: int, persist) -> None:
        import struct
        payload = struct.pack(">Q", created_at) + serialized
        blob = self._store.seal(IDENTITY_RECORD_TYPE, self._record_id,
                                IDENTITY_SCHEMA_VERSION, payload)
        persist(blob)

    def create(self, persist, now: Optional[int] = None) -> IdentityRecord:
        """Generate a new identity and hand the sealed blob to `persist`.

        `persist(blob: bytes) -> None` is supplied by the caller so this class
        never touches the filesystem: on Android the blob goes to app-private
        storage, in tests it goes to a dict.
        """
        import time
        created_at = int(now if now is not None else time.time())
        ident, prekey, serialized = self._key_store.create()
        try:
            self._seal_and_persist(serialized, created_at, persist)
        finally:
            del serialized
        rec = IdentityRecord(ident, prekey,
                             bytes(ident.public_bytes()), bytes(prekey.public_bytes()),
                             created_at)
        self._loaded = rec
        return rec

    def load(self, blob: bytes) -> IdentityRecord:
        """Reconstruct the identity from a sealed blob.

        Raises `CorruptIdentity` for anything unusable -- failed authentication,
        truncation, or contents the key store rejects.
        """
        import struct
        if not blob:
            raise CorruptIdentity("no identity record")
        try:
            payload = self._store.unseal(IDENTITY_RECORD_TYPE, self._record_id,
                                         IDENTITY_SCHEMA_VERSION, bytes(blob))
        except UnsealError:
            raise CorruptIdentity("identity record failed authentication") from None
        if len(payload) < 8:
            raise CorruptIdentity("identity record truncated")

        created_at = struct.unpack(">Q", payload[:8])[0]
        serialized = payload[8:]
        try:
            ident, prekey = self._key_store.restore(serialized)
        except CorruptIdentity:
            raise
        except Exception:
            raise CorruptIdentity("identity record unusable") from None
        finally:
            del serialized

        rec = IdentityRecord(ident, prekey,
                             bytes(ident.public_bytes()), bytes(prekey.public_bytes()),
                             created_at)
        self._loaded = rec
        return rec

    def load_or_create(self, blob: Optional[bytes], persist) -> IdentityRecord:
        """Load an existing identity, or create one on first run.

        A present-but-unopenable record is NOT silently replaced: that would turn
        tampering or a key-custody bug into silent identity loss, and the peer
        would see a fingerprint change with no explanation.  The caller decides.
        """
        if blob:
            return self.load(blob)
        return self.create(persist)

    @property
    def current(self) -> Optional[IdentityRecord]:
        return self._loaded
