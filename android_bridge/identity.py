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

Two ways to resolve it were considered:

  A. Generate the seed in Python, seal it, reconstruct with `from_seed_bytes`.
     Works with no Rust change.  Costs the documented property that private key
     bytes never appear on the Python heap: the seed is on the heap at creation
     and again at every load, and CPython gives no reliable zeroization for it.

  B. Seal and unseal INSIDE Rust.  Only ciphertext crosses the boundary; the
     seed never enters Python at any point.

**Option B is the approved and implemented design** (decision B1).  The additive
Rust module `Rust/src/identity.rs` provides `create_sealed_identity`,
`seal_identity` and `unseal_identity`, using the crate-internal accessors that
are `pub(crate)` and therefore invisible to Python.  No `get_seed()` accessor
was added and none may be: `tests/test_rust_identity_sealing.py` enumerates the
module's Python-visible surface and fails if anything seed-shaped appears.

`RustSealedIdentityKeyStore` below is the production implementation.  Option A
survives only as a test double in `tests/test_android_identity.py`, kept because
it exercises the manager's lifecycle without requiring a DEK, and marked there
as development/test only.

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


class RustSealedIdentityKeyStore(IdentityKeyStore):
    """Production identity custody: sealing happens inside Rust (decision B1).

    The Ed448 seed and X448 private scalar are read through Rust's
    crate-internal accessors and encrypted before anything crosses into Python.
    What this class handles is ciphertext.

    Two layers of AES-256-GCM end up wrapping the identity, deliberately:

      inner  Rust `identity.rs`  -- keeps the seed inside the Rust boundary and
                                    binds the record version and key_id
      outer  `SealedStore`       -- binds the record to its slot (record type,
                                    record id, schema version)

    The outer layer is what stops a sealed identity being replayed into a
    different record slot; the inner layer is what stops the seed ever being a
    Python object.  They solve different problems, so both are kept.

    The data-encryption key is supplied by a `DekProvider`.  On Android that key
    is unwrapped from a Keystore-held wrapping key; here it is whatever the
    provider supplies.

    Known residual, recorded rather than glossed: the DEK itself is a Python
    `bytes` in this arrangement, because the provider hands it over to be passed
    down to Rust.  The seed is not, which is what decision B1 required.  Phase 4
    should shorten that path further by having Kotlin pass the unwrapped DEK
    straight into Rust over JNI, so Python only ever holds an opaque handle.
    """

    def __init__(self, dek_provider, key_id: int = 1):
        if dek_provider is None:
            raise IdentityError(
                "RustSealedIdentityKeyStore requires a DekProvider; identity "
                "material is never sealed under a key this class invents."
            )
        self._dek_provider = dek_provider
        self._key_id = int(key_id)

    def _core(self):
        try:
            import otrv4_core
        except ImportError as exc:
            raise IdentityError(
                "otrv4_core is required for identity sealing"
            ) from exc
        for required in ("create_sealed_identity", "unseal_identity"):
            if not hasattr(otrv4_core, required):
                raise IdentityError(
                    f"otrv4_core is missing {required}; rebuild the Rust core"
                )
        return otrv4_core

    def _dek(self) -> bytes:
        handle = self._dek_provider.current()
        raw = getattr(handle, "raw_key_for_rust", None)
        if raw is None:
            raise IdentityError(
                "the DekProvider must expose raw_key_for_rust() so the key can "
                "be handed to the Rust sealing layer"
            )
        return raw()

    def create(self):
        """Generate and seal an identity without the seed entering Python."""
        core = self._core()
        dek = self._dek()
        try:
            ident, prekey, sealed = core.create_sealed_identity(dek, self._key_id)
        except Exception as exc:
            raise IdentityError(f"identity creation failed: {type(exc).__name__}") from None
        return ident, prekey, bytes(sealed)

    def restore(self, serialized: bytes):
        """Rebuild the handles from a Rust-sealed blob.

        Any failure -- wrong key, tampering, truncation, unknown version --
        raises `CorruptIdentity`, undifferentiated.
        """
        core = self._core()
        dek = self._dek()
        try:
            ident, prekey = core.unseal_identity(bytes(serialized), dek, self._key_id)
        except Exception:
            raise CorruptIdentity("identity record could not be opened") from None
        return ident, prekey


__all__.append("RustSealedIdentityKeyStore")
