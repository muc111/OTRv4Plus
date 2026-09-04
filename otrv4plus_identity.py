"""Persistent long-term identity for the XMPP client, and nothing else.

Why this module exists separately
---------------------------------
OTRv4+ generates a fresh Ed448 identity every process by deliberate design
(ROADMAP Phase 5.3g).  For IRC that is correct and stays: an IRC nick is
ephemeral, so an identity pinned to one is pinned to nothing, and a fingerprint
that never persists cannot be compared against anything later.

XMPP is the opposite case.  A JID is a durable name.  If the identity behind it
changes every launch then a changed fingerprint carries no information, TOFU
cannot work, and -- as the trust database actually behaved before this module
existed -- every reconnect produced a fingerprint mismatch that read as a MITM
alert.  Training a user to dismiss that alert is worse than never showing it.

So: XMPP gets a persistent identity, IRC does not.  Keeping the wiring in its
own module rather than inside ``otrv4+.py`` means the IRC client never imports
any of it, and the separation is visible rather than a flag deep in a
constructor.

What protects the identity at rest
----------------------------------
Read this before describing the guarantee anywhere.

The sealed record is AES-256-GCM twice over -- once inside Rust (the Ed448 seed
never becomes a Python object; see ``Rust/src/identity.rs``) and once by the
``SealedStore`` binding it to its record slot.  That is real, and it is what
stops the seed reaching the Python heap or a record being replayed into another
slot.

The data-encryption key protecting it is a 32-byte random file at
``identity_dek_path``, mode 0600, stretched with Argon2id.  There is no OS
keyring on Termux and no passphrase prompt here, which means:

    an attacker who can read your home directory can read the key file, and
    therefore the identity.  The at-rest protection is FILESYSTEM PERMISSIONS,
    not cryptography.

This is the same posture ``SMPAutoRespondStorage`` has always used for SMP
secrets (``~/.otrv4plus/.smp_seed``), so it adds no new class of exposure --
but it must not be described as hardware-backed, passphrase-protected, or
"encrypted at rest" without that qualification.  What it does defend against is
another process reading the sealed blob without also holding the key file, and
backups or sync tools that capture one file and not the other.
"""

from __future__ import annotations

import os
import secrets as _secrets
import stat


class IdentityUnavailable(RuntimeError):
    """Persistent identity was requested and could not be provided.

    Raised rather than falling back to an ephemeral identity.  A silent
    fallback would change the local fingerprint without telling anyone, and
    every peer would see that as the identity change TOFU exists to flag.
    """


# ---------------------------------------------------------------------------
# Data-encryption key
# ---------------------------------------------------------------------------

class _FileDekHandle:
    """One device-local DEK, in the shape ``RustSealedIdentityKeyStore`` wants."""

    def __init__(self, key: bytes, key_id: int):
        self._key = bytes(key)
        self._key_id = int(key_id)
        self._counter = 0

    @property
    def key_id(self) -> int:
        return self._key_id

    def raw_key_for_rust(self) -> bytes:
        """Hand the raw key down to the Rust sealing layer.

        The DEK is a Python ``bytes`` here.  That is a known residual, recorded
        in ``android_bridge/identity.py``: decision B1 required the *seed* to
        stay out of Python, and it does.  The DEK does not.
        """
        return self._key

    def next_counter(self) -> int:
        self._counter += 1
        return self._counter

    def _seal(self, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        return _aead(True, self._key, nonce, plaintext, aad)

    def _open(self, nonce: bytes, ciphertext_and_tag: bytes, aad: bytes) -> bytes:
        return _aead(False, self._key, nonce, ciphertext_and_tag, aad)


def _aead(seal: bytes, key: bytes, nonce: bytes, data: bytes, aad: bytes) -> bytes:
    """AES-256-GCM through the Rust core, which is the only implementation here."""
    import otrv4_core
    if seal:
        return bytes(otrv4_core.aes256gcm_encrypt(key, nonce, data, aad))
    return bytes(otrv4_core.aes256gcm_decrypt(key, nonce, data, aad))


class TermuxFileDekProvider:
    """A DEK read from a 0600 file, created on first use.

    Deliberately NOT passphrase-derived: see the module docstring for exactly
    what that costs.  The file is created with 0600 before any key material is
    written to it, not after, so there is no window in which the key exists
    with default permissions.
    """

    def __init__(self, dek_path: str, key_id: int = 1):
        if not dek_path:
            raise IdentityUnavailable("no identity DEK path configured")
        self._path = dek_path
        self._key_id = int(key_id)
        self._handle = None

    def current(self):
        if self._handle is None:
            self._handle = _FileDekHandle(self._load_or_create(), self._key_id)
        return self._handle

    def for_key_id(self, key_id: int):
        if int(key_id) != self._key_id:
            raise IdentityUnavailable(
                "identity sealed under key_id %d; this device holds %d"
                % (int(key_id), self._key_id))
        return self.current()

    def begin_epoch(self) -> None:
        """No key rotation on this provider; nothing to roll."""

    def _load_or_create(self) -> bytes:
        if os.path.exists(self._path):
            try:
                with open(self._path, "rb") as fh:
                    key = fh.read(32)
            except OSError as exc:
                raise IdentityUnavailable(
                    "identity key file unreadable: %s" % exc.__class__.__name__)
            if len(key) != 32:
                # Truncated key: refuse rather than pad or regenerate.
                # Regenerating here would make the sealed identity permanently
                # unopenable while looking like a successful first run.
                raise IdentityUnavailable(
                    "identity key file is %d bytes, expected 32 -- refusing to "
                    "replace it, because doing so would discard the identity "
                    "it protects" % len(key))
            _warn_if_group_or_world_readable(self._path)
            return key
        return self._create()

    def _create(self) -> bytes:
        key = _secrets.token_bytes(32)
        directory = os.path.dirname(self._path) or "."
        try:
            os.makedirs(directory, mode=0o700, exist_ok=True)
            # O_EXCL: never overwrite a key that appeared between the check and
            # here, because that key may already be protecting an identity.
            fd = os.open(self._path,
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(fd, key)
                os.fsync(fd)
            finally:
                os.close(fd)
        except FileExistsError:
            return self._load_or_create()
        except OSError as exc:
            raise IdentityUnavailable(
                "cannot create identity key file: %s" % exc.__class__.__name__)
        return key


def _warn_if_group_or_world_readable(path: str) -> None:
    """Say so if the only thing protecting the identity has been widened."""
    try:
        mode = os.stat(path).st_mode
    except OSError:
        return
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        print("[identity] WARNING: %s is readable beyond your user account. "
              "The identity is protected by file permissions only, so this "
              "means it is not protected." % path)


# ---------------------------------------------------------------------------
# Identity lifecycle
# ---------------------------------------------------------------------------

def load_or_create_identity(identity_path: str, dek_path: str):
    """Return ``(ed448_handle, x448_handle, fingerprint_bytes)`` for XMPP.

    First run creates and seals.  Every later run reloads the same identity, so
    the local fingerprint is stable and a peer's TOFU pin of it stays valid.

    Fails closed.  A record that exists but will not open is NOT replaced: that
    would turn a key-custody bug or tampering into silent identity loss, and
    every peer would see an unexplained fingerprint change.  The caller is told
    and the user decides.
    """
    if not identity_path:
        raise IdentityUnavailable("no identity path configured")

    try:
        from android_bridge.identity import (
            IdentityManager, RustSealedIdentityKeyStore, CorruptIdentity,
            IdentityError,
        )
        from android_bridge.secure_store import AesGcmSealedStore
    except ImportError as exc:
        raise IdentityUnavailable(
            "identity persistence needs the android_bridge package: %s" % exc)

    provider = TermuxFileDekProvider(dek_path)
    store = AesGcmSealedStore(provider)
    key_store = RustSealedIdentityKeyStore(provider)
    manager = IdentityManager(store, key_store)

    blob = _read_record(identity_path)

    def _persist(sealed: bytes) -> None:
        _write_record(identity_path, sealed)

    try:
        record = manager.load_or_create(blob, _persist)
    except CorruptIdentity as exc:
        raise IdentityUnavailable(
            "the stored XMPP identity could not be opened (%s).\n"
            "  It has NOT been replaced. Replacing it silently would change "
            "your fingerprint\n"
            "  and every peer who pinned it would see that as an identity "
            "change.\n"
            "  If you know why (restored backup, deleted key file), move %s "
            "aside to start\n"
            "  a new identity -- and expect peers to warn about the change."
            % (exc, identity_path)) from None
    except IdentityError as exc:
        raise IdentityUnavailable("identity storage unusable: %s" % exc) from None

    return (record.identity_handle, record.prekey_handle,
            record.identity_pub)


def _read_record(path: str):
    try:
        with open(path, "rb") as fh:
            blob = fh.read()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise IdentityUnavailable(
            "identity record unreadable: %s" % exc.__class__.__name__)
    return blob or None


def _write_record(path: str, sealed: bytes) -> None:
    """Write the sealed record atomically, 0600, fsynced.

    Atomic because a half-written record is an unopenable one, and an
    unopenable record deliberately does not self-heal -- a torn write during a
    first run would otherwise strand the identity permanently.
    """
    directory = os.path.dirname(path) or "."
    tmp = None
    try:
        os.makedirs(directory, mode=0o700, exist_ok=True)
        fd, tmp = _mkstemp_600(directory)
        try:
            os.write(fd, bytes(sealed))
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, path)
        tmp = None
        _fsync_dir(directory)
    except OSError as exc:
        raise IdentityUnavailable(
            "cannot write identity record: %s" % exc.__class__.__name__)
    finally:
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass


def _mkstemp_600(directory: str):
    import tempfile
    fd, name = tempfile.mkstemp(dir=directory, prefix=".identity-")
    os.fchmod(fd, 0o600)
    return fd, name


def _fsync_dir(directory: str) -> None:
    try:
        dfd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(dfd)
    except OSError:
        pass
    finally:
        os.close(dfd)
