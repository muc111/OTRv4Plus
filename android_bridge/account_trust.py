# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Where the apps keep each account's trust pins (P1, SPEC §4.3).

The pins are what `TrustDatabase` checks every handshake against: each
contact's Ed448 fingerprint, the ML-DSA key pinned under it (A2), and the
user's "They match" confirmation. Kept only in memory, they were gone at the
next start, and a key substituted then was taken as a first contact
(docs/SECURITY_ISSUES.md P1). Now they are kept per account, like the
account's identity (F3), and apart from it:

  * the same sealing path as F3 -- AES-256-GCM in Rust under a 0600 key file
    created by Rust (`otrv4plus_identity.TermuxFileDekProvider`,
    `AesGcmSealedStore`), each record bound to its own name -- but its own key
    file and its own directory, ~/.otrv4plus/trust;
  * Android -- in the Keystore vault's own "trust-vault" section, sealed a
    second time under the AndroidKeyStore key. Not the identity vault and not
    chat history: clearing either never takes the pins with it;
  * desktop -- as 0600 files in that directory.

The pins are public values (fingerprints, key hashes) but show whom the
user talks to, so they are sealed, never plaintext.

A record that exists and will not open is REFUSED (`TrustUnavailable`), never
replaced: an empty trust store in its place would be P1 again. On Android
the vault answers None both for "never written" and for "will not open", so
a marker file -- empty, named by the account's hash -- says a record was
written. Only a vault that really keeps records (a KeystoreVault, not the
in-memory fallback) gets a trust store at all, so a device whose Keystore
does not work keeps pins for one run, as before, instead of being refused.

Wipe & Exit destroys all of it: the Keystore key and every vault section,
then ~/.otrv4plus (`wipe.python_state_roots`).
"""
from __future__ import annotations

import hashlib
import json
import os
from typing import Optional

from otrv4plus_identity import TermuxFileDekProvider, _read_record, _write_record

from .secure_store import AesGcmSealedStore, UnsealError

__all__ = ["TrustUnavailable", "trust_dir", "trust_tag", "for_android", "for_desktop"]

RECORD_TYPE = "otr.trust"
SCHEMA = 1


class TrustUnavailable(RuntimeError):
    """The account's trust record exists and will not open. It is not
    replaced; the connection is refused (`trust_unavailable`)."""


def trust_dir() -> str:
    path = os.path.join(os.path.expanduser("~"), ".otrv4plus", "trust")
    os.makedirs(path, mode=0o700, exist_ok=True)
    return path


def trust_tag(account) -> str:
    """The name an account's trust record is kept under: a domain-separated
    SHA3-256 of the bare JID, so no file or vault entry names the JID."""
    bare = str(account or "").split("/", 1)[0].strip().lower()
    if "@" not in bare:
        raise ValueError("trust pins are per account (user@server)")
    return hashlib.sha3_256(b"OTRv4+ trust record v1\x00" + bare.encode("utf-8")).hexdigest()[:32]


class _FileTrustRecords:
    """Sealed records as 0600 files (the desktop). A file that is there is
    a record that was written."""

    def __init__(self, directory: str):
        self._dir = directory

    def get(self, name: str) -> Optional[bytes]:
        blob = _read_record(os.path.join(self._dir, name))
        if blob is None and os.path.exists(os.path.join(self._dir, name)):
            raise TrustUnavailable("trust record empty")
        return blob

    def put(self, name: str, sealed: bytes) -> None:
        _write_record(os.path.join(self._dir, name), sealed)


class _VaultTrustRecords:
    """Sealed records in the Keystore vault's trust section (Android), with
    a marker file per record, because the vault cannot say "will not open"."""

    PREFIX = "otrv4plus.trust."

    def __init__(self, vault, marker_dir: str):
        self._vault = vault
        self._markers = marker_dir

    def _marker(self, name: str) -> str:
        return os.path.join(self._markers, name + ".present")

    def get(self, name: str) -> Optional[bytes]:
        blob = self._vault.get(self.PREFIX + name)
        if blob is not None and len(blob):
            return bytes(blob)
        if os.path.exists(self._marker(name)):
            raise TrustUnavailable("the vault holds a trust record it cannot open")
        return None

    def put(self, name: str, sealed: bytes) -> None:
        self._vault.put(self.PREFIX + name, bytes(sealed))
        if not os.path.exists(self._marker(name)):
            _write_record(self._marker(name), b"")


class AccountTrustRecord:
    """One account's pins: `load()` for `TrustDatabase.use_store`, then
    `save(db)` on every change."""

    def __init__(self, records, sealed: AesGcmSealedStore, name: str):
        self._records = records
        self._sealed = sealed
        self._name = name

    def load(self) -> Optional[dict]:
        blob = self._records.get(self._name)
        if blob is None:
            return None
        try:
            plain = self._sealed.unseal(RECORD_TYPE, self._name, SCHEMA, blob)
            data = json.loads(bytes(plain).decode("utf-8"))
        except (UnsealError, ValueError, UnicodeDecodeError):
            raise TrustUnavailable("the account's trust record would not open") from None
        except Exception as exc:
            raise TrustUnavailable("trust record: %s" % exc.__class__.__name__) from None
        if not isinstance(data, dict):
            raise TrustUnavailable("the account's trust record is not a table")
        return data

    def save(self, db: dict) -> None:
        plain = json.dumps(db, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self._records.put(self._name, self._sealed.seal(RECORD_TYPE, self._name, SCHEMA, plain))


class AccountTrust:
    """Every account's trust record on this install."""

    def __init__(self, records, dek_path: str):
        self._records = records
        self._sealed = AesGcmSealedStore(TermuxFileDekProvider(dek_path))

    def for_account(self, account) -> AccountTrustRecord:
        return AccountTrustRecord(self._records, self._sealed,
                                  "trust.%s.sealed" % trust_tag(account))


def for_android(vault, persistent: bool) -> Optional[AccountTrust]:
    """[vault]: the Keystore vault's trust section. [persistent]: whether it
    is a real KeystoreVault (not the in-memory fallback). Without one there
    is no trust store, and the pins last one run, as before."""
    if not persistent:
        return None
    directory = trust_dir()
    return AccountTrust(_VaultTrustRecords(vault, directory),
                        os.path.join(directory, "trust.dek"))


def for_desktop() -> AccountTrust:
    directory = trust_dir()
    return AccountTrust(_FileTrustRecords(directory), os.path.join(directory, "trust.dek"))
