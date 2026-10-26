# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Where the apps keep each account's identity (F3, SPEC §3.1).

Same account on the same install: the same identity, so the same
fingerprint, on every sign-in. The identity is random, made by Rust on the
account's first sign-in here, sealed inside Rust (the private keys never reach
Python or Kotlin) under a key file of this install, and kept:

  * Android -- in the Keystore vault, which seals the record again under a
    key in the AndroidKeyStore. The records have a vault directory of their
    own, so clearing chat history cannot remove them; Wipe & Exit deletes the
    Keystore key, after which none of them can be opened.
  * desktop -- as 0600 files. There is no keystore: the protection at rest is
    the user account's file permissions (as for the terminal client).

The key file lives under ~/.otrv4plus, which Wipe & Exit destroys
(`wipe.python_state_roots`).
"""
from __future__ import annotations

import os

from otrv4plus_identity import AccountIdentities, FileRecords, VaultRecords

__all__ = ["identity_dir", "for_android", "for_desktop"]


def identity_dir() -> str:
    path = os.path.join(os.path.expanduser("~"), ".otrv4plus", "identity")
    os.makedirs(path, mode=0o700, exist_ok=True)
    return path


def for_android(vault) -> AccountIdentities:
    """[vault]: the Kotlin `Vault` the records go in (see module doc)."""
    return AccountIdentities(VaultRecords(vault),
                             os.path.join(identity_dir(), "identity.dek"))


def for_desktop() -> AccountIdentities:
    directory = identity_dir()
    return AccountIdentities(FileRecords(directory),
                             os.path.join(directory, "identity.dek"))
