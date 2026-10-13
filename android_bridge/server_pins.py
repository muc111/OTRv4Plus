# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Which I2P destination a human-readable server name was trusted at (X1).

THE DEFECT
----------
A short `.i2p` name is not an identity. The router's address book binds it
to a destination, and whoever can influence that binding -- a subscription
feed, a jump service, a name registered first -- decides which key-holder
`otrv4plus.i2p` reaches. Over I2P the transport turns TLS certificate checks
off (there is no CA for `.i2p`), so nothing else stood between a substituted
destination and the account password the client then sent it.

THE RULE
--------
The endpoint's identity is its DESTINATION -- as the `.b32.i2p` hash of the
full destination the router returned -- never the name. The first destination
a name resolves to is pinned once that connection succeeds (trust on first
use). From then on:

  * same destination  -> proceed;
  * other destination -> refuse BEFORE STREAM CONNECT. Not one byte, and
    therefore no credential, goes to the new destination; the user is told
    both addresses and only an explicit "trust this new address" for that
    exact destination replaces the pin.

`.b32.i2p` addresses and `.onion` names need no pin: the address is the key
(the destination the router returns for a b32 is still checked against it).

What this does NOT authenticate: the FIRST contact with a name (TOFU), and
anything about the server's software. SCRAM-only authentication
(transport._apply_tls_policy) covers the first contact: a substituted server
never receives the password, only a SCRAM proof -- which still allows an
offline guessing attack on a weak password.

Public data only (names and destination hashes), stored beside the other
Python state and destroyed by Wipe & Exit with it.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import threading
import time
from typing import Dict, Optional

__all__ = ["b32_of_destination", "ServerPins", "DestinationChanged",
           "MATCH", "NEW", "CHANGED", "default_store"]

MATCH, NEW, CHANGED = "match", "new", "changed"


def b32_of_destination(dest_b64: str) -> str:
    """The `.b32.i2p` address of a full destination (I2P base64).

    I2P base64 uses '-' and '~' for '+' and '/'. The b32 address is the
    base32 of SHA-256 over the destination's bytes -- a public identifier
    hash, not a secret operation.
    """
    text = (dest_b64 or "").strip()
    if not text:
        raise ValueError("empty destination")
    raw = base64.b64decode(text.replace("-", "+").replace("~", "/") +
                           "=" * (-len(text) % 4), validate=True)
    digest = hashlib.sha256(raw).digest()
    return base64.b32encode(digest).decode("ascii").lower().rstrip("=") + ".b32.i2p"


class DestinationChanged(Exception):
    """A pinned name now resolves to another destination. Carries both."""

    def __init__(self, name: str, pinned: str, seen: str):
        super().__init__("%s: destination changed" % name)
        self.name, self.pinned, self.seen = name, pinned, seen


class ServerPins:
    """name -> pinned b32, persisted as JSON. Thread-safe."""

    def __init__(self, path: Optional[str]):
        self._path = path
        self._lock = threading.Lock()
        self._pins: Dict[str, Dict[str, object]] = {}
        #: name -> b32 seen on an attempt not yet known to have succeeded.
        self._pending: Dict[str, str] = {}
        #: name -> b32 the user explicitly approved after a change.
        self._approved: Dict[str, str] = {}
        #: name -> (pinned, seen) for the last refused change, so the UI can
        #: show both and approve exactly the one that was refused.
        self._changes: Dict[str, tuple] = {}
        self._load()

    # -- persistence ---------------------------------------------------------

    def _load(self) -> None:
        if not self._path or not os.path.exists(self._path):
            return
        try:
            with open(self._path, encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                self._pins = {str(k).lower(): v for k, v in data.items()
                              if isinstance(v, dict) and "b32" in v}
        except (OSError, ValueError):
            # Unreadable: fail CLOSED for names we can no longer vouch for by
            # keeping nothing -- the next contact is a first contact again,
            # which SCRAM-only still protects. Never silently "match".
            self._pins = {}

    def _save(self) -> None:
        if not self._path:
            return
        os.makedirs(os.path.dirname(self._path), exist_ok=True)
        tmp = self._path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(self._pins, f, sort_keys=True)
        os.replace(tmp, self._path)

    # -- the rule ------------------------------------------------------------

    def pinned(self, name: str) -> Optional[str]:
        with self._lock:
            entry = self._pins.get(name.lower())
            return str(entry["b32"]) if entry else None

    def check(self, name: str, b32: str) -> str:
        """MATCH, NEW or CHANGED. Never changes a pin by itself."""
        name, b32 = name.lower(), b32.lower()
        with self._lock:
            entry = self._pins.get(name)
            if entry is None:
                self._pending[name] = b32
                return NEW
            if entry["b32"] == b32:
                return MATCH
            if self._approved.get(name) == b32:
                self._pending[name] = b32
                return MATCH
            self._changes[name] = (str(entry["b32"]), b32)
            return CHANGED

    def verify(self, name: str, b32: str) -> None:
        """Raise DestinationChanged unless `b32` may be used for `name`."""
        if self.check(name, b32) == CHANGED:
            raise DestinationChanged(name, self.pinned(name) or "", b32)

    def confirm(self, name: str) -> Optional[str]:
        """The attempt reached the server and it answered as that account's
        server (authenticated, or registration answered): pin what was seen.
        Returns the pinned b32, or None if nothing was pending."""
        name = name.lower()
        with self._lock:
            b32 = self._pending.pop(name, None)
            if b32 is None:
                return None
            entry = self._pins.get(name)
            if entry is not None and entry["b32"] != b32 \
                    and self._approved.get(name) != b32:
                return None             # never overwrite without approval
            self._pins[name] = {"b32": b32, "since": int(time.time())}
            self._approved.pop(name, None)
            self._changes.pop(name, None)
            self._save()
            return b32

    def last_change(self, name: str) -> Optional[tuple]:
        """(pinned, seen) of the last refused change for `name`, or None."""
        with self._lock:
            return self._changes.get(name.lower())

    def approve(self, name: str, b32: str) -> None:
        """The user explicitly trusts THIS new destination for `name`. Takes
        effect on the next attempt, and becomes the pin when it succeeds.

        Only the destination that was actually refused and shown to the user
        can be approved: an approval is an answer to a warning, not a way to
        set a pin to an arbitrary value."""
        name, b32 = name.lower(), b32.lower().strip()
        if not b32.endswith(".b32.i2p") or len(b32) != 60:
            raise ValueError("not a .b32.i2p address")
        with self._lock:
            change = self._changes.get(name)
            if change is None or change[1] != b32:
                raise ValueError("that destination was not the one refused "
                                 "for this server")
            self._approved[name] = b32

    def forget(self) -> None:
        with self._lock:
            self._pins.clear()
            self._pending.clear()
            self._approved.clear()
            self._changes.clear()
            if self._path and os.path.exists(self._path):
                os.remove(self._path)


_DEFAULT: Optional[ServerPins] = None
_DEFAULT_LOCK = threading.Lock()


def default_store() -> ServerPins:
    """The process-wide store under the Python home (~/.otrv4plus)."""
    global _DEFAULT
    with _DEFAULT_LOCK:
        if _DEFAULT is None:
            _DEFAULT = ServerPins(os.path.join(
                os.path.expanduser("~"), ".otrv4plus", "server_pins.json"))
        return _DEFAULT
