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

__all__ = ["check_destination", "ensure_pins_usable", "b32_of_destination", "ServerPins",
           "DestinationChanged", "PinsUnreadable", "MATCH", "NEW", "CHANGED", "default_store"]

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


class PinsUnreadable(Exception):
    """The pins file is there and will not open, will not parse, or is not
    the shape pins have (X1 residual 5, closed 2026-10-27). Refused, never
    replaced: read as empty, the next connection to a changed destination
    would be a first visit. Carries the file and why."""

    def __init__(self, path: str, reason: str):
        super().__init__("%s: server pins unreadable (%s)" % (path, reason))
        self.path, self.reason = path, reason


def ensure_pins_usable(host: str, store: "ServerPins", *,
                       shipped: Optional[str], self_authenticating: bool) -> None:
    """Before any byte goes to the router: raise PinsUnreadable if the
    connection to [host] would consult the pins and they will not open.

    A shipped address and a typed .b32.i2p never consult the pins (their
    check is the address itself, `check_destination`), so an unreadable file
    cannot weaken them, and they proceed. Every other name is refused until
    the user moves the file aside or fixes it."""
    if shipped or self_authenticating:
        return
    store.ensure_usable()


def check_destination(host: str, seen: str, store: "ServerPins", *,
                      shipped: Optional[str], self_authenticating: bool) -> str:
    """X1's rule for one resolved destination, for a client without the
    bridge's transport (the terminal client). Raises DestinationChanged, or
    returns why `seen` may be used: "shipped address", "b32 address",
    "pinned" or "first use".

    The same order as XmppTransport._verify_destination, and
    tests/test_x1_terminal_client.py runs both over the same cases:
      * a name this version ships an address for is checked against that
        address, and no pin is consulted;
      * a typed .b32.i2p is its key hash, so the router must return the
        destination that hashes to it;
      * any other name is pinned on first use and refused if it changes.
    """
    host, seen = (host or "").strip().lower(), (seen or "").strip().lower()
    if shipped:
        if seen != shipped.lower():
            raise DestinationChanged(host, shipped.lower(), seen)
        return "shipped address"
    if self_authenticating:
        if seen != host:
            raise DestinationChanged(host, host, seen)
        return "b32 address"
    verdict = store.check(host, seen)
    if verdict == CHANGED:
        raise DestinationChanged(host, store.pinned(host) or "", seen)
    return "pinned" if verdict == MATCH else "first use"


#: A sealed pins file: magic || nonce(12) || AES-256-GCM(json) || tag.
SEALED_MAGIC = b"OTRVSP1\x00"
_AAD = b"otrv4plus/server_pins/v1"


class ServerPins:
    """name -> pinned b32, persisted as JSON. Thread-safe.

    With [dek_path] the JSON is sealed under a Rust `FileDek` in that key
    file -- itself wrapped by the key-store KEK where there is one
    (`key_custody`), so Wipe & Exit's crypto-erase covers the pins too. A
    plaintext file from before is read once and rewritten sealed.
    """

    def __init__(self, path: Optional[str], dek_path: Optional[str] = None):
        self._path = path
        self._dek_path = dek_path
        self._lock = threading.Lock()
        self._pins: Dict[str, Dict[str, object]] = {}
        #: name -> b32 seen on an attempt not yet known to have succeeded.
        self._pending: Dict[str, str] = {}
        #: name -> b32 the user explicitly approved after a change.
        self._approved: Dict[str, str] = {}
        #: name -> (pinned, seen) for the last refused change, so the UI can
        #: show both and approve exactly the one that was refused.
        self._changes: Dict[str, tuple] = {}
        #: Why the file will not open, while it will not; None when usable.
        self._unreadable: Optional[str] = None
        self._load()

    # -- persistence ---------------------------------------------------------

    def _load(self) -> None:
        """A missing file is a first run. A file that is there and will not
        open, will not parse, or is not the shape pins have is REFUSED, never
        read as empty and never rewritten (P1's rule): `ensure_usable` and
        `check` raise PinsUnreadable, and the file is read again at the next
        attempt, after the user has moved it aside or fixed it."""
        self._pins, self._unreadable = {}, None
        if not self._path or not os.path.exists(self._path):
            return
        legacy = False
        try:
            with open(self._path, "rb") as f:
                raw = f.read()
            if raw.startswith(SEALED_MAGIC):
                if not self._dek_path:
                    raise ValueError("sealed pins file and no key file")
                raw = self._dek().open(raw[8:20], raw[20:], _AAD)
            else:
                legacy = bool(self._dek_path)
            self._pins = _validated(json.loads(bytes(raw).decode("utf-8")))
        except Exception as exc:        # a Rust open failure is not an OSError
            self._unreadable = ("not a pins file: %s" % exc if isinstance(exc, _NotPins)
                                else exc.__class__.__name__)
            return
        if legacy:
            self._save()                # rewritten sealed, once

    def _dek(self):
        import otrv4_core
        return otrv4_core.FileDek.load_or_create(self._dek_path)

    def _save(self) -> None:
        if not self._path or self._unreadable is not None:
            return                      # never write over a file that would not open
        os.makedirs(os.path.dirname(self._path), exist_ok=True)
        tmp = self._path + ".tmp"
        data = json.dumps(self._pins, sort_keys=True).encode("utf-8")
        if self._dek_path:
            nonce = os.urandom(12)
            data = SEALED_MAGIC + nonce + bytes(self._dek().seal(nonce, data, _AAD))
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self._path)

    def unreadable(self) -> Optional[str]:
        """Why the pins file will not open, read again now; None if usable."""
        with self._lock:
            if self._unreadable is not None:
                self._load()
            return self._unreadable

    def ensure_usable(self) -> None:
        """Raise PinsUnreadable while the file will not open."""
        reason = self.unreadable()
        if reason is not None:
            raise PinsUnreadable(self._path or "", reason)

    @property
    def path(self) -> Optional[str]:
        return self._path

    # -- the rule ------------------------------------------------------------

    def pinned(self, name: str) -> Optional[str]:
        with self._lock:
            entry = self._pins.get(name.lower())
            return str(entry["b32"]) if entry else None

    def check(self, name: str, b32: str) -> str:
        """MATCH, NEW or CHANGED. Never changes a pin by itself. Raises
        PinsUnreadable while the file will not open: never NEW for a name
        whose pin could not be read."""
        self.ensure_usable()
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
            if self._unreadable is not None:
                return None             # nothing is pinned over an unreadable file
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
        if self.unreadable() is not None:
            raise ValueError("the pins file would not open; move it aside first")
        with self._lock:
            change = self._changes.get(name)
            if change is None or change[1] != b32:
                raise ValueError("that destination was not the one refused "
                                 "for this server")
            self._approved[name] = b32

    def forget(self) -> None:
        """Wipe & Exit: the user destroys every pin, a file that would not
        open included."""
        with self._lock:
            self._unreadable = None
            self._pins.clear()
            self._pending.clear()
            self._approved.clear()
            self._changes.clear()
            for p in (self._path, self._dek_path):
                if p and os.path.exists(p):
                    os.remove(p)


class _NotPins(ValueError):
    """Valid JSON, but not the shape the pins file has."""


def _validated(data) -> Dict[str, Dict[str, object]]:
    """The pins in [data], or _NotPins: a table of server name -> {"b32": a
    .b32.i2p address, optionally "since": seconds}. Nothing is dropped
    quietly: one malformed entry refuses the file."""
    if not isinstance(data, dict):
        raise _NotPins("not a table")
    pins = {}
    for name, entry in data.items():
        b32 = entry.get("b32") if isinstance(entry, dict) else None
        if not (isinstance(name, str) and name.strip()
                and isinstance(b32, str) and b32.endswith(".b32.i2p") and len(b32) == 60):
            raise _NotPins("an entry is not a pin")
        since = entry.get("since", 0)
        if isinstance(since, bool) or not isinstance(since, int):
            raise _NotPins("an entry is not a pin")
        pins[name.lower()] = dict(entry)
    return pins


_DEFAULT: Optional[ServerPins] = None
_DEFAULT_LOCK = threading.Lock()


def default_store() -> ServerPins:
    """The process-wide store under the Python home (~/.otrv4plus)."""
    global _DEFAULT
    with _DEFAULT_LOCK:
        if _DEFAULT is None:
            home = os.path.join(os.path.expanduser("~"), ".otrv4plus")
            _DEFAULT = ServerPins(os.path.join(home, "server_pins.json"),
                                  dek_path=os.path.join(home, "server_pins.dek"))
        return _DEFAULT
