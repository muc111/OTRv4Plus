# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Where the desktop's key-wrapping key lives, so Wipe & Exit can destroy it.

Every key file under ~/.otrv4plus (identity, trust, groups, received files,
SMP seed) is wrapped by one 256-bit key-encryption key (KEK) while it is
installed in Rust (`otrv4_core.set_key_wrapping_key`, Rust/src/at_rest.rs).
The KEK is generated here from the kernel CSPRNG and kept in the platform's
key store, never in a file of ours. Wipe & Exit deletes it from the key
store first: after that no wrapped key file opens, so nothing sealed under
them does, whatever an SSD's wear levelling kept. That is cryptographic
erase, the purge NIST SP 800-88 gives for flash.

HOW STRONG "DELETED" IS depends on the key store, and `status()` says which:

  * "keyring"  -- Linux Secret Service (GNOME Keyring, KWallet) or the macOS
    login Keychain. The store is itself a file encrypted under the login
    password: an old copy could survive on flash, and someone holding that
    copy AND the login password could recover the KEK.
  * "none"     -- no key store reachable (no keyring daemon, Windows for now,
    Android and Termux, which have their own story). Key files stay plain,
    exactly as before, and the wipe says crypto-erase was not available.

Hardware-backed stores (TPM 2.0, Secure Enclave, Windows CNG/TPM) are the
next tier and are not implemented yet; nothing here claims them.

The KEK crosses Python once, as a `bytearray` that Rust copies and zeroes.
The key-store tools are always given it on stdin, never on a command line
another process could read.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from typing import Callable, List, Optional, Sequence

__all__ = ["Backend", "SecretToolBackend", "MacKeychainBackend", "choose",
           "install", "destroy", "status"]

SERVICE = "otrv4plus"
ACCOUNT = "key-wrapping-key"
KEK_LEN = 32

# (argv, stdin bytes) -> (returncode, stdout bytes)
Runner = Callable[[Sequence[str], Optional[bytes]], "tuple[int, bytes]"]


def _run(argv: Sequence[str], stdin: Optional[bytes] = None):
    try:
        p = subprocess.run(list(argv), input=stdin, capture_output=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return 127, b""
    return p.returncode, p.stdout


def _parse_hex_kek(out: bytes) -> Optional[bytearray]:
    text = out.strip()
    if len(text) != 2 * KEK_LEN:
        return None
    try:
        return bytearray.fromhex(text.decode("ascii"))
    except (ValueError, UnicodeDecodeError):
        return None


class Backend:
    """One key store. `load` -> the KEK or None; `store`; `delete`."""

    name = "none"
    tier = "none"

    def available(self) -> bool:
        return False

    def load(self) -> Optional[bytearray]:
        return None

    def store(self, kek: bytearray) -> bool:
        return False

    def delete(self) -> bool:
        return True


class SecretToolBackend(Backend):
    """Linux Secret Service through libsecret's `secret-tool`."""

    name = "secret-service"
    tier = "keyring"

    def __init__(self, run: Runner = _run, which=shutil.which):
        self._run, self._which = run, which

    def _attrs(self) -> List[str]:
        return ["service", SERVICE, "account", ACCOUNT]

    def available(self) -> bool:
        if not self._which("secret-tool"):
            return False
        # A lookup that reaches the daemon answers 0 (found) or 1 (absent);
        # anything else means no Secret Service is running.
        code, _ = self._run(["secret-tool", "lookup"] + self._attrs(), None)
        return code in (0, 1)

    def load(self) -> Optional[bytearray]:
        code, out = self._run(["secret-tool", "lookup"] + self._attrs(), None)
        return _parse_hex_kek(out) if code == 0 else None

    def store(self, kek: bytearray) -> bool:
        code, _ = self._run(["secret-tool", "store", "--label=OTRv4+ key-wrapping key"]
                            + self._attrs(), kek.hex().encode("ascii"))
        return code == 0

    def delete(self) -> bool:
        self._run(["secret-tool", "clear"] + self._attrs(), None)
        return self.load() is None


class MacKeychainBackend(Backend):
    """The macOS login Keychain through `security`, commands on stdin."""

    name = "macos-keychain"
    tier = "keyring"

    def __init__(self, run: Runner = _run, which=shutil.which):
        self._run, self._which = run, which

    def available(self) -> bool:
        return sys.platform == "darwin" and bool(self._which("security"))

    def load(self) -> Optional[bytearray]:
        code, out = self._run(["security", "find-generic-password", "-s", SERVICE,
                               "-a", ACCOUNT, "-w"], None)
        return _parse_hex_kek(out) if code == 0 else None

    def store(self, kek: bytearray) -> bool:
        # `security -i` reads commands from stdin, so the key is never on argv.
        line = "add-generic-password -U -s %s -a %s -w %s\n" % (SERVICE, ACCOUNT, kek.hex())
        code, _ = self._run(["security", "-i"], line.encode("ascii"))
        return code == 0

    def delete(self) -> bool:
        self._run(["security", "delete-generic-password", "-s", SERVICE, "-a", ACCOUNT], None)
        return self.load() is None


def candidates() -> List[Backend]:
    return [MacKeychainBackend(), SecretToolBackend()]


def choose(backends: Optional[List[Backend]] = None) -> Backend:
    """The first key store that answers, or the no-store backend."""
    for b in candidates() if backends is None else backends:
        try:
            if b.available():
                return b
        except Exception:
            continue
    return Backend()


_STATE = {"backend": None, "installed": False}


def install(backend: Optional[Backend] = None, core=None) -> dict:
    """Load the KEK from the key store (creating it on first run) and hand it
    to Rust. Never raises: without a store the key files stay plain, and the
    status says so."""
    if core is None:
        import otrv4_core as core
    b = backend if backend is not None else choose()
    _STATE["backend"], _STATE["installed"] = b, False
    if b.tier == "none":
        return status()
    kek = b.load()
    if kek is None:
        kek = bytearray(os.urandom(KEK_LEN))
        stored = b.store(kek)
        check = b.load() if stored else None
        if check is None or check != kek:
            # Never wrap under a key the store did not keep: the key files
            # would be lost at the next start.
            kek[:] = bytes(len(kek))
            if check is not None:
                check[:] = bytes(len(check))
            return status()
        check[:] = bytes(len(check))
    core.set_key_wrapping_key(kek)        # copies, and zeroes the bytearray
    _STATE["installed"] = True
    return status()


def destroy(core=None) -> dict:
    """Wipe & Exit, first: delete the KEK from the key store and from Rust.
    `crypto_erased` is True only if the store confirms it is gone."""
    if core is None:
        import otrv4_core as core
    b = _STATE["backend"] or Backend()
    try:
        gone = bool(b.delete())
    except Exception:
        gone = False
    try:
        core.clear_key_wrapping_key()
    except Exception:
        pass
    erased = bool(_STATE["installed"]) and gone
    _STATE["installed"] = False
    return {"key_store": b.name, "key_store_tier": b.tier, "crypto_erased": erased}


def status() -> dict:
    b = _STATE["backend"] or Backend()
    return {"key_store": b.name, "key_store_tier": b.tier,
            "key_wrapping": bool(_STATE["installed"])}
