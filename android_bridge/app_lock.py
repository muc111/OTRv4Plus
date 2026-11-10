# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The app lock, as Kotlin calls it through Chaquopy.

A thin pass-through to `otrv4_core.app_lock_*` (Rust/src/app_lock.rs), which
makes, wraps and holds the 256-bit data key. Design and audit:
docs/APP_LOCK_PASSPHRASE.md.

THE ONE RULE HERE: a secret is never turned into `bytes` or `str`. Kotlin
hands over its passphrase bytes and the key store's HMAC as Java `byte[]`
(a Chaquopy `jarray`); they are copied straight into a `bytearray`, which
Rust copies and then zeroes, and Kotlin zeroes its own array. An immutable
`bytes` copy would sit in Python's heap with no way to wipe it.

Nothing secret is logged or traced. What is traced is that the lock was
set up, opened, refused, changed or closed.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from .trace import TRACE as _TRACE

#: The Argon2id cost new records are made with: t=3, 64 MiB, 4 lanes (the
#: desktop engine's, and the design's starting point). Stored in each record,
#: so a calibrated cost later still opens older records (finding F4).
DEFAULT_COST = {"t": 3, "m_kib": 64 * 1024, "p": 4}


class AppLocked(RuntimeError):
    """The data key is not loaded: nothing sealed can be read or written."""


def _core():
    import otrv4_core
    return otrv4_core


def _secret(value: Any) -> Optional[bytearray]:
    """[value] as a fresh bytearray, without an immutable copy on the way."""
    if value is None:
        return None
    if isinstance(value, bytearray):
        return value
    try:
        return bytearray(memoryview(value))         # buffer protocol: no bytes copy
    except TypeError:
        out = bytearray(len(value))
        for i, v in enumerate(value):              # Java bytes are signed
            out[i] = int(v) & 0xFF
        return out


def new_salt() -> bytes:
    """A fresh public salt for a new record (Kotlin HMACs it in the key store)."""
    return bytes(_core().app_lock_new_salt())


def record_info(record) -> Dict[str, Any]:
    """The record's public header: mode, salt, Argon2id cost."""
    return dict(_core().app_lock_record_info(bytes(record)))


def enrol(passphrase, hw, salt, t: int = DEFAULT_COST["t"],
          m_kib: int = DEFAULT_COST["m_kib"], p: int = DEFAULT_COST["p"]) -> bytes:
    """Make the data key; returns the record to store. Nothing uses the key
    until `commit()`, called once the record is safely on disk.
    `passphrase` None makes a device-only record."""
    pw, h = _secret(passphrase), _secret(hw)
    try:
        record = bytes(_core().app_lock_enrol(pw, h, bytes(salt), int(t), int(m_kib), int(p)))
    finally:
        _wipe(pw, h)
    _TRACE.record("app_lock", "enrolled", "info",
                  mode="passphrase" if passphrase is not None else "device")
    return record


def commit() -> bool:
    """The enrolment record is stored: start using its key."""
    ok = bool(_core().app_lock_commit())
    if ok:
        _TRACE.record("app_lock", "committed", "info")
    return ok


def unlock(passphrase, hw, record) -> bool:
    """Open [record]. False for a wrong passphrase or a damaged record."""
    pw, h = _secret(passphrase), _secret(hw)
    try:
        ok = bool(_core().app_lock_unlock(pw, h, bytes(record)))
    finally:
        _wipe(pw, h)
    _TRACE.record("app_lock", "unlocked" if ok else "unlock_refused",
                  "info" if ok else "warning")
    return ok


def check(passphrase, hw, record) -> bool:
    """Whether [passphrase] opens [record] to the key in use (no change)."""
    pw, h = _secret(passphrase), _secret(hw)
    try:
        return bool(_core().app_lock_check(pw, h, bytes(record)))
    finally:
        _wipe(pw, h)


def rewrap(passphrase, hw, salt, t: int = DEFAULT_COST["t"],
           m_kib: int = DEFAULT_COST["m_kib"], p: int = DEFAULT_COST["p"]) -> bytes:
    """The key in use, wrapped anew (passphrase change, lock on or off)."""
    pw, h = _secret(passphrase), _secret(hw)
    try:
        record = bytes(_core().app_lock_rewrap(pw, h, bytes(salt), int(t), int(m_kib), int(p)))
    finally:
        _wipe(pw, h)
    _TRACE.record("app_lock", "rewrapped", "info",
                  mode="passphrase" if passphrase is not None else "device")
    return record


def lock() -> None:
    """Zeroize the data key and the key-wrapping key it installed."""
    _core().app_lock_lock()
    _TRACE.record("app_lock", "locked", "info")


def unlocked() -> bool:
    return bool(_core().app_lock_unlocked())


def is_sealed(record) -> bool:
    return bool(_core().app_lock_is_sealed(bytes(record)))


def seal(name: str, plaintext) -> bytes:
    """The vault's inner layer for one record. Raises AppLocked."""
    try:
        return bytes(_core().app_lock_seal(name.encode("utf-8"), bytes(plaintext)))
    except RuntimeError as exc:
        if "locked" in str(exc):
            raise AppLocked("the app is locked") from None
        raise


def open_sealed(name: str, record) -> Optional[bytes]:
    """Open a sealed record; None when it does not open. Raises AppLocked."""
    try:
        out = _core().app_lock_open(name.encode("utf-8"), bytes(record))
    except RuntimeError as exc:
        if "locked" in str(exc):
            raise AppLocked("the app is locked") from None
        raise
    return None if out is None else bytes(out)


def _wipe(*buffers: Optional[bytearray]) -> None:
    # Rust zeroes them already; this covers a call that failed before Rust
    # took them (a type or length error).
    for buf in buffers:
        if buf is not None:
            for i in range(len(buf)):
                buf[i] = 0
