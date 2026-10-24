# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""What every part of OtrApp shares: its error, its redacting log, message ids.

OtrApp (app.py) is built from mixins in app_*.py; they import these from
here rather than from app.py, which imports them. app.py re-exports them.
"""
from __future__ import annotations

import logging


def _new_message_id() -> str:
    import uuid
    return uuid.uuid4().hex


class BridgeError(RuntimeError):
    """A bridge-level failure.  Carries a code, never engine exception text."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(code)
        self.code = code
        self.detail = detail


class _RedactingFilter(logging.Filter):
    """Drops any record that could carry sensitive material.

    The bridge logs identifiers, enum names and counts.  It never logs message
    bodies, SMP secrets, seeds, or key material.  Rather than trusting every
    future call site to remember that, this filter refuses records carrying a
    `sensitive` marker and truncates everything else.

    This is defence in depth, not the primary control: the primary control is
    that no call site in this package passes such values to the logger at all,
    which tests/test_android_bridge.py asserts directly.
    """

    MAX = 200

    def filter(self, record: logging.LogRecord) -> bool:
        if getattr(record, "sensitive", False):
            return False
        try:
            msg = record.getMessage()
        except Exception:
            return False
        if len(msg) > self.MAX:
            record.msg = msg[: self.MAX] + "...<truncated>"
            record.args = ()
        return True


def redacting_logger(name: str = "otrv4plus.bridge") -> logging.Logger:
    """A logger safe for the bridge to use.

    On Android the release build should attach no handler at all; this exists so
    development builds have something structured, and so the filter is present
    even if a handler is attached later.
    """
    log = logging.getLogger(name)
    if not any(isinstance(f, _RedactingFilter) for f in log.filters):
        log.addFilter(_RedactingFilter())
    return log


_log = redacting_logger()
