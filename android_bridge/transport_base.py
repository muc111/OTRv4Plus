# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""What every part of the XMPP transport shares: its error, its timeouts and
its log.

XmppTransport (transport.py) is built from mixins in transport_*.py; they
import these from here rather than from transport.py, which imports them.
transport.py re-exports all four.
"""
import logging

_log = logging.getLogger("otrv4plus.bridge.transport")

#: How long a blocking call waits on the loop thread before giving up. Not the
#: same thing as the SAM timeouts: those are how long a tunnel may take to
#: build (SAM_CONNECT_TIMEOUT is 240s), and this has to be larger or a cold
#: tunnel would be reported as a failed connection while it was still working.
#: The number is deliberately generous; the UI shows progress, not a stopwatch.
CONNECT_TIMEOUT = 300.0
CALL_TIMEOUT = 30.0


class TransportError(RuntimeError):
    """The transport could not do what was asked.

    Carries a short stable `code` for the UI to branch on and a `detail` for a
    human. The detail never contains the password -- it is built from exception
    types and our own strings, never from the credential.
    """

    def __init__(self, code: str, detail: str = ""):
        super().__init__(detail or code)
        self.code = code
        self.detail = detail
