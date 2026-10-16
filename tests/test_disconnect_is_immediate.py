# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Disconnect and Sign out show at once (owner report, 2026-10-16).

The screens read the service's `status`. A disconnect tore the connection
down on a background thread -- up to ~15 s over I2P: the stream, the SAM
session, the bundled router -- and never wrote `status` again, so the screen
kept saying connected and both buttons seemed to do nothing.
"""

import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVICE = os.path.join(ROOT, "android/app/src/main/java/org/otrv4plus/android/"
                       "connection/OtrConnectionService.kt")


def _stop_connection() -> str:
    src = open(SERVICE).read()
    body = src[src.index("fun stopConnection(explicit: Boolean)"):]
    return body[:body.index("private suspend fun connectLoop")]


def test_the_status_says_not_connected_before_the_teardown_starts():
    body = _stop_connection()
    marked = body.index("status = status.copy(connected = false")
    assert marked < body.index("teardown.launch")


def test_the_teardowns_result_is_what_the_screen_reads_after():
    body = _stop_connection()
    after = body[body.index("teardown.launch"):]
    assert "core.disconnect() }.getOrNull()?.let" in after
    # ...unless a new attempt began while it ran.
    assert "phase == LinkPhase.DISCONNECTING" in after


def test_sign_out_goes_through_the_same_path():
    src = open(SERVICE).read()
    logout = src[src.index("ACTION_LOGOUT ->"):]
    logout = logout[:logout.index("credentials.clear()")]
    assert "stopConnection(explicit = true)" in logout
