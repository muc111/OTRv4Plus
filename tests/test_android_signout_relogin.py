# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Signing in again right after Sign out (device report, 2026-10-24).

The account was signed in on a second phone, so the server replaced the
first phone's session (one session per account, newest wins). On the first
phone the user signed out and signed in again, and it never connected.

Two defects, both in OtrConnectionService:

1. Sign out's teardown runs in the background (disconnect, then the built-in
   router). A sign-in in that window found the old router alive and used it;
   the teardown then stopped it under the new attempt and marked the link
   STOPPED. A new connection now waits for the teardown first.
2. Sign out shuts the engine down; the bound service kept `initialised`
   true, so every later attempt failed `not_initialized`. The engine's own
   state is checked now, and Sign out clears the flag.
"""
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PKG = os.path.join(ROOT, "android", "app", "src", "main", "java", "org", "otrv4plus", "android")
SERVICE = open(os.path.join(PKG, "connection", "OtrConnectionService.kt"), encoding="utf-8").read()
CORE = open(os.path.join(PKG, "bridge", "ChaquopyOtrCore.kt"), encoding="utf-8").read()


def _body(text, signature):
    start = text.index(signature)
    i = text.index("{", start)
    depth = 0
    for j in range(i, len(text)):
        depth += {"{": 1, "}": -1}.get(text[j], 0)
        if depth == 0:
            return text[i:j + 1]
    raise AssertionError(signature)


def test_a_new_connection_waits_for_the_previous_teardown():
    loop = _body(SERVICE, "private suspend fun connectLoop()")
    assert loop.index("pendingTeardown?.join()") < loop.index("while (scope.isActive)")


def test_every_teardown_is_recorded_for_it_to_wait_on():
    stop = _body(SERVICE, "fun stopConnection(")
    assert "pendingTeardown = teardown.launch" in stop
    assert "router.stop()" in stop[stop.index("pendingTeardown = teardown.launch"):]
    logout = SERVICE[SERVICE.index("ACTION_LOGOUT ->"):SERVICE.index("ACTION_START ->")]
    assert "pendingTeardown = teardown.launch" in logout
    assert logout.index("stopping?.join()") < logout.index("core.shutdown()"), \
        "the engine goes after the connection, in order"
    assert "teardown.launch {" not in SERVICE.replace("pendingTeardown = teardown.launch {", ""), \
        "no teardown a new sign-in would not wait for"


def test_the_engine_is_reinitialised_after_sign_out():
    assert "val isInitialized: Boolean get() = app != null" in CORE
    loop = _body(SERVICE, "private suspend fun connectLoop()")
    assert "!initialised || !core.isInitialized" in loop
    logout = SERVICE[SERVICE.index("ACTION_LOGOUT ->"):SERVICE.index("ACTION_START ->")]
    assert "initialised = false" in logout


def test_being_replaced_by_another_device_stops_reconnecting():
    # The first half of the report is by design: newest session wins, and
    # reconnecting would throw the other phone out in turn.
    transport = open(os.path.join(ROOT, "android_bridge", "transport.py"), encoding="utf-8").read()
    assert 'if cond == "conflict":\n            self._replaced = True' in transport
