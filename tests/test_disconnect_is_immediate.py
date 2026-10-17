# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Sign out shows at once (owner report, 2026-10-16), and only the
deliberate ends stop the built-in router.

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
    body = src[src.index("fun stopConnection(explicit: Boolean"):]
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
    assert "stopConnection(explicit = true, stopRouter = true)" in logout


def test_only_sign_out_wipe_closing_and_stop_take_the_router():
    """rc.100: no Disconnect; the built-in router stays warm between
    connections, because one started cold cannot be reached for minutes."""
    src = open(SERVICE).read()
    body = _stop_connection()
    assert "if (stopRouter) {" in body
    assert "fun stopConnection(explicit: Boolean, stopRouter: Boolean = false)" in body
    destroy = src[src.index("override fun onDestroy()"):]
    destroy = destroy[:destroy.index("super.onDestroy()")]
    assert "stopConnection(explicit = true, stopRouter = true)" in destroy
    stop = src[src.index("ACTION_STOP ->"):src.index("ACTION_LOGOUT ->")]
    assert "stopRouter = !keepRouter" in stop
    vm = open(os.path.join(ROOT, "android/app/src/main/java/org/otrv4plus/"
                           "android/ConnectionViewModel.kt")).read()
    assert "fun disconnect()" not in vm
    cancel = vm[vm.index("fun cancelConnect()"):]
    assert "keepRouter = true" in cancel[:cancel.index("}")]


def test_a_lost_router_is_restarted_from_the_failure_path():
    src = open(SERVICE).read()
    loop = src[src.index("private suspend fun connectLoop()"):]
    loop = loop[:loop.index("val wait = (if (ConnectProblem.settling(")]
    assert "restartRouterIfLost(failure)" in loop
    fn = src[src.index("private fun restartRouterIfLost("):]
    fn = fn[:fn.index("\n    }\n")]
    assert "RouterChoice.shouldRestart(" in fn
    assert "routerState != RouterChoice.State.RUNNING" in fn   # ours only


def test_the_connection_is_timed_from_start_or_drop_to_signed_in():
    src = open(SERVICE).read()
    start = src[src.index("fun startConnection()"):]
    start = start[:start.index("worker = scope.launch { connectLoop() }")]
    assert "startTiming()" in start
    watch = src[src.index("private suspend fun watchUntilDropped"):]
    watch = watch[:watch.index("private fun codeOf")]
    assert "startTiming()" in watch
    loop = src[src.index("private suspend fun connectLoop()"):]
    ok = loop[loop.index("if (ok) {"):loop.index("reconnect.onConnected()")]
    assert "lastConnectTiming = ConnectTiming.Result(" in ok
    screen = open(os.path.join(ROOT, "android/app/src/main/java/org/otrv4plus/"
                               "android/ui/ConnectScreen.kt")).read()
    assert 'StatusRow("Connected in"' in screen


def test_a_settling_router_is_retried_soon():
    src = open(SERVICE).read()
    loop = src[src.index("private suspend fun connectLoop()"):]
    loop = loop[:loop.index("private suspend fun watchUntilDropped")] if "private suspend fun watchUntilDropped" in loop else loop
    assert "ConnectProblem.settling(failure, bundledRouterUpMs())" in loop
    assert "reconnect.settlingDelayMs()" in loop
