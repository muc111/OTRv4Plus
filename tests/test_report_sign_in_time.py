# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The diagnostic report says how long the last sign-in took.

Owner, 2026-10-28: the summary showed CONNECTED at 00:25 (the clock time),
while the sign-in with the built-in router had taken over two minutes. The
service now notes `connect_timing` (ConnectTiming.note), and the report
splits it into the router, the I2P tunnels and the server login.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "client"))

from android_bridge import report                                # noqa: E402
from android_bridge.connection import ConnectionController       # noqa: E402
from android_bridge.trace import TraceLog                        # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "..")
T0 = 1_800_000_000.0


def _run(router_ms=110_000, attempts=1, total_ms=145_000, steps=True,
         register_ms=0):
    """A sign-in as the phone records it: router, tunnels, login, note."""
    log = TraceLog()
    end = T0 + total_ms / 1000.0
    log.record_at(T0 + 1, "service", "phase_change", detail="STOPPED -> CONNECTING")
    if steps:
        log.record_at(end - 35, "connection", "sam_opening")
        log.record_at(end - 30, "connection", "sam_established")
        log.record_at(end - 15, "connection", "tunnel_open")
        log.record_at(end - 10, "connection", "tls")
        log.record_at(end - 5, "connection", "signed_in")
    log.record_at(end, "service", "connect_timing",
                  detail="total_ms=%d router_ms=%d attempts=%d register_ms=%d"
                  % (total_ms, router_ms, attempts, register_ms))
    return log


class TestSignInTime:

    def test_the_whole_wait_is_split_into_router_tunnels_and_login(self):
        assert report.connect_time(_run()) == (
            "2:25 (I2P router 1:50, tunnels 0:20, server login 0:15), 1 attempt")

    def test_what_the_parts_leave_is_shown_so_they_add_up(self):
        line = report.connect_time(_run(router_ms=60_000, attempts=3))
        assert line == ("2:25 (I2P router 1:00, tunnels 0:20, server login 0:15, "
                        "retries and waiting 0:50), 3 attempts")

    def test_create_account_first_is_counted_from_its_tap(self):
        """Owner, 2026-10-28: after Create account the duration was not
        accurate -- the sign-in's clock started after the router had booted
        for the account. The whole run is now one wait."""
        line = report.connect_time(_run(total_ms=225_000, register_ms=80_000))
        assert line == ("3:45 (I2P router 1:50, creating the account 1:20, "
                        "tunnels 0:20, server login 0:15), 1 attempt")

    def test_without_the_router_or_steps_only_the_total(self):
        assert report.connect_time(_run(router_ms=0, steps=False)) == "2:25, 1 attempt"

    def test_no_sign_in_yet_says_nothing(self):
        log = TraceLog()
        log.record("connection", "sam_opening")
        assert report.connect_time(log) is None

    def test_the_summary_and_the_full_report_carry_it(self):
        log = _run()
        line = "2:25 (I2P router 1:50, tunnels 0:20, server login 0:15), 1 attempt"
        assert "took    " + line in report.summary({"stage": "connected"}, trace=log)
        full = report.build({"stage": "connected"}, trace=log)
        assert "Last sign-in" in full and line in full

    def test_the_note_survives_the_trace_and_the_controller(self):
        """The note goes through `ConnectionController.note` and the trace's
        redaction unchanged: a redacted detail would leave no timing."""
        log = TraceLog()
        import android_bridge.connection as connection
        old = connection._TRACE
        connection._TRACE = log
        try:
            ConnectionController.note(None, "service", "connect_timing", "info",
                                      "total_ms=145000 router_ms=110000 attempts=1",
                                      T0)
        finally:
            connection._TRACE = old
        assert report.connect_time(log) == (
            "2:25 (I2P router 1:50, sign-in 0:35), 1 attempt")


class TestTheServiceNotesIt:

    def test_the_service_notes_the_timing_when_it_connects(self):
        src = open(os.path.join(ROOT, "android/app/src/main/java/org/otrv4plus/"
                                "android/connection/OtrConnectionService.kt")).read()
        ok = src[src.index("lastConnectTiming = ConnectTiming.Result("):]
        ok = ok[:ok.index('enter(LinkPhase.CONNECTED')]
        assert 'core.note("service", "connect_timing", "info"' in ok
        assert "ConnectTiming.note(timing)" in ok
        assert "registerMs = registerMs" in src

    def test_create_account_does_not_restart_the_clock(self):
        src = open(os.path.join(ROOT, "android/app/src/main/java/org/otrv4plus/"
                                "android/connection/OtrConnectionService.kt")).read()
        reg = src[src.index("private fun startRegistration()"):]
        reg = reg[:reg.index("private suspend fun registerWhenReachable")]
        assert reg.index("startTiming()") < reg.index("scope.launch")
        assert reg.index("afterRegistration = true") < reg.index("startConnection()")
        start = src[src.index("fun startConnection()"):]
        start = start[:start.index("worker = scope.launch { connectLoop() }")]
        assert "if (!afterRegistration) startTiming()" in start
        assert "afterRegistration = false" in start
        when = src[src.index("private suspend fun registerWhenReachable"):]
        when = when[:when.index("delay(RegisterRetry")]
        assert when.index("chooseRouter()") < when.index("routerWaited(routerFrom)")

    def test_a_router_still_joining_is_counted(self):
        src = open(os.path.join(ROOT, "android/app/src/main/java/org/otrv4plus/"
                                "android/connection/OtrConnectionService.kt")).read()
        timed = src[src.index("private fun routerWaited(from: Long)"):]
        timed = timed[:timed.index("\n    }\n")]
        assert "RouterChoice.State.JOINING" in timed


def test_the_build_with_the_timing_is_told_apart_from_rc_187():
    gradle = open(os.path.join(ROOT, "android/app/build.gradle.kts")).read()
    code = int(__import__("re").search(r"versionCode = (\d+)", gradle).group(1))
    assert code >= 189
