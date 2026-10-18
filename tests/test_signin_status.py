# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Gate: the first sign-in with the built-in router never shows an alarm.

rc.82 promised "setting up (2-5 minutes, normal)", never "Connection lost",
while the built-in router builds its first connection. rc.111 (9fe2c9e)
made a young router retry every ~10 s for every ConnectProblem.settling
failure, but ConnectProblem.line stayed quiet only for the narrower
SILENT_SERVER set (rc.98, 356c789): three "peer unreachable" failures in
~30 s then showed "Can't reach the server ... offline" in red.

The behaviour is tested in Kotlin (ConnectProblemTest, run by CI's
:app:testDebugUnitTest). This pytest gate runs first and cheaply: it checks
the rule is still wired the same way in the source, so the regression cannot
come back without one of these assertions failing.
"""
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONN = os.path.join(ROOT, "android", "app", "src", "main", "java", "org",
                    "otrv4plus", "android", "connection")
TEST = os.path.join(ROOT, "android", "app", "src", "test", "java", "org",
                    "otrv4plus", "android", "connection", "ConnectProblemTest.kt")


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _line_body():
    src = _read(os.path.join(CONN, "ConnectProblem.kt"))
    start = src.index("fun line(")
    return src[start:src.index("private fun stillSettingUp(", start)]


def test_settling_is_checked_before_any_error_branch():
    body = _line_body()
    quiet = body.index("if (retrying && settling(code, bundledRouterUpMs))")
    for alarm in ("failuresInARow >= PERSISTENT_AFTER", "Kind.NEEDS_YOU ->",
                  "if (code == SESSION_LIMIT)"):
        assert quiet < body.index(alarm), alarm
    after = body[quiet:quiet + 200]
    assert "Tone.QUIET" in after and "Tone.ERROR" not in after


def test_the_retry_policy_and_the_screen_use_the_same_rule():
    """The service retries fast on exactly ConnectProblem.settling; the
    screen must be quiet on exactly the same set, or the two drift apart
    again (the rc.111 regression)."""
    service = _read(os.path.join(CONN, "OtrConnectionService.kt"))
    assert "ConnectProblem.settling(failure, bundledRouterUpMs())" in service
    assert "settling(code, bundledRouterUpMs)" in _line_body()


def test_the_setting_up_words_carry_no_alarm():
    src = _read(os.path.join(CONN, "ConnectProblem.kt"))
    words = src[src.index("private fun stillSettingUp("):src.index("private fun needsYou(")]
    words += src[src.index("private fun transient("):src.index("private fun persistent(")]
    # (Not "failed": it is part of codes such as i2p_session_failed.)
    for alarm in ("Connection lost", "Can't reach", "offline", "dropped"):
        assert alarm not in words, alarm
    first = _read(os.path.join(CONN, "LoginProgress.kt"))
    first = first[first.index("const val FIRST_CONNECTION"):first.index("const val RECONNECTING")]
    assert "2 to 5 minutes" in first and "Connection lost" not in first


def test_the_kotlin_regression_test_exists():
    kt = _read(TEST)
    assert "fun `the first sign-in with the built-in router is never an alarm`()" in kt
    assert re.search(r'listOf\(0L, 30L, 120L, 299L', kt)
    assert "fun `after the settling window a real failure is said`()" in kt
