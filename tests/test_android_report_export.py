"""The report must be exportable whether or not the start-up succeeded.

The export and copy buttons were written inside `if (!r.ok)`, on the
assumption that a report is something you need when things break. That was
wrong in the way that matters: the first time the stack came up green on a
handset, the buttons vanished, FLAG_SECURE blocked a screenshot, and there was
no way to get the good news off the device at all.

A working run is evidence too. The Python version, the ABI, the Rust core's
symbol count and the self-test results are what close the device gates in
ANDROID_PHASE2_REPORT.md §14, and they are only worth collecting if they can
be sent.

This is a source check rather than a behavioural one, which is a compromise:
exercising Compose properly needs an instrumented test on a device or
emulator, and there is no emulator in CI. It pins the specific regression
rather than the general property.
"""

import os
import re

import pytest

SCREEN = ("android/app/src/main/java/org/otrv4plus/android/ui/"
          "DevShellScreen.kt")

pytestmark = pytest.mark.skipif(
    not os.path.exists(SCREEN), reason="no android/ project in this checkout")


def source():
    return open(SCREEN).read()


def test_the_export_button_is_not_behind_a_failure_check():
    src = source()
    # Renamed when the error log landed: this one is the LAUNCH snapshot,
    # and the new "Share error log" button is the live event trace. Both are
    # always offered; the invariant guarded here is that neither is hidden
    # behind a failure check.
    assert "Export start-up report" in src, "the export button is gone entirely"
    assert "Share error log" in src, "the error-log export is gone entirely"
    # Any `if (!r.ok)` block is the shape that hid it before.
    assert not re.search(r'if\s*\(\s*!\s*r\.ok\s*\)\s*\{', src), (
        "the buttons are inside a failure-only branch again; a successful "
        "start would have no way to produce a report, and FLAG_SECURE means "
        "no screenshot either")


def test_copy_is_offered_as_well():
    """The fallback when no app answers the share intent."""
    assert "setText(AnnotatedString(fullReport" in source()


def test_the_report_names_its_own_build():
    """Three identical reports arrived before this existed."""
    src = source()
    assert "BuildConfig.BUILD_ID" in src
    body = src[src.index("private fun fullReport"):]
    body = body[:body.index("\n}")]
    assert "BUILD_ID" in body, "the build id is on screen but not in the export"


def test_flag_secure_is_still_set():
    """The export exists so that screenshots need not be weakened."""
    activity = ("android/app/src/main/java/org/otrv4plus/android/"
                "MainActivity.kt")
    assert "FLAG_SECURE" in open(activity).read()
