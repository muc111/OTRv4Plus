# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The desktop's connection banner offers a way back to the login form.

Device report, 2026-10-27: "the desktop got disconnected I had a
notification without an option to re login". A failed or stopped
connection does not come back by itself; the banner said so and offered
nothing but a restart. It now has "Log in again", which signs out (so the
old connection is torn down first) and shows the login form.
"""
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _src(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as fh:
        return fh.read()


def test_failed_or_stopped_the_banner_offers_log_in_again():
    src = _src("desktop", "src", "main", "kotlin", "org", "otrv4plus", "desktop", "ui",
               "MainScreen.kt")
    banner = src[src.index("private fun LinkBanner(model: AppModel)"):]
    banner = banner[:banner.index("\n}\n")]
    assert "if (phase == LinkPhase.FAILED || phase == LinkPhase.STOPPED)" in banner
    assert 'TextButton(onClick = { model.disconnect() }) { Text("Log in again") }' in banner
    model = _src("desktop", "src", "main", "kotlin", "org", "otrv4plus", "desktop", "AppModel.kt")
    sign_out = model[model.index("    fun disconnect() {"):]
    sign_out = sign_out[:sign_out.index("\n    }\n")]
    assert "core.disconnect()" in sign_out and "screen = Screen.CONNECT" in sign_out


def test_the_dev_builds_are_told_apart_from_rc_186():
    gradle = _src("android", "app", "build.gradle.kts")
    code = int(re.search(r"versionCode = (\d+)", gradle).group(1))
    rc = int(re.search(r"versionName = \"[^\"]*experimental\.rc\.(\d+)", gradle).group(1))
    assert code >= 188 and rc >= 187
    desktop = re.search(r'version = "0\.14\.(\d+)"', _src("desktop", "build.gradle.kts"))
    assert desktop and int(desktop.group(1)) >= 10
