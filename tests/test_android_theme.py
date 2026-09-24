# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Theme: one source of colour, applied app-wide, persisted, listed for wipe.

The palettes' contrast is checked in Kotlin (`ThemeTokensTest`); this checks
the wiring that only CI can compile.
"""

import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "android/app/src/main/java/org/otrv4plus/android")


def _read(*parts):
    with open(os.path.join(SRC, *parts), encoding="utf-8") as f:
        return f.read()


def test_no_screen_hard_codes_a_colour():
    for name in sorted(os.listdir(os.path.join(SRC, "ui"))):
        if not name.endswith(".kt") or name == "AppTheme.kt":
            continue
        code = _read("ui", name)
        assert not re.search(r"Color\(0x[0-9A-Fa-f]{8}\)", code), (
            "%s hard-codes a colour; add a token to ThemeTokens" % name)


def test_the_whole_app_is_themed_from_the_stored_choice():
    main = _read("MainActivity.kt")
    assert "OtrTheme(themeMode)" in main
    assert "ThemeStore.load(this)" in main
    assert "ThemeStore.save(this@MainActivity, mode)" in main
    assert "MaterialTheme {" not in main, "an unthemed MaterialTheme remains"


def test_verified_colour_follows_the_palette():
    colours = _read("ui", "SecurityColours.kt")
    assert "LocalVerifiedColour.current" in colours
    theme = _read("ui", "AppTheme.kt")
    assert "LocalVerifiedColour provides Color(palette.verified)" in theme


def test_the_choice_is_ordinary_preferences_and_listed_for_wipe():
    theme = _read("ui", "AppTheme.kt")
    assert "getSharedPreferences(FILE, Context.MODE_PRIVATE)" in theme
    assert "vault" not in theme.split("object ThemeStore")[1].split("fun load")[0] \
        .replace("NOT the vault", "")
    wipe = _read("security", "WipeAndExit.kt")
    assert "shared_prefs: otrv4plus.ui.xml" in wipe


def test_three_choices_offered_with_the_default_marked():
    screen = _read("ui", "ConversationsScreen.kt")
    assert "ThemeTokens.Mode.entries" in screen
    assert '" (default)"' in screen
