# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Location pins: GPS receiver only, asked on tap, encrypted conversations only."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ANDROID = ROOT / "android/app/src/main"
UI = ANDROID / "java/org/otrv4plus/android/ui"


def _src(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_only_the_gps_receiver_is_used():
    sheet = _src(UI / "LocationSheet.kt")
    assert "GPS_PROVIDER" in sheet
    for provider in ("NETWORK_PROVIDER", "FUSED_PROVIDER", "FusedLocationProviderClient",
                     "play-services-location", "PASSIVE_PROVIDER"):
        assert provider not in sheet, provider
    gradle = _src(ROOT / "android/app/build.gradle.kts")
    assert "play-services-location" not in gradle


def test_only_fine_location_and_never_in_the_background():
    manifest = _src(ANDROID / "AndroidManifest.xml")
    assert "android.permission.ACCESS_FINE_LOCATION" in manifest
    assert "ACCESS_BACKGROUND_LOCATION" not in manifest
    assert "ACCESS_COARSE_LOCATION" not in manifest


def test_pins_are_offered_only_where_encrypted():
    vm = _src(ANDROID / "java/org/otrv4plus/android/chat/ChatViewModel.kt")
    assert "fun canShareLocation" in vm
    screen = _src(UI / "ConversationScreen.kt")
    assert "if (model.canShareLocation(jid))" in screen
    desktop = _src(ROOT / "desktop/src/main/kotlin/org/otrv4plus/desktop/ui/ConversationPane.kt")
    assert "security != SecurityState.PLAINTEXT" in desktop


def test_no_web_map_or_lookup_service():
    for path in (UI / "LocationSheet.kt", ANDROID / "java/org/otrv4plus/android/chat/Location.kt"):
        text = _src(path)
        for banned in ("WebView", "http://", "https://", "api.what3words", "Geocoder"):
            assert banned not in text, (path.name, banned)


def test_opening_another_app_warns_first():
    sheet = _src(UI / "LocationSheet.kt")
    assert "Location.OPEN_WARNING" in sheet
    assert "confirmOpen" in sheet
