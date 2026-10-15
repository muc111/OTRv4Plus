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


def test_pins_go_only_where_the_identity_is_verified():
    """Owner (2026-10-15): "GPS location should be behind verification".
    Encrypted is not enough; the sheet (and the GPS) does not open before."""
    vm = _src(ANDROID / "java/org/otrv4plus/android/chat/ChatViewModel.kt")
    open_fn = vm[vm.index("fun openLocation"):vm.index("fun closeLocation")]
    assert "locationRefusal(jid)" in open_fn and "return" in open_fn
    assert open_fn.index("return") < open_fn.index("locationFor =")
    refusal = vm[vm.index("fun locationRefusal"):vm.index("fun canShareLocation")]
    assert "TransferUi.Offer.Available" in refusal
    send = vm[vm.index("fun sendLocation"):]
    assert "locationRefusal(jid)" in send[:400]
    desktop = _src(ROOT / "desktop/src/main/kotlin/org/otrv4plus/desktop/ui/ConversationPane.kt")
    assert "Location.shareRefusal(" in desktop and "enabled = allowed && pin != null" in desktop


def test_a_set_or_mocked_location_is_never_refused():
    """Owner: "mock GPS location should be allowed". A mock-location app
    feeds the same GPS provider; nothing may inspect or reject it, and the
    typed path stays."""
    sheet = _src(UI / "LocationSheet.kt")
    for check in ("isMock", "isFromMockProvider", "MOCK"):
        assert check not in sheet, check
    assert "Location.SET_HINT" in sheet
    assert "fun fromTyped" in _src(ANDROID / "java/org/otrv4plus/android/chat/Location.kt")


def test_no_web_map_or_lookup_service():
    for path in (UI / "LocationSheet.kt", ANDROID / "java/org/otrv4plus/android/chat/Location.kt"):
        text = _src(path)
        for banned in ("WebView", "http://", "https://", "api.what3words", "Geocoder"):
            assert banned not in text, (path.name, banned)


def test_opening_another_app_warns_first():
    sheet = _src(UI / "LocationSheet.kt")
    assert "Location.OPEN_WARNING" in sheet
    assert "confirmOpen" in sheet
