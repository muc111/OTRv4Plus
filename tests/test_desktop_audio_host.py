# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The desktop runs the Android bridge on Linux, and must keep Linux audio.

Device report (2026-10-20, ThinkPad on Ubuntu, PulseAudio on PipeWire):
the desktop app said "the microphone could not be opened", voice notes did
not play, and calls from the phone never connected -- while the very same
`otrv4plus_audio` and `Recorder` worked from a shell. The call bridge had
bound the ANDROID hooks (`android_audio.bind`), which pin the backend to
AAudio with no fallback; Linux has no libaaudio.so, so after the first call
setup every capture and playback failed. The desktop host now says it is
the desktop, and the bridge keeps the Linux hooks there.
"""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

otr = pytest.importorskip("otrv4_")
voice = pytest.importorskip("otrv4plus_voice")
import otrv4plus_xmpp as xmpp                                         # noqa: E402
from android_bridge import android_audio                              # noqa: E402
from android_bridge.app import OtrApp                                 # noqa: E402


def _app():
    return OtrApp(otr.EnhancedSessionManager(otr.OTRConfig(test_mode=True)), None, None)


def test_on_the_desktop_the_call_bridge_keeps_the_linux_audio(monkeypatch):
    monkeypatch.setenv(android_audio.HOST_ENV, "desktop")
    monkeypatch.delenv("OTRV4PLUS_AUDIO_BACKEND", raising=False)
    bound = []
    monkeypatch.setattr(android_audio, "bind", lambda v: bound.append(v))
    app = _app()
    try:
        app.calls._ensure_manager()
        assert bound == [], "the desktop bound the Android (AAudio-only) hooks"
        assert "OTRV4PLUS_AUDIO_BACKEND" not in os.environ, \
            "the desktop was pinned to one audio backend"
    finally:
        app.shutdown() if hasattr(app, "shutdown") else None


def test_on_the_desktop_voice_is_judged_by_the_linux_check(monkeypatch):
    monkeypatch.setenv(android_audio.HOST_ENV, "desktop")
    monkeypatch.setattr(xmpp, "voice_available", lambda: (True, "ok"))
    monkeypatch.setattr(android_audio, "unavailable_reason",
                        lambda: android_audio.NO_AAUDIO)
    assert _app().voice_unavailable_reason() == ""
    monkeypatch.setattr(xmpp, "voice_available", lambda: (False, "no audio backend"))
    assert _app().voice_unavailable_reason() == "no audio backend"


def test_the_phone_still_pins_aaudio(monkeypatch):
    monkeypatch.delenv(android_audio.HOST_ENV, raising=False)
    bound = []
    monkeypatch.setattr(android_audio, "bind", lambda v: bound.append(v))
    _app().calls._ensure_manager()
    assert len(bound) == 1
    assert not android_audio.is_desktop()


def test_the_desktop_host_says_it_is_the_desktop_before_anything_loads():
    src = open(os.path.join(ROOT, "desktop_bridge", "host.py"), encoding="utf-8").read()
    main = src[src.index("def main()"):]
    assert main.index('os.environ["OTRV4PLUS_HOST"] = "desktop"') < main.index("Host(proto)")
