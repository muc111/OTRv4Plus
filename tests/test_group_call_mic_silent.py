# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""A muted microphone is noticed and said, in every app.

Owner, 2026-11-09: "mic was off on laptop, had to test a second time". A
microphone muted outside the app (laptop mic key, system mixer, Android's
privacy toggle) still delivers frames -- zeros -- which the call encodes and
sends at full rate, so every counter looked healthy and nobody was told.
"""
import asyncio
import os
import struct
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for p in (ROOT, os.path.join(ROOT, "client")):
    if p not in sys.path:
        sys.path.insert(0, p)

import otrv4plus_groupcall as G  # noqa: E402
import otrv4plus_voice as V  # noqa: E402
from android_bridge.trace import TRACE  # noqa: E402
from kotlin_parts import with_parts  # noqa: E402

FRAME = V.VOICE_FRAME_BYTES
SILENCE = b"\x00" * FRAME


def pcm(*samples):
    body = struct.pack("<%dh" % len(samples), *samples)
    return body + b"\x00" * (FRAME - len(body))


def test_the_peak_of_a_frame():
    assert G.frame_peak(SILENCE) == 0
    assert G.frame_peak(pcm(3, -9, 5)) == 9
    assert G.frame_peak(pcm(-32768)) == 32768
    assert G.frame_peak(b"") == 0


def test_room_noise_counts_as_sound_and_zeros_do_not():
    assert G.frame_peak(pcm(*([12, -14] * 50))) <= G.MIC_SILENT_PEAK     # dither
    assert G.frame_peak(pcm(*([300, -280] * 50))) > G.MIC_SILENT_PEAK    # a quiet room


class _Capture:
    name = "test"

    def __init__(self, frames):
        self.frames = list(frames)

    def read_frame(self, _ms):
        if not self.frames:
            raise OSError("end")          # ends the capture loop
        return self.frames.pop(0)


class _Encoder:
    def encode(self, pcm_bytes, _n):
        return b"\x01" * 20


def _media(frames):
    loop = asyncio.new_event_loop()
    m = G.GroupCallMedia(loop=loop, sam_host="127.0.0.1", sam_port=7656, printer=lambda *a: None)
    m._capture = _Capture(frames)
    m._encoder = _Encoder()
    m._calls = type("Calls", (), {"send_audio": lambda self, _b: None})()
    m._running = True
    return m, loop


def test_only_silence_since_capture_began_counts_up(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(G.time, "monotonic", lambda: clock[0])
    m, loop = _media([SILENCE] * 10)
    m._started = 100.0
    m._capture_loop()
    clock[0] = 106.0
    assert m.mic_silent_seconds() == pytest.approx(6.0)
    assert m.describe()["mic_silent_s"] == 6
    loop.close()


def test_one_frame_with_sound_resets_it(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(G.time, "monotonic", lambda: clock[0])
    m, loop = _media([SILENCE, pcm(*([400, -350] * 40)), SILENCE])
    m._started = 90.0
    m._capture_loop()
    clock[0] = 101.0
    assert m.mic_silent_seconds() == pytest.approx(1.0)
    loop.close()


def test_not_capturing_is_never_silent():
    m, loop = _media([])
    m._running = False
    assert m.mic_silent_seconds() == 0.0
    loop.close()


class _Calls:
    def __init__(self, room, paused=False):
        self.room, self.paused = room, paused

    def active(self):
        return self.room

    def ringing(self):
        return []

    def participants(self, room):
        return ["bob@x.i2p"]


class _SilentMedia:
    def __init__(self, seconds):
        self.seconds = seconds

    def mic_silent_seconds(self):
        return self.seconds


def _bridge(seconds, paused=False):
    from android_bridge.group_call_bridge import GroupCallBridge
    br = GroupCallBridge.__new__(GroupCallBridge)
    br.calls = _Calls("room@conf", paused)
    br._media = _SilentMedia(seconds)
    br._reset_watch()
    return br


def test_the_call_state_says_so_after_a_few_seconds():
    assert _bridge(G.MIC_SILENT_WARN + 1).status("room@conf")["mic_silent"] is True
    assert _bridge(1.0).status("room@conf")["mic_silent"] is False
    # Not for another room, and not when we paused ourselves.
    assert _bridge(60).status("other@conf")["mic_silent"] is False
    assert _bridge(60, paused=True).status("room@conf")["mic_silent"] is False


def test_the_report_records_it_once_per_call():
    TRACE.clear()
    br = _bridge(60)
    br._reopening = True               # the receive watchdog itself stays out
    for _ in range(3):
        br._watch(br._media)
    events = [e for e in TRACE.events() if e["event"] == "mic_silent"]
    assert len(events) == 1 and events[0]["severity"] == "warning"


def test_every_app_shows_it():
    def src(*parts):
        return with_parts(os.path.join(ROOT, *parts))
    kt = "android/app/src/main/java/org/otrv4plus/android".split("/")
    assert "micSilent" in src(*kt, "bridge", "OtrCore.kt")
    assert 'flag(value, "mic_silent")' in src(*kt, "bridge", "ChaquopyOtrCore.kt")
    assert "callState.micSilent" in src(*kt, "ui", "ConversationGroupUi.kt")
    assert 'v["mic_silent"].flag()' in src("desktop", "src", "main", "kotlin", "org", "otrv4plus",
                                          "desktop", "engine", "DesktopCore.kt")
    assert "call.micSilent" in src("desktop", "src", "main", "kotlin", "org", "otrv4plus",
                                   "desktop", "ui", "GroupPane.kt")
    assert "_warn_mic_silent()" in src("client", "otrv4plus_groups.py")
