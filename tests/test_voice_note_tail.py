# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The end of a voice note is kept, recorded and played (owner, 2026-10-20:
"in playback the end of my recording is cut short we may need to add a 2 sec
extension").

* Stop keeps recording TAIL_SECONDS more, so what the microphone was still
  delivering is in the note (the mask trims the silence after it).
* Playback waits until the note has actually been heard before stopping the
  speaker: pacat takes audio faster than it plays it, and stopping it as soon
  as the last frame was written threw away over a second.
"""
import os
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import otrv4plus_voicenote as vn                                    # noqa: E402

FRAME = 960          # 20 ms at 24 kHz, s16le


class _SlowMic:
    """A frame every 20 ms, like a real microphone."""
    rate = 24000

    def __init__(self, frames):
        self.frames = list(frames)
        self.stopped = False

    def read_frame(self, timeout_ms=200):
        time.sleep(0.02)
        return self.frames.pop(0) if self.frames else None

    def stop(self):
        self.stopped = True


def test_stop_keeps_recording_for_the_tail():
    frames = [bytes([i % 250 + 1]) * FRAME for i in range(200)]   # 4 s worth
    mic = _SlowMic(frames)
    rec = vn.Recorder(open_capture=lambda: (mic, []))
    rec.start()
    time.sleep(0.5)
    t = time.monotonic()
    pcm, _ = rec.stop(0.6)
    waited = time.monotonic() - t
    assert waited >= 0.55
    # ~0.5 s before Stop and ~0.6 s after it: the tail is in the note.
    assert len(pcm) / 2 / 24000 > 0.95, len(pcm) / 2 / 24000


def test_the_app_stops_with_the_two_second_tail(monkeypatch):
    assert vn.TAIL_SECONDS == 2.0
    src = open(os.path.join(ROOT, "android_bridge", "app.py"), encoding="utf-8").read()
    assert "rec.stop(vn.TAIL_SECONDS)" in src


def test_cancel_does_not_wait():
    mic = _SlowMic([b"\x01" * FRAME] * 200)
    rec = vn.Recorder(open_capture=lambda: (mic, []))
    rec.start()
    t = time.monotonic()
    rec.cancel()
    assert time.monotonic() - t < 1.0


class _FastSpeaker:
    """Takes every frame at once, as pacat's pipe does."""
    rate = 16000
    frame_bytes = 640

    def __init__(self):
        self.stopped_at = None
        self.done = threading.Event()

    def write_frame(self, chunk):
        return True

    def stop(self):
        self.stopped_at = time.monotonic()
        self.done.set()


def test_playback_is_not_stopped_before_the_note_has_played(monkeypatch):
    spk = _FastSpeaker()
    monkeypatch.setattr(vn, "decode", lambda data: (b"\x00\x10" * 16000, 16000))  # 1 s
    player = vn.Player(open_playback=lambda: (spk, []))
    t = time.monotonic()
    assert abs(player.play(b"note") - 1.0) < 0.01
    assert spk.done.wait(5)
    assert spk.stopped_at - t >= 1.0, "the speaker was stopped before the end was heard"


def test_stop_still_stops_playback_at_once(monkeypatch):
    spk = _FastSpeaker()
    monkeypatch.setattr(vn, "decode", lambda data: (b"\x00\x10" * 16000 * 10, 16000))  # 10 s
    player = vn.Player(open_playback=lambda: (spk, []))
    t = time.monotonic()
    player.play(b"note")
    time.sleep(0.2)
    player.stop()
    assert spk.done.wait(2)
    assert spk.stopped_at - t < 1.5
