# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Voice masking for live calls (Rust/src/live_mask.rs, otrv4plus_audio).

Owner, 2026-11-09: "we must clearly understand the person speaking but
can't identify who -- maybe men should sound like women and vice versa ...
add a button". The Rust tests check the voice itself (pitch and formants
moved together, the direction from the speaker's pitch, a new mask each
call, nothing above 7.5 kHz, real time with room to spare). These check the
switch and the one rule around it: a user who asked to be masked is never
sent their real voice -- before the mask is ready, or if it cannot run, the
call carries silence.
"""
import asyncio
import math
import os
import struct
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for p in (ROOT, os.path.join(ROOT, "client")):
    if p not in sys.path:
        sys.path.insert(0, p)

import otrv4plus_audio as A  # noqa: E402

otrv4_core = pytest.importorskip("otrv4_core")
if not hasattr(otrv4_core, "LiveVoiceMask"):
    pytest.skip("otrv4_core built without the live voice mask", allow_module_level=True)

FRAME_SAMPLES = 1440            # 60 ms at 24 kHz
MASK = otrv4_core.LiveVoiceMask  # held: one test replaces the attribute


def voiced(f0=110.0, frames=1, start=0):
    """A buzzy voiced sound: harmonics of f0, as 16-bit PCM frames."""
    out = []
    for f in range(frames):
        samples = []
        for i in range(FRAME_SAMPLES):
            t = (start + f * FRAME_SAMPLES + i) / 24000.0
            v = sum(math.sin(2 * math.pi * h * f0 * t) / h for h in range(1, 20) if h * f0 < 5000)
            samples.append(int(4000 * v))
        out.append(struct.pack("<%dh" % FRAME_SAMPLES, *samples))
    return out


@pytest.fixture(autouse=True)
def mask_off_and_forgotten():
    A.set_live_mask(False)
    MASK.forget_direction()
    yield
    A.set_live_mask(False)
    MASK.forget_direction()


def test_off_means_the_audio_passes_untouched():
    m = A.LiveMasker()
    frame = bytearray(voiced()[0])
    assert m.process(frame) is frame


def test_on_the_first_moment_is_silence_then_the_voice_is_changed():
    A.set_live_mask(True)
    m = A.LiveMasker()
    frames = voiced(frames=20)
    outs = [m.process(bytearray(f)) for f in frames]
    assert all(len(o) == len(f) for o, f in zip(outs, frames))
    assert outs[0] == bytearray(len(frames[0]))          # never the real voice
    assert m.ready
    tail = outs[-1]
    assert any(tail) and tail != bytearray(frames[-1])


def test_the_next_call_starts_masked_at_once():
    A.set_live_mask(True)
    first = A.LiveMasker()
    for f in voiced(frames=10):
        first.process(bytearray(f))
    assert first.ready
    second = A.LiveMasker()                              # next call
    second.process(bytearray(voiced()[0]))
    assert second.ready


def test_masking_that_cannot_run_sends_silence_never_the_voice(monkeypatch):
    A.set_live_mask(True)

    class Broken:
        def process(self, _pcm):
            raise RuntimeError("boom")
    m = A.LiveMasker()
    m._mask = Broken()
    frame = bytearray(voiced()[0])
    assert m.process(frame) == bytearray(len(frame)) and m.failed

    monkeypatch.setattr(otrv4_core, "LiveVoiceMask", None, raising=False)
    m = A.LiveMasker()
    assert m.process(bytearray(frame)) == bytearray(len(frame))


def test_the_switch_works_mid_call():
    m = A.LiveMasker()
    frame = bytearray(voiced()[0])
    assert m.process(frame) is frame
    A.set_live_mask(True)
    assert m.process(bytearray(frame)) != frame
    A.set_live_mask(False)
    assert m.process(frame) is frame


def test_a_group_call_masks_before_opus():
    import otrv4plus_groupcall as G
    encoded = []

    class Enc:
        def encode(self, pcm, _n):
            encoded.append(bytes(pcm))
            return b"\x01" * 20

    class Cap:
        name = "test"

        def __init__(self, frames):
            self.frames = list(frames)

        def read_frame(self, _ms):
            if not self.frames:
                raise OSError("end")
            return self.frames.pop(0)

    loop = asyncio.new_event_loop()
    try:
        media = G.GroupCallMedia(loop=loop, sam_host="127.0.0.1", sam_port=7656,
                                 printer=lambda *a: None)
        media._capture = Cap(voiced(frames=3))
        media._encoder = Enc()
        media._calls = type("C", (), {"send_audio": lambda self, b: None})()
        media._running = True
        media._mic_gain = type("G", (), {"process": lambda self, x: x})()
        media._mic_comp = media._mic_gain
        A.set_live_mask(True)
        media._capture_loop()
    finally:
        loop.close()
    assert encoded and all(e == bytes(len(e)) for e in encoded)  # silence while it listens


def test_a_one_to_one_call_masks_before_opus():
    src = open(os.path.join(ROOT, "client", "otrv4plus_voice.py"), encoding="utf-8").read()
    assert "self._masker = _audio.LiveMasker()" in src
    levelled = src.index("pcm = self._mic_gain.process(self._mic_comp.process(raw))")
    masked = src.index("pcm = self._masker.process(pcm)")
    encoded = src.index("self._opus_enc.encode(bytes(pcm), VOICE_FRAME_SAMPLES)")
    assert levelled < masked < encoded


def test_the_apps_switch_and_ask():
    from android_bridge.app_calls import CallsMixin
    app = CallsMixin()
    assert app.set_voice_mask(True) == {"on": True, "available": True}
    assert A.live_mask_on()
    assert app.voice_mask_state()["on"] is True
    assert app.set_voice_mask(False)["on"] is False
    from desktop_bridge import host as H
    assert H.APP_OPS["set_voice_mask"] == ("on",)
    assert H.APP_OPS["voice_mask_state"] == ()


def test_the_terminal_has_mask():
    src = open(os.path.join(ROOT, "client", "otrv4plus_xmpp.py"), encoding="utf-8").read()
    assert 'lstrip in ("/mask", "/mask on", "/mask off")' in src
    assert "/mask [on|off]" in src
