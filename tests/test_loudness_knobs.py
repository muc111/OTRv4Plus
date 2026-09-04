#!/usr/bin/env python3
"""What the loudness controls actually do, measured through the real chain.

Reported: two-way audio works but is too quiet to follow comfortably. The
instinct is to add gain. Measured on a 3 s speech-shaped signal peaking at
-14 dBFS, the shipped chain already delivers +7.4 dB of RMS and peaks at
-3.5 dBFS, so there is ~3.5 dB of digital headroom and no more -- which means
a still-quiet call is usually about which Android stream it is on.

The trap these tests exist for: OTRV4PLUS_SPEAKER_MAKEUP_DB REPLACES the
compressor's automatic makeup instead of adding to it. Unset it derives
22.5 dB from the threshold and ratio, so a plausible-looking 12 makes the call
QUIETER. That is surprising enough to pin.
"""

import importlib
import math
import os
import struct
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

audio = pytest.importorskip("otrv4plus_audio")


def _speechy(n=16000 * 2, peak_dbfs=-14.0):
    """Bursts and pauses, crest factor like speech. Deterministic."""
    import random
    random.seed(7)
    amp = (10 ** (peak_dbfs / 20.0)) * 32767
    out = []
    for i in range(n):
        env = 0.0 if (i // 1600) % 3 == 2 else abs(math.sin(i / 400.0)) ** 2
        out.append(max(-32768, min(32767, int(amp * env * random.uniform(-1, 1)))))
    return struct.pack("<%dh" % n, *out)


def _rms_dbfs(b):
    n = len(b) // 2
    if not n:
        return -99.0
    s = struct.unpack("<%dh" % n, b)
    r = math.sqrt(sum(v * v for v in s) / n)
    return 20 * math.log10(r / 32767.0) if r > 0 else -99.0


def _peak_dbfs(b):
    n = len(b) // 2
    p = max(abs(v) for v in struct.unpack("<%dh" % n, b)) if n else 0
    return 20 * math.log10(p / 32767.0) if p else -99.0


@pytest.fixture
def chain(monkeypatch):
    """Run the source through the real speaker chain under given env."""
    def run(**env):
        for k in [k for k in os.environ if k.startswith("OTRV4PLUS_SPEAKER")]:
            monkeypatch.delenv(k, raising=False)
        for k, v in env.items():
            monkeypatch.setenv(k, v)
        mod = importlib.reload(audio)
        comp, gain = mod.make_speaker_compressor(), mod.make_speaker_gain()
        src = _speechy()
        out = bytearray()
        step = mod.FRAME_SAMPLES * 2
        for i in range(0, len(src) - step + 1, step):
            out += gain.process(comp.process(src[i:i + step]))
        return _rms_dbfs(bytes(out)), _peak_dbfs(bytes(out)), _rms_dbfs(src)
    yield run
    importlib.reload(audio)


class TestTheShippedChainIsAlreadyLoud:

    def test_it_lifts_rms_substantially(self, chain):
        out_rms, _peak, in_rms = chain()
        assert out_rms - in_rms > 5.0, (
            "the default chain only adds %.1f dB; the compressor is not doing "
            "its job" % (out_rms - in_rms))

    def test_it_does_not_clip(self, chain):
        _rms, peak, _in = chain()
        assert peak < 0.0, "output peaks at %.1f dBFS" % peak

    def test_there_is_little_headroom_left(self, chain):
        """The reason more gain is not the answer."""
        _rms, peak, _in = chain()
        assert peak > -8.0, (
            "peak is %.1f dBFS, so there IS headroom and this test's premise "
            "-- that the digital path is nearly maxed -- no longer holds"
            % peak)


class TestTheMakeupKnobReplacesRatherThanAdds:

    def test_a_low_value_makes_it_quieter(self, chain):
        default_rms = chain()[0]
        low_rms = chain(OTRV4PLUS_SPEAKER_MAKEUP_DB="12")[0]
        assert low_rms < default_rms, (
            "MAKEUP_DB=12 was expected to be QUIETER than the automatic "
            "22.5 dB; if it is not, the knob's semantics changed and the "
            "documentation warning is now wrong")

    def test_the_automatic_value_comes_from_threshold_and_ratio(self):
        c = audio.make_speaker_compressor()
        expected = -c.threshold * (1.0 - 1.0 / c.ratio)
        assert abs(c.makeup_db - expected) < 0.01

    def test_a_high_value_does_make_it_louder(self, chain):
        assert chain(OTRV4PLUS_SPEAKER_MAKEUP_DB="24")[0] > chain()[0]


class TestTheBluntKnobStillWorks:

    def test_gain_raises_level_but_eats_the_headroom(self, chain):
        base_rms, _bp, _ = chain()
        rms, peak, _ = chain(OTRV4PLUS_SPEAKER_GAIN="2.0")
        assert rms > base_rms
        assert peak > -3.0, (
            "2x gain should be pushing the limiter; if it is not, the limiter "
            "is attenuating more than expected")

    def test_the_limiter_still_prevents_clipping(self, chain):
        _rms, peak, _ = chain(OTRV4PLUS_SPEAKER_GAIN="16.0")
        assert peak <= 0.0, "16x gain clipped at %.1f dBFS" % peak


class TestTheRouteIsReachable:

    def test_media_usage_is_selectable(self, monkeypatch):
        monkeypatch.setenv("OTRV4PLUS_AUDIO_USAGE", "media")
        assert audio.playback_usage() == audio.AAUDIO_USAGE_MEDIA

    def test_the_call_stream_is_the_default(self, monkeypatch):
        monkeypatch.delenv("OTRV4PLUS_AUDIO_USAGE", raising=False)
        assert audio.playback_usage() == audio.AAUDIO_USAGE_VOICE_COMMUNICATION
