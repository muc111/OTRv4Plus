#!/usr/bin/env python3
"""Speech clarity: a high-pass and a presence lift, ahead of the compressor.

Reported: a working two-way call that is hard to follow. The instinct is more
gain, and the measurements say gain is spent: the chain already peaks near
-1 dBFS, so adding 2x buys +0.5 dB of speech and the rest goes into the
limiter.

What was actually missing is that the compressor had no idea which part of the
signal was speech. Two consequences, both measured on speech with a 60 Hz
rumble under it:

  * Rumble below ~120 Hz carries no speech but does carry level, so the
    compressor turned the WHOLE frame down for it. High-passing hands that
    headroom back.
  * Consonants live at 2-4 kHz and carry intelligibility; vowels carry the
    energy. A compressor set for loudness flattens the band that carries
    meaning. A presence lift puts it back.

Result: speech RMS -16.0 -> -13.9 dBFS at an unchanged -1.0 dBFS peak, and the
1-4 kHz share of energy 0.348 -> 0.421. Louder voice, same headroom, no extra
gain.
"""

import math
import os
import struct
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

audio = pytest.importorskip("otrv4plus_audio")


def _tone(hz, n=16000, amp_dbfs=-12.0, rate=16000):
    a = (10 ** (amp_dbfs / 20.0)) * 32767
    return struct.pack("<%dh" % n,
                       *[int(a * math.sin(2 * math.pi * hz * i / rate))
                         for i in range(n)])


def _rms(b):
    n = len(b) // 2
    if not n:
        return 0.0
    s = struct.unpack("<%dh" % n, bytes(b))
    return math.sqrt(sum(v * v for v in s) / n)


def _db(b):
    r = _rms(b)
    return 20 * math.log10(r / 32767.0) if r > 0 else -99.0


def _through(stage, pcm, frame_bytes=None):
    """Feed it in frames, as the call does -- filter state must carry over."""
    step = frame_bytes or audio.FRAME_SAMPLES * 2
    out = bytearray()
    for i in range(0, len(pcm) - step + 1, step):
        out += stage.process(pcm[i:i + step])
    return bytes(out)


class TestItRemovesWhatIsNotSpeech:

    def test_rumble_is_attenuated_hard(self):
        sc = audio.make_speech_clarity()
        before = _db(_tone(60))
        after = _db(_through(sc, _tone(60)))
        assert after < before - 12.0, (
            "60 Hz rumble only dropped %.1f dB; it still steals compressor "
            "headroom from speech" % (before - after))

    def test_the_speech_band_is_not_attenuated(self):
        sc = audio.make_speech_clarity()
        before = _db(_tone(500))
        after = _db(_through(sc, _tone(500)))
        assert after > before - 1.5, (
            "500 Hz lost %.1f dB; the high-pass is eating voice"
            % (before - after))


class TestItLiftsTheConsonantBand:

    def test_the_presence_band_gains(self):
        sc = audio.make_speech_clarity()
        before = _db(_tone(2600))
        after = _db(_through(sc, _tone(2600)))
        assert after > before + 2.0, (
            "2.6 kHz gained only %.1f dB; consonants are not being lifted"
            % (after - before))

    def test_the_lift_is_a_band_not_a_shelf(self):
        """A broadband lift would just be gain, which is already spent."""
        sc = audio.make_speech_clarity()
        presence = _db(_through(sc, _tone(2600))) - _db(_tone(2600))
        low = _db(_through(audio.make_speech_clarity(), _tone(700))) - _db(_tone(700))
        assert presence > low + 1.5, (
            "presence %.1f dB vs 700 Hz %.1f dB -- this is a shelf, not a "
            "presence peak" % (presence, low))


class TestItDoesNotCostHeadroomOrCpu:

    def test_a_hot_frame_does_not_clip(self):
        """Clipping is a RUN of pinned samples, not a sample on the rail.

        abs() also lies here: -32768 is a legal int16 and abs() reports 32768,
        which reads as an overflow when it is the most negative representable
        value. Measure flat tops instead.
        """
        sc = audio.make_speech_clarity()
        out = _through(sc, _tone(2600, amp_dbfs=-1.0))
        s = struct.unpack("<%dh" % (len(out) // 2), out)
        run = best = 0
        for v in s:
            if v >= 32767 or v <= -32768:
                run += 1
                best = max(best, run)
            else:
                run = 0
        assert best <= 2, (
            "%d consecutive samples pinned at the rail: the presence lift is "
            "clipping before the limiter, where nothing downstream can undo it"
            % best)

    def test_a_hot_frame_gives_back_headroom(self):
        sc = audio.make_speech_clarity()
        _through(sc, _tone(2600, amp_dbfs=-1.0))
        assert sc._headroom < 0.9, (
            "no headroom was taken for a near-full-scale frame")

    def test_a_quiet_frame_keeps_the_whole_lift(self):
        """The reason the headroom is adaptive rather than constant.

        A flat attenuation by the boost is safe but costs: the compressor
        recovers only (1 - 1/ratio) of it, so the measured speech gain fell
        from +2.1 dB to +0.8. Real speech peaks nowhere near full scale.
        """
        sc = audio.make_speech_clarity()
        quiet = _tone(2600, amp_dbfs=-20.0)
        out = _through(sc, quiet)
        gained = _db(out) - _db(quiet)
        assert gained > 4.0, (
            "quiet speech only gained %.1f dB of the %.1f dB lift"
            % (gained, sc.presence_db))
        assert sc._headroom > 0.99

    def test_it_is_cheap_enough_for_a_phone(self):
        import time
        sc = audio.make_speech_clarity()
        frame = bytes(b"\x11\x22" * audio.FRAME_SAMPLES)
        sc.process(frame)
        t0 = time.perf_counter()
        for _ in range(100):
            sc.process(frame)
        ms = (time.perf_counter() - t0) * 10.0
        # 60 ms budget; allow a wide margin for slow CI, since the point is to
        # catch an accidental O(n^2) rewrite, not to benchmark the host.
        assert ms < 15.0, "%.1f ms per 60 ms frame" % ms


class TestItIsWiredInAndReversible:

    def test_it_runs_before_the_compressor(self):
        """After the compressor the lift would be squashed by the gain
        reduction it caused; before it, the compressor spends its range on
        speech instead of rumble."""
        import inspect
        voice = pytest.importorskip("otrv4plus_voice")
        src = inspect.getsource(voice.VoiceCallSession)
        i = src.index("_speech_clarity.process")
        j = src.index("_speaker_comp.process")
        k = src.index("_speaker_gain.process")
        assert k < j < i, (
            "the chain is not gain(comp(clarity(x))); clarity must be "
            "innermost so it runs first")

    def test_it_can_be_turned_off(self, monkeypatch):
        monkeypatch.setenv("OTRV4PLUS_SPEECH_CLARITY", "0")
        sc = audio.make_speech_clarity()
        assert sc.enabled is False
        frame = _tone(60)[:audio.FRAME_SAMPLES * 2]
        assert sc.process(frame) == frame, "disabled still altered the audio"

    def test_each_shaping_parameter_is_tunable(self, monkeypatch):
        monkeypatch.setenv("OTRV4PLUS_SPEECH_HPF_HZ", "200")
        monkeypatch.setenv("OTRV4PLUS_SPEECH_PRESENCE_DB", "8")
        monkeypatch.setenv("OTRV4PLUS_SPEECH_PRESENCE_HZ", "3000")
        import importlib
        m = importlib.reload(audio)
        try:
            sc = m.make_speech_clarity()
            assert sc.hpf_hz == 200.0
            assert sc.presence_db == 8.0
            assert sc.presence_hz == 3000.0
        finally:
            for k in ("OTRV4PLUS_SPEECH_HPF_HZ", "OTRV4PLUS_SPEECH_PRESENCE_DB",
                      "OTRV4PLUS_SPEECH_PRESENCE_HZ"):
                monkeypatch.delenv(k, raising=False)
            importlib.reload(audio)

    def test_filter_state_survives_between_frames(self):
        """A biquad reset every frame clicks at the boundary."""
        sc = audio.make_speech_clarity()
        frame = _tone(2600)[:audio.FRAME_SAMPLES * 2]
        sc.process(frame)
        assert any(s._z1 or s._z2 for s in sc._sections), (
            "no filter state carried; each frame starts cold and will click")
