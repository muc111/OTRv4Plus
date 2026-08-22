"""Level control for the voice path.

Two phones on the same call reported 4090 and 31226 for the same microphone
self-test -- 17 dB apart for the same speech. Opus encodes what it is given,
so the quiet device sounded quiet and thin at the far end no matter what the
codec was set to. The platform AGC is already requested through the
VOICE_COMMUNICATION input preset and did not deliver, so gain is applied on
top of it.

The property that matters most here is that output cannot clip. A plain
multiply large enough to fix a -18 dBFS device destroys any louder passage,
and hard clipping costs more intelligibility than the quietness it fixes.
"""

import math
import struct

import pytest

import otrv4plus_audio as audio


def tone(peak, samples=960, period=16.0):
    return struct.pack("<%dh" % samples,
                       *[int(peak * math.sin(i / period))
                         for i in range(samples)])


def peak_of(pcm):
    return audio.GainStage._peak(pcm)


class TestPeakMeasurement:
    def test_it_finds_the_peak(self):
        assert peak_of(tone(12000)) == pytest.approx(12000, abs=30)

    def test_silence_measures_zero(self):
        assert peak_of(b"\x00\x00" * 480) == 0

    def test_an_empty_buffer_measures_zero(self):
        assert peak_of(b"") == 0

    def test_negative_excursions_count(self):
        # A frame whose only large excursion is negative must not read quiet.
        pcm = struct.pack("<4h", 0, -30000, 0, 100)
        assert peak_of(pcm) >= 30000


class TestNoConfigurationCanClip:
    @pytest.mark.parametrize("gain", [1.0, 2.0, 4.0, 8.0, 16.0])
    @pytest.mark.parametrize("level", [500, 4090, 16000, 30000, 32767])
    def test_output_stays_under_the_ceiling(self, gain, level):
        stage = audio.GainStage(gain=gain)
        out = stage.process(tone(level))
        assert peak_of(out) <= audio.GAIN_CEILING

    def test_a_hot_signal_is_limited_not_wrapped(self):
        # Wrapping turns a loud vowel into noise; the value must come down,
        # not around.
        stage = audio.GainStage(gain=8.0)
        out = stage.process(tone(32000))
        assert peak_of(out) == pytest.approx(audio.GAIN_CEILING, rel=0.01)
        assert stage.limited_frames == 1

    def test_limiting_is_counted(self):
        stage = audio.GainStage(gain=10.0)
        for _ in range(5):
            stage.process(tone(20000))
        assert stage.limited_frames == 5

    def test_a_frame_that_needs_no_limiting_is_not_counted(self):
        stage = audio.GainStage(gain=1.0)
        stage.process(tone(1000))
        assert stage.limited_frames == 0


class TestFixedGain:
    def test_unity_gain_returns_the_same_samples(self):
        stage = audio.GainStage(gain=1.0)
        pcm = tone(8000)
        assert bytes(stage.process(pcm)) == pcm

    def test_a_quiet_signal_is_amplified(self):
        stage = audio.GainStage(gain=4.0)
        out = stage.process(tone(2000))
        assert peak_of(out) == pytest.approx(8000, rel=0.02)

    def test_silence_stays_silence(self):
        stage = audio.GainStage(gain=8.0)
        out = stage.process(b"\x00\x00" * 480)
        assert peak_of(out) == 0

    def test_an_empty_frame_is_handled(self):
        assert bytes(audio.GainStage(gain=4.0).process(b"")) == b""


class TestAutomaticGain:
    def test_it_brings_a_quiet_device_up_to_target(self):
        # The measured case: a device peaking at 4090.
        stage = audio.GainStage(auto=True)
        pcm = tone(4090)
        for _ in range(60):
            out = stage.process(pcm)
        assert peak_of(out) == pytest.approx(audio.GAIN_TARGET_PEAK, rel=0.02)

    def test_it_leaves_an_already_loud_device_alone(self):
        # The other phone measured 31226; boosting that would only limit.
        stage = audio.GainStage(auto=True)
        for _ in range(30):
            out = stage.process(tone(28000))
        assert peak_of(out) <= audio.GAIN_CEILING
        assert stage._auto_gain == pytest.approx(1.0, rel=0.01)

    def test_it_never_ducks_below_unity(self):
        # Automatic gain that attenuates would fight the far end's own stage.
        stage = audio.GainStage(auto=True)
        for _ in range(30):
            stage.process(tone(30000))
        assert stage._auto_gain >= 1.0

    def test_it_rises_gradually_rather_than_in_one_step(self):
        # A single-step rise is audible as a lurch at the start of speech.
        stage = audio.GainStage(auto=True)
        stage.process(tone(1000))
        after_one = stage._auto_gain
        assert 1.0 < after_one < audio.GAIN_MAX_AUTO

    def test_it_falls_faster_than_it_rises(self):
        # Slow recovery after a loud noise leaves the next words inaudible.
        assert audio.GainStage._AUTO_FALL < 1.0 < audio.GainStage._AUTO_RISE
        assert (1.0 - audio.GainStage._AUTO_FALL
                > audio.GainStage._AUTO_RISE - 1.0)

    def test_the_boost_is_bounded(self):
        # Past the cap the noise floor rises as fast as the speech does.
        stage = audio.GainStage(auto=True)
        for _ in range(200):
            stage.process(tone(50))
        assert stage._auto_gain <= audio.GAIN_MAX_AUTO

    def test_auto_is_off_unless_asked_for(self):
        stage = audio.GainStage(gain=1.0)
        for _ in range(20):
            out = stage.process(tone(2000))
        assert peak_of(out) == pytest.approx(2000, abs=30)


class TestConfiguration:
    def test_the_microphone_defaults_to_automatic(self, monkeypatch):
        monkeypatch.delenv("OTRV4PLUS_MIC_AGC", raising=False)
        monkeypatch.delenv("OTRV4PLUS_MIC_GAIN", raising=False)
        stage = audio.make_mic_gain()
        assert stage.auto is True

    def test_the_speaker_defaults_to_a_fixed_boost(self, monkeypatch):
        # A second automatic stage here would chase the sender's.
        monkeypatch.delenv("OTRV4PLUS_SPEAKER_AGC", raising=False)
        monkeypatch.delenv("OTRV4PLUS_SPEAKER_GAIN", raising=False)
        stage = audio.make_speaker_gain()
        assert stage.auto is False
        assert stage.gain > 1.0

    def test_gain_is_configurable(self, monkeypatch):
        monkeypatch.setenv("OTRV4PLUS_SPEAKER_GAIN", "3.5")
        assert audio.make_speaker_gain().gain == 3.5

    @pytest.mark.parametrize("bad", ["", "loud", "0", "-2", "999", "nan"])
    def test_a_nonsense_gain_falls_back_to_the_default(self, monkeypatch, bad):
        monkeypatch.setenv("OTRV4PLUS_SPEAKER_GAIN", bad)
        assert audio.make_speaker_gain().gain == 2.0

    @pytest.mark.parametrize("value,expected",
                             [("1", True), ("true", True), ("on", True),
                              ("0", False), ("no", False), ("off", False)])
    def test_the_agc_flag_is_parsed(self, monkeypatch, value, expected):
        monkeypatch.setenv("OTRV4PLUS_MIC_AGC", value)
        assert audio.make_mic_gain().auto is expected

    def test_even_the_maximum_configured_gain_cannot_clip(self, monkeypatch):
        monkeypatch.setenv("OTRV4PLUS_SPEAKER_GAIN", "16")
        stage = audio.make_speaker_gain()
        assert peak_of(stage.process(tone(32767))) <= audio.GAIN_CEILING


class TestReporting:
    def test_the_summary_carries_the_measured_levels(self):
        stage = audio.GainStage(gain=2.0, name="mic")
        stage.process(tone(4090))
        text = stage.summary()
        assert "mic" in text and "peak_in=" in text and "peak_out=" in text

    def test_input_and_output_peaks_are_both_recorded(self):
        # The pair is what identifies a quiet device: a low peak_in with a
        # healthy peak_out means the gain stage is doing its job.
        stage = audio.GainStage(gain=4.0)
        stage.process(tone(4090))
        assert stage.peak_in == pytest.approx(4090, abs=30)
        assert stage.peak_out == pytest.approx(16360, rel=0.02)


class TestPurePythonFallbackMatchesAudioop:
    """audioop was removed in Python 3.13, so both paths must agree."""

    def _without_audioop(self, monkeypatch):
        monkeypatch.setattr(audio, "_audioop", None)

    def test_peak_agrees(self, monkeypatch):
        pcm = tone(9000)
        native = audio.GainStage._peak(pcm)
        self._without_audioop(monkeypatch)
        assert audio.GainStage._peak(pcm) == native

    def test_scaling_agrees(self, monkeypatch):
        pcm = tone(5000)
        native = bytes(audio.GainStage._scale(pcm, 2.0))
        self._without_audioop(monkeypatch)
        fallback = bytes(audio.GainStage._scale(pcm, 2.0))
        # Rounding differs by at most one LSB per sample.
        assert len(fallback) == len(native)
        a = struct.unpack("<%dh" % (len(native) // 2), native)
        b = struct.unpack("<%dh" % (len(fallback) // 2), fallback)
        assert max(abs(x - y) for x, y in zip(a, b)) <= 1

    def test_the_fallback_also_cannot_clip(self, monkeypatch):
        self._without_audioop(monkeypatch)
        stage = audio.GainStage(gain=16.0)
        assert peak_of(stage.process(tone(32000))) <= audio.GAIN_CEILING
