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

    def test_the_speaker_gain_is_fixed_at_unity(self, monkeypatch):
        # A second automatic stage here would chase the sender's, and a fixed
        # boost would fight the compressor ahead of it -- see
        # TestCompressorConfiguration.test_the_speaker_gain_defaults_to_unity.
        monkeypatch.delenv("OTRV4PLUS_SPEAKER_AGC", raising=False)
        monkeypatch.delenv("OTRV4PLUS_SPEAKER_GAIN", raising=False)
        stage = audio.make_speaker_gain()
        assert stage.auto is False
        assert stage.gain == 1.0

    def test_gain_is_configurable(self, monkeypatch):
        monkeypatch.setenv("OTRV4PLUS_SPEAKER_GAIN", "3.5")
        assert audio.make_speaker_gain().gain == 3.5

    @pytest.mark.parametrize("bad", ["", "loud", "0", "-2", "999", "nan"])
    def test_a_nonsense_gain_falls_back_to_the_default(self, monkeypatch, bad):
        monkeypatch.setenv("OTRV4PLUS_SPEAKER_GAIN", bad)
        assert audio.make_speaker_gain().gain == 1.0

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
        stage.sample()
        text = stage.summary()
        assert "mic" in text and "peak" in text and "rms" in text

    def test_input_and_output_peaks_are_both_recorded(self):
        # The pair is what identifies a quiet device: a low peak_in with a
        # healthy peak_out means the gain stage is doing its job.
        stage = audio.GainStage(gain=4.0)
        stage.process(tone(4090))
        stage.sample()
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


# ---------------------------------------------------------------------------
# Metering
# ---------------------------------------------------------------------------

class TestMeteringHoldsThePeak:
    """The reported level must cover the window, not one 60 ms frame.

    The device self-test holds its peak over two seconds and read 30430. The
    in-call meter reported whatever single frame coincided with the stats
    line, so it read peak_in=0 through most of a call. The two numbers were
    compared against each other and were never comparable.
    """

    def test_the_peak_survives_a_later_quiet_frame(self):
        stage = audio.GainStage(gain=1.0)
        stage.process(tone(20000))
        stage.process(b"\x00\x00" * 480)
        stage.process(b"\x00\x00" * 480)
        stage.sample()
        assert stage.peak_in == pytest.approx(20000, abs=40)

    def test_sampling_starts_a_new_window(self):
        # Otherwise one loud moment masks every quiet stretch afterwards.
        stage = audio.GainStage(gain=1.0)
        stage.process(tone(20000))
        stage.sample()
        stage.process(tone(1000))
        stage.sample()
        assert stage.peak_in == pytest.approx(1000, abs=40)

    def test_rms_is_reported_alongside_peak(self):
        # Peak alone cannot say whether something is loud: speech has a
        # 12-18 dB crest factor.
        stage = audio.GainStage(gain=1.0)
        stage.process(tone(20000))
        stage.sample()
        assert 0 < stage.rms_in < stage.peak_in

    def test_rms_averages_across_the_window(self):
        stage = audio.GainStage(gain=1.0)
        stage.process(tone(20000))
        stage.process(b"\x00\x00" * 480)
        stage.sample()
        loud_only = audio.GainStage._rms(tone(20000))
        assert stage.rms_in < loud_only

    def test_output_levels_are_measured_too(self):
        stage = audio.GainStage(gain=4.0)
        stage.process(tone(2000))
        stage.sample()
        assert stage.peak_out > stage.peak_in
        assert stage.rms_out > stage.rms_in


class TestDbfsFormatting:
    def test_full_scale_is_zero(self):
        assert audio.dbfs(audio.PCM_FULL_SCALE).startswith("0")

    def test_half_scale_is_about_minus_six(self):
        assert "-6" in audio.dbfs(audio.PCM_FULL_SCALE // 2)

    def test_silence_is_negative_infinity(self):
        assert "inf" in audio.dbfs(0)


# ---------------------------------------------------------------------------
# Compression
# ---------------------------------------------------------------------------

def speech_frame(peak, samples=960, seed=None):
    """A frame with a speech-like crest factor."""
    import random
    rng = random.Random(seed if seed is not None else peak)
    return struct.pack("<%dh" % samples,
                       *[int(peak * math.sin(i / 3.0) * rng.uniform(0.25, 1.0))
                         for i in range(samples)])


class TestCompressorLiftsQuietSpeech:
    def _chain(self, compress):
        comp = audio.make_speaker_compressor() if compress else None
        gain = audio.GainStage(gain=1.0 if compress else 2.0)

        def run(pcm):
            return gain.process(comp.process(pcm) if comp else pcm)
        return run

    def test_quiet_speech_comes_up(self):
        # The whole point. Peak gain cannot do this: it lifts the loud parts
        # into the limiter and the quiet parts stay where they were.
        quiet = speech_frame(400)
        plain = self._chain(False)
        comped = self._chain(True)
        for _ in range(30):
            a = plain(quiet)
            b = comped(quiet)
        assert audio.GainStage._rms(b) > audio.GainStage._rms(a) * 1.8

    def test_loud_speech_is_not_made_louder(self):
        # It is already near full scale; there is nowhere to go and trying
        # only engages the limiter.
        loud = speech_frame(28000)
        comped = self._chain(True)
        for _ in range(30):
            out = comped(loud)
        assert peak_of(out) <= audio.GAIN_CEILING

    def test_the_loud_to_quiet_spread_narrows(self):
        comp = audio.make_speaker_compressor()
        gain = audio.GainStage(gain=1.0)

        def settle(pcm):
            for _ in range(40):
                out = gain.process(comp.process(pcm))
            return audio.GainStage._rms(out)

        loud_in = audio.GainStage._rms(speech_frame(12000))
        quiet_in = audio.GainStage._rms(speech_frame(400))
        loud_out = settle(speech_frame(12000))
        quiet_out = settle(speech_frame(400))
        spread_in = loud_in / max(quiet_in, 1)
        spread_out = loud_out / max(quiet_out, 1)
        assert spread_out < spread_in


class TestCompressorDoesNotAmplifyNoise:
    def test_room_noise_is_left_alone(self):
        # 12 dB of makeup on the silence between words turns a call into a
        # hiss; the gate is what stops that.
        import random
        rng = random.Random(3)
        noise = struct.pack("<960h", *[rng.randint(-25, 25) for _ in range(960)])
        comp = audio.make_speaker_compressor()
        gain = audio.GainStage(gain=1.0)
        for _ in range(40):
            out = gain.process(comp.process(noise))
        assert (audio.GainStage._rms(out)
                <= audio.GainStage._rms(noise) * 1.5)
        assert comp.gated_blocks > 0

    def test_digital_silence_stays_silent(self):
        comp = audio.make_speaker_compressor()
        out = comp.process(b"\x00\x00" * 480)
        assert peak_of(out) == 0


class TestMakeupGain:
    def test_it_is_derived_from_the_curve_by_default(self):
        # -threshold * (1 - 1/ratio) leaves full scale at full scale.
        comp = audio.Compressor(threshold_dbfs=-30.0, ratio=4.0,
                                makeup_db=None)
        assert comp.makeup_db == pytest.approx(22.5, rel=0.01)

    def test_a_hand_picked_value_is_honoured(self):
        comp = audio.Compressor(makeup_db=6.0)
        assert comp.makeup_db == 6.0

    def test_it_is_configurable(self, monkeypatch):
        monkeypatch.setenv("OTRV4PLUS_SPEAKER_MAKEUP_DB", "9")
        assert audio.make_speaker_compressor().makeup_db == 9.0

    def test_an_absent_override_derives_it(self, monkeypatch):
        monkeypatch.delenv("OTRV4PLUS_SPEAKER_MAKEUP_DB", raising=False)
        assert audio.make_speaker_compressor().makeup_db > 20.0


class TestCompressorConfiguration:
    def test_playback_compression_is_on_by_default(self, monkeypatch):
        # On playback rather than capture, so it fixes what this device hears
        # regardless of what the peer is running.
        monkeypatch.delenv("OTRV4PLUS_SPEAKER_COMPRESSOR", raising=False)
        assert audio.make_speaker_compressor().enabled is True

    def test_capture_compression_is_off_by_default(self, monkeypatch):
        # Compressing at both ends is what makes voice sound over-processed.
        monkeypatch.delenv("OTRV4PLUS_MIC_COMPRESSOR", raising=False)
        assert audio.make_mic_compressor().enabled is False

    def test_it_can_be_disabled(self, monkeypatch):
        monkeypatch.setenv("OTRV4PLUS_SPEAKER_COMPRESSOR", "0")
        comp = audio.make_speaker_compressor()
        assert comp.enabled is False
        pcm = speech_frame(4000)
        assert bytes(comp.process(pcm)) == pcm

    def test_the_speaker_gain_defaults_to_unity(self, monkeypatch):
        # Stacking a fixed 2x on the compressor drives the limiter, which
        # then attenuates the whole frame including the blocks the
        # compressor had just lifted. Measured as a 2.6 dB LOSS.
        monkeypatch.delenv("OTRV4PLUS_SPEAKER_GAIN", raising=False)
        assert audio.make_speaker_gain().gain == 1.0

    def test_the_attack_is_faster_than_the_release(self):
        assert audio.COMP_ATTACK > audio.COMP_RELEASE

    def test_the_block_is_short_enough_to_avoid_pumping(self):
        # Per-frame gain at 60 ms pumps audibly.
        assert audio.COMP_BLOCK_MS <= 20


class TestCompressorOutputIsWellFormed:
    def test_the_frame_length_is_preserved(self):
        comp = audio.make_speaker_compressor()
        pcm = speech_frame(6000)
        assert len(comp.process(pcm)) == len(pcm)

    def test_a_partial_block_is_handled(self):
        comp = audio.make_speaker_compressor()
        pcm = speech_frame(6000, samples=97)
        assert len(comp.process(pcm)) == len(pcm)

    def test_an_empty_frame_is_handled(self):
        assert bytes(audio.make_speaker_compressor().process(b"")) == b""

    def test_the_chain_still_cannot_clip(self):
        comp = audio.make_speaker_compressor()
        gain = audio.GainStage(gain=16.0)
        for level in (100, 4090, 16000, 32767):
            for _ in range(20):
                out = gain.process(comp.process(speech_frame(level)))
            assert peak_of(out) <= audio.GAIN_CEILING
