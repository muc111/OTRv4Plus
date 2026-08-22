"""Frame geometry and rate-shaping invariants for the voice path.

Every assertion here corresponds to a defect that has actually shipped and
failed silently:

  * ``otrv4plus_audio`` and ``otrv4plus_voice`` each declared their own frame
    duration.  Setting one to 40 ms and the other to 60 ms handed Opus a
    1280-byte buffer and told it to read 1920 bytes, on every frame, with no
    error anywhere.
  * An Opus frame larger than ``VOICE_OPUS_SLOT`` makes ``pad_opus`` return
    ``None``.  The capture worker substitutes silence and increments a counter,
    so the call connects, reports healthy, and carries no audio.
  * libopus accepts only a fixed set of frame durations.  Anything else fails
    per frame at runtime rather than at configuration time.
  * Jitter-buffer depths are counts of frames.  Because a frame is not a fixed
    duration, changing the frame duration silently changed the buffer's latency
    in milliseconds -- which is the quantity anyone actually cares about.

These are cheap to check and expensive to discover on a live call.
"""

import pytest

import otrv4plus_audio as audio
import otrv4plus_voice as voice


class TestFrameGeometryIsShared:
    def test_voice_takes_its_frame_duration_from_audio(self):
        assert voice.VOICE_FRAME_MS == audio.FRAME_MS

    def test_voice_takes_its_sample_rate_and_channels_from_audio(self):
        assert voice.VOICE_SAMPLE_RATE == audio.SAMPLE_RATE
        assert voice.VOICE_CHANNELS == audio.CHANNELS

    def test_the_pcm_buffer_the_capture_returns_is_the_one_the_encoder_reads(self):
        # The exact mismatch that produced a silent call: read_frame() hands
        # back FRAME_BYTES, the encoder is told to consume VOICE_FRAME_SAMPLES.
        assert voice.VOICE_FRAME_BYTES == audio.FRAME_BYTES
        assert voice.VOICE_FRAME_SAMPLES == audio.FRAME_SAMPLES

    def test_samples_and_bytes_agree_with_the_declared_duration(self):
        expected_samples = audio.SAMPLE_RATE * audio.FRAME_MS // 1000
        assert audio.FRAME_SAMPLES == expected_samples
        assert audio.FRAME_BYTES == (
            expected_samples * audio.CHANNELS * audio.SAMPLE_WIDTH)

    def test_the_frame_interval_matches_the_frame_duration(self):
        assert voice.FRAME_INTERVAL_S == pytest.approx(
            voice.VOICE_FRAME_MS / 1000.0)


class TestOpusAcceptsTheConfiguration:
    def test_the_frame_duration_is_one_libopus_supports(self):
        # libopus: 2.5/5/10/20/40/60 ms. Below 10 ms the packet rate makes the
        # constant-rate shaping pointless over I2P, so the module restricts
        # itself further -- assert against the module's own list.
        assert voice.VOICE_FRAME_MS in voice._OPUS_VALID_FRAME_MS

    def test_an_encoded_frame_fits_the_fixed_slot(self):
        # pad_opus returns None above the slot, and the caller substitutes
        # silence rather than failing, so an overflow is inaudible in logs.
        assert voice.VOICE_OPUS_PEAK_BYTES <= voice.VOICE_OPUS_SLOT

    def test_the_slot_still_leaves_room_for_the_timestamp(self):
        assert voice.VOICE_PLAIN_LEN == (
            2 + voice.VOICE_TS_LEN + voice.VOICE_OPUS_SLOT)


class TestJitterBufferDepthsAreDerivedFromMilliseconds:
    def test_prefill_matches_its_declared_latency(self):
        assert (voice.VOICE_JITTER_PREFILL * voice.VOICE_FRAME_MS
                == pytest.approx(voice.VOICE_JITTER_PREFILL_MS,
                                 abs=voice.VOICE_FRAME_MS))

    def test_the_ceiling_matches_its_declared_latency(self):
        assert (voice.VOICE_JITTER_DRIFT_HIGH * voice.VOICE_FRAME_MS
                == pytest.approx(voice.VOICE_JITTER_DRIFT_HIGH_MS,
                                 abs=voice.VOICE_FRAME_MS))

    def test_the_hard_cap_matches_its_declared_latency(self):
        assert (voice.VOICE_JITTER_MAX * voice.VOICE_FRAME_MS
                == pytest.approx(voice.VOICE_JITTER_MAX_MS,
                                 abs=voice.VOICE_FRAME_MS))

    def test_the_depths_are_ordered(self):
        # A ceiling at or below the prefill would shed a frame the instant
        # playout started, forever.
        assert (voice.VOICE_JITTER_PREFILL
                < voice.VOICE_JITTER_DRIFT_HIGH
                <= voice.VOICE_JITTER_MAX)

    def test_every_depth_holds_at_least_one_frame(self):
        assert voice.VOICE_JITTER_PREFILL >= 1
        assert voice.VOICE_JITTER_MAX >= 2


class TestOfferedRate:
    def test_the_packet_length_is_fixed_and_independent_of_content(self):
        assert voice.VOICE_PACKET_LEN == (
            voice.VOICE_HDR_LEN + voice.VOICE_SEALED_LEN)

    def test_the_offered_rate_is_below_what_the_path_was_observed_to_starve_at(self):
        # The failure being addressed is starvation, not codec quality: a live
        # call received 8 frames where ~125 were expected. 39.8 kbit/s was the
        # rate at which that happened; anything at or above it is a regression.
        packets_per_second = 1000.0 / voice.VOICE_FRAME_MS
        kbit_s = voice.VOICE_PACKET_LEN * 8 * packets_per_second / 1000.0
        assert kbit_s < 39.0, "offered rate %.1f kbit/s" % kbit_s

    def test_forward_error_correction_is_still_enabled(self):
        # FEC repairs a one-frame gap. It cannot help with multi-second
        # starvation, but disabling it entirely loses the repair that does work.
        assert 0 < voice.VOICE_LOSS_PCT <= 10
