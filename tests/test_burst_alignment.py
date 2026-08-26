#!/usr/bin/env python3
"""Burst-aligned playback writes.

Measured on a live call, from the device itself:

    framesPerBurst 1920 @ 16 kHz  =  120 ms transfer unit
    our packet      960 frames    =   60 ms

Feeding half a burst per write made every write block for a p50 of 95-100 ms
against a 60 ms frame period. Playout ran at 9.3 fps against a 16.7 fps stream,
so the jitter buffer shed 32.1% of all received audio to hold latency down --
while the network lost 2.72% over the same call. `conv 0.0/0.0` in the same
telemetry ruled out resampling and upmix: the device write was the whole cost.

These tests drive the real write path against a fake libaaudio, so what is
asserted is the sequence of AAudioStream_write calls, not the shape of the
source.
"""

import ctypes
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

audio = pytest.importorskip("otrv4plus_audio")


class FakeLib:
    """Records every write. Accepts everything offered, in one go."""

    def __init__(self):
        self.writes = []          # frames per call

    def AAudioStream_write(self, stream, buf, num_frames, timeout_ns):
        n = int(getattr(num_frames, "value", num_frames))
        self.writes.append(n)
        return n


def make_playback(burst, device_rate=16000, channels=1, align=True):
    """An AAudioPlayback with the device's answers stubbed, no real stream."""
    p = audio.AAudioPlayback.__new__(audio.AAudioPlayback)
    p._lib = FakeLib()
    p._stream = ctypes.c_void_p(1)
    p._closed = False
    p.disconnected = False
    p.device_rate = device_rate
    p.device_channels = channels
    p.frames_per_burst = burst
    p.buffer_capacity = burst * 4
    p.buffer_size = burst * 2
    p._resampler = audio.Resampler(audio.SAMPLE_RATE, device_rate, 1)
    p._upmix = max(1, channels)
    p._pending_pcm = bytearray()
    # The REAL decision, not a restatement of it. A helper that recomputes
    # the production rule cannot detect the production rule changing.
    p._device_frames_per_packet = max(
        1, int(round(audio.FRAME_SAMPLES * device_rate / float(audio.SAMPLE_RATE))))
    p._align_frames = audio.alignment_frames(
        burst, p._device_frames_per_packet, enabled=align)
    p.last_convert_s = 0.0
    p.last_device_s = 0.0
    return p


FRAME = b"\x01\x02" * audio.FRAME_SAMPLES        # one 60 ms packet, 16-bit mono


class TestTheDeviceThatCausedThis:
    """framesPerBurst=1920 @ 16 kHz, exactly as the handset reported."""

    def test_alignment_engages(self):
        p = make_playback(1920)
        assert p._align_frames == 1920, (
            "a 1920-frame burst against a 960-frame packet must align")

    def test_writes_are_whole_bursts_not_half_ones(self):
        p = make_playback(1920)
        for _ in range(6):
            p.write_frame(FRAME)
        assert p._lib.writes == [1920, 1920, 1920], (
            "expected one write per burst, got %r" % p._lib.writes)

    def test_the_first_frame_is_held_not_dropped(self):
        p = make_playback(1920)
        assert p.write_frame(FRAME) is True
        assert p._lib.writes == [], "wrote a half burst"
        assert len(p._pending_pcm) == len(FRAME), "the held frame vanished"

    def test_no_audio_is_lost_across_the_boundary(self):
        p = make_playback(1920)
        marked = bytes(range(256)) * (len(FRAME) // 256) + FRAME[:len(FRAME) % 256]
        p.write_frame(marked)
        p.write_frame(FRAME)
        assert sum(p._lib.writes) * 2 == len(marked) + len(FRAME), (
            "bytes went missing between the two frames")

    def test_the_tail_is_flushed_rather_than_dropped(self):
        p = make_playback(1920)
        p.write_frame(FRAME)          # held
        assert p._lib.writes == []
        p.flush()
        assert p._lib.writes == [1920], (
            "the last words of the call were dropped instead of padded")
        assert p._pending_pcm == bytearray()

    def test_flush_is_idempotent_and_silent_when_empty(self):
        p = make_playback(1920)
        p.flush()
        p.flush()
        assert p._lib.writes == []


class TestTheAlignmentRule:
    """Drives alignment_frames directly, so the rule itself is under test."""

    PKT16 = audio.FRAME_SAMPLES                 # 960 device frames at 16 kHz
    PKT48 = audio.FRAME_SAMPLES * 3             # 2880 device frames at 48 kHz

    def test_the_handsets_burst(self):
        assert audio.alignment_frames(1920, self.PKT16, enabled=True) == 1920

    def test_a_burst_at_or_below_our_packet_needs_nothing(self):
        for burst in (0, 192, 480, 960):
            assert audio.alignment_frames(burst, self.PKT16, enabled=True) == 0, burst

    def test_the_burst_is_compared_in_device_frames_not_ours(self):
        """A 48 kHz device is where mixing the two units shows up.

        1920 device frames is 40 ms there -- under our 60 ms packet, so no
        alignment is needed. Comparing it against FRAME_SAMPLES (960, our
        count at 16 kHz) makes it look larger and aligns to two thirds of a
        packet, stranding a remainder on every single frame.
        """
        assert audio.alignment_frames(1920, self.PKT48, enabled=True) == 0
        assert audio.alignment_frames(2880, self.PKT48, enabled=True) == 0
        assert audio.alignment_frames(5760, self.PKT48, enabled=True) == 5760

    def test_it_always_returns_a_whole_number_of_packets(self):
        for packet in (self.PKT16, self.PKT48):
            for burst in range(1, 9000, 7):
                n = audio.alignment_frames(burst, packet, enabled=True)
                assert n % packet == 0, (
                    "packet %d burst %d aligned to %d, which splits a packet"
                    % (packet, burst, n))

    def test_it_is_never_smaller_than_the_burst_it_covers(self):
        for packet in (self.PKT16, self.PKT48):
            for burst in range(1, 9000, 7):
                n = audio.alignment_frames(burst, packet, enabled=True)
                if n:
                    assert n >= burst, (
                        "burst %d aligned to %d, still under a burst"
                        % (burst, n))

    def test_disabled_means_disabled(self):
        assert audio.alignment_frames(1920, self.PKT16, enabled=False) == 0

    def test_it_follows_the_module_default_when_unspecified(self):
        expected = 1920 if audio.ALIGN_WRITES else 0
        assert audio.alignment_frames(1920, self.PKT16) == expected

    def test_the_stream_derives_the_packet_from_the_device_rate(self):
        p48 = make_playback(5760, device_rate=48000)
        assert p48._device_frames_per_packet == self.PKT48
        assert p48._align_frames == 5760
        p16 = make_playback(1920, device_rate=16000)
        assert p16._device_frames_per_packet == self.PKT16
        assert p16._align_frames == 1920


class TestStopFlushesTheTail:

    def test_stop_hands_over_the_held_frame(self):
        p = make_playback(1920)
        stopped = []
        # Stub the base teardown; what is under test is that stop() flushes
        # BEFORE it closes, not what closing does.
        type(p).__mro__[1].stop = lambda self: stopped.append(True)
        try:
            p.write_frame(FRAME)
            assert p._lib.writes == []
            p.stop()
            assert p._lib.writes == [1920], (
                "stop() closed the stream without flushing the held audio")
            assert stopped == [True], "stop() no longer tears the stream down"
        finally:
            del type(p).__mro__[1].stop


class TestDevicesThatNeedNoAlignment:

    def test_a_burst_at_or_below_our_frame_is_left_alone(self):
        for burst in (192, 480, 960):
            p = make_playback(burst)
            assert p._align_frames == 0, "burst %d should need no alignment" % burst
            p.write_frame(FRAME)
            assert p._lib.writes == [audio.FRAME_SAMPLES], (
                "burst %d: writes should pass straight through" % burst)

    def test_a_device_reporting_no_burst_is_left_alone(self):
        p = make_playback(0)
        assert p._align_frames == 0
        p.write_frame(FRAME)
        assert p._lib.writes == [audio.FRAME_SAMPLES]

    def test_alignment_can_be_switched_off(self):
        # The only way to reproduce the original stall, which is why it exists.
        p = make_playback(1920, align=False)
        assert p._align_frames == 0
        p.write_frame(FRAME)
        assert p._lib.writes == [audio.FRAME_SAMPLES]


class TestAlignmentIsAWholeNumberOfPackets:

    def test_a_burst_that_is_not_a_packet_multiple_rounds_up(self):
        # 1000 frames against a 960 packet: aligning to 1000 would split a
        # packet and leave a fragment forever. Round up to 2 packets.
        p = make_playback(1000)
        assert p._align_frames == 2 * audio.FRAME_SAMPLES
        for _ in range(4):
            p.write_frame(FRAME)
        assert p._lib.writes == [1920, 1920]
        assert p._pending_pcm == bytearray(), "a fragment was stranded"

    def test_a_short_chunk_leaves_its_remainder_queued(self):
        """The case that distinguishes keeping the remainder from clearing it.

        With whole packets in, `pending` is always an exact multiple of the
        alignment unit and the remainder is always empty -- so dropping it
        instead of slicing it off is indistinguishable. A short chunk is not
        exotic (concealment and the tail of a stream can both produce one) and
        it is the input where clearing the buffer silently eats audio.
        """
        p = make_playback(1920)
        half = FRAME[:len(FRAME) // 2]
        p.write_frame(FRAME)          # 960 frames held
        p.write_frame(FRAME)          # 1920 -> one burst written, 0 left
        assert p._lib.writes == [1920]
        p.write_frame(half)           # 480 frames held
        p.write_frame(FRAME)          # 1440 held, still under a burst
        p.write_frame(FRAME)          # 2400 -> write 1920, KEEP 480
        assert p._lib.writes == [1920, 1920]
        assert len(p._pending_pcm) == len(half), (
            "the %d-byte remainder was discarded instead of carried forward"
            % len(half))

    def test_it_never_holds_more_than_one_alignment_unit(self):
        p = make_playback(1920)
        for _ in range(21):
            p.write_frame(FRAME)
        assert len(p._pending_pcm) < p._align_frames * 2, (
            "the hold-back buffer is growing without bound")


class TestTheTunablesAreReal:

    def test_defaults(self):
        assert audio.ALIGN_WRITES is True
        assert audio.OUTPUT_BURSTS >= 2, (
            "two bursts is the floor for a blocking writer")
        assert audio.OUTPUT_CAPACITY_FRAMES >= 4

    def test_capacity_leaves_room_for_the_buffer_size(self):
        # Capacity 3840 (2 bursts) is what the handset granted before this
        # change, which left no room to set a size at all.
        assert audio.FRAME_SAMPLES * audio.OUTPUT_CAPACITY_FRAMES >= 1920 * 3

    def test_the_buffer_size_setter_is_bound(self):
        src = __import__("inspect").getsource(audio._bind)
        assert "setBufferSizeInFrames" in src, (
            "buffer size is a runtime setter and must be bound; it cannot be "
            "a builder call because framesPerBurst is unknown until open")
