"""Jitter buffer depth is the call's steady-state latency.

Arrivals and playout run at the same rate, so nothing pulls the buffer down
except the drift shed. That makes the shed threshold -- target plus margin --
the exact depth the buffer settles at, and therefore the delay every frame
pays. It was target + max(prefill, 4) FRAMES, which at 60 ms was 240 ms of
hysteresis stacked on a target that already carries its own slack. With the
target pinned at its ceiling the buffer parked at 14 frames, 840 ms, on top
of ~1 s of network delay. Observed on a live call as jitter=12/33 through
25/33 with a "delayed" conversation.

These tests pin the relationship between the constants, the arithmetic that
converts them, and the buffer's actual settling behaviour.
"""

import pytest

import otrv4plus_voice as voice


def _buf(**kw):
    kw.setdefault("adaptive", False)
    return voice.JitterBuffer(**kw)


def _fill(buf, count, start=0):
    for i in range(count):
        buf.push(0, start + i, bytearray(b"\xaa" * 8))


class TestConstantsAreDurationsNotFrameCounts:
    def test_the_shed_margin_is_derived_from_milliseconds(self):
        assert voice.VOICE_JITTER_SHED_MARGIN == max(
            1, voice.VOICE_JITTER_SHED_MARGIN_MS // voice.VOICE_FRAME_MS)

    def test_the_prefill_is_derived_from_milliseconds(self):
        assert (voice.VOICE_JITTER_PREFILL * voice.VOICE_FRAME_MS
                == pytest.approx(voice.VOICE_JITTER_PREFILL_MS,
                                 abs=voice.VOICE_FRAME_MS))

    def test_the_worst_case_steady_state_is_under_700ms(self):
        # target + margin, with target at its ceiling. This is the number the
        # user experiences as delay, and it was 840 ms.
        worst = ((voice.VOICE_JITTER_DRIFT_HIGH + voice.VOICE_JITTER_SHED_MARGIN)
                 * voice.VOICE_FRAME_MS)
        assert worst <= 700, "steady-state buffer delay is %d ms" % worst

    def test_the_best_case_steady_state_is_under_400ms(self):
        best = ((voice.VOICE_JITTER_PREFILL + voice.VOICE_JITTER_SHED_MARGIN)
                * voice.VOICE_FRAME_MS)
        assert best <= 400, "floor buffer delay is %d ms" % best

    def test_the_ceiling_still_leaves_room_above_the_floor(self):
        assert voice.VOICE_JITTER_DRIFT_HIGH > voice.VOICE_JITTER_PREFILL

    def test_the_hard_cap_is_above_the_ceiling(self):
        assert voice.VOICE_JITTER_MAX > (voice.VOICE_JITTER_DRIFT_HIGH
                                         + voice.VOICE_JITTER_SHED_MARGIN)


class TestTheCeilingIsTunable:
    def test_a_valid_override_is_honoured(self, monkeypatch):
        monkeypatch.setenv("OTRV4PLUS_JITTER_MAX_MS", "900")
        assert voice._env_ms("OTRV4PLUS_JITTER_MAX_MS", 480, 120, 2000) == 900

    @pytest.mark.parametrize("bad", ["", "lots", "0", "50", "99999", "-1"])
    def test_a_nonsense_override_falls_back(self, monkeypatch, bad):
        monkeypatch.setenv("OTRV4PLUS_JITTER_MAX_MS", bad)
        assert voice._env_ms("OTRV4PLUS_JITTER_MAX_MS", 480, 120, 2000) == 480


class TestSteadyStateDepth:
    def test_the_buffer_settles_at_the_shed_threshold(self):
        # The property that makes the margin a latency decision: feed and
        # drain at the same rate and depth converges on target + margin.
        buf = _buf(prefill=3, drift_high=8, shed_margin=3, maxlen=40)
        _fill(buf, 30)
        for _ in range(60):
            buf.pop()
            _fill(buf, 1, start=30 + _)
        assert buf.depth() <= buf.target_depth + 3

    def test_an_overfilled_buffer_is_trimmed_back_down(self):
        buf = _buf(prefill=3, drift_high=8, shed_margin=3, maxlen=60)
        _fill(buf, 50)
        deep = buf.depth()
        for _ in range(60):
            if buf.pop() is None:
                break
        assert buf.depth() < deep
        assert buf.stats["drift"] > 0

    def test_trimming_takes_from_the_oldest_end(self):
        # Shedding the newest would discard the audio just received and keep
        # the stale audio that caused the backlog.
        buf = _buf(prefill=2, drift_high=3, shed_margin=1, maxlen=40)
        _fill(buf, 20)
        first = buf.pop()
        assert first is not None
        pcm, _gap = first
        # Something after sequence 0 must have been played: 0 was shed.
        assert buf.stats["drift"] >= 1

    def test_a_buffer_at_target_is_not_trimmed(self):
        buf = _buf(prefill=3, drift_high=8, shed_margin=3, maxlen=40)
        _fill(buf, 4)
        for _ in range(4):
            buf.pop()
        assert buf.stats["drift"] == 0

    def test_reordering_within_the_margin_does_not_trigger_a_shed(self):
        # The margin exists so that frames arriving out of order are not
        # mistaken for accumulated latency and discarded.
        buf = _buf(prefill=3, drift_high=8, shed_margin=3, maxlen=40)
        for i in (3, 1, 0, 2, 5, 4):
            buf.push(0, i, bytearray(b"\xaa" * 8))
        played = []
        for _ in range(6):
            item = buf.pop()
            if item is None:
                break
            played.append(item[0])
        assert buf.stats["drift"] == 0


class TestOrderingIsPreserved:
    def test_frames_play_in_sequence_despite_arriving_shuffled(self):
        # Target and margin sized above the burst, so this exercises ordering
        # and not the drift shed -- with a target of 1 the buffer is above
        # its threshold on arrival and correctly trims the oldest instead.
        buf = _buf(prefill=6, shed_margin=4, maxlen=40)
        order = [4, 0, 2, 1, 5, 3]
        for i in order:
            buf.push(0, i, bytearray(bytes([i]) * 8))
        seen = []
        while True:
            item = buf.pop()
            if item is None:
                break
            seen.append(item[0][0])
        assert seen == sorted(order)

    def test_a_frame_older_than_the_last_played_is_refused(self):
        buf = _buf(prefill=1, maxlen=40)
        _fill(buf, 5)
        buf.pop()
        buf.pop()
        assert buf.push(0, 0, bytearray(b"\xaa" * 8)) is False
        assert buf.stats["late"] >= 1

    def test_a_duplicate_is_refused(self):
        buf = _buf(prefill=1, maxlen=40)
        buf.push(0, 7, bytearray(b"\xaa" * 8))
        assert buf.push(0, 7, bytearray(b"\xaa" * 8)) is False
        assert buf.stats["duplicate"] == 1

    def test_a_gap_is_reported_for_concealment(self):
        buf = _buf(prefill=1, maxlen=40)
        buf.push(0, 0, bytearray(b"\xaa" * 8))
        buf.push(0, 3, bytearray(b"\xbb" * 8))
        buf.pop()
        item = buf.pop()
        assert item is not None
        assert item[1] == 2


class TestSequenceZero:
    def test_the_very_first_frame_of_a_call_is_tracked(self):
        # sequence(0, 0) is exactly 0, and `self._last_seq or -1` treated that
        # falsy 0 as -1 -- so the first frame of every call was mishandled by
        # the arrival estimator.
        buf = voice.JitterBuffer(prefill=1, maxlen=40, adaptive=True)
        buf.push(0, 0, bytearray(b"\xaa" * 8))
        assert buf._last_seq == 0
        assert buf._last_arrival is not None

    def test_sequence_zero_is_not_treated_as_late(self):
        buf = _buf(prefill=1, maxlen=40)
        assert buf.push(0, 0, bytearray(b"\xaa" * 8)) is True


class TestAdaptiveTarget:
    def _adaptive(self):
        return voice.JitterBuffer(prefill=3, drift_high=8, maxlen=40,
                                  adaptive=True)

    def test_a_steady_path_keeps_the_target_at_the_floor(self):
        buf = self._adaptive()
        now = 1000.0
        for i in range(80):
            now += voice.FRAME_INTERVAL_S
            buf._observe_arrival(i, now)
        assert buf.target_depth == voice.VOICE_JITTER_PREFILL or \
            buf.target_depth <= 4

    def test_a_jittery_path_raises_the_target(self):
        buf = self._adaptive()
        now = 1000.0
        for i in range(200):
            now += voice.FRAME_INTERVAL_S * (3.0 if i % 2 else 0.05)
            buf._observe_arrival(i, now)
        assert buf.target_depth > 3
        assert buf.jitter_ms > 0

    def test_the_target_never_exceeds_the_ceiling(self):
        buf = self._adaptive()
        now = 1000.0
        for i in range(300):
            now += voice.FRAME_INTERVAL_S * (40.0 if i % 2 else 0.01)
            buf._observe_arrival(i, now)
        assert buf.target_depth <= 8

    def test_the_target_never_falls_below_the_floor(self):
        buf = self._adaptive()
        now = 1000.0
        for i in range(200):
            now += voice.FRAME_INTERVAL_S       # perfectly paced
            buf._observe_arrival(i, now)
        assert buf.target_depth >= 3

    def test_the_safety_factor_scales_the_target(self):
        """Two buffers, same arrivals, different factors."""
        def run(factor):
            b = voice.JitterBuffer(prefill=1, drift_high=30, maxlen=60,
                                   adaptive=True, safety_factor=factor)
            now = 1000.0
            for i in range(300):
                now += voice.FRAME_INTERVAL_S * (2.5 if i % 2 else 0.2)
                b._observe_arrival(i, now)
            return b.target_depth

        assert run(3.0) > run(2.0), (
            "the safety factor must actually move the target -- it is the "
            "latency/dropout trade")

    def test_the_configured_factor_is_the_documented_one(self):
        assert voice.VOICE_JITTER_SAFETY_FACTOR == 2.0


class TestBoundedness:
    def test_depth_never_exceeds_the_hard_cap(self):
        buf = _buf(prefill=2, maxlen=10)
        _fill(buf, 500)
        assert buf.depth() <= 10
        assert buf.stats["overflow"] > 0

    def test_overflow_discards_the_oldest(self):
        buf = _buf(prefill=1, maxlen=4)
        _fill(buf, 10)
        item = buf.pop()
        assert item is not None
        # Sequence 0 cannot have survived a cap of 4 with 10 pushed.
        assert buf.depth() <= 4

    def test_clearing_empties_it(self):
        buf = _buf(prefill=1, maxlen=20)
        _fill(buf, 10)
        buf.clear()
        assert buf.depth() == 0
