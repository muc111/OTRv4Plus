"""How deep the jitter buffer decides to be, and what it decides it from.

The v10.15.1 soak measured inter-arrival spacing of p50 69 ms, p95 128 ms,
p99 211 ms and max 281 ms against a 60 ms expected spacing.  The median frame
is 9 ms late; the p99 frame is 151 ms late.  The tail is sixteen times the
median, and it is the tail that empties a buffer.

The target was sized from RFC 3550's J -- a smoothed MEAN absolute deviation
-- doubled.  On that distribution 2xJ asks for under two frames, so the target
pinned at the hand-set floor and the adaptive machinery never once bound.  The
soak's own counters say what happened next: ``underrun=27 shed=313``.  Both at
the same time is not a buffer that is too deep or too shallow, it is a buffer
that never settles.

Two things changed at v10.29.0, and these tests are about both:

  * the target is sized from the measured LATENESS TAIL as well as the mean.
    The distribution was already being collected -- `self.spacing` exists for
    exactly this, and its comment says a mean deviation "cannot distinguish a
    steadily late path from a punctual one with a long tail, and only the
    second is worth buffering for" -- and was then only ever printed;

  * an underrun buys a frame of depth.  It is the only DIRECT evidence that
    the buffer was too shallow, and nothing used it: the target after the
    soak's twenty-seventh underrun was what it had been before the first.

Because depth is now earned from evidence, the static floor could come down.
That is the latency win, and it is only safe while the mechanism above works,
so most of what follows is about the mechanism rather than the constant.
"""

import otrv4plus_voice as V


FRAME = V.VOICE_FRAME_MS / 1000.0


def buf(**kw):
    """A buffer with the shipped defaults unless a test says otherwise."""
    return V.JitterBuffer(**kw)


def arrive(b, n, late_s=0.0, start_seq=0, t0=0.0):
    """Feed `n` arrivals, each `late_s` later than its expected time.

    Drives `_observe_arrival` directly rather than `push`, because the target
    is a function of ARRIVAL TIMING alone -- what the frames contain, and
    whether they are subsequently played, has nothing to do with it.
    """
    t = t0
    for i in range(n):
        t += FRAME + late_s
        b._observe_arrival(V.JitterBuffer.sequence(0, start_seq + i), t)
    return t


# ---------------------------------------------------------------------------
# the tail estimator
# ---------------------------------------------------------------------------

class TestTheTargetSeesTheTail:

    def test_a_punctual_path_sits_on_the_floor(self):
        b = buf()
        arrive(b, 100, late_s=0.0)
        assert b.target_depth == V.VOICE_JITTER_PREFILL

    def test_a_late_tail_raises_the_target(self):
        # Every frame two frames late: the buffer must carry that.
        b = buf()
        arrive(b, 100, late_s=2 * FRAME)
        assert b.target_depth > V.VOICE_JITTER_PREFILL

    def test_earliness_is_not_charged_as_risk(self):
        """A frame that arrives EARLY costs the buffer nothing.

        RFC 3550's D is symmetric, so it charges a path that runs ahead
        exactly as much as one that runs behind. Only lateness can empty a
        buffer, so only lateness is recorded.
        """
        b = buf()
        arrive(b, 100, late_s=-0.4 * FRAME)
        assert b._tail_frames() == 0.0

    def test_the_tail_is_a_percentile_not_a_maximum(self):
        # One catastrophic arrival in a hundred must not hold the buffer deep
        # for the rest of the call. That is what the p99 costs and why p95 is
        # the default: 150 ms on every frame to save one dropout in a hundred.
        b = buf()
        arrive(b, 99, late_s=0.0)
        arrive(b, 1, late_s=10 * FRAME, start_seq=99, t0=1000.0)
        assert b._tail_frames() < 1.0

    def test_the_window_forgets(self):
        """A lifetime percentile cannot recover.

        One bad tunnel minute would hold the buffer deep for the rest of the
        call, which is the exact failure the adaptive target exists to avoid.
        """
        b = buf()
        arrive(b, V.VOICE_JITTER_TAIL_WINDOW, late_s=3 * FRAME)
        deep = b._tail_frames()
        assert deep > 1.0
        arrive(b, V.VOICE_JITTER_TAIL_WINDOW, late_s=0.0,
               start_seq=V.VOICE_JITTER_TAIL_WINDOW, t0=10000.0)
        assert b._tail_frames() < deep

    def test_too_few_samples_claims_nothing(self):
        b = buf()
        arrive(b, 3, late_s=5 * FRAME)
        assert b._tail_frames() == 0.0

    def test_the_tail_catches_what_the_mean_misses(self):
        """The mutation that survives without this: `frames = mean_frames`.

        This is the whole defect. A path that is punctual 90% of the time and
        three frames late the rest has a small MEAN deviation and a tail that
        empties the buffer. RFC 3550's J is an average, so it prices that
        path as if the late frames were not there -- which is exactly the
        measured path, whose p50 is 9 ms late and whose p99 is 151 ms late.
        """
        b = buf()
        t = 0.0
        for i in range(200):
            late = 3 * FRAME if i % 10 == 0 else 0.0
            t += FRAME + late
            b._observe_arrival(V.JitterBuffer.sequence(0, i), t)
        mean_frames = (V.VOICE_JITTER_SAFETY_FACTOR * b._jitter_est) / FRAME
        assert b._tail_frames() > mean_frames, (
            "the tail must ask for more than the mean on a bursty path, or "
            "there is no reason for it to exist")
        # The mean alone would not have moved the target off the floor at
        # all -- which is the observed behaviour this replaces, and the
        # reason asserting `target > mean + 1` is not enough: the floor
        # satisfies that on its own.
        assert int(mean_frames + 1.0) <= V.VOICE_JITTER_PREFILL
        assert b.target_depth > V.VOICE_JITTER_PREFILL

    def test_the_larger_estimator_wins(self):
        """Mean and tail are both kept, and neither is allowed to veto.

        The mean responds within a frame or two and catches a path that has
        just got worse; the tail is slower but is the only one that sees the
        arrivals that actually empty the buffer.
        """
        b = buf()
        arrive(b, 100, late_s=2 * FRAME)
        assert b._tail_frames() > 0
        assert b._jitter_est > 0
        # The target reflects at least the larger of the two, plus a frame.
        assert b.target_depth >= int(b._tail_frames() + 1)

    def test_the_ceiling_still_binds(self):
        b = buf()
        arrive(b, 200, late_s=50 * FRAME)
        assert b.target_depth <= V.VOICE_JITTER_DRIFT_HIGH


# ---------------------------------------------------------------------------
# learning from underruns
# ---------------------------------------------------------------------------

class TestAnUnderrunBuysDepth:

    def test_it_starts_owing_nothing(self):
        assert buf().learned_frames == 0

    def test_an_underrun_raises_the_target(self):
        b = buf()
        before = b.target_depth
        b.note_underrun()
        assert b.target_depth > before
        assert b.learned_frames == V.VOICE_JITTER_UNDERRUN_STEP

    def test_running_dry_through_pop_records_it(self):
        # Wired to the real path, not only callable in isolation: the soak
        # underran 27 times and the target never moved.
        b = buf()
        b._primed = True
        assert b.pop() is None
        assert b.learned_frames > 0

    def test_it_cannot_walk_past_the_ceiling(self):
        b = buf()
        for _ in range(500):
            b.note_underrun()
        assert b.target_depth <= V.VOICE_JITTER_DRIFT_HIGH

    def test_it_cannot_walk_past_the_ceiling_from_an_already_deep_target(self):
        """The ceiling applies to the SUM, not to the learned part alone.

        A path bad enough to underrun repeatedly must not be able to walk the
        buffer past the latency cap one dropout at a time.
        OTRV4PLUS_JITTER_MAX_MS is the last word on depth, and a buffer that
        can be argued past it by the very path it is meant to survive is not
        a cap.
        """
        b = buf()
        arrive(b, 200, late_s=4 * FRAME)        # target already well up
        assert b._target > V.VOICE_JITTER_PREFILL
        for _ in range(500):
            b.note_underrun()
        assert b.target_depth <= V.VOICE_JITTER_DRIFT_HIGH

    def test_depth_is_given_back_after_a_clean_run(self):
        b = buf()
        b.note_underrun()
        held = b.learned_frames
        for _ in range(V.VOICE_JITTER_UNDERRUN_DECAY):
            b._note_clean_pop()
        assert b.learned_frames == held - 1

    def test_playing_frames_is_what_gives_depth_back(self):
        """Driven through the real pop(), not by calling the decay directly.

        The mutation this catches removes `_note_clean_pop()` from `pop()`:
        every unit test of the decay still passes, and on a real call the
        buffer keeps every frame it ever bought for the rest of the session.
        """
        b = buf()
        b.note_underrun()
        held = b.learned_frames
        assert held > 0
        seq = 0
        for _ in range(V.VOICE_JITTER_UNDERRUN_DECAY + 50):
            # Keep it primed and fed so each pop is a clean one.
            while len(b._heap) <= b.target_depth:
                b.push(0, seq, bytearray(V.VOICE_FRAME_BYTES))
                seq += 1
            assert b.pop() is not None
        assert b.learned_frames < held

    def test_it_rises_faster_than_it_falls(self):
        """Asymmetric on purpose.

        A dropout is immediate and audible; the latency paid to avoid the
        next one is quiet. One underrun buys a frame at once, and it takes a
        few hundred clean frames to give it back.
        """
        b = buf()
        b.note_underrun()
        b._note_clean_pop()
        assert b.learned_frames == V.VOICE_JITTER_UNDERRUN_STEP

    def test_a_clean_run_cannot_go_negative(self):
        b = buf()
        for _ in range(5 * V.VOICE_JITTER_UNDERRUN_DECAY):
            b._note_clean_pop()
        assert b.learned_frames == 0

    def test_a_fresh_underrun_restarts_the_decay(self):
        b = buf()
        b.note_underrun()
        b.note_underrun()
        for _ in range(V.VOICE_JITTER_UNDERRUN_DECAY - 1):
            b._note_clean_pop()
        b.note_underrun()                      # resets the clean run
        for _ in range(V.VOICE_JITTER_UNDERRUN_DECAY - 1):
            b._note_clean_pop()
        assert b.learned_frames == min(3 * V.VOICE_JITTER_UNDERRUN_STEP,
                                       V.VOICE_JITTER_DRIFT_HIGH
                                       - V.VOICE_JITTER_PREFILL)


# ---------------------------------------------------------------------------
# the floor that came down because of all of the above
# ---------------------------------------------------------------------------

class TestTheFloor:

    def test_the_floor_is_two_frames(self):
        assert V.VOICE_JITTER_PREFILL_MS == 120
        assert V.VOICE_JITTER_PREFILL == 120 // V.VOICE_FRAME_MS

    def test_the_shed_margin_came_down_too(self):
        # The cheapest 60 ms in the budget: the margin is hysteresis above
        # the target, and it is the TARGET that guards against a dropout.
        assert V.VOICE_JITTER_SHED_MARGIN_MS == 120

    def test_the_old_floor_is_one_variable_away(self):
        import os
        import subprocess
        import sys
        env = dict(os.environ, OTRV4PLUS_JITTER_MIN_MS="180")
        out = subprocess.run(
            [sys.executable, "-c",
             "import otrv4plus_voice as V;print(V.VOICE_JITTER_PREFILL_MS)"],
            capture_output=True, text=True, env=env, cwd=os.getcwd())
        assert out.returncode == 0, out.stderr
        assert out.stdout.strip() == "180"

    def test_the_floor_is_still_a_floor(self):
        # However good the path looks, the buffer does not go below it.
        b = buf()
        arrive(b, 200, late_s=0.0)
        assert b.target_depth >= V.VOICE_JITTER_PREFILL


# ---------------------------------------------------------------------------
# the measured path, replayed
# ---------------------------------------------------------------------------

class TestTheMeasuredPath:

    def _soak_arrivals(self, b, n=400):
        """Spacing shaped like the soak: p50 69 ms, p95 128 ms, p99 211 ms."""
        import random
        rng = random.Random(20260905)
        t = 0.0
        for i in range(n):
            r = rng.random()
            if r < 0.50:
                spacing = 0.069
            elif r < 0.95:
                spacing = 0.069 + (0.128 - 0.069) * rng.random()
            elif r < 0.99:
                spacing = 0.128 + (0.211 - 0.128) * rng.random()
            else:
                spacing = 0.211 + (0.281 - 0.211) * rng.random()
            t += spacing
            b._observe_arrival(V.JitterBuffer.sequence(0, i), t)
        return t

    def test_the_target_now_responds_to_this_path(self):
        """The whole point: on the measured distribution the target MOVES.

        Under the mean-only estimator it sat on the floor for the entire
        call, whatever the path did.
        """
        b = buf()
        self._soak_arrivals(b)
        assert b._tail_frames() > 0.0

    def test_it_does_not_ask_for_the_worst_case(self):
        # The max spacing is 281 ms, 3.7 frames late. Buying that on every
        # frame is what the p99/max would cost and is not the trade being
        # made here.
        b = buf()
        self._soak_arrivals(b)
        assert b.target_depth < V.VOICE_JITTER_DRIFT_HIGH

    def test_the_steady_state_band_is_shallower_than_it_was(self):
        """Steady-state depth is the shed trigger: target + margin.

        The soak measured 229 ms of dwell under a trigger of 3+3=6 frames.
        The trigger is now lower, so the band the buffer settles in is too --
        and that is the mouth-to-ear saving, the only part of the 855 ms
        budget this client controls.
        """
        b = buf()
        self._soak_arrivals(b)
        trigger_frames = b.target_depth + V.VOICE_JITTER_SHED_MARGIN
        old_trigger_frames = (180 // V.VOICE_FRAME_MS) + (180
                                                          // V.VOICE_FRAME_MS)
        assert trigger_frames <= old_trigger_frames
