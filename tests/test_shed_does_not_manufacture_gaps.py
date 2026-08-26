#!/usr/bin/env python3
"""The shedder must not make its own drops look like transit loss.

Measured on a live call after the playout write was fixed:

    arriving   16.24 frames/s
    played     13.03 frames/s
    shed       19.8% of everything received
    write p50  51 ms   -- the device could sustain ~19.5 pops/s

Playout had spare capacity and was still losing a fifth of the audio. The
mechanism was a feedback loop of the buffer's own making:

    depth over target  ->  shedder discards a frame
                       ->  its sequence number leaves a hole
                       ->  `gap` reports transit loss
                       ->  the worker writes FEC or concealment AS WELL AS
                          the real frame, so one pop costs two device writes
                       ->  each write blocks ~a frame period, so the pop rate
                          roughly halves
                       ->  the buffer grows, and the shedder fires harder

Concealment exists for frames that never arrived. A shed frame did arrive and
was dropped on purpose to cut latency, so synthesising a replacement spends
device time to undo the thing the drop was for. The buffer now advances its
played-marker as it sheds: consumed, not lost.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

voice = pytest.importorskip("otrv4plus_voice")


def _frame(n):
    return bytearray(b"\x00\x01" * 8) + bytes([n & 0xFF])


def _filled(depth, **kw):
    """A primed buffer holding `depth` consecutive frames from seq 0."""
    jb = voice.JitterBuffer(**kw)
    for i in range(depth):
        jb.push(0, i, _frame(i))
    return jb


def _push(jb, seq):
    jb.push(0, seq, _frame(seq))


class TestASheddingPopReportsNoGap:

    def test_the_shedder_advances_the_played_marker(self):
        jb = _filled(20)
        first = jb.pop()
        assert first is not None
        # Whatever it shed on the way, the frame it returns must not also ask
        # the caller to conceal the frames it deliberately dropped.
        _pcm, gap = first
        assert gap == 0, (
            "a pop that shed frames reported gap=%d, so the worker will write "
            "%d extra concealment frames for audio the buffer chose to drop"
            % (gap, gap))

    def test_no_pop_in_a_long_drain_ever_reports_a_gap(self):
        jb = _filled(40)
        gaps = []
        for _ in range(12):
            item = jb.pop()
            if item is None:
                break
            gaps.append(item[1])
        assert gaps, "the buffer returned nothing"
        assert set(gaps) == {0}, (
            "draining a burst manufactured gaps %s" % sorted(set(gaps)))

    def test_it_actually_shed_something(self):
        # Otherwise the assertions above pass for the wrong reason.
        jb = _filled(40)
        for _ in range(12):
            if jb.pop() is None:
                break
        assert jb.stats["drift"] > 0, "nothing was shed; the test proves nothing"


class TestRealLossIsStillReported:
    """The fix must not silence concealment for frames that never arrived."""

    def test_a_hole_in_the_arrivals_still_reports_a_gap(self):
        jb = voice.JitterBuffer()
        for i in (0, 1, 2, 4, 5, 6):        # 3 never arrives
            _push(jb, i)
        seen = []
        for _ in range(6):
            item = jb.pop()
            if item is None:
                break
            seen.append(item[1])
        assert any(g > 0 for g in seen), (
            "a genuinely lost frame no longer triggers concealment; FEC and "
            "PLC are now dead code")

    def test_the_gap_matches_the_number_actually_missing(self):
        jb = voice.JitterBuffer()
        for i in (0, 1, 2, 6, 7, 8):        # 3, 4, 5 never arrive
            _push(jb, i)
        gaps = []
        for _ in range(6):
            item = jb.pop()
            if item is None:
                break
            gaps.append(item[1])
        assert 3 in gaps, "expected a gap of 3, got %s" % gaps


class TestTheMarkerStaysMonotonic:

    def test_shedding_never_moves_the_marker_backwards(self):
        jb = _filled(30)
        last = -1
        for _ in range(10):
            if jb.pop() is None:
                break
            assert jb._last_played >= last
            last = jb._last_played

    def test_a_frame_older_than_a_shed_one_is_refused(self):
        """Having decided not to play it, do not accept it back later.

        Accepting it would put a sequence number behind the marker into the
        heap, where it is either played out of order or dropped again.
        """
        jb = _filled(30)
        jb.pop()
        marker = jb._last_played
        assert marker >= 0
        before = len(jb._heap)
        assert jb.push(0, marker - 1, _frame(0)) is False
        assert len(jb._heap) == before
