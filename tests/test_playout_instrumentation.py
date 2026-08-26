#!/usr/bin/env python3
"""The playout split, and the counter labels that misled a diagnosis.

A 1960 s call showed `play` at p50 95-102 ms against a 60 ms frame period.
Frames arrived at 15.66/s, were played at 10.55/s, and the jitter buffer shed
the 32.6% difference -- eight times more audio destroyed locally than the
network lost. None of that was visible in the counters:

  * `play` was one number covering both the pure-Python resample/upmix and the
    blocking device write. Those fail for opposite reasons and have opposite
    fixes, so a single figure cannot say which is happening. An outside review
    read the total and concluded "sender clock slightly fast", which the
    arrival rate contradicts.
  * The telemetry printed `discard=` for `stats["drift"]` and `overrun=` for
    `stats["overflow"]`. The labels did not name the counters.
  * `/audioprobe` collected the playback device parameters and printed none of
    them, so the one command that would have answered the question did not.
"""

import ast
import inspect
import os
import sys
import textwrap

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

audio = pytest.importorskip("otrv4plus_audio")
voice = pytest.importorskip("otrv4plus_voice")


class TestTheWriteIsSplit:

    def test_both_halves_are_recorded_stages(self):
        assert "conv" in voice.StageTimers.NAMES
        assert "write" in voice.StageTimers.NAMES
        assert "play" in voice.StageTimers.NAMES, (
            "the combined figure is still worth keeping: it is what the "
            "budget line uses")

    def test_every_stream_answers_the_question(self):
        # Defaults on the base class, so a backend that does not measure the
        # split reports zero rather than raising or silently omitting it.
        assert audio.AudioStream.last_convert_s == 0.0
        assert audio.AudioStream.last_device_s == 0.0

    def test_the_aaudio_write_measures_conversion_apart_from_the_device(self):
        src = textwrap.dedent(
            inspect.getsource(audio.AAudioPlayback.write_frame))
        tree = ast.parse(src)
        assigned = {t.attr for n in ast.walk(tree)
                    if isinstance(n, ast.Assign)
                    for t in n.targets if isinstance(t, ast.Attribute)}
        assert "last_convert_s" in assigned
        assert "last_device_s" in assigned

    def test_the_device_timer_starts_after_the_conversion(self):
        """Otherwise the split is a lie: conversion cost would land in both."""
        src = textwrap.dedent(
            inspect.getsource(audio.AAudioPlayback.write_frame))
        conv_at = src.index("last_convert_s")
        t1_at = src.index("_t1 = time.monotonic()")
        assert conv_at < t1_at, (
            "the device timer starts before the conversion is measured")

    def test_no_return_after_the_device_timer_starts_leaves_it_stale(self):
        """Once the device write has begun, every way out must record how long
        it took. A path that returns without doing so leaves the PREVIOUS
        frame's figure in place, which is worse than no reading -- it still
        looks like a measurement.

        Scoped to returns after the timer starts. The guard returns above it
        run before any device work and correctly report the 0.0 reset.
        """
        src = textwrap.dedent(
            inspect.getsource(audio.AAudioPlayback.write_frame))
        fn = ast.parse(src).body[0]

        t1 = [n.lineno for n in ast.walk(fn)
              if isinstance(n, ast.Assign)
              and any(isinstance(t, ast.Name) and t.id == "_t1"
                      for t in n.targets)]
        assert t1, "the device timer is gone"
        t1 = min(t1)

        stamps = sorted(n.lineno for n in ast.walk(fn)
                        if isinstance(n, ast.Assign)
                        and n.lineno > t1
                        and any(isinstance(t, ast.Attribute)
                                and t.attr == "last_device_s"
                                for t in n.targets))
        stale = [n.lineno for n in ast.walk(fn)
                 if isinstance(n, ast.Return)
                 and n.lineno > t1
                 and not any(s < n.lineno for s in stamps)]
        assert not stale, (
            "returns at lines %s exit after the device write began without "
            "recording its duration" % stale)

    def test_the_voice_layer_records_both(self):
        src = inspect.getsource(voice.VoiceCallSession)
        assert 'record(\n' in src or 'record("conv"' in src
        assert '"conv"' in src and '"write"' in src


class TestTheCountersAreNamedAfterWhatTheyCount:

    def test_the_labels_match_the_stats_keys(self):
        """`discard=` printed stats["drift"] and `overrun=` printed
        stats["overflow"]. Reading the label instead of the source produced a
        wrong mechanism in an outside review."""
        src = inspect.getsource(voice.VoiceCallManager)
        i = src.index("buffer depth %d-%d frames")
        window = src[i:i + 1200]
        assert "shed=%d" in window, "the shed counter is mislabelled again"
        assert "overflow=%d" in window, "the overflow counter is mislabelled again"
        assert "discard=%d" not in window
        assert "overrun=%d" not in window

    def test_the_shed_counter_still_counts_shed_frames(self):
        src = inspect.getsource(voice.JitterBuffer.pop)
        assert 'stats["drift"] += 1' in src, (
            "the counter the telemetry calls `shed` no longer counts frames "
            "dropped by the shedder")


class TestTheProbeReportsThePlaybackDevice:

    def test_it_prints_what_it_already_collected(self):
        """Assert on the format STRING, not on the field names.

        The names appear in the `d.get(...)` arguments whether or not the
        format string still has a slot for them, so checking for the names
        passes on a gutted line.
        """
        src = inspect.getsource(audio.probe)
        fmt = [n.value for n in ast.walk(ast.parse(textwrap.dedent(src)))
               if isinstance(n, ast.Constant) and isinstance(n.value, str)]
        joined = "".join(fmt)
        assert "playback OK  rate=%s" in joined
        for slot in ("burst=%s", "capacity=%s", "ch=%s", "resample=%s"):
            assert slot in joined, (
                "the probe no longer prints %s for playback" % slot)

    def test_it_flags_a_buffer_smaller_than_one_frame(self):
        src = inspect.getsource(audio.probe)
        assert "capacity holds" in src

    def test_a_failed_playback_still_reports_its_detail(self):
        src = inspect.getsource(audio.probe)
        i = src.index("playback FAILED")
        assert "detail" in src[i:i + 300], (
            "a playback failure prints a code with no detail")


class TestTheCallLogsThePlayoutDevice:

    def test_every_call_records_the_playout_parameters(self):
        """Not only when someone thinks to run /audioprobe. A playout deficit
        does not show up in the frame counters -- the buffer sheds the surplus
        and the call reads healthy.

        Asserts the string reaches `_print`, not merely that it exists: a
        literal assigned to a dead local is still in the source.
        """
        src = textwrap.dedent(inspect.getsource(voice.VoiceCallSession))
        tree = ast.parse(src)
        printed = []
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "_print"):
                continue
            printed += [c.value for c in ast.walk(node)
                        if isinstance(c, ast.Constant)
                        and isinstance(c.value, str)]
        joined = "".join(printed)
        assert "[voice] playout:" in joined, (
            "the playout parameters are no longer printed")
        for slot in ("burst %s frames", "capacity %s frames"):
            assert slot in joined, "the playout line dropped %s" % slot

    def test_it_never_takes_the_call_down(self):
        src = inspect.getsource(voice.VoiceCallSession)
        i = src.index("[voice] playout:")
        tail = src[i:i + 1400]
        assert "except Exception" in tail, (
            "diagnostics that can raise are wrapped nowhere; a telemetry line "
            "must not be able to fail a call")
