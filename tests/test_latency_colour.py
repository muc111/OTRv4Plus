"""Mouth-to-ear delay, coloured so a reading is a verdict at a glance.

The figure is the whole path a listener waits through -- network transit plus
our own dwell, decode and playout -- because that is what a person actually
experiences.

The BANDS are calibrated for I2P, and that changed at v10.28.1. They used to
be ITU-T G.114's terrestrial numbers (400 ms green, 800 ms amber), under
which this transport could not reach the top band at all: the project's own
soak median is 917 ms and a live two-handset call at 914 ms with 96.5% of its
audio delivered was reported red, "quality was poor". A scale that calls its
own median a fault is not strict, it is broken -- and it spends the colour
reserved for "something is wrong" on the ordinary case.

Three garlic-routed hops each way is closer to a satellite link than to a
phone network, and G.114 itself carves those out as outside its range and in
daily use anyway. So green is now the floor this path can reach (<=1000 ms),
amber is noticeably worse than the floor (<=1500 ms), and red is where
turn-taking breaks down. G.114's numbers are still named, and still one
environment variable away for a LAN or clearnet deployment.

These tests pin the boundaries, that every band is still REACHABLE (the real
property the old scale was reaching for), the fallbacks, and the two ways
colour can go wrong -- appearing where it will not render, and appearing on a
value that was never measured.
"""

import importlib
import os
import subprocess
import sys

import otrv4plus_voice as V


def _reload_with(**env):
    """Re-import the module under a different environment, in a subprocess.

    Doing it in-process would leave the module-level thresholds changed for
    whatever ran next.
    """
    code = (
        "import otrv4plus_voice as V;"
        "print(V.M2E_GOOD_MS, V.M2E_WARN_MS,"
        " V.latency_band(V.M2E_GOOD_MS), V.latency_band(V.M2E_WARN_MS + 1))"
    )
    child = dict(os.environ)
    child.pop("OTRV4PLUS_M2E_GOOD_MS", None)
    child.pop("OTRV4PLUS_M2E_WARN_MS", None)
    child.update({k: str(v) for k, v in env.items()})
    out = subprocess.run([sys.executable, "-c", code], capture_output=True,
                         text=True, env=child, cwd=os.getcwd())
    assert out.returncode == 0, out.stderr
    return out.stdout.split()


# ---------------------------------------------------------------------------
# bands
# ---------------------------------------------------------------------------

class TestBands:

    def test_the_green_edge_is_the_i2p_floor(self):
        assert V.M2E_GOOD_MS == 1000

    def test_the_terrestrial_scale_is_still_named(self):
        # Kept as constants rather than a comment so the legend, the README
        # and these tests cite one pair of numbers, not three copies.
        assert (V.G114_GOOD_MS, V.G114_WARN_MS) == (400, 800)

    def test_bands_are_ordered(self):
        assert V.M2E_GOOD_MS <= V.M2E_WARN_MS

    def test_good_up_to_and_including_the_boundary(self):
        assert V.latency_band(0) == "good"
        assert V.latency_band(V.M2E_GOOD_MS) == "good"

    def test_warn_above_it(self):
        assert V.latency_band(V.M2E_GOOD_MS + 1) == "warn"
        assert V.latency_band(V.M2E_WARN_MS) == "warn"

    def test_bad_above_the_second_boundary(self):
        assert V.latency_band(V.M2E_WARN_MS + 1) == "bad"
        assert V.latency_band(60000) == "bad"

    def test_an_unmeasured_value_has_no_band(self):
        assert V.latency_band(None) == "unknown"

    def test_a_healthy_i2p_call_reads_green(self):
        """This test used to assert the opposite, and it was wrong.

        It read: "measured medians on this transport were 494-688 ms one-way
        and ~1050 ms mouth-to-ear. If a change ever makes those read green,
        the scale has stopped meaning anything."

        The instinct is right -- a scale where everything is green says
        nothing -- but it anchored on the wrong property. Requiring a TYPICAL
        reading to be non-green pins this transport's median into a warning
        band permanently, and a live call at 914 ms with 96.5% of its audio
        delivered, which both people completed, was reported red: "quality
        was poor". A scale that cannot reach its top band on the only
        transport it runs on is not discriminating, it is stuck; and it burns
        the colour reserved for "something is wrong" on the ordinary case, so
        the day something IS wrong it has nothing left to say.

        What the guard actually wants is `test_the_scale_still_discriminates`
        below: every band reachable, and a bad call distinguishable from a
        normal one.
        """
        assert V.latency_band(914) == "good"        # the live two-handset call
        assert V.latency_band(917) == "good"        # the soak median

    def test_the_scale_still_discriminates(self):
        # Each band has a realistic I2P reading in it. This is the property
        # the old assertion was reaching for.
        readings = {V.latency_band(ms) for ms in (600, 914, 1200, 1900, 3000)}
        assert readings == {"good", "warn", "bad"}

    def test_a_call_well_past_the_floor_is_still_bad(self):
        # The floor is ~900 ms. Twice that is not "I2P being I2P", it is a
        # call in which people talk over each other.
        assert V.latency_band(1800) == "bad"

    def test_the_terrestrial_scale_can_be_restored(self):
        # A LAN or clearnet deployment wants G.114 back, and gets it without
        # a code change.
        good, warn, at_good, past_warn = _reload_with(
            OTRV4PLUS_M2E_GOOD_MS=V.G114_GOOD_MS,
            OTRV4PLUS_M2E_WARN_MS=V.G114_WARN_MS)
        assert (good, warn) == ("400", "800")
        assert (at_good, past_warn) == ("good", "bad")


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------

class TestRendering:

    def setup_method(self):
        self._saved = os.environ.get("OTRV4PLUS_FORCE_COLOR")
        os.environ["OTRV4PLUS_FORCE_COLOR"] = "1"

    def teardown_method(self):
        if self._saved is None:
            os.environ.pop("OTRV4PLUS_FORCE_COLOR", None)
        else:
            os.environ["OTRV4PLUS_FORCE_COLOR"] = self._saved

    def test_each_band_gets_its_own_colour(self):
        good = V.colour_latency(100)
        warn = V.colour_latency(1200)
        bad = V.colour_latency(2000)
        assert good.startswith("\033[92m") and good.endswith("\033[0m")
        assert warn.startswith("\033[93m")
        assert bad.startswith("\033[91m")
        assert len({good[:5], warn[:5], bad[:5]}) == 3

    def test_the_reading_survives_the_colouring(self):
        assert "600ms" in V.colour_latency(600)
        assert "1200ms" in V.colour_latency(1200)

    def test_an_unmeasured_value_is_never_coloured(self):
        # "-" in red would read as a bad measurement rather than none.
        assert V.colour_latency(None) == "-"
        assert "\033[" not in V.colour_latency(None)

    def test_a_caller_supplied_label_is_used(self):
        assert "mouth-to-ear" in V.colour_latency(100, "mouth-to-ear")

    def test_the_legend_names_both_thresholds(self):
        legend = V.latency_legend()
        assert str(V.M2E_GOOD_MS) in legend
        assert str(V.M2E_WARN_MS) in legend
        assert "\033[92m" in legend and "\033[91m" in legend


class TestWhereColourIsSuppressed:

    def test_no_color_is_honoured(self):
        saved = os.environ.get("NO_COLOR")
        os.environ["NO_COLOR"] = "1"
        try:
            assert "\033[" not in V.colour_latency(100)
        finally:
            if saved is None:
                os.environ.pop("NO_COLOR", None)
            else:
                os.environ["NO_COLOR"] = saved

    def test_a_redirected_stdout_gets_no_escape_codes(self):
        # pytest captures stdout, so isatty() is False here — which is
        # exactly the redirected case this must not pollute.
        saved = os.environ.pop("OTRV4PLUS_FORCE_COLOR", None)
        try:
            assert V.colour_latency(100) == "100ms"
        finally:
            if saved is not None:
                os.environ["OTRV4PLUS_FORCE_COLOR"] = saved


# ---------------------------------------------------------------------------
# retuning without a code change
# ---------------------------------------------------------------------------

class TestOverrides:

    def test_both_thresholds_are_tunable(self):
        good, warn, at_good, above_warn = _reload_with(
            OTRV4PLUS_M2E_GOOD_MS=700, OTRV4PLUS_M2E_WARN_MS=1500)
        assert (good, warn) == ("700", "1500")
        assert at_good == "good" and above_warn == "bad"

    def test_an_inverted_pair_cannot_produce_an_empty_band(self):
        good, warn, _at_good, _above = _reload_with(
            OTRV4PLUS_M2E_GOOD_MS=900, OTRV4PLUS_M2E_WARN_MS=100)
        assert int(warn) >= int(good), "warn band collapsed below good"

    def test_a_nonsense_value_falls_back_to_the_default(self):
        good, _warn, _a, _b = _reload_with(OTRV4PLUS_M2E_GOOD_MS="banana")
        assert good == "1000"


# ---------------------------------------------------------------------------
# where it is actually used
# ---------------------------------------------------------------------------

class TestWiring:

    def test_the_summary_line_bands_the_one_way_figure(self):
        import inspect
        src = inspect.getsource(V.LatencyTracker.summary)
        assert "colour_latency(ow)" in src

    def test_rtt_is_left_uncoloured(self):
        # RTT is a diagnostic; one-way is the half the listener waits through.
        import inspect
        src = inspect.getsource(V.LatencyTracker.summary)
        assert "colour_latency(rtt)" not in src

    def test_the_budget_line_bands_the_mouth_to_ear_total(self):
        import inspect
        src = inspect.getsource(V.VoiceCallManager._stats_loop)
        assert "mouth-to-ear ~%s" in src
        assert "colour_latency(m2e)" in src

    def test_the_legend_is_printed_once_per_call(self):
        import inspect
        src = inspect.getsource(V.VoiceCallManager._start_stats)
        assert "latency_legend()" in src

    def test_the_transcript_strips_the_escape_codes(self):
        # Colour is for the terminal. The on-disk transcript must stay plain.
        import otrv4plus_xmpp as X
        assert "\033[" not in X._ANSI_RE.sub("", V.colour_latency(100))
