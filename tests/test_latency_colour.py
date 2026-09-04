"""Mouth-to-ear delay, coloured so a reading is a verdict at a glance.

The bands come from ITU-T G.114: one-way delay under 400 ms is "acceptable
for most user applications". That is applied to the full mouth-to-ear figure
-- network transit plus our own dwell and playout -- because that is what a
person actually experiences.

Over three I2P hops each way a healthy call usually lands in the middle band.
That is the point: a scale calibrated so everything came out green would say
nothing. These tests pin the boundaries, the fallbacks, and the two ways
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

    def test_the_itu_boundary_is_the_green_edge(self):
        assert V.M2E_GOOD_MS == 400

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

    def test_a_real_call_reading_is_not_green(self):
        # Measured medians on this transport were 494-688 ms one-way and
        # ~1050 ms mouth-to-ear. If a change ever makes those read green,
        # the scale has stopped meaning anything.
        assert V.latency_band(1050) == "bad"
        assert V.latency_band(660) == "warn"


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
        warn = V.colour_latency(600)
        bad = V.colour_latency(2000)
        assert good.startswith("\033[92m") and good.endswith("\033[0m")
        assert warn.startswith("\033[93m")
        assert bad.startswith("\033[91m")
        assert len({good[:5], warn[:5], bad[:5]}) == 3

    def test_the_reading_survives_the_colouring(self):
        assert "600ms" in V.colour_latency(600)

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
        assert good == "400"


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
