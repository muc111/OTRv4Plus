"""What the terminal says about a call: at the start, and at the end.

Two complaints from the handsets drove this, and both are about a person
watching a call rather than a developer reading a log.

The first: bringing a call up printed fourteen lines of codec settings, gain
figures, buffer geometry and Android stream routing, and not one word about
the cryptography.  A user could not tell a post-quantum call from a classical
one, and on a phone the one line that mattered -- that the call was live --
had already scrolled away.

The second: hanging up printed a packet tally.  That says whether the
SOFTWARE worked.  It does not say whether the CALL worked, and the two
figures that answer that -- how long speech took to reach an ear, and how
much of it arrived -- were already being computed, for the debug stream,
where nobody on a call would ever see them.

The tests below pin the parts of that which can go quietly wrong: the summary
read after teardown (which reports zeros that look like measurements), a
delivery ratio built from a counter that mixes send and receive failures, a
verdict that goes green on a call that lost a fifth of its audio, and a
report that raises and takes the hangup with it.
"""

import time

import pytest

import otrv4plus_voice as V


# ---------------------------------------------------------------------------
# fakes
# ---------------------------------------------------------------------------

class _Pct:
    def __init__(self, value=0.0):
        self.value = float(value)

    def percentile(self, _q):
        return self.value


class _Latency:
    def __init__(self, oneway=None):
        self.oneway_ms = oneway


class _Jitter:
    def __init__(self, queued=0, gaps=0, dwell=0.0, drift=0):
        self.stats = {"queued": queued, "gaps": gaps, "drift": drift}
        self.dwell = _Pct(dwell)


class _Stages:
    def __init__(self, decode=0.0, play=0.0):
        self.t = {"decode": _Pct(decode), "play": _Pct(play)}


class FakeSession:
    """Only the surface `_call_summary` and `security_line` actually read."""

    def __init__(self, *, age_s=120.0, oneway=None, dwell=0.0, decode=0.0,
                 play=0.0, queued=0, gaps=0, drift=0, sent=0,
                 constant_rate=True, transport=None):
        self.peer = "peer@example.i2p"
        self._call_t0 = time.monotonic() - age_s
        self.latency = _Latency(oneway)
        self.jitter = _Jitter(queued, gaps, dwell, drift)
        self.stages = _Stages(decode, play)
        self.stats = {"sent": sent, "recv": queued, "dropped": 0,
                      "auth_fail": 0, "replay": 0}
        self.constant_rate = constant_rate
        self._transport_mode = (V.VOICE_TRANSPORT_DATAGRAM
                                if transport is None else transport)
        self.ended = False

    # The real one is async and tears the buffers down.
    async def end(self):
        self.ended = True
        self.latency = _Latency(None)
        self.jitter = _Jitter(0, 0, 0.0)
        self.stages = _Stages(0.0, 0.0)
        out = dict(self.stats)
        self.stats = {k: 0 for k in self.stats}
        return out

    security_line = V.VoiceCallSession.security_line


def voice_manager_shed_limit():
    return V.VoiceCallManager.CALL_MAX_SHED


def manager():
    """A manager with only the attributes the reporting paths touch.

    Built without __init__ deliberately: the real constructor opens a control
    FIFO and rate limiters, none of which has anything to do with printing a
    summary, and a test that needed them would break every time one changed.
    """
    mgr = object.__new__(V.VoiceCallManager)
    mgr._debug = False
    mgr._debug_t0 = {}
    return mgr


@pytest.fixture
def printed(monkeypatch):
    lines = []
    monkeypatch.setitem(V._HOST, "print", lambda *a: lines.append(" ".join(
        str(x) for x in a)))
    return lines


@pytest.fixture(autouse=True)
def _quiet_verbose(monkeypatch):
    """Each test starts with the setup detail OFF, and leaves it that way."""
    monkeypatch.setattr(V, "VOICE_VERBOSE", False)
    yield
    monkeypatch.setattr(V, "VOICE_VERBOSE", False)


# ---------------------------------------------------------------------------
# the security line
# ---------------------------------------------------------------------------

class TestTheCallSaysWhatProtectsIt:

    def test_it_names_the_suite(self):
        line = FakeSession().security_line()
        assert V.VOICE_SUITE_NAME in line

    def test_the_suite_is_the_hybrid_and_the_aead(self):
        # The three things a user is entitled to be told, and the reason the
        # name is a constant rather than three strings assembled at each
        # call site: X448 alone is not post-quantum, ML-KEM alone is not
        # classically safe, and neither encrypts a frame.
        assert "X448" in V.VOICE_SUITE_NAME
        assert "ML-KEM-1024" in V.VOICE_SUITE_NAME
        assert "AES-256-GCM" in V.VOICE_SUITE_NAME

    def test_it_names_the_transport(self):
        dgram = FakeSession(transport=V.VOICE_TRANSPORT_DATAGRAM)
        assert "datagram" in dgram.security_line()

    def test_a_stream_call_says_streams(self):
        other = [m for m in (V.VOICE_TRANSPORT_DATAGRAM, "stream")
                 if m != V.VOICE_TRANSPORT_DATAGRAM][0]
        assert "stream" in FakeSession(transport=other).security_line()

    def test_it_promises_shaping_only_when_shaping_holds(self):
        assert "NOT constant-rate" not in FakeSession(
            constant_rate=True).security_line()

    def test_a_call_that_could_not_shape_says_so(self):
        # The whole reason this line is built rather than written down: if
        # VBR or DTX could not be disabled the traffic leaks conversation
        # rhythm, and a fixed string would tell the user otherwise.
        assert "NOT constant-rate" in FakeSession(
            constant_rate=False).security_line()

    def test_it_says_the_keys_do_not_outlive_the_call(self):
        line = FakeSession().security_line()
        assert "zeroized" in line

    def test_announcing_it_prints_it(self, printed):
        manager()._announce_security(FakeSession())
        assert any(V.VOICE_SUITE_NAME in ln for ln in printed)

    def test_announcing_it_never_raises(self, printed):
        class Broken:
            peer = "p"

            def security_line(self):
                raise RuntimeError("boom")

        manager()._announce_security(Broken())          # must not raise

    def test_it_prints_even_with_the_setup_detail_off(self, printed):
        # It is not part of the noise that was demoted. A user who never
        # types /voicedebug still learns what the call is protected by.
        assert V.VOICE_VERBOSE is False
        manager()._announce_security(FakeSession())
        assert printed


# ---------------------------------------------------------------------------
# the verdict
# ---------------------------------------------------------------------------

class TestTheVerdict:

    def _line(self, **kw):
        return manager()._call_summary(FakeSession(**kw))[0]

    def test_a_fast_complete_call_is_green(self):
        line = self._line(oneway=100.0, queued=1000, gaps=0)
        assert "🟢" in line and "good" in line

    def test_a_slow_call_is_not_green(self):
        # Between the two bands: usable, but not a call anybody would call
        # good on this transport.
        line = self._line(oneway=float(V.M2E_WARN_MS - 10), queued=1000,
                          gaps=0)
        assert "🟡" in line
        assert "🟢" not in line

    def test_a_very_slow_call_is_red(self):
        line = self._line(oneway=float(V.M2E_WARN_MS + 200), queued=1000,
                          gaps=0)
        assert "🔴" in line

    def test_a_lossy_call_is_red_even_when_it_was_fast(self):
        # The failure this exists to catch: delay and loss are independent,
        # and a call with a fifth of its audio missing was not a good call
        # however quickly the rest of it arrived.
        line = self._line(oneway=50.0, queued=800, gaps=200)
        assert "🔴" in line
        assert "🟢" not in line

    def test_the_delivery_threshold_is_where_it_says_it_is(self):
        good = V.VoiceCallManager.CALL_GOOD_DELIVERY
        assert 0.5 < good < 1.0
        total = 10000
        at = int(round(good * total))
        assert "🟢" in self._line(oneway=50.0, queued=at, gaps=total - at)
        assert "🔴" in self._line(oneway=50.0, queued=at - 1,
                                  gaps=total - at + 1)

    def test_the_delay_that_is_judged_is_mouth_to_ear_not_the_network(self):
        # Network transit alone would be green here. The frame still has to
        # sit in the jitter buffer, be decoded and be written to the device,
        # and the user hears the sum.
        network_only = float(V.M2E_GOOD_MS - 50)
        assert V.latency_band(network_only) == "good"
        line = self._line(oneway=network_only, dwell=120.0, decode=20.0,
                          play=30.0, queued=1000, gaps=0)
        assert "🟢" not in line

    def test_the_live_two_handset_call_reads_green(self):
        """The measured call, replayed through the summary.

        1m51s, 914 ms mouth-to-ear, 96.5% delivered, 2.6% shed, 1068 frames.
        Both people completed it. Under the pre-v10.28.1 G.114 bands this
        printed "🔴 quality was poor", which is the reading that showed the
        scale was calibrated for a telephone network rather than for three
        garlic-routed hops each way.
        """
        line = manager()._call_summary(FakeSession(
            age_s=111.0, oneway=914.0, queued=965, gaps=35, drift=26,
            sent=1068))[0]
        assert "🟢" in line
        assert "quality was poor" not in line

    def test_a_call_with_nothing_measured_claims_nothing(self):
        line = self._line(age_s=3.0, oneway=None, queued=0, gaps=0)
        assert "🟢" not in line and "🔴" not in line and "🟡" not in line


# ---------------------------------------------------------------------------
# the figures
# ---------------------------------------------------------------------------

class TestTheFigures:

    def _line(self, **kw):
        return manager()._call_summary(FakeSession(**kw))[0]

    def test_it_reports_mouth_to_ear(self):
        assert "mouth-to-ear" in self._line(oneway=100.0, queued=10)

    def test_mouth_to_ear_is_the_sum_of_the_stages(self):
        line = self._line(oneway=100.0, dwell=40.0, decode=10.0, play=20.0,
                          queued=10)
        assert "170ms" in line

    def test_an_unmeasured_call_says_so_rather_than_printing_a_dash(self):
        # "-" reads as a bad reading. On a short call the probes simply have
        # not answered yet, which is not a fault and must not look like one.
        line = self._line(age_s=4.0, oneway=None)
        assert "not measured" in line
        assert "too short" in line

    def test_a_long_call_with_no_probes_does_not_blame_the_length(self):
        line = self._line(age_s=600.0, oneway=None)
        assert "not measured" in line
        assert "too short" not in line

    def test_delivery_is_a_percentage(self):
        assert "99.5% of audio delivered" in self._line(
            oneway=50.0, queued=1990, gaps=10)

    def test_delivery_ignores_send_side_drops(self):
        # The bug this pins: recv/(recv+dropped) mixes our own send failures
        # into a figure about what the LISTENER heard, so a call that could
        # not transmit would be reported as one that could not receive.
        session = FakeSession(oneway=50.0, queued=1000, gaps=0)
        session.stats["dropped"] = 5000
        line = manager()._call_summary(session)[0]
        assert "100.0% of audio delivered" in line

    def test_the_duration_is_wall_clock(self):
        assert "2m14s" in self._line(age_s=134.0, oneway=50.0)

    def test_a_short_call_is_reported_in_seconds(self):
        assert "9s" in self._line(age_s=9.4, oneway=50.0)

    def test_the_duration_is_not_the_masked_frame_stamp(self):
        # LatencyTracker.call_ms() is a frame timestamp with a random
        # per-call origin, not an elapsed time. Reading it here once printed
        # a two-minute call as several weeks.
        line = self._line(age_s=134.0, oneway=50.0)
        assert "2m14s" in line
        assert "m" == line[line.index("2m14s") + 1]

    def test_audio_thrown_away_locally_is_reported(self):
        # The number the 1960 s diagnosis needed and never had. The jitter
        # buffer sheds frames to pull latency down, a shed frame advances the
        # playout marker so it leaves no gap, and every counter therefore
        # read healthy while a third of the call was destroyed here.
        line = self._line(oneway=50.0, queued=1000, gaps=0, drift=330)
        assert "shed locally" in line

    def test_a_call_that_shed_nothing_says_nothing_about_it(self):
        line = self._line(oneway=50.0, queued=1000, gaps=0, drift=0)
        assert "shed" not in line

    def test_shedding_is_not_counted_as_loss(self):
        # It is not loss: the frames arrived and we discarded them. The
        # delivery figure must stay honest about what the network did.
        line = self._line(oneway=50.0, queued=1000, gaps=0, drift=330)
        assert "100.0% of audio delivered" in line

    def test_heavy_shedding_makes_the_call_bad(self):
        line = self._line(oneway=50.0, queued=1000, gaps=0, drift=330)
        assert "🔴" in line
        assert "🟢" not in line

    def test_a_little_shedding_is_still_a_good_call(self):
        # Shedding in small amounts is the mechanism working: it is how a
        # call that started on a congested path gets its latency back.
        # `queued` counts every frame the buffer accepted, shed ones
        # included, so it IS the denominator -- not the survivors.
        total = 1000
        drift = int(voice_manager_shed_limit() * total)
        line = self._line(oneway=50.0, queued=total, gaps=0, drift=drift)
        assert "🟢" in line

    def test_it_reports_how_much_we_sent(self):
        assert "1244 frames sent" in self._line(oneway=50.0, sent=1244)

    def test_it_is_one_line(self):
        assert len(manager()._call_summary(FakeSession(oneway=50.0))) == 1


# ---------------------------------------------------------------------------
# ordering: the summary must be read before teardown
# ---------------------------------------------------------------------------

class TestItIsReadBeforeTeardown:

    def test_a_summary_taken_after_end_would_be_zeros(self):
        session = FakeSession(oneway=100.0, queued=1000, gaps=0, sent=900)
        import asyncio
        asyncio.get_event_loop_policy().new_event_loop().run_until_complete(
            session.end())
        line = manager()._call_summary(session)[0]
        # Proof the ordering matters at all: this is what the user would see
        # if the summary were gathered after the buffers were torn down.
        assert "not measured" in line

    def test_end_call_prints_the_figures_from_before_teardown(self, printed):
        import asyncio

        mgr = manager()
        session = FakeSession(oneway=100.0, dwell=40.0, decode=10.0,
                              play=20.0, queued=1000, gaps=0, sent=900)
        mgr._calls = {"peer@example.i2p": session}
        mgr._stats_tasks = {}
        mgr._rekey_tasks = {}
        mgr._stop_ringing = lambda _p: None
        mgr._cancel_timeout = lambda _p: None
        mgr._signal = lambda *a, **k: True

        asyncio.run(V.VoiceCallManager.end_call(mgr, "peer@example.i2p",
                                                notify_peer=False))
        assert session.ended
        joined = "\n".join(printed)
        assert "170ms" in joined
        assert "not measured" not in joined


# ---------------------------------------------------------------------------
# the report can never take the call with it
# ---------------------------------------------------------------------------

class TestItNeverRaises:

    def test_a_session_missing_everything_still_summarises(self):
        class Empty:
            peer = "p"

        lines = manager()._call_summary(Empty())
        assert lines and all(isinstance(ln, str) for ln in lines)

    def test_an_exploding_session_still_summarises(self):
        class Exploding:
            peer = "p"

            def __getattr__(self, _name):
                raise RuntimeError("boom")

        lines = manager()._call_summary(Exploding())
        assert lines == ["[voice] call ended"]

    def test_a_summary_failure_does_not_claim_a_verdict(self):
        class Exploding:
            def __getattr__(self, _name):
                raise RuntimeError("boom")

        line = manager()._call_summary(Exploding())[0]
        for mark in ("🟢", "🟡", "🔴"):
            assert mark not in line


# ---------------------------------------------------------------------------
# teardown reporting
# ---------------------------------------------------------------------------

class TestTheTeardownLine:

    def test_a_clean_call_says_the_keys_are_gone(self, printed):
        manager()._report_teardown({"sent": 10, "recv": 10, "dropped": 0,
                                    "auth_fail": 0, "replay": 0})
        assert any("zeroized" in ln for ln in printed)

    def test_a_clean_call_does_not_print_the_packet_tally(self, printed):
        manager()._report_teardown({"sent": 10, "recv": 10, "dropped": 0,
                                    "auth_fail": 0, "replay": 0})
        assert not any("received" in ln for ln in printed)

    def test_the_tally_comes_back_with_the_setup_detail(self, printed,
                                                        monkeypatch):
        monkeypatch.setattr(V, "VOICE_VERBOSE", True)
        manager()._report_teardown({"sent": 10, "recv": 10, "dropped": 0,
                                    "auth_fail": 0, "replay": 0})
        assert any("received" in ln for ln in printed)

    def test_an_authentication_failure_is_never_hidden(self, printed):
        # The counter that must not be behind a flag: frames arrived that did
        # not authenticate under our key. That is the one number a user of an
        # encrypted call is entitled to see without asking for diagnostics.
        assert V.VOICE_VERBOSE is False
        manager()._report_teardown({"sent": 10, "recv": 10, "dropped": 0,
                                    "auth_fail": 3, "replay": 0})
        assert any("auth-failed" in ln and "3" in ln for ln in printed)

    def test_a_replay_is_never_hidden(self, printed):
        manager()._report_teardown({"sent": 10, "recv": 10, "dropped": 0,
                                    "auth_fail": 0, "replay": 2})
        assert any("replay" in ln.lower() for ln in printed)

    def test_discarded_is_said_plainly(self, printed):
        manager()._report_teardown({"sent": 1, "recv": 1, "dropped": 0,
                                    "auth_fail": 1, "replay": 0})
        assert any("DISCARDED" in ln for ln in printed)

    def test_a_broken_stats_dict_still_confirms_the_wipe(self, printed):
        class Hostile(dict):
            def get(self, *_a, **_k):
                raise RuntimeError("boom")

        manager()._report_teardown(Hostile())
        assert any("zeroized" in ln for ln in printed)


# ---------------------------------------------------------------------------
# the setup detail, and getting it back
# ---------------------------------------------------------------------------

class TestTheSetupDetailIsBehindTheFlag:

    def test_vprint_is_silent_by_default(self, printed):
        V._vprint("[voice] codec: something")
        assert printed == []

    def test_vprint_speaks_when_asked(self, printed, monkeypatch):
        monkeypatch.setattr(V, "VOICE_VERBOSE", True)
        V._vprint("[voice] codec: something")
        assert printed == ["[voice] codec: something"]

    def test_the_environment_variable_turns_it_on(self, monkeypatch):
        monkeypatch.setenv("OTRV4PLUS_VOICE_VERBOSE", "1")
        V.set_voice_verbose(False)
        try:
            assert V.VOICE_VERBOSE is True
        finally:
            monkeypatch.delenv("OTRV4PLUS_VOICE_VERBOSE", raising=False)
            V.set_voice_verbose(False)

    def test_the_environment_variable_cannot_be_switched_off_at_runtime(
            self, monkeypatch):
        # Somebody who set the variable asked for the detail for the whole
        # process. /voicedebug off should not silently override that.
        monkeypatch.setenv("OTRV4PLUS_VOICE_VERBOSE", "1")
        V.set_voice_verbose(True)
        V.set_voice_verbose(False)
        try:
            assert V.VOICE_VERBOSE is True
        finally:
            monkeypatch.delenv("OTRV4PLUS_VOICE_VERBOSE", raising=False)
            V.set_voice_verbose(False)

    def test_voicedebug_restores_the_setup_detail(self, monkeypatch):
        # One switch, not two: somebody who types /voicedebug because a call
        # sounds wrong wants the codec, transport and playout lines, not
        # telemetry with the explanation missing.
        monkeypatch.setattr(V, "VOICE_VERBOSE", False)
        mgr = manager()
        mgr.debug = True
        assert V.VOICE_VERBOSE is True
        assert mgr.debug is True

    def test_turning_diagnostics_off_quietens_it_again(self, monkeypatch):
        monkeypatch.setattr(V, "VOICE_VERBOSE", False)
        mgr = manager()
        mgr.debug = True
        mgr.debug = False
        assert V.VOICE_VERBOSE is False
        assert mgr.debug is False

    def test_the_shaping_warning_is_not_behind_the_flag(self):
        # Everything else in call setup was demoted. This one was not: a user
        # told the call is constant-rate is entitled to be told when it is
        # not, and that line is the only setup line that changes what the
        # call protects.
        import inspect
        src = inspect.getsource(V.VoiceCallSession._build_codec)
        assert '_print("[voice] ⚠ WARNING: could not disable VBR/DTX' in src
        assert '_vprint("[voice] ⚠ WARNING' not in src

    def test_everything_else_in_codec_setup_is_behind_the_flag(self):
        import inspect
        for line in inspect.getsource(
                V.VoiceCallSession._build_codec).splitlines():
            stripped = line.strip()
            if stripped.startswith("_print(") and "WARNING" not in stripped:
                pytest.fail("un-demoted setup line: %s" % stripped)
