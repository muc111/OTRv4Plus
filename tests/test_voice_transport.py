#!/usr/bin/env python3
"""Transport-layer regression tests for the voice path.

Covers the pre-Android transport pass: SAM write pacing, transport health and
its hysteresis, the latency distribution, jitter accounting, the send-queue
bound, the I2P tunnel-option table, and the guarantee that none of the new
diagnostics can carry plaintext or key material.

The security-shaped tests here are not decoration. The new telemetry layer is
the first thing in this codebase that writes structured records to a file, and
a diagnostics channel that can be handed a message body is a diagnostics
channel that eventually is.
"""

import asyncio
import os
import struct
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

telemetry = pytest.importorskip("otrv4plus_telemetry")
i2pcfg = pytest.importorskip("otrv4plus_i2p")


# ── Transport health: hysteresis is the whole point ──────────────────────────

class TestTransportHealthHysteresis:

    def test_one_spike_does_not_degrade(self):
        """THE requirement: a single latency spike must not trigger recovery.

        I2P delivers a frame seconds late routinely -- a tunnel is being
        replaced, a peer is congested. A transport that reacts to one sample
        reconnects during every call, and each reconnect costs a fresh tunnel
        build and a guaranteed audio gap.
        """
        health = telemetry.TransportHealth(degrade_samples=5)
        for i in range(200):
            health.observe_rtt(9000.0 if i == 50 else 900.0)
        assert health.state == telemetry.HEALTHY
        assert health.transitions == 0

    @pytest.mark.parametrize("spikes", [1, 2, 3, 4])
    def test_fewer_than_the_threshold_never_degrades(self, spikes):
        health = telemetry.TransportHealth(degrade_samples=5)
        for _ in range(spikes):
            health.observe_rtt(9000.0)
        assert health.state == telemetry.HEALTHY

    def test_sustained_degradation_is_detected(self):
        health = telemetry.TransportHealth(degrade_samples=5)
        for _ in range(5):
            health.observe_rtt(9000.0)
        assert health.state == telemetry.DEGRADED

    def test_degraded_is_not_a_reconnect_trigger(self):
        """DEGRADED is a signal, not an instruction to tear down a session."""
        health = telemetry.TransportHealth(degrade_samples=5)
        for _ in range(50):
            health.observe_rtt(30000.0)
        assert health.state == telemetry.DEGRADED
        assert health.should_reconnect is False

    def test_recovery_needs_sustained_good_samples(self):
        health = telemetry.TransportHealth(degrade_samples=5,
                                           recover_samples=10)
        for _ in range(5):
            health.observe_rtt(9000.0)
        health.observe_rtt(100.0)
        assert health.state == telemetry.RECOVERING
        for _ in range(8):
            health.observe_rtt(100.0)
        assert health.state == telemetry.RECOVERING, \
            "recovered before the sample threshold"
        health.observe_rtt(100.0)
        assert health.state == telemetry.HEALTHY

    def test_a_relapse_during_recovery_returns_to_degraded(self):
        health = telemetry.TransportHealth(degrade_samples=5,
                                           recover_samples=10)
        for _ in range(5):
            health.observe_rtt(9000.0)
        health.observe_rtt(100.0)
        assert health.state == telemetry.RECOVERING
        health.observe_rtt(9000.0)
        assert health.state == telemetry.DEGRADED, \
            "one bad sample during recovery must not be ignored"

    def test_flapping_never_reaches_healthy_and_never_reconnects(self):
        """A path alternating good/bad must settle, not oscillate into a
        reconnect storm."""
        health = telemetry.TransportHealth(degrade_samples=5,
                                           recover_samples=10)
        for _ in range(5):
            health.observe_rtt(9000.0)
        seen = set()
        for i in range(200):
            health.observe_rtt(100.0 if i % 2 == 0 else 9000.0)
            seen.add(health.state)
            assert not health.should_reconnect
        assert telemetry.HEALTHY not in seen
        assert telemetry.DISCONNECTED not in seen

    def test_only_an_explicit_failure_disconnects(self):
        health = telemetry.TransportHealth()
        for _ in range(500):
            health.observe_rtt(60000.0)
        assert health.state != telemetry.DISCONNECTED
        health.note_failure()
        assert health.state == telemetry.DISCONNECTED
        assert health.should_reconnect is True

    def test_a_silent_stream_degrades_on_the_clock(self):
        """No frames means no RTT samples, so nothing else would notice."""
        now = [1000.0]
        health = telemetry.TransportHealth(stall_seconds=6.0,
                                           degrade_samples=1,
                                           clock=lambda: now[0])
        health.note_progress()
        now[0] += 3.0
        assert health.tick() == telemetry.HEALTHY
        now[0] += 4.0
        assert health.tick() == telemetry.DEGRADED

    def test_progress_resets_the_stall_timer(self):
        now = [1000.0]
        health = telemetry.TransportHealth(stall_seconds=6.0,
                                           degrade_samples=1,
                                           clock=lambda: now[0])
        for _ in range(10):
            now[0] += 5.0
            health.note_progress()
            assert health.tick() == telemetry.HEALTHY

    def test_reconnection_returns_to_recovering_not_healthy(self):
        health = telemetry.TransportHealth()
        health.note_failure()
        health.note_reconnected()
        assert health.state == telemetry.RECOVERING


# ── Latency distribution ─────────────────────────────────────────────────────

class TestLatencyDistribution:

    def test_percentiles_track_a_known_distribution(self):
        hist = telemetry.Histogram()
        for value in range(1, 1001):        # 1..1000 ms, uniform
            hist.observe(float(value))
        assert abs(hist.percentile(50) - 500) < 15
        assert abs(hist.percentile(95) - 950) < 30
        assert abs(hist.percentile(99) - 990) < 30

    def test_min_and_max_are_exact_not_bucketed(self):
        """"maximum spike" is one of the numbers being optimised, so it must
        not carry bucket error."""
        hist = telemetry.Histogram()
        for value in (12.5, 1337.25, 4.75, 8801.5):
            hist.observe(value)
        snap = hist.snapshot()
        assert snap["min_ms"] == 4.75
        assert snap["max_ms"] == 8801.5
        assert hist.percentile(100) == 8801.5

    def test_a_tail_is_visible_where_a_median_hides_it(self):
        """The defect this replaces: a 10-sample median cannot report a tail."""
        hist = telemetry.Histogram()
        for _ in range(9800):
            hist.observe(1300.0)
        for _ in range(200):
            hist.observe(9000.0)
        assert abs(hist.percentile(50) - 1300) < 30
        assert hist.percentile(99) > 1400, "the 1% tail is invisible"
        assert hist.percentile(100) == 9000.0

    def test_memory_is_independent_of_sample_count(self):
        small, large = telemetry.Histogram(), telemetry.Histogram()
        small.observe(1.0)
        for i in range(200000):
            large.observe(float(i % 5000))
        assert len(small._counts) == len(large._counts)
        assert large.count == 200000

    def test_percentiles_are_none_before_any_sample(self):
        hist = telemetry.Histogram()
        assert hist.percentile(50) is None
        assert hist.snapshot()["count"] == 0

    def test_values_beyond_the_top_bucket_are_counted_not_lost(self):
        hist = telemetry.Histogram()
        hist.observe(500000.0)
        snap = hist.snapshot()
        assert snap["over_range"] == 1
        assert snap["max_ms"] == 500000.0


# ── Jitter accounting ────────────────────────────────────────────────────────

class TestJitterAccounting:

    def test_perfect_cadence_is_zero_jitter(self):
        metrics = telemetry.TransportMetrics()
        for _ in range(100):
            metrics.observe("jitter", abs(40.0 - 40.0))
        assert metrics.histogram("jitter").percentile(95) == 0.0

    def test_jitter_is_the_deviation_from_the_frame_interval(self):
        metrics = telemetry.TransportMetrics()
        for gap in (30.0, 50.0, 40.0, 55.0, 25.0):
            metrics.observe("jitter", abs(gap - 40.0))
        snap = metrics.histogram("jitter").snapshot()
        assert snap["max_ms"] == 15.0
        assert snap["min_ms"] == 0.0

    def test_series_names_are_fixed(self):
        """A typo'd series name must raise rather than silently vanish."""
        metrics = telemetry.TransportMetrics()
        with pytest.raises(KeyError):
            metrics.observe("rtt_ms", 5.0)


# ── SAM write pacing ─────────────────────────────────────────────────────────

class TestSamWritePacing:

    @pytest.fixture
    def pacer_cls(self):
        return i2pcfg.SamWritePacer

    def test_a_message_inside_one_chunk_is_never_delayed(self, pacer_cls):
        """A stanza that fits in a single write pays nothing.

        This is where the old form was plainly wasteful: it slept 20 ms after
        every chunk INCLUDING the last, so even a one-chunk message delayed
        whatever was queued behind it.
        """
        now = [0.0]
        pacer = pacer_cls(clock=lambda: now[0])
        assert pacer.delay_for(1024) == 0.0
        assert pacer.delay_for(0) == 0.0
        assert pacer.paced_writes == 0

    def test_the_old_inter_chunk_spacing_is_preserved(self, pacer_cls):
        """The safety property the previous implementation actually provided.

        Not "under 8 KB per burst" -- that was a misreading that broke SMP on a
        real path. The empirical guarantee was: never more than SAM_CHUNK bytes
        toward SAM without a ~20 ms gap. A full chunk must therefore cost the
        same 20 ms it always did.
        """
        now = [0.0]
        pacer = pacer_cls(clock=lambda: now[0])
        assert pacer.delay_for(i2pcfg.SAM_CHUNK) == 0.0       # first is free
        second = pacer.delay_for(i2pcfg.SAM_CHUNK)
        assert abs(second - 0.020) < 1e-6, (
            "a full chunk must still wait the 20 ms the fixed sleep gave it")

    def test_the_default_burst_is_one_chunk(self, pacer_cls):
        """Regression guard on the exact value that broke SMP.

        A default above SAM_CHUNK lets more than one chunk leave back to back,
        which is what the old pacing existed to prevent -- and TCP_NODELAY,
        added in the same pass, removed the coalescing that had been masking
        it.
        """
        assert i2pcfg.SAM_BURST_BYTES == i2pcfg.SAM_CHUNK

    def test_no_trailing_delay_after_the_final_chunk(self, pacer_cls):
        """The part of the improvement that survives.

        The old loop slept after the last chunk too, delaying the NEXT stanza
        for no transport reason at all.
        """
        now = [0.0]
        pacer = pacer_cls(clock=lambda: now[0])
        total = 0.0
        for offset in range(0, 6000, i2pcfg.SAM_CHUNK):
            piece = min(i2pcfg.SAM_CHUNK, 6000 - offset)
            delay = pacer.delay_for(piece)
            total += delay
            now[0] += delay                     # take() sleeps here
        old_form = 6 * 0.020                    # six chunks, six sleeps
        assert total < old_form, "no better than the fixed sleep"
        assert total >= 4 * 0.020, (
            "inter-chunk spacing was weakened, not just the trailing sleep")

    def test_a_burst_within_the_allowance_is_free(self, pacer_cls):
        now = [0.0]
        pacer = pacer_cls(burst_bytes=4096, clock=lambda: now[0])
        total = sum(pacer.delay_for(1024) for _ in range(4))
        assert total == 0.0

    def test_beyond_the_allowance_is_paced(self, pacer_cls):
        now = [0.0]
        pacer = pacer_cls(burst_bytes=4096, rate_bps=51200.0,
                          clock=lambda: now[0])
        for _ in range(4):
            pacer.delay_for(1024)
        delay = pacer.delay_for(1024)
        assert delay > 0.0
        assert abs(delay - 1024 / 51200.0) < 1e-9

    def test_the_burst_never_exceeds_the_cliff_allowance(self, pacer_cls):
        """The protection that must survive: no unpaced burst may approach the
        ~8 KB size at which I2P has been observed to drop the stream."""
        now = [0.0]
        pacer = pacer_cls(burst_bytes=4096, clock=lambda: now[0])
        unpaced = 0
        for _ in range(64):
            if pacer.delay_for(1024) == 0.0:
                unpaced += 1024
            else:
                break
        assert unpaced <= 4096

    def test_the_sustained_rate_is_unchanged(self, pacer_cls):
        """Long-run throughput must match the old 1024 B / 20 ms ceiling."""
        now = [0.0]
        pacer = pacer_cls(burst_bytes=4096, rate_bps=51200.0,
                          clock=lambda: now[0])
        total_delay = 0.0
        written = 0
        for _ in range(400):
            delay = pacer.delay_for(1024)
            total_delay += delay
            now[0] += delay
            written += 1024
        # The burst allowance is free by design, so exclude it from the
        # long-run rate: it is the sustained ceiling being compared.
        rate = (written - pacer.burst_bytes) / total_delay
        assert abs(rate - 51200.0) / 51200.0 < 0.02

    def test_tokens_refill_over_time(self, pacer_cls):
        now = [0.0]
        pacer = pacer_cls(burst_bytes=4096, rate_bps=51200.0,
                          clock=lambda: now[0])
        for _ in range(4):
            pacer.delay_for(1024)
        assert pacer.delay_for(1024) > 0.0
        now[0] += 1.0                      # a second of idle refills the bucket
        assert pacer.delay_for(1024) == 0.0

    def test_take_sleeps_only_when_charged(self, pacer_cls):
        async def run():
            pacer = pacer_cls(burst_bytes=4096, rate_bps=51200.0)
            loop = asyncio.get_running_loop()
            start = loop.time()
            for _ in range(4):
                await pacer.take(1024)
            return loop.time() - start
        elapsed = asyncio.new_event_loop().run_until_complete(run())
        assert elapsed < 0.05, "a burst inside the allowance slept"


# ── Concurrent chat and voice signalling ─────────────────────────────────────

class TestChatDoesNotBlockSignalling:
    """Voice media has its own SAM stream, so chat cannot delay audio frames.

    Signalling is different: INVITE, REKEY and END ride the one XMPP stream
    alongside chat, and a rekey has a deadline. These pin the head-of-line
    behaviour on that shared path.
    """

    @pytest.fixture
    def pacer_cls(self):
        return i2pcfg.SamWritePacer

    def test_a_rekey_behind_a_chat_message_is_not_delayed(self, pacer_cls):
        now = [0.0]
        pacer = pacer_cls(burst_bytes=4096, rate_bps=51200.0,
                          clock=lambda: now[0])
        # A 2 KB chat message, then a rekey-sized control message.
        chat = sum(pacer.delay_for(n) for n in (1024, 1024))
        rekey = sum(pacer.delay_for(n) for n in (1024, 512))
        assert chat == 0.0
        assert rekey == 0.0, "signalling paid for the chat message ahead of it"

    def test_the_old_model_would_have_delayed_it(self, pacer_cls):
        """States the size of the defect, so the test is a comparison rather
        than an assertion that the current number is nice."""
        old_delay_per_chunk = 0.020
        chat_chunks = 2
        rekey_chunks = 2
        old_total = (chat_chunks + rekey_chunks) * old_delay_per_chunk
        assert old_total == pytest.approx(0.080)

        now = [0.0]
        pacer = pacer_cls(burst_bytes=4096, rate_bps=51200.0,
                          clock=lambda: now[0])
        new_total = sum(pacer.delay_for(1024) for _ in range(4))
        assert new_total == 0.0


# ── I2P tunnel options ───────────────────────────────────────────────────────

class TestTunnelOptions:

    def test_hop_count_is_not_reduced(self):
        """Shortening tunnels is the biggest latency lever available and it is
        not on the table: hop count is the anonymity parameter."""
        for profile in (i2pcfg.VOICE_TUNNEL_OPTIONS,
                        i2pcfg.XMPP_TUNNEL_OPTIONS):
            assert profile["inbound.length"] == 3
            assert profile["outbound.length"] == 3

    def test_length_variance_is_pinned_to_zero(self):
        """Variance only ever adds hops, so pinning it costs no anonymity and
        stops latency moving for that reason."""
        for profile in (i2pcfg.VOICE_TUNNEL_OPTIONS,
                        i2pcfg.XMPP_TUNNEL_OPTIONS):
            assert profile["inbound.lengthVariance"] == 0
            assert profile["outbound.lengthVariance"] == 0

    def test_options_render_as_sam_key_value_pairs(self):
        rendered = i2pcfg.format_options(i2pcfg.VOICE_TUNNEL_OPTIONS)
        assert "inbound.length=3" in rendered
        assert "inbound.quantity=4" in rendered
        assert "=" in rendered and "\n" not in rendered

    def test_rendering_is_stable(self):
        """Two identical settings must produce an identical command line."""
        a = i2pcfg.format_options(i2pcfg.VOICE_TUNNEL_OPTIONS)
        b = i2pcfg.format_options(dict(i2pcfg.VOICE_TUNNEL_OPTIONS))
        assert a == b

    @pytest.mark.parametrize("option", [
        "inbound.backupQuantity",
        "outbound.backupQuantity",
        "i2p.streaming.initialAckDelay",
        "i2p.streaming.initialWindowSize",
    ])
    def test_options_i2pd_does_not_implement_are_refused(self, option):
        """Setting one of these looks like configuration and does nothing."""
        with pytest.raises(ValueError) as exc:
            i2pcfg.session_options({option: 2})
        assert "not implemented" in str(exc.value)

    def test_an_unknown_option_is_refused(self):
        with pytest.raises(ValueError):
            i2pcfg.session_options({"inbound.somethingInvented": 1})

    def test_a_non_integer_option_is_refused(self):
        with pytest.raises(ValueError):
            i2pcfg.session_options({"inbound.quantity": "four"})

    def test_the_session_create_line_stays_one_line(self):
        """A newline in an option would split the SAM command in two."""
        rendered = i2pcfg.format_options(i2pcfg.VOICE_TUNNEL_OPTIONS)
        assert "\n" not in rendered and "\r" not in rendered


# ── Send-queue bound ─────────────────────────────────────────────────────────

class TestSendQueueBound:

    @pytest.fixture
    def voice(self):
        return pytest.importorskip("otrv4plus_voice")

    def test_the_backlog_is_bounded_in_time_not_packets(self, voice):
        session_cls = voice.VoiceCallSession
        assert session_cls.VOICE_MAX_WRITE_BACKLOG_MS <= 600, (
            "the send queue admits more stale audio than the receiver's own "
            "drift ceiling will keep")

    def test_the_bound_shrank(self, voice):
        """The old bound was 50 packets: two seconds of audio queued in the
        transport before anything was dropped."""
        old_bytes = voice.VOICE_PACKET_LEN * 50
        assert voice.VoiceCallSession._MAX_WRITE_BACKLOG < old_bytes

    def test_at_least_a_few_frames_are_still_buffered(self, voice):
        """Bounded is not the same as unbuffered: a momentary scheduling
        hiccup must not drop audio."""
        assert (voice.VoiceCallSession._MAX_WRITE_BACKLOG
                >= voice.VOICE_PACKET_LEN * 2)


# ── Diagnostics must not carry plaintext or secrets ──────────────────────────

class TestNoPlaintextDiagnostics:

    def test_a_free_form_string_is_refused(self):
        metrics = telemetry.TransportMetrics()
        with pytest.raises(telemetry.TelemetryValueError):
            metrics.event("stream_lost", detail="hello, this is the message")

    def test_a_jid_is_refused(self):
        metrics = telemetry.TransportMetrics()
        with pytest.raises(telemetry.TelemetryValueError):
            metrics.event("xmpp_connect", peer_jid="alice@example.com")

    def test_bytes_are_refused(self):
        """Covers every key type in one assertion: they are all bytes."""
        metrics = telemetry.TransportMetrics()
        for material in (b"\x00" * 32, bytearray(64), memoryview(b"abc")):
            with pytest.raises(telemetry.TelemetryValueError):
                metrics.event("rekey_commit", key=material)

    def test_an_i2p_destination_is_refused(self):
        metrics = telemetry.TransportMetrics()
        with pytest.raises(telemetry.TelemetryValueError):
            metrics.event("sam_connect", dest="A" * 516)

    def test_an_unregistered_event_name_is_refused(self):
        """Event names are a fixed vocabulary, so a caller cannot smuggle text
        through the name either."""
        metrics = telemetry.TransportMetrics()
        with pytest.raises(telemetry.TelemetryValueError):
            metrics.event("peer said: hello")

    def test_numbers_and_enum_names_are_accepted(self):
        metrics = telemetry.TransportMetrics()
        metrics.event("health_change", from_state="HEALTHY",
                      to_state="DEGRADED", rtt_ms=4210.5, samples=17)
        assert metrics.events[-1]["rtt_ms"] == 4210.5

    def test_identifiers_are_opaque_and_not_the_jid(self):
        tag = telemetry.opaque_tag("alice@example.com")
        assert len(tag) == 8
        assert "alice" not in tag and "@" not in tag
        assert tag == telemetry.opaque_tag("alice@example.com")
        assert tag != telemetry.opaque_tag("bob@example.com")

    def test_a_written_log_contains_no_free_text(self):
        directory = tempfile.mkdtemp()
        path = os.path.join(directory, "transport.jsonl")
        sink = telemetry.JsonlSink(path)
        try:
            metrics = telemetry.TransportMetrics(
                call_tag=telemetry.opaque_tag(b"\x01" * 16),
                peer_tag=telemetry.opaque_tag("alice@example.com"),
                sink=sink)
            metrics.event("session_open", role_id=1)
            metrics.observe("rtt", 1300.0)
            metrics.write_snapshot()
        finally:
            sink.close()

        with open(path, encoding="utf-8") as handle:
            body = handle.read()
        for forbidden in ("alice", "example.com", "hello", "BEGIN"):
            assert forbidden not in body

    def test_the_log_is_not_world_readable(self):
        directory = tempfile.mkdtemp()
        path = os.path.join(directory, "transport.jsonl")
        sink = telemetry.JsonlSink(path)
        try:
            mode = os.stat(path).st_mode & 0o777
        finally:
            sink.close()
        assert mode & 0o077 == 0, "transport telemetry is traffic analysis"

    def test_telemetry_is_off_unless_a_path_is_given(self):
        sink = telemetry.JsonlSink(None)
        assert sink.enabled is False
        sink.write({"event": "session_open"})     # must not raise


# ── The session wiring ───────────────────────────────────────────────────────

class TestSessionWiring:

    @pytest.fixture
    def voice(self):
        return pytest.importorskip("otrv4plus_voice")

    def _session(self, voice, **kwargs):
        loop = asyncio.new_event_loop()
        try:
            return voice.VoiceCallSession(
                "peer@example.com", loop, b"\x01" * 16, True, **kwargs)
        finally:
            loop.close()

    def test_a_session_carries_tunnel_options(self, voice):
        session = self._session(voice)
        assert session.sam_options["inbound.length"] == 3
        assert session.sam_options["inbound.quantity"] >= 2

    def test_a_session_refuses_unsupported_tunnel_options(self, voice):
        with pytest.raises(ValueError):
            self._session(voice,
                          sam_options={"inbound.backupQuantity": 3})

    def test_a_session_has_a_health_machine(self, voice):
        session = self._session(voice)
        assert session.transport_health() == telemetry.HEALTHY

    def test_transport_summary_is_empty_before_any_sample(self, voice):
        """A call that has just started must not display placeholder
        percentiles."""
        session = self._session(voice, metrics=telemetry.TransportMetrics())
        assert "p95" not in session.transport_summary()

    def test_transport_summary_reports_the_tail_once_sampled(self, voice):
        metrics = telemetry.TransportMetrics()
        session = self._session(voice, metrics=metrics)
        for value in (1200.0, 1300.0, 1250.0, 8000.0):
            metrics.observe("rtt", value)
        summary = session.transport_summary()
        assert "p95" in summary and "max" in summary
        assert "link=" in summary

    def test_a_stream_failure_disconnects_the_health_machine(self, voice):
        session = self._session(voice)
        session._signal_stream_lost("peer closed the media stream")
        assert session.transport_health() == telemetry.DISCONNECTED


# ── SAM failure handling ─────────────────────────────────────────────────────

class TestSamFailure:

    def test_nodelay_on_a_dead_socket_does_not_raise(self):
        """Best effort by design: a platform that refuses the option must not
        prevent a call from being placed."""
        import socket as _socket
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.close()
        assert i2pcfg.set_nodelay(sock) in (True, False)

    def test_nodelay_on_none_is_false(self):
        assert i2pcfg.set_nodelay(None) is False

    def test_nodelay_takes_effect_on_a_live_socket(self):
        import socket as _socket
        server = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        client = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        try:
            client.connect(server.getsockname())
            assert i2pcfg.set_nodelay(client) is True
            assert client.getsockopt(_socket.IPPROTO_TCP,
                                     _socket.TCP_NODELAY) == 1
        finally:
            client.close()
            server.close()


# ── Counters ─────────────────────────────────────────────────────────────────

class TestCounters:

    def test_counters_start_at_zero_and_accumulate(self):
        metrics = telemetry.TransportMetrics()
        assert metrics.get("frames_sent") == 0
        for _ in range(7):
            metrics.incr("frames_sent")
        assert metrics.get("frames_sent") == 7

    def test_the_snapshot_is_json_serialisable(self):
        import json
        metrics = telemetry.TransportMetrics()
        metrics.incr("frames_sent", 10)
        metrics.observe("rtt", 1300.0)
        json.dumps(metrics.snapshot())

    def test_the_event_ring_is_bounded(self):
        metrics = telemetry.TransportMetrics()
        for _ in range(5000):
            metrics.event("resync")
        assert len(metrics.events) <= 512
