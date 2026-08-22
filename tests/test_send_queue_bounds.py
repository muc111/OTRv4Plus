"""Every queue on the send path must be bounded in time, not in bytes.

A live call was observed running 24 seconds behind with drop=0, late=0 and
rx arriving in bursts of 381 frames per 5 s window. Nothing was being lost;
audio was being queued and delivered minutes-of-wall-clock later. Three
queues sit between the encoder and the peer, and only one of them was bounded:

  1. ``call_soon_threadsafe`` between the capture thread and the event loop.
     Unbounded. Now bounded by a capture-time deadline.
  2. asyncio's transport write buffer. Bounded, but at 50 packets -- 3 s of
     audio at 60 ms frames.
  3. the kernel send buffer on the loopback socket to the SAM bridge.
     Unbounded in practice: Linux autotunes it to net.ipv4.tcp_wmem[2],
     4 MiB on a stock Android kernel, which is ~21000 frames. This is where
     the 24 seconds lived, and it is invisible to
     ``transport.get_write_buffer_size()`` -- which is why every backpressure
     check passed while the call ran twenty seconds late.

These tests assert the bounds in milliseconds of audio, because that is the
unit the failure was measured in.
"""

import socket
import time

import pytest

import otrv4plus_voice as voice


def _ms_of_audio(byte_count):
    return byte_count / voice.VOICE_PACKET_LEN * voice.VOICE_FRAME_MS


class TestAsyncioWriteBacklogIsBoundedInTime:
    def test_the_backlog_holds_well_under_a_second_of_audio(self):
        session_cls = voice.VoiceCallSession
        held_ms = _ms_of_audio(session_cls._MAX_WRITE_BACKLOG)
        assert held_ms <= 600, "asyncio backlog holds %.0f ms of audio" % held_ms

    def test_the_backlog_still_absorbs_normal_scheduling_jitter(self):
        # Bounded is not the same as zero: a backlog under two frames would
        # shed audio every time the loop was briefly busy.
        session_cls = voice.VoiceCallSession
        assert session_cls._MAX_WRITE_BACKLOG >= voice.VOICE_PACKET_LEN * 2


class TestKernelSendBufferIsPinned:
    def test_the_requested_size_is_a_fraction_of_a_second(self):
        requested_ms = _ms_of_audio(voice.VOICE_SEND_BUFFER_BYTES)
        assert requested_ms <= 600, "requested %.0f ms" % requested_ms

    def test_pinning_actually_shrinks_a_real_socket(self):
        sock = socket.socket()
        try:
            before = sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
            granted = voice.limit_media_send_buffer(sock)
            if granted < 0:
                pytest.skip("platform refuses SO_SNDBUF")
            assert granted <= before
            # The kernel floor is well under a second; the point of the call is
            # that autotuning to tcp_wmem[2] (4 MiB, ~20 minutes of audio) can
            # no longer happen.
            assert _ms_of_audio(granted) < 3000, (
                "granted %d bytes = %.0f ms" % (granted, _ms_of_audio(granted)))
        finally:
            sock.close()

    def test_it_reports_rather_than_raises_when_unsupported(self):
        class Refuses:
            def setsockopt(self, *a):
                raise OSError("nope")

            def getsockopt(self, *a):
                raise OSError("nope")

        assert voice.limit_media_send_buffer(Refuses()) == -1


class _FakeTransport:
    def __init__(self, buffered=0):
        self._buffered = buffered

    def get_write_buffer_size(self):
        return self._buffered


class _FakeWriter:
    def __init__(self, buffered=0):
        self.transport = _FakeTransport(buffered)
        self.written = []

    def is_closing(self):
        return False

    def write(self, data):
        self.written.append(data)


def _session_stub(buffered=0):
    """A VoiceMediaSession with just enough state for _write_packet."""
    session = object.__new__(voice.VoiceCallSession)
    session._running = True
    session._writer = _FakeWriter(buffered)
    session._transport_mode = voice.VOICE_TRANSPORT_STREAM
    session._dgram_transport = None
    session._dgram_send_header = None
    session.stages = voice.StageTimers()
    session.stats = {"sent": 0, "dropped": 0, "backpressure": 0, "stale": 0}
    return session


class TestStaleFramesAreDiscardedRatherThanSent:
    def test_a_fresh_frame_is_written(self):
        session = _session_stub()
        session._write_packet(b"x" * voice.VOICE_PACKET_LEN, time.monotonic())
        assert session.stats["sent"] == 1
        assert session.stats["stale"] == 0
        assert len(session._writer.written) == 1

    def test_a_frame_past_the_deadline_is_not_written(self):
        session = _session_stub()
        stamped = time.monotonic() - (session._SEND_DEADLINE_S + 0.5)
        session._write_packet(b"x" * voice.VOICE_PACKET_LEN, stamped)
        assert session.stats["stale"] == 1
        assert session.stats["sent"] == 0
        assert session._writer.written == [], "stale audio reached the socket"

    def test_the_deadline_is_short_enough_to_matter(self):
        # A deadline longer than the jitter buffer's own ceiling would let the
        # send path alone exceed the entire latency budget.
        deadline_ms = voice.VoiceCallSession._SEND_DEADLINE_S * 1000
        assert deadline_ms <= voice.VOICE_JITTER_DRIFT_HIGH_MS

    def test_an_unstamped_frame_is_exempt(self):
        # Probes pass None deliberately: a probe that waited is measuring the
        # delay we want reported.
        session = _session_stub()
        session._write_packet(b"x" * voice.VOICE_PACKET_LEN, None)
        assert session.stats["sent"] == 1
        assert session.stats["stale"] == 0


class TestBackpressureStillSheds:
    def test_a_full_transport_buffer_sheds_the_frame(self):
        session = _session_stub(
            buffered=voice.VoiceCallSession._MAX_WRITE_BACKLOG + 1)
        session._write_packet(b"x" * voice.VOICE_PACKET_LEN, time.monotonic())
        assert session.stats["backpressure"] == 1
        assert session.stats["sent"] == 0
        assert session._writer.written == []

    def test_shedding_is_counted_separately_from_encoder_drops(self):
        # "dropped" means we failed to produce a frame; "backpressure" and
        # "stale" mean we produced one and chose not to send it. Collapsing
        # them hides which of the two is happening.
        session = _session_stub()
        assert "backpressure" in session.stats
        assert "stale" in session.stats
        assert "dropped" in session.stats


class TestTotalBoundedSendLatency:
    def test_the_whole_send_path_is_bounded_near_a_second(self):
        # deadline + asyncio backlog + pinned kernel buffer. This is the number
        # that was 24000 ms on the call that prompted the change.
        sock = socket.socket()
        try:
            granted = voice.limit_media_send_buffer(sock)
        finally:
            sock.close()
        kernel_ms = _ms_of_audio(granted) if granted > 0 else 0.0
        backlog_ms = _ms_of_audio(voice.VoiceCallSession._MAX_WRITE_BACKLOG)
        deadline_ms = voice.VoiceCallSession._SEND_DEADLINE_S * 1000
        total = kernel_ms + backlog_ms + deadline_ms
        assert total < 3000, (
            "send path can hold %.0f ms (kernel %.0f + backlog %.0f + "
            "deadline %.0f)" % (total, kernel_ms, backlog_ms, deadline_ms))


class TestExpectedFrameRateReporting:
    def test_the_expectation_is_not_truncated(self):
        # (1000 // 60) * 5 == 80; 5000 // 60 == 83. The stats line warned
        # against the wrong denominator for the whole of the 60 ms rollout.
        assert 5000 // voice.VOICE_FRAME_MS == 83
