"""Where the milliseconds actually go.

The reported one-way figure is stamped right after Opus encode and read
right after AEAD decrypt, so it contains seal, the hop to the event loop,
the wait for that loop to run the callback, sendto, I2P, receive and verify
-- all in one number. A 700-1000 ms reading could be a slow path or a busy
device and the aggregate cannot tell them apart.

These cover the instrumentation that separates them.
"""

import time

import pytest

import otrv4plus_voice as voice


class TestStageTimers:
    def test_every_pipeline_stage_is_named(self):
        # If a stage is missing from here it is missing from the budget, and
        # its milliseconds get silently attributed to the network.
        for stage in ("encode", "seal", "queue", "decrypt", "dwell",
                      "decode", "play"):
            assert stage in voice.StageTimers.NAMES

    def test_it_records_in_milliseconds(self):
        st = voice.StageTimers()
        st.record("encode", 0.005)
        assert st.t["encode"].percentile(0.5) == pytest.approx(5.0, rel=0.01)

    def test_record_since_measures_elapsed(self):
        st = voice.StageTimers()
        start = time.monotonic()
        time.sleep(0.02)
        st.record_since("decode", start)
        assert st.t["decode"].percentile(0.5) >= 15.0

    def test_a_negative_duration_is_refused(self):
        # A clock that went backwards must not poison the percentiles.
        st = voice.StageTimers()
        st.record("encode", -1.0)
        assert len(st.t["encode"]) == 0

    def test_an_unknown_stage_is_ignored_rather_than_raising(self):
        # This runs on the real-time path; a typo must not kill a call.
        st = voice.StageTimers()
        st.record("nonsense", 0.01)

    def test_the_local_send_contribution_is_seal_plus_queue(self):
        # Exactly the part of the one-way figure this device produced.
        st = voice.StageTimers()
        for _ in range(10):
            st.record("seal", 0.001)
            st.record("queue", 0.004)
            st.record("decode", 0.100)      # not part of the send side
        assert st.local_send_ms() == pytest.approx(5.0, rel=0.05)

    def test_the_summary_omits_stages_with_no_samples(self):
        st = voice.StageTimers()
        st.record("encode", 0.001)
        text = st.summary()
        assert "encode" in text
        assert "decode" not in text

    def test_an_empty_timer_says_so(self):
        assert voice.StageTimers().summary() == "no samples"

    def test_the_window_is_bounded(self):
        st = voice.StageTimers(window=32)
        for _ in range(500):
            st.record("encode", 0.001)
        assert len(st.t["encode"]) == 32


class TestJitterDwellIsMeasuredNotInferred:
    """Depth x frame duration assumes playout is exactly on time.

    The moment that assumption breaks is precisely when the number matters,
    so arrival time rides with the frame and dwell is measured per frame.
    """

    def test_dwell_reflects_real_elapsed_time(self):
        buf = voice.JitterBuffer(prefill=2, maxlen=20, adaptive=False)
        for i in range(6):
            buf.push(0, i, bytearray(b"x" * 8))
        time.sleep(0.05)
        buf.pop()
        assert buf.dwell.percentile(0.5) >= 40.0

    def test_dwell_is_recorded_per_frame(self):
        buf = voice.JitterBuffer(prefill=1, maxlen=20, adaptive=False)
        for i in range(5):
            buf.push(0, i, bytearray(b"x" * 8))
        for _ in range(3):
            buf.pop()
        assert len(buf.dwell) == 3

    def test_the_frame_still_survives_the_round_trip(self):
        # Arrival time is a third heap element; the payload must come back
        # unchanged.
        buf = voice.JitterBuffer(prefill=1, maxlen=20, adaptive=False)
        buf.push(0, 0, bytearray(b"payload!"))
        item = buf.pop()
        assert item is not None
        assert bytes(item[0]) == b"payload!"

    def test_ordering_still_holds_with_the_extra_element(self):
        buf = voice.JitterBuffer(prefill=1, shed_margin=8, maxlen=40,
                                 adaptive=False)
        for i in (3, 0, 4, 1, 2):
            buf.push(0, i, bytearray(bytes([i]) * 4))
        seen = []
        while True:
            item = buf.pop()
            if item is None:
                break
            seen.append(item[0][0])
        assert seen == [0, 1, 2, 3, 4]

    def test_shedding_still_works_with_the_extra_element(self):
        buf = voice.JitterBuffer(prefill=2, drift_high=3, shed_margin=1,
                                 maxlen=60, adaptive=False)
        for i in range(40):
            buf.push(0, i, bytearray(b"x" * 8))
        buf.pop()
        assert buf.stats["drift"] > 0

    def test_overflow_still_works_with_the_extra_element(self):
        buf = voice.JitterBuffer(prefill=1, maxlen=5, adaptive=False)
        for i in range(20):
            buf.push(0, i, bytearray(b"x" * 8))
        assert buf.depth() <= 5
        assert buf.stats["overflow"] > 0

    def test_clear_still_works_with_the_extra_element(self):
        buf = voice.JitterBuffer(prefill=1, maxlen=20, adaptive=False)
        for i in range(5):
            buf.push(0, i, bytearray(b"x" * 8))
        buf.clear()
        assert buf.depth() == 0


class TestLoopLagSeparatesUsFromTheNetwork:
    """slixmpp and the media path share one event loop and one thread.

    Media sendto, AEAD for every inbound frame, XMPP TLS and XML, OTR
    handling including ML-DSA-87 verification, and rekey keygen all run
    there, and the GIL means none of it overlaps. XMPP work therefore delays
    media, and in arrival-spacing terms that is indistinguishable from
    network jitter.
    """

    def test_a_busy_loop_is_visible_as_lag(self):
        import asyncio

        lag = voice.Percentiles(512)

        async def monitor():
            for _ in range(15):
                start = time.monotonic()
                await asyncio.sleep(0.05)
                lag.add(max(0.0, (time.monotonic() - start - 0.05) * 1000.0))

        async def blocker():
            for _ in range(6):
                await asyncio.sleep(0.02)
                time.sleep(0.04)          # stands in for ML-DSA-87 verify

        async def main():
            await asyncio.gather(monitor(), blocker())

        asyncio.run(main())
        assert lag.percentile(0.99) > 10.0, (
            "a loop blocked for 40 ms at a time must show up as lag")

    def test_an_idle_loop_reports_near_zero(self):
        import asyncio

        lag = voice.Percentiles(512)

        async def main():
            for _ in range(10):
                start = time.monotonic()
                await asyncio.sleep(0.02)
                lag.add(max(0.0, (time.monotonic() - start - 0.02) * 1000.0))

        asyncio.run(main())
        assert lag.percentile(0.50) < 10.0
