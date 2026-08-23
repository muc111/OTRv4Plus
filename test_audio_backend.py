#!/usr/bin/env python3
"""Tests for the OTRv4+ audio backend (otrv4plus_audio).

    python3 -m unittest test_audio_backend -v

Runs anywhere. AAudio itself cannot be exercised off Android, so the tests
that need a device drive a fake libaaudio through the same ctypes call path —
which is enough to cover the logic that is actually mine: error
classification, resampling, framing, disconnect handling and teardown. The
parts that can only be verified on hardware are listed at the bottom of the
audit report rather than faked into a green tick here.
"""

import struct
import time
import unittest

import otrv4plus_audio as A


def _int(v):
    """ctypes hands the fake c_int32/c_int64 objects, not plain ints."""
    return int(getattr(v, "value", v))


class FakeAAudioLib:
    """A stand-in for libaaudio.so driving the real ctypes call path."""

    def __init__(self, open_rc=A.AAUDIO_OK, start_rc=A.AAUDIO_OK,
                 device_rate=A.SAMPLE_RATE, device_channels=1,
                 fmt=A.AAUDIO_FORMAT_PCM_I16, read_plan=None,
                 has_input_preset=True, frames_per_burst=96, steady=None):
        self.open_rc = open_rc
        self.start_rc = start_rc
        self.device_rate = device_rate
        self.device_channels = device_channels
        self.fmt = fmt
        self.read_plan = list(read_plan or [])
        self.frames_per_burst = frames_per_burst
        # A real microphone keeps producing after the scripted plan runs out.
        # Without this the fake goes silent mid-frame and reassembly tests
        # fail for a reason that has nothing to do with the code under test.
        self.steady = steady
        self.reads = 0
        self.read_sizes = []
        self.started = 0
        self.stopped = 0
        self.closed = 0
        self.builders_deleted = 0
        self.input_preset = None
        self.written_frames = 0
        self._handle = 0x1000
        # Android 8 has no setInputPreset; shadow the class method with
        # None so getattr() finds nothing, as it would on the real lib.
        if not has_input_preset:
            self.AAudioStreamBuilder_setInputPreset = None

    # -- builder ----------------------------------------------------------

    def AAudio_createStreamBuilder(self, out):
        out._obj.value = 0x2000
        return A.AAUDIO_OK

    def AAudioStreamBuilder_setDirection(self, b, v): self.direction = v
    def AAudioStreamBuilder_setSampleRate(self, b, v): self.req_rate = v
    def AAudioStreamBuilder_setChannelCount(self, b, v): self.req_ch = v
    def AAudioStreamBuilder_setFormat(self, b, v): self.req_fmt = v
    def AAudioStreamBuilder_setSharingMode(self, b, v): pass
    def AAudioStreamBuilder_setPerformanceMode(self, b, v): pass
    def AAudioStreamBuilder_setBufferCapacityInFrames(self, b, v): self.cap = v
    def AAudioStreamBuilder_setInputPreset(self, b, v): self.input_preset = v

    def AAudioStreamBuilder_openStream(self, b, out):
        if self.open_rc != A.AAUDIO_OK:
            return self.open_rc
        out._obj.value = self._handle
        return A.AAUDIO_OK

    def AAudioStreamBuilder_delete(self, b):
        self.builders_deleted += 1
        return A.AAUDIO_OK

    # -- stream -----------------------------------------------------------

    def AAudioStream_requestStart(self, s):
        if self.start_rc == A.AAUDIO_OK:
            self.started += 1
        return self.start_rc

    def AAudioStream_requestStop(self, s):
        self.stopped += 1
        return A.AAUDIO_OK

    def AAudioStream_close(self, s):
        self.closed += 1
        return A.AAUDIO_OK

    def AAudioStream_getSampleRate(self, s): return self.device_rate
    def AAudioStream_getChannelCount(self, s): return self.device_channels
    def AAudioStream_getFormat(self, s): return self.fmt
    def AAudioStream_getState(self, s): return A.AAUDIO_STREAM_STATE_STARTED
    def AAudioStream_getBufferCapacityInFrames(self, s): return 2560
    def AAudioStream_getFramesPerBurst(self, s): return self.frames_per_burst
    def AAudioStream_getBufferSizeInFrames(self, s): return 1920
    def AAudioStream_getPerformanceMode(self, s): return 12

    def AAudioStream_read(self, stream, buf, num_frames, timeout):
        self.reads += 1
        self.read_sizes.append(_int(num_frames))
        if not self.read_plan:
            if self.steady is None:
                return 0
            item = (self.steady, _int(num_frames))
        else:
            item = self.read_plan.pop(0)
        if isinstance(item, int):
            return item
        amplitude, frames = item
        frames = min(frames, _int(num_frames))
        total = frames * self.device_channels
        payload = struct.pack("<%dh" % total, *([amplitude] * total))
        import ctypes
        ctypes.memmove(buf, payload, len(payload))
        return frames

    def AAudioStream_write(self, stream, buf, num_frames, timeout):
        if self.read_plan:
            item = self.read_plan.pop(0)
            if isinstance(item, int) and item < 0:
                return item
        self.written_frames += _int(num_frames)
        return _int(num_frames)

    def AAudio_convertResultToText(self, code):
        return b"FAKE_RESULT_%d" % _int(code)


def install(lib):
    A._LIB = lib
    A._LIB_ERROR = None
    return lib


class BackendBase(unittest.TestCase):
    def tearDown(self):
        A._LIB = None
        A._LIB_ERROR = None


# ===========================================================================
# 1. Backend initialises  /  2. Permission failure  /  3. Format
# ===========================================================================

class TestInitialisation(BackendBase):

    def test_capture_initialises(self):
        lib = install(FakeAAudioLib(read_plan=[(1000, A.FRAME_SAMPLES)]))
        cap = A.AAudioCapture()
        self.assertEqual(lib.started, 1)
        self.assertEqual(lib.direction, A.AAUDIO_DIRECTION_INPUT)
        self.assertEqual(lib.req_rate, 16000)
        self.assertEqual(lib.req_ch, 1)
        self.assertEqual(lib.req_fmt, A.AAUDIO_FORMAT_PCM_I16)
        self.assertEqual(lib.builders_deleted, 1, "builder must not leak")
        cap.stop()

    def test_voice_communication_preset_preferred(self):
        lib = install(FakeAAudioLib())
        cap = A.AAudioCapture()
        self.assertEqual(lib.input_preset,
                         A.AAUDIO_INPUT_PRESET_VOICE_COMMUNICATION)
        cap.stop()

    def test_missing_preset_setter_tolerated(self):
        install(FakeAAudioLib(has_input_preset=False))
        cap = A.AAudioCapture()          # Android 8: no setInputPreset
        cap.stop()

    def test_permission_denied_is_structured(self):
        for rc in (A.AAUDIO_ERROR_UNAVAILABLE, A.AAUDIO_ERROR_NO_SERVICE,
                   A.AAUDIO_ERROR_INVALID_STATE):
            install(FakeAAudioLib(open_rc=rc))
            with self.assertRaises(A.AudioError) as ctx:
                A.AAudioCapture()
            self.assertEqual(ctx.exception.code,
                             A.MICROPHONE_PERMISSION_DENIED)
            self.assertIn("RECORD_AUDIO", ctx.exception.detail)

    def test_init_failure_is_distinct_from_permission(self):
        install(FakeAAudioLib(open_rc=A.AAUDIO_ERROR_INTERNAL
                              if hasattr(A, "AAUDIO_ERROR_INTERNAL") else -896))
        with self.assertRaises(A.AudioError) as ctx:
            A.AAudioCapture()
        self.assertEqual(ctx.exception.code,
                         A.AUDIO_RECORD_INITIALIZATION_FAILED)

    def test_format_unavailable_is_distinct(self):
        for rc in (A.AAUDIO_ERROR_INVALID_FORMAT, A.AAUDIO_ERROR_INVALID_RATE):
            install(FakeAAudioLib(open_rc=rc))
            with self.assertRaises(A.AudioError) as ctx:
                A.AAudioCapture()
            self.assertEqual(ctx.exception.code, A.AUDIO_FORMAT_UNAVAILABLE)

    def test_non_pcm16_device_rejected_and_closed(self):
        lib = install(FakeAAudioLib(fmt=4))       # PCM_FLOAT
        with self.assertRaises(A.AudioError) as ctx:
            A.AAudioCapture()
        self.assertEqual(ctx.exception.code, A.AUDIO_FORMAT_UNAVAILABLE)
        self.assertEqual(lib.closed, 1, "stream must be closed on rejection")

    def test_start_failure_closes_the_stream(self):
        lib = install(FakeAAudioLib(start_rc=A.AAUDIO_ERROR_INVALID_STATE))
        with self.assertRaises(A.AudioError):
            A.AAudioCapture()
        self.assertEqual(lib.closed, 1)

    def test_library_absent_is_structured(self):
        A._LIB = None
        A._LIB_ERROR = "libaaudio.so not found"
        with self.assertRaises(A.AudioError) as ctx:
            A.AAudioCapture()
        self.assertEqual(ctx.exception.code, A.AUDIO_BACKEND_UNAVAILABLE)


# ===========================================================================
# 4-6. Capture starts, frames delivered, correct format
# ===========================================================================

class TestCapture(BackendBase):

    def test_frame_size_and_format(self):
        install(FakeAAudioLib(steady=1234))
        cap = A.AAudioCapture()
        frame = cap.read_frame()
        self.assertEqual(len(frame), A.FRAME_BYTES)
        # Was a literal 1280/640, which encoded a 40 ms frame. Production
        # moved to 60 ms deliberately in 29b9c28, so the literal described a
        # contract that no longer existed while the derived assertion beside
        # it stayed correct. Derived only, so it holds at any configured
        # OTRV4PLUS_OPUS_FRAME_MS.
        samples = struct.unpack("<%dh" % A.FRAME_SAMPLES, frame)
        self.assertEqual(len(samples), A.FRAME_SAMPLES)
        self.assertTrue(all(s == 1234 for s in samples))
        cap.stop()

    def test_partial_reads_are_reassembled(self):
        chunk = A.FRAME_SAMPLES // 4
        install(FakeAAudioLib(frames_per_burst=chunk, steady=7))
        cap = A.AAudioCapture()
        frame = cap.read_frame()
        self.assertEqual(len(frame), A.FRAME_BYTES)
        cap.stop()

    def test_timeout_returns_none_not_failure(self):
        install(FakeAAudioLib(read_plan=[A.AAUDIO_ERROR_TIMEOUT]))
        cap = A.AAudioCapture()
        self.assertIsNone(cap.read_frame())
        cap.stop()

    def test_zero_frame_read_does_not_busy_loop(self):
        # A zero return must yield to the caller rather than spin. The fake
        # returns 0 forever; if read_frame looped it would never return.
        install(FakeAAudioLib(read_plan=[]))
        cap = A.AAudioCapture()
        self.assertIsNone(cap.read_frame())
        cap.stop()

    def test_dead_object_raises_disconnect(self):
        install(FakeAAudioLib(read_plan=[A.AAUDIO_ERROR_DISCONNECTED]))
        cap = A.AAudioCapture()
        with self.assertRaises(A.AudioError) as ctx:
            cap.read_frame()
        self.assertEqual(ctx.exception.code, A.AUDIO_DEVICE_DISCONNECTED)
        self.assertTrue(cap.diagnostics()["disconnected"])
        cap.stop()

    def test_read_after_stop_returns_none(self):
        install(FakeAAudioLib(read_plan=[(1, A.FRAME_SAMPLES)]))
        cap = A.AAudioCapture()
        cap.stop()
        self.assertIsNone(cap.read_frame())

    def test_no_unbounded_buffering(self):
        # Every completed frame must leave the pending buffer, or a long call
        # would grow memory without limit.
        install(FakeAAudioLib(steady=3))
        cap = A.AAudioCapture()
        for _ in range(40):
            if cap.read_frame() is None:
                break
        self.assertLess(len(cap._pending), A.FRAME_BYTES)
        cap.stop()


# ===========================================================================
# 7-8, 10. Clean stop, repeated start/stop, teardown
# ===========================================================================

class TestLifecycle(BackendBase):

    def test_stop_releases_the_device(self):
        lib = install(FakeAAudioLib())
        cap = A.AAudioCapture()
        cap.stop()
        self.assertEqual(lib.stopped, 1)
        self.assertEqual(lib.closed, 1)

    def test_stop_is_idempotent(self):
        lib = install(FakeAAudioLib())
        cap = A.AAudioCapture()
        cap.stop()
        cap.stop()
        cap.stop()
        self.assertEqual(lib.closed, 1, "device closed more than once")

    def test_repeated_open_close_does_not_leak(self):
        lib = install(FakeAAudioLib())
        for _ in range(25):
            cap = A.AAudioCapture()
            cap.stop()
        self.assertEqual(lib.started, 25)
        self.assertEqual(lib.closed, 25)
        self.assertEqual(lib.builders_deleted, 25)

    def test_stop_wipes_residual_pcm(self):
        install(FakeAAudioLib(frames_per_burst=A.FRAME_SAMPLES // 2,
                              read_plan=[(9999, A.FRAME_SAMPLES // 2)]))
        cap = A.AAudioCapture()
        cap.read_frame()
        self.assertGreater(len(cap._pending), 0)
        cap.stop()
        self.assertEqual(len(cap._pending), 0)


# ===========================================================================
# Playback
# ===========================================================================

class TestPlayback(BackendBase):

    def test_playback_opens_as_output(self):
        lib = install(FakeAAudioLib())
        out = A.AAudioPlayback()
        self.assertEqual(lib.direction, A.AAUDIO_DIRECTION_OUTPUT)
        self.assertTrue(out.write_frame(b"\x00" * A.FRAME_BYTES))
        self.assertEqual(lib.written_frames, A.FRAME_SAMPLES)
        out.stop()

    def test_playback_disconnect(self):
        install(FakeAAudioLib(read_plan=[A.AAUDIO_ERROR_DISCONNECTED]))
        out = A.AAudioPlayback()
        with self.assertRaises(A.AudioError) as ctx:
            out.write_frame(b"\x00" * A.FRAME_BYTES)
        self.assertEqual(ctx.exception.code, A.AUDIO_DEVICE_DISCONNECTED)
        out.stop()

    def test_stereo_device_gets_duplicated_channels(self):
        lib = install(FakeAAudioLib(device_channels=2))
        out = A.AAudioPlayback()
        out.write_frame(b"\x00" * A.FRAME_BYTES)
        self.assertEqual(lib.written_frames, A.FRAME_SAMPLES)
        out.stop()


# ===========================================================================
# Format negotiation and resampling
# ===========================================================================

class TestResampling(unittest.TestCase):

    def test_no_op_when_rates_match(self):
        r = A.Resampler(16000, 16000, 1)
        self.assertFalse(r.needed)
        data = b"\x01\x02" * 100
        self.assertEqual(r.process(data), data)

    def test_48k_to_16k_thirds_the_sample_count(self):
        r = A.Resampler(48000, 16000, 1)
        self.assertTrue(r.needed)
        pcm = struct.pack("<1920h", *([500] * 1920))
        out = r.process(pcm)
        produced = len(out) // 2
        # 1920 / 3. This is the resampler's ratio, not the frame geometry, so
        # it stays a literal and must NOT follow FRAME_SAMPLES.
        self.assertAlmostEqual(produced, 640, delta=8)

    def test_44100_to_16000_non_integer_ratio(self):
        r = A.Resampler(44100, 16000, 1)
        pcm = struct.pack("<4410h", *([100] * 4410))
        produced = len(r.process(pcm)) // 2
        self.assertAlmostEqual(produced, 1600, delta=40)

    def test_dc_level_preserved_through_decimation(self):
        r = A.Resampler(48000, 16000, 1)
        pcm = struct.pack("<1920h", *([1000] * 1920))
        out = struct.unpack("<%dh" % (len(r.process(pcm)) // 2),
                            r.process(pcm))
        if out:
            self.assertAlmostEqual(sum(out) / len(out), 1000, delta=60)

    def test_stereo_downmix_to_mono(self):
        r = A.Resampler(16000, 16000, 2)
        self.assertTrue(r.needed)
        pcm = struct.pack("<8h", 100, 300, 100, 300, 100, 300, 100, 300)
        out = struct.unpack("<4h", r.process(pcm))
        self.assertEqual(out, (200, 200, 200, 200))

    def test_pure_python_fallback_matches_shape(self):
        saved = A._audioop
        try:
            A._audioop = None
            r = A.Resampler(48000, 16000, 1)
            pcm = struct.pack("<960h", *([250] * 960))
            produced = len(r.process(pcm)) // 2
            self.assertEqual(produced, 320)
        finally:
            A._audioop = saved

    def test_capture_resamples_to_canonical_frame(self):
        A._LIB = FakeAAudioLib(device_rate=48000, frames_per_burst=960,
                               steady=400)
        A._LIB_ERROR = None
        try:
            cap = A.AAudioCapture()
            self.assertEqual(cap.device_rate, 48000)
            self.assertTrue(cap.diagnostics()["resampling"])
            frame = cap.read_frame()
            self.assertEqual(len(frame), A.FRAME_BYTES,
                             "pipeline must always see 40 ms of 16 kHz mono")
            cap.stop()
        finally:
            A._LIB = None


# ===========================================================================
# Selection policy, and the constraints the brief sets
# ===========================================================================

class TestSelection(BackendBase):

    def test_aaudio_is_preferred(self):
        self.assertEqual(A.BACKEND_ORDER[0], A.BACKEND_AAUDIO)

    def test_permission_denial_is_not_papered_over_by_fallback(self):
        # Falling through to PulseAudio here would open auto_null and the call
        # would encrypt and transmit silence while looking healthy.
        install(FakeAAudioLib(open_rc=A.AAUDIO_ERROR_UNAVAILABLE))
        with self.assertRaises(A.AudioError) as ctx:
            A.open_capture()
        self.assertEqual(ctx.exception.code, A.MICROPHONE_PERMISSION_DENIED)

    def test_explicit_backend_is_honoured_exactly(self):
        self.assertEqual(A._pick_order("pulseaudio"), ("pulseaudio",))
        self.assertEqual(A._pick_order("aaudio"), ("aaudio",))
        self.assertEqual(A._pick_order(None), A.BACKEND_ORDER)

    def test_termux_api_is_never_a_live_backend(self):
        info = A._probe_termux_api()
        self.assertFalse(info["usable_for_calls"])
        self.assertNotIn("termux", A.BACKEND_ORDER)

    def test_no_audio_files_are_created(self):
        import tempfile, os as _os
        d = tempfile.mkdtemp()
        before = set(_os.listdir(d))
        install(FakeAAudioLib(steady=5))
        cap = A.AAudioCapture()
        for _ in range(10):
            cap.read_frame()
        cap.stop()
        self.assertEqual(set(_os.listdir(d)), before)

    def test_diagnostics_carry_no_samples(self):
        install(FakeAAudioLib(steady=31000))
        cap = A.AAudioCapture()
        cap.read_frame()
        diag = cap.diagnostics()
        # Every value must be a scalar describing configuration, never audio.
        for key, value in diag.items():
            self.assertNotIsInstance(value, (bytes, bytearray),
                                     "%s carries raw data" % key)
        self.assertEqual(
            set(diag) & {"selected_source", "pcm", "samples", "buffer"}, set())
        self.assertIn("device_rate", diag)
        self.assertIn("encoding", diag)
        cap.stop()


class TestBurstAlignment(BackendBase):
    """Reads must line up with the device's hardware burst.

    The target device reports framesPerBurst=480. A read that is not a whole
    number of bursts straddles them, so every read waits on a partially
    filled second burst.
    """

    def test_read_size_matches_frames_per_burst(self):
        lib = install(FakeAAudioLib(frames_per_burst=480, steady=100))
        cap = A.AAudioCapture()
        self.assertEqual(cap._chunk_frames, 480)
        cap.read_frame()
        self.assertTrue(lib.read_sizes)
        self.assertTrue(all(n == 480 for n in lib.read_sizes),
                        "reads must be burst-aligned, got %s" % lib.read_sizes)
        cap.stop()

    def test_frame_is_still_exactly_one_frame_on_that_device(self):
        install(FakeAAudioLib(frames_per_burst=480, steady=250))
        cap = A.AAudioCapture()
        for _ in range(5):
            frame = cap.read_frame()
            self.assertEqual(len(frame), A.FRAME_BYTES)
        cap.stop()

    def test_absurd_burst_falls_back_to_frame_sized_reads(self):
        install(FakeAAudioLib(frames_per_burst=99999, steady=1))
        cap = A.AAudioCapture()
        self.assertEqual(cap._chunk_frames, A.FRAME_SAMPLES)
        cap.stop()

    def test_unreported_burst_falls_back(self):
        install(FakeAAudioLib(frames_per_burst=0, steady=1))
        cap = A.AAudioCapture()
        self.assertEqual(cap._chunk_frames, A.FRAME_SAMPLES)
        cap.stop()

    def test_matches_the_validated_device_profile(self):
        # Exactly what the hardware reported: 16 kHz, mono, PCM_I16,
        # capacity 2560, burst 480, no resampling.
        lib = install(FakeAAudioLib(device_rate=16000, device_channels=1,
                                    frames_per_burst=480, steady=30628))
        lib.AAudioStream_getBufferCapacityInFrames = lambda s: 2560
        cap = A.AAudioCapture()
        diag = cap.diagnostics()
        self.assertEqual(diag["device_rate"], 16000)
        self.assertEqual(diag["device_channels"], 1)
        self.assertEqual(diag["encoding"], "PCM_16BIT")
        self.assertEqual(diag["buffer_capacity_frames"], 2560)
        self.assertEqual(diag["frames_per_burst"], 480)
        self.assertFalse(diag["resampling"])
        self.assertFalse(diag["disconnected"])
        frame = cap.read_frame()
        self.assertEqual(len(frame), A.FRAME_BYTES)
        peak = max(abs(v) for v in
                   struct.unpack("<%dh" % A.FRAME_SAMPLES, frame))
        self.assertEqual(peak, 30628)
        cap.stop()


class TestPlaintextWiping(BackendBase):

    def test_stop_wipes_the_raw_device_buffer(self):
        # _raw holds the last burst read straight off the microphone.
        # Wiping only _pending leaves up to one burst of real speech behind.
        install(FakeAAudioLib(frames_per_burst=480, steady=25000))
        cap = A.AAudioCapture()
        cap.read_frame()
        self.assertTrue(any(v != 0 for v in cap._raw),
                        "fixture did not populate the raw buffer")
        cap.stop()
        self.assertTrue(all(v == 0 for v in cap._raw),
                        "raw microphone buffer survived teardown")

    def test_stop_wipes_partial_frame(self):
        install(FakeAAudioLib(frames_per_burst=A.FRAME_SAMPLES // 2,
                              read_plan=[(31000, A.FRAME_SAMPLES // 2)]))
        cap = A.AAudioCapture()
        cap.read_frame()
        self.assertGreater(len(cap._pending), 0)
        cap.stop()
        self.assertEqual(len(cap._pending), 0)


class TestPlaybackPinning(BackendBase):
    """Playback must not fall back independently of capture.

    AAudio capture with PulseAudio playback is a one-way call: the peer hears
    us and we hear auto_null, with nothing reporting a fault.
    """

    def test_pinned_backend_does_not_try_pulseaudio(self):
        install(FakeAAudioLib(open_rc=A.AAUDIO_ERROR_INVALID_STATE))
        with self.assertRaises(A.AudioError):
            A.open_playback(preferred="aaudio")

    def test_pinning_is_exact(self):
        self.assertEqual(A._pick_order("aaudio"), ("aaudio",))

    def test_voice_pins_playback_to_capture_backend(self):
        import inspect
        import otrv4plus_voice as V
        src = inspect.getsource(V.VoiceCallSession._open_audio_devices)
        self.assertIn("preferred=self._capture.name", src,
                      "playback must be pinned to the capture backend")


class TestRinger(BackendBase):
    """Incoming-call ringer: audible, silenceable, and never blocking a call."""

    def test_pattern_is_canonical_pcm(self):
        frames = A.Ringer._build_pattern()
        self.assertGreater(len(frames), 20)
        for f in frames:
            self.assertEqual(len(f), A.FRAME_BYTES)

    def test_pattern_has_tone_and_silence(self):
        frames = A.Ringer._build_pattern()
        peaks = []
        for f in frames:
            n = len(f) // 2
            peaks.append(max(abs(v) for v in struct.unpack("<%dh" % n, f)))
        self.assertGreater(max(peaks), 3000, "ringer must be audible")
        self.assertEqual(min(peaks), 0, "pattern must contain silent gaps")
        self.assertLess(max(peaks), 32767, "must not clip")

    def test_ringing_plays_through_the_backend(self):
        lib = install(FakeAAudioLib())
        r = A.Ringer(notify=False, vibrate=False)
        r.start(peer="p@e.org")
        # Wait for actual audio, not just for the device to open: started is
        # set the moment the stream exists, and stopping there would race the
        # first write.
        deadline = time.time() + 5.0
        while time.time() < deadline and lib.written_frames == 0:
            time.sleep(0.02)
        self.assertTrue(r.started, "ringer never opened playback: %s" % r.error)
        r.stop()
        self.assertGreater(lib.written_frames, 0)
        self.assertEqual(lib.closed, 1, "ringer must release the device")

    def test_stop_is_idempotent_and_releases_once(self):
        lib = install(FakeAAudioLib())
        r = A.Ringer(notify=False, vibrate=False)
        r.start(peer="p@e.org")
        time.sleep(0.2)
        r.stop()
        r.stop()
        self.assertLessEqual(lib.closed, 1)

    def test_no_playback_device_does_not_raise(self):
        # A silent ring is survivable; a crash in the receive path is not.
        #
        # BOTH backends must be suppressed for this to be the no-device case.
        # Clearing _LIB/_LIB_ERROR only removes AAudio; open_playback then
        # falls back to PulseAudio and, on a device that actually has pacat --
        # i.e. every phone this software is meant to run on -- opens
        # successfully and sets started=True. The test was asserting a
        # property of the host, not of the ringer, and failed on Termux for
        # that reason. `which` is the documented seam for suppressing the
        # PulseAudio probe, so use it and make the case deterministic
        # everywhere.
        saved_lib, saved_err = A._LIB, A._LIB_ERROR
        A._LIB = None
        A._LIB_ERROR = "no libaaudio"
        try:
            r = A.Ringer(notify=False, vibrate=False)
            r.start(peer="p@e.org", which=lambda _binary: None)
            time.sleep(0.3)
            r.stop()                       # must not raise: that is the test
            self.assertFalse(r.started)
            self.assertIsNotNone(r.error)
        finally:
            # These are module globals. Leaving them clobbered made this test
            # a source of order-dependent failures in whatever ran next.
            A._LIB, A._LIB_ERROR = saved_lib, saved_err

    def test_a_working_backend_still_rings(self):
        """The counterpart, on a host that does have playback.

        Guards against "does not raise" being satisfied by a ringer that
        never rings anywhere.
        """
        lib = install(FakeAAudioLib())
        r = A.Ringer(notify=False, vibrate=False)
        r.start(peer="p@e.org")
        deadline = time.time() + 5.0
        while time.time() < deadline and lib.written_frames == 0:
            time.sleep(0.02)
        try:
            self.assertTrue(r.started, "ringer never opened playback: %s"
                            % r.error)
            self.assertIsNone(r.error)
        finally:
            r.stop()

    def test_privacy_mode_keeps_the_jid_off_the_lock_screen(self):
        import inspect
        src = inspect.getsource(A.Ringer._post_notification)
        self.assertIn("OTRV4PLUS_RING_PRIVACY", src)
        self.assertIn("Open Termux to answer", src)

    def test_ringer_stops_before_call_playback_opens(self):
        import inspect
        import otrv4plus_voice as V
        src = inspect.getsource(V.VoiceCallManager.answer_call)
        self.assertIn("self._stop_ringing(peer)", src)
        self.assertLess(src.index("_stop_ringing"),
                        src.index("responder_derive"),
                        "ringer must be silenced before the call takes the "
                        "audio device")


class TestAdaptiveJitter(unittest.TestCase):
    """Target depth must track the path instead of being fixed."""

    def _sim(self, spikes, n=400, seed=1):
        import random
        import otrv4plus_voice as V
        random.seed(seed)
        jb = V.JitterBuffer()
        t = 0.0
        for i in range(n):
            # Pace at the module's frame interval. Hardcoding 0.040 fed a
            # 40 ms cadence into a pipeline that now expects 60 ms, so the
            # estimator correctly reported the 20 ms difference as jitter --
            # a property of the test, not of the path being simulated.
            t += V.FRAME_INTERVAL_S + random.choice(spikes)
            jb._observe_arrival(jb.sequence(0, i), t)
        return jb

    def test_clean_path_stays_at_the_floor(self):
        import otrv4plus_voice as V
        jb = self._sim([0.0])
        self.assertEqual(jb.target_depth, V.VOICE_JITTER_PREFILL)
        self.assertLess(jb.jitter_ms, 1.0)

    def test_bad_path_grows_the_cushion(self):
        import otrv4plus_voice as V
        jb = self._sim([0.0, 0.25, 0.4])
        self.assertGreater(jb.jitter_ms, 100.0)
        self.assertGreater(jb.target_depth, V.VOICE_JITTER_PREFILL)
        self.assertLessEqual(jb.target_depth, V.VOICE_JITTER_DRIFT_HIGH)

    def test_target_is_always_bounded(self):
        import otrv4plus_voice as V
        for spikes in ([0.0], [0.0, 0.5], [2.0], [0.0, 0.01, 0.9]):
            jb = self._sim(spikes, n=200)
            self.assertGreaterEqual(jb.target_depth, V.VOICE_JITTER_PREFILL)
            self.assertLessEqual(jb.target_depth, V.VOICE_JITTER_DRIFT_HIGH)

    def test_recovers_when_the_path_settles(self):
        import otrv4plus_voice as V
        jb = self._sim([0.0, 0.3], n=200)
        bad = jb.target_depth
        t = 100.0
        for i in range(200, 900):
            t += 0.040
            jb._observe_arrival(jb.sequence(0, i), t)
        self.assertLess(jb.target_depth, bad,
                        "cushion must shrink once the path recovers")
        self.assertEqual(jb.target_depth, V.VOICE_JITTER_PREFILL)


class TestHostApiCompatibility(unittest.TestCase):
    """Names otrv4plus_xmpp.py reaches for must exist on the objects it uses.

    The v3 rewrite moved CALL_PREFIX from a VoiceCallManager class attribute
    to module scope. otrv4plus_xmpp.py checks
    `text.startswith(VoiceCallManager.CALL_PREFIX)` in three places to decide
    whether a decrypted body is call signalling, so every inbound INVITE
    raised AttributeError inside the OTR receive path and voice could never
    start. Compiling and importing cleanly did not catch it, because the
    attribute is only touched when a call actually arrives.
    """

    def test_call_prefix_on_both_class_and_module(self):
        import otrv4plus_voice as V
        self.assertEqual(V.VoiceCallManager.CALL_PREFIX, V.CALL_PREFIX)
        self.assertTrue(V.CALL_PREFIX.startswith("?OTRv4-CALL"))

    def test_every_attribute_the_host_dereferences_exists(self):
        import re
        import otrv4plus_voice as V
        try:
            with open("otrv4plus_xmpp.py") as fh:
                src = fh.read()
        except OSError:
            self.skipTest("otrv4plus_xmpp.py not beside the tests")
        missing = []
        for cls, attr in re.findall(
                r"\b(VoiceCallManager|VoiceCallSession|CallState)\.([A-Za-z_]+)",
                src):
            obj = getattr(V, cls, None)
            if obj is not None and not hasattr(obj, attr):
                missing.append("%s.%s" % (cls, attr))
        self.assertEqual(sorted(set(missing)), [],
                         "otrv4plus_xmpp.py dereferences names the voice "
                         "module does not define")


class TestPipelineAgreement(unittest.TestCase):
    """The audio module and the voice module must not drift apart."""

    def test_constants_match_the_voice_pipeline(self):
        import otrv4plus_voice as V
        self.assertEqual(A.SAMPLE_RATE, V.VOICE_SAMPLE_RATE)
        self.assertEqual(A.CHANNELS, V.VOICE_CHANNELS)
        self.assertEqual(A.FRAME_MS, V.VOICE_FRAME_MS)
        self.assertEqual(A.FRAME_SAMPLES, V.VOICE_FRAME_SAMPLES)
        self.assertEqual(A.FRAME_BYTES, V.VOICE_FRAME_BYTES)


if __name__ == "__main__":
    unittest.main(verbosity=2)
