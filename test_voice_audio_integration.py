#!/usr/bin/env python3
"""Integration tests: otrv4plus_voice <-> otrv4plus_audio.

    OTRV4PLUS_ALLOW_PYTHON_MLKEM=1 python3 -m unittest test_voice_audio_integration -v

These drive the REAL VoiceCallSession capture and playback workers against a
fake libaaudio, so the whole path is exercised:

    fake AAudio -> AAudioCapture.read_frame() -> _capture_worker
      -> Opus -> pad_opus -> VoiceFrameCrypto.seal -> _write_packet

The point is to prove that swapping the audio device did not disturb anything
above it: the sealed packets must be byte-for-byte the shape the protocol
produced before, and the crypto objects must be the same ones.

Nothing here needs an Android device.  The on-device counterpart is
`otrv4plus_audio.probe()`, reached from the client as /audioprobe.
"""

import asyncio
import os
import struct
import threading
import time
import unittest

os.environ.setdefault("OTRV4PLUS_ALLOW_PYTHON_MLKEM", "1")

import otrv4plus_audio as A
import otrv4plus_voice as V
from test_audio_backend import FakeAAudioLib, install

CALL_ID = bytes(range(16))
OTR_BINDING = b"OTRv4+Voice/session/v3"
FP_A = "AA" * 64
FP_B = "BB" * 64


class FakeOpusEncoder:
    """Deterministic stand-in for opuslib.

    Returns a fixed-size payload so packet lengths are predictable; the real
    encoder's output size is irrelevant to what these tests check, which is
    that the framing and sealing around it are unchanged.
    """

    def __init__(self):
        self.calls = 0
        self.last_input_len = None

    def encode(self, pcm, frame_samples):
        self.calls += 1
        self.last_input_len = len(pcm)
        assert frame_samples == V.VOICE_FRAME_SAMPLES
        return b"\xAB" * 80


class FakeOpusDecoder:
    def __init__(self):
        self.calls = 0

    def decode(self, data, frame_samples):
        self.calls += 1
        return b"\x11\x22" * frame_samples


def build_session(loop, is_initiator=True):
    session = V.VoiceCallSession("peer@example.org", loop, CALL_ID,
                                 is_initiator)
    session.otr_material = (OTR_BINDING, FP_A, FP_B)
    session.schedule.install_initial(b"\x5c" * V.ROOT_LEN)
    session.keys_confirmed.set()
    session._opus_enc = FakeOpusEncoder()
    session._opus_dec = FakeOpusDecoder()
    session._silence_frame = b"\x00" * 40
    return session


class IntegrationBase(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        self.addCleanup(self.loop.close)
        self.addCleanup(self._reset_lib)

    @staticmethod
    def _reset_lib():
        A._LIB = None
        A._LIB_ERROR = None

    def run_capture(self, session, frames=6, timeout=5.0):
        """Run the real _capture_worker until `frames` packets are sealed."""
        packets = []
        done = threading.Event()

        def collect(packet):
            packets.append(packet)
            if len(packets) >= frames:
                done.set()

        # _capture_worker hands packets to the loop; capture them directly.
        session._write_packet = collect
        session.loop = _InlineLoop()
        session._running = True
        thread = threading.Thread(target=session._capture_worker, daemon=True)
        thread.start()
        done.wait(timeout)
        session._running = False
        thread.join(timeout=2.0)
        return packets


class _InlineLoop:
    """call_soon_threadsafe that runs inline, so tests need no running loop."""

    def call_soon_threadsafe(self, fn, *args):
        fn(*args)


# ===========================================================================
# The capture path end to end
# ===========================================================================

class TestCaptureIntegration(IntegrationBase):

    def test_microphone_pcm_reaches_the_sealer_as_valid_packets(self):
        install(FakeAAudioLib(frames_per_burst=480, steady=12345))
        session = build_session(self.loop)
        session._capture = A.AAudioCapture()
        self.addCleanup(session._capture.stop)

        packets = self.run_capture(session, frames=6)
        self.assertGreaterEqual(len(packets), 6)

        # Every packet must be a well-formed v3 media frame that the peer's
        # cipher opens — i.e. the audio swap did not disturb framing or AEAD.
        peer = V.VoiceFrameCrypto(b"\x5c" * V.ROOT_LEN, CALL_ID, 0, False)
        for i, packet in enumerate(packets[:6]):
            self.assertEqual(len(packet), V.VOICE_PACKET_LEN)
            header = packet[:V.VOICE_HDR_LEN]
            epoch, counter, length, ftype = V.parse_media_header(header)
            self.assertEqual(epoch, 0)
            self.assertEqual(counter, i)
            self.assertEqual(length, V.VOICE_SEALED_LEN)
            self.assertEqual(ftype, V.FRAME_TYPE_AUDIO)
            plain = peer.open(header, packet[V.VOICE_HDR_LEN:])
            self.assertEqual(len(plain), V.VOICE_PLAIN_LEN)
            self.assertEqual(V.unpad_opus(plain), b"\xAB" * 80)

    def test_encoder_receives_exactly_1280_bytes(self):
        install(FakeAAudioLib(frames_per_burst=480, steady=999))
        session = build_session(self.loop)
        session._capture = A.AAudioCapture()
        self.addCleanup(session._capture.stop)
        self.run_capture(session, frames=3)
        self.assertEqual(session._opus_enc.last_input_len, 1280)
        self.assertEqual(session._opus_enc.last_input_len,
                         V.VOICE_FRAME_BYTES)

    def test_48k_device_still_yields_1280_byte_frames(self):
        # Resampling stays inside the backend; the pipeline never sees 48 kHz.
        install(FakeAAudioLib(device_rate=48000, frames_per_burst=960,
                              steady=700))
        session = build_session(self.loop)
        session._capture = A.AAudioCapture()
        self.addCleanup(session._capture.stop)
        self.assertTrue(session._capture.diagnostics()["resampling"])
        packets = self.run_capture(session, frames=3)
        self.assertGreaterEqual(len(packets), 3)
        self.assertEqual(session._opus_enc.last_input_len, 1280)
        for packet in packets[:3]:
            self.assertEqual(len(packet), V.VOICE_PACKET_LEN)

    def test_counters_are_monotonic_and_gapless(self):
        install(FakeAAudioLib(frames_per_burst=480, steady=42))
        session = build_session(self.loop)
        session._capture = A.AAudioCapture()
        self.addCleanup(session._capture.stop)
        packets = self.run_capture(session, frames=10)
        counters = [V.parse_media_header(p[:V.VOICE_HDR_LEN])[1]
                    for p in packets[:10]]
        self.assertEqual(counters, list(range(10)))

    def test_mute_still_transmits_constant_rate(self):
        install(FakeAAudioLib(frames_per_burst=480, steady=20000))
        session = build_session(self.loop)
        session._capture = A.AAudioCapture()
        self.addCleanup(session._capture.stop)
        session._muted = True
        packets = self.run_capture(session, frames=4)
        self.assertGreaterEqual(len(packets), 4)
        for packet in packets[:4]:
            self.assertEqual(len(packet), V.VOICE_PACKET_LEN)

    def test_timeout_does_not_end_the_call_or_spin(self):
        # A device that produces nothing must not be mistaken for a dead one.
        install(FakeAAudioLib(frames_per_burst=480))      # steady=None -> 0
        session = build_session(self.loop)
        session._capture = A.AAudioCapture()
        self.addCleanup(session._capture.stop)
        lost = []
        session.on_stream_lost = lambda *a: lost.append(a)
        session._write_packet = lambda p: None
        session.loop = _InlineLoop()
        session._running = True
        t = threading.Thread(target=session._capture_worker, daemon=True)
        t.start()
        time.sleep(0.3)
        session._running = False
        t.join(timeout=2.0)
        self.assertFalse(t.is_alive())
        self.assertEqual(lost, [], "a starved device must not end the call")


# ===========================================================================
# Disconnect must be loud, never silence
# ===========================================================================

class TestDisconnectPropagation(IntegrationBase):

    def test_capture_disconnect_ends_the_call(self):
        install(FakeAAudioLib(frames_per_burst=480,
                              read_plan=[A.AAUDIO_ERROR_DISCONNECTED]))
        session = build_session(self.loop)
        session._capture = A.AAudioCapture()
        self.addCleanup(session._capture.stop)

        reported = []
        session.on_stream_lost = lambda peer, cid, why: reported.append(why)
        session.loop = _InlineLoop()
        session._write_packet = lambda p: None
        session._running = True
        session._capture_worker()

        self.assertEqual(len(reported), 1)
        self.assertIn("disconnected", reported[0])

    def test_playback_disconnect_ends_the_call(self):
        install(FakeAAudioLib(read_plan=[A.AAUDIO_ERROR_DISCONNECTED]))
        session = build_session(self.loop)
        session._playback = A.AAudioPlayback()
        self.addCleanup(session._playback.stop)

        reported = []
        session.on_stream_lost = lambda peer, cid, why: reported.append(why)
        session.loop = _InlineLoop()
        session.jitter.push(0, 0, bytearray(b"\x00" * V.VOICE_FRAME_BYTES))
        session.jitter._primed = True
        session._running = True

        t = threading.Thread(target=session._playback_worker, daemon=True)
        t.start()
        time.sleep(0.3)
        session._running = False
        t.join(timeout=2.0)
        self.assertTrue(any("disconnected" in w for w in reported),
                        "a dead speaker must be reported, not played as silence")

    def test_disconnected_stream_is_never_re_read(self):
        install(FakeAAudioLib(frames_per_burst=480,
                              read_plan=[A.AAUDIO_ERROR_DISCONNECTED]))
        cap = A.AAudioCapture()
        with self.assertRaises(A.AudioError):
            cap.read_frame()
        self.assertTrue(cap.diagnostics()["disconnected"])
        cap.stop()


# ===========================================================================
# Teardown
# ===========================================================================

class TestTeardownIntegration(IntegrationBase):

    def test_end_releases_both_devices_and_wipes_pcm(self):
        lib = install(FakeAAudioLib(frames_per_burst=480, steady=27000))
        session = build_session(self.loop)
        session._capture = A.AAudioCapture()
        session._playback = A.AAudioPlayback()
        session.transition(V.CallState.INVITING)
        session._capture.read_frame()
        raw = session._capture._raw

        self.loop.run_until_complete(session.end())

        self.assertEqual(session.state, V.CallState.ENDED)
        self.assertIsNone(session._capture)
        self.assertIsNone(session._playback)
        self.assertEqual(lib.closed, 2, "both streams must be closed")
        self.assertTrue(all(v == 0 for v in raw),
                        "microphone buffer survived teardown")
        self.assertEqual(session.schedule.live_epochs(), [])

    def test_force_close_releases_devices(self):
        lib = install(FakeAAudioLib(steady=1))
        session = build_session(self.loop)
        session._capture = A.AAudioCapture()
        session._playback = A.AAudioPlayback()
        session.force_close_sync()
        self.assertEqual(lib.closed, 2)
        self.assertIsNone(session._capture)
        session.force_close_sync()

    def test_teardown_during_capture_does_not_crash_the_thread(self):
        # end() clears self._capture before joining the capture thread.
        install(FakeAAudioLib(frames_per_burst=480, steady=5))
        session = build_session(self.loop)
        session._capture = A.AAudioCapture()
        session._playback = A.AAudioPlayback()
        session.transition(V.CallState.INVITING)
        session._write_packet = lambda p: None
        session.loop = _InlineLoop()
        session._running = True
        t = threading.Thread(target=session._capture_worker, daemon=True)
        t.start()
        session._capture_thread = t
        time.sleep(0.2)

        errors = []
        old_hook = threading.excepthook
        threading.excepthook = lambda args: errors.append(args.exc_type)
        try:
            self.loop.run_until_complete(session.end())
            t.join(timeout=2.0)
        finally:
            threading.excepthook = old_hook
        self.assertFalse(t.is_alive())
        self.assertEqual(errors, [], "capture thread raised during teardown")


# ===========================================================================
# Isolation guarantees
# ===========================================================================

class TestIsolation(IntegrationBase):

    def test_aaudio_path_starts_no_subprocess(self):
        import subprocess
        install(FakeAAudioLib(frames_per_burst=480, steady=3))
        spawned = []
        real = subprocess.Popen

        class Guard(subprocess.Popen):
            def __init__(self, args, *a, **k):
                spawned.append(args)
                raise AssertionError("subprocess spawned on the AAudio path: "
                                     "%r" % (args,))

        subprocess.Popen = Guard
        try:
            session = build_session(self.loop)
            session._capture = A.AAudioCapture()
            self.addCleanup(session._capture.stop)
            self.run_capture(session, frames=3)
        finally:
            subprocess.Popen = real
        self.assertEqual(spawned, [])

    def test_no_files_created_during_a_call(self):
        import tempfile
        install(FakeAAudioLib(frames_per_burst=480, steady=4))
        d = tempfile.mkdtemp()
        before = set(os.listdir(d))
        cwd_before = set(os.listdir("."))
        session = build_session(self.loop)
        session._capture = A.AAudioCapture()
        self.addCleanup(session._capture.stop)
        self.run_capture(session, frames=5)
        self.assertEqual(set(os.listdir(d)), before)
        self.assertEqual(set(os.listdir(".")) - cwd_before, set())

    def test_key_schedule_untouched_by_the_audio_swap(self):
        install(FakeAAudioLib(frames_per_burst=480, steady=8))
        session = build_session(self.loop)
        session._capture = A.AAudioCapture()
        self.addCleanup(session._capture.stop)
        before = session.schedule.epoch
        cipher = session.schedule.cipher_for_send()
        self.run_capture(session, frames=5)
        self.assertEqual(session.schedule.epoch, before)
        self.assertIs(session.schedule.cipher_for_send(), cipher,
                      "audio must not rotate or replace the media cipher")
        # >= rather than ==: the worker may seal one more frame between the
        # collector reaching its target and _running going false.  What
        # matters is that the same cipher advanced, not that it stopped on an
        # exact count.
        self.assertGreaterEqual(cipher.send_counter, 5)

    def test_backend_name_surfaces_in_describe(self):
        install(FakeAAudioLib(steady=1))
        session = build_session(self.loop)
        session._capture = A.AAudioCapture()
        self.addCleanup(session._capture.stop)
        session.audio_backend = session._capture.name
        self.assertIn("audio=aaudio", session.describe())


if __name__ == "__main__":
    unittest.main(verbosity=2)
