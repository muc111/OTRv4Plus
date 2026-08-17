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

class TestBurstDelivery(IntegrationBase):
    """I2P delivers in bursts. A burst must not cost frames or alignment.

    The live-call symptom this pins: dropped and resync climbing together
    while authfail stayed at 0. Nothing was failing to decrypt — whole frames
    were being discarded before the parser saw them, and the survivor was cut
    mid-frame so the parser then had to hunt for sync.
    """

    def _session(self):
        session = build_session(self.loop, is_initiator=False)
        session._opus_dec = FakeOpusDecoder()
        session.jitter = V.JitterBuffer(prefill=1, maxlen=200)
        return session

    def test_large_burst_loses_no_frames(self):
        session = self._session()
        tx = V.VoiceFrameCrypto(b"\x5c" * V.ROOT_LEN, CALL_ID, 0, True)
        plain = bytes(V.pad_opus(b"\xAB" * 80))

        # 41 packets: exactly what one read(8192) can return.
        burst = b"".join(tx.seal(plain) for _ in range(41))
        self.assertGreater(len(burst), V.VOICE_PACKET_LEN * 8,
                           "burst must exceed the old trim threshold")

        buf = bytearray(burst)
        session._drain_buffer(buf)

        self.assertEqual(session.stats["recv"], 41,
                         "every frame in the burst must be recovered")
        self.assertEqual(session.stats["resync"], 0,
                         "a clean burst must not desync the parser")
        self.assertEqual(session.stats["dropped"], 0)
        self.assertEqual(len(buf), 0)

    def test_sustained_bursts_do_not_accumulate_resync(self):
        session = self._session()
        tx = V.VoiceFrameCrypto(b"\x5c" * V.ROOT_LEN, CALL_ID, 0, True)
        plain = bytes(V.pad_opus(b"\xAB" * 80))
        buf = bytearray()
        for _ in range(20):
            buf += b"".join(tx.seal(plain) for _ in range(30))
            session._drain_buffer(buf)
        self.assertEqual(session.stats["recv"], 600)
        self.assertEqual(session.stats["resync"], 0)
        self.assertEqual(session.stats["dropped"], 0)

    def test_partial_trailing_frame_is_held_not_discarded(self):
        session = self._session()
        tx = V.VoiceFrameCrypto(b"\x5c" * V.ROOT_LEN, CALL_ID, 0, True)
        plain = bytes(V.pad_opus(b"\xAB" * 80))
        packets = [tx.seal(plain) for _ in range(10)]
        stream = b"".join(packets)
        split = len(stream) - 50               # last frame arrives cut short
        buf = bytearray(stream[:split])
        session._drain_buffer(buf)
        self.assertEqual(session.stats["recv"], 9)
        buf += stream[split:]
        session._drain_buffer(buf)
        self.assertEqual(session.stats["recv"], 10,
                         "a frame split across reads must still arrive")
        self.assertEqual(session.stats["resync"], 0)

    def test_garbage_flood_is_still_bounded(self):
        # The bound must remain a real DoS guard for a peer that never
        # completes a frame.
        session = self._session()
        buf = bytearray(b"\xa7" * 100000)
        session._drain_buffer(buf)
        self.assertLessEqual(len(buf), V.VOICE_HDR_LEN)


class TestRekeyReceiveWindow(IntegrationBase):
    """The responder must accept the new epoch before it commits.

    The initiator commits a full round trip earlier: it verifies REKEYACK,
    switches its send epoch, then sends REKEYCOMMIT. Media takes the direct
    I2P tunnel while REKEYCOMMIT goes via the XMPP server, so new-epoch audio
    reliably overtakes it. Live call: authfail=87 on the responder, 0 on the
    initiator, across 5 rekeys.
    """

    def _pair(self):
        call_id = CALL_ID
        root = b"\x5c" * V.ROOT_LEN
        si = V.VoiceKeySchedule(call_id, True)
        sr = V.VoiceKeySchedule(call_id, False)
        si.install_initial(root)
        sr.install_initial(root)
        return si, sr

    def _derive(self, si, sr, epoch):
        new_root = V.derive_rekey_root(
            si.current_root(), b"\x01" * 56, b"\x02" * 32,
            V.build_transcript(CALL_ID, OTR_BINDING, FP_A, FP_B,
                               b"\x03" * 56, b"\x04" * 56,
                               b"\x05" * V.MLKEM_EK_LEN,
                               b"\x06" * V.MLKEM_CT_LEN, epoch))
        si.begin_rekey(epoch, new_root)
        sr.begin_rekey(epoch, new_root)
        return si.our_confirm(), sr.our_confirm()

    def test_responder_opens_new_epoch_frames_before_commit(self):
        si, sr = self._pair()
        ci, cr = self._derive(si, sr, 1)

        # Initiator commits and immediately transmits on epoch 1.
        self.assertTrue(si.commit_rekey(1, cr))
        self.assertEqual(si.epoch, 1)
        plain = bytes(V.pad_opus(b"\xAB" * 80))
        packet = si.cipher_for_send().seal(plain)

        # Responder has NOT committed yet — REKEYCOMMIT is still in flight.
        self.assertEqual(sr.epoch, 0)
        cipher = sr.cipher_for_epoch(1)
        self.assertIsNotNone(cipher, "pending epoch must be receivable")
        self.assertEqual(cipher.open(packet[:V.VOICE_HDR_LEN],
                                     packet[V.VOICE_HDR_LEN:]), plain)

    def test_responder_still_sends_on_the_committed_epoch(self):
        si, sr = self._pair()
        self._derive(si, sr, 1)
        self.assertEqual(sr.epoch, 0)
        self.assertEqual(sr.cipher_for_send().epoch, 0,
                         "receiving early must not move the send epoch")

    def test_no_authfail_across_a_rekey_boundary(self):
        import asyncio
        session = build_session(self.loop, is_initiator=False)
        session._opus_dec = FakeOpusDecoder()
        session.jitter = V.JitterBuffer(prefill=1, maxlen=200)
        si = V.VoiceKeySchedule(CALL_ID, True)
        si.install_initial(b"\x5c" * V.ROOT_LEN)
        sr = session.schedule

        plain = bytes(V.pad_opus(b"\xAB" * 80))
        buf = bytearray()
        for _ in range(5):
            buf += si.cipher_for_send().seal(plain)

        ci, cr = self._derive(si, sr, 1)
        si.commit_rekey(1, cr)
        # 20 frames on the new epoch arrive before REKEYCOMMIT is processed.
        for _ in range(20):
            buf += si.cipher_for_send().seal(plain)

        session._drain_buffer(buf)
        self.assertEqual(session.stats["auth_fail"], 0,
                         "new-epoch audio must not be rejected pre-commit")
        self.assertEqual(session.stats["recv"], 25)
        self.assertEqual(session.stats["resync"], 0)

    def test_aborted_rekey_withdraws_the_receive_cipher(self):
        si, sr = self._pair()
        self._derive(si, sr, 1)
        self.assertIsNotNone(sr.cipher_for_epoch(1))
        sr.abort_rekey()
        self.assertIsNone(sr.cipher_for_epoch(1),
                          "a failed rekey must not leave a live key behind")
        self.assertEqual(sr.epoch, 0)


class TestJitterDrift(IntegrationBase):
    """Latency accumulated during a burst must not persist for the call."""

    def test_depth_converges_back_to_the_ceiling(self):
        jb = V.JitterBuffer(prefill=2, maxlen=60, drift_high=10,
                            adaptive=False)
        for c in range(40):
            jb.push(0, c, bytearray(b"\x00" * 8))
        self.assertGreater(jb.depth(), 10)
        for _ in range(60):
            if jb.pop() is None:
                break
        self.assertLessEqual(jb.depth(), 10)
        self.assertGreater(jb.stats["drift"], 0)

    def test_steady_state_sheds_nothing(self):
        # One frame in, one frame out — arrival matched to playout, which is
        # what a healthy call looks like. Depth stays at the prefill cushion.
        # adaptive=False: this test is about the shed rule, not the
        # estimator. With adaptation on, synthetic arrivals with no delay
        # between them read as jitter and move the target mid-test.
        jb = V.JitterBuffer(prefill=2, maxlen=60, drift_high=10,
                            adaptive=False)
        # Prime to exactly the target. Priming above the shed threshold and
        # then complaining that it sheds would be testing the test.
        for seq in range(jb.target_depth):
            jb.push(0, seq, bytearray(b"\x00" * 8))
        seq = jb.target_depth
        for _ in range(200):
            jb.push(0, seq, bytearray(b"\x00" * 8))
            seq += 1
            jb.pop()
        self.assertLessEqual(jb.depth(), 10)
        self.assertEqual(jb.stats["drift"], 0,
                         "one frame in, one frame out must never shed audio")


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
