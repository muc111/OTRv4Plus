# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Voice at 24 kHz, super-wideband (owner request, 2026-10-11: "16 kHz is not
great; 24 maybe better; it shouldn't delay the sound too much").

What is checked, with the real Opus codec:
  * the pipeline is 24 kHz, 60 ms frames -- no added frame delay;
  * the encoder is told super-wideband (up to 12 kHz of audio) at the SAME
    constant 24 kbit/s, so every frame is the same size and fits the padding
    slot: the wire format is unchanged;
  * a peer still at 16 kHz decodes our packets, and we decode theirs;
  * group calls use the same encoder settings as 1:1 (they used libopus
    defaults: a variable rate, frame sizes following speech).
"""
import math
import os
import struct
import sys
import types

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

core = pytest.importorskip("otrv4_core")
if not hasattr(core, "OpusEncoder"):
    pytest.skip("this core has no Opus codec", allow_module_level=True)

import otrv4plus_audio as A  # noqa: E402
import otrv4plus_voice as V  # noqa: E402


def _opus():
    return types.SimpleNamespace(Encoder=core.OpusEncoder, Decoder=core.OpusDecoder,
                                 APPLICATION_VOIP=core.OPUS_APPLICATION_VOIP,
                                 SIGNAL_VOICE=core.OPUS_SIGNAL_VOICE)


def _speech(n, rate, start=0):
    out = []
    for i in range(n):
        t = (start + i) / rate
        s = sum(math.sin(2 * math.pi * f * t) / k
                for k, f in enumerate((180, 360, 540, 2500, 5200, 7800, 9500), 1))
        out.append(max(-32768, min(32767, int(6000 * s))))
    return struct.pack("<%dh" % n, *out)


class TestTheFormat:

    def test_24k_and_still_60_ms(self):
        assert A.SAMPLE_RATE == 24000 and V.VOICE_SAMPLE_RATE == 24000
        assert V.VOICE_FRAME_MS == 60, "frames, not the rate, set the delay"
        assert V.VOICE_FRAME_SAMPLES == 1440 and V.VOICE_FRAME_BYTES == 2880

    def test_the_wire_format_is_unchanged(self):
        # The padding slot and packet length depend on bitrate and frame
        # length only.
        assert V.VOICE_BITRATE == 24000
        assert V.VOICE_OPUS_SLOT == 232

    def test_super_wideband_at_24k(self):
        assert V.opus_bandwidth(types.SimpleNamespace()) == 1104
        assert V.opus_bandwidth(types.SimpleNamespace(BANDWIDTH_SUPERWIDEBAND=1104)) == 1104


class TestTheEncoder:

    def test_constant_size_frames_that_fit_the_slot(self):
        opus = _opus()
        enc = opus.Encoder(V.VOICE_SAMPLE_RATE, 1, opus.APPLICATION_VOIP)
        applied, failed = V.configure_encoder(enc, opus)
        assert failed == [] and "bandwidth" in applied and "vbr" in applied
        sizes = {len(bytes(enc.encode(_speech(1440, 24000, k * 1440), 1440)))
                 for k in range(40)}
        assert len(sizes) == 1, "frame sizes follow speech: %s" % sorted(sizes)
        assert sizes.pop() <= V.VOICE_OPUS_SLOT

    def test_a_16k_peer_and_a_24k_peer_hear_each_other(self):
        opus = _opus()
        enc24 = opus.Encoder(24000, 1, opus.APPLICATION_VOIP)
        V.configure_encoder(enc24, opus)
        pkt = bytes(enc24.encode(_speech(1440, 24000), 1440))
        assert len(bytes(opus.Decoder(16000, 1).decode(pkt, 960))) == 1920
        enc16 = opus.Encoder(16000, 1, opus.APPLICATION_VOIP)
        pkt16 = bytes(enc16.encode(_speech(960, 16000), 960))
        assert len(bytes(opus.Decoder(24000, 1).decode(pkt16, 1440))) == 2880


class TestGroupCallsUseTheSameSettings:

    def test_the_group_call_encoder_is_configured(self, monkeypatch):
        import otrv4plus_groupcall as G
        seen = []
        monkeypatch.setattr(V, "configure_encoder",
                            lambda enc, opus: seen.append(enc) or ([], []))
        monkeypatch.setitem(V._HOST, "load_opus", lambda: True)
        monkeypatch.setitem(V._HOST, "opus", _opus())

        class Stream:
            name = "test"

            def read_frame(self, *a, **k):
                return b""

            def write_frame(self, *a, **k):
                return True

            def stop(self):
                pass

        import otrv4plus_audio as audio
        monkeypatch.setattr(audio, "open_capture", lambda **k: (Stream(), []))
        monkeypatch.setattr(audio, "open_playback", lambda **k: (Stream(), []))
        m = G.GroupCallMedia(loop=None, sam_host="127.0.0.1", sam_port=1)
        m.start_audio(calls=object())
        m.close()
        assert seen and seen[0] is m._encoder


class TestGroupPlayout:
    """rc.62: group calls receive like 1:1 calls -- a jitter buffer and a
    decoder per member, FEC for one lost frame, concealment for more."""

    def _setup(self):
        import otrv4plus_groupcall as G
        opus = _opus()
        enc = opus.Encoder(24000, 1, opus.APPLICATION_VOIP)
        V.configure_encoder(enc, opus)
        frames = [bytes(enc.encode(_speech(1440, 24000, k * 1440), 1440))
                  for k in range(30)]
        p = G.Playout(V.VOICE_FRAME_BYTES, lambda: opus.Decoder(24000, 1))
        return G, p, frames

    def _drain(self, p, n):
        silence = b"\x00" * V.VOICE_FRAME_BYTES
        return [f for f in (p.next_frame() for _ in range(n)) if f != silence]

    def _live(self, p, who, sends, frames, extra=6):
        """As a call runs: one packet arrives (or not) per playback tick."""
        silence = b"\x00" * V.VOICE_FRAME_BYTES
        heard = 0
        for item in sends:
            if item is not None:
                n, idx = item
                p.push(who, frames[idx], n)
            heard += p.next_frame() != silence
        for _ in range(extra):
            heard += p.next_frame() != silence
        return heard

    def test_out_of_order_frames_are_played_in_order(self):
        G, p, frames = self._setup()
        order = [0, 2, 1, 3, 5, 4, 6, 7, 8, 9]
        heard = self._live(p, "bob", [(n, n) for n in order], frames)
        assert heard == 10
        assert p.stats["concealed"] == 0 and p.stats["fec"] == 0

    def test_one_lost_frame_is_rebuilt_from_fec(self):
        G, p, frames = self._setup()
        sends = [None if n == 5 else (n, n) for n in range(12)]
        heard = self._live(p, "bob", sends, frames)
        assert p.stats["fec"] == 1
        assert heard == 12, "the lost frame was not filled in"

    def test_a_longer_gap_is_concealed_not_left_silent(self):
        G, p, frames = self._setup()
        sends = [None if 6 <= n <= 8 else (n, n) for n in range(15)]
        self._live(p, "bob", sends, frames)
        assert p.stats["concealed"] >= 2

    def test_a_member_who_rejoins_is_heard_again(self):
        G, p, frames = self._setup()
        self._live(p, "bob", [(200 + n, n) for n in range(10)], frames)
        # They hung up and joined again: their frame numbers start at 0.
        heard = self._live(p, "bob", [(n, n) for n in range(8)], frames)
        assert heard == 8
        assert p.stats["restarts"] == 1

    def test_frame_numbers_from_timestamps(self):
        import otrv4plus_groupcall as G
        assert [G.frame_number(n * 60) for n in range(4)] == [0, 1, 2, 3]
        # A sender before rc.62 sent milliseconds, not exact multiples.
        assert [G.frame_number(t) for t in (0, 58, 123, 179, 241)] == [0, 1, 2, 3, 4]


class TestLinuxEchoCancellation:
    """A laptop on speakers sent the far end's voice back to them: parec and
    pacat ran with no echo cancellation. The echo-cancelled source and sink
    are used when PulseAudio/PipeWire has them."""

    LISTING = ("0\talsa_input.pci\tmodule-alsa-card.c\ts16le 2ch 48000Hz\tRUNNING\n"
               "3\techo-cancel-source\tmodule-echo-cancel.c\tfloat32le 1ch 32000Hz\tIDLE\n")

    def test_the_echo_cancelled_source_is_picked(self, monkeypatch):
        monkeypatch.delenv("OTRV4PLUS_PULSE_SOURCE", raising=False)
        got = A.pulse_device("source", which=lambda b: "/usr/bin/" + b,
                             runner=lambda argv: self.LISTING)
        assert got == "echo-cancel-source"

    def test_none_loaded_means_the_default(self, monkeypatch):
        monkeypatch.delenv("OTRV4PLUS_PULSE_SINK", raising=False)
        assert A.pulse_device("sink", which=lambda b: "/usr/bin/" + b,
                              runner=lambda argv: "0\talsa_output.pci\tx\n") == ""
        assert A.pulse_device("sink", which=lambda b: None) == ""

    def test_a_monitor_is_never_the_microphone(self, monkeypatch):
        monkeypatch.delenv("OTRV4PLUS_PULSE_SOURCE", raising=False)
        listing = "5\techo-cancel-sink.monitor\tx\n"
        assert A.pulse_device("source", which=lambda b: "/usr/bin/" + b,
                              runner=lambda argv: listing) == ""

    def test_the_user_can_name_one(self, monkeypatch):
        monkeypatch.setenv("OTRV4PLUS_PULSE_SOURCE", "my-mic")
        assert A.pulse_device("source", which=lambda b: None) == "my-mic"


class _FakePulse:
    """A pactl stand-in: no echo canceller until one is loaded, then it is
    listed; records loads and unloads. Driven through the runner/which hooks
    so no real PulseAudio is touched."""

    def __init__(self, preloaded=False):
        self.loaded = preloaded
        self.load_calls = 0
        self.unloaded = []
        self.last_load_argv = None

    def which(self, binary):
        return "/usr/bin/" + binary

    def run(self, argv):
        if "load-module" in argv:
            self.load_calls += 1
            self.loaded = True
            self.last_load_argv = list(argv)
            return "42"
        if "unload-module" in argv:
            self.unloaded.append(argv[-1])
            self.loaded = False
            return ""
        if "list" in argv:                       # pactl list short sources/sinks
            if self.loaded:
                return ("0\talsa_input.pci\tx\tRUNNING\n"
                        "42\techo-cancel-source\tmodule-echo-cancel.c\tx\tIDLE\n")
            return "0\talsa_input.pci\tx\tRUNNING\n"
        return ""


class TestAutoEchoCancel:
    """A desktop call now loads module-echo-cancel itself when nothing is
    cancelling echo, and unloads it on teardown -- so a laptop on speakers is
    clear by default, like a phone, without changing the user's audio system
    permanently."""

    def _clear_env(self, monkeypatch):
        for name in ("OTRV4PLUS_NO_AUTO_ECHO_CANCEL", "OTRV4PLUS_PULSE_SOURCE",
                     "OTRV4PLUS_PULSE_SINK", "OTRV4PLUS_AEC_METHOD"):
            monkeypatch.delenv(name, raising=False)

    def test_it_loads_when_nothing_is_cancelling(self, monkeypatch):
        self._clear_env(monkeypatch)
        fake = _FakePulse(preloaded=False)
        index = A.ensure_echo_cancel(which=fake.which, runner=fake.run)
        assert index == 42 and fake.load_calls == 1

    def test_it_does_not_load_over_an_existing_one(self, monkeypatch):
        self._clear_env(monkeypatch)
        fake = _FakePulse(preloaded=True)
        assert A.ensure_echo_cancel(which=fake.which, runner=fake.run) is None
        assert fake.load_calls == 0

    def test_a_pinned_device_is_left_alone(self, monkeypatch):
        self._clear_env(monkeypatch)
        monkeypatch.setenv("OTRV4PLUS_PULSE_SOURCE", "my-mic")
        fake = _FakePulse(preloaded=False)
        assert A.ensure_echo_cancel(which=fake.which, runner=fake.run) is None
        assert fake.load_calls == 0

    def test_the_opt_out_is_honoured(self, monkeypatch):
        self._clear_env(monkeypatch)
        monkeypatch.setenv("OTRV4PLUS_NO_AUTO_ECHO_CANCEL", "1")
        fake = _FakePulse(preloaded=False)
        assert A.ensure_echo_cancel(which=fake.which, runner=fake.run) is None
        assert fake.load_calls == 0

    def test_no_pactl_means_no_load(self, monkeypatch):
        self._clear_env(monkeypatch)
        assert A.ensure_echo_cancel(which=lambda b: None,
                                    runner=lambda argv: "") is None

    def test_a_load_that_does_not_appear_is_undone(self, monkeypatch):
        """If the module loads but no usable source shows up, the call must not
        be routed through a device that is not there -- undo and fall back to
        the default, which is a working (if echoing) call rather than silence."""
        self._clear_env(monkeypatch)

        class Ghost(_FakePulse):
            def run(self, argv):
                out = super().run(argv)
                if "list" in argv:
                    return "0\talsa_input.pci\tx\tRUNNING\n"   # never appears
                return out

        ghost = Ghost(preloaded=False)
        assert A.ensure_echo_cancel(which=ghost.which, runner=ghost.run) is None
        assert ghost.load_calls == 1 and ghost.unloaded == ["42"]

    def test_unload_undoes_exactly_what_was_loaded(self, monkeypatch):
        self._clear_env(monkeypatch)
        fake = _FakePulse(preloaded=False)
        index = A.ensure_echo_cancel(which=fake.which, runner=fake.run)
        A.unload_module(index, which=fake.which, runner=fake.run)
        assert fake.unloaded == ["42"] and fake.loaded is False

    def test_unload_of_nothing_is_harmless(self):
        A.unload_module(None)                     # no raise, no pactl needed

    def test_webrtc_is_the_default_method(self, monkeypatch):
        self._clear_env(monkeypatch)
        monkeypatch.delenv("OTRV4PLUS_AEC_METHOD", raising=False)
        assert A.aec_method() == "webrtc"
        fake = _FakePulse(preloaded=False)
        A.ensure_echo_cancel(which=fake.which, runner=fake.run)
        assert "aec_method=webrtc" in fake.last_load_argv

    def test_speex_is_the_non_webrtc_alternative(self, monkeypatch):
        """OTRV4PLUS_AEC_METHOD=speex loads the speexdsp canceller instead, so
        a user who wants no WebRTC code in the process can have none -- both
        methods are local DSP and neither touches the network."""
        self._clear_env(monkeypatch)
        monkeypatch.setenv("OTRV4PLUS_AEC_METHOD", "speex")
        assert A.aec_method() == "speex"
        assert "aec_method=speex" in A.echo_cancel_command()
        fake = _FakePulse(preloaded=False)
        A.ensure_echo_cancel(which=fake.which, runner=fake.run)
        assert "aec_method=speex" in fake.last_load_argv

    def test_an_unknown_method_falls_back_to_webrtc(self, monkeypatch):
        self._clear_env(monkeypatch)
        monkeypatch.setenv("OTRV4PLUS_AEC_METHOD", "nonsense")
        assert A.aec_method() == "webrtc"


class TestSharedEchoCancel:
    """One canceller module provides both the mic's source and the speaker's
    sink, so it must outlive either stream alone. Mute releases the
    microphone while the speaker plays on: a canceller owned by the mic alone
    was unloaded on mute, the speaker lost its reference sink, and the echo
    came back after the first mute/unmute."""

    @pytest.fixture(autouse=True)
    def _fresh(self, monkeypatch):
        for name in ("OTRV4PLUS_NO_AUTO_ECHO_CANCEL", "OTRV4PLUS_PULSE_SOURCE",
                     "OTRV4PLUS_PULSE_SINK", "OTRV4PLUS_AEC_METHOD"):
            monkeypatch.delenv(name, raising=False)
        A._EC.update(refs=0, index=None, ctx=(None, None, None))
        yield
        A._EC.update(refs=0, index=None, ctx=(None, None, None))

    def test_mute_and_unmute_keep_one_canceller_loaded(self):
        fake = _FakePulse(preloaded=False)
        A.acquire_echo_cancel(fake.which, runner=fake.run)      # call: mic
        A.acquire_echo_cancel(fake.which, runner=fake.run)      # call: speaker
        assert fake.load_calls == 1
        A.release_echo_cancel()                                 # mute: mic off
        assert fake.unloaded == [] and fake.loaded, (
            "muting unloaded the canceller under the live speaker")
        A.acquire_echo_cancel(fake.which, runner=fake.run)      # unmute
        assert fake.load_calls == 1, "unmute loaded a second canceller"
        A.release_echo_cancel()                                 # hang up: mic
        A.release_echo_cancel()                                 #          speaker
        assert fake.unloaded == ["42"], "the last stream did not unload it"

    def test_a_failed_load_is_not_retried_by_every_stream(self):
        """Each retry would add pactl's latency to opening a stream, for the
        same answer: the first holder tries, the rest of that call do not."""
        class Refuses(_FakePulse):
            def run(self, argv):
                if "load-module" in argv:
                    self.load_calls += 1
                    return "Failure: Module initialization failed"
                return super().run(argv)

        fake = Refuses(preloaded=False)
        A.acquire_echo_cancel(fake.which, runner=fake.run)
        first = fake.load_calls        # its own attempts (with and without args)
        assert first >= 1
        A.acquire_echo_cancel(fake.which, runner=fake.run)
        assert fake.load_calls == first, "a second stream retried the load"
        A.release_echo_cancel()
        A.release_echo_cancel()
        assert fake.unloaded == []

    def test_one_already_loaded_by_the_user_is_never_unloaded(self):
        fake = _FakePulse(preloaded=True)
        A.acquire_echo_cancel(fake.which, runner=fake.run)
        A.release_echo_cancel()
        assert fake.load_calls == 0 and fake.unloaded == []

    def test_a_call_opened_while_the_last_one_closes_keeps_a_canceller(self):
        """Hang up and call again at once: the new call's stream must not slip
        in between "we no longer own it" and the unload, see the old
        canceller still listed, take it for someone else's -- and then lose
        it. The unload now happens under the lock the new stream waits on."""
        import threading
        fake = _FakePulse(preloaded=False)
        real = fake.run
        entered, go = threading.Event(), threading.Event()

        def slow(argv):
            if "unload-module" in argv:
                entered.set()
                go.wait(2)                   # the unload takes its time
            return real(argv)

        A.acquire_echo_cancel(fake.which, runner=slow)
        t = threading.Thread(target=A.release_echo_cancel)
        t.start()
        assert entered.wait(2)
        opener = threading.Thread(target=A.acquire_echo_cancel,
                                  args=(fake.which,), kwargs={"runner": slow})
        opener.start()                       # the new call, during the unload
        go.set()
        t.join(2)
        opener.join(2)
        assert A._EC["refs"] == 1
        assert A._EC["index"] == 42 and fake.loaded, (
            "the new call was left without an echo canceller")
        A.release_echo_cancel()

    def test_releasing_more_than_acquired_is_harmless(self):
        A.release_echo_cancel()
        A.release_echo_cancel()
        assert A._EC["refs"] == 0

    def test_a_crash_with_a_call_up_still_unloads_it(self):
        fake = _FakePulse(preloaded=False)
        A.acquire_echo_cancel(fake.which, runner=fake.run)
        A._release_echo_cancel_at_exit()
        assert fake.unloaded == ["42"]

    def test_each_stream_releases_exactly_once(self):
        """stop() twice, or a failed open followed by stop(), must not drop
        another stream's reference."""
        fake = _FakePulse(preloaded=False)
        A.acquire_echo_cancel(fake.which, runner=fake.run)      # speaker
        mic = object.__new__(A.PulseCapture)
        mic._ec_held = A.acquire_echo_cancel(fake.which, runner=fake.run)
        mic._release_ec()
        mic._release_ec()
        assert A._EC["refs"] == 1 and fake.unloaded == []
        A.release_echo_cancel()
        assert fake.unloaded == ["42"]

    def test_the_ringtone_does_not_load_a_canceller(self, monkeypatch):
        """A ring is not a call: loading (and then unloading) the canceller
        just to ring would churn the audio system before the call opens it."""
        seen = {}

        class Recorder:
            def __init__(self, **kw):
                seen.update(kw)

        monkeypatch.setattr(A, "PulsePlayback", Recorder)
        A.open_playback(preferred="pulseaudio", echo_cancel=False)
        assert seen.get("echo_cancel") is False
        import inspect
        assert "echo_cancel=False" in inspect.getsource(A), (
            "the ringer opens its playback with a canceller")


class TestCancellerLeavesTheMicLevelAlone:
    """Classic PulseAudio's webrtc canceller runs analog gain control by
    default and moves the HARDWARE mic volume -- undoing a level the user set
    (device test: the laptop's input had just been turned down) and leaving it
    moved after the call. Its gain control is switched off; a server that
    refuses the argument gets the plain load, so the call keeps a canceller."""

    @pytest.fixture(autouse=True)
    def _fresh(self, monkeypatch):
        for name in ("OTRV4PLUS_NO_AUTO_ECHO_CANCEL", "OTRV4PLUS_PULSE_SOURCE",
                     "OTRV4PLUS_PULSE_SINK", "OTRV4PLUS_AEC_METHOD"):
            monkeypatch.delenv(name, raising=False)

    def test_webrtc_is_loaded_with_its_gain_control_off(self):
        fake = _FakePulse(preloaded=False)
        assert A.ensure_echo_cancel(which=fake.which, runner=fake.run) == 42
        assert ('aec_args="analog_gain_control=0 digital_gain_control=0"'
                in fake.last_load_argv)

    def test_a_server_refusing_the_argument_still_gets_a_canceller(self):
        class Strict(_FakePulse):
            def run(self, argv):
                if "load-module" in argv and any(a.startswith("aec_args=") for a in argv):
                    self.load_calls += 1
                    return "Failure: Module initialization failed"
                return super().run(argv)

        fake = Strict(preloaded=False)
        assert A.ensure_echo_cancel(which=fake.which, runner=fake.run) == 42
        assert fake.load_calls == 2
        assert not any(a.startswith("aec_args=") for a in fake.last_load_argv)

    def test_speex_gets_no_webrtc_arguments(self, monkeypatch):
        monkeypatch.setenv("OTRV4PLUS_AEC_METHOD", "speex")
        fake = _FakePulse(preloaded=False)
        A.ensure_echo_cancel(which=fake.which, runner=fake.run)
        assert "aec_method=speex" in fake.last_load_argv
        assert not any(a.startswith("aec_args=") for a in fake.last_load_argv)

    def test_the_printed_command_is_what_the_call_runs(self):
        """/audiotest prints the command for pasting into a shell: split the
        way a shell splits it, it must be exactly the argv the call uses."""
        import shlex
        fake = _FakePulse(preloaded=False)
        A.ensure_echo_cancel(which=lambda b: b, runner=fake.run)
        assert shlex.split(A.echo_cancel_command()) == fake.last_load_argv
