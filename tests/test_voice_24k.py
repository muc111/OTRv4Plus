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
