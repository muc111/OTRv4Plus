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
