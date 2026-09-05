"""Configurable packetisation, and the limits that keep it safe.

Phase 4 of the optimisation brief asks for 20/40/60 ms to be benchmarked over
the real path rather than argued about. That means every derived constant --
including the wire-format ones -- has to follow the setting, or a benchmark
run silently measures a broken configuration instead of the one it names.

These run the import in a SUBPROCESS. Reloading modules in-process to test
import-time configuration does not work: the environment has to be restored
afterwards, restoring it means reloading again, and the second reload undoes
the first. A subprocess gets a clean interpreter with the environment that is
actually under test.
"""

import json
import os
import subprocess
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PROBE = """
import json, sys
sys.path.insert(0, %r)
import otrv4plus_voice as v
json.dump({
    "frame_ms":      v.VOICE_FRAME_MS,
    "samples":       v.VOICE_FRAME_SAMPLES,
    "bytes":         v.VOICE_FRAME_BYTES,
    "sample_rate":   v.VOICE_SAMPLE_RATE,
    "channels":      v.VOICE_CHANNELS,
    "bitrate":       v.VOICE_BITRATE,
    "slot":          v.VOICE_OPUS_SLOT,
    "peak":          v.VOICE_OPUS_PEAK_BYTES,
    "packet":        v.VOICE_PACKET_LEN,
    "datagram":      v.VOICE_DATAGRAM_LEN,
    "tunnel":        v.I2P_TUNNEL_MESSAGE_PAYLOAD,
    "complexity":    v.VOICE_COMPLEXITY,
    "fec_pct":       v.VOICE_LOSS_PCT,
    "jitter_min_ms": v.VOICE_JITTER_PREFILL_MS,
    "jitter_tgt_ms": v.VOICE_JITTER_DRIFT_HIGH_MS,
    "jitter_max_ms": v.VOICE_JITTER_MAX_MS,
    "drain_ms":      v.VOICE_JITTER_DRAIN_MS,
}, sys.stdout)
""" % REPO


def config(**env):
    """Import the media stack in a clean interpreter under `env`."""
    child = dict(os.environ)
    child.pop("OTRV4PLUS_OPUS_FRAME_MS", None)
    child.pop("OTRV4PLUS_OPUS_BITRATE", None)
    child.update({k: str(v) for k, v in env.items()})
    done = subprocess.run([sys.executable, "-c", PROBE], cwd=REPO, env=child,
                          capture_output=True, text=True)
    if done.returncode != 0:
        raise RuntimeError(done.stderr)
    return json.loads(done.stdout)


@pytest.mark.parametrize("frame_ms", [20, 40, 60])
class TestEveryBenchmarkConfiguration:
    def test_the_geometry_follows_the_setting(self, frame_ms):
        c = config(OTRV4PLUS_OPUS_FRAME_MS=frame_ms)
        assert c["frame_ms"] == frame_ms
        assert c["samples"] == c["sample_rate"] * frame_ms // 1000
        assert c["bytes"] == c["samples"] * c["channels"] * 2

    def test_the_slot_still_holds_an_encoded_frame(self, frame_ms):
        # If the slot does not grow with the frame, pad_opus returns None,
        # the capture worker substitutes silence, and the call connects,
        # reports healthy and carries no audio.
        c = config(OTRV4PLUS_OPUS_FRAME_MS=frame_ms)
        assert c["peak"] <= c["slot"]

    def test_it_does_not_fragment_across_tunnel_messages(self, frame_ms):
        c = config(OTRV4PLUS_OPUS_FRAME_MS=frame_ms)
        assert c["datagram"] < c["tunnel"]

    def test_the_packet_rate_is_what_the_frame_implies(self, frame_ms):
        c = config(OTRV4PLUS_OPUS_FRAME_MS=frame_ms)
        assert 1000 // c["frame_ms"] == 1000 // frame_ms


class TestBitrate:
    @pytest.mark.parametrize("bitrate", [12000, 16000, 24000, 32000])
    def test_the_slot_follows_the_bitrate(self, bitrate):
        c = config(OTRV4PLUS_OPUS_BITRATE=bitrate)
        assert c["bitrate"] == bitrate
        assert c["peak"] <= c["slot"]

    def test_a_higher_bitrate_needs_a_bigger_packet(self):
        low = config(OTRV4PLUS_OPUS_BITRATE=12000)
        high = config(OTRV4PLUS_OPUS_BITRATE=32000)
        assert high["packet"] > low["packet"]

    def test_an_out_of_range_bitrate_is_ignored(self):
        assert config(OTRV4PLUS_OPUS_BITRATE=500000)["bitrate"] == 24000


class TestGuards:
    def test_a_fragmenting_configuration_is_refused_at_import(self):
        # Fragmentation multiplies both loss probability and latency, since
        # every fragment must arrive before any of the frame is usable.
        # Better to refuse than to let a benchmark measure it unknowingly.
        with pytest.raises(RuntimeError, match="fragment"):
            config(OTRV4PLUS_OPUS_FRAME_MS=60, OTRV4PLUS_OPUS_BITRATE=64000)

    def test_an_unsupported_frame_duration_is_ignored(self):
        # libopus takes 2.5/5/10/20/40/60; 33 must never reach the encoder.
        assert config(OTRV4PLUS_OPUS_FRAME_MS=33)["frame_ms"] == 60

    def test_a_non_numeric_setting_is_ignored(self):
        assert config(OTRV4PLUS_OPUS_FRAME_MS="twenty")["frame_ms"] == 60


class TestJitterConfiguration:
    def test_the_bounds_are_configurable(self):
        c = config(OTRV4PLUS_JITTER_MIN_MS=120,
                   OTRV4PLUS_JITTER_TARGET_MS=360,
                   OTRV4PLUS_JITTER_MAX_MS=720)
        assert c["jitter_min_ms"] == 120
        assert c["jitter_tgt_ms"] == 360
        assert c["jitter_max_ms"] == 720

    def test_the_drain_rate_is_configurable(self):
        assert config(OTRV4PLUS_JITTER_DRAIN_MS=250)["drain_ms"] == 250

    def test_an_out_of_range_value_is_ignored_not_clamped(self):
        # A typo must not stop a call, and a silently clamped value is harder
        # to notice than an ignored one.
        assert config(OTRV4PLUS_JITTER_MIN_MS=999999)["jitter_min_ms"] == 120


class TestOpusTuning:
    def test_complexity_is_configurable(self):
        assert config(OTRV4PLUS_OPUS_COMPLEXITY=3)["complexity"] == 3

    def test_fec_is_configurable(self):
        assert config(OTRV4PLUS_OPUS_FEC_PCT=15)["fec_pct"] == 15

    def test_fec_can_be_disabled_for_an_a_b_test(self):
        assert config(OTRV4PLUS_OPUS_FEC_PCT=0)["fec_pct"] == 0

    def test_an_out_of_range_complexity_is_ignored(self):
        assert config(OTRV4PLUS_OPUS_COMPLEXITY=99)["complexity"] == 8


class TestDefaults:
    def test_nothing_set_gives_the_shipped_configuration(self):
        c = config()
        assert c["frame_ms"] == 60
        assert c["bitrate"] == 24000
        assert c["slot"] == 232
        assert c["packet"] == 279

    def test_the_shipped_configuration_leaves_tunnel_headroom(self):
        c = config()
        assert c["datagram"] < c["tunnel"] * 0.85
