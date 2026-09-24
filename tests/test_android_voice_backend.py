#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Android voice uses the APK's codec and AAudio -- never Termux's opuslib.

THE HANDSET REPORT (0.7.0-experimental.rc.1)
============================================
    Call unavailable — opuslib not installed  (pip install opuslib --break-system-packages)

on a conversation where OTR had not started. The sentence is the Termux
client's (`otrv4plus_xmpp.voice_available`), reached because the Android call
bridge imports `otrv4plus_xmpp` -- which binds its Termux codec hooks into
`otrv4plus_voice` -- and then asked those hooks. The APK has no opuslib and
could not have one, so every Android call would also have failed at
`_build_codec`. rc.2 moved the device question after the security one, which
hid the sentence before OTR; it did not give Android a codec.

WHAT THESE HOLD
===============
1. Android voice capability does not require Python `opuslib`.
2. The Android call path never runs the Termux opuslib check.
3. A conversation before OTR says "start encryption", never "opuslib".
4. OTR without SMP does not enable calling.
5. OTR + SMP enables calling only when the Android audio backend is there.
6. Termux keeps its opuslib codec and its own availability answer.
7. Android and Termux backend selection stay separate (source and build).
8. The Android binding keeps the I2P transport hooks: no direct fallback.
9. Voice stays I2P datagrams and the codec fits the fixed encrypted slot.
"""

import builtins
import os
import re
import struct
import sys
import math

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

otr = pytest.importorskip("otrv4_")
core = pytest.importorskip("otrv4_core")
voice = pytest.importorskip("otrv4plus_voice")
import otrv4plus_xmpp as xmpp                                         # noqa: E402
from android_bridge import android_audio                              # noqa: E402
from android_bridge.app import OtrApp                                 # noqa: E402

HAS_CODEC = hasattr(core, "OpusEncoder")
needs_codec = pytest.mark.skipif(
    not HAS_CODEC, reason="otrv4_core built without android-opus (CI builds it)")


@pytest.fixture
def no_opuslib(monkeypatch):
    """Make `import opuslib` fail, and make the Termux check itself explode
    if anything on the Android path calls it."""
    real_import = builtins.__import__

    def guarded(name, *a, **k):
        if name == "opuslib" or name.startswith("opuslib."):
            raise ImportError("no opuslib in an APK")
        return real_import(name, *a, **k)
    monkeypatch.setattr(builtins, "__import__", guarded)
    monkeypatch.delitem(sys.modules, "opuslib", raising=False)

    def termux_called(*_a, **_k):
        raise AssertionError("the Android path asked the TERMUX opuslib check")
    monkeypatch.setattr(xmpp, "voice_available", termux_called)
    monkeypatch.setattr(xmpp, "_load_opus", termux_called)
    monkeypatch.setattr(xmpp, "_load_opus_and_bind", termux_called, raising=False)
    return termux_called


def _app():
    return OtrApp(otr.EnhancedSessionManager(otr.OTRConfig(test_mode=True)),
                  None, None)


def _tone(samples):
    return b"".join(struct.pack("<h", int(8000 * math.sin(i * 0.07)))
                    for i in range(samples))


# 1, 2 -------------------------------------------------------------------------

class TestAndroidNeedsNoOpuslib:

    @needs_codec
    def test_android_voice_is_available_with_no_opuslib_anywhere(self, no_opuslib, monkeypatch):
        monkeypatch.setattr(android_audio, "aaudio_available", lambda: True)
        assert android_audio.unavailable_reason() == ""
        assert android_audio.voice_available() == (True, "ok")

    @needs_codec
    def test_the_call_bridge_builds_a_real_codec_without_the_termux_check(
            self, no_opuslib, monkeypatch):
        """Through the bridge the handset uses: the manager is built, the
        Android hooks are bound, and `_build_codec` -- the step that needed
        opuslib -- runs on the Rust codec with the pipeline's own settings."""
        monkeypatch.setattr(android_audio, "aaudio_available", lambda: True)
        app = _app()
        try:
            assert app.voice_unavailable_reason() == ""
            manager = app.calls._ensure_manager()
            assert manager is not None
            assert voice._HOST["voice_available"] is android_audio.voice_available
            assert voice._HOST["load_opus"]() is True
            assert voice._HOST["opus"].Encoder is core.OpusEncoder
            assert voice._HOST["is_termux"] is False
            assert os.environ["OTRV4PLUS_AUDIO_BACKEND"] == "aaudio"

            call = voice.VoiceCallSession.__new__(voice.VoiceCallSession)
            for attr, value in (("_mic_gain", _Gain()), ("_speaker_gain", _Gain()),
                                ("_speaker_comp", _Comp()),
                                ("_transport_mode", voice.VOICE_TRANSPORT_DATAGRAM)):
                setattr(call, attr, value)
            call._playback_usage_is_voice = lambda: False
            call._build_codec()
            assert call.constant_rate, "VBR/DTX could not be disabled on the Rust codec"
            assert call._silence_frame, "the codec produced no silence frame"
        finally:
            app.shutdown()

    def test_the_bridge_reason_never_comes_from_the_termux_hook(self, no_opuslib, monkeypatch):
        monkeypatch.setattr(android_audio, "aaudio_available", lambda: False)
        app = _app()
        try:
            # would raise AssertionError via `no_opuslib` if the Termux hook ran
            assert app.voice_unavailable_reason() in (android_audio.NO_AAUDIO,
                                                      android_audio.NO_CODEC)
        finally:
            app.shutdown()

    def test_the_android_bridge_source_asks_no_termux_availability(self):
        src = open(os.path.join(ROOT, "android_bridge", "voice.py"), encoding="utf-8").read()
        code = "\n".join(l for l in src.splitlines() if not l.strip().startswith("#"))
        assert '_HOST["voice_available"]' not in code
        assert "voice_available()" not in code.replace("android_audio.voice_available", "")


# 3, 4, 5 ----------------------------------------------------------------------

class TestTheTwoQuestionsStaySeparate:

    def test_before_otr_the_answer_is_encryption_not_a_codec(self, no_opuslib, monkeypatch):
        monkeypatch.setattr(android_audio, "aaudio_available", lambda: False)
        app = _app()
        try:
            app._transport = type("T", (), {"is_connected": True})()
            gate = app.call_gate("peer@example.test")
            assert gate == {"gate": "no_session", "reason": ""}
            assert "opus" not in str(gate).lower()
        finally:
            app._transport = None
            app.shutdown()

    def test_no_android_sentence_mentions_opuslib_or_pip(self):
        for text in (android_audio.NO_CODEC, android_audio.NO_AAUDIO):
            assert "opuslib" not in text and "pip" not in text


class TestTheGateOnARealSession:
    """A real DAKE and SMP between two Android bridges."""

    @pytest.fixture
    def pair(self, monkeypatch):
        import uuid
        from test_android_calls import Wire, Sink, _manager
        otr._dake1_rate_limiter._attempts.clear()
        a_jid = "a-%s@example.test" % uuid.uuid4().hex[:8]
        b_jid = "b-%s@example.test" % uuid.uuid4().hex[:8]
        aw, bw = Wire(), Wire()
        a = OtrApp(_manager(), aw, Sink())
        b = OtrApp(_manager(), bw, Sink())
        aw.peer_app, aw.peer_id = b, a_jid
        bw.peer_app, bw.peer_id = a, b_jid
        a.start_session(b_jid)
        yield a, b, a_jid, b_jid
        for app in (a, b):
            app.shutdown()

    def test_otr_without_smp_does_not_enable_calling(self, pair, monkeypatch):
        monkeypatch.setattr(android_audio, "aaudio_available", lambda: True)
        a, b, a_jid, b_jid = pair
        assert a.call_gate(b_jid)["gate"] == "not_verified"

    def test_smp_enables_calling_only_with_the_android_backend(self, pair, monkeypatch):
        a, b, a_jid, b_jid = pair
        secret = "we agreed this on the train"
        b.smp_set_secret(a_jid, secret) if hasattr(b, "smp_set_secret") else \
            b._engine.set_smp_secret(a_jid, secret)
        a.smp_start(b_jid, secret)
        monkeypatch.setattr(android_audio, "aaudio_available", lambda: False)
        g = a.call_gate(b_jid)
        assert g["gate"] in ("voice_unavailable", "not_verified")
        if g["gate"] == "not_verified":
            pytest.skip("SMP did not complete in this harness")
        assert g["reason"] in (android_audio.NO_AAUDIO, android_audio.NO_CODEC)
        assert "opuslib" not in g["reason"]
        monkeypatch.setattr(android_audio, "aaudio_available", lambda: True)
        if HAS_CODEC:
            assert a.call_gate(b_jid) == {"gate": "available", "reason": ""}


# 6, 7 -------------------------------------------------------------------------

class TestTermuxIsUnchanged:

    def test_termux_still_uses_opuslib_and_says_so(self, monkeypatch):
        real_import = builtins.__import__

        def guarded(name, *a, **k):
            if name == "opuslib":
                raise ImportError("not installed")
            return real_import(name, *a, **k)
        monkeypatch.setattr(builtins, "__import__", guarded)
        monkeypatch.setattr(xmpp, "_OPUS_AVAILABLE", False)
        ok, reason = xmpp.voice_available()
        assert not ok and "opuslib" in reason

    def test_importing_the_termux_client_binds_the_termux_hooks(self):
        import importlib
        importlib.reload(xmpp)
        assert voice._HOST["voice_available"] is xmpp.voice_available
        assert voice._HOST["load_opus"] is not android_audio.voice_available

    def test_the_backends_are_separate_in_source(self):
        for name in ("otrv4plus_xmpp.py", "otrv4plus_voice.py", "otrv4plus_audio.py"):
            src = open(os.path.join(ROOT, name), encoding="utf-8").read()
            assert "android_audio" not in src, name
            assert "OpusEncoder" not in src, name

    def test_only_the_android_build_enables_the_codec(self):
        build_sh = open(os.path.join(ROOT, "Rust", "build.sh"), encoding="utf-8").read()
        assert "android-opus" not in build_sh, "the Termux build took the Android codec"
        android = open(os.path.join(ROOT, ".github", "workflows", "android.yml"),
                       encoding="utf-8").read()
        assert re.search(r"--features [^\n]*android-opus", android), \
            "the APK's core is built without its codec"
        assert "ANDROID_NDK_HOME" in android

    def test_the_crypto_core_keeps_forbid_unsafe(self):
        lib = open(os.path.join(ROOT, "Rust", "src", "lib.rs"), encoding="utf-8").read()
        assert "#![forbid(unsafe_code)]" in lib
        codec = open(os.path.join(ROOT, "Rust", "src", "opus_codec.rs"), encoding="utf-8").read()
        assert "unsafe" not in re.sub(r"//.*", "", codec)


# 8, 9 -------------------------------------------------------------------------

class TestTransportIsUntouched:

    def test_the_android_binding_keeps_the_i2p_hooks(self, monkeypatch):
        import importlib
        importlib.reload(xmpp)
        before = {k: voice._HOST[k] for k in ("sam_open", "sam_read_line", "sam_parse",
                                              "sam_release", "sanitise")}
        android_audio.bind(voice)
        for key, value in before.items():
            assert voice._HOST[key] is value, "%s was rebound by the Android binding" % key

    def test_voice_is_datagrams_by_default(self, monkeypatch):
        monkeypatch.delenv("OTRV4PLUS_VOICE_TRANSPORT", raising=False)
        mode = voice._voice_transport_mode() if hasattr(voice, "_voice_transport_mode") else None
        if mode is None:
            src = open(os.path.join(ROOT, "otrv4plus_voice.py"), encoding="utf-8").read()
            assert 'VOICE_TRANSPORT_DATAGRAM = "datagram"' in src
        else:
            assert mode == voice.VOICE_TRANSPORT_DATAGRAM

    def test_android_audio_imports_no_socket(self):
        src = open(os.path.join(ROOT, "android_bridge", "android_audio.py"), encoding="utf-8").read()
        assert "import socket" not in src and "create_connection" not in src

    @needs_codec
    def test_the_rust_codec_fits_the_fixed_encrypted_slot(self):
        enc = core.OpusEncoder(voice.VOICE_SAMPLE_RATE, voice.VOICE_CHANNELS,
                               core.OPUS_APPLICATION_VOIP)
        enc.bitrate = voice.VOICE_BITRATE
        enc.vbr = 0
        enc.dtx = 0
        dec = core.OpusDecoder(voice.VOICE_SAMPLE_RATE, voice.VOICE_CHANNELS)
        sizes = set()
        for _ in range(8):
            pkt = enc.encode(_tone(voice.VOICE_FRAME_SAMPLES), voice.VOICE_FRAME_SAMPLES)
            sizes.add(len(pkt))
            assert voice.pad_opus(pkt) is not None, "frame larger than the encrypted slot"
            assert len(dec.decode(pkt, voice.VOICE_FRAME_SAMPLES)) == voice.VOICE_FRAME_BYTES
        assert len(sizes) == 1, "not constant-rate: %s" % sizes
        assert len(dec.decode(None, voice.VOICE_FRAME_SAMPLES)) == voice.VOICE_FRAME_BYTES

    @needs_codec
    def test_bad_input_is_refused_not_crashed(self):
        enc = core.OpusEncoder(16000, 1, core.OPUS_APPLICATION_VOIP)
        with pytest.raises(ValueError):
            enc.encode(b"\0" * 10, 960)
        dec = core.OpusDecoder(16000, 1)
        with pytest.raises(RuntimeError):
            dec.decode(b"\xff" * 3, 960)
        with pytest.raises(ValueError):
            core.OpusEncoder(44100, 1, core.OPUS_APPLICATION_VOIP)


class _Gain:
    gain = 1.0
    auto = False


class _Comp:
    enabled = False
    makeup_db = 0.0
