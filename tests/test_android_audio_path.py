#!/usr/bin/env python3
"""AAudio reachability checks (Phase 2, §18).

The requirement is narrow: establish whether the EXISTING audio/native path can
be called from the eventual Android architecture. Not to rewrite voice crypto,
and not to build a call UI.

The AAudio backend in otrv4plus_audio.py binds libaaudio.so through ctypes. It
cannot be exercised here -- there is no libaaudio.so and no audio device -- so
these tests verify the properties that determine whether it will work inside an
APK, and that its failure behaviour is safe. The device half is recorded as
blocked in ANDROID_PHASE2_REPORT.md rather than claimed.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

audio = pytest.importorskip("otrv4plus_audio")


class TestAAudioIsReachableFromAnApk:
    """Structural properties that decide whether AAudio works in an APK."""

    def test_backend_is_loaded_via_ctypes_not_a_python_extension(self):
        """ctypes.CDLL works in any Android process; a compiled extension
        would need its own per-ABI build and packaging."""
        import inspect
        src = inspect.getsource(audio._load_aaudio)
        assert "ctypes.CDLL" in src
        assert "libaaudio.so" in src

    def test_looks_in_the_android_system_library_paths(self):
        import inspect
        src = inspect.getsource(audio._load_aaudio)
        for path in ("libaaudio.so", "/system/lib64/libaaudio.so", "/system/lib/libaaudio.so"):
            assert path in src, f"{path} not searched"

    def test_module_imports_without_an_audio_device(self):
        """Chaquopy imports the module long before any call is placed."""
        assert hasattr(audio, "open_capture")
        assert hasattr(audio, "open_playback")
        assert hasattr(audio, "aaudio_available")

    def test_availability_probe_is_safe_off_android(self):
        """Must report absence, not raise: the diagnostics screen calls this."""
        assert audio.aaudio_available() is False

    def test_backend_selection_is_overridable(self):
        """open_capture(preferred=...) lets the Android host pin AAudio rather
        than relying on probe order."""
        import inspect
        sig = inspect.signature(audio.open_capture)
        assert "preferred" in sig.parameters
        assert "preferred" in inspect.signature(audio.open_playback).parameters

    def test_explicit_backend_choice_is_honoured_exactly(self):
        assert audio._pick_order(audio.BACKEND_AAUDIO) == (audio.BACKEND_AAUDIO,)


class TestFailureBehaviourIsSafe:
    """A silent fallback would encrypt and transmit silence while reporting a
    healthy call. The existing code guards against that; keep it that way."""

    def test_microphone_permission_denial_is_not_routed_around(self):
        """Every backend runs under the same UID, so no other backend can fix a
        missing manifest permission. It must propagate, not fall back."""
        import inspect
        src = inspect.getsource(audio.open_capture)
        assert "MICROPHONE_PERMISSION_DENIED" in src
        assert "raise" in src

    def test_fallback_is_reported_not_silent(self):
        import inspect
        src = inspect.getsource(audio.open_capture)
        assert "notes" in src, "the caller must be told why a backend was skipped"

    def test_opening_capture_without_any_backend_raises(self):
        """Off Android with no PulseAudio, this must fail loudly."""
        with pytest.raises(audio.AudioError):
            audio.open_capture(which=lambda _binary: None)


class TestVoiceLayerHostSeam:
    """otrv4plus_voice.bind_host is the injection point the Android host uses to
    supply audio and transport helpers without the voice module importing them."""

    def test_bind_host_exists_and_accepts_the_expected_keys(self):
        voice = pytest.importorskip("otrv4plus_voice")
        assert callable(voice.bind_host)
        for key in ("print", "sanitise", "ossl_cleanse", "sam_open",
                    "sam_read_line", "sam_parse", "sam_release", "opus"):
            assert key in voice._HOST, f"host seam missing {key!r}"

    def test_voice_module_imports_without_a_host_bound(self):
        """It must be importable (and testable) standalone -- Chaquopy imports
        it at startup, long before any call."""
        voice = pytest.importorskip("otrv4plus_voice")
        assert hasattr(voice, "VoiceCallManager")
        assert hasattr(voice, "CallState")

    def test_call_state_machine_is_intact(self):
        """The bridge projects this; it must not have been altered."""
        voice = pytest.importorskip("otrv4plus_voice")
        cs = voice.CallState
        assert cs.ALLOWED[cs.ENDED] == set(), "ENDED must stay absorbing"
        for state in cs.LIVE:
            assert cs.ENDED in cs.ALLOWED[state], f"{state} must be able to reach ENDED"

    def test_bridge_call_states_match_the_engine(self):
        """android_bridge.events.CallState must mirror the engine exactly."""
        voice = pytest.importorskip("otrv4plus_voice")
        from android_bridge.events import CallState as BridgeCallState
        engine_states = {
            v for k, v in vars(voice.CallState).items()
            if isinstance(v, str) and k.isupper() and not k.startswith("_")
        }
        bridge_states = {s.value for s in BridgeCallState}
        assert engine_states == bridge_states, (
            f"bridge and engine call states diverged: "
            f"engine-only={engine_states - bridge_states}, "
            f"bridge-only={bridge_states - engine_states}"
        )
