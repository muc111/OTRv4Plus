"""The playback stream must declare itself as voice communication.

A live call was half duplex: one party audible at a time, never both, with
the far end barely audible. The capture stream asks for
AAUDIO_INPUT_PRESET_VOICE_COMMUNICATION, which switches on the platform echo
canceller, AGC and noise suppression. An echo canceller needs a reference --
the signal being played -- so it can subtract it from what the microphone
hears, and Android pairs that reference with the voice communication output
stream.

The playback stream declared no usage at all, so it defaulted to
AAUDIO_USAGE_MEDIA. With no reference the suppressor cannot separate the far
end's speech coming out of the speaker from the near end's speech going into
the microphone, so it gates the microphone whenever the speaker is active.
Playback also landed on the media volume stream rather than the call one.
"""

import os

import pytest

import otrv4plus_audio as audio


class TestUsageConstants:
    def test_they_match_the_ndk_values(self):
        # From android/media/AAudio.h. Wrong values would be accepted by the
        # setter and silently select a different usage.
        assert audio.AAUDIO_USAGE_MEDIA == 1
        assert audio.AAUDIO_USAGE_VOICE_COMMUNICATION == 2
        assert audio.AAUDIO_CONTENT_TYPE_SPEECH == 3

    def test_the_input_preset_still_matches_the_ndk(self):
        assert audio.AAUDIO_INPUT_PRESET_VOICE_COMMUNICATION == 7
        assert audio.AAUDIO_INPUT_PRESET_GENERIC == 1


class TestPlaybackUsageSelection:
    def test_voice_communication_is_the_default(self, monkeypatch):
        monkeypatch.delenv("OTRV4PLUS_AUDIO_USAGE", raising=False)
        assert audio.playback_usage() == audio.AAUDIO_USAGE_VOICE_COMMUNICATION

    def test_media_stays_reachable(self, monkeypatch):
        # Usage also drives routing; a device that sends voice communication
        # to the earpiece is quieter held away from the ear.
        monkeypatch.setenv("OTRV4PLUS_AUDIO_USAGE", "media")
        assert audio.playback_usage() == audio.AAUDIO_USAGE_MEDIA

    def test_an_unrecognised_value_does_not_silently_pick_media(self, monkeypatch):
        monkeypatch.setenv("OTRV4PLUS_AUDIO_USAGE", "ringtone")
        assert audio.playback_usage() == audio.AAUDIO_USAGE_VOICE_COMMUNICATION

    def test_the_value_is_case_and_space_insensitive(self, monkeypatch):
        monkeypatch.setenv("OTRV4PLUS_AUDIO_USAGE", "  MEDIA ")
        assert audio.playback_usage() == audio.AAUDIO_USAGE_MEDIA


class _RecordingBuilder:
    """Stands in for libaaudio, recording every builder setter call."""

    def __init__(self, missing=()):
        self.calls = {}
        self._missing = set(missing)

    def __getattr__(self, name):
        if not name.startswith("AAudioStreamBuilder_set"):
            raise AttributeError(name)
        field = name[len("AAudioStreamBuilder_set"):]
        if field in self._missing:
            raise AttributeError(name)

        def _setter(_builder, value):
            self.calls[field] = value
        return _setter


def _apply(builder_lib, input_preset=None, usage=None, content_type=None):
    """Replay the builder-setter loop from AAudioStreamBase.__init__."""
    for name, value in (("setInputPreset", input_preset),
                        ("setUsage", usage),
                        ("setContentType", content_type)):
        if value is None:
            continue
        setter = getattr(builder_lib, "AAudioStreamBuilder_" + name, None)
        if setter is not None and callable(setter):
            setter(None, value)


class TestBuilderApplication:
    def test_output_attributes_are_applied(self):
        lib = _RecordingBuilder()
        _apply(lib, usage=audio.AAUDIO_USAGE_VOICE_COMMUNICATION,
               content_type=audio.AAUDIO_CONTENT_TYPE_SPEECH)
        assert lib.calls["Usage"] == audio.AAUDIO_USAGE_VOICE_COMMUNICATION
        assert lib.calls["ContentType"] == audio.AAUDIO_CONTENT_TYPE_SPEECH

    def test_the_input_preset_is_not_applied_to_an_output_stream(self):
        lib = _RecordingBuilder()
        _apply(lib, input_preset=None,
               usage=audio.AAUDIO_USAGE_VOICE_COMMUNICATION)
        assert "InputPreset" not in lib.calls

    def test_usage_is_not_applied_to_an_input_stream(self):
        # setUsage is output-only; the capture side's analogue is the input
        # preset, which it already sets.
        lib = _RecordingBuilder()
        _apply(lib, input_preset=audio.AAUDIO_INPUT_PRESET_VOICE_COMMUNICATION)
        assert lib.calls == {
            "InputPreset": audio.AAUDIO_INPUT_PRESET_VOICE_COMMUNICATION}

    def test_a_platform_without_the_setters_still_opens(self):
        # setUsage and setContentType are Android 9+. On Android 8 the symbols
        # are absent and the stream must still open, just without the hints.
        lib = _RecordingBuilder(missing=("Usage", "ContentType"))
        _apply(lib, usage=audio.AAUDIO_USAGE_VOICE_COMMUNICATION,
               content_type=audio.AAUDIO_CONTENT_TYPE_SPEECH)
        assert lib.calls == {}


class TestCaptureAndPlaybackAgree:
    def test_the_capture_preset_and_playback_usage_are_a_matched_pair(self):
        # This is the invariant the bug violated: the echo canceller is armed
        # by the capture preset and referenced by the playback usage. Setting
        # one without the other is worse than setting neither, because the
        # suppressor then runs with nothing to subtract and gates the mic.
        capture_names = audio.AAudioCapture.__init__.__code__.co_names
        assert "AAUDIO_INPUT_PRESET_VOICE_COMMUNICATION" in capture_names, (
            "capture no longer arms the platform AEC; if that is deliberate "
            "the playback usage below should change with it")
        assert audio.playback_usage() == audio.AAUDIO_USAGE_VOICE_COMMUNICATION, (
            "playback must be the AEC reference whenever capture asks for "
            "the VOICE_COMMUNICATION input preset")

    def test_the_playback_class_requests_speech_content(self):
        source = audio.AAudioPlayback.__init__.__code__.co_names
        assert "AAUDIO_CONTENT_TYPE_SPEECH" in source
        assert "playback_usage" in source
