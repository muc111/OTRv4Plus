# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Voice on Android: the APK's own codec and audio, never the Termux ones.

THE DEFECT THIS REPLACES
========================
A handset running 0.7.0-experimental.rc.1 showed, on a conversation where
OTR had not even started:

    Call unavailable — opuslib not installed  (pip install opuslib --break-system-packages)

That sentence is `otrv4plus_xmpp.voice_available()`, the TERMUX client's
answer. `CallBridge` imports `otrv4plus_xmpp` (for the SAM helpers it binds
into `otrv4plus_voice`), and that import also binds the Termux codec and
availability hooks: `_load_opus` tries `import opuslib`, a Python wrapper
over Termux's libopus.so. An APK has neither -- Chaquopy ships no opuslib and
Android's own libopus is a private platform library an app may not load --
so the answer was always "no", and the remedy it named is a Termux command.
The screen asked the device question before the security one, which is why
it appeared before OTR.

It was not only a wrong message. `VoiceCallManager._build_codec` asks the
same hook for its encoder, so no call from the APK could ever have carried
audio.

WHAT ANDROID USES
=================
  codec    upstream libopus 1.5.2, statically linked into `otrv4_core` for the
           APK (`Rust/opus-codec`, feature `android-opus`), exposed as
           `otrv4_core.OpusEncoder` / `OpusDecoder` with opuslib's interface.
  audio    AAudio (`otrv4plus_audio`, ctypes over the system libaaudio.so),
           PINNED: no PulseAudio fallback, which on Android has no binaries
           and at best would carry silence.
  crypto   unchanged: `voice.rs` seals every frame; I2P datagrams carry it.

Termux keeps `otrv4plus_xmpp`'s own hooks (opuslib + Termux libopus.so, and
AAudio or PulseAudio) -- this module is imported only by the Android bridge.

Two questions stay separate, and this answers only the second:
  * may this peer be called (OTR + SMP) -- `OtrApp.call_gate`;
  * can this DEVICE do voice -- here.
"""

from __future__ import annotations

import os
import types
from typing import Optional, Tuple

__all__ = ["codec", "aaudio_available", "unavailable_reason", "voice_available",
           "bind", "NO_CODEC", "NO_AAUDIO", "BACKEND"]

#: Said when the APK's core was built without its codec. Names the build, not
#: a package to install: there is nothing a user can install to fix it.
NO_CODEC = "this build has no Android voice codec"
#: Said when libaaudio.so cannot be loaded (Android 8.0+ has it).
NO_AAUDIO = "Android audio (AAudio) is not available on this device"

#: The only audio backend the APK uses.
BACKEND = "aaudio"


def codec() -> Optional[types.SimpleNamespace]:
    """The Rust Opus codec, shaped like the `opuslib` module, or None."""
    try:
        import otrv4_core as core
    except Exception:
        return None
    if not all(hasattr(core, n) for n in ("OpusEncoder", "OpusDecoder",
                                          "OPUS_APPLICATION_VOIP")):
        return None
    return types.SimpleNamespace(
        Encoder=core.OpusEncoder,
        Decoder=core.OpusDecoder,
        APPLICATION_VOIP=core.OPUS_APPLICATION_VOIP,
        SIGNAL_VOICE=core.OPUS_SIGNAL_VOICE,
        BANDWIDTH_WIDEBAND=core.OPUS_BANDWIDTH_WIDEBAND,
    )


def aaudio_available() -> bool:
    try:
        import otrv4plus_audio as audio
        return bool(audio.aaudio_available())
    except Exception:
        return False


def unavailable_reason() -> str:
    """Why this device cannot do voice, or "" when it can. Never raises."""
    if codec() is None:
        return NO_CODEC
    if not aaudio_available():
        return NO_AAUDIO
    return ""


def voice_available() -> Tuple[bool, str]:
    """`otrv4plus_voice`'s host hook, answered for Android."""
    reason = unavailable_reason()
    return (not reason, reason or "ok")


def bind(voice_module) -> None:
    """Give `otrv4plus_voice` the Android codec, availability and backend.

    Called by `CallBridge` AFTER `otrv4plus_xmpp` is imported, because that
    import binds the Termux hooks and this must be the last word. The SAM
    and sanitising helpers it bound are kept: they are the I2P datagram
    transport and are the same on both platforms.
    """
    found = codec()
    voice_module.bind_host(
        load_opus=lambda: codec() is not None,
        voice_available=voice_available,
        is_termux=False,
    )
    if found is not None:
        voice_module.bind_host(opus=found)
    # AAudio only. `otrv4plus_audio` honours an explicit choice exactly and
    # never falls back from it.
    os.environ["OTRV4PLUS_AUDIO_BACKEND"] = BACKEND
