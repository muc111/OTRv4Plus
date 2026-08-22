"""Audio capture and playback for OTRv4+ voice, without PulseAudio.

WHY THIS IS AAUDIO AND NOT android.media.AudioRecord
=====================================================

The brief asks for `android.media.AudioRecord` behind a Python -> Rust ->
AudioRecord FFI boundary.  That cannot be built in this repository, and the
reason is structural rather than a matter of effort:

  * `android.media.AudioRecord` is a **Java** class.  Reaching it requires a
    JNI attachment to a live ART/Dalvik VM.
  * Termux runs a plain Linux userland.  The process holding this code is
    CPython, started from a shell.  There is no JVM in it and Termux ships
    none.  `AttachCurrentThread` has nothing to attach to.
  * Repository inspection confirms there is no Java anywhere: otrv4_core is
    `crate-type = ["cdylib"]`, a PyO3 extension module.  No JNI, no
    AndroidManifest.xml, no Gradle.
  * Getting a JVM would mean shipping a companion Android APK with a
    foreground service and an IPC channel — a second build system, which the
    brief explicitly rules out.

So the requested call graph is not implementable here.  Writing something
that claimed to be it would be fiction.

What IS implementable gives the brief everything it actually asks for:

**AAudio** (`libaaudio.so`), the NDK **C** audio API added in Android 8.0.
It is Android's audio framework — the same AudioFlinger path that
`AudioRecord` sits on top of — exposed as plain C symbols.  No JVM, no JNI,
no Java.  A Termux process dlopens it directly.  It gives real-time
streaming PCM with no intermediate files, and it satisfies every constraint
in the brief:

    no PulseAudio, no module-sles-source, no module-sles-sink, no ALSA,
    no /dev/snd, no D-Bus, no systemd, no root, no audio files.

The mapping from the requested API to what is actually used:

    AudioRecord                  -> AAudioStream, DIRECTION_INPUT
    AudioTrack                   -> AAudioStream, DIRECTION_OUTPUT
    AudioSource.VOICE_COMMUNICATION -> AAUDIO_INPUT_PRESET_VOICE_COMMUNICATION
    AudioFormat.ENCODING_PCM_16BIT  -> AAUDIO_FORMAT_PCM_I16
    getMinBufferSize()           -> AAudioStream_getBufferCapacityInFrames()
    getState() == STATE_INITIALIZED -> openStream() returning AAUDIO_OK
    ERROR_DEAD_OBJECT            -> AAUDIO_ERROR_DISCONNECTED (-899)

Every semantic requirement in the brief maps onto something real.


WHAT THIS CANNOT TELL YOU FROM HERE
===================================

Your device reports OpenSL ES error 12 for BOTH module-sles-source and
module-sles-sink.  12 is `SL_RESULT_FEATURE_UNSUPPORTED`.  Sink failing as
well as source matters: a pure permission problem would break capture and
leave playback working, so the OpenSL ES path is likely failing at engine or
device-capability level rather than at RECORD_AUDIO.

AAudio is a different code path and is worth trying.  But there is a
possibility I cannot resolve without your hardware:

    `termux-microphone-record` working proves the **Termux:API app** holds
    RECORD_AUDIO.  It does NOT prove the **Termux app** does.  Code in this
    process runs under Termux's UID and inherits Termux's permissions, not
    Termux:API's.  If Termux itself lacks RECORD_AUDIO, AAudio input will
    fail here exactly as OpenSL ES did, because the limit is the package
    manifest and no native API can route around it.

That is why `probe()` exists.  Run it on the device and it will say which
backend actually works, and — if AAudio input fails — distinguish a
permission refusal from a device-capability refusal.  I have not tested any
of this on Android; nothing below should be believed until probe() has run.

If AAudio input does turn out to be blocked by Termux's manifest, the only
remaining route to the microphone is the Termux:API app, and that is
file-based (MediaRecorder, AAC/AMR in a container). It cannot carry a live
call: containers need seekable output, MediaRecorder buffers on the order of
hundreds of milliseconds, and the brief rules out file recording as
transport. `probe()` reports this rather than pretending otherwise.


FORMAT
======

The voice pipeline is fixed at PCM signed 16-bit, mono, 16 kHz,
little-endian, in 60 ms frames (960 samples, 1920 bytes).  AAudio is asked
for exactly that.  When the device refuses and grants another rate — 48 kHz
is the common case — the stream is resampled here so the pipeline above
always sees the canonical format.  The negotiated values are reported by
diagnostics() rather than hidden.
"""

from __future__ import annotations

import ctypes
import os
import struct
import threading
import time

# Canonical pipeline format.  These mirror otrv4plus_voice and are asserted
# against it by the test suite so the two cannot drift apart.
SAMPLE_RATE = 16000
CHANNELS = 1
SAMPLE_WIDTH = 2                      # PCM_16BIT
# 60 ms frames: a third fewer packets per second than 40 ms, which is the
# variable that matters on a congested I2P path. Costs 20 ms of accumulation
# delay. otrv4plus_voice derives its own frame geometry from these constants
# rather than redeclaring them, so this is the ONE place frame duration is
# defined -- see the assertions there.
FRAME_MS = 60
FRAME_SAMPLES = SAMPLE_RATE * FRAME_MS // 1000        # 960
FRAME_BYTES = FRAME_SAMPLES * CHANNELS * SAMPLE_WIDTH  # 1920


# ---------------------------------------------------------------------------
# Structured errors
# ---------------------------------------------------------------------------

class AudioError(RuntimeError):
    """An audio backend failure with a stable machine-readable code."""

    def __init__(self, code: str, detail: str = ""):
        self.code = code
        self.detail = detail
        super().__init__(detail and "%s: %s" % (code, detail) or code)


MICROPHONE_PERMISSION_DENIED = "MICROPHONE_PERMISSION_DENIED"
AUDIO_RECORD_INITIALIZATION_FAILED = "AUDIO_RECORD_INITIALIZATION_FAILED"
AUDIO_FORMAT_UNAVAILABLE = "AUDIO_FORMAT_UNAVAILABLE"
AUDIO_BACKEND_UNAVAILABLE = "AUDIO_BACKEND_UNAVAILABLE"
AUDIO_DEVICE_DISCONNECTED = "AUDIO_DEVICE_DISCONNECTED"
AUDIO_PLAYBACK_INITIALIZATION_FAILED = "AUDIO_PLAYBACK_INITIALIZATION_FAILED"


# ---------------------------------------------------------------------------
# Resampling
# ---------------------------------------------------------------------------

try:                                   # removed in Python 3.13
    import warnings as _warnings
    with _warnings.catch_warnings():
        # Deprecated since 3.11 and gone in 3.13. The fallback below covers
        # 3.13+; until then ratecv is the better resampler, so the warning is
        # suppressed rather than the module avoided.
        _warnings.simplefilter("ignore", DeprecationWarning)
        import audioop as _audioop
except Exception:                      # pragma: no cover - version dependent
    _audioop = None


class Resampler:
    """Rate conversion to the canonical 16 kHz mono stream.

    Uses stdlib `audioop.ratecv` where available: it is C, it carries filter
    state across calls so block boundaries do not click, and it is already on
    every Termux Python before 3.13.

    The fallback matters because audioop was removed in 3.13.  For an integer
    decimation such as 48000 -> 16000 it averages each group of N input
    samples before dropping them, which is a length-N box FIR and enough
    anti-aliasing for 16 kHz speech.  For non-integer ratios it interpolates
    linearly.  Neither is hi-fi; both are honest about being adequate for
    voice and nothing more.
    """

    def __init__(self, in_rate: int, out_rate: int = SAMPLE_RATE,
                 channels: int = 1):
        self.in_rate = int(in_rate)
        self.out_rate = int(out_rate)
        self.channels = int(channels)
        self._state = None
        self._carry = b""
        self.needed = (self.in_rate != self.out_rate or self.channels != CHANNELS)

    def process(self, pcm: bytes) -> bytes:
        if not self.needed:
            return pcm
        if self.channels > 1:
            pcm = self._downmix(pcm, self.channels)
        if self.in_rate == self.out_rate:
            return pcm
        if _audioop is not None:
            converted, self._state = _audioop.ratecv(
                pcm, SAMPLE_WIDTH, 1, self.in_rate, self.out_rate, self._state)
            return converted
        return self._pure_python(pcm)

    @staticmethod
    def _downmix(pcm: bytes, channels: int) -> bytes:
        """Average interleaved channels down to mono."""
        n = len(pcm) // (SAMPLE_WIDTH * channels)
        if n == 0:
            return b""
        samples = struct.unpack("<%dh" % (n * channels), pcm[:n * channels * 2])
        out = [sum(samples[i * channels:(i + 1) * channels]) // channels
               for i in range(n)]
        return struct.pack("<%dh" % n, *out)

    def _pure_python(self, pcm: bytes) -> bytes:
        data = self._carry + pcm
        self._carry = b""
        n = len(data) // SAMPLE_WIDTH
        if n == 0:
            return b""
        samples = struct.unpack("<%dh" % n, data[:n * SAMPLE_WIDTH])

        if self.in_rate % self.out_rate == 0:
            step = self.in_rate // self.out_rate
            usable = (n // step) * step
            self._carry = data[usable * SAMPLE_WIDTH:]
            out = [sum(samples[i:i + step]) // step
                   for i in range(0, usable, step)]
        else:
            ratio = self.out_rate / float(self.in_rate)
            count = int(n * ratio)
            out = []
            for i in range(count):
                pos = i / ratio
                lo = int(pos)
                hi = min(lo + 1, n - 1)
                frac = pos - lo
                out.append(int(samples[lo] * (1.0 - frac) + samples[hi] * frac))
        if not out:
            return b""
        return struct.pack("<%dh" % len(out),
                           *[max(-32768, min(32767, v)) for v in out])


# ---------------------------------------------------------------------------
# AAudio bindings
# ---------------------------------------------------------------------------

AAUDIO_OK = 0
AAUDIO_DIRECTION_OUTPUT = 0
AAUDIO_DIRECTION_INPUT = 1
AAUDIO_FORMAT_PCM_I16 = 1
AAUDIO_SHARING_MODE_SHARED = 1
AAUDIO_PERFORMANCE_MODE_LOW_LATENCY = 12
AAUDIO_INPUT_PRESET_VOICE_COMMUNICATION = 7
AAUDIO_INPUT_PRESET_GENERIC = 1
AAUDIO_STREAM_STATE_STARTED = 5

AAUDIO_ERROR_DISCONNECTED = -899       # the AAudio analogue of ERROR_DEAD_OBJECT
AAUDIO_ERROR_INVALID_STATE = -895
AAUDIO_ERROR_UNIMPLEMENTED = -890
AAUDIO_ERROR_UNAVAILABLE = -889
AAUDIO_ERROR_NO_MEMORY = -887
AAUDIO_ERROR_TIMEOUT = -885
AAUDIO_ERROR_INVALID_FORMAT = -883
AAUDIO_ERROR_NO_SERVICE = -881
AAUDIO_ERROR_INVALID_RATE = -880

# AAudio has no distinct "permission denied".  A capture stream refused
# because the package lacks RECORD_AUDIO surfaces as one of these, so they
# are classified as a permission problem and the user is told to check the
# manifest rather than the format.
_PERMISSION_LIKE = (AAUDIO_ERROR_UNAVAILABLE, AAUDIO_ERROR_NO_SERVICE,
                    AAUDIO_ERROR_INVALID_STATE)
_FORMAT_LIKE = (AAUDIO_ERROR_INVALID_FORMAT, AAUDIO_ERROR_INVALID_RATE)

_LIB = None
_LIB_ERROR = None


def _load_aaudio():
    """dlopen libaaudio.so once.  Returns the handle or None."""
    global _LIB, _LIB_ERROR
    if _LIB is not None or _LIB_ERROR is not None:
        return _LIB
    for name in ("libaaudio.so", "/system/lib64/libaaudio.so",
                 "/system/lib/libaaudio.so"):
        try:
            lib = ctypes.CDLL(name)
        except OSError as exc:
            _LIB_ERROR = str(exc)
            continue
        if not hasattr(lib, "AAudio_createStreamBuilder"):
            _LIB_ERROR = "%s has no AAudio_createStreamBuilder" % name
            continue
        _bind(lib)
        _LIB, _LIB_ERROR = lib, None
        return _LIB
    if _LIB_ERROR is None:
        _LIB_ERROR = "libaaudio.so not found (Android 8.0+ required)"
    return None


def _bind(lib) -> None:
    """Declare argtypes/restypes.

    Not optional on 64-bit: without restype ctypes assumes int and truncates
    returned pointers to 32 bits, which produces a stream handle that appears
    valid and segfaults on first use.
    """
    p = ctypes.c_void_p
    i32 = ctypes.c_int32
    i64 = ctypes.c_int64

    lib.AAudio_createStreamBuilder.argtypes = [ctypes.POINTER(p)]
    lib.AAudio_createStreamBuilder.restype = i32
    for fn, arg in (("setDeviceId", i32), ("setSampleRate", i32),
                    ("setChannelCount", i32), ("setFormat", i32),
                    ("setDirection", i32), ("setSharingMode", i32),
                    ("setPerformanceMode", i32), ("setBufferCapacityInFrames", i32)):
        f = getattr(lib, "AAudioStreamBuilder_" + fn, None)
        if f is not None:
            f.argtypes = [p, arg]
            f.restype = None
    f = getattr(lib, "AAudioStreamBuilder_setInputPreset", None)
    if f is not None:                  # Android 9+
        f.argtypes = [p, i32]
        f.restype = None
    lib.AAudioStreamBuilder_openStream.argtypes = [p, ctypes.POINTER(p)]
    lib.AAudioStreamBuilder_openStream.restype = i32
    lib.AAudioStreamBuilder_delete.argtypes = [p]
    lib.AAudioStreamBuilder_delete.restype = i32

    lib.AAudioStream_requestStart.argtypes = [p]
    lib.AAudioStream_requestStart.restype = i32
    lib.AAudioStream_requestStop.argtypes = [p]
    lib.AAudioStream_requestStop.restype = i32
    lib.AAudioStream_close.argtypes = [p]
    lib.AAudioStream_close.restype = i32
    lib.AAudioStream_read.argtypes = [p, ctypes.c_void_p, i32, i64]
    lib.AAudioStream_read.restype = i32
    lib.AAudioStream_write.argtypes = [p, ctypes.c_void_p, i32, i64]
    lib.AAudioStream_write.restype = i32
    for fn in ("getSampleRate", "getChannelCount", "getFormat", "getState",
               "getBufferCapacityInFrames", "getFramesPerBurst",
               "getBufferSizeInFrames", "getPerformanceMode"):
        f = getattr(lib, "AAudioStream_" + fn, None)
        if f is not None:
            f.argtypes = [p]
            f.restype = i32
    f = getattr(lib, "AAudio_convertResultToText", None)
    if f is not None:
        f.argtypes = [i32]
        f.restype = ctypes.c_char_p


def _result_text(code: int) -> str:
    lib = _LIB
    fn = getattr(lib, "AAudio_convertResultToText", None) if lib else None
    if fn is not None:
        try:
            raw = fn(ctypes.c_int32(code))
            if raw:
                return raw.decode("ascii", "replace")
        except Exception:
            pass
    return "AAUDIO_ERROR_%d" % code


def aaudio_available() -> bool:
    return _load_aaudio() is not None


# ---------------------------------------------------------------------------
# Stream interface
# ---------------------------------------------------------------------------

class AudioStream:
    """One direction of one backend.

    read_frame / write_frame move exactly FRAME_BYTES of canonical-format PCM.
    Everything above this class — codec, AEAD, ratchet, transport — is
    unchanged by which backend is underneath.
    """

    name = "abstract"
    direction = "none"

    def read_frame(self, timeout_ms: int = 200):
        raise NotImplementedError

    def write_frame(self, pcm) -> bool:
        raise NotImplementedError

    def stop(self) -> None:
        raise NotImplementedError

    def diagnostics(self) -> dict:
        return {"backend": self.name, "direction": self.direction}


class AAudioStreamBase(AudioStream):
    """Shared open/close for an AAudio input or output stream."""

    name = "aaudio"

    def __init__(self, direction: int, input_preset=None):
        lib = _load_aaudio()
        if lib is None:
            raise AudioError(AUDIO_BACKEND_UNAVAILABLE, _LIB_ERROR or "no libaaudio")
        self._lib = lib
        self._stream = None
        self._closed = False
        self._lock = threading.Lock()
        self._is_input = (direction == AAUDIO_DIRECTION_INPUT)
        self.disconnected = False

        builder = ctypes.c_void_p()
        rc = lib.AAudio_createStreamBuilder(ctypes.byref(builder))
        if rc != AAUDIO_OK or not builder.value:
            raise AudioError(AUDIO_RECORD_INITIALIZATION_FAILED,
                             "createStreamBuilder: %s" % _result_text(rc))
        try:
            lib.AAudioStreamBuilder_setDirection(builder, direction)
            lib.AAudioStreamBuilder_setSampleRate(builder, SAMPLE_RATE)
            lib.AAudioStreamBuilder_setChannelCount(builder, CHANNELS)
            lib.AAudioStreamBuilder_setFormat(builder, AAUDIO_FORMAT_PCM_I16)
            lib.AAudioStreamBuilder_setSharingMode(
                builder, AAUDIO_SHARING_MODE_SHARED)
            lib.AAudioStreamBuilder_setPerformanceMode(
                builder, AAUDIO_PERFORMANCE_MODE_LOW_LATENCY)
            # Four frames of capacity.  getMinBufferSize()'s role: enough
            # slack that a scheduling hiccup does not drop audio, small
            # enough that latency stays inside a conversation's tolerance.
            lib.AAudioStreamBuilder_setBufferCapacityInFrames(
                builder, FRAME_SAMPLES * 4)
            setter = getattr(lib, "AAudioStreamBuilder_setInputPreset", None)
            if input_preset is not None and setter is not None and callable(setter):
                setter(builder, input_preset)

            stream = ctypes.c_void_p()
            rc = lib.AAudioStreamBuilder_openStream(builder,
                                                    ctypes.byref(stream))
            if rc != AAUDIO_OK or not stream.value:
                raise self._classify_open_failure(rc)
            self._stream = stream
        finally:
            lib.AAudioStreamBuilder_delete(builder)

        self.device_rate = self._get("getSampleRate", SAMPLE_RATE)
        self.device_channels = self._get("getChannelCount", CHANNELS)
        self.device_format = self._get("getFormat", AAUDIO_FORMAT_PCM_I16)
        self.buffer_capacity = self._get("getBufferCapacityInFrames", 0)
        self.frames_per_burst = self._get("getFramesPerBurst", 0)

        if self.device_format != AAUDIO_FORMAT_PCM_I16:
            self._close_locked()
            raise AudioError(
                AUDIO_FORMAT_UNAVAILABLE,
                "device granted format %d, not PCM_I16" % self.device_format)

        rc = lib.AAudioStream_requestStart(self._stream)
        if rc != AAUDIO_OK:
            self._close_locked()
            raise self._classify_open_failure(rc)

    def _classify_open_failure(self, rc: int) -> AudioError:
        """Map an AAudio result onto the brief's structured error codes."""
        text = _result_text(rc)
        if self._is_input and rc in _PERMISSION_LIKE:
            return AudioError(
                MICROPHONE_PERMISSION_DENIED,
                "AAudio refused a capture stream (%s). The Termux app itself "
                "must hold android.permission.RECORD_AUDIO — Termux:API "
                "holding it is not enough, because this process runs under "
                "Termux's UID." % text)
        if rc in _FORMAT_LIKE:
            return AudioError(
                AUDIO_FORMAT_UNAVAILABLE,
                "device rejected %d Hz mono PCM_I16 (%s)" % (SAMPLE_RATE, text))
        code = (AUDIO_RECORD_INITIALIZATION_FAILED if self._is_input
                else AUDIO_PLAYBACK_INITIALIZATION_FAILED)
        return AudioError(code, text)

    def _get(self, fn_name: str, default: int) -> int:
        fn = getattr(self._lib, "AAudioStream_" + fn_name, None)
        if fn is None or self._stream is None:
            return default
        try:
            value = fn(self._stream)
            return value if value > 0 else default
        except Exception:
            return default

    def _close_locked(self) -> None:
        if self._stream is not None:
            try:
                self._lib.AAudioStream_requestStop(self._stream)
            except Exception:
                pass
            try:
                self._lib.AAudioStream_close(self._stream)
            except Exception:
                pass
            self._stream = None

    def stop(self) -> None:
        """Release the device.  Idempotent — teardown may run twice."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._close_locked()

    def diagnostics(self) -> dict:
        return {
            "backend": "aaudio",
            "direction": "input" if self._is_input else "output",
            "requested_rate": SAMPLE_RATE,
            "device_rate": getattr(self, "device_rate", None),
            "requested_channels": CHANNELS,
            "device_channels": getattr(self, "device_channels", None),
            "encoding": "PCM_16BIT",
            "buffer_capacity_frames": getattr(self, "buffer_capacity", None),
            "frames_per_burst": getattr(self, "frames_per_burst", None),
            "state": self._get("getState", -1),
            "resampling": getattr(self, "device_rate", SAMPLE_RATE) != SAMPLE_RATE,
            "disconnected": self.disconnected,
            "closed": self._closed,
        }


class AAudioCapture(AAudioStreamBase):
    """Microphone capture.  Replaces parec.

    VOICE_COMMUNICATION is preferred for the platform echo canceller and AGC;
    GENERIC is the fallback when the preset is unsupported (Android 8, where
    setInputPreset does not exist).
    """

    direction = "input"

    def __init__(self):
        self.input_preset = AAUDIO_INPUT_PRESET_VOICE_COMMUNICATION
        try:
            super().__init__(AAUDIO_DIRECTION_INPUT,
                             AAUDIO_INPUT_PRESET_VOICE_COMMUNICATION)
        except AudioError as exc:
            # Retry with GENERIC only where the preset could plausibly be the
            # cause.  A permission refusal and a format refusal are both
            # about something else, and reopening the device to fail the same
            # way twice just holds the microphone longer and doubles the log.
            if exc.code in (MICROPHONE_PERMISSION_DENIED,
                            AUDIO_FORMAT_UNAVAILABLE):
                raise
            self.input_preset = AAUDIO_INPUT_PRESET_GENERIC
            super().__init__(AAUDIO_DIRECTION_INPUT,
                             AAUDIO_INPUT_PRESET_GENERIC)
        self._resampler = Resampler(self.device_rate, SAMPLE_RATE,
                                    self.device_channels)
        self._pending = bytearray()

        # Read one hardware burst at a time and let _pending reassemble the
        # 60 ms frame.  Asking for a non-multiple of framesPerBurst makes
        # AAudio wait on a partially filled burst for every read, which adds
        # jitter and costs frames at the start of a call.  Measured on a
        # Xiaomi 25028RN03Y: framesPerBurst=480 against a 960-sample frame,
        # so a 960-frame read straddles two bursts every time.
        device_frame = max(
            1, int(FRAME_SAMPLES * self.device_rate / float(SAMPLE_RATE)))
        burst = self.frames_per_burst
        if 0 < burst <= device_frame * 4:
            self._chunk_frames = burst
        else:
            self._chunk_frames = device_frame
        self._raw = (ctypes.c_int16 * (self._chunk_frames
                                       * max(1, self.device_channels)))()

    def read_frame(self, timeout_ms: int = 200):
        """Return exactly FRAME_BYTES of canonical PCM, or None.

        None means "nothing yet" — a timeout, not a failure.  The caller
        loops; it must not treat None as end-of-stream, or a momentarily
        starved device would end the call.
        """
        if self._closed or self._stream is None:
            return None
        while len(self._pending) < FRAME_BYTES:
            got = self._lib.AAudioStream_read(
                self._stream, ctypes.byref(self._raw),
                ctypes.c_int32(self._chunk_frames),
                ctypes.c_int64(int(timeout_ms) * 1000000))
            if got == AAUDIO_ERROR_DISCONNECTED:
                # Route change, headset unplug, or the audio server dying.
                # The AAudio equivalent of ERROR_DEAD_OBJECT: the stream is
                # dead and must be reopened, never re-read.
                self.disconnected = True
                raise AudioError(AUDIO_DEVICE_DISCONNECTED,
                                 "capture stream disconnected")
            if got < 0:
                if got == AAUDIO_ERROR_TIMEOUT:
                    return None
                raise AudioError(AUDIO_RECORD_INITIALIZATION_FAILED,
                                 "read failed: %s" % _result_text(got))
            if got == 0:
                # A zero-frame read with a real timeout already elapsed inside
                # AAudio.  Returning here rather than spinning is what keeps
                # this off 100% CPU.
                return None
            raw = bytes(memoryview(self._raw).cast("B")[
                :got * self.device_channels * SAMPLE_WIDTH])
            self._pending += self._resampler.process(raw)

        frame = bytes(self._pending[:FRAME_BYTES])
        del self._pending[:FRAME_BYTES]
        return frame

    def stop(self) -> None:
        super().stop()
        # Residual microphone samples are plaintext audio; do not leave them
        # for the allocator.  Both buffers matter: _pending holds the partial
        # frame, and _raw holds the last burst read straight off the device.
        # Wiping only the first leaves up to one burst of real speech behind.
        if self._pending:
            for i in range(len(self._pending)):
                self._pending[i] = 0
            self._pending.clear()
        raw = getattr(self, "_raw", None)
        if raw is not None:
            try:
                ctypes.memset(ctypes.byref(raw), 0, ctypes.sizeof(raw))
            except Exception:
                pass


class AAudioPlayback(AAudioStreamBase):
    """Speaker playback.  Replaces pacat, and AudioTrack's role."""

    direction = "output"

    def __init__(self):
        super().__init__(AAUDIO_DIRECTION_OUTPUT, None)
        # Playback runs the conversion the other way: the pipeline produces
        # 16 kHz and the device may want 48 kHz.
        self._resampler = Resampler(SAMPLE_RATE, self.device_rate, 1)
        self._upmix = max(1, self.device_channels)

    def write_frame(self, pcm, timeout_ms: int = 200) -> bool:
        if self._closed or self._stream is None:
            return False
        data = self._resampler.process(bytes(pcm))
        if self._upmix > 1:
            data = self._duplicate_channels(data, self._upmix)
        if not data:
            return True
        total = len(data) // (SAMPLE_WIDTH * self._upmix)
        buf = (ctypes.c_char * len(data)).from_buffer_copy(data)
        written = 0
        while written < total:
            offset = written * SAMPLE_WIDTH * self._upmix
            got = self._lib.AAudioStream_write(
                self._stream,
                ctypes.byref(buf, offset),
                ctypes.c_int32(total - written),
                ctypes.c_int64(int(timeout_ms) * 1000000))
            if got == AAUDIO_ERROR_DISCONNECTED:
                self.disconnected = True
                raise AudioError(AUDIO_DEVICE_DISCONNECTED,
                                 "playback stream disconnected")
            if got < 0:
                if got == AAUDIO_ERROR_TIMEOUT:
                    return False
                raise AudioError(AUDIO_PLAYBACK_INITIALIZATION_FAILED,
                                 "write failed: %s" % _result_text(got))
            if got == 0:
                return False
            written += got
        return True

    @staticmethod
    def _duplicate_channels(pcm: bytes, channels: int) -> bytes:
        n = len(pcm) // SAMPLE_WIDTH
        if n == 0:
            return b""
        samples = struct.unpack("<%dh" % n, pcm[:n * SAMPLE_WIDTH])
        out = []
        for s in samples:
            out.extend([s] * channels)
        return struct.pack("<%dh" % len(out), *out)


# ---------------------------------------------------------------------------
# PulseAudio backend (retained, deprecated for voice)
# ---------------------------------------------------------------------------
# Not deleted.  otrv4plus_xmpp.py uses parec for the /audiotest self-test and
# the bootstrap installs the package, so removing it would break paths the
# brief says to leave alone.  It is simply no longer the default for calls.

class PulseCapture(AudioStream):
    """parec -> pipe.  The legacy path, kept as an explicit opt-in."""

    name = "pulseaudio"
    direction = "input"

    def __init__(self, which=None, read_exact=None, env=None):
        import subprocess
        which = which or _default_which
        parec = which("parec")
        if parec is None:
            raise AudioError(AUDIO_BACKEND_UNAVAILABLE, "parec not found")
        self._read_exact = read_exact
        self._closed = False
        self._proc = subprocess.Popen(
            [parec, "--client-name=otrv4plus-mic", "--channels=%d" % CHANNELS,
             "--rate=%d" % SAMPLE_RATE, "--format=s16le",
             "--latency-msec=%d" % FRAME_MS],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL, bufsize=0, env=env or dict(os.environ))
        time.sleep(0.25)
        if self._proc.poll() is not None:
            # Reap the pipes before raising. Leaving them to the GC leaked a
            # file descriptor per failed attempt, and open_capture() retries.
            _terminate(self._proc)
            raise AudioError(AUDIO_RECORD_INITIALIZATION_FAILED,
                             "parec exited immediately")

    def read_frame(self, timeout_ms: int = 200):
        if self._closed or self._proc.stdout is None:
            return None
        if self._read_exact is not None:
            return self._read_exact(self._proc.stdout, FRAME_BYTES,
                                    lambda: not self._closed)
        buf = b""
        while len(buf) < FRAME_BYTES:
            chunk = self._proc.stdout.read(FRAME_BYTES - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    def stop(self) -> None:
        if self._closed:
            return
        self._closed = True
        _terminate(self._proc)

    def diagnostics(self) -> dict:
        return {"backend": "pulseaudio", "direction": "input",
                "device_rate": SAMPLE_RATE, "device_channels": CHANNELS,
                "encoding": "PCM_16BIT", "resampling": False,
                "alive": self._proc.poll() is None}


class PulsePlayback(AudioStream):
    """pipe -> pacat.  The legacy path, kept as an explicit opt-in."""

    name = "pulseaudio"
    direction = "output"

    def __init__(self, which=None, write_all=None, env=None):
        import subprocess
        which = which or _default_which
        pacat = which("pacat")
        if pacat is None:
            raise AudioError(AUDIO_BACKEND_UNAVAILABLE, "pacat not found")
        self._write_all = write_all
        self._closed = False
        self._proc = subprocess.Popen(
            [pacat, "--playback", "--client-name=otrv4plus-spk",
             "--channels=%d" % CHANNELS, "--rate=%d" % SAMPLE_RATE,
             "--format=s16le", "--latency-msec=%d" % FRAME_MS],
            stdin=subprocess.PIPE, stderr=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, bufsize=0, env=env or dict(os.environ))
        time.sleep(0.25)
        if self._proc.poll() is not None:
            _terminate(self._proc)
            raise AudioError(AUDIO_PLAYBACK_INITIALIZATION_FAILED,
                             "pacat exited immediately")

    def write_frame(self, pcm, timeout_ms: int = 200) -> bool:
        if self._closed or self._proc.poll() is not None:
            return False
        try:
            if self._write_all is not None:
                return bool(self._write_all(self._proc.stdin, bytes(pcm)))
            self._proc.stdin.write(bytes(pcm))
            return True
        except Exception:
            return False

    def stop(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            if self._proc.stdin is not None:
                self._proc.stdin.close()
        except Exception:
            pass
        _terminate(self._proc)

    def diagnostics(self) -> dict:
        return {"backend": "pulseaudio", "direction": "output",
                "device_rate": SAMPLE_RATE, "device_channels": CHANNELS,
                "encoding": "PCM_16BIT", "resampling": False,
                "alive": self._proc.poll() is None}


def _terminate(proc) -> None:
    """Stop a child and close its pipes. Never raises."""
    for stream in ("stdin", "stdout", "stderr"):
        handle = getattr(proc, stream, None)
        if handle is not None:
            try:
                handle.close()
            except Exception:
                pass
    try:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except Exception:
                proc.kill()
                try:
                    proc.wait(timeout=2)
                except Exception:
                    pass
    except Exception:
        pass


def _default_which(binary: str):
    import shutil
    return shutil.which(binary)


# ---------------------------------------------------------------------------
# Backend selection
# ---------------------------------------------------------------------------

BACKEND_AAUDIO = "aaudio"
BACKEND_PULSE = "pulseaudio"

# AAudio first.  On this hardware PulseAudio exposes only auto_null, so a
# call placed through it would connect, negotiate keys, encrypt and transmit
# pure silence — the worst failure mode available, because everything looks
# healthy.  Ordering AAudio ahead of it means the working path is tried
# first, and open_capture() below refuses to fall back silently.
BACKEND_ORDER = (BACKEND_AAUDIO, BACKEND_PULSE)


def _env_backend():
    value = (os.environ.get("OTRV4PLUS_AUDIO_BACKEND") or "").strip().lower()
    return value or None


def open_capture(preferred=None, which=None, read_exact=None, env=None):
    """Open a capture stream.  Returns (stream, notes).

    A fallback from AAudio to PulseAudio is NEVER silent: `notes` carries why
    the preferred backend was skipped, and the caller prints it. Silently
    demoting to a backend that yields auto_null would encrypt and transmit
    silence while reporting a healthy call.
    """
    order = _pick_order(preferred)
    notes, first_error = [], None
    for backend in order:
        try:
            if backend == BACKEND_AAUDIO:
                return AAudioCapture(), notes
            if backend == BACKEND_PULSE:
                return PulseCapture(which=which, read_exact=read_exact,
                                    env=env), notes
        except AudioError as exc:
            first_error = first_error or exc
            notes.append("%s capture unavailable: %s" % (backend, exc))
            if exc.code == MICROPHONE_PERMISSION_DENIED:
                # No other backend can route around a missing manifest
                # permission — they all run under the same UID.
                raise
    raise first_error or AudioError(AUDIO_BACKEND_UNAVAILABLE,
                                    "no capture backend available")


def open_playback(preferred=None, which=None, write_all=None, env=None):
    """Open a playback stream.  Returns (stream, notes).

    Callers that already have a capture stream should pass its backend as
    `preferred`, which pins playback to the same one.  Letting playback fall
    back independently produces a half-working call: on this hardware
    PulseAudio exposes only auto_null, so AAudio capture plus PulseAudio
    playback means the peer hears you and you hear silence, with no error
    anywhere.  A clear failure beats a one-way call the user cannot diagnose.
    """
    order = _pick_order(preferred)
    notes, first_error = [], None
    for backend in order:
        try:
            if backend == BACKEND_AAUDIO:
                return AAudioPlayback(), notes
            if backend == BACKEND_PULSE:
                return PulsePlayback(which=which, write_all=write_all,
                                     env=env), notes
        except AudioError as exc:
            first_error = first_error or exc
            notes.append("%s playback unavailable: %s" % (backend, exc))
    raise first_error or AudioError(AUDIO_BACKEND_UNAVAILABLE,
                                    "no playback backend available")


def _pick_order(preferred):
    choice = preferred or _env_backend()
    if choice in (BACKEND_AAUDIO, BACKEND_PULSE):
        return (choice,)          # explicit choice is honoured exactly
    return BACKEND_ORDER


# ---------------------------------------------------------------------------
# Diagnostics
# ---------------------------------------------------------------------------

def probe(duration: float = 2.0, verbose: bool = True) -> dict:
    """Determine, on the actual device, which audio backend works.

    This exists because I cannot test on your hardware.  It opens each
    backend for real, captures for `duration` seconds, and reports the peak
    amplitude — the byte count alone cannot distinguish a working microphone
    from a stream of zeroes, and a stream of zeroes is exactly what a revoked
    RECORD_AUDIO or an auto_null sink produces.

    Never writes audio to disk and never prints samples.  Peak amplitude is a
    single integer derived from the frame; it carries no speech content.
    """
    report = {
        "aaudio_library": aaudio_available(),
        "aaudio_library_error": None if aaudio_available() else _LIB_ERROR,
        "capture": {}, "playback": {},
        "termux_api": _probe_termux_api(),
        "recommended": None,
    }

    def say(msg):
        if verbose:
            print(msg)

    say("[audio] libaaudio.so: %s"
        % ("loaded" if report["aaudio_library"]
           else "UNAVAILABLE (%s)" % report["aaudio_library_error"]))

    for backend in BACKEND_ORDER:
        entry = {"opened": False, "error": None, "bytes": 0, "peak": 0}
        stream = None
        try:
            stream, _ = open_capture(preferred=backend)
            entry["opened"] = True
            entry["diagnostics"] = stream.diagnostics()
            deadline = time.time() + duration
            while time.time() < deadline:
                frame = stream.read_frame(timeout_ms=200)
                if not frame:
                    continue
                entry["bytes"] += len(frame)
                n = len(frame) // 2
                peak = max(abs(v) for v in struct.unpack("<%dh" % n, frame))
                entry["peak"] = max(entry["peak"], peak)
        except AudioError as exc:
            entry["error"] = {"code": exc.code, "detail": exc.detail}
        except Exception as exc:
            entry["error"] = {"code": "UNEXPECTED", "detail": str(exc)}
        finally:
            if stream is not None:
                stream.stop()
        report["capture"][backend] = entry

        if entry["opened"]:
            d = entry.get("diagnostics", {})
            say("[audio] %-11s capture OK  rate=%s ch=%s resample=%s "
                "bytes=%d peak=%d"
                % (backend, d.get("device_rate"), d.get("device_channels"),
                   d.get("resampling"), entry["bytes"], entry["peak"]))
            if entry["bytes"] == 0:
                say("           opened but delivered nothing — the device is "
                    "not producing samples")
            elif entry["peak"] == 0:
                say("           delivered %d bytes of pure silence. Either "
                    "RECORD_AUDIO is revoked or this is a null source; a live "
                    "room never reads exactly zero." % entry["bytes"])
        else:
            say("[audio] %-11s capture FAILED  %s"
                % (backend, entry["error"]["code"]))
            if entry["error"]["detail"]:
                say("           %s" % entry["error"]["detail"])

    for backend in BACKEND_ORDER:
        entry = {"opened": False, "error": None}
        stream = None
        try:
            stream, _ = open_playback(preferred=backend)
            entry["opened"] = True
            entry["diagnostics"] = stream.diagnostics()
            stream.write_frame(b"\x00" * FRAME_BYTES)
        except AudioError as exc:
            entry["error"] = {"code": exc.code, "detail": exc.detail}
        except Exception as exc:
            entry["error"] = {"code": "UNEXPECTED", "detail": str(exc)}
        finally:
            if stream is not None:
                stream.stop()
        report["playback"][backend] = entry
        say("[audio] %-11s playback %s" % (backend,
            "OK" if entry["opened"] else "FAILED  %s" % entry["error"]["code"]))

    for backend in BACKEND_ORDER:
        cap = report["capture"].get(backend, {})
        play = report["playback"].get(backend, {})
        if cap.get("opened") and cap.get("peak", 0) > 0 and play.get("opened"):
            report["recommended"] = backend
            break

    if report["recommended"]:
        say("\n[audio] usable backend: %s" % report["recommended"])
        if report["recommended"] == BACKEND_AAUDIO:
            say("[audio] PulseAudio is not required for voice.")
    else:
        say("\n[audio] no backend delivered live audio in both directions.")
        cap = report["capture"].get(BACKEND_AAUDIO, {})
        err = (cap.get("error") or {}).get("code")
        if err == MICROPHONE_PERMISSION_DENIED:
            say("[audio] AAudio capture was refused. This process runs under "
                "the Termux app's UID, so the TERMUX app must hold "
                "RECORD_AUDIO — Termux:API holding it does not help.")
            say("[audio] Check: Android Settings > Apps > Termux > "
                "Permissions > Microphone.")
            say("[audio] If Termux has no Microphone entry at all, its "
                "manifest does not declare RECORD_AUDIO and no native API "
                "in this process can reach the microphone. The F-Droid "
                "Termux build is worth testing; the Play build is more "
                "restricted.")
        if report["termux_api"]["available"]:
            say("[audio] termux-microphone-record is present, but it records "
                "to a file via MediaRecorder (AAC/AMR in a container). It "
                "cannot carry a live call: containers need seekable output "
                "and MediaRecorder buffers hundreds of milliseconds. It "
                "proves the microphone works; it is not a transport.")
    return report


def _probe_termux_api() -> dict:
    """Is Termux:API present?  Diagnostic only — never a live backend."""
    path = _default_which("termux-microphone-record")
    return {"available": path is not None, "path": path,
            "usable_for_calls": False,
            "reason": "file-based MediaRecorder; not a real-time PCM stream"}


def backend_summary() -> str:
    lib = "available" if aaudio_available() else "unavailable"
    return ("audio backends: aaudio=%s pulseaudio=%s (order: %s)"
            % (lib,
               "available" if _default_which("parec") else "unavailable",
               ", ".join(BACKEND_ORDER)))


if __name__ == "__main__":
    import json
    result = probe()
    if os.environ.get("OTRV4PLUS_AUDIO_JSON"):
        print(json.dumps(result, indent=2, default=str))


# ---------------------------------------------------------------------------
# Incoming-call ringer
# ---------------------------------------------------------------------------

class Ringer:
    """Ring pattern for an incoming call, synthesised and played via AAudio.

    No audio file is read or written: the tone is generated as PCM in memory,
    which keeps the "nothing touches disk" property and needs no extra
    package. It plays through the same backend the call will use, so if the
    ringer is audible the call will be too — a silent ringer is itself a
    useful signal that playback is broken.

    Termux:API notification and vibration run alongside it, because the phone
    is usually screen-off and face-down when a call arrives and a tone from a
    backgrounded terminal is easy to miss.

    stop() is idempotent and must be called before the call opens its own
    playback stream, so the two never contend for the device.
    """

    # UK-style double ring: 400 + 450 Hz, 0.4 s on, 0.2 s gap, 0.4 s on,
    # then two seconds of silence. Distinct from a notification chirp and
    # recognisable as a call without being shrill.
    TONE_HZ = (400.0, 450.0)
    PATTERN = ((0.4, True), (0.2, False), (0.4, True), (2.0, False))
    AMPLITUDE = 0.28                      # headroom: two summed tones

    def __init__(self, notify=True, vibrate=True):
        self._helpers = []              # Termux:API children awaiting reap
        self._stop = threading.Event()
        self._thread = None
        self._stream = None
        self._notify = notify
        self._vibrate = vibrate
        self._notif_id = "otrv4plus-call"
        self.started = False
        self.error = None

    # -- tone generation --------------------------------------------------

    _PATTERN_CACHE = None

    @classmethod
    def _build_pattern(cls):
        """One full ring cycle as a list of canonical-format PCM frames.

        Cached: this is ~80 frames of pure-Python sine, and generating it
        after the device opens delayed the first audible ring on a slow
        phone. Same bytes every call, so building it once is free.
        """
        if cls._PATTERN_CACHE is not None:
            return cls._PATTERN_CACHE
        import math
        frames = []
        phase = 0
        for seconds, voiced in cls.PATTERN:
            for _ in range(max(1, int(round(seconds / (FRAME_MS / 1000.0))))):
                samples = []
                for i in range(FRAME_SAMPLES):
                    if not voiced:
                        samples.append(0)
                        continue
                    t = (phase + i) / float(SAMPLE_RATE)
                    v = sum(math.sin(2.0 * math.pi * f * t)
                            for f in cls.TONE_HZ) / len(cls.TONE_HZ)
                    samples.append(int(max(-1.0, min(1.0, v))
                                       * cls.AMPLITUDE * 32767))
                phase += FRAME_SAMPLES
                frames.append(struct.pack("<%dh" % FRAME_SAMPLES, *samples))
        cls._PATTERN_CACHE = frames
        return frames

    # -- lifecycle --------------------------------------------------------

    def start(self, peer: str = "", which=None, write_all=None) -> None:
        if self._thread is not None:
            return
        self._stop.clear()
        if self._notify:
            self._post_notification(peer, which)
        self._thread = threading.Thread(target=self._run, name="voice-ringer",
                                        args=(which, write_all), daemon=True)
        self._thread.start()

    def _run(self, which, write_all) -> None:
        pattern = self._build_pattern()
        try:
            self._stream, _notes = open_playback(which=which,
                                                 write_all=write_all)
            self.started = True
        except Exception as exc:
            # A silent ring is survivable — the call still shows on screen —
            # so this never propagates into the call path.
            self.error = str(exc)
            return
        try:
            while not self._stop.is_set():
                for frame in pattern:
                    if self._stop.is_set():
                        break
                    try:
                        self._stream.write_frame(frame)
                    except Exception:
                        return
        finally:
            try:
                self._stream.stop()
            except Exception:
                pass
            self._stream = None

    def stop(self) -> None:
        """Silence the ringer and release the device.  Idempotent."""
        self._stop.set()
        thread, self._thread = self._thread, None
        if thread is not None and thread.is_alive():
            # Bounded: the loop checks the flag once per 40 ms frame.
            thread.join(timeout=1.5)
        stream = self._stream
        if stream is not None:
            try:
                stream.stop()
            except Exception:
                pass
            self._stream = None
        self._clear_notification()

    # -- Termux:API -------------------------------------------------------

    def _post_notification(self, peer: str, which) -> None:
        """Notification plus vibration, best effort.

        OTRV4PLUS_RING_PRIVACY=1 keeps the peer's JID off the lock screen,
        where anyone holding the phone can read it.
        """
        import subprocess
        which = which or _default_which
        if os.environ.get("OTRV4PLUS_RING_PRIVACY"):
            content = "Open Termux to answer"
        else:
            content = str(peer)[:96] or "unknown peer"

        notif = which("termux-notification")
        if notif:
            self._spawn([notif, "--id", self._notif_id,
                         "--title", "Incoming encrypted call",
                         "--content", content,
                         "--priority", "max", "--sound"])
        if self._vibrate:
            vib = which("termux-vibrate")
            if vib:
                self._spawn([vib, "-d", "800"])

    def _spawn(self, argv) -> None:
        """Launch a Termux:API helper without blocking or leaking it.

        These are fire-and-forget and exit in well under a second, but a
        Popen garbage-collected while its child still runs leaves a zombie
        and emits a ResourceWarning. Holding the handle and reaping finished
        ones on the next call keeps that tidy without ever blocking the
        receive path on an external binary.
        """
        import subprocess
        self._helpers = [p for p in self._helpers if p.poll() is None]
        try:
            self._helpers.append(subprocess.Popen(
                argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL))
        except Exception:
            pass

    def _reap_helpers(self) -> None:
        for proc in self._helpers:
            try:
                if proc.poll() is None:
                    proc.wait(timeout=1.0)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        self._helpers = []

    def _clear_notification(self) -> None:
        remove = _default_which("termux-notification-remove")
        if remove:
            self._spawn([remove, self._notif_id])
        self._reap_helpers()
