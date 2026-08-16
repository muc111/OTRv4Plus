# OTRv4+ audio backend: PulseAudio → AAudio

## The requested architecture cannot be built in this repository

The brief asks for `android.media.AudioRecord` behind a Python → Rust →
AudioRecord FFI boundary. That is not implementable here, for a structural
reason rather than a difficulty one:

- `android.media.AudioRecord` is a **Java** class. Reaching it needs a JNI
  attachment to a live ART VM.
- Termux runs a plain Linux userland. This code lives in CPython started from
  a shell. There is no JVM in that process and Termux ships none —
  `AttachCurrentThread` has nothing to attach to.
- Repository inspection confirms no Java anywhere: `otrv4_core` is
  `crate-type = ["cdylib"]`, a PyO3 extension. No JNI, no `AndroidManifest.xml`,
  no Gradle, no `jni` crate.
- Obtaining a JVM would mean shipping a companion Android APK with a
  foreground service and an IPC channel — a second build system, which the
  brief explicitly rules out.

So I did not write it. Anything claiming to call `AudioRecord` from here would
have been fiction.

## What was built instead

**AAudio** (`libaaudio.so`) — the NDK **C** audio API added in Android 8.0. It
is Android's audio framework, the same AudioFlinger path `AudioRecord` sits on
top of, exposed as plain C symbols. No JVM, no JNI, no Java: a Termux process
dlopens it directly. Every constraint in the brief is met — no PulseAudio, no
`module-sles-source`, no `module-sles-sink`, no ALSA, no `/dev/snd`, no D-Bus,
no systemd, no root, no audio files, real-time streaming PCM.

| Brief asks for | Actually used |
|---|---|
| `AudioRecord` | `AAudioStream`, `DIRECTION_INPUT` |
| `AudioTrack` | `AAudioStream`, `DIRECTION_OUTPUT` |
| `AudioSource.VOICE_COMMUNICATION` | `AAUDIO_INPUT_PRESET_VOICE_COMMUNICATION` (fallback `GENERIC`) |
| `ENCODING_PCM_16BIT` | `AAUDIO_FORMAT_PCM_I16` |
| `getMinBufferSize()` | `setBufferCapacityInFrames` + `getBufferCapacityInFrames` |
| `getState() == STATE_INITIALIZED` | `openStream()` returning `AAUDIO_OK` |
| `ERROR_DEAD_OBJECT` | `AAUDIO_ERROR_DISCONNECTED` (−899) |

## What I cannot tell you from here

Your device reports OpenSL ES **error 12** for both source *and* sink. 12 is
`SL_RESULT_FEATURE_UNSUPPORTED`. Sink failing as well as source is the
informative part: a pure permission problem breaks capture and leaves playback
working, so OpenSL ES is likely failing at engine or device-capability level
rather than at RECORD_AUDIO. AAudio is a different code path and is worth
trying.

But there is a possibility I cannot resolve without your hardware:

> `termux-microphone-record` working proves the **Termux:API app** holds
> RECORD_AUDIO. It does **not** prove the **Termux app** does. This process
> runs under Termux's UID and inherits Termux's permissions. If Termux itself
> lacks RECORD_AUDIO, AAudio input will fail here exactly as OpenSL ES did,
> because the limit is the package manifest and no native API can route around
> it.

That is why `probe()` exists. **I have not tested any of this on Android.**
Run `/audioprobe` before believing any of it.

If AAudio input turns out to be blocked by Termux's manifest, the only
remaining route to the microphone is the Termux:API app — and that is
file-based (MediaRecorder, AAC/AMR in a container). It cannot carry a live
call: containers need seekable output and MediaRecorder buffers hundreds of
milliseconds. The probe says so rather than pretending otherwise. The next
thing to try in that case is the **F-Droid Termux build**, which is less
restricted than the Play build.

## Files changed

| File | Change | Why |
|---|---|---|
| **`otrv4plus_audio.py`** (new, 1006 lines) | Backend abstraction: `AAudioCapture`, `AAudioPlayback`, `PulseCapture`, `PulsePlayback`, `Resampler`, `open_capture`/`open_playback`, `probe()` | The device layer had no seam — `subprocess.Popen(parec)` was hard-wired into the capture thread |
| **`otrv4plus_voice.py`** | `_spawn_audio_processes` → `_open_audio_devices`; capture/playback workers read and write through the stream interface; teardown calls `stream.stop()`; `describe()` reports the backend | Only the device abstraction. **No crypto changed** |
| **`otrv4plus_xmpp.py`** | `voice_available()` no longer requires parec/pacat; added `/audioprobe` | Requiring PulseAudio would refuse calls on a device where AAudio works |
| **`test_audio_backend.py`** (new) | 37 tests | The brief's 15 test requirements |

**PulseAudio was not deleted.** `otrv4plus_xmpp.py` still uses `parec` for the
`/audiotest` self-test and the bootstrap still installs the package, so removal
would break paths the brief says to leave alone. It is demoted from default to
opt-in via `OTRV4PLUS_AUDIO_BACKEND=pulseaudio`.

## The crypto path is untouched

Diff-verified: the call state machine, X448/ML-KEM establishment, key
confirmation, AEAD/AAD construction, ratchet, two-phase rekey, replay window,
epoch handling, I2P transport and teardown ordering are byte-identical. The
capture thread's change is exactly one line — where the PCM comes from. The
110-test voice suite still passes unmodified.

## Two design decisions worth flagging

**Fallback is never silent.** On your hardware PulseAudio exposes only
`auto_null`. A call demoted silently to it would establish keys, encrypt, and
transmit *pure silence* while every indicator showed a healthy call — the worst
failure mode available. So AAudio is tried first, any fallback is printed, and
`MICROPHONE_PERMISSION_DENIED` aborts rather than falling through (no other
backend can route around a missing manifest permission; they share a UID).

**The probe reports peak amplitude, not just byte count.** A byte count cannot
distinguish a working microphone from a stream of zeroes, and zeroes are
exactly what a revoked RECORD_AUDIO or an `auto_null` source produces. Peak is
a single integer derived from the frame — it carries no speech content, is
never written to disk, and no samples are logged.

## Format negotiation

16 kHz / mono / PCM_16BIT is requested. If the device grants something else —
48 kHz is the usual case — the stream is resampled so the pipeline always
receives 40 ms frames of 16 kHz mono. `audioop.ratecv` is used where available
(C, carries filter state across block boundaries); the pure-Python fallback
exists because `audioop` was **removed in Python 3.13**, and does box-filter
decimation for integer ratios, linear interpolation otherwise. Adequate for
speech; not hi-fi, and documented as such.

## Errors

`MICROPHONE_PERMISSION_DENIED`, `AUDIO_RECORD_INITIALIZATION_FAILED`,
`AUDIO_FORMAT_UNAVAILABLE`, `AUDIO_BACKEND_UNAVAILABLE`,
`AUDIO_DEVICE_DISCONNECTED`, `AUDIO_PLAYBACK_INITIALIZATION_FAILED` — all
carried on `AudioError.code`.

## Test results — actually run

```
$ python3 -m unittest test_audio_backend -v
Ran 37 tests in 0.037s
OK

$ OTRV4PLUS_ALLOW_PYTHON_MLKEM=1 python3 -m unittest test_voice_security
Ran 110 tests in 2.476s
OK
```

AAudio cannot be exercised off Android, so device tests drive a fake
`libaaudio` through the **real ctypes call path** — enough to cover error
classification, resampling, framing, disconnect handling and teardown.

Covering the brief's list: backend initialises (3), permission failure (2),
capture starts (2), frames delivered (3), format correct (2), stops cleanly
(1), repeated start/stop leaks nothing (1), `ERROR_DEAD_OBJECT` (2), teardown
releases the device (2), no PulseAudio required (2), no files created (1), no
plaintext logged (1), voice-encryption tests pass (110), constants agree with
the pipeline (1).

One test caught a real defect: the VOICE_COMMUNICATION → GENERIC retry fired on
*any* error, so a format rejection reopened the device to fail identically
twice. Now restricted to errors the preset could plausibly cause.

## Build and run

No new dependencies. No NDK, no Gradle, no Rust rebuild — `ctypes` is stdlib
and `libaaudio.so` is on the device.

```
cp otrv4plus_audio.py otrv4plus_voice.py otrv4plus_xmpp.py ~/otrv4plus/
cd ~/otrv4plus
python3 -m unittest test_audio_backend -v
python3 otrv4plus_audio.py          # standalone probe
```

Then in a session: `/audioprobe`. Force a backend with
`OTRV4PLUS_AUDIO_BACKEND=aaudio` or `=pulseaudio`.

## Permissions

`android.permission.RECORD_AUDIO`, held by the **Termux** app — not Termux:API.
Check *Settings → Apps → Termux → Permissions → Microphone*. If Termux has no
Microphone entry at all, its manifest does not declare it and no native API in
this process can reach the microphone.

## Is PulseAudio still required?

**For voice capture and playback: no** — conditional on `/audioprobe` showing
AAudio capture with a non-zero peak. That condition is real and I cannot
discharge it from here.

Still used elsewhere, deliberately: the `/audiotest` self-test and the
bootstrap package list.

## Not done

- OpenSL ES backend. Your device already fails it with error 12 in both
  directions; a ~600-line ctypes binding of COM-style vtables for a path proven
  broken on your hardware is effort better spent elsewhere. If AAudio works,
  it is redundant; if AAudio fails on permissions, OpenSL ES fails the same way.
- Any on-device test. Nothing here has touched Android.
