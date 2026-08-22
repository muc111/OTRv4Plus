# Opus audit

Measurement phase. **No production default was changed.**

Numbers below are libopus 1.4 via ctypes on x86_64 in a container, 1200–2000
iterations per configuration, monotonic clock, synthetic speech-shaped input.
An aarch64 handset under thermal load will be slower — plausibly 3–5× — which
is why `tools/opus_bench.py` exists and should be run there. The ratios
transfer; the absolutes do not.

## 1. Current configuration

Configured in `otrv4plus_voice.py::_build_codec`, line 2988.

| Parameter | Value | Where | Meaning | Action |
|---|---|---|---|---|
| Sample rate | 16000 Hz | `otrv4plus_audio.py:110` `SAMPLE_RATE` | wideband | keep |
| Channels | 1 | `otrv4plus_audio.py:111` `CHANNELS` | mono | keep |
| Frame duration | 60 ms | `otrv4plus_audio.py:130` `FRAME_MS` | env `OTRV4PLUS_OPUS_FRAME_MS` | keep — see §5 |
| Bitrate | 24000 | `otrv4plus_voice.py:434` `VOICE_BITRATE` | env `OTRV4PLUS_OPUS_BITRATE` | keep |
| Application | `APPLICATION_VOIP` | `otrv4plus_voice.py:3001` | speech-optimised | keep |
| Complexity | 8 | `otrv4plus_voice.py:439` | encoder effort | **candidate**, see §8 |
| FEC | `inband_fec=1` | `otrv4plus_voice.py:3011` | one-frame repair | see §7 |
| Packet loss % | 5 | `otrv4plus_voice.py:445` `VOICE_LOSS_PCT` | FEC strength | see §7 |
| DTX | `0` (explicit) | `otrv4plus_voice.py:3010` | **must stay 0** | keep |
| VBR | `0` (explicit) | `otrv4plus_voice.py:3009` | **must stay 0** | keep |
| Signal | `SIGNAL_VOICE` | `otrv4plus_voice.py:3014` | speech hint | keep |
| Bandwidth | `BANDWIDTH_WIDEBAND` | `otrv4plus_voice.py:3015` | forced 16 kHz | keep |

Nothing is left to a library default: every one of these is set explicitly,
and `constant_rate` is only claimed when both `vbr` and `dtx` were actually
accepted by the build.

Call sites: encode `otrv4plus_voice.py:3263`, decode `:3604`/`:3606`, PLC
`:3620`, silence frame `:3064`. Encoder and decoder are created once per call
at `:3001`/`:3003` — **not** per frame.

## 2–3. Encode / decode performance (60 ms, 24 kbit/s, complexity 8)

| | p50 | p95 | p99 | max | share of frame |
|---|---|---|---|---|---|
| encode | 1.333 | 1.485 | 1.665 | 1.908 ms | **2.5 %** |
| decode | 0.046 | 0.062 | 0.075 | 0.119 ms | **0.1 %** |

Against the measured one-way delay of ~700–1000 ms, encode p95 is **0.15 %
of mouth-to-ear**. Decode is a rounding error.

## 4. Verdict: NEGLIGIBLE

By the brief's own decision rule, encode at 1.5 ms p95 against a 60 ms frame
budget is comfortably below it and cannot be a material contributor to
event-loop lag at 16.7 frames/s (≈25 ms of CPU per second of audio).

**Replacing the encoder would not move the number that matters.**

## 5. Python overhead

`bytes(pcm)` at `:3263` and `bytearray(...)` at `:3604`/`:3606` copy a
1920-byte and a 1920-byte buffer per frame. Measured: **p50 and p95 both
0.000 ms**, max 0.014 ms. Below timer resolution.

Encoder/decoder objects are created once per call, not per frame. No NumPy,
no resampling in the codec path, no per-frame lock around the codec.

There is nothing to reclaim here.

## 6. Frame duration

| frame | encode p95 | frames/s | **CPU per second of audio** | payload | packets/s |
|---|---|---|---|---|---|
| 20 ms | 0.874 ms | 50.0 | **43.7 ms/s** | 60 B | 50.0 |
| 40 ms | 1.113 ms | 25.0 | **27.8 ms/s** | 120 B | 25.0 |
| 60 ms | 1.485 ms | 16.7 | **24.8 ms/s** | 180 B | 16.7 |

Per frame, longer frames cost more. **Per second of audio, longer frames cost
less** — 60 ms is the cheapest of the three, by 43 % against 20 ms.

The four latencies, kept distinct:

* **codec packetisation** — 60 ms of audio must exist before it can be
  encoded. Moving to 20 ms genuinely removes 40 ms here. Real, and small.
* **transport** — I2P, measured at 700–1000 ms one-way. Frame duration does
  not change tunnel latency. It triples the packet *rate*, and packet rate is
  what I2P charges for: every media datagram occupies one ~1 KB tunnel
  message regardless of whether it holds 20 ms or 60 ms.
* **jitter buffer** — sized from measured arrival deviation, in milliseconds,
  not frames. Shorter frames give finer granularity but do not reduce the
  deviation being buffered against.
* **playback** — device-paced, unchanged.

So 20 ms buys ≤ 40 ms of packetisation delay and costs 3× the tunnel
messages and 76 % more codec CPU. Whether that trade is positive depends
entirely on whether the path degrades under packet rate — which is exactly
what the earlier stream-transport collapse suggested and what only a real
call can settle.

## 7. Bitrate

| bitrate | encode p95 | payload/frame | slot | datagram |
|---|---|---|---|---|
| 16000 | 1.547 ms | 120 B | 152 B | 654 B |
| 24000 | 1.673 ms | 180 B | 232 B | 734 B |
| 32000 | 1.792 ms | 240 B | 304 B | 806 B |

Bitrate barely moves CPU. All three fit one tunnel message, so on this
transport the bitrate is close to free — which is why 24000 was chosen and
why there is no measurement-backed reason to change it.

## 8. Complexity — the one place a change is defensible

At 60 ms, 24 kbit/s:

| complexity | encode p95 | CPU per second of audio |
|---|---|---|
| 0 | 0.272 ms | 4.5 ms/s |
| 3 | 0.602 ms | 10.1 ms/s |
| 5 | 0.747 ms | 12.5 ms/s |
| **8 (current)** | **1.591 ms** | **26.6 ms/s** |
| 10 | 1.596 ms | 26.7 ms/s (max 12.4 ms outlier) |

8 → 5 halves codec CPU and saves ~14 ms of CPU per second of audio; on
aarch64 that could be 40–70 ms/s, which is battery rather than latency.

Complexity 10 is measurably pointless here: identical p95 to 8, with a worse
tail.

**But**: 1.6 ms → 0.75 ms p95 is 0.85 ms against a ~1000 ms budget. It is a
battery argument, not a latency one, and it costs some quality. Not
recommended without a reason to want the CPU back.

## 9. FEC

`inband_fec=1`, `packet_loss_perc=5`.

The landmark call reported `drop=0`, `authfail=0`, `replay=0`, `late` 0–2.
**Measured transport loss is effectively zero; the problem is delay.** FEC
repairs a lost frame; it does nothing whatsoever for a frame that arrives
late, and Opus in-band FEC repairs only a **one-frame** gap in any case.

The starvation windows (`26/83 expected frames`) are the interesting case,
and they are multi-frame — beyond what in-band FEC can reach.

At 5 % the cost is small and single-frame repair does apply when it happens.
No change, but raising it would be spending bitrate on a repair the telemetry
says is rarely needed.

## 10. DTX

Explicitly `0`, and it must stay `0`. DTX suppresses transmission during
silence, which makes packet timing a direct function of whether someone is
speaking — the exact property the constant-rate shaping exists to deny an
observer. This is a privacy invariant, not a tuning parameter.

Same for `vbr=0`: variable packet size leaks speech activity through length.

## 11. Event-loop interaction

Opus runs on the **capture and playback threads**, not the event loop:
encode at `:3263` is in `_capture_worker` (thread `voice-capture`), decode at
`:3604` is in `_playback_worker` (thread `voice-playback`).

It therefore cannot directly stall the shared slixmpp/media loop. The GIL
means it can still *compete* for the interpreter — 25 ms of CPU per second of
audio, ~2.5 % duty — but that is small, and the `loop lag` telemetry from
`4cfd2f3` measures the real figure rather than inferring it.

**If the loop-lag p99 comes back high, Opus is not the explanation.**

## 12. Native / Rust assessment

1. Library: **opuslib**, a ctypes wrapper over native libopus
   (`otrv4plus_xmpp.py:168` `_load_opus`).
2. Already native — libopus does the DSP.
3. Wrapper overhead: unmeasurable here (opuslib would not build in this
   container). The ctypes-direct path costs 1.5 ms p95; opuslib adds one
   Python call plus a ctypes marshal on top. `tools/opus_bench.py` measures
   both side by side when run where opuslib is installed — i.e. the phone.
4. Copies around it: 0.000 ms.
5–9. **Not justified.** Rewriting a component that costs 2.5 % of its frame
   budget, to save at most a fraction of that, while adding a Rust/NDK build
   dependency to an Android/Termux target, is effort spent where the
   measurement says there is nothing to win.

## 13. Recommended next experiment — exactly one

**Do not touch Opus.** Run one 15-minute call on `4cfd2f3` or later with no
overrides and read the `budget:` line.

The codec is 1.5 ms of a ~1000 ms path. The remaining candidates are the
event loop, the jitter buffer, and I2P itself, and the instrumentation
already in place distinguishes them. Pick the frame-duration comparison only
if that budget shows packetisation actually mattering — which, at 60 ms of a
1000 ms budget, it almost certainly will not.
