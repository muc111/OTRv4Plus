# Voice tuning over I2P

## Making a call louder

Measured on a 3-second speech-shaped signal peaking at -14 dBFS, through the
real playback chain:

| setting | output RMS | output peak | vs input |
|---|---|---|---|
| as shipped | -17.5 dBFS | -3.5 dBFS | **+7.4 dB** |
| `SPEAKER_MAKEUP_DB=12` | -24.0 dBFS | -12.9 dBFS | +0.9 dB |
| `SPEAKER_MAKEUP_DB=18` | -20.0 dBFS | -7.3 dBFS | +4.9 dB |
| `SPEAKER_MAKEUP_DB=24` | -16.7 dBFS | -2.5 dBFS | +8.2 dB |
| `SPEAKER_GAIN=2.0` | -12.8 dBFS | -1.0 dBFS | +12.1 dB |

Two things fall out of that table.

**The digital path is nearly maxed already.** The default output peaks at
-3.5 dBFS, so there is about 3.5 dB of headroom before the limiter starts
working for a living. The compressor is doing +7.4 dB unaided.

**`OTRV4PLUS_SPEAKER_MAKEUP_DB` replaces the automatic makeup rather than
adding to it.** Unset, the compressor derives 22.5 dB from its threshold and
ratio. Setting 12 therefore makes the call *quieter*. Only values above ~22
increase loudness, and above 24 the limiter takes back what you added.

So if a call is still too quiet, the cause is usually **which Android stream
it is on**, not the DSP:

1. **Press volume-up during an active call.** Playback declares
   `VOICE_COMMUNICATION`, which puts it on the *call* volume stream — a
   different slider from media, and often left low. This costs nothing and
   fixes it more often than any setting here.
2. **`OTRV4PLUS_AUDIO_USAGE=media`** routes to the media stream instead, which
   is louder on most handsets and avoids an earpiece route. **It costs the
   platform echo canceller**, so expect echo if both ends are on speaker in
   one room. On a device that routes voice-communication to the earpiece this
   is genuinely the better trade.
3. Only then reach for `OTRV4PLUS_SPEAKER_GAIN` (try 1.5 before 2.0). It is
   blunt: it drives the limiter, which then attenuates the whole frame
   including the quiet parts the compressor just lifted.

Every one of these is **local**. None changes the wire, and the two phones need
not agree.


> **Playback burst alignment (v10.12.0).** Before touching anything below, know
> that a device-side mismatch cost more audio than every setting here combined.
> A handset reported `framesPerBurst=1920` at 16 kHz — a 120 ms transfer unit —
> while the pipeline wrote 60 ms packets. Every write blocked for a p50 of
> 95–100 ms, playout ran at 9.3 fps against a 16.7 fps stream, and the jitter
> buffer shed **32% of all received audio** while the network lost 2.7%.
> Writes are now accumulated to a whole burst. Check `[voice] playout:` in a
> `--voice-debug` log and the `write` figure in the stages line before
> concluding anything is a network problem.
>
> | Variable | Default | Effect |
> |---|---|---|
> | `OTRV4PLUS_AAUDIO_ALIGN_WRITES` | `1` | `0` writes packet-at-a-time again, which is the only way to reproduce the stall |
> | `OTRV4PLUS_AAUDIO_OUTPUT_BURSTS` | `2` | playback buffer size in device bursts; two is the floor for a blocking writer |
> | `OTRV4PLUS_AAUDIO_OUTPUT_CAPACITY` | `8` | requested capacity in our frames; a ceiling, not a latency |
>
> These are **local** settings. They change nothing on the wire and the two
> phones need not agree on them.


Every parameter here, its safe range, and what it trades against what.

Two rules before anything else:

**Wire-format settings must match on both phones.** They set the packet
length, and peers that disagree reject each other's frames — the call
establishes, reports healthy, and carries no audio.

**Local settings may differ per device.** Playout, gain and buffering are
decisions each phone makes for itself. A phone on a worse path should
buy itself more cushion without dragging the other one down.

---

## Wire format — BOTH PHONES MUST MATCH

| Variable | Default | Range | Effect |
|---|---|---|---|
| `OTRV4PLUS_OPUS_FRAME_MS` | `60` | 10, 20, 40, 60 | Audio per packet. Sets the packet **rate**, which is what I2P charges for. |
| `OTRV4PLUS_OPUS_BITRATE` | `24000` | 6000–64000 | Codec bitrate. Sets the slot, and so the packet length. |

The slot, packet length and datagram size are **derived** from these two.
A combination whose datagram would exceed one I2P tunnel message is
refused at import rather than silently fragmented.

Measured sizes:

| frame | bitrate | packet | datagram | pkt/s | wire | one tunnel msg |
|---|---|---|---|---|---|---|
| 60 ms | 24 kbit/s | 279 B | 734 B | 16.7 | 37.2 kbit/s | yes |
| 40 ms | 24 kbit/s | 199 B | 654 B | 25.0 | 39.8 kbit/s | yes |
| 20 ms | 24 kbit/s | 127 B | 582 B | 50.0 | 50.8 kbit/s | yes |

The datagram column is what the router actually moves: the media packet
plus the 455-byte repliable-datagram header (destination + signature).
All three fit one ~960-byte tunnel message, so **packet rate — not
packet size — is the cost on I2P.** 20 ms frames cost three times the
tunnel messages of 60 ms for the same conversation.

That is the argument for long frames. The argument against is that a
60 ms frame is 60 ms of accumulation delay before the packet even
leaves, and one lost packet is 60 ms of audio gone. Which wins on your
path is empirical — hence the benchmark.

---

## Codec — local, but keep them equal for a fair comparison

| Variable | Default | Range | Effect |
|---|---|---|---|
| `OTRV4PLUS_OPUS_COMPLEXITY` | `8` | 0–10 | Encoder effort. Lower saves CPU on a slow phone. |
| `OTRV4PLUS_OPUS_FEC_PCT` | `5` | 0–50 | In-band FEC. Repairs a **one-frame gap only**; longer gaps fall through to concealment regardless. |

FEC above about 10 spends bitrate on a repair that rarely applies. It is
worth raising only if the logs show single-frame gaps dominating.

---

## Jitter buffer — local

This is where conversational delay is decided.

| Variable | Default | Range | Effect |
|---|---|---|---|
| `OTRV4PLUS_JITTER_MIN_MS` | `180` | 60–1000 | Floor, and what playout waits for before starting. |
| `OTRV4PLUS_JITTER_TARGET_MS` | `480` | 120–2000 | Ceiling on the adaptive target. |
| `OTRV4PLUS_JITTER_MARGIN_MS` | `180` | 60–1000 | Hysteresis above target before shedding. |
| `OTRV4PLUS_JITTER_MAX_MS` | `1000` | 240–4000 | Hard cap. Past this a burst is discarded, not queued. |
| `OTRV4PLUS_JITTER_DRAIN_MS` | `400` | 100–2000 | How fast the buffer returns to target after a burst. |

**Steady-state delay is `target + margin`.** Arrivals and playout run at
the same rate, so nothing else pulls the buffer down. With the target at
its ceiling that is 480 + 180 = 660 ms; at the floor, 360 ms.

Read `jit=` in the debug output first. It is the measured arrival
deviation, and the target is derived from it. If `jit=` says 400 ms, the
path genuinely needs a deep buffer and lowering the ceiling will buy
latency by spending audio.

Lower `OTRV4PLUS_JITTER_TARGET_MS` for less delay and more dropouts.
Raise it for the reverse. There is no setting that gives both.

---

## Levels — local, and the two phones will likely differ

| Variable | Default | Range | Effect |
|---|---|---|---|
| `OTRV4PLUS_MIC_GAIN` | `1.0` | 0.1–16 | Fixed capture gain, applied under the automatic stage. |
| `OTRV4PLUS_MIC_AGC` | `on` | on/off | Automatic capture gain. |
| `OTRV4PLUS_SPEAKER_GAIN` | `1.0` | 0.1–16 | Fixed playback gain. The compressor carries loudness; raising this mostly feeds the limiter. |
| `OTRV4PLUS_SPEAKER_COMPRESSOR` | `on` | on/off | Playback compression. |
| `OTRV4PLUS_SPEAKER_MAKEUP_DB` | derived | 0–30 | Makeup gain. Derived from the curve when unset. |
| `OTRV4PLUS_MIC_COMPRESSOR` | `off` | on/off | Capture compression. Compressing at both ends sounds over-processed. |
| `OTRV4PLUS_AUDIO_USAGE` | `voice` | voice/media | See below. |

Nothing in this section can clip the output — the limiter is enforced,
not advisory.

**`OTRV4PLUS_AUDIO_USAGE=media`** is the one to reach for when levels
read healthy and the call is still faint. Declaring
`VOICE_COMMUNICATION` makes playback the echo canceller's reference and
puts it on the call volume stream, but some phones route that to the
**earpiece** rather than the speaker. Switching to `media` routes to the
speaker at the cost of the platform AEC — which then risks the mic being
gated when the speaker is active. Per-device call.

---

## Transport — local

| Variable | Default | Range | Effect |
|---|---|---|---|
| `OTRV4PLUS_VOICE_TRANSPORT` | `datagram` | datagram/stream | `stream` restores the old reliable transport. Keep datagrams unless the router has SAM UDP disabled. |
| `OTRV4PLUS_SAM_UDP_PORT` | `7655` | 1–65535 | i2pd's SAM UDP port. |

Do not set `stream` to chase reliability. It is reliable, ordered and
retransmitting, and on this path that turns congestion into unbounded
delay rather than loss — measured at 24 s one-way with zero packet loss.

---

## Benchmarking

Both phones, same wire-format settings, at least five minutes each —
ten to fifteen preferred. I2P tunnel behaviour over a short call is not
representative.

```sh
OTRV4PLUS_OPUS_FRAME_MS=60 python3 otrv4plus_xmpp.py \
    --jid you@server --server <b32>.b32.i2p --peer them@server \
    --insecure-tls --voice-debug 2>&1 | tee bench-A-60ms.log

OTRV4PLUS_OPUS_FRAME_MS=40 ... 2>&1 | tee bench-B-40ms.log
OTRV4PLUS_OPUS_FRAME_MS=20 ... 2>&1 | tee bench-C-20ms.log
```

Then:

```sh
python3 tools/voice_bench.py bench-A-60ms.log        # full report
python3 tools/voice_bench.py bench-*.log --compare   # one row per call
```

Change **one** variable at a time. I2P queueing is not linear and a
five-variable change tells you nothing about which variable did it.

Lower `buf p50` at comparable `late` and `underrun` is a genuine
improvement. Lower `buf p50` bought with rising underruns is not — that
is the same latency moved into dropouts.
