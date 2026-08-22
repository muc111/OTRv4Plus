# Voice tuning over I2P

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
