# Media path audit

Phase 1 deliverable. Written before any change in this pass, from reading
the code rather than from the telemetry.

## Architecture map

```
SENDER                                       THREAD
  AAudio capture (read_frame, blocking)      voice-capture
  └─ device paces the loop; 200 ms timeout
  PCM 960 samples / 1920 B @ 60 ms
  └─ Compressor.process (optional)           voice-capture
  └─ GainStage.process (+ limiter)           voice-capture
  └─ opus_enc.encode                         voice-capture
  └─ pad_opus  → fixed VOICE_OPUS_SLOT       voice-capture
  │    stamps latency.call_ms() HERE  ◄── one-way clock starts
  └─ cipher.seal (AES-256-GCM, epoch key)    voice-capture
  └─ loop.call_soon_threadsafe(_write_packet, pkt, monotonic())
       ▼  ── THREAD BOUNDARY ──
  _write_packet                              EVENT LOOP
  └─ staleness deadline (250 ms) → drop
  └─ transport.sendto → SAM UDP :7655
       ▼
I2P  (tunnels, 3 hops each way)

RECEIVER
  _MediaDatagramProtocol.datagram_received   EVENT LOOP
  └─ split_datagram_receive (source filter)
  └─ _drain_buffer
       └─ parse_media_header
       └─ open_packet → AEAD verify + decrypt + replay window
       └─ PING → emit PONG        (before jitter buffer)
       └─ PONG → handle_pong      (before jitter buffer)
       └─ unpad_frame → observe_frame  ◄── one-way clock stops
       └─ jitter.push (heap, ordered on (epoch,counter))
       ▼  ── THREAD BOUNDARY ──
  jitter.pop                                 voice-playback
  └─ prefill / target / shed / gap accounting
  └─ opus_dec.decode (+ FEC on gap==1, PLC otherwise)
  └─ Compressor.process → GainStage.process
  └─ AAudio write_frame (blocking, 200 ms timeout)
```

## What one-way actually measures

The send stamp goes on in `pad_opus`, immediately after Opus encode. It is
read in `_drain_buffer` immediately after AEAD decrypt, **before**
`jitter.push`.

So the reported `oneway`:

* **includes** seal, the hop to the event loop, any wait in
  `call_soon_threadsafe`, `sendto`, I2P, receive, and AEAD verify
* **excludes** capture device latency, Opus encode, the jitter buffer,
  Opus decode, and playout

RTT is the same — probes are answered before `jitter.push`.

**This matters for reading the telemetry**: `oneway` and `buf` do not
overlap. Mouth-to-ear is roughly `oneway + buf + device`, and a
700–1000 ms `oneway` is *not* the jitter buffer. But it is not purely
network either — it contains our send-side queueing, which is exactly
what Phase 2 has to separate.

## Every queue on the path

| # | Queue | Bound | Notes |
|---|---|---|---|
| 1 | AAudio capture ring | device | `read_frame` blocks; device is the clock |
| 2 | `call_soon_threadsafe` callbacks | **unbounded** | bounded in TIME by the 250 ms send deadline |
| 3 | asyncio transport write buffer | 8 packets | `_MAX_WRITE_BACKLOG` |
| 4 | kernel `SO_SNDBUF` | pinned ~4.6 KB | autotuning disabled |
| 5 | i2pd SAM/stream buffers | i2pd's | not ours; backpressures the socket |
| 6 | jitter buffer | 16 frames / 960 ms | hard cap; sheds proportionally |
| 7 | AAudio playback ring | device | `write_frame` blocks |

## Blocking points

| Location | Blocks | Assessment |
|---|---|---|
| `capture.read_frame(timeout_ms=200)` | voice-capture | correct — the device is the pacing clock |
| `playback.write_frame(timeout_ms=200)` | voice-playback | correct |
| `jitter.pop()` returns None → `sleep(FRAME_MS/2000)` | voice-playback | **30 ms poll**; adds up to 30 ms at prime/underrun |
| `run_in_executor` for SAM connect/accept | event loop | setup only, not in the call |
| `await wait_for(rekey_waiter)` | event loop | yields; does not block media |

## The finding that matters most

`otrv4plus_xmpp.py:902` passes `asyncio.get_event_loop()` to the voice
manager. **slixmpp and the media path share one event loop and therefore
one thread.** That loop carries:

* media `sendto` for every outbound frame
* AEAD verify + decrypt for every inbound frame
* XMPP TLS, XML parsing, OTR message handling
* **ML-DSA-87 signature verification** on inbound OTR messages
* rekey key generation and encapsulation

Python's GIL means none of this overlaps. Any XMPP work — an OTR message
arriving, a rekey, a reconnect attempt — delays media packet processing
on both directions. That would present exactly as arrival jitter, and it
is indistinguishable from network jitter in the current telemetry.

Whether it is actually significant is an empirical question, which is
why the next phase measures event-loop lag directly rather than
reasoning about it.

## Rekey resilience (Phase 11/12)

Rekey signalling (`REKEY` / `REKEYCOMMIT` / `REKEYACK`) travels over
XMPP, every `VOICE_REKEY_SECONDS` (120 s). A rekey that times out is
already handled correctly:

> A failed rekey must never drop a working call. The committed epoch
> stays in force and the next attempt runs on schedule.

So losing XMPP mid-call does **not** by itself end the media session —
the call keeps running on the committed epoch. That matches the landmark
test, where XMPP dropped and audio continued. No change needed; the
property is verified, not assumed.
