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

### Rekey liveness — the other half of the property

Surviving a failed rekey is not the same as recovering from one. A
69-minute live call (`call_id=825157dc78cd7c98`, 17 XMPP reconnections)
rekeyed 12 times, lost one exchange at t≈1781 s, and then failed **all 15
remaining attempts**. Media was healthy throughout — rx/tx 92–98 %, median
one-way 494–688 ms — so nothing in the call looked wrong. What was wrong is
that the last 40 minutes ran on a single epoch with no forward-secrecy
refresh.

Two distinct wedges, one on each side, both permanent once entered:

* **Responder, lost `REKEYACK`.** The initiator gives up after
  `VOICE_REKEY_TIMEOUT` (45 s), aborts its pending material and retries the
  same epoch number. The responder had **no expiry at all**: its `pending`
  slot stayed set forever, and `_on_rekey`'s pending guard rejected every
  retry. This is the failure in the log — all 15 retries named epoch 13,
  which is only possible if the initiator never committed it.
* **Initiator, lost `REKEYCOMMIT`.** The initiator commits the moment the
  peer's confirmation verifies, and only then sends `REKEYCOMMIT`. If that
  one message is lost the peer stays an epoch behind, so every later `REKEY`
  names an epoch it considers two ahead and the epoch guard rejects it.

Both are repaired symmetrically, with no wire-format, key-schedule or
crypto change:

* The responder gets the same expiry the initiator already has. A pending
  epoch younger than `VOICE_REKEY_TIMEOUT` is still protected against
  duplicates and replays; an older one is aborted (wiping its root and
  retiring its receive cipher) and the retry is answered. The committed
  epoch never moves on an unconfirmed rekey, so a superseded exchange costs
  nothing but itself.
* The initiator repeats its last `REKEYCOMMIT` immediately before each new
  `REKEY`. The tag is a public MAC output that already travelled the wire,
  it can promote only the exact epoch it names, and a peer that already
  committed that epoch has nothing pending and ignores it. Cost: one small
  signal per 120 s.

The net effect is that a control-plane blip costs **one** rekey rather than
every rekey for the rest of the call. Covered by `tests/test_rekey_recovery.py`.


## Inbound media liveness

### The failure

A 33-minute live call lost inbound media at t=1418 s and never recovered. The
call stayed ACTIVE and kept transmitting for the remaining 9.5 minutes.

```
1412s  tx=86  rx=85
1417s  tx=85  rx=34     <- cliff
1422s  tx=84  rx=0
...    9.5 minutes
1990s  tx=84  rx=0      <- log ends
```

Every rejection counter read zero throughout: `drop=0 foreign=0 authfail=0
replay=0 late=0 stale=0`. Nothing was being rejected, because nothing was
arriving.

### What the evidence eliminated

* **Rekey and epoch handling.** Rekeys 11-14 committed at 1500 s, 1626 s,
  1758 s and 1880 s — all *after* the cliff. A commit needs a REKEYACK from
  the peer, so the peer's client was alive and answering throughout, the
  control plane was healthy, and the epoch machinery was working.
* **Anything audio-specific.** The RTT window froze at `n=264` and stayed
  there for 115 consecutive samples. Probe replies are inbound media
  datagrams, so PONGs died in the same instant as the audio. Nothing above
  the transport — Opus, jitter buffer, playout — can explain a failure common
  to both.
* **Event-loop starvation.** Loop lag held at p50 1 ms, max 12 ms.
* **The local I2P router.** The XMPP path built a brand-new SAM session at
  1478 s, during the dead period. The router was up and accepting sessions.
* **The receive task dying.** There is no receive task in datagram mode; it
  is callback-driven, and `sent` proves `_running` was true.

### Root cause

Media rode SAM `STYLE=STREAM` until `892ef7a`, which moved it to
`STYLE=DATAGRAM` and made the reader task conditional:

```diff
-        self._reader_task = asyncio.ensure_future(self._network_reader())
+        if self._writer is not None:
+            self._reader_task = asyncio.ensure_future(self._network_reader())
```

`_network_reader` was the only caller of `_signal_stream_lost` for the
receive path, and it got its liveness signal for free from stream EOF. A
datagram has no EOF. **Datagram calls therefore had no inbound liveness
detection at all** — not a weak one, none. The transmit side cannot supply it
either: a datagram handed to the local SAM UDP bridge is accepted whether or
not the session behind it still exists, so `sent` climbs happily over a dead
path.

The trigger was the network transition. Reconnect 8 took 70.3 s against
10-30 s for the other nine — the only outlier, and the WiFi-to-mobile switch.
XMPP recovered because it has a reconnect path. Media did not, because
nothing was watching and nothing could fail.

### What changed

A watchdog on the session, running in **both** transport modes, checking at
the media probe cadence:

| Constant | Value | Basis |
|---|---|---|
| `VOICE_RX_CHECK_S` | 5 s | the media probe interval |
| `VOICE_RX_WARN_S` | 15 s | three consecutive probe intervals of silence |
| `VOICE_RX_DEAD_S` | 45 s | `VOICE_REKEY_TIMEOUT`, the existing "not coming back" horizon |

45 s is ~750 consecutive frames at 60 ms. The worst measured stall on the old
stream transport was 24 s and would not trip it. Loss is declared through the
existing `_signal_stream_lost` path, which already ends the call, notifies the
peer, and is already bound to the call_id.

### The counter that was missing

`rx=0` with every rejection counter at 0 was **ambiguous**: it could mean
nothing arrived, or that things arrived and were discarded on a path that
counts nothing — and `_on_datagram` had two such paths. `dgram_in` now counts
every arrival before every filter, and appears in the telemetry as `dg=`:

* `rx=0 dg=0` — the path is dead.
* `rx=0 dg>0` — the path is fine and the fault is above it.

Two clocks are kept: `_rx_last_datagram` (anything at the socket) and
`_rx_last_frame` (anything that authenticated, including PINGs and PONGs).
The watchdog judges on the second, so a flood of junk cannot keep a dead call
looking alive; the difference between them is what names the failing stage.

### A second defect, found while testing

`AESGCM.decrypt` raises `InvalidTag`, which is not a `FrameError`, so every
AEAD authentication failure was landing in the generic handler and being
counted as a plain `dropped`. `authfail` only ever counted the structural
rejections above the cipher — wrong epoch, bad length, sub-epoch too far. The
one event the counter exists to report was invisible in it. The frame is
rejected exactly as before; only the accounting changed.

### Limitation

The watchdog **detects and ends**; it does not re-establish the media path.
Recovery would mean building a new SAM datagram session, which yields a new
transient destination, which the peer must be told about — a new signalling
verb and a wire change. That is deliberately not in this change.
