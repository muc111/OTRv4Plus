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

## Media endpoint recovery

The watchdog above detects a dead receive path. Ending the call was the
correct fail-safe but the wrong outcome: the path can usually be rebuilt.

### Why a local rebuild alone is useless

A SAM datagram session is bound to a transient destination. Replacing the
session yields a **new destination the peer has never heard of**, so the peer
keeps sending to an endpoint that no longer receives. Recovery is therefore
not a local operation: it needs the peer to be told where we moved.

### Why the announcement needs its own authentication

The announcement rides the XMPP control channel, so arriving over it proves
nothing — the same channel carries whatever the server, or a compromised
account, puts there. Accepting an endpoint change on that basis would let
anyone with write access to the signalling path redirect a call's media.

The tag is derived from the **committed epoch root**, which exists only
because the hybrid X448 + ML-KEM agreement succeeded. Producing one needs the
media secret, not access to signalling. It is the same HKDF hierarchy and the
same construction as `derive_confirmations`, deliberately: a second trust
model for endpoints would be a second thing to get wrong.

    MEDIAPATH: call_id | epoch | seq | destination | tag

    tag = HKDF(root_epoch, call_id,
               "OTRv4+Voice/Endpoint/v1" || call_id || epoch || seq
                                         || destination || direction)

Everything that decides whether to act is inside the tag:

| Field | Stops |
|---|---|
| `call_id` | a tag crossing calls, or resurrecting an ended one |
| `epoch` | an announcement outliving a rekey |
| `seq` | replay, reordering, and endpoint rollback |
| `destination` | substituting a different endpoint under a valid tag |
| direction | reflecting our own announcement back at us |

`seq` is strictly increasing per call and checked **before** the tag, so a
replay costs no cryptography. Nothing moves until the tag verifies.

### Why this is an announcement and not a rekey

No media key derives from the destination — `build_transcript` covers the
call_id, the OTR binding, both fingerprints, the X448 and ML-KEM material and
the epoch, and nothing else. Moving the address invalidates no key. So the
epoch, the replay windows, the ratchet and the call identity all survive
recovery untouched, and a packet already accepted stays rejected afterwards.
Tying an address change to a rekey would spend a hybrid exchange to solve a
routing problem, and would make the replay state harder to reason about, not
easier.

### The state machine

    ACTIVE, inbound idle >= VOICE_RX_WARN_S (15 s)
        |
        +-- datagrams arriving but not authenticating
        |       -> NOT a transport fault; no rebuild. The path works and
        |          discarding it would fix nothing.
        |
        +-- stream transport, or attempts exhausted
        |       -> no recovery available; fall through to the dead check
        |
        +-- nothing arriving at all, attempts remain
                -> RECOVERING (deadline suspended)
                   close the old session, build a new one,
                   bounded by VOICE_RECOVER_TIMEOUT_S (150 s)
                        |
                        +-- rebuild failed or timed out
                        |       -> deadline handed back, watchdog resumes
                        |
                        +-- rebuilt
                                -> announce MEDIAPATH, deadline handed back
                                   |
                                   +-- inbound resumes -> ACTIVE,
                                   |   attempt budget reset
                                   |
                                   +-- still silent at VOICE_RX_DEAD_S
                                       and attempts exhausted
                                           -> _signal_stream_lost -> teardown

Recovery can **extend** the deadline, never remove it. The dead check is
suspended only while a rebuild is genuinely in flight, the rebuild is wrapped
in `wait_for`, and attempts are capped at `VOICE_RECOVER_ATTEMPTS` (2).

The worst case is **375 s** (6.2 minutes) for a path that was working and
stopped — not the 15 + 2 × 150 a naive sum gives, because each rebuild resets
the liveness clock so the final teardown needs `VOICE_RX_DEAD_S` of silence
measured from the *last* reset rather than from the original failure.

### A cold path is not a broken path

The thresholds above assume a path that has already carried audio. One that
has never carried any is a different question, and treating it the same way
cost a live call ~70 s: media first flowed at t=96 s while the watchdog fired
at 26.6 s and rebuilt an endpoint that was merely still coming up. The tunnels
are built before `start_audio`, but the peer still has to learn our
destination and the first datagram still has to cross three hops each way.

So until one frame has authenticated, `VOICE_RX_START_GRACE_S` (120 s)
replaces the warning threshold and the dead horizon moves with it. 120 s is
the budget call setup already allows the media path — the key-confirmation
wait uses it, and the call banner tells the user 30–120 s is normal. The
moment a single frame authenticates the path is proven and the steady-state
thresholds apply for the rest of the call.

That makes the cold worst case **705 s** (11.8 minutes) before a call that
never carries audio is torn down, since a freshly announced endpoint has not
carried any either and gets the same grace. Both numbers are computed from
the constants by `TestTheWorstCaseIsBounded`, which fails if this document
and the code disagree. `OTRV4PLUS_RECOVER_ATTEMPTS=0` disables recovery and
restores the plain fail-safe for anyone who would rather the call drop than
wait.

Success is confirmed by **inbound media resuming**, not by an acknowledgement.
That is deliberate: an ACK would prove the peer received a message, whereas
resumed media proves the path actually works, which is the thing being fixed.

### Lifecycle binding

A rebuild takes as long as an I2P tunnel build, so the call it started for can
end, be torn down, or be replaced while the router works. Every step that
outlives an `await` re-resolves the session and re-checks the `call_id`, so a
late rebuild cannot announce for, or resurrect, the call that replaced it. The
recovery task is registered with the session's teardown, is cancellable, and
`_recovering` is cleared on every exit path — including failure and timeout,
because a suspended deadline that is never handed back would leave the call
dead and silent forever, which is the bug this all exists to remove.

### Diagnostics

`dg=` in the 5-second telemetry is the raw arrival count. `rx=0 dg=0` means
the path is dead and a rebuild may help; `rx=0 dg>0` means the transport is
fine and a rebuild would discard a working path. The refusal reason for a
rejected announcement is logged under `--voice-debug` (`MEDIAPATH seq=N
rejected: ...`), so a refusal is diagnosable rather than silent.

### Two defects the adversarial pass found in the first implementation

**A rebuild was mistaken for recovery.** `rebuild_media_endpoint` re-stamps the
liveness clock so the new path is not judged dead the instant it opens. The
watchdog read that small idle as success: it announced "inbound audio
recovered" over a path that had delivered nothing, and handed the attempt
budget back. The second half is the serious one — with the budget reset on
every rebuild the loop never terminated, so a call could sit rebuilding
indefinitely instead of failing safe, which is precisely the unbounded
recovery the design was supposed to exclude.

Recovery is now confirmed by a frame that authenticated *after* the rebuild
(`_rx_authenticated > _rx_mark`), never by the clock. Probe replies count:
they are inbound media too, and in the original incident they died with the
audio.

**A cancelled rebuild leaked its SAM session.** `SESSION CREATE` runs in an
executor. `asyncio.wait_for` cancels the coroutine that awaits it, but not the
thread — which finishes, returns a live control socket to a caller that no
longer exists, and leaves the router-side session open for the life of the
process. Recovery is the first place in this codebase where `create_session`
is genuinely cancelled, so the exposure arrived with it. The socket is now
published to the session the moment it exists (`_sam_pending`) so teardown can
always reclaim it, and recovery passes its own budget as the blocking-read
timeout so the thread cannot outlive the deadline its caller is held to
(`SAM_SESSION_TIMEOUT` is 300 s against a 150 s budget).

### Recovery depends on the control plane — and now says so

Replacing our endpoint without telling the peer is **worse than doing
nothing**: the peer keeps addressing an endpoint we have just destroyed, and
the old one can no longer come back when the router rebuilds its tunnels.

A WiFi-to-mobile transition takes both planes down together. The media
watchdog fires at 15 s; XMPP reconnected in 10–70 s on the logged call. So
recovery running with no signalling path is the common case, not a corner
one — and the first implementation did exactly that: it rebuilt, the
`MEDIAPATH` announcement was silently dropped by `_signal`, and a recovery
attempt was consumed. Two attempts later the call was torn down, having
stranded its own endpoint twice.

Two changes close it:

* `_signal` now returns whether the frame reached the transport. Most callers
  ignore it — a lost `REKEY` already fails safe on the committed epoch — but
  recovery must not, because it changes our destination *before* announcing.
* `_handle_media_stalled` refuses to start a rebuild unless XMPP is connected
  **and** an OTR session exists (the announcement is authenticated inside OTR
  and is never sent in the clear). A refusal refunds the attempt: the budget
  bounds rebuilds, not how often the watchdog asks.

If XMPP dies *during* the rebuild — which takes as long as a tunnel build —
the endpoint is already gone. Rebuilding again would strand a second one, so
the announcement alone is retried (`_endpoint_announce_pending`).

Deferral does **not** suspend the fail-safe. If signalling never returns the
call still ends at the dead horizon, which is correct: without a control
plane there is no rekey and no recovery, so the call is finished regardless.

### The two planes stay independent

Neither path is ever used as evidence for the other. They are separate SAM
sessions over separate I2P tunnels and they fail independently — which is why
both the media watchdog and the XMPP keepalive exist.

| | Judged on |
|---|---|
| XMPP keepalive | inbound **XMPP stanzas** only (a slixmpp `in` filter) |
| Media watchdog | authenticated **inbound media frames** only |

`_control_plane_ready` is the single exception, and it gates only the
*action* that genuinely needs signalling — never the detection of a dead
media path. A test enumerates its callers and fails if it leaks anywhere
else. Measured during a live call, event-loop lag was p50 2 ms / max 36 ms,
so media does not starve XMPP callbacks either.

### Limitations

* Only the datagram transport has an endpoint that can be replaced. The
  stream transport falls straight through to the fail-safe.
* Recovery cannot help if the peer's inbound is the broken direction — but it
  does not need to: that side runs the same watchdog and rebuilds its own.
* The thresholds are reasoned from existing constants and exercised by
  deterministic tests. They have not yet been observed against a real network
  transition.
