# I2P voice latency — analysis and transport changes

Pre-Android transport pass. What the voice path costs before I2P is involved,
what was changed, what the change is worth, and what could not be established
on this host.

Evidence labels are used throughout and mean exactly what they say:

| Label | Meaning |
|---|---|
| **OBSERVED** | Seen in a run or a reading of the source. Not generalised. |
| **MEASURED** | A number produced by `tools/transport_bench.py` on this host, reproducible by re-running it. |
| **INFERRED** | Follows from a mechanism that was read, but no measurement supports it here. |
| **ASSUMED** | Neither measured nor derived. Stated so it can be checked later. |

---

## 0. The honest limit of this work

**This host has no I2P router, no XMPP server and no peer.** Nothing here is a
measurement of I2P latency, and no claim below says otherwise.

What *was* measured is the delay this application adds before a byte reaches
the SAM bridge, plus the behaviour of the loopback socket that carries it.
That was previously unmeasured, it is not small, and it is the only part of
the path this codebase can change. The router's contribution — tunnel build
time, peer selection, congestion — is not reachable from here and is not
claimed.

The multi-hour A/B soak the brief asks for (Phase 11) **has not been run**;
see §8.

---

## 1. The path

```
  microphone
     │  capture thread, 40 ms cadence
     ▼
  Opus encode ── pad to 160 B ── AES-256-GCM seal (MKmedia, epoch/counter)
     │
     │  loop.call_soon_threadsafe                     ← thread hop
     ▼
  _write_packet ── write-buffer bound ── asyncio transport.write
     │
     ▼
  SAM stream socket (loopback TCP → 127.0.0.1:7656)
     │
     ▼
  i2pd  ── 3-hop outbound tunnel ── … ── 3-hop inbound tunnel ── peer
```

Signalling takes a different road:

```
  INVITE / REKEY / END
     │  OTR-encrypted, inside an ordinary <message><body>
     ▼
  slixmpp ── local bridge socket ── pump_to_i2p ── SAM stream ── XMPP server
```

**OBSERVED:** media and signalling use *separate* SAM streams. Voice frames
therefore cannot queue behind a chat message — the head-of-line risk the brief
asks about does not exist for audio. It does exist for signalling, and INVITE
and REKEY both have deadlines. That is where §3.1 applies.

Points at which this process can add delay, in path order:

| # | Point | Finding |
|---|---|---|
| 1 | Capture cadence | Paced by the device read, not by a sleep. No issue found. |
| 2 | Opus + seal | On the capture thread, off the loop. No issue found. |
| 3 | Thread hop to the loop | One `call_soon_threadsafe` per frame. Now measured (`send_queue`). |
| 4 | Send-queue bound | **Defect T5** — 2 s of stale audio admitted. §3.3 |
| 5 | Loopback socket | **Defect T2** — Nagle, 41 ms on burst drain. §3.2 |
| 6 | SAM session options | **Defect T3** — none set; router-dependent. §3.4 |
| 7 | XMPP bridge pacing | **Defect T1** — up to 120 ms fixed sleep. §3.1 |
| 8 | Reader loop | `read(8192)`, drain-before-bound. No issue found. |
| 9 | Jitter buffer | Adaptive, RFC 3550 smoothing, drift clawback. No issue found. |
| 10 | Instrumentation | **Defect T4** — cannot report a tail at all. §2 |

---

## 2. T4 — the tail was never measurable

**OBSERVED.** `LatencyTracker` keeps a 10-sample rolling window and reports the
**median**. That is the right choice for a status line: one tunnel stall must
not drag the displayed number for the rest of a four-hour call. But it means
the implementation has never been able to report a p95, a p99 or a maximum.

The baseline's "occasional significant latency spikes" is therefore an
impression from watching a median move — not a measurement. A median of 1.3 s
that occasionally reaches 8 s and one that never exceeds 2 s are different
products, and the old instrumentation could not tell them apart.

**Fixed** in `otrv4plus_telemetry.py`: a fixed-bucket histogram per series.

* Bounded memory — 164 buckets, ~2 KB, independent of call length. A four-hour
  call is ~360,000 frames; keeping samples would be megabytes and unbounded.
* min and max are **exact**, not bucketed, because "maximum spike" is one of
  the numbers being optimised.
* **MEASURED** percentile error against an exact sort over 200,000 samples
  shaped like the observed path (1.3 s body, 2 % heavy tail):

  | q | exact | histogram | error |
  |---|---|---|---|
  | p50 | 1303.0 ms | 1303.1 ms | +0.06 ms |
  | p95 | 1542.7 ms | 1543.5 ms | +0.81 ms |
  | p99 | 5401.3 ms | 5396.9 ms | −4.36 ms |
  | max | 8998.5 ms | 8998.5 ms | 0.00 ms |

Nine series are recorded: `rtt`, `oneway`, `interarrival`, `jitter`,
`send_queue`, `socket_write`, `recv_to_decode`, `jitter_depth`,
`xmpp_stanza`. `/status` now shows `rtt p50/p95/p99/max` and `jit p95/max`
alongside the existing median.

**Not print-scraping.** The previous diagnostics worked by parsing lines the
application printed. Nothing in the new layer touches stdout; a caller that
wants a file passes a path and gets JSONL, 0600, off by default.

---

## 3. The four defects and what was done

### 3.1 T1 — fixed sleep in the XMPP↔SAM bridge

**OBSERVED.** `start_i2p_sam_forwarder` chunked writes at 1024 bytes and slept
20 ms after **every** chunk, including the last:

```python
for i in range(0, len(data), SAM_CHUNK):
    dst.write(data[i:i+SAM_CHUNK]); await dst.drain()
    await asyncio.sleep(SAM_CHUNK_DELAY)     # 20 ms, unconditionally
```

The chunking exists for a real reason — I2P has been observed to drop a stream
when a large message is written as one burst, at roughly 8 KB. The *sleep* is
what costs. `send_otr_fragmented` emits 6000-byte fragments, and a voice
INVITE or REKEY reaches that size once an ML-KEM-1024 encapsulation is
base64'd into it, so those paid 6 × 20 ms.

Worse, this is a **single pump task over one stream**. The sleep delayed every
stanza queued behind it: sending a chat message could push a voice rekey
120 ms later, and a rekey has a deadline.

**Changed** to a token bucket (`otrv4plus_i2p.SamWritePacer`). Every protection
that mattered is kept:

* no single write exceeds `SAM_CHUNK` (1024 B), and `drain()` still applies
  backpressure between writes;
* no unpaced burst exceeds `SAM_BURST_BYTES` (4096 B) — half the observed
  cliff;
* the sustained ceiling is unchanged at 1024 B / 20 ms = 51200 B/s.

What it removes is the fixed cost paid by traffic that was never near the
cliff.

**CORRECTED 2026-08-21 — the first version of this change broke SMP on a real
I2P path.** The burst allowance was set to 4096 bytes on the reasoning that
half of an "~8 KB cliff" mentioned in a comment must be safe. That was a
misreading. The old code's actual, empirically-derived guarantee was **never
more than 1024 bytes toward SAM without a ~20 ms gap** — the cliff figure
describes a single large write, not how much may be sent back to back. Nothing
on the build host could test the difference, and TCP_NODELAY (§3.2, same pass)
made it worse by removing the coalescing that had been spreading those writes
out. Reported symptom: SMP, whose messages are large enough to fragment, failed
with the peer dropping mid-fragment.

`SAM_BURST_BYTES` is now 1024, which reproduces the old inter-chunk spacing
exactly. What survives is the removal of the **trailing** sleep after the final
chunk — which delayed the next stanza and nothing else — and byte-proportional
rather than per-chunk charging, so a short final chunk costs less than a full
20 ms.

**MEASURED** (`tools/transport_bench.py`, benchmark 1):

| message | old | new | saved |
|---|---|---|---|
| 200 B | 0.0 ms | 0.0 ms | — |
| 900 B | 0.0 ms | 0.0 ms | — |
| 1500 B | 40.0 ms | **9.3 ms** | 30.7 ms |
| 2500 B | 60.0 ms | **28.8 ms** | 31.2 ms |
| 4096 B | 80.0 ms | **60.0 ms** | 20.0 ms |
| 6000 B (an OTR fragment) | 120.0 ms | **97.2 ms** | 22.8 ms |
| 24000 B | 480.0 ms | 448.8 ms | 31.2 ms |

Sustained rate over 200 KB: 49.8 KiB/s → 50.3 KiB/s, i.e. unchanged within the
granularity of the old integer-chunk model.

The saving is ~20–31 ms per message, not the 40–83 ms first claimed. The
larger figure required a burst allowance that does not survive contact with a
real tunnel.

### 3.2 T2 — Nagle on the SAM sockets

**OBSERVED.** No socket in the transport set `TCP_NODELAY`. Every SAM socket is
loopback TCP carrying small periodic writes — 199-byte media frames every
40 ms — which is exactly what Nagle coalesces.

**MEASURED**, and the first result was negative:

| pattern | Nagle on | TCP_NODELAY | verdict |
|---|---|---|---|
| steady, 199 B every 40 ms | p50 0.354 ms, max 0.594 ms | p50 0.309 ms, max 0.621 ms | **no difference** — within noise across repeated runs |
| burst drain, 25 frames back to back | p50 **41.506 ms**, p95 42.404 ms, max 47.493 ms | p50 **0.513 ms**, p95 0.710 ms, max 0.882 ms | **~80× lower** |

The steady-cadence result is the expected one and is reported as a negative:
on loopback the ACK returns in microseconds, long before the next frame is
due, so Nagle never engages and `TCP_NODELAY` buys nothing. **Anyone claiming
this change helps the normal case would be wrong.**

The burst case is where it matters, and it is the case the brief cares about:
frames written back to back is what happens when a stalled send queue drains
after an I2P hiccup — the moment that decides the tail. There, Nagle adds
41 ms at the median.

`TCP_NODELAY` is now set on the media socket, the SAM control socket, the
XMPP stream socket and both ends of the local bridge.

### 3.3 T5 — two seconds of bufferbloat in the send queue

**OBSERVED.** `_MAX_WRITE_BACKLOG = VOICE_PACKET_LEN * 50` — at 40 ms per
frame, **two seconds** of audio permitted to sit in the transport before
anything is dropped.

This converts congestion directly into a tail: every queued frame is delivered
late by however long the queue takes to drain. The receiver then has to absorb
or discard it, and the receiver's own adaptive jitter buffer already claws
latency back above 600 ms — so those frames largely cost bandwidth, delay the
frames behind them, and get dropped at the far end anyway.

**Changed** to a time-based bound, `VOICE_MAX_WRITE_BACKLOG_MS = 400`
(10 packets, 1990 bytes). Chosen against the receiver: a frame more than
400 ms late is already competing with the jitter buffer's drift ceiling.
Backpressure drops are counted (`stats["backpressure"]`, and
`backpressure_drops` in telemetry) so the change is observable rather than
silent.

**INFERRED, not measured:** that this lowers p95/p99 on a real path. The
mechanism is clear and the arithmetic is exact, but it only bites during
congestion, which cannot be produced here.

### 3.4 T3 — SAM sessions created with no tunnel options

**OBSERVED.** Both `SESSION CREATE` commands passed no options at all, so every
tunnel property was the local router's default. Those differ: **i2pd defaults
to 5 inbound and 5 outbound tunnels, Java I2P to 2.** The same build on two
machines was getting materially different resilience, and neither was a
decision anyone had made.

**Verified against i2pd's source**, not documentation or memory:

* `libi2pd_client/SAM.cpp` — `ExtractParams()` parses every `key=value` on the
  SESSION CREATE line into a `Mapping` and passes the whole mapping to
  `CreateSession()`, so unrecognised keys reach the I2CP destination layer.
  Passing options this way is supported.
* `libi2pd/Destination.h` — the option names and defaults now recorded in
  `otrv4plus_i2p.TUNNEL_OPTION_DEFAULTS`.

**Now sent** (both the media and the XMPP session):

```
inbound.length=3 outbound.length=3
inbound.quantity=4 outbound.quantity=4
inbound.lengthVariance=0 outbound.lengthVariance=0
```

* **Hop count stays at 3.** Shortening tunnels is the single most effective
  latency change available and it is not on the table: hop count is the
  anonymity parameter. It is set *explicitly* so a router whose default
  differs cannot quietly give a call fewer hops than intended.
* **quantity 4** — above Java I2P's 2, which is where the resilience gain is;
  slightly below i2pd's 5, so on the bundled router this is marginally *less*
  build overhead, not more. Deliberately not maximised.
* **lengthVariance 0** — variance only ever *adds* hops, so a tunnel built
  with variance 1 can be 4 hops and slower, and latency then depends on which
  tunnel a message took. Pinning it costs no anonymity and removes one source
  of latency variance.

**INFERRED, not measured:** that 4 tunnels absorbs expiry better than 2. It
follows from expiry being staggered across a pool, but no router was available
to confirm it.

Two families of option are deliberately **not** used, and
`otrv4plus_i2p.session_options()` raises if anyone adds them:

* `inbound.backupQuantity` / `outbound.backupQuantity` — Java I2P only.
  i2pd's `Destination.cpp` never reads them, so on the bundled router they
  would be configuration that looks like resilience and is not.
* `i2p.streaming.*` — i2pd fixes its window, ACK delay, RTO and pacing as
  compile-time constants in `Streaming.h` and exposes no I2CP option strings
  for them. **There is no supported way to ask i2pd for a smaller ACK delay or
  a different initial window through SAM.** This is a real limit on what
  transport tuning can achieve, not an oversight.

---

## 4. Transport health (Phase 7)

`otrv4plus_telemetry.TransportHealth` — four states with hysteresis.

```
HEALTHY   ──5 consecutive bad samples, or 6 s silent──▶ DEGRADED
DEGRADED  ──first good sample──▶ RECOVERING
RECOVERING──10 consecutive good──▶ HEALTHY
RECOVERING──one bad sample──▶ DEGRADED
any       ──explicit transport failure──▶ DISCONNECTED
```

The property that matters: **only DISCONNECTED triggers reconnection, and only
an actual stream failure reaches it.** Latency, however bad, never does.

The reasoning is a cost comparison. I2P delivers a frame seconds late
routinely — a tunnel is being replaced, a peer is congested. Reconnecting
costs a fresh tunnel build (tens of seconds, per `SAM_SESSION_TIMEOUT = 300`)
and a guaranteed audio gap. A transport that reconnects on a spike reconnects
during every call and is worse than one that rides the spike out.

Recovery deliberately needs more samples (10) than degradation (5), so a
flapping path settles into DEGRADED rather than oscillating. **TEST-VERIFIED**:
a path alternating good/bad for 200 samples never reaches HEALTHY and never
requests a reconnect.

A silent stream produces no RTT samples, so nothing else would notice it. A
1 Hz `_health_loop` per active call drives `tick()`, which degrades after 6 s
without a frame.

---

## 5. What is NOT in this change

* **No cryptography touched.** Not the ratchet, DAKE, SMP, AES-256-GCM, the
  KDF, Ed448, X448, ML-KEM, ML-DSA, MAC revelation, or voice frame
  cryptography. §7.
* **No fallback outside I2P.** No WebRTC, no STUN/TURN, no RTP, no Jingle, no
  direct Internet path. Media stays on the SAM stream and signalling stays
  inside OTR.
* **No hop-count reduction.** §3.4.
* **No manual tunnel manipulation.** SAM exposes no per-tunnel control and the
  router remains responsible for tunnel selection. The application influences
  the pool only through the session options in §3.4 — which is the entire
  supported surface (Phase 8).
* **No new metadata on the wire.** Frames are still 199 bytes on a 40 ms
  cadence; the telemetry is local-only and derived from timestamps already
  present.

---

## 6. Cost

| Resource | Cost |
|---|---|
| Memory | ~2 KB per histogram × 9 = ~18 KB per call, fixed |
| CPU | One float and one bisect per frame (~25/s); one 1 Hz health tick per call |
| Bandwidth | Unchanged — no new frames, no size change |
| Disk | None unless `OTRV4PLUS_TRANSPORT_LOG` is set |
| Tunnel build | 4 in + 4 out instead of the router default (5/5 i2pd, 2/2 Java) |

---

## 7. Security regression (Phase 12)

| Property | Status |
|---|---|
| OTR security | Unchanged — no file under `Rust/src/` was touched; `cargo test` 65 passed |
| Voice frame cryptography | Unchanged — `VoiceFrameCrypto`, `VoiceKeySchedule`, `VoiceKeyExchange` not modified |
| Ratchet / rekey | Unchanged — rekey cadence, two-phase commit and epoch handling untouched |
| MAC implementation | Unchanged |
| I2P still carries everything | Yes — no path added that bypasses SAM |
| Plaintext voice logging | None — telemetry refuses `bytes` by type |
| Plaintext message logging | None — free-form strings are refused |
| Secrets in diagnostics | Structurally impossible — see below |
| Direct Internet fallback | None |
| Metadata-expanding protocol | None |

The telemetry value guard is the load-bearing part. `_check_value` accepts
ints, floats, `None`, a fixed enum vocabulary, and 8-hex-digit opaque tags —
and **raises** on anything else. Keys, seeds and frame plaintext are `bytes`
and are rejected by type; JIDs, I2P destinations and message bodies are
free-form strings and are rejected by shape. Event names come from a closed
set, so text cannot be smuggled through the name either.

Peers and calls appear as `sha3_256(per-process random salt || value)[:8]`.
Stable within a run so records correlate, meaningless across runs, not
reversible to a JID.

The JSONL sink is off unless a path is given and is created 0600 when it is —
numeric transport telemetry is still traffic-analysis material, because frame
counts and RTTs describe when a call happened and how long it lasted.

**TEST-VERIFIED** in `tests/test_voice_transport.py`: a JID, a message body, an
I2P destination, raw `bytes`, a `bytearray` and a `memoryview` are each
refused; a written log file contains none of the strings fed to the session;
the file is not world-readable.

---

## 8. Phase 11 — the soak test has NOT been run

The brief asks for a multi-hour A/B soak against the 4-hour baseline. **It was
not performed, and no substitute figures are offered.**

This container has no I2P router, no XMPP account and no peer. A soak run here
would measure a loopback socket talking to itself, and reporting that next to
the real baseline's p95 would be worse than reporting nothing.

What is needed to run it, on a host that has a router:

1. Set `OTRV4PLUS_TRANSPORT_LOG=/path/baseline.jsonl`, place a call on the
   commit before this pass, and let it run four hours.
2. Repeat on this commit into `optimised.jsonl`.
3. Compare `p50/p95/p99/max` for `rtt`, `oneway` and `jitter`, plus the
   counters `frames_sent`, `frames_received`, `late_frames`,
   `backpressure_drops`, and the health `transitions` / `seconds_degraded`.

The instrumentation for that comparison is the deliverable this pass can
honestly claim: **before it, the run could not have been scored on p95, p99 or
maximum at all.**

Predictions, recorded now so they can be falsified:

* **MEASURED, will hold:** signalling latency drops by ~20–31 ms per fragment
  (§3.1). Independent of the router. The 40–120 ms originally predicted here
  depended on a burst allowance that broke SMP on a real path and has been
  reverted.
* **MEASURED, conditional:** ~41 ms per frame removed whenever a stalled queue
  drains (§3.2). How often that happens on a real path is unknown.
* **INFERRED:** p95/p99 improve from the send-queue bound (§3.3) and from
  explicit tunnel quantity (§3.4). Neither can be confirmed without a router.
* **ASSUMED:** median RTT is essentially unchanged. Nothing here shortens the
  I2P path, and it should not be expected to.

---

## 9. Remaining limitations

1. **i2pd exposes no streaming-layer tuning through SAM** (§3.4). Its
   `INITIAL_RTO = 9000 ms` and `INITIAL_WINDOW_SIZE = 10` are compile-time
   constants; a lost segment early in a call can therefore cost seconds and
   the application cannot influence it. This is likely a significant part of
   the observed tail and is **not addressable from this codebase**.
2. **Signalling shares one stream with chat.** Media does not, so audio is
   safe, but a large chat message still delays a rekey by up to the pacer's
   rate. Fixing that properly needs a second SAM stream for signalling, which
   is a protocol change and out of scope here.
3. **The 40 ms frame interval is not adaptive.** Larger frames would cut
   per-frame overhead on a congested path at the cost of latency; no evidence
   was gathered either way.
4. **Tunnel quantity 4 is a judgement, not a measurement** (§3.4).
5. **Battery and CPU under Android's scheduler are unmeasured**, as in the
   soak report.

---

## 10. Files changed

| File | Change |
|---|---|
| `otrv4plus_telemetry.py` | **New.** Histogram, TransportMetrics, TransportHealth, JsonlSink, value guard |
| `otrv4plus_i2p.py` | **New.** Verified tunnel-option table, `SamWritePacer`, `set_nodelay` |
| `otrv4plus_xmpp.py` | Token-bucket pacing replaces the fixed sleep; TCP_NODELAY on bridge and SAM sockets |
| `otrv4plus_voice.py` | Tunnel options on SESSION CREATE; send-queue bound 2 s → 400 ms; telemetry and health wiring; `transport_summary()` |
| `otrv4+.py` | Tunnel options on the XMPP SESSION CREATE; TCP_NODELAY on the stream socket |
| `tools/transport_bench.py` | **New.** The measurements in §2 and §3 |
| `tests/test_voice_transport.py` | **New.** 68 tests |
| `test_voice_audio_integration.py` | Stubs updated for the `_write_packet` timestamp |
