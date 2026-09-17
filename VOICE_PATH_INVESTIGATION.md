<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial -->
<!-- Copyright (C) 2025-2026 muc111 -->

# I2P voice path: what the diagnostics were actually measuring

Triggered by a real 41m51s call that established X448 + ML-KEM-1024, carried
AES-256-GCM media, sustained bidirectional speech, survived two media outages,
and then reported **`0.0% of audio delivered`** and **`6 I2P hops`**.

Both numbers were wrong. Neither was wrong about the network.

**Nothing cryptographic was changed.** No change to X448, ML-KEM-1024,
AES-256-GCM, Rust key ownership, zeroization, the hybrid handshake, media
encryption, the codec parameters, or the tunnel configuration.

---

## 1. `0.0% of audio delivered` — root cause found and fixed

### 1.1 The measurement, traced

```
delivery = queued / (queued + gaps)                      otrv4plus_voice.py
  queued  += 1          in JitterBuffer.push()   — every frame accepted
  gaps    += gap        in JitterBuffer.pop()    — frames missing in sequence
  gap      = seq - last_played - 1
  seq      = JitterBuffer.sequence(epoch, counter)
           = (epoch << 62) | counter
```

### 1.2 The defect

`sequence()` packs the **rekey epoch** into the top 62 bits, and counters
restart at zero each epoch. So `seq - last_played` is a frame count **only
within one epoch**. Across a rekey it is `2**62` ≈ **4.6 × 10¹⁸**, and `pop()`
added that straight into `gaps`.

One rekey is therefore enough to drive delivery to zero:

```
 41 min at 60 ms  ≈       41,850 frames queued
 one rekey        ≈ 4,611,686,018,427,387,899 phantom "lost" frames
 delivery         = 41850 / (41850 + 4.6e18) ≈ 9e-15  →  "0.0%"
```

Reproduced directly:

```
after epoch 0: queued=5 gaps=0
after rekey:   queued=10 gaps=4611686018427387899
displayed as:  0.0% of audio delivered
```

### 1.3 How bad it was

Mostly cosmetic, and worth stating precisely rather than alarming.

`pop()` returns `gap` to the playout worker, which passes it to `_conceal()` —
and that is bounded: `for _ in range(min(gap, 3))`. So the audible cost was up
to **three concealment frames (~180 ms of synthetic audio) per rekey**, not a
stall. The serious damage was to the metric, and through it to every judgement
anyone made from a call summary.

The same corruption also fed the `shed` percentage and the 🔴/🟡/🟢 verdict,
so affected calls were additionally reported as **"quality was poor"**.

### 1.4 The fix

`JitterBuffer.pop()` now counts a gap only when both sequence keys are in the
same epoch. Across the boundary it counts **zero** — the counter restarted, so
how many frames were lost in the changeover is genuinely unknown, and zero is
off by at most a handful where the old value was off by 4.6 × 10¹⁸.

`_observe_arrival()` already refused deltas ≥ 200 for exactly this reason. The
guard existed; `pop()` was the one place that missed it.

**Verified by re-planting the defect:** removing the epoch comparison fails
`test_an_epoch_change_adds_no_phantom_gaps` with
`assert 4611686018427387899 == 0`.

### 1.5 The metric is now counts, not a percentage

Per §18, `"x% of audio delivered"` is gone. A percentage is where the
measurement stops being checkable, and even uncorrupted the phrasing invites
the reading *"zero audio was received"*, which the ratio never meant. The
summary now reports what was measured:

```
1990 played, 10 missing, 330 shed locally (frames)
```

A counter that was never wired prints **nothing** rather than a confident zero,
and a call with no counters at all says `no media counters were recorded`
rather than reporting a row of zeros.

---

## 2. `6 I2P hops` — the number was never measured

### 2.1 What generated it

A string literal:

```python
line = ("[voice]   %.0fms network (6 I2P hops) + %.0fms jitter "
        "buffer + %.0fms playout" % (oneway, dwell, playout))
```

### 2.2 The finding

**This application never configures or reads tunnel length.** The media session
is created with:

```
SESSION CREATE STYLE=DATAGRAM ID=... DESTINATION=TRANSIENT
                SIGNATURE_TYPE=7 PORT=... HOST=127.0.0.1
```

A search of the entire codebase for `inbound.length`, `outbound.length`,
`inbound.quantity` and `i2cp.` returns **zero matches** — in the voice module,
the XMPP client, and the Android bridge alike.

So tunnel length is **whatever the router defaults to** (3 for i2pd and Java
I2P), and `6` was an assumption typed into a format string by someone
describing the architecture from memory.

### 2.3 Two things were wrong with the wording

1. **Nothing counted anything.**
2. **"6 hops" describes the wrong architecture.** It reads as one six-hop path.
   The real shape is two independent three-hop tunnels, one per direction —
   a materially different and *better* anonymity story than the display gave.

### 2.4 What it says now

```
706ms network (I2P: a tunnel each way, 3 hops each at the router's default
               (this client does not set tunnel length))
```

`hop_note()` makes the stronger claim automatically if `hops_are_configured()`
ever becomes true, and a test asserts the two cannot drift apart.

### 2.5 ⚠ The 3-hop requirement is not enforced

**This is the most important finding in the document.**

The 3-hop requirement is documented, assumed throughout, and **never asserted
on the wire**. A router configured with `inbound.length = 1` — a common latency
optimisation, and the default in some bundled configurations — would give this
application a **1-hop path**, and nothing in the client would notice or say so.
The old diagnostic would have gone on claiming six.

**The tunnel configuration has deliberately not been changed** — §12 forbids
altering it because the display said six, and §20 forbids redesigning the
3-hop requirement. But the gap between "documented requirement" and "asserted
requirement" is a security property this milestone should close, and it is a
one-line addition to `SESSION CREATE`:

```
SESSION CREATE ... inbound.length=3 outbound.length=3
```

That is a behaviour change to a working voice path on a live product, so it is
recorded as a **recommendation requiring your decision**, not applied.

---

## 3. `706ms network` — the measurement is sound

### 3.1 Traced

| Stage | What happens |
|---|---|
| **Definition** | Median one-way media latency |
| **Clock sync** | NTP four-timestamp: `offset = ((t2−t1) + (t3−t4)) / 2` from PING/PONG |
| **Per-frame** | `delta = arrival − peer_send_ms + offset`, from each frame's own timestamp |
| **Filter** | `−1000 < delta < 120000` ms |
| **Readout** | Median of the sample window |

This is **genuine one-way latency from in-band frame timestamps**, not RTT/2,
not an estimate, and not a tunnel measurement. `rtt_ms` exists separately and
is explicitly documented as the diagnostic while one-way is "the half of it the
listener actually waits through".

### 3.2 Plausibility

706 ms one-way over three I2P hops each direction, garlic-routed, on a mobile
router, is **entirely plausible**. Typical I2P one-way latencies run 200–800 ms
and are dominated by per-hop queuing rather than distance.

### 3.3 One caveat, and it is real

The NTP offset calculation **assumes a symmetric path**. I2P's outbound and
inbound tunnels are different paths through different routers with different
latencies, so that assumption is violated by construction. The offset absorbs
half of any asymmetry, which means:

> the reported one-way figure carries an error of up to **half the path
> asymmetry**, in whichever direction the asymmetry runs.

It is still the best available measurement and the right one to display — but
it is an estimate with a known bias, not a measured constant, and §11 asked
whether it was physically plausible rather than whether it was exact.

---

## 4. The latency budget is internally consistent

```
706 network + 190 jitter buffer + 52 playout = 948 ms
reported mouth-to-ear:                        ~948 ms   ✓
```

`budget_is_consistent()` now checks this, so a component reading from a stale
call or an unwired counter is caught rather than displayed. §19's requirement.

### 4.1 Why the buffer grew to 190 ms

The buffer is adaptive: RFC 3550 interarrival jitter, target depth =
`safety_factor × jitter_estimate`, with a tail estimator taking the larger
value. **190 ms of buffer against 706 ms of network is the mechanism working
correctly** — it is roughly three 60 ms frames of protection on a path with
large arrival variance.

**It should not be reduced to make the latency number look better.** §17 says
this and the mathematics agrees: the network is 74% of the budget. Halving the
buffer would save 95 ms of a 948 ms budget — a 10% improvement — and would
spend it on dropouts on a path that demonstrably suffers multi-second outages.

The dominant term is the network, and the buffer is not where it went.

---

## 5. The media outages — what is and is not established

**What the instrumentation now distinguishes** (`MediaCounters`, per §14):
`captured → encoded → encrypted → sent → received → decrypted → queued →
played`, plus `concealed`, `shed`, `gaps`, `underruns`. A gap between two
adjacent counters localises a fault to one stage instead of to "the network".

**What is NOT established:** where the packets went. Determining that requires
the counters above to be collected on *both ends of a real call during an
outage*, which is Test C in §22 and has not been run.

The candidate that best fits the observed evidence — SAM control socket
healthy, no inbound datagrams, recovery after ~15–19 s, recovery again after a
rebuild — is **inbound tunnel expiry on the remote side**. I2P tunnels have a
10-minute lifetime and are rebuilt continuously; a failed rebuild leaves a
destination briefly unreachable while the control socket stays perfectly
healthy, because the control socket is a local TCP connection to the router and
knows nothing about tunnel state. That is a hypothesis consistent with the
evidence, **not a finding**, and it is labelled as such.

### 5.1 A rebuild is not a recovery

`recovery_verdict()` now requires that **inbound media actually resumed**:
`Outage.recovered` is true only when frames arrived after the outage ended. A
rebuild that completed while no media resumed reports `failed`, not
`recovered`.

§27 asked for exactly this: *"media path recovered" means actual media
datagrams were received and processed again* — not that the state machine
started a rebuild.

**Recovery thresholds were not changed.** §15 requires evidence first, and the
evidence is Test C.

---

## 6. What was changed

| File | Change |
|---|---|
| `otrv4plus_voice.py` | `pop()` epoch guard; `EPOCH_SHIFT`/`epoch_of()`; honest hop note; counts instead of a percentage |
| `otrv4plus_mediapath.py` | **New.** Hop description, media counters, outage/recovery accounting, budget consistency |
| `tests/test_media_path_accounting.py` | **New.** 39 tests |
| `tests/test_voice_call_summary.py` | Updated: the four tests that pinned the old wording now pin the corrected claims |

**Executed:** 39 new + 188 voice tests. The epoch defect fails a test when
re-planted.

**Not performed:** every physical test in §22. No call has been made with this
instrumentation.

---

## 7. Open items

| # | Item | Status |
|---|---|---|
| 1 | `inbound.length=3 outbound.length=3` on `SESSION CREATE` | **Recommended — needs your decision** |
| 2 | Where outage packets are lost | Hypothesis only; needs Test C |
| 3 | One-way latency bias from path asymmetry | Documented; no fix proposed |
| 4 | Counters wired into the live pipeline | `MediaCounters` is defined and tested; the voice module still uses its own `stats` dict |
| 5 | Tests A/B/D/E in §22 | Not performed |
