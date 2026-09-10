# Where an I2P call's delay actually goes

Written for the v10.29.0 tuning pass, from the v10.15.1 instrumented soak
(`VOICE_SOAK_TEST.md` §A.3.2) and a live two-handset call on 2026-09-05.

The purpose of this document is to stop the same argument being had twice. It
records what is measured, what is ours, and what is not.

---

## The budget

```
mouth-to-ear ~855 ms  =  network 576 ms  +  jitter buffer 229 ms  +  playout 51 ms
```

| Component | Measured | Ours? |
|---|---|---|
| Network transit | 576 ms | **No.** Six I2P hops one way, ~96 ms each. |
| Jitter buffer | 229 ms | **Yes.** Entirely a local playout decision. |
| Playout (decode + device write) | 51 ms | Partly. |
| Encode + seal + queue + decrypt + decode | **~7 ms total** | Yes, and irrelevant. |

Per-stage medians from the soak: encode 5.6 ms, seal 0.2 ms, queue 0.3 ms,
decrypt 0.3 ms, decode 0.9 ms.

**The cryptography costs half a millisecond of an 855 ms budget** — sealing
and opening together. Whatever makes an I2P call feel slow, it is not the
post-quantum crypto, and no amount of work on the cipher suite will move this
number.

## What is not on the table

**The hop count.** Three hops per tunnel in each direction is the reason the
project exists. A 1-hop tunnel would roughly halve the network term and would
also make the sender's IP recoverable by a single colluding router. Not a
trade-off, a change of product.

**Transport-level tuning.** SAM session options, a write pacer and
`TCP_NODELAY` were tried in the pass reverted at `8683be3`, which "broke a
working system twice on a real I2P path". That whole area stays closed until
there is a way to test it that does not involve breaking the only two handsets
that can test it.

**A smaller frame.** 40 ms frames would cut packetisation delay by 20 ms and
raise the packet rate from 16.7/s to 25/s. A live call has already starved at
25 packets/s (`tests/test_voice_frame_geometry.py` pins it as a regression
bound). The 20 ms is not worth re-testing that.

So the winnable budget is the jitter buffer, and it is about a quarter of the
total.

---

## What was wrong with the buffer

The target depth was `2 x J`, where J is RFC 3550's smoothed **mean absolute
deviation** of inter-arrival time. The measured spacing, against a 60 ms
expected:

| | spacing | lateness | frames |
|---|---|---|---|
| p50 | 69 ms | 9 ms | 0.15 |
| p95 | 128 ms | 68 ms | 1.13 |
| p99 | 211 ms | 151 ms | 2.52 |
| max | 281 ms | 221 ms | 3.68 |

**The tail is sixteen times the median.** On that distribution `2 x J` asks
for under two frames, so the target sat on the hand-set floor of three for the
entire call and the adaptive machinery never once bound. Meanwhile the frames
that actually empty a buffer are two and a half frames late.

The soak's own counters record the result: `underrun=27 shed=313`. Both at the
same time is not a buffer that is too deep or too shallow — it is a buffer
that never settles.

Two things followed from that:

1. **The distribution was already being collected and never used.**
   `JitterBuffer.spacing` exists for exactly this, and its comment says a mean
   deviation "cannot distinguish a steadily late path from a punctual one with
   a long tail, and only the second is worth buffering for". It was only ever
   printed into the debug stream.

2. **Nothing learned from an underrun.** It is the only *direct* evidence that
   the buffer was too shallow; everything else is inference from arrival
   times. The target after the twenty-seventh underrun was identical to what
   it had been before the first.

## What changed at v10.29.0

- The target is sized from the measured **lateness tail** (p95 over a rolling
  200-frame window) as well as from J, whichever asks for more. Only lateness
  is recorded: a frame that arrives early costs the buffer nothing, while J is
  symmetric and charges earliness as if it were a risk.
- **An underrun buys a frame of depth**, up to the latency ceiling, given back
  after ~300 clean frames. Rise on evidence, fall on time.
- Because depth is now earned rather than insured by a constant, the static
  floor came down: prefill 180 → 120 ms, shed margin 180 → 120 ms.

The shed margin is the cheapest 60 ms in the budget: it is hysteresis above
the target, and it is the **target** that guards against a dropout. Lowering
it lowers the band the buffer settles in without moving the depth that
prevents a gap by a single frame.

### Predicted, not measured

Replaying the soak's spacing distribution through the new estimator:

```
            target   trigger   steady-state band
  before      3 f      6 f       180-360 ms
  after       2 f      4 f       120-240 ms
```

Scaling by the 229 ms actually measured under the old trigger gives a
predicted dwell of ~153 ms, so **mouth-to-ear ~855 → ~779 ms**.

That is a prediction from a replayed distribution, not a measurement. It is
about 9% of the total, and it is roughly the whole of what is available
locally. Anyone hoping for a large win here should read the first table again:
two thirds of the delay is six hops of garlic routing.

---

## How to check it in the morning

Every call now prints the decomposition at hangup, so this no longer needs
`--voice-debug`:

```
[voice] 🟢 call ended — good — 2m14s, mouth-to-ear ~780ms, 99.1% of audio delivered, 1244 frames sent
[voice]   560ms network (6 I2P hops) + 170ms jitter buffer + 50ms playout
```

What to look for, in order:

1. **The jitter-buffer term.** It should be lower than the ~229 ms this
   started from. If it is not, the tail on the day is longer than the soak's.
2. **`underrun`** in `--voice-debug`. If it has gone *up* materially, the
   floor came down too far — the mechanism is meant to prevent exactly that,
   so this is the number that says whether it works.
3. **`; buffer holding N extra frame(s) after underruns`** on the budget line.
   That is the learning being exercised. Seeing it is not a fault: it means
   the buffer met a bad patch and paid for it. Seeing it grow to the ceiling
   and stay there means the floor is too low for this path.
4. **The shed percentage** in the summary. It should fall, because a lower
   trigger sheds sooner but from a shallower band.

### If it is worse

Everything is one variable away from where it was, on either handset
independently — these are local playout decisions, not wire format, so the two
peers do not have to agree:

```sh
OTRV4PLUS_JITTER_MIN_MS=180      # the old floor
OTRV4PLUS_JITTER_MARGIN_MS=180   # the old shed margin
OTRV4PLUS_JITTER_TAIL_PCT=99     # buy the p99 instead of the p95
OTRV4PLUS_JITTER_UNDERRUN_STEP=0 # turn the learning off entirely
```

Setting the first two restores v10.28.1's depth exactly.
