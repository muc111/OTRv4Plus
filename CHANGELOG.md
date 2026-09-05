# Changelog

OTRv4+ post-quantum messaging client. Solo dev project. AI-assisted (Claude). Each version live-tested between two I2P peers before commit.

---

## v10.29.0 — the buffer was sized from an average, on a path that has a tail

*2026-09-05.  `VERSION → 10.29.0`.  `otrv4_core` unchanged at 0.10.28.*

Asked to find whatever latency could be found without touching the three-hop
tunnel configuration, which is not negotiable and is the reason the project
exists.  Full analysis in **[VOICE_LATENCY_BUDGET.md](VOICE_LATENCY_BUDGET.md)**.

The measured budget, from the v10.15.1 soak:

```
mouth-to-ear ~855 ms  =  network 576 ms  +  jitter buffer 229 ms  +  playout 51 ms
```

Two thirds of it is six I2P hops at about 96 ms each and is not ours.  The
cryptography is 0.5 ms of it — sealing and opening together — so no amount of
work on the cipher suite moves this number.  The jitter buffer is the only
quarter this client controls.

### What was wrong with it

The target depth was `2 x J`, RFC 3550's smoothed **mean absolute deviation**
of inter-arrival time.  The measured spacing against a 60 ms expected: p50
69 ms, p95 128 ms, p99 211 ms, max 281 ms.  The median frame is 9 ms late and
the p99 frame is 151 ms late — **the tail is sixteen times the median**.

On that distribution `2 x J` asks for under two frames, so the target sat on
the hand-set floor of three for the whole call and the adaptive machinery
never once bound, while the frames that actually empty a buffer are two and a
half frames late.  The soak's own counters say what happened: `underrun=27
shed=313`.  Both at once is not a buffer that is too deep or too shallow, it
is a buffer that never settles.

Two things had been sitting in the code waiting to be noticed.

`JitterBuffer.spacing` already collected the distribution, and its own comment
already said why it mattered — a mean deviation "cannot distinguish a steadily
late path from a punctual one with a long tail, and only the second is worth
buffering for" — and it was then only ever printed into the debug stream.  The
same shape as v10.28.0's bug: the right figure computed for a log nobody
watching a call would read.

And nothing learned from an underrun, which is the only DIRECT evidence that
the buffer was too shallow.  The target after the soak's twenty-seventh
underrun was identical to what it had been before the first.

### What it does now

- Sized from the measured **lateness tail** (p95 over a rolling 200-frame
  window) as well as from J, whichever asks for more.  Only lateness counts: a
  frame that arrives early costs the buffer nothing, while J is symmetric and
  charges earliness as though it were a risk.
- **An underrun buys a frame of depth**, to the latency ceiling, given back
  after ~300 clean frames.  Rise on evidence, fall on time.
- Because depth is now earned rather than insured by a constant, the static
  floor came down: prefill 180 → 120 ms, shed margin 180 → 120 ms.  The shed
  margin is the cheapest 60 ms in the budget — it is hysteresis above the
  target, and it is the TARGET that guards against a dropout.

Replaying the soak's distribution through the new estimator moves the
steady-state band from 180–360 ms to 120–240 ms, predicting **mouth-to-ear
~855 → ~779 ms**.  That is a prediction from a replayed distribution and not a
measurement, it is about 9%, and it is roughly the whole of what was available
locally.

Every call now prints the decomposition at hangup, so checking it no longer
needs `--voice-debug`:

```
[voice]   560ms network (6 I2P hops) + 170ms jitter buffer + 50ms playout
```

Nothing here is wire format — these are local playout decisions, so the two
handsets can run different values.  `OTRV4PLUS_JITTER_MIN_MS=180
OTRV4PLUS_JITTER_MARGIN_MS=180` restores v10.28.1's depth exactly.

### Deliberately not attempted

Tunnel options, a SAM write pacer and `TCP_NODELAY` were the reverted pass at
`8683be3`, which "broke a working system twice on a real I2P path".  40 ms
frames would save 20 ms of packetisation and raise the packet rate to 25/s, at
which a live call has already starved.  Neither is worth spending a test
window on.

### The message you typed appeared twice

```
i shiuld not seewgat i type twice
🔒 [otr] alice@xmpp-elite.i2p: i shiuld not seewgat i type twice
```

v10.27.0 added an attributed echo of outgoing messages, because without it the
session log recorded only one side of the conversation.  In the TUI that is
right — it owns the screen in raw mode and echoes input itself.  In plain
mode, which is the default, the input loop sits in `sys.stdin.readline()` with
the tty in canonical mode, so the terminal has already drawn the line before
our echo runs.

The echo now erases the terminal's copy and prints the attributed line in its
place.  Moving the cursor up is destructive, so it happens only when all three
of these hold: the line is the one the terminal just echoed, **nothing has
been printed since** (an inbound message arriving in between means the rows
above the cursor are no longer the user's input), and stdout is a terminal
whose width can be read.  Wrapped input is counted properly, a pasted wall of
text over twelve rows is left alone, and any failure falls back to the
v10.28.1 behaviour — printing twice is ugly, deleting a line of somebody's
conversation is not recoverable.

51 tests, 25 mutations killed.  Full suite: 3299 passed, 44 skipped, 1 xfailed.
The buffer change is predicted, not measured; the two-handset run in the
morning is what settles it, and VOICE_LATENCY_BUDGET.md says what to look at.

---

## v10.28.1 — the latency scale was calibrated for a phone network

*2026-09-05.  `VERSION → 10.28.1`.  `otrv4_core` unchanged at 0.10.28.*

The first real call under v10.28.0's new summary:

```
[voice] 🔴 call ended — quality was poor — 1m51s, mouth-to-ear ~914ms, 96.5% of audio delivered, 2.6% shed locally to hold latency down, 1068 frames sent
```

Two people had that conversation start to finish.  96.5% of the audio arrived,
2.6% was shed to hold latency down, nothing failed to authenticate.  It was
reported as a poor call because of one number, and that number was being judged
against the wrong scale.

The bands were ITU-T G.114's: green under 400 ms, amber to 800 ms.  G.114 is a
standard about **terrestrial** telephony, where propagation is nearly free and
400 ms means something has gone wrong.  It says so itself — it carves out links
with unavoidable long propagation, a geostationary satellite hop being about
250–280 ms each way, as outside its range and in daily use anyway.

A call here crosses three garlic-routed I2P hops in each direction, plus the
jitter buffer that has to absorb each hop's variance.  This repository has
recorded the consequence for some time without acting on it: `README.md`,
`FEATURES.md` and `ROADMAP.md` all state a measured median mouth-to-ear of
**917 ms** on this path.  The scale was calling its own transport's median a
fault.

That is a broken instrument, not a bad call.  A scale that cannot reach its top
band on the only transport the project supports is not strict, it is stuck —
and it spends the colour reserved for *something is wrong* on the ordinary
case, so the day something is genuinely wrong it has nothing left to say.

The bands are now set against what this path can actually deliver:

| Colour | Mouth-to-ear | Meaning |
|---|---|---|
| green | ≤ 1000 ms | at or near the floor of the path — as good as I2P gets |
| yellow | ≤ 1500 ms | noticeably worse than the floor; still a conversation, with the pauses of a satellite call |
| red | > 1500 ms | turn-taking breaks down |

The 914 ms call now reads `🟢 call ended — good`.

**The measurement has not moved and is not being flattered.**  917 ms is still
917 ms, it is still the price of the anonymity configuration, and reducing it is
still open work — `ROADMAP.md` keeps it as a target.  What changed is the
sentence printed next to it.  G.114's numbers are kept as named constants,
`G114_GOOD_MS` / `G114_WARN_MS`, cited by the legend, and one environment
variable away for a LAN or clearnet deployment:
`OTRV4PLUS_M2E_GOOD_MS=400 OTRV4PLUS_M2E_WARN_MS=800`.

### The test that argued the other way

`test_latency_colour.py` carried this, and it deserved an answer rather than a
deletion:

> Measured medians on this transport were 494–688 ms one-way and ~1050 ms
> mouth-to-ear. If a change ever makes those read green, the scale has stopped
> meaning anything.

The instinct is right — a scale where everything is green says nothing — but it
anchored on the wrong property.  Requiring a *typical* reading to be non-green
pins the median into a warning band permanently, whatever the transport does.
What the guard actually wants is that the scale **discriminates**, so that is
what is now asserted: every band has a realistic I2P reading in it, a call at
twice the floor is still red, and the live 914 ms call is replayed through
`_call_summary` as a regression case.

The legend also now names what it is a scale of — "calibrated for I2P, not for
a telephone network" — because printing the numbers without that invites the
reading these bands exist to prevent: that 900 ms is fine in general.  It is
fine *here*, and it would be a fault on a LAN.

Delivery and shedding thresholds are unchanged (95% and 5%); the 914 ms call
passed both on its own merits.

7 tests changed or added.  Full suite: 3243 passed, 44 skipped, 1 xfailed.

---

## v10.28.0 — the call told you about buffers, not about the call

*2026-09-05.  `VERSION → 10.28.0`.  `otrv4_core` unchanged at 0.10.28.*

Two complaints from the handsets, and both are about a person watching a call
rather than a developer reading a log.

Bringing a call up printed fourteen lines — codec settings, mic and speaker
gains, transport, shaping, audio backend, playout geometry, three about
loudness and two about which Android stream the volume keys control — and not
one word about the cryptography.  A user could not tell a post-quantum call
from a classical one, and on a phone the one line that mattered, that the call
was live, had already scrolled off the top.

Hanging up printed a packet tally.  That says whether the software worked.  It
does not say whether the *call* worked, and the two figures that answer that —
how long speech took to reach an ear, and how much of it arrived — were being
computed already, for the debug stream, where nobody on a call would ever see
them.

Call setup is now three lines, one of which is new:

```
[voice] call active with alice@example.i2p — /hangup to end, /mute to toggle mic
[voice] 🔒 X448 + ML-KEM-1024 → AES-256-GCM over I2P datagrams, constant-rate — keys are per call, held in Rust, and zeroized on hangup
```

and hangup is two:

```
[voice] 🟢 call ended — good — 2m14s, mouth-to-ear ~340ms, 99.8% of audio delivered, 1244 frames sent
[voice] 🔒 every media key for this call has been zeroized
```

Nothing was deleted.  Every one of those fourteen lines was added to answer a
real question during a real failure, so they moved behind `_vprint` and come
back with `--voice-debug`, `/voicedebug` or `OTRV4PLUS_VOICE_VERBOSE=1`.  That
is deliberately the *same* switch as the telemetry, not a second one: somebody
who types `/voicedebug` because a call sounds wrong wants the codec, transport
and playout lines, not telemetry with the explanation missing.

Four things stayed at normal volume because a flag would hide the wrong
thing.  The shaping line, when it is bad news: a user told the call is
constant-rate is entitled to be told when VBR or DTX could not be disabled and
it is not.  The authentication-failure and replay counters, when either is
non-zero: frames arrived that did not authenticate under our key.  The
confirmation that the media keys were wiped, which is printed outside every
`try`, because a counter that could not be formatted must not be able to
withhold it.  And the playout finding, for a reason a pre-existing test made
on better evidence than this change had.

`test_playout_instrumentation.py` required the playout line on *every* call,
from a 1960 s diagnosis in which the playback device buffer held less than one
packet, every write blocked, the pop rate fell below the arrival rate and the
jitter buffer shed a third of the audio — eight times more than the network
lost, with every counter reading healthy, because a shed frame advances the
playout marker rather than leaving a gap.  That reasoning survives the tidy,
but what it actually demands is that the *finding* be unmissable, not that
four numbers of device geometry print on every healthy call.  So
"every write waits on the device" stays at normal volume, names the flag that
produces the numbers, and the numbers moved.

Better still, the shedding itself is now reported at hangup — `33.4% shed
locally to hold latency down` — and counts against the verdict above 5%.  That
is the figure the 1960 s diagnosis needed and never had: the setup line can
only say the device buffer is small, while this says how much audio the call
actually destroyed.

### What the verdict actually measures

Mouth-to-ear is the full path a listener waits through — network one-way, plus
dwell in our jitter buffer, plus decode, plus playout — banded green/amber/red
on ITU-T G.114 (400 ms / 800 ms), the same thresholds the debug stream already
used.  Delivery is `queued / (queued + gaps)` from the jitter buffer: the
fraction of the far end's audio that arrived in time to be played.  Not
`recv / (recv + dropped)`, because `dropped` counts send-side failures too, so
a call that could not transmit would have been reported as one that could not
listen.  Local shedding is reported separately and deliberately not folded
into that ratio: those frames arrived, and calling them loss would blame the
network for something this device did.

Delay, loss and shedding are judged independently and the worst one wins.  A
call two seconds behind was not good however completely it arrived; a call
that lost a fifth of its audio was not good however fast the rest of it was;
and a call that threw away a third of its own audio was not good at all.

The summary is gathered *before* `session.end()`, which tears down the jitter
buffer and the latency tracker it reads.  Taken afterwards it reports zeros,
which is worse than no summary: it looks like a measurement.  And a session
from which nothing could be read at all now says `call ended` and stops,
rather than `0s, mouth-to-ear not measured (call too short)` — a sentence full
of figures that were never taken.

### XMPP status tags are colour-coded

Nearly every line the XMPP client prints is `[tag] free text`, and every one of
those tags used to be the same grey as the sentence after it.  Tags are now
coloured by what the line *means* — red for a failure, yellow for attention,
cyan for things the user asked for, magenta for the call subsystem, grey for
plumbing that is working.

Two things that colour must not disturb, and does not.  The session log takes
the line before any colour is applied, so INV-03's redaction still reasons
about shapes rather than escape sequences.  And the TUI is handed the plain
line, because `_tui_route_output` picks a panel with
`startswith("[keepalive]")` — a coloured tag would have failed every one of
those tests silently and put keepalive ticks in the peer's chat panel.

`[otr]` and `[smp]` are deliberately absent: they already carry their own
padlock-and-colour prefixes, and a second scheme on the same line would fight
them.  So are ten tags that colour *would* suit but the log allowlist
deliberately excludes — `[file]` prints filenames, `[roster]` prints contacts,
`[tip]` prints a Monero address — because making the two tables symmetrical
would put all of that on disk to tidy up a colour table.  A test pins the
asymmetry so the "obvious" fix has to be a deliberate edit.

77 tests, 34 mutations killed.  Not yet exercised on the handsets: everything
in this entry is terminal output, and the call figures in particular need a
real I2P call to confirm the bands read sensibly.

---

## v10.27.0 — the XMPP transcript was missing one side of the conversation

*2026-09-05.  `VERSION → 10.27.0`.  `otrv4_core` unchanged at 0.10.28.*

From a handset, the IRC client:

```
20:50:55 [EchoingNexus] 🔵EchoingNexus: ey
20:50:57 [EchoingNexus] 🔵ScarletEmber: lol
```

Two people, two names, one readable conversation — and a request to make XMPP
do the same.  Looking at why it could not turned up something worse than a
formatting difference.

### Outgoing messages were never printed at all

`send_user_text` encrypted the line, sent it, and returned.  Nothing was
echoed.  The typed line scrolled away behind the next arriving message, and
the session read as a monologue by the peer with the user's own half missing
entirely.  On a handset there was no way to read back who had said what.

That is the defect; the shape was the cosmetic part.

```
🔐 [otr] bob@example.i2p: ey
🔐 [otr] alice@example.i2p: lol
```

Same padlock on both sides, same `[otr]` tag, our own JID rather than "me" —
two names in two formats is how a transcript stops being quotable.  A
different colour separates the two sides at a glance.  The echo goes out
**after** the send and only when the engine produced ciphertext: a padlock on
a message that never left would be a false claim about the one thing this
client exists to be right about.

Incoming lines moved from `[otr] <bob@host> text` to `[otr] bob@host: text`,
and the plaintext path with them — a transcript that changes shape between
encrypted and plain lines is harder to read than either shape alone.

### The part that needed care

`_LOG_CONTENT_RE` is the INV-03 allowlist that keeps message bodies off disk,
and it matched the old shape by hand:

```
^(\[(?:otr|plain)\] <[^>]*>)\s(.*)$
```

Changing the display without it would **not** have leaked — `_log_line_for_file`
falls through to `<unlogged line: N chars>` for anything it cannot classify,
which is the right way round — but every chat line would have become an
anonymous byte count.  A transcript that cannot say who spoke is most of the
way to useless, so the pattern moved with the display and still accepts the
old shape for any path that has not.

23 tests in `test_xmpp_transcript_shape.py`, 6 mutants killed — including the
echo going out before the send, the echo always claiming verified, the name
pattern loosened enough to swallow a colon in the body, and a peer forging
`[otr]` from inside their own message text.

Full suite 3161 passed / 44 skipped / 1 xfailed.

**Not hardware-tested.**  The two-device check is simply whether a conversation
reads back correctly on both handsets afterwards.

---

## v10.26.2 — `safe` is the answer, and the model now says so

*2026-09-05.  `VERSION → 10.26.2`.  `otrv4_core` unchanged at 0.10.28.*

A fifth observation, from the peer this time: a **47-fragment SMP2 at
`normal`, killed with `Excess Flood`**.

The v10.26.1 peer-flood backoff caught it and dropped this end to `safe`
before its own SMP3 — also 47 fragments — went out.  That is the mechanism
working exactly as intended on its first real firing, and it probably saved
the session.

### A penalty of 2.0 is now arithmetically impossible

`normal` costs exactly 2.0 s/line.  At a penalty of 2.0 its debt after the
burst is **zero**, so no length could ever be refused — and one was.  Solving
all five observations together needs a penalty of at least 2.75; 3.0 fits with
room:

| lines | rate | debt at 3.0 | outcome |
|---|---|---|---|
| 17 | `fast` | 38 | survived |
| 19 | `fast` | 42 | killed |
| 34 | `fast` | 72 | killed |
| 24 | `normal` | 28 | survived |
| **47** | **`normal`** | **51** | **killed** |

### The consequence is the whole answer

At a penalty of 3.0, **`safe` (3.15 s/line) is the only preset whose debt per
line is negative** — the only one that never accumulates, and therefore the
only one safe at the lengths this protocol sends.

That is not a coincidence discovered here.  It is why `safe` has completed two
full verifications on this server while `normal`, `fast` and `turbo` have been
killed four times between them.  `auto` now returns `safe` for every OTR
message, which is the answer the wire has given repeatedly.

### On the model itself

Three refits, **every one correcting in the unsafe direction**: 2.0 with a
budget of 28, then 2.0 with the burst charged properly, now 3.0.  Twice that
produced a release which got a handset killed.

So the budget is deliberately **not** the fitted value.  It stays at 15 against
a fitted 38–42, which is low enough that `auto` picks `safe` for everything
here while the arithmetic still picks a faster rate on a genuinely tolerant
server.  The model is a heuristic for an unknown server, not a licence to go
faster on this one.

**The tuning is finished.**  `safe` is the setting for irc.postman.i2p.  A
verification costs about seven minutes of pacing plus I2P transit, and that is
what this server allows.

**Confirmed on hardware the same evening:** a full responder-side verification
on `safe`, 12m12s end to end, no disconnect — the third on this setting.  The
DAKE2 send took 48s where the model predicts 47.9s for 17 fragments, so the
pacing is doing exactly what it is told and the remaining time is I2P transit
and two 47-fragment proofs in each direction.

138 tests, 3 further mutants killed.

Full suite 3138 passed / 44 skipped / 1 xfailed.

---

## v10.26.1 — the burst was the expensive part

*2026-09-05.  `VERSION → 10.26.1`.  `otrv4_core` unchanged at 0.10.28.*

`auto` was killed on its first real run — an SMP1, 19 of 23 fragments, at
`fast`:

```
19:22:08 Server: Closing Link: FierceRidge[...] (Excess Flood)
19:22:08    Fragment pacing was 'fast' for that send, and is 'safe' now.
```

That second line is the v10.25.3 fix earning its keep: without it the report
would have said `safe`, which is what the rate had already been changed to.

### Two errors in the v10.26.0 model

**The burst was charged as a paced line.**  Debt was `n × (PENALTY − cost)`
for every line — but the lines covered by the allowance go out back to back
at essentially zero interval, so the server charges each of them the **full**
penalty while the client waits almost nothing.  At `fast` that is four lines
and eight seconds of debt spent before the message has properly started,
against a budget of fifteen.  **A burst is nearly free in seconds and
expensive in debt**, and the first model had that exactly backwards.

**The budget was too high.**  With the debt corrected, the four real
observations bracket it tightly:

| lines | rate | debt | outcome |
|---|---|---|---|
| 17 | `fast` | 21 | survived |
| **19** | **`fast`** | **23** | **killed** |
| 34 | `fast` | 38 | killed |
| 24 | `normal` | 4 | survived |

Survived at 21, killed at 23.  The real budget is about 22; this uses **15**.

### The answer is not the one `auto` was built for

At `fast` the corrected limit is **eleven lines**, and the shortest OTR
message is sixteen.  So `auto` now returns `normal` for every real message,
and the honest reading is that **`normal` — whose debt per line is exactly
zero — is the floor on this server**, not that `auto` found something clever.

It is kept because the arithmetic is the useful part: on a more tolerant
server the same rule picks `fast`, and on a stricter one it picks `safe`,
without anybody rewriting it.  `normal` is still 35% faster than `safe`, which
is the whole of the speed-up that was ever available here.

### A third defect from the same log

```
29s since our last OTR message (23 fragments).
```

The 29s came from the DAKE3 that landed and the 23 from the SMP1 that was cut
off at fragment 19 — because `_last_otr_sent` records only *successful* sends,
and the send that earns a flood kill is by definition the one that failed.
Two different messages in one sentence, in the report whose whole job is to
say what was happening.  The start time is now recorded beside the fragment
count, so the pair belong to each other.

137 tests, 7 further mutants killed.

Full suite 3137 passed / 44 skipped / 1 xfailed.

---

## v10.26.0 — `auto`: the limit is a rate AND a length

*2026-09-05.  `VERSION → 10.26.0`.  `otrv4_core` unchanged at 0.10.28.*

Suggested from the handsets: *"maybe do the DAKE fast and then normal for SMP
as SMP is huge hybrid encryption plus PQC"*.  The data supports it, and says
the cut-off sits slightly further out than that.

### Fitting the server

Three observations on irc.postman.i2p, all 2026-09-05, all at 403–406 byte
fragments:

| lines | interval | outcome |
|---|---|---|
| 24 | 0.54 s/line | survived (a DAKE2 at `turbo`) |
| 34 | 0.97 s/line | **killed** — `Excess Flood` (an SMP2 at `fast`) |
| 24 | 2.00 s/line | survived (a full DAKE at `normal`) |

Fit a leaky bucket: the server charges `PENALTY` seconds a line, the allowance
refills a second a second, and the connection dies when debt passes `BUDGET`.
Debt after *n* lines at interval *i* is `n × (PENALTY − i)`.  The killed case
needs `BUDGET < 35`; the survived case needs `BUDGET ≥ 35`.  That pins
**`PENALTY = 2.0`, `BUDGET ≈ 35`**.  A penalty of 1.5 is inconsistent with the
pair.

### The consequence

**At or above the penalty, debt never accumulates and any length is safe** —
which is why `normal` carried a whole DAKE and `safe` two whole verifications.
Below it, the safe length is the budget over the shortfall.  So the limit is
not a rate, it is a rate *and* a length, and a short enough message can go
faster than any sustained rate could.

Fragment counts, measured: DAKE1 16, DAKE2 24, DAKE3 19, SMP1 23, **SMP2 47,
SMP3 47**, SMP4 20.  Only the two big proofs are long enough to exhaust the
budget at `fast` — which is exactly the message that got a handset killed.

`/fragrate auto` picks per message:

```
DAKE1  16 → fast     SMP1  23 → fast
DAKE2  24 → fast     SMP2  47 → normal
DAKE3  19 → fast     SMP3  47 → normal
                     SMP4  20 → fast
```

That is the suggestion, plus SMP1 and SMP4 which are also short enough.  On
the fitted model it should take a verification from about 6.8 minutes of
pacing to about 3.9, with the two messages that actually earned a kill still
at a rate whose debt is zero.

### What it is not

`BUDGET` here is **28**, 20% under what was measured, and `auto` is **opt-in**
— the default stays `safe`.  Two data points and a straight line through them
is not a proof.  The rule assumes the debt drains between messages, which
holds because an OTRv4 handshake waits tens of seconds for each reply and
nothing here sends two long messages back to back.

`turbo` is excluded from `auto` deliberately: it is the preset for finding a
ceiling by hitting it, which is not a thing to do automatically.

`/fragrate auto` prints where the cut-off falls and says the rule is fitted
rather than proven, because a boundary nobody can see is one nobody can check.

126 tests, 6 further mutants killed.

Full suite 3126 passed / 44 skipped / 1 xfailed.

---

## v10.25.3 — the server answered: Excess Flood

*2026-09-05.  `VERSION → 10.25.3`.  `otrv4_core` unchanged at 0.10.28.*

The question left open since v10.25.0 has an answer.  Both handsets at a fast
preset, mid-verification:

```
18:46:57 [LucidDusk] 🔐 DAKE 2
18:46:57 [LucidDusk] 🟢 OK                      <- 24 fragments in 13s
...
18:52:58 [LucidDusk] ⚠ LucidDusk disconnected: Excess Flood - OTR session ended
```

**irc.postman.i2p enforces a flood limit, and it is below `fast`.**  The peer
was killed while sending a 47-fragment SMP2.  `safe` — the default since
v10.25.1 — has now completed two full verifications; `fast` and `turbo` have
not survived one.

That also settles the 17:42 disconnect from v10.25.0 by contrast rather than
by proof: a real flood kill on this server produces a named reason, and that
one produced none.  Two different events.

### The gap it exposed

The peer was killed.  **This client carried on at the same rate having learned
nothing**, because only an `ERROR` addressed to us counted as evidence.

Both ends of an OTRv4+ conversation run this client at whatever preset the
pair agreed, and the messages are symmetrical — SMP2 and SMP3 are 47
fragments each.  If their SMP2 was too fast for this server, our SMP3 was
about to be.  The peer's kill is the cheapest warning available, because it
arrives before ours.

A flood-shaped QUIT reason from a peer we hold a session with now drops this
end to `safe` as well, and says why:

```
⚠ LucidDusk was disconnected by the server for flooding, at the same
  fragment rate this client is using.
   Pacing dropped to 'safe' here too — the next long message from this end
   would have been the one to go.
```

The reason string is attacker-controlled: a peer can `/quit` with any text,
including that one.  The worst it buys them is making us slower, which is why
acting on it is safe — and why nothing ever raises the rate automatically.
The quit reason was also reaching the terminal unsanitised, which is fixed
here.

### Two defects the killed handset's own log exposed

The other side of that event was the useful one. Four new mechanisms fired
correctly — the automatic backoff, the ERROR handler, the four-line disconnect
report, and the v10.24.0 session preservation — and two things were wrong.

**The report named the retreat, not the cause.**

```
18:52:57 [sys] The server complained about the send rate - pacing dropped to 'safe'
18:52:57 [sys] Server: Closing Link: LucidDusk[...] (Excess Flood)
18:52:58 [sys]    43s since our last OTR message (46 fragments).
18:52:58 [sys]    Fragment pacing was 'safe'.
```

It was not `safe`.  34 of those 46 fragments went out in 33 seconds, which is
`fast`.  `_note_possible_flood` had already dropped the live value one second
earlier and the report read it — so on the single path the report exists for,
it named what we had retreated to rather than what earned the kill.  The
preset in force is now recorded when a send starts, before anything can
change it, and both values are shown when they differ.

**The reconnect contradicted itself.**  Two lines apart, about one session:

```
🔐 1 OTR session(s) kept through the reconnect — identity keys and pinned
   fingerprints unchanged.
⚠ OTR sessions lost on reconnect - /otr IvoryDelta
```

The second was left over from when `_try_reconnect` really did clear the
sessions.  Of the two it was the wrong one, and it is the one that tells the
user to throw away a working session and spend four minutes rebuilding it.  It
now lists only peers with no live session, and says so in those terms.

101 tests, 8 further mutants killed.

Full suite 3101 passed / 44 skipped / 1 xfailed.

### Where this leaves the speed question

`safe` is the answer for this server until someone measures otherwise, and a
verification costs about seven minutes of pacing on top of I2P transit.  The
remaining levers are structural rather than tunable — the fragment count is
set by ML-KEM-1024 and ML-DSA-87 message sizes and by base64 — and none of
them is worth touching for the 8% they would return.

---

## v10.25.2 — the tuning number was measuring the burst

*2026-09-05.  `VERSION → 10.25.2`.  `otrv4_core` unchanged at 0.10.28.*

Second full two-handset run, both sides on v10.25.1 at `safe`.  **The
responder path worked again** — `Passphrase stored — verifying…` →
`SMP step 2/4 · Passphrase accepted - answering the challenge…`, no
`ValueError`.  Second hardware confirmation of the v10.24.0 fix.

Both sides also matched the pacing model exactly:

| leg | observed | predicted at `safe` |
|---|---|---|
| DAKE1 send, 16 fragments | 47s | 45s |
| SMP1 send, 23 fragments | 66s | 67s |
| SMP2 send, 47 fragments | 141.8s | 142.3s |

### The defect

`/fragrate` on the initiator reported:

```
Last multi-fragment send: 2 fragments in 0.6s (3.32 lines/sec).
```

3.32 lines/sec, on a preset whose sustained rate is 0.32.  A 60-second
heartbeat is two fragments, both of which come out of the burst allowance
without waiting — so it measured the burst and called it the rate, overwriting
the 23-fragment SMP1 sample at the moment the number was being read to decide
whether to go faster.

Sends shorter than the burst plus three paced lines are no longer recorded.

**And the threshold has to follow the preset**, which is the part a fixed
number would have got wrong: `safe` and `normal` clear two lines before the
penalty bites, `fast` four and `turbo` eight.  A flat threshold of five is
three paced lines on `safe` and *pure allowance* on `turbo`, where it would
have reported 8 lines/sec for a preset whose sustained rate is 2 — the same
defect, one preset along.  Caught by a parametrised test rather than by
review.

79 tests, 4 further mutants killed.

Full suite 3079 passed / 44 skipped / 1 xfailed.

**Still open:** whether irc.postman.i2p tolerates anything faster than `safe`.
`normal` completed a full DAKE cleanly at 18:26 including a 24-fragment send,
and separately coincided with a disconnect at 17:42 while idle and with no
ERROR line.  One success and one ambiguous failure is not an answer.
`TWO_DEVICE_TEST.md` section 6 is the ladder for getting one.

---

## v10.25.1 — back to the rate that was working, and say why next time

*2026-09-05.  `VERSION → 10.25.1`.  `otrv4_core` unchanged at 0.10.28.*

v10.25.0 made the ircd penalty (`normal`, 2.0s a line) the default on the
arithmetic.  The first real run at it ended like this:

```
17:40:38 [LoneStyx] 🔑 Starting OTR session with LoneStyx…
17:41:08 [LoneStyx] 🔐 DAKE 1
17:41:08 [LoneStyx] 🟢 OK
17:41:08 [LoneStyx]    waiting for their answer…
17:42:03 [sys]   ⚠ Server closed the connection. Reconnecting automatically…
```

**The default is `safe` again.** One observed disconnect is enough: a lost
handshake costs minutes on I2P, and the conservative rate is the one that was
already working.  `normal`, `fast` and `turbo` remain, opt-in, through
`/fragrate`.

### What that log does not establish

It is worth being precise, because the obvious reading is not supported:

- **No ERROR line arrived.**  Most ircds send `Closing Link: … (Excess
  Flood)` before a flood kill.  The client would have printed it — v10.25.0
  added that handler — and did not.
- **The disconnected side was idle.**  It finished sending DAKE1 at 17:41:08
  and the connection went 55 seconds later, while it was waiting.  A flood
  kill lands during or just after the burst.
- **The 30 seconds to send DAKE1 is exactly what `normal` predicts** for 17
  fragments, so the pacing was doing what it was told.
- **An I2P SAM tunnel dropping looks identical from here.**

So this is a retreat to a known-good value, not a diagnosis.  Calling it a
flood kill would be a guess presented as a finding.

### Making the next one answerable

`_report_disconnect_context` prints, on every unexpected close:

```
   No ERROR line from the server — a flood kill usually sends one first.
   240s since the last message from the server.
   55s since our last OTR message (17 fragments).
   Fragment pacing was 'safe'. /fragrate to change it.
```

Four facts, and between them they separate a flood kill from a ping timeout
from a dead tunnel.  Nothing sensitive: counts, seconds, a preset name, and a
sanitised server string.

### A hazard found while looking, and deliberately not fixed

`handle_message` runs on the receive thread, so a responder's DAKE2 — 24
fragments, about 72 seconds at the default pacing — is sent from inside
`_recv_loop`, which spends that time in `time.sleep()` and cannot read the
socket or answer a `PING`.  The same disease was fixed for the SMP path
(`_handle_data_message` offloads to `_smp_executor`, with a comment saying
exactly this); the DAKE path never was.

It is **not** fixed here, for two reasons.  It does not explain the disconnect
above — that was the initiator, whose sends run on the main thread.  And
fixing it means sending on a worker, which means the `DAKE 2 / OK` report has
to move onto a completion callback to keep firing only after the send actually
succeeded — a restructure of the handshake display on the same day it first
worked end to end.  Recorded in the docstring, and a test asserts the record
is still there.

### Also

`safe` gets its two-line burst back.  Reproducing the old schedule with a
one-line allowance made a two-fragment message take 3.15s where the old code
took 0.30 — slower, in the name of reproducing it.  It now tracks the old
schedule to within one line's cost at every count from 2 to 60.

69 tests in `test_irc_fragment_pacing.py`, 8 further mutants killed.

### And a test that was passing by the clock

Chasing the disconnect turned up three failures in
`test_xmpp_keepalive.py::TestFailureCountIsPerSession` that had nothing to do
with any of this — **and that a full-suite run had reported green a few hours
earlier on identical code.**

`_FakeClient.__init__` measures `_last_inbound` against the real
`time.monotonic()` (`now - 10_000` for a silent stream).  The driver then
replaces that clock with a simulated one starting at 0.0, so
`_stream_quiet_for` was computing `0.0 - (real_uptime - 10_000)`.  On a host
up for less than about 2.8 hours that is positive and the stream reads as
silent, which is what the test needs.  Past that it goes negative, the stream
reads as busy, the probe is skipped and the counter never climbs.

So those tests passed or failed **according to the machine's uptime**.  The
v10.25.0 release note in this file claimed "3053 passed" and that was luck,
not evidence: the same commit checked out clean and re-run reports 3050 passed
and 3 failed.  Corrected here rather than quietly.

`_run_loop` in the same file had always rebased `_last_inbound` onto the
collapsed clock and said why.  The other two drivers never did.  They do now,
and the fix is verified against simulated uptimes of 500 000 and 5 000 000
seconds as well as the real one — a fourth test, in the second driver, was
failing at the higher values.

Full suite 3069 passed / 44 skipped / 1 xfailed.

---

## v10.25.0 — the handshake was mostly this client sleeping

*2026-09-05.  `VERSION → 10.25.0`.  `otrv4_core` unchanged at 0.10.28.*

First full two-handset run of v10.24.1 on irc.postman.i2p reached **SMP
VERIFIED** — the responder bug is fixed and the staged DAKE output works. It
took seventeen minutes, and about **ten of those were this client sleeping
between IRC lines.** Not I2P latency, not the PQC computation.

### Where the time went

A 12 KiB SMP2 is 48 IRC lines. The I2P path slept 6s after every second
fragment — an average of 3.15s a line — while the clearnet path in the same
function had always used the model mainstream ircds actually implement: a
leaky bucket, each line costing a fixed penalty, the allowance refilling one
second per second, at 2.0s a line with a burst. The overlay path was paying
roughly double, with no reason recorded.

The model predicts the observed log closely: SMP1 at 23 fragments predicts
69s, and the handset shows 75s between "Challenge sent" and the send
finishing. That agreement is why the rest of this is arithmetic rather than
hope.

| | fragments | pacing |
|---|---|---|
| before (fixed 380, 6s/2 lines) | 198 | 9.8 min |
| `safe` (the old rate, kept) | 185 | 9.3 min |
| **`normal` (default, ircd penalty)** | **185** | **5.7 min** |
| `fast` | 185 | 2.6 min |
| `turbo` | 185 | 1.1 min |

### `/fragrate`

The sweet spot for a given server cannot be derived, only found. `/fragrate`
reports what the last multi-fragment send actually achieved, so a rate can be
raised, tried on a real handshake, and kept or reverted **on evidence**. In
memory only, like everything else this client holds.

`fast` and `turbo` are above the standard ircd penalty and say so when
selected. If the server complains — `Excess Flood`, `Max SendQ exceeded`,
`throttl`, and the rest — the client drops to `safe` immediately, says why,
and **never raises it again on its own**: a server that threw us off once will
do it again, and an automatic recovery would rediscover the limit the
expensive way, mid-handshake.

### A latent bug found on the way

The fragment size was a fixed 380 for every I2P line. The binding limit is not
the line we send, it is the one the **recipient** sees —
`:nick!user@host PRIVMSG target :<fragment>` — and the prefix is added by the
server after we hand the line over.

380 was sized for a worst case that it did not actually cover. With a
thirty-character nick sending to a thirty-character target over a b32 host
cloak the line comes to **520 bytes**, and the server truncates it — taking
the fragment's terminating `.` with it and corrupting the message. It has not
bitten because the nicks in use are short (the tested session had 31 bytes of
headroom), but it was there.

The size is now computed: from the prefix the server echoes back with our own
JOIN when we have it, and from our nick plus a worst-case `user@host` when we
do not. For the tested session that is 403 rather than 380 — 13 fewer
fragments across the handshake.

The first attempt at this had the same bug in a new place: `max(380,
computed)` still returned 380 when the real limit was 364. A floor may be a
fallback for not knowing; it may never override knowing. Caught by a test,
not by review.

### And a docstring that claimed a protection that does not exist

`OTRMessageFragmenter.fragment` said every multi-fragment message was padded
to a uniform fragment count so an observer could not tell DAKE1 from DAKE3 by
counting IRC lines. No such padding is implemented and no `MIN_FRAGMENTS`
constant exists anywhere in the file. The claim described an intention, and a
reader checking whether the traffic pattern was protected would have found the
answer and been wrong.

The claim is removed rather than the padding added: padding every message to
48 fragments costs more than this whole release saves. It is now recorded as a
known limitation. On I2P the fragment count is visible to the IRC server and
to nobody else.

### Tests

`test_irc_fragment_pacing.py`, 53 tests, 12 mutants killed. Three of those
mutants survived the first attempt — the ceiling masked the bare-nick check,
the inter-line floor masked the bucket cap, and nothing pinned the safety
margin at all — and the notes on those tests say so, because a test that
cannot fail is worse than no test.

Full suite 3053 passed / 44 skipped / 1 xfailed — **and that figure was
wrong**: three tests in `test_xmpp_keepalive.py` pass or fail according to the
host's uptime, and that run happened to be inside the window where they pass.
Re-run on a clean checkout the same commit reports 3050 passed and 3 failed.
See v10.25.1.

**Not hardware-tested.** The arithmetic matches the observed handshake, but
whether irc.postman.i2p tolerates the new default is exactly the thing only a
real run can answer. `TWO_DEVICE_TEST.md` section 7 says how to find out
without losing a session to it.

---

## v10.24.1 — a nick is not an identity, and the client now says so

*2026-09-05.  `VERSION → 10.24.1`.  `otrv4_core` unchanged at 0.10.28.*

Follow-up to v10.24.0, raised in review of it.  Sessions now survive a
transport reconnect, which makes one confusion **likelier, not rarer**: a peer
comes back under a different IRC nick, the preserved session is keyed by the
old one, and nothing matches.  Both ways that showed up were silent.

**An encrypted message from a nick with no session.**
`_handle_data_message` opened with a bare `return`.  The message was dropped
and nothing was printed — indistinguishable from the peer having said nothing.

**A live nick change.**  The server says `OldNick` is now `NewNick`; the
client updated the channel user list and the OTRv4+ marker and said nothing
about the encrypted session it holds under the old name.

Now:

```
🔴 OTR SESSION NOT CARRIED OVER
   IronFenrir is now SwiftOmega. The encrypted session stays with
   IronFenrir: keys follow the handshake that made them, not a name the
   server has just reassigned.
   Run  /otr SwiftOmega  to start a new session with them, then compare the
   fingerprint against the one pinned for IronFenrir before you trust it.
   /endotr IronFenrir  clears the old session when you no longer want it.
```

**The session is not moved, and that is the feature.**  Following a rename
would mean encrypting to whoever holds a name now, and the server hands names
out and takes them back — the one mistake that turns a preserved session into
a leak.  A new DAKE is required.  A test asserts the re-key does not happen,
and a mutant that adds it is caught.

**The two messages differ in what they claim, on purpose.**  On the live-NICK
path the server told us authoritatively that one connection changed name, so
that message names both nicks.  On the undecryptable-message path there is no
evidence at all about the sender — the message did not decrypt — so it reports
only what is true: no session for this nick, sessions held for these others,
and *if* this is one of them, their keys stayed behind.  A guess printed as a
fact, next to a fingerprint the user is about to rely on, is worse than
silence.

The trigger is a message from an unauthenticated stranger, so the warning is
once per nick and the set of warned nicks is bounded at 64.  Establishing a
session clears that nick's entry, so a peer who later loses a session is
reported again rather than going quiet for the rest of the process.

24 tests in `test_irc_nick_session_diagnostic.py`, 8 mutants killed —
including the silent drop returning, the session being re-keyed onto the new
nick, and a hostile nick's terminal escapes reaching the panel.

Still not hardware-tested; this is step 7 of `TWO_DEVICE_TEST.md`.

---

## v10.24.0 — the responder could not answer, and a tunnel blip killed the session

*2026-09-05.  `VERSION → 10.24.0`.  `otrv4_core` unchanged at 0.10.28.*

Two real-device failures and a handshake that was hard to read.

### 1. "Could not answer the held request: ValueError"

Two handsets. The receiving side got all the way through the guided flow —
consent prompt, `y`, hidden passphrase entry — and then:

```
🔐 Passphrase stored – verifying...
🔐 Could not answer the held request: ValueError
```

**Root cause.** `_consume_secret_line` stored the passphrase with
`session_manager.smp_storage.set_secret(...)`.  That call writes the file and
stops there.  The engine copy — the one
`resume_held_smp1_generate_smp2()` reads — was never bound, so Rust failed
closed with

```
SMP protocol: secret still not set: cannot answer the held SMP1
```

which the PyO3 wrapper raises as `ValueError`.  Reproduced exactly against the
real engine in `tests/test_irc_smp_responder_resume.py`.

The initiator never showed it because `_start_smp` binds the secret itself on
the way past.  One path bound and the other did not; the asymmetry was the
whole defect.  `set_smp_secret` is the two-layer write — storage **and**
engine — and is what the XMPP client has always called here.  Binding twice on
the initiator path is deliberate: `session.set_smp_secret` permits a rebind in
`IDLE` and `SECRET_REQUIRED`, and one extra SHAKE-256 stretch is a better
trade than two paths that differ.

**The diagnostic was the second defect.** The handler printed
`type(exc).__name__`, turning a sentence that says exactly what is wrong into
the word "ValueError" — and cost a two-handset session to work out.  It now
prints the engine's own reason, sanitised and length-capped.  Every string
raised on that path is a fixed literal in `Rust/src/smp.rs` and the passphrase
is not an argument to any call made there.

Three smaller repairs alongside it:

- `_resume_smp` refuses when the flow holds no request, so a second `y` or a
  post-decline resume says so rather than surfacing an engine error.
- A failed resume returns the flow to `IDLE`, not `FAILED`: nothing was
  compared, so nothing failed, and the user can retry cleanly.
- `Session.resume_held_smp1` asks `has_held_smp1()` before consuming and
  clears `_smp_secret_required` **after** the engine has produced the answer.
  Clearing it first left the session claiming no request was outstanding while
  the engine still held one.

`_redact_secret` is new: on the one path where an error is reported while the
passphrase is still in scope, the message is scrubbed first.  Nothing there is
known to quote its argument — "known" being a property of today's code.

### 2. A SAM tunnel blip destroyed every encrypted session

The I2P tunnel dropped, IRC went with it, and the OTR session became unusable;
the only way back was `/quit` and a full restart.

`_try_reconnect` was doing it on purpose: `ratchet.zeroize()` on every session,
the root and chain keys wiped by hand, then `session_manager.sessions.clear()`.

**A transport interruption is not a security boundary.** The XMPP client has
never treated it as one — `_on_disconnected` drops trades and presence,
rebuilds the tunnel, reconnects the stream and leaves `self.otr.sessions`
untouched.  The double ratchet is a property of the two peers, not of the
socket that carried the bytes.  IRC now matches.

**Kept:** the session objects, and with them the ratchet, root and chain keys,
message counters, the pinned fingerprint and the SMP state.  The identity key
was never touched here and still is not, so a reconnect does not look like a
new person.

**Dropped, each for its own reason:** half-reassembled inbound messages (their
remaining fragments died with the socket, and keeping the prefix means the
next connection's fragments get appended to it); an armed passphrase prompt
(it must not outlive the thing it was armed for — the other half of INV-06);
a pending consent question.

**Replayed: nothing.**  Not a data message, not a fragment, not an SMP
message.  OTRv4 replay protection is not something to work around.

After the rejoin the client says what survived, because a padlock that came
through a transport drop with no explanation is a claim the user cannot check.
A verification that was part-way through is named, with what to do about it.
`/quit` still tears everything down — preserving across a blip must not become
preserving across a deliberate exit, and a test asserts it.

### 3. The handshake says which stage it is on

```
🔐 DAKE 1
🟢 OK
   waiting for their answer…
🔐 DAKE 2
🟢 OK
🔐 DAKE 3
🟢 OK
🟢 OTR SESSION READY
   DAKE 🦀 Rust | Ratchet 🦀 Rust | SMP 🐍 Python
```

The header and the verdict come from one call, made after the operation
returned.  That is structural rather than tidy: there is no code path that
prints a header on its own, so there is none that can print `OK` for a stage
that has not succeeded.  The initiator's stage 1 reports from the *result* of
the send — a DAKE1 that never left the socket is not a completed stage.  A
failure prints against its own number: `🔴 FAILED — reason`, sanitised.

Fragment counts are not deleted, they are moved: `detail` goes to
`self.debug`, which reaches the debug panel only under `DEBUG_MODE`.  The TOFU
wording is untouched and pinned by a test — *pinned* and *SMP verified* remain
different states.

### Tests

`test_irc_smp_responder_resume.py` (38), `test_irc_reconnect_preserves_otr.py`
(36), `test_irc_dake_stages.py` (33).  The responder file drives the real
`otrv4_core.RustSMP` rather than a stubbed manager — a stub cannot express
this bug, which is why the c3070e7 suite was green throughout — and enters at
`handle_chat_message`, where the user enters.  13 of its tests fail against
v10.23.2.  16 mutants killed across the three areas, including the storage-only
write, the resume guard, the fail-open session check, `OK` printed regardless
of outcome, and the initiator reporting `OK` without checking the send.

Two-handset re-test of all three is still outstanding, and `TWO_DEVICE_TEST.md` is new: it says what the suite proves, what it cannot (the Termux hidden read, a real SAM tunnel dropping, a resumed ratchet actually carrying messages), and the order to check them in.

---

## v10.23.2 — the guided /smp existed and was unreachable

*2026-09-05.  `VERSION → 10.23.2`.  `otrv4_core` unchanged at 0.10.28.*

v10.23.0 shipped the guided SMP flow for the IRC client.  On a handset it did
nothing:

```
14:56:49 [sys]   Usage: /smp <command> [args]
14:57:07 [IronFenrir] ✅ SMP secret stored (🦀 Rust vault)
14:57:07 [IronFenrir] 🔐 Type  /smp start  to begin verification.
```

The masked prompt, the auto-start, the responder consent — all present, all
correct, none of it reachable.  `otrv4+.py` had **two** `/smp` dispatchers:
one in `OTRv4IRCClient.handle_command` and one in the
`EnhancedOTRv4IRCClient` override.  v10.23.0's branch went into the base
class.  The subclass claims `smp` before the `else` that delegates down, and
the subclass is the only class the program instantiates.

### What changed

**Bare `/smp` is handled in the class that runs.** Masked prompt, passphrase
stored in the Rust vault, verification started — one command, no second step.

**`/smp start` is the same thing.** It used to refuse with *"No SMP secret
stored — use `/smp <peer> <secret>` first"*, sending the user to the one
spelling that puts a shared passphrase in their own scrollback.  It now asks
for the passphrase when none is stored and starts when one is, exactly as the
XMPP client does.

**`/smp <secret>` verifies immediately** instead of storing and demanding
`/smp start`.  Nobody types that meaning "store but do not verify" — that is
`/smp-secret`.  It now also says the passphrase was echoed: the input line is
cleared on Enter, but a `script` capture recorded the keystrokes before the
erase, and saying nothing implies it was hidden.

**The dead dispatcher is gone.** 54 lines removed from
`OTRv4IRCClient.handle_command`, which also called `self._smp_verify` — a
method defined only on the subclass, so it would have raised `AttributeError`
had anything reached it.

**A passphrase is never asked for when there is nothing to verify.**
`_smp_session_ready` gates every spelling, fail-closed: a `session_manager`
that raises counts as not ready.  A prompt for a session that does not exist
is a shared secret typed for nothing, and the user cannot tell the difference.

### Why the tests passed on code nobody could run

`test_irc_guided_smp.py` binds the flow methods onto a stub and calls
`_smp_verify` directly.  Every assertion in it was true.  Not one went through
`handle_command`, so *"can a user get here by typing /smp"* was never asked.

`test_irc_smp_command_routing.py` (27 tests) starts at the typing: every case
enters through the real `handle_command` on the real class.  13 of them fail
against v10.23.1 and 12 more error on the helpers that did not exist.  8
mutants killed, including the guard failing open on an exception, the inline
form storing without starting, and the inline form going straight to
`_start_smp` — which would start a second SMP run while the engine is holding
a peer's SMP1, leaving the peer waiting on a message that never comes.  Two
structural tests assert that the base class does not claim `smp` again and
that the subclass routes to `_smp_verify` — because two dispatchers for one
command is the defect, not the branch that was wrong.

Not yet re-run on the two handsets.

---

## v10.23.1 — DAKE1 was not sent twice, it was printed twice

*2026-09-05.  `VERSION → 10.23.1`.  `otrv4_core` unchanged at 0.10.28.*

From a handset, mid-handshake:

```
2026-09-05 14:52:59 [IronFenrir] 🔑 Starting OTR session with IronFenrir…
2026-09-05 14:53:50 [IronFenrir] 🔑 DAKE1 → sent - waiting for response…
──────────────── 🔴IronFenrir ─────────────────
2026-09-05 14:52:59 [IronFenrir] 🔑 Starting OTR session with IronFenrir…
2026-09-05 14:53:50 [IronFenrir] 🔑 DAKE1 → sent - waiting for response…
──────────────── live ────────────────
```

*"strange to be sending DAKE 1 twice"*.  It was sent once.  The timestamps are
identical, and a real second send carries a new one; the panel header and the
`live` separator bracketing the second copy are what `_switch_panel` prints
when you enter a tab.

`_switch_panel` replays a tab's whole buffer, and its only guard was *does this
panel exist*.  So being asked to switch to the tab already focused reprinted
it.  The inbound DAKE2's first fragment did exactly that: `_on_first_fragment`
computed `if _in_channel or _cur == s` — a condition that asks, in as many
words, to switch to the tab it is already on — while the initiator sat on the
peer's tab watching the handshake.

**The guard is in `_switch_panel`, not at the call site.** Fifteen call sites;
three of them checked `active_panel != peer` first and twelve did not, which is
the ratio that says the check belongs in the callee.  Switching to the active
tab is now a no-op returning `True` — `True` because `/switch` reads `False` as
*no such panel* and retries with a `#` prefix.  The one caller that should
still redraw the current tab is `/switch` itself, typed by a user who has
scrolled away, and it passes the new `force=True`.  The redundant clause in
`_on_first_fragment` is gone as well: leaving it would be a trap for whoever
removes `force` later.

Why a display bug is in the changelog at all: the panel is the only account the
user has of what the protocol did.  A client that shows a handshake step twice
when it happened once teaches the reader to discount duplicates — and a real
duplicate (a glare, a replay, a second initiator) is something they need to
see.

16 tests in `test_irc_panel_replay.py`, 5 mutants killed: guard deleted, guard
returning `False`, `force` defaulting to `True`, `force` ignored, and the old
`or _cur == s` restored.  Not yet re-run on the two handsets.

---

## v10.23.0 — the IRC client finally has the guided SMP flow

*2026-09-05.  `VERSION → 10.23.0`.  `otrv4_core` unchanged at 0.10.28.*

From a handset screenshot of an IRC session with `GlacialWolf`: a y/n trust
prompt on first contact, then *"Type `/smp` when you are ready to verify. It
will ask for the passphrase"* — followed, when you actually type `/smp`, by
*"Type `/smp <passphrase>` (it will be visible on this terminal)"*.

The client was promising a prompt it did not have. `set_input_mask()` had
existed since v10.15 with **no caller anywhere in the file**.

### Three gaps, all closed by reusing the XMPP machinery

**First contact pins instead of asking.** `Trust this fingerprint? Type y or n`
asked a question nobody can answer — there is nothing to compare against on
first contact — and it was *armed by a remote DAKE*, which is the shape INV-06
exists to keep out of the client. A **changed** fingerprint is now reported
loudly, left untrusted and never auto-accepted (INV-11); clearing it stays a
deliberate `/trust-reset`. INV-10 is untouched: nothing is written to disk, so
the pin lives for the session.

**Bare `/smp` asks, hidden.** Masked read, and the mask is lifted on every
exit — accepted, cancelled, too short, too long, storage failure. Four
parametrised cases plus a monkeypatched failure, because a mask left on hides
the user's ordinary chat and `_secret_request` left set makes their next line a
passphrase.

**The responder gets asked.** A peer's SMP1 with no stored passphrase was
parked by the engine and nothing surfaced it, so verification could only ever
be driven from one side. The consent prompt now appears, `y` opens the
passphrase read, and the answer **resumes the held SMP1** rather than
restarting — no second round trip over I2P.

### Why it imports `SmpFlow` instead of reimplementing it

INV-06 is the property that a remote peer may make the client ASK for the
passphrase but never make the next typed line BECOME one. In `SmpFlow` that is
structural — there is no edge from a remote transition into `AWAITING_SECRET`.
A second copy of the logic in the IRC client would have been a second chance to
get it wrong.

### The coverage that was asked for in the audit and never shipped

`SMP_UX_AUDIT.md` §7 item 4: *"IRC. Remove the remotely-armed generic capture
and extend INV-06's test to cover `otrv4+.py`."* The removal shipped in v10.15.
The coverage did not — `test_no_remote_input_capture.py` walks
`otrv4plus_xmpp.py` only, which is how this client could grow a masked read
with nobody checking what could reach it.

`tests/test_irc_guided_smp.py` now walks `otrv4+.py`'s inbound call graph from
eight entry points and asserts none reaches `_arm_secret_prompt` — and that the
two local paths do, because a reachability check that passes because nothing
reaches the armer at all is worthless. INV-06 lists both clients.

### Also

The passphrase length bounds lived in `otrv4plus_xmpp.py` only, so the IRC
client enforced **none** and took whatever was typed. `SMP_MIN_LEN` and
`SMP_MAX_LEN` are now defined in the engine and re-exported by the XMPP client,
because two clients disagreeing about how long a shared secret may be is a way
for one side to store something the other refuses.

### Verification

Python suite **2817 passed, 0 failed**. 53 new tests. Seven mutations — consent
prompt arming the read directly, mask never lifted, no length bounds, a changed
fingerprint auto-accepted, the old visible-typing advice returning, an ordinary
message at the consent prompt swallowed as consent, and the prompt not re-armed
after a non-answer — all seven killed. The sixth survived the first pass: I had
no test that an ordinary message at the consent prompt stays ordinary, which is
precisely what that prompt promises.

**Not tested between two handsets.** The flow was driven end to end against a
stub — initiator, responder, decline, cancel — but a real two-device run is
what would show whether the masked read behaves in Termux's raw mode.

---

## v10.22.0 — the chat prefix now says what protected the message

*2026-09-05.  `VERSION → 10.22.0`.  Display only; no protocol or wire change.*

From a handset screenshot: an SMP-verified session showed

```
[otr] <bob@xmpp-elite.i2p> ohhh lala
```

with `[otr]` in green, and nothing else on the line said the message was
encrypted or that the peer's identity had been proved. The reassurance was a
colour, and only a colour.

| | |
|---|---|
| 🔐 `[otr]` blue | encrypted **and** SMP-verified |
| 🔒 `[otr]` yellow | encrypted, identity **not** verified |

**Two padlocks, not one.** An unverified session really is encrypted, so a
padlock there is not a lie — but if it were the *same* padlock, a reader who
never ran SMP would get exactly the reassurance of one who did, which is worse
than no padlock at all. The glyph differs and the colour differs, because
either alone is weak: emoji are small on a handset, and colour is invisible to
some readers. Tests assert the two differ under ANSI-stripping *and* under
glyph-stripping, so a change that collapses one signal fails even while the
other still distinguishes them.

**The colours are the project's own, and the old one was wrong.**
`UIConstants.SECURITY_ICONS` says 🟡 yellow is `ENCRYPTED`, 🟢 green is
`FINGERPRINT` — pinned but *not* SMP-verified — and 🔵 blue is `SMP_VERIFIED`.
The prefix was using green for the strongest state, so the tab bar and the
message prefix were making different claims with the same colour. It is blue
now, which is also the colour of the existing `🔐 [smp]` marker.

**The half that would have been a security regression.** `_log_line_for_file`
is an allowlist (INV-03) that redacts message bodies by matching
`[otr] <peer> body`. A prefix glyph not listed in `_LOG_MARKERS` stops
`_strip_log_markers` removing it, the pattern then fails to match, and every
received message goes to the session log in plaintext. Both padlocks were
already in that tuple — checked before the change, not after — and a test now
derives the glyphs from the prefixes themselves and asserts each is registered,
so a third state with a new glyph fails here rather than in production.

Also: the message body is `_sanitise`'d in both states. It always was, but the
old branch structure made that easy to miss on a read, and a test now pins it —
a padlock must not arrive alongside a relaxation somewhere else.

### Verification

Python suite **2761 passed, 0 failed**. 18 new tests. Six mutations — same
padlock for both, differ by colour only, differ by glyph only, an unregistered
glyph, green for verified, and a prefix that ignores the SMP state — all six
killed.

**Not seen on a handset yet.** Whether 🔐 and 🔒 are actually distinguishable
in Termux's font at that size is the one thing only the device can answer; the
colour difference is the backstop if they are not.

---

## v10.21.1 — the payment URI was encoded in the QR and shown nowhere

*2026-09-05.  `VERSION → 10.21.1`.  Display only; no protocol or wire change.*

Reported on review of the v10.21.0 notes, and correct: the release said the QR
was generated from the `monero:` URI and sized for scanning, but it did not say
the URI itself was displayed — **because it was not**.

A reader whose wallet could not scan fell back to the bare address and
**silently lost the amount**. They would have had to be told it separately and
type it in, which is the sort of gap that produces a payment for the wrong
number without anyone noticing it went wrong.

There are three ways a wallet might take a payment, and the client cannot know
which one the reader has, so all three are now on screen:

1. **scan the QR** — easiest, and it carries the amount;
2. **copy the address** — works when the wallet cannot scan;
3. **copy the payment URI** — keeps the amount when the wallet understands
   `monero:` URIs but you cannot scan.

```
🔐 [tip] bob@example.i2p's Monero address:
📸 scan this, or copy the text below:
   [QR]

📬 address:
   8B…
🔗 payment URI (keeps the amount):
   monero:8B…?tx_amount=0.01
💰 amount: 0.01 XMR
📝 note: thanks for the call test
[tip] this client sends nothing — pay from your own wallet, and check the
      address before you do
```

**The order is reversed from v10.21.0, and that is the other half of the fix.**
The copyable text now comes *after* the QR. A 95-character address makes a
symbol about 22 rows tall; with the address above it, the address scrolled off
the top of a handset terminal and the last thing on screen was a caveat. What
you want to select should still be visible.

The amount is also a labelled field now rather than a clause inside the header
sentence. An amount that is not a plain decimal is still displayed — it is what
the peer claimed — but it is kept out of both the QR and the URI, and the line
says why.

Rendering moved out of `_on_response` into `format_address_block`, a pure
function, so it is tested on its output rather than through a manager's notify
strings.

### Verification

Python suite **2743 passed, 0 failed**. 10 new tests. Five mutations run
against the new display guarantees — drop the URI line, put the text back above
the QR, silently drop a hostile amount, let a hostile amount into the URI, move
the caveat off the end — all five killed. The ordering mutant survived the
first attempt: the test looked for the last line *containing* the address, and
the URI line contains it too, so moving the bare address above the QR still
passed. It now looks for the line that holds the address on its own.

---

## v10.21.0 — `/tip`: relay a Monero address, and only an address

*2026-09-05.  `VERSION → 10.21.0`.  `otrv4_core` unchanged at 0.10.28 — again
no Rust in this release.  One optional new dependency, `segno`, for QR codes.*

`otrv4plus_tip.py` asks a verified peer for their Monero address and shows it
as text and as a scannable QR. **It sends no money.** `/tip` is short for "ask
where to tip you"; the transfer is something you do afterwards in your own
wallet, looking at the address. Same courier posture as v10.20.0's trade
module, in a much smaller shape — one string instead of a state machine.

```
/setxmr <address>     store your own, persisted 0600
/setxmr clear         stop answering
/tip                  status
/tip <amount> [note]  ask a verified peer
/tipreply             answer a request that arrived before you configured one
```

### The interactive prompt in the specification is not implemented

The brief asked that an inbound request from a peer with no address configured
prompt the local user to type one, reading their next line.

That is the mechanism INV-06 forbids. `_apply_tofu` once ended by setting
`_pending[peer] = "smp_secret"`, so a peer who completed a DAKE could make the
user's next keystrokes mean something they had not chosen;
`tests/test_no_remote_input_capture.py` exists because of it. The address is
public and not worth protecting — **the mechanism is the problem, not the
payload**, and here the captured line would be *transmitted* rather than merely
stored. It might be a passphrase, or a message meant for someone else.

So an unanswerable request is reported and nothing is sent. The user answers
with `/setxmr <address>` then `/tipreply`: two deliberate keystrokes, both
locally initiated, neither of which a peer can cause. A test asserts the module
contains no reference to `input`, `getpass` or `stdin` at all.

### A real bug the tests caught

`_AMOUNT_RE` was `^\d{1,20}(\.\d{1,12})?$`. **Python's `\d` is Unicode-aware
for `str` patterns**, so it accepts Arabic-Indic `١٢٣` and every other decimal
digit range — and the amount is concatenated into a `monero:` URI that a wallet
scanner parses. Now `[0-9]`, explicitly. Found by a parametrised test, not by
review, and the comment in the source says so.

### A new engine hook, deliberately narrow

TLV type `0x0020` (above OTRv4's allocated `0x0000`–`0x0009`), routed to a
registered handler. `register_tlv_handler` refuses every type outside a
one-element allowlist, because a forwarding hook that accepts anything is how
an unreviewed second protocol gets bolted onto a session. `send_tlv` is
fail-closed to match: it will not open a session, will not queue, and will not
fall back to plaintext — a feature TLV that started a DAKE would hand a peer a
handshake they never asked for.

### The rest

- **INV-26 gates both branches**, and the response direction matters most: a
  response is a string the client is about to show the user as somewhere to
  send money.
- **No validation of the address.** Carried verbatim, any shape. An opinion
  about Monero's address format is one that starts rejecting valid addresses at
  a hard fork. The one rejected shape is an address containing a space, and not
  as validation — a space means two things were pasted, and sending half an
  address is worse than refusing.
- **Your address persists 0600; a peer's never touches disk** and goes on
  disconnect and `/quit`.
- **Nothing reaches the session log.** `tip` is absent from `_LOG_SAFE_TAGS`:
  an address is public, but a log of who asked whom for which address is a
  record of who paid whom.
- **`segno` is optional.** Missing library, or any exception from it, falls
  back to the plain address plus a one-line install hint — a QR is a nicety and
  a missing nicety must not withhold what the user actually needs. `error="l"`
  and `compact=True` bring a 95-character address down to 22×43, which fits a
  handset; a QR you have to scroll is not scannable.

### Verification

Python suite **2733 passed, 0 failed** on 3.12. 103 new tests. Six mutations
run against the security properties; four were killed on the first pass and two
survived — both because the tests I had written for them could not fail (the
URI is encoded into the QR image and never printed, so grepping the output for
`monero:` proved nothing; and the receiving party in the persistence test had no
store file to write to). Both tests were rewritten and both mutants then died.

**Not tested between two devices yet.** The QR has not been scanned by a real
wallet.

---

## v10.20.0 — a courier for multisig coordination, and no Monero code at all

*2026-09-05.  `VERSION → 10.20.0`.  `otrv4_core` stays at 0.10.28: there is no
Rust change in this release, and that is the headline rather than an omission.*

`MONERO_ESCROW_AUDIT.md` looked at putting Monero's multisig cryptography in
the Rust core and recommended against it. `monero-serai` is `0.1.4-alpha` from
May 2023 with every version yanked; its successor `monero-oxide` implements
multisig as **FROST** (`modular-frost 0.11`), which produces wallets
`monero-wallet-cli` cannot create, join or spend from; native Monero multisig
is experimental, off by default, and its enabling flag cannot be set over RPC;
and FCMP++ removes CLSAG, with the stressnet not supporting multisig at all.

So the client became a **courier** instead. It relays opaque base64 between two
Monero wallets the users run themselves, and holds no Monero code. No
Ed25519, no curve25519-dalek, no FROST, no consensus-coupled transaction
format, no MSRV bump, and nothing new that can panic inside a `panic = "abort"`
process while funds sit in a half-built multisig.

### What shipped

`otrv4plus_trade.py`, plus routing and six subcommands in the XMPP client:

```
/trade                    list open trades
/trade init <terms>       propose to the verified peer
/trade accept | decline   answer a proposal
/trade blob <base64>      relay one blob from your wallet
/trade confirm | cancel
```

Framing is `?OTRv4-TRADE:VERB:version|trade_id|seq|fields`, dispatched exactly
like `?OTRv4-FILE:` and travelling inside the established session — if the OTR
channel is unavailable the message is dropped, never downgraded. XMPP only,
same as file transfer; IRC's 510-byte lines make it pointless there.

### The two invariants this rests on

**INV-25 — it is not a wallet.** No wallet file is opened, no seed or spend or
view key read, no address derived, nothing signed. A blob is checked for
base64 alphabet and length and passed through verbatim; it is never parsed,
because parsing is the first step toward interpreting. The module's import
list is asserted *exactly* — `base64`, `hashlib`, `re`, `secrets`, `time`,
`typing` — so it cannot reach a daemon or a wallet at all, and its identifiers
are walked for anything key-, network- or wallet-shaped. This is INV-08 in its
strongest form: the keys do not cross the PyO3 boundary because they never
enter the process.

**INV-26 — no trade on an unverified or changed peer.** `is_smp_verified` is
checked on **every** message in both directions, not once when the trade
opens: a trade agreed at 09:00 and still running at 14:00 would otherwise span
five hours in which a session teardown goes unnoticed while blobs keep
flowing. Fail-closed like INV-12 — a predicate that raises counts as
unverified. The peer's fingerprint is bound at trade creation and re-checked
with it; a change cancels the trade and never re-pins (INV-11). Binding is to
the fingerprint and never to the I2P destination, which is `TRANSIENT` and
changes every session by design.

### Other properties, each because of a specific failure mode

- **Terms-hash echo.** The responder echoes a hash of the terms it read. A
  mismatch stops the trade rather than reconciling silently — the terms are
  the trade.
- **Strictly increasing sequence numbers** per direction. The concrete case:
  an ACCEPT captured and replayed after a CANCEL would otherwise put the
  proposer back into ACTIVE with no counterparty.
- **Trade id checked before the sequence advances.** The other order would let
  an unrelated id burn the replay window and wedge the trade.
- **24 KiB blob cap**, refused up front rather than sent and throttled halfway.
  This is a rate-limit constraint and a test derives it from the XMPP client's
  own `_RATE_MAX` so the two files cannot drift apart. Bigger blobs
  (`export_multisig_info` on a busy wallet, a large signed tx set) do not fit;
  the fix is to route them through the file-transfer engine, which already
  solved this, and that is deliberately not in this version.
- **Nothing reaches the session log.** `trade` is deliberately absent from
  `_LOG_SAFE_TAGS`, so every `[trade]` line is redacted by the INV-03
  allowlist rather than by a rule someone remembered. A blob is sensitive —
  the 2021 Monero disclosure included view-secret-key recovery by an
  eavesdropper on the setup exchange — and a test pins the tag's absence,
  because the obvious "improvement" is to add it so the transcript reads
  better.
- **State is in memory only**, cleared on disconnect, `/quit` and process
  exit. No resume: a trade restored from a file would mean trusting that file
  about who the counterparty was and how far it had got.
- **Terminal escapes stripped** from peer-supplied terms and reasons before
  anything prints them.

### No arbitration service

The project does not act as an arbitrator and ships no arbitrator key. 2-of-3
works — the third party runs a trade session like anyone else — but this
client holds none of the three keys, and a test asserts there is no code path
that could. That is a deliberate decision on legal grounds: holding one of
three keys is the part of an escrow design most likely to be read as a
financial activity.

### What it does not do, stated plainly

It cannot tell you a multisig address was formed from the right keys, that a
payment landed, or that a signature is valid. Your wallet does. Comparing the
multisig address with your counterparty out of band is the one check nothing
here can do for you, and [TRADE.md](TRADE.md) says so at the step where it
matters. This is a real limitation, and it is the price of the client not
becoming a wallet.

### Verification

Python suite **2627 passed, 0 failed, 43 skipped, 1 xfailed** on 3.12. 86 new
tests in `tests/test_trade_courier.py`. Six mutations run against the security
properties — SMP gate per-message, fingerprint re-pin, replay window, terms
hash, check ordering, blob cap — all six killed; the blob-cap mutant survived
the first attempt because the test tracked the constant instead of pinning it,
which is why the cap now derives from `_RATE_MAX`.

Two test stubs (`test_xmpp_keepalive.py`, `test_xmpp_session_lifecycle.py`)
gained `_clear_trades`, since the disconnect path now calls it.

**Not live-tested between wallets.** Nothing here has carried a real
`prepare_multisig` blob between two `monero-wallet-cli` instances yet. The
next step is [TRADE.md](TRADE.md)'s runbook on stagenet, by hand, on the two
handsets — which is also what will tell us whether 24 KiB is the right cap.

---

## v10.19.0 — PyO3 0.29 for GHSA-36hh-v3qg-5jq4, and IRC scrollback stops outliving the connection

*2026-09-05.  `VERSION → 10.19.0`, `otrv4_core 0.10.28`, `pyo3 0.24.2 → 0.29.2`.*

Two unrelated pieces of work that both landed on the same boundary between
"what the code says" and "what actually ships".

### PyO3 GHSA-36hh-v3qg-5jq4 — audited first, then upgraded

`BoundListIterator` and `BoundTupleIterator` computed `index + n` in
`Iterator::nth` / `DoubleEndedIterator::nth_back` before bounds-checking it and
then read the element with `get_item_unchecked`: `nth` can wrap and re-yield
from the front, `nth_back` can underflow and read past the storage. CVSS 8.7,
CWE-125, fixed in pyo3 0.29.0.

**Not reachable from OTRv4+.** The entire Python→Rust surface of `otrv4_core` is
`&[u8]`, `&str`, `u32`/`u64`, `bool`, `&Bound<PyByteArray>`, `&Bound<PyAny>` and
opaque pyclass handles. `PyList` and `PyTuple` appear nowhere in the crate;
`nth`, `nth_back` and `step_by` are called on nothing. There is no Python
sequence for the vulnerable iterators to walk. Severity for this project:
informational.

**Upgraded anyway**, to 0.29.2, because an unreachable bug in the boundary layer
is one refactor from reachable and the upgrade was clean: MSRV 1.83 against our
declared 1.85, `abi3-py39` still offered, and four transitive dependencies
*removed* (`indoc`, `unindent`, `memoffset`, `rustversion`) with none added.

**One API change, two call sites.** `Bound::downcast` was renamed `Bound::cast`
(same signature, `CastError` for `DowncastError`) — `ratchet.rs:718`,
`voice.rs:458`. Nothing about ownership, lifetimes, conversions or exception
propagation changed, and no secret material moved.

**Rebuilt, not just re-locked.** The `.so` was rebuilt with
`--features extension-module` and installed before anything was tested against
it, `NOTICE` was regenerated from the new graph, and the boundary tests drive
the installed module rather than the source tree.

Also fixed while in there: `cargo clippy --all-targets` reported 88 pre-existing
`unwrap_used` errors and 3 warnings, all in `#[cfg(test)]` code, which had been
hiding real findings. `deny(clippy::unwrap_used)` is now
`cfg_attr(not(test), deny(...))` — the shipped crate keeps the ban, where a
panic aborts the whole Python process; test code is where an unwrap *should*
panic. Clippy is clean under `--all-targets` for the first time.

### IRC history stopped outliving the connection

Reported from a real session: the client dropped, reconnected in five seconds,
found its own previous session still holding the nick, renamed itself, and
replayed the entire previous conversation into the new one — three times, with
the unread badge climbing `system(53)` → `system(105)` → `system(158)` and the
nick going `AngryMouse` → `BrokenNexus` → `HollowNexus`.

Three separate causes, three fixes:

- **Unbounded, never-cleared history.** `ChatPanel.history` had no ceiling and
  nothing emptied it, so a tab switch replayed to the start of the process. Now
  capped at 1000 messages, and `_purge_scrollback()` empties every panel — plus
  the unread counters and the recent-user sets — at every boundary between one
  connection and the next: disconnect, reconnect, `/quit`, and process exit via
  `atexit`, so SIGINT and unhandled exceptions are covered too. The terminal's
  own saved scrollback is cleared as well (`\033[3J`, because on Termux the
  visible history *is* the scrollback) on `/quit`, process exit and `/clear` —
  but **not** on an automatic reconnect, where blanking the emulator would
  destroy the error messages the user is reading to find out what just
  happened.
- **A reconnect that raced the server.** The backoff started at 5s and doubled;
  five seconds is shorter than any server's ping timeout, so the reconnect
  arrived while the ghost still held the nick. Now a flat 30/60/90/120s.
- **A permanent rename on 433.** The client took a fresh random nick and kept
  it, so one dropped connection cost the user their identity. Now a temporary
  nick is taken only if registration has not completed, and up to four attempts
  are scheduled to reclaim the original once the ghost has timed out.

`/clear` now clears everything rather than just the active tab, without touching
the connection; `/clear <panel>` keeps the old single-tab behaviour.

Timestamps carry the date: `TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"`, one
constant replacing four copies of `"%H:%M:%S"`. A debug-log line that read
`12:34:56.` with nothing after the dot was fixed at the same time — `%f` is a
`datetime` directive, not a `time.strftime` one, so `[:-3]` had been trimming
the literal `%f`.

**Honest about what this is not.** A Python `str` cannot be scrubbed from
memory; it is immutable and may be interned. The purge drops the last reference
the client holds, which is what stops the conversation coming back on screen —
the bytes stay in freed heap until the allocator reuses them. INV-24 is recorded
as `PARTIAL` for that reason. Anything that must genuinely be destroyed is not
kept in a chat panel at all.

### Also

`No module named 'socks'` now says what to install. The engine's import guard
blamed file placement for every failure — "ensure `otrv4+.py`, the
`otrv4plus.py` symlink and `otrv4_core.so` are in this directory" — which sent a
tester chasing three files that were all present and correct. The module comes
from **PySocks**, and the PyPI project literally named `socks` is an empty
placeholder (version 0, "should be deleted soon") that installs nothing, so
`pip install socks` succeeded and changed nothing. The guard now names the
missing module and its actual distribution, and `import socks` in `otrv4+.py`
carries the same explanation plus a check that what it imported really is
PySocks.

### Verification

`cargo test` 111 passed. `cargo clippy --all-targets` clean, 0 errors, 0
warnings. Release `.so` rebuilt and installed. Python suite **2538 passed, 0
failed, 43 skipped, 1 xfailed** on Python 3.12. 117 new tests across four files:
`test_dependency_advisories.py` (25), `test_pyo3_boundary.py` (44 — hostile
input against the installed module), `test_irc_history_privacy.py` (35), `test_import_diagnostics.py` (13). Eight
mutations run against the new assertions, seven killed, one confirmed
semantically equivalent (`>` vs `>=` in the prune, where `overflow` is 0 at the
boundary either way).

**Not live-tested on the two handsets yet.** The IRC reconnect and nick-reclaim
paths need a real dropped connection against a real server to exercise; nothing
here claims transport verification that has not happened.

---

## v10.18.6 — building a Python extension with no `.so` is now an error

*2026-09-05.  `VERSION → 10.18.6`.  Build configuration only; no code change.*

v10.18.5 added a **warning** when `crt-static` would drop the cdylib. A second
Alpine report showed why that was not enough:

```
$ CC=clang cargo build --release --features extension-module,pq-rust
warning: dropping unsupported crate type `cdylib` for target `x86_64-unknown-linux-musl`
warning: `otrv4_core` (lib) generated 1 warning
    Finished `release` profile [optimized] target(s) in 0.15s
```

**`--features extension-module` means "build the Python extension".** Finishing
without one is not a success worth reporting, and a warning is not enough: it
scrolls past in several hundred lines of compile output looking exactly like
rustc's own `dropping unsupported crate type` line — which is the line that had
already gone unread twice.

So with that feature on, it is a hard error naming both the cause and the two
fixes. Without the feature — `cargo test`, which wants only the rlib — it stays
a warning, because failing there would take the Rust test suite with it.

**`cargo test` on Alpine hits the same root cause** and is now documented: the
test binary links libpython on purpose (that is why `extension-module` is not
in `default`), and under `-static-pie` the linker asks for a static libpython
Alpine does not ship — `cannot find -lpython3.12`. The same `-crt-static`
makes it a dynamic link that finds `libpython3.12.so`.

### A test that would have passed on a broken message

The build script is compiled standalone by the test suite. Plain `rustc`
defaults to an older edition, where inline format captures like `{fix}` render
as that **literal text** — so the message went out as `{fix}` and a test
looking only for the `cargo:warning=` prefix passed anyway. The test now
compiles with `--edition 2021` to match cargo, asserts the build script
compiles without warnings, and asserts no unrendered placeholder survives into
the output. The message itself uses positional arguments so it is correct under
any edition.

3 new tests (24 in the file). Two mutations killed — the hard error downgraded
to a warning, and the hard error made unconditional. A third, reverting to
inline captures, correctly **survives**: at edition 2021 it renders properly,
so it is equivalent rather than a defect. Fixing the test's edition removed
that whole class of bug.

---

## v10.18.5 — and on musl it now produces a `.so`, not just an `.rlib`

*2026-09-05.  `VERSION → 10.18.5`.  Build configuration only; no code change.*

v10.18.4 got the musl build to *compile*. It then hit a second problem, and
this one is quieter, because the build **succeeds**:

```
$ cp target/release/libotrv4_core.so ../otrv4_core.so
cp: cannot stat 'target/release/libotrv4_core.so': No such file or directory
$ ls target/release/libotrv4_core.*
target/release/libotrv4_core.d    target/release/libotrv4_core.rlib
```

**musl targets enable `crt-static` by default**, and rustc cannot build a
cdylib against a statically linked C runtime. So it drops the crate type,
prints `dropping unsupported crate type` in one line among several hundred
lines of compile output, and **exits 0**. The `.so` that the whole build step
exists to produce is simply absent, and the failure surfaces one command later
as a `cp` that cannot find its source — minutes and several steps from the
cause.

Verified rather than assumed: forcing `+crt-static` on this machine's own
target reproduces it exactly — `warning: dropping unsupported crate type
'cdylib'`, and only an `.rlib` in `target/release/`.

**Two changes.** `Rust/.cargo/config.toml` turns `crt-static` off for the four
musl triples, restoring the cdylib; the resulting `.so` links musl dynamically,
which is what a musl Python needs in order to load it. And `build.rs` now warns
when `crt-static` is on, naming both the consequence and the fix — because
cargo finds `.cargo/config.toml` by walking up from the invocation directory,
so it *can* be bypassed, and a silent bypass returns you to a `cp` that fails
for no visible reason.

The warning is a warning and not an error on purpose: `cargo test` wants only
the rlib, and failing the build there would take the Rust test suite with it.

10 tests (21 in the file), 3 mutations applied and killed: the override
removed, the flag set the wrong way round (`+crt-static`), and the build.rs
backstop disabled. The build script is compiled and run standalone against a
synthetic environment, so both the musl case and the ordinary case are checked
on a machine that has no musl toolchain.

---

## v10.18.4 — the Rust core builds on musl

*2026-09-05.  `VERSION → 10.18.4`.  Build configuration only; no code change.*

On Alpine, or any musl toolchain, the build died before compiling a single
line of Rust:

```
pqclean/common/compat.h:20:21: error: missing binary operator before token "("
   20 | #  if !__GNUC_PREREQ(7, 1) // at least GCC 7.1
error: failed to run custom build command for `pqcrypto-mlkem v0.1.1`
```

**`__GNUC_PREREQ` is a glibc macro.** `pqcrypto-mlkem` vendors PQClean, whose
`compat.h` includes `<features.h>` and then uses it. musl ships a
`<features.h>` that does not define it, so the preprocessor meets an undefined
identifier followed by `(` — which is not a valid `#if` expression. Nothing is
wrong with the checkout; it is an upstream assumption that glibc is the only
libc, and there is no fixed release to move to: 0.1.1 is the newest
`pqcrypto-mlkem` published.

**`Rust/.cargo/config.toml` now supplies the macro** for the four common musl
triples. Three things make that safe rather than a blunt override:

* The definition is **logically identical to glibc's own**. Verified by
  compiling and running both against each other — glibc's
  `((__GNUC__ << 16) + __GNUC_MINOR__ >= ((maj) << 16) + (min))` versus the
  space-free form — across every version either side of the 7.1 boundary the
  header tests.
* It is written **without spaces**, because `cc-rs` splits `CFLAGS` on
  whitespace and a single space would truncate it into fragments that are not
  valid flags.
* It is keyed to the **musl triples only**. `cc-rs` prefers `CFLAGS_<target>`
  over plain `CFLAGS`, so a glibc build never sees it and cannot pick up a
  macro-redefinition warning from it — which matters on a project that just
  spent a release getting the build silent.

`CC=clang` is an equally good workaround and is documented alongside: the
clang branch of that header avoids `__GNUC_PREREQ` entirely.

**One caveat worth knowing.** cargo finds `.cargo/config.toml` by walking up
from the directory it is *invoked* in, not from the manifest. So
`cargo build --manifest-path Rust/Cargo.toml` run at the repository root
silently skips the fix and fails exactly as before. The README's build steps
already `cd Rust` first; that is now stated as a requirement rather than a
habit.

11 tests, 5 mutations applied and killed — including one that survived the
first attempt: changing `>=` to `>` in the macro passed, because a fixed list
of low GCC versions never reaches the minor-number comparison at all
(`__GNUC__ > maj` short-circuits the `||`). The equivalence cases are derived
from the compiler's own version now, so the boundary is actually exercised.
The end-to-end test compiles PQClean's real `compat.h` with musl's behaviour
simulated — an empty `<features.h>` shadowing the real one — and asserts it
fails without the flag and succeeds with it.

---

## v10.18.3 — a wrong `--peer` now looks like a wrong `--peer`

*2026-09-05.  `VERSION → 10.18.3`.  Python only.  No protocol change.*

A device run was started with `--peer bob@xmpp-elite` — missing the `.i2p`.
Nothing about that address is malformed: one `@`, a non-empty local part, a
non-empty domain, so `_check_jid` passed it happily. What followed looked like
a protocol bug for the whole session, and **both people concluded the software
was broken at the other end**.

Here is what actually happened, in order:

1. `/otr` sent a DAKE to `bob@xmpp-elite`. The server bounced it —
   `Communication with remote domains is not enabled` — printed once, with no
   explanation, and the run carried on.
2. The *peer's* DAKE arrived and established a session under their **real**
   JID, `bob@xmpp-elite.i2p`. So the log showed ENCRYPTED, fingerprints, TOFU
   pinning and the full SMP exchange, all working.
3. `/smp` said `no encrypted session with bob@xmpp-elite. Run /otr first` —
   about an address that could never have one — while a fully verified session
   sat under the real JID.
4. The verified banner printed twice, once per identity.

Every one of those lines was individually correct. Together they told the user
everything except the one thing that mattered.

**Three places now say it.**

* **At startup**, before a single stanza goes out: if `--peer` and `--jid` are
  on different servers, both are printed side by side, and when one domain is
  a prefix of the other the missing part is named with the corrected command
  to type. Not fatal — federated XMPP across domains is ordinary and this
  client should not refuse it — but a mismatch is worth stopping to read.
* **When the server refuses the domain**, that is a definitive answer about
  the address rather than a transient failure, and it now says so: which
  domain was refused, that you are on a different one, the likely truncation,
  and that nothing sent to that address will arrive.
* **When a command reports no session**, it now names the session that *does*
  exist under another address. "Run /otr first" is sound advice unless `/otr`
  can never work, in which case it sends the user round the same loop.

15 tests, 3 mutations applied and killed: the startup warning removed, one of
the four no-session messages left without the hint, and the truncation
detection disabled.

---

## v10.18.2 — the Rust core builds silent, and `Cargo.toml` is valid TOML

*2026-09-04.  `VERSION → 10.18.2`.  No behaviour change intended; the wire
format, the key schedule and every derivation are byte-for-byte unchanged.*

`cargo build --release` emitted **10 warnings**. It now emits none, and
neither does `cargo clippy` or `cargo test`.

### The one that was not cosmetic: `Cargo.toml` was invalid TOML

```toml
ed448-goldilocks-plus = {
    version          = "0.16",
    ...
}
```

**TOML 1.0 forbids newlines inside `{ }`.** Cargo's own parser accepts them as
an extension, so `cargo build` never said a word — while `maturin build` died
before compiling anything:

```
Caused by: TOML parse error at line 151, column 26
invalid inline table
```

Verified by building with maturin 1.7.8 and 1.8.1 (fails before the fix,
succeeds after, and both carry the licence field). Anything else that reads
the manifest with a conformant parser — packaging tools, licence scanners,
SBOM generators — rejected the file outright, which for a project that has
just taken on a dual licence and needs its metadata read by other people's
tooling is worse than a warning. It is a dedicated `[dependencies.…]` table
now, valid everywhere, with the same one-field-per-line layout and the same
resolved dependency.

### Nine deprecated nonce constructions, two of which could panic

`Nonce::from_slice` is deprecated in the generic-array the tree resolves. It
also **panics** on a wrong length rather than failing to compile. Seven sites
already held a `[u8; NONCE_LEN]`, where the size is a type-level fact, and
became `Nonce::from`. The other two took a *slice* of peer- or
disk-supplied bytes:

* the identity record's nonce, from a file that syncs between devices;
* the file-transfer key envelope's nonce, straight off the wire.

Both had a length check above them, so neither could actually panic — but the
panic was one moved guard away, and `panic = "abort"` in release means a panic
is the process. They use `try_into` and refuse now, which is what the rest of
the parsing in those functions already does.

### The rest

* **`Dakeresult::success` reported as dead code.** It is not dead: all three
  callers are behind `legacy-dake-keys`. Gated to match them, so the warning
  stays meaningful for the day it becomes dead for real. `#[allow(dead_code)]`
  would have silenced that permanently.
* **Two clippy `erasing_op` *errors*** on `sig[0*57..1*57]` in `ring_sig.rs`.
  Arithmetically clippy is right; the intent is a uniform four-field table
  where `n*57..(n+1)*57` on every line makes a field-order mistake visible
  against the spec. Documented allow rather than a rewrite that would lose
  that.
* **~40 further clippy findings** fixed: redundant closures, needless borrows,
  a `push_str` of one character, an `Option` replace, doc-list indentation.
  Four `too_many_arguments` and one `new_without_default` are documented
  allows — restructuring an authenticated message's argument list, or giving a
  passphrase vault a `Default`, are semantic decisions, not lint compliance.

### One test had to stop pinning a line number

`test_the_rust_core_declares_one_unsendable_pyclass` asserted
`found == ["dake.rs:183"]`. Adding the `legacy-dake-keys` gate above it shifted
the file by eight lines and the test failed reporting "the set of unsendable
pyclasses changed" — when the set had not changed at all; the same single
`DakeOutput` was eight lines lower. It now identifies the class by the struct
it marks. A check that cries wolf on unrelated edits is one whose expectation
gets bumped without being read, and for a test guarding thread affinity across
the executor boundary that is the whole value gone.

**Verification.** 111 Rust tests pass; the Python suite runs against a wheel
rebuilt from the changed source, not the old one. Five tests pin the manifest:
it must parse under `tomllib` (TOML 1.0 only), no inline table may span lines,
and the rewritten dependency must still resolve to exactly what it did.

---

## v10.18.1 — `/otr` can actually unstick a hung handshake now

*2026-09-04.  `VERSION → 10.18.1`.  A method that three call sites had been
calling since they were written, and that never existed.*

```
/otr
[otr] resetting stuck session with bob@xmpp-elite.i2p, retrying DAKE...
[otr] reset error: 'EnhancedSessionManager' object has no attribute 'end_session'
[otr] could not start DAKE with bob@xmpp-elite.i2p — try /otr again
```

**`EnhancedSessionManager.end_session` did not exist.** Three places in the
XMPP client call it — `_forget_otr` clearing a peer whose session should not
survive, the DAKE glare path yielding the initiator role, and `/otr`
force-resetting a stuck handshake. All three raised `AttributeError` into an
`except` that printed it and carried on, so **none of them ever tore anything
down**. The comment promising that `/otr` "can always unstick a hung
handshake" has been false since it was written, and stayed false until a phone
got wedged and said so out loud.

`terminate_session` could not stand in for it, which is presumably how the gap
survived: it terminates the session object but leaves the entry in
`self.sessions`, so the next `get_or_create_session` hands back the dead one
and the handshake stays exactly as stuck. `end_session` removes the session
*and* the DAKE engine, tolerates a half-built session that cannot terminate
cleanly — the reset has to work on precisely the sessions that are broken —
and is idempotent.

**It sends no DISCONNECTED TLV.** All three callers want a local teardown, and
announcing it would be wrong in two of the three: a stuck handshake has no
encrypted session to send through, and on glare we are about to answer the
peer's DAKE1 as responder, so telling them we disconnected first is the
opposite of what is happening. `SessionManager.end_session` keeps its TLV
because that one is the graceful goodbye; this is the reset path. The trust
database is untouched — a pinned fingerprint is long-term identity, and
forgetting it on reset would turn every reset into a fresh
trust-on-first-use decision.

### The half that was worse than the missing method

The reset's client-side cleanup sat in the **same `try`** as the engine
teardown:

```python
try:
    self.otr.end_session(peer)      # raised here
    self._encrypted.discard(peer)   # never ran
    self._last_dake1.pop(peer, None)
    ...
except Exception as e:
    print(f"[otr] reset error: {e}")
```

So one AttributeError on the first line skipped every line below it, and a
failure in the *engine* also left the *client* holding stale state. The retry
never had a chance. They are two steps now, and the reset additionally drops
the SMP flow state it had been leaving behind.

16 tests, 3 mutations applied and killed: `end_session` terminating without
removing (the `terminate_session` trap), a broken session aborting the
teardown, and the client cleanup coupled back into the engine's `try`.

**This changes three previously-inert paths into live ones**, including DAKE
glare — which has been live-tested successfully *with the no-op in place*.

*Status at 2026-09-05:* the two-handset run that followed reported the client
working, and `/otr` recovering a stuck handshake is part of ordinary use. **A
deliberate glare test — both sides typing `/otr` at once — has still not been
run**, and a general "works well" does not close it: glare is a race, and the
path that changed is the one taken only when both sides start at the same
moment.

---

## v10.18.0 — a transfer says what it is doing, and says when it is done

*2026-09-04.  `VERSION → 10.18.0`.  Python only.  Minor bump: new user-visible
output.*

A 254-byte transfer was accepted and then printed nothing at all. It very
likely worked. There was no way to tell.

**A completed transfer was silent.** `on_done` verified the hashes, placed the
file and returned its path — and `handle_control` discards a handler's return
value. So the announcement went into a value nothing read: the file appeared in
`~/.otrv4plus/files` and the user was never told it had arrived, where it went,
or that its hashes checked out. Both ends now say so:

```
[file] received holiday-photo.jpg (1.9 MB) — hashes verified, saved to …
[file] sent holiday-photo.jpg (1.9 MB) in 1:14 — waiting for bob@… to verify it
```

**And nothing reported progress.** `render_progress` had existed since
v10.14.0, with its own tests, and was never once called by the client. Over
I2P a transfer takes a minute or more, so "is this working or has it stalled?"
was unanswerable — which is precisely the question that mattered while the
transport bugs of v10.16.2 and v10.17.1 were being hunted. Both directions now
report:

```
[file] ↓ holiday-photo.jpg [████░░░░░░] 40% · 784.8 KB/1.9 MB · 21.2 KB/s · ETA 0:54
[file] ↑ holiday-photo.jpg [█████░░░░░] 50% · 981.0 KB/1.9 MB · 26.5 KB/s · ETA 0:36
```

Three things the numbers get right rather than approximately right:

* **The clock starts at accept, not at the offer.** The gap while a human
  reads the prompt is not transfer time, and counting it makes every rate and
  ETA wrong for the whole run.
* **No ETA is extrapolated from a single instant.** One chunk in a fraction of
  a second gives an absurd rate and an ETA of zero on a transfer that will
  take a minute; rate and ETA appear once there is a second of history to
  divide by. An unknown duration prints `--` rather than a confident `0:00`.
* **One line a second, not one per chunk.** 119 chunks would be 119 lines —
  the same wall of text the rate-limit log used to produce. The final line is
  never throttled away, so a transfer always ends on `100%`.

The filename in every line goes through `sanitise_filename`; it is remote
input, and a progress line is not exempt from that.

24 tests, 4 mutations applied and killed: the completion announcement back in
the discarded return value, the receiver's progress removed, the throttle
removed, and an ETA invented from no elapsed time.

---

## v10.17.2 — NOTICE, generated from the graph rather than written by hand

*2026-09-04.  `VERSION → 10.17.2`.  No code change.  The attribution file
v10.17.0 said was missing.*

Every permissive licence in the tree requires its notice reproduced in a
binary that includes the code. There was none, so an APK on a store would have
been non-compliant under either half of the dual licence.

**Generated, not written.** [`tools/generate_notice.py`](tools/generate_notice.py)
walks the resolved dependency graph and emits [NOTICE](NOTICE). A hand-written
list rots the first time someone runs `cargo add`; a test now fails when the
file and the graph disagree.

**Only what actually ships.** The walk follows *normal* dependency edges from
the root: **109 of the 137 resolved packages** are compiled into `otrv4_core`;
the other 28 are build- and dev-only. Attributing a test framework pads the
file that a reviewer has to read, and the audit's earlier "134 packages" was
answering a different question — what is in the lockfile — which is right for
an audit and wrong for attribution.

**A choice is recorded as taken.** `MIT OR Apache-2.0 OR LGPL-2.1-or-later` is
a choice, and a choice recorded nowhere has not really been made. Each crate
now shows what it *offered* and what was *taken*: 104 MIT, 4 BSD-3-Clause, 1
Apache-2.0 with the LLVM exception, 1 Unicode-3.0. Only the taken licences'
texts are reproduced — printing the LGPL text for `r-efi`, which is taken under
MIT, would imply an obligation not accepted and would suggest a copyleft
dependency that is not in the tree. `unicode-ident`'s `(MIT OR Apache-2.0) AND
Unicode-3.0` is *not* a choice: both halves apply and both are reproduced.

### Two defects in the generator, caught before it was committed

Both are the characteristic failure modes of any attribution tool, so they are
recorded rather than quietly fixed:

* **It attributed a sentence from the Apache-2.0 licence body to every crate
  shipping that licence** — `(c) You must retain, in the Source form of any
  Derivative Works...` matched as a copyright line. Attribution that names the
  wrong holder is worse than none.
* **It split `(MIT OR Apache-2.0) AND Unicode-3.0` on `OR` first**, producing
  the identifier `(MIT`, for which no licence text could be found. `AND` binds
  the whole expression.

Copyright holders are read from each crate's own licence files. Where a crate
ships none — `x448` and `ed448-goldilocks-plus` among them — the manifest's
`authors` is used and the line says so, rather than inventing a holder.

`LICENSING_AUDIT.md` records the re-measurement and closes the NOTICE item it
had left open. What remains is a delivery requirement rather than an audit
one: the APK must render this on a licences screen, and whoever bundles i2pd
must attribute its own dependencies (Boost, OpenSSL 3.x).

19 tests (36 in the file), 2 mutations applied and killed: a crate dropped
from the NOTICE, and the declined LGPL text reappearing.

---

## v10.17.1 — a transfer the receiver accepted is not throttled at all

*2026-09-04.  `VERSION → 10.17.1`.  Python only.  The v10.16.2 fix was a half
measure; a device test walked off the new cliff.*

A 1.9 MB transfer got to **chunk 33 of 119** — up from chunk 10 before — and
then died the same way, and this time took the connection with it.

**Raising the rate-limit budget only moved the cliff.** v10.16.2 gave an
accepted transfer 120 messages per 5 s instead of 20. The sender was faster
than that, three fragments of chunk 32 were dropped, and the sequence ended.
A receiver whose transfers survive only while the sender paces itself is
broken by construction: the sender may be an older build, on a faster network,
or hostile, and none of those should cost the user their file.

So an accepted transfer's traffic is now **taken out of the limiter's hands
entirely**. What bounds it is not a rate but a **quantity**: the offer declared
how many chunks it would take, the user agreed to receive them, and the
allowance is set from that (`chunk_count × 8 + 64` stanzas). A peer that keeps
sending past what it said it would send stops being exempt and is back on the
chat limit like anyone else. Bounded by consent, not by speed.

**The receiver never told the sender it had given up, and that is what killed
the session.** Abandoning destroyed the local state and sent nothing. The
sender, hearing nothing, pushed the remaining ~430 stanzas at a receiver that
had just dropped back to the chat rate limit — every one dropped, the terminal
filled with identical lines, and the keepalive starved until the stream was
declared dead. Giving up now sends `CANCEL` first. Deliberately *not* folded
into `_destroy_incoming`, which also runs on the success path: cancelling a
transfer that just completed would be worse than saying nothing.

**Two log fixes, because the output actively hid the fault.** Chunks already in
flight when the `CANCEL` goes out still arrive; they are counted rather than
printed, instead of ~430 lines of `DATA rejected: no such transfer`. And
throttling is now reported once per window with a count — the number is the
useful part, the repetition never was.

Sender pacing (8 stanzas/s) stays. It is still right for the I2P stream and the
peer's CPU. It is simply no longer load-bearing for correctness, which is the
point.

13 new tests (33 in the file), 3 mutations applied and killed: abandoning
without telling the sender, the limiter ignoring the allowance, and the
allowance made unbounded.

**Confirmed on two handsets over I2P, 2026-09-05**, with the v10.18.x builds
that followed: `/sendfile` completes, and the client is reported working. The
`[rate-limit] dropping message` wall and the `chunk N arrived out of order`
that this release was written to fix have not recurred.

---

## v10.17.0 — dual-licensed: AGPL-3.0, or a commercial licence

*2026-09-04.  `VERSION → 10.17.0`.  No code change.  A licence change, which is
why it is a minor bump and not a patch.*

OTRv4+ was GPL-3.0. From this release it is **dual-licensed**: AGPL-3.0 for
everyone, plus a [commercial licence](LICENSE-COMMERCIAL.md) for anyone who
cannot or will not comply with it.

**The audit came first, because a licence you cannot grant is worse than the
one you have.** `LICENSING_AUDIT.md` had left this open, and re-running it over
the resolved graph settled it: 137 Rust packages, the Python layer, Chaquopy
(MIT since 12.0.1) and i2pd (BSD-3-Clause) are **all permissive**. Not one
imposes copyleft. The only copyleft in play was the project's own — which is
exactly the condition dual licensing needs. One AGPL dependency anywhere in
that tree and the commercial half would have been unsellable.

**Why AGPL and not GPL.** The GPL's source obligation attaches to
*distribution*. An operator can run a modified version as a hosted service and
distribute nothing, so the obligation never fires — for a messaging client with
a server side, that is the loophole that matters. AGPL §13 closes it.

**Why not a licence that forbids commercial use outright.** PolyForm
Noncommercial and BUSL-1.1 were considered. Either would match the plain
intention more literally, and both would make the project *source-available*
rather than open source — which means F-Droid will not distribute it. F-Droid
is where this project's Termux/I2P audience actually installs software. For a
security tool, being genuinely auditable and genuinely redistributable is worth
more than closing the "comply with the AGPL instead of paying" route.

Charging money is not the trigger; the AGPL explicitly permits selling copies
(§4). The trigger is wanting to keep your source closed.

**Nothing is withdrawn.** Releases up to and including v10.16.2 went out under
GPL-3.0 from a public repository. Everyone who received them keeps those rights
permanently, including the right to fork from those commits. The `LICENSE` file
says so rather than implying a retraction its author could not enforce.

### Keeping the commercial half grantable

It stays sellable only while every line can be licensed both ways, so two
documents arrive with it:

* **[CLA.md](CLA.md)** — contributors grant a dual licence and sign off per
  commit (`git commit -s`). It is a licence, **not** an assignment: the
  contributor keeps their copyright and the contribution stays under the AGPL
  like everything else. Without it, one AGPL-only patch at a time, the
  commercial option would disappear with nobody deciding to end it.
* **[CONTRACTOR-IP.md](CONTRACTOR-IP.md)** — for paid work, where a sign-off is
  not enough. In most jurisdictions the person who writes the code owns the
  copyright even when you paid them; "work made for hire" is narrow in the US
  and absent in that form from UK and EU law. A contractor who owns the Android
  layer is a contractor whose code you cannot include in a commercial licence.
  It carries assignment, moral-rights, further-assurance, third-party-material
  and security-warranty clauses, and asks for a written dependency list on
  delivery.

### Two things stated rather than buried

* **No NOTICE file exists.** Every permissive dependency requires its notice
  reproduced in a distributed binary, so an APK on a store needs one under
  either licence. `LICENSING_AUDIT.md` §2-§5 has the raw material.
* **Whether AI-generated code is copyrightable is unsettled**, and this
  project's README states plainly that it is AI-generated under the author's
  direction. It does not affect the AGPL side in any way that matters. It does
  bear on the commercial side, which presumes there is an exclusive right to
  sell. `CONTRACTOR-IP.md` sets out the position and says where the human
  authorship argument is strongest. Advice before taking money, not before
  posting a job.

`tests/test_licence_declarations_agree.py` (17 tests) pins the licence text
whole — including §13, without which this would just be the GPL under another
name — checks every declaration agrees, and re-runs the copyleft check over the
live dependency graph so a future `cargo add` cannot quietly make the
commercial licence unsellable.

**Not legal advice.** Written by a non-lawyer. Have a solicitor review the
commercial terms and the contractor clauses before relying on them.

---

## v10.16.2 — `/sendfile` actually transfers

*2026-09-04.  `XMPP_VERSION → 10.16.2`.  Python only.  Three defects, all on
the first real transfer between two phones.*

v10.16.1 fixed the picker, so a file was finally chosen, sealed, offered and
accepted. Then the receiver's screen filled with this:

```
[rate-limit] dropping message from alice@xmpp-elite.i2p
[rate-limit] dropping message from alice@xmpp-elite.i2p
   ... about eighty more ...
[file] DATA rejected: chunk 10 arrived out of order
```

Three things were wrong at once, and each would have killed the transfer
alone.

**The receiver throttled the file as if it were a flood.** The inbound limiter
is 20 messages per 5 seconds — four a second. One 16 KB chunk becomes five
6 KB fragments, so a 340 KB file is about a hundred stanzas, and four fifths
of them were dropped. Because the chunk AEAD is a sequence, the first gap
ended the transfer: that is what `chunk 10 arrived out of order` was reporting,
a symptom rather than the fault.

A rate limiter exists to stop an **unsolicited** flood. The chunks of a
transfer the user accepted, from a peer the engine says is SMP-verified, are
the opposite of unsolicited. An accepted transfer now raises that peer's
budget to 120 per 5 seconds for as long as it runs. Raised, not lifted — an
accepted transfer is not a licence to send anything at any rate, an *offer*
alone (which any verified peer can send unprompted) buys nothing, and the
moment the transfer ends the peer is back to the chat limit.

**Nothing paced the sender.** It pushed chunks as fast as the loop could
encrypt them. Sending is now one chunk per turn with a pause between, computed
from the stanzas that actually went out rather than a fixed guess — the first
and last chunks of a file are usually shorter than the rest. The rate, 8
fragments a second, sits deliberately below the receiver's 24: a sender that
exactly fills the budget starves the chat and keepalives sharing it.

**And the whole file was being sent on the event loop.** `on_accept` is
reached from inside the inbound message handler, and the engine's pump sent
every chunk in one unbroken run. So a 340 KB transfer encrypted and pushed a
hundred stanzas with nothing else getting a turn — keepalives could not run,
the stream was declared dead, and the transfer took the connection down with
it. That disconnect looked like a network problem in the earlier session too,
and was not one. `pump_step` sends one chunk and returns; the client drives it
from a task, with sends staying on the loop thread because slixmpp's writer is
not ours to call from another.

**A lost chunk now says so once.** There is no retransmit — the chunk AEAD is
a sequence, so a gap can never be filled in and the transfer is already dead.
It used to report the fault once per remaining chunk, burying the cause under
twenty identical lines; it now abandons the transfer with one message that
says what happened and to ask for the file again.

20 tests, 3 mutations applied and killed: `on_accept` sending inline again,
the limiter reading the budget and throttling anyway, and the pacing pause
removed.

---

## v10.16.1 — the file picker waits for you; every SMP line wears a padlock

*2026-09-04.  `XMPP_VERSION → 10.16.1`.  Python only.  Two device-found fixes.*

### `/sendfile` reported "no file chosen" while the gallery was still open

Choosing a file did nothing. The picker opened, a photo was tapped, and the
client had already given up:

```
[file] opening the Android file picker — choose a file on the phone
[file] no file chosen
```

`termux-storage-get` does not wait for the human. It hands the intent to the
Termux:API app and exits, so the shell command returns in milliseconds and the
chosen file lands at the destination path seconds later, when the chooser
closes. The client checked once, the instant the command returned, and found
nothing — which is to say it could never have worked, on any phone, for any
file. The two-phone plan had exercised `/sendfile <path>`; the no-argument
form had not been run on a device until now.

The destination is now polled until the file appears **and stops growing**.
The size has to hold steady across three consecutive polls before the file is
sealed, because the copy is a stream and a file that merely exists may still be
filling — sending a truncated photo would have been the next bug.

Three smaller things came out of the same reading:

* **The shell exit status says nothing about whether you picked anything.** It
  describes dispatching the intent. The old code treated a non-zero status as
  "user backed out"; it is now ignored unless it is a status that means the
  intent never went out at all.
* **The client says it is waiting.** A silent pause for as long as the gallery
  is open reads as a hang.
* **A file delivered after we stopped waiting is deleted.** It is a plaintext
  copy of whatever was chosen, sitting in the staging directory with nothing
  left to seal it. Staged copies are named `pick-*` until they are claimed, so
  the sweep can never touch a file a transfer is reading.

Backing out of the chooser still costs the full three-minute wait — nothing is
written either way, so a cancelled picker and a slow one are indistinguishable
from outside. The waiting line says so.

### Every `[smp]` line now carries a padlock

Verification is the one thing this client asks a user to *do* rather than
watch, and its lines looked like every other bracketed tag scrolling past.
They now read `🔐 [smp] …`, with the tag itself in blue.

🔐 is the glyph the SMP progress bar already used, so the whole exchange reads
as one thing. Blue on the text rather than the emoji, and not 🔵: that already
means *verified*, the end state, and putting it on every SMP line would say
"verified" while verification was still running.

The session transcript's allowlist had to learn about markers first. It writes
a line only if its shape is recognised, and `🔐 [smp] …` is not `[smp] …`, so
every SMP line would have been redacted to `<unlogged line: N chars>`. Status
glyphs are now stripped before any rule is matched — before, specifically, and
not inside the `[tag]` rule alone: had the marker been tolerated only there,
`🔐 [otr] <peer> body` would have walked straight past the message-body
redaction and written the message to disk. The list of markers is exact;
"any leading emoji" would have been the hole.

### The README was three versions stale, and wrong in the safe direction

The badge said `v10.14.0`. It also listed the AEAD for voice and not for chat,
which reads as though chat has none — the question that started this.

**SMP does not use AES-256-GCM, and the badge should not say it does.**
`Rust/src/smp.rs` contains no AES at all. The construction is the classical
Schnorr ZKP over the 3072-bit group, ML-KEM-1024 encapsulation, ML-DSA-87
signatures, and Argon2id stretching the passphrase. AES-256-GCM sits on either
side of it and not inside it: every SMP message is a TLV in an ordinary
double-ratchet data message, so it is AES-256-GCM in transit like any other
message, and a stored passphrase is sealed at rest with AES-256-GCM. Neither is
part of the proof. The badge now names the chat AEAD in its own segment, where
it belongs, and the SMP section spells the distinction out.

Two things found while checking that, both stale since v10.13.2:

* **Honest caveat 4 still said voice crypto came from the Python
  `cryptography` library** — "two AES-256-GCM implementations in the tree" —
  while two other sections of the same README said it had moved. The only
  remaining `AESGCM(` call sites in the repository are in `.attic/`. A README
  that overstates a weakness is as wrong as one that hides it, and one that
  contradicts itself gives a reader no way to tell which half to believe.
* **`SECURITY.md`'s voice key-material table listed every item as a Python
  `bytearray` or an OpenSSL object.** The epoch root, the media keys and the
  X448 private scalar are Rust-owned with no accessor; the two shared secrets
  are zeroed in place by Rust as it takes them. What is genuinely still
  Python-side is named rather than dropped: the initiator's ML-KEM
  decapsulation key, which lives from keygen until the peer's ciphertext
  arrives.

The SMP wire-version paragraph was stale too — it described `0x02` as the
hybrid format without mentioning that `0x03`, with Argon2id, has been the
default since v10.13.0.

### One sentence above the diagram, with "hybrid" meaning what it means

The chain now has a prose summary. It says X448 **with** ML-KEM-1024 and Ed448
**with** ML-DSA-87 — two pairs — *keying* AES-256-GCM, rather than listing AES
alongside them as a third ingredient.

That is not pedantry about wording. "Hybrid" in hybrid post-quantum
cryptography means a classical asymmetric primitive paired with a
post-quantum one, so that breaking the scheme requires breaking both. AES-256
is neither half of such a pair: 256-bit symmetric encryption is already
considered quantum-resistant and has no post-quantum partner to be paired
with. Naming it in the same breath as X448 and ML-KEM invites a reader to
think the AES is somehow part of the hybridisation, or worse, that it is the
part doing the post-quantum work.

### The crypto chain, drawn once at the top

The README described the stack in five separate places and nowhere in one
glance. It now opens with the chain from key agreement to ciphertext, checked
line by line against the code rather than from memory. Two corrections were
needed before it could be committed:

* **Ed448 ring signatures belong beside ML-DSA-87, not under it.** They are
  what makes the authentication deniable, which is the property OTR exists
  for. `dake.rs` verifies one in DAKE3 through `ring_sig::ring_verify_bytes`.
  A diagram naming only ML-DSA-87 credits the whole of authentication to the
  post-quantum half and quietly drops deniability.
* **The KEM is not a one-time handshake step.** A fresh ML-KEM-1024 exchange
  runs at *every* DH ratchet step, rotating the brace key that feeds the
  SHAKE-256 schedule (`kdf_brace_rotate` in `ratchet.rs`). Drawn as a single
  arrow into the ratchet it would describe PQXDH, which is precisely the
  comparison the rest of the README is careful about.

`tests/test_readme_matches_the_code.py` pins the parts that can be checked
mechanically: the badge version against `XMPP_VERSION`, the absence of AES in
`smp.rs` against the claim that there is none, the default wire version, and
the two documents agreeing with each other. Six of its nine tests fail against
the README as it was.

---

## Repository — one branch, one history

*2026-09-04.  No code change.  Branch housekeeping only.*

`main` had fallen 110 commits behind the working branch, so the default branch
on GitHub showed a version of this project that predates the PQ SMP hardening,
`/sendfile`, guided verification and the group protocol spec. It has been
brought up to date, and development now happens on a single line of history.

- `main` — current, at v10.16.0.
- `claude/otrv4plus-android-spec-a3oq4d` — the working branch, merged into
  `main` and still the place new work lands.
- `voice-v10.11.0` — **deleted.** It carried exactly one commit that `main`
  did not have, `177d0f5ff3309116802596e06bc1345204d433c2` ("v10.11.0: hybrid
  PQ voice calls over I2P, AAudio backend"), whose only unique file was
  `test_voice_verify.py` — a file deliberately removed later in `36efffe`.
  Nothing in the voice implementation itself was lost; the shipping voice code
  is on `main`.

If that commit is ever wanted back:

```bash
git fetch origin 177d0f5ff3309116802596e06bc1345204d433c2
git push origin 177d0f5ff3309116802596e06bc1345204d433c2:refs/heads/voice-v10.11.0
```

GitHub keeps the objects of a deleted branch reachable for some time and can
also restore the branch from the repository's branch page; this SHA is recorded
here so the commit stays findable after that window closes.

---

## v10.16.0 — TLS follows the transport; `--insecure-tls` is no longer needed

*2026-09-04.  `VERSION → 10.16.0`.  Python only.  A user-visible default changes, hence the minor bump.*

The normal command loses its most alarming word:

```bash
python3 otrv4plus_xmpp.py --jid alice@xmpp-elite.i2p \
                          --peer bob@xmpp-elite.i2p
```

**Over I2P the address is a public key.** A `.b32.i2p` label is the SHA-256 of
the server's destination key, so reaching that address means reaching that
key-holder, over I2P's own end-to-end encryption, or not connecting at all.
There is no certificate authority in the path and no MITM position for one to
defend against. A v3 `.onion` name over Tor is the same property — the name
*is* the key.

Requiring a CA-valid certificate there was asking for a weaker second name for
a server already named by its key, and the only way past it was a flag with
"insecure" in it, typed on every single connection. That is worse than
useless: it teaches a habit that is genuinely dangerous the first time someone
carries it to a clearnet host, where nothing replaces a real certificate.

| Server | Certificate check |
|---|---|
| `.b32.i2p` over I2P | skipped, and the client says what authenticates the endpoint instead |
| `.onion` over Tor | skipped, same reason |
| Tor to a **non**-onion host | **required** — the exit sees an ordinary TLS session, so there is no endpoint key |
| clearnet | **required**; only `--insecure-tls` disables it, with the existing warning |

The flag still exists for a clearnet server with a self-signed certificate, and
passing it where it is not needed now says so rather than silently accepting it.

**The message says why, not just that.** "The endpoint is authenticated by I2P:
the .b32.i2p address is the hash of the server's key, so the connection reaches
that key or it fails." It deliberately does not say "verified" — TLS is not
verifying anything here, and claiming otherwise would be a different lie from
the one being removed.

**On certificates generally**, since this came up: a certificate proves
possession of a key, not that a server is uncompromised. An attacker who took
the server holds the key too and serves the same certificate. Certificates
detect *substitution* — which is exactly what the b32 already prevents. No
public CA issues for `.i2p` in any case, as it is outside the public DNS
namespace.

14 new tests in `tests/test_tls_follows_transport.py`, four mutations killed. Python 2466 passed, 43 skipped, 1 xfailed. Four mutations killed
including "clearnet verification disabled unconditionally" and "any Tor
connection counts as self-authenticating".

---

## v10.15.5 — a SAM failure that stopped blaming the address

*2026-09-04.  `VERSION → 10.15.5`.  Python only.*

First real use of the alias layer produced this, and the last two lines are
the problem:

```
[i2p] opening SAM stream to xmpp-elite.i2p (a cold tunnel can take 30-90s)...
[i2p] xmpp-elite.i2p -> hq4t…q.b32.i2p (from ~/.otrv4plus/i2p_hosts)
[i2p] SAM bridge failed: SAM stream connect failed:
      STREAM STATUS RESULT=CANT_REACH_PEER MESSAGE="LeaseSet not found"
[i2p] Is i2pd running with SAM enabled on 127.0.0.1:7656? Is the server b32 correct?
```

The alias worked. The address resolved. By the time `STREAM CONNECT` runs the
address is the one thing known to be *right* — and the client asked the user
to go and check it. `CANT_REACH_PEER` with `LeaseSet not found` means the
destination has not published tunnels the router can find: the server is down,
or its I2P tunnel is not running, or the local router is too cold to have
found the LeaseSet yet.

Each `STREAM STATUS` result now gets the advice that fits it — and only
`INVALID_KEY`, where the router rejected the destination, says to check the
address and any alias pointing at it. An unrecognised result is passed through
without invented advice. The follow-up "is i2pd running?" line is suppressed
when the router already answered, since it contradicts the explanation above
it.

The announcement line also names the destination actually used:

```
[i2p] opening SAM stream to xmpp-elite.i2p -> hq4t…q.b32.i2p (a cold tunnel…)
```

Previously it printed the short name and only then the substitution, which
read as though the alias had been ignored.

7 new tests, 48 in `tests/test_i2p_short_names.py`. Python 2452 passed.

---

## v10.15.4 — a shipped address book, so a server move reaches people

*2026-09-04.  `VERSION → 10.15.4`, `otrv4_core 0.10.27` unchanged.  Python only.*

`i2p_hosts.defaults` now travels with the source. A fresh clone connects with
the short name and never sees a b32:

```bash
python3 otrv4plus_xmpp.py --jid alice@xmpp-elite.i2p \
                          --peer bob@xmpp-elite.i2p --insecure-tls
```

It is also how a **server move** reaches users: ship a new line, they
`git pull`, and the command they have always run reaches the new address.

### The precedence rule, and why it is not simply "newest wins"

v10.15.3 deliberately refused to overwrite a recorded destination, on the
grounds that a server that moved is something the user must see. Taken
literally that would also mean the first successful connection pins an address
forever and a migration strands everyone who ever connected — the opposite
failure. The two are reconciled by asking **whose entry it is**:

| Entry | On a changed shipped default |
|---|---|
| hand-written in `~/.otrv4plus/i2p_hosts` | **wins.** Someone typed that line and meant it. |
| learned by the client (`# learned`) | **yields**, with a notice naming both addresses and how to keep the old one. |
| absent | the shipped default applies. |

An update never edits the user's file. The defaults change because `git pull`
changed them, which is visible in the diff like any other code.

Nothing is recorded when the shipped defaults already say it, so users do not
accumulate a learned copy of the shipped address that would then have to lose
an argument with it later.

### Retired addresses are explained, never redirected

An old command naming the old b32 in full still gets used as given — the rule
that no file may re-point an address the user spelled out is unchanged. But a
`retired <old b32> <name>` line in the defaults lets the client say where it
went:

```
[i2p] hq4t…q.b32.i2p is a retired address for xmpp-elite.i2p.
[i2p] Still trying it as given. The current form is:  --server xmpp-elite.i2p
```

### What this does not add to the threat model

A shipped address book is trusted exactly as much as the code around it — and
no more, because the server is not a trust anchor here. Anyone who could
change `i2p_hosts.defaults` in the repository could change the cryptography
instead, which is a strictly better attack. And a wrong address cannot read a
conversation: the DAKE authenticates the peer and TOFU pins their identity key
end to end, through whatever server is in the middle. Emptying the file leaves
the client fully functional with an explicit `--server`.

14 new tests, 41 in `tests/test_i2p_short_names.py`.

---

## v10.15.3 — the b32 gets typed once

*2026-09-04.  `VERSION → 10.15.3`, `otrv4_core 0.10.27` unchanged.  Python only.*

v10.15.2 made short `.i2p` names work if you wrote the alias yourself. This
writes it for you: the first time a connection to a `.b32.i2p` server
succeeds, the mapping from the JID's domain to that destination is recorded,
and announced.

```
[i2p] recorded xmpp-elite.i2p = hq4t24b7…q.b32.i2p in ~/.otrv4plus/i2p_hosts
[i2p] next time:  --jid bob@xmpp-elite.i2p --peer <peer> (no --server needed)
```

**After the connection, never before.** That is the only moment the client
knows the name and the destination actually belong together.

**Three refusals**, and the third is the one that matters. Nothing is written
for a name or destination that would not load back. Nothing is written when
the same pair is already recorded. And when the name is already recorded
against a **different** destination, the file is left alone and the
difference is reported — a server whose destination changed is something the
user needs to see, not something a client should quietly rewrite under them.
Accepting such a change means editing the file by hand.

**It writes only to the client's own file.** The suggestion that started this
was to add the entry to i2pd's address book, since we know where that lives.
That is the wrong file: the format varies between versions, the daemon owns
and rewrites those files on its own schedule, and a bad write would break name
resolution for every I2P application on the device rather than just this one.
`test_nothing_opens_a_router_file` walks both clients' ASTs and fails if any
`open`/`makedirs`/`chmod`/`rename` call names an i2pd path. It checks what is
*opened*, not what is mentioned — naming `i2pd.conf` in a help string is
exactly what a stuck user needs to read.

The alias file is created 0600 with a header explaining what an alias is and
is not.

8 new tests, 27 in `tests/test_i2p_short_names.py`.

### Still open

The router-side question is unresolved. On the test handset, i2pd answers
`NAMING LOOKUP NAME=xmpp-elite.i2p` with `RESULT=INVALID_KEY`, its address
book is 6 KB dated seven months ago, and the name registered with reg.i2p
weeks ago is not in it. Two possibilities remain — the book is simply stale,
or i2pd's SAM never consults the book at all and only resolves b32 — and they
have not been told apart. If it turns out to be the second, the client should
read `addresses.csv` itself, **read-only**, as a resolution fallback. That is
not built yet, because building it before knowing would be building on a
guess.

---

## v10.15.2 — short `.i2p` names, so nobody has to type a b32

*2026-09-04.  `VERSION → 10.15.2`, `otrv4_core 0.10.27` unchanged.  No wire change, no Rust change.*

Connecting meant pasting

```
--server hq4t24b7vkllfbk55e5xfocqhfi7hxprwc47zyuilbg6wgzikidq.b32.i2p
```

every time, because `xmpp-elite.i2p` would not resolve. That is not a bug in
the client and it was already doing the right thing: it sends `NAMING LOOKUP`
to the router over SAM, and the router answers honestly that it has never
heard of the name.

**`.i2p` names are not DNS.** A router resolves only what is in its own
address book, which it builds from subscriptions, and a private server is in
nobody's subscription. The b32 form works everywhere because it *is* the
destination hash — 52 characters of it. On a phone keyboard that is not a
reasonable thing to ask of anyone.

**The fix is a local alias file**, `~/.otrv4plus/i2p_hosts`:

```
xmpp-elite.i2p = hq4t24b7vkllfbk55e5xfocqhfi7hxprwc47zyuilbg6wgzikidq.b32.i2p
```

With that line the address is the JID's own domain, so **`--server` is no
longer needed at all**:

```bash
python3 otrv4plus_xmpp.py --jid bob@xmpp-elite.i2p \
                          --peer alice@xmpp-elite.i2p --insecure-tls
```

Both clients share the file, since the lookup lives in `I2PSAMConnection`.

**An alias has no authority, and one rule enforces it.** An address given in
full as `.b32.i2p` is *never* looked up in the file, so a local file cannot
redirect an address the user spelled out (`test_a_full_b32_is_never_looked_up`).
Aliases must point at a b32 or a full destination — not at another short name,
so no chaining and no loop detection — and the substitution is printed when
used, so the destination actually reached is always visible. Nothing about
conversation security rests on any of it: the DAKE authenticates the peer and
TOFU pins the identity key, end to end through whatever server is in the
middle.

**The failure message now says what to do.** It used to be `Cannot resolve
xmpp-elite.i2p: NAMING REPLY RESULT=KEY_NOT_FOUND` — accurate and useless. It
now explains that short names are not global, and prints the exact line to
add. A b32 that fails is reported as a router or tunnel problem instead, since
naming is not involved.

`TRANSPORT_POLICY.md` §8.1 records the resolution paths and the property that
matters: **no system resolver ever sees an `.i2p` or `.onion` name.** b32 needs
no lookup, the alias file is a local read, and `NAMING LOOKUP` travels the same
loopback SAM socket as the stream.

19 new tests. Python 2423 passed, 43 skipped, 1 xfailed. Rust 111 passed.

---

## v10.15.1 — three bugs the phones found that the tests did not

*2026-09-04.  `VERSION → 10.15.1`, `otrv4_core 0.10.27` unchanged.  No wire change.*

First run of v10.15.0 between two handsets over I2P. Three defects, and the
common thread is that the v10.15.0 tests drove the client's own methods with a
fake engine and never let a real SMP1 reach a real session.

**1. The responder flow was never switched on.** `smp_guided_prompt` gates
whether an incoming SMP1 is parked or aborted, and nothing in the XMPP client
ever set it to `True` — the plumbing was written, the switch was not. So Alice
aborted with `NOSECRET` exactly as she had before the feature existed, and Bob
was told to ask her to run `/smp-secret`. Everything in the responder half of
v10.15.0 was unreachable on a real device. Now set where the manager is
built, with a behavioural test that feeds a real SMP1 to a real session and
asserts the phase becomes `SECRET_REQUIRED`.

**2. Simultaneous initiation could never recover.** When both sides run `/smp`
at once, the higher-fingerprint side yields, rebuilds its engine and rebinds
the secret from the vault. `initialize_smp()` constructs a **new**
`RustSMPVault` whenever `rust_smp is None`, so clearing the engine threw away
the `smp_secret` entry the rebind then looked for. It failed every time:

```
🔐 SMP · ❌ SMP error: SMP race-recovery: vault rebind failed
```

This predates v10.15.0 — the recovery path has never worked — and it is not
rare over I2P, because "both people are told to verify and both do" is the
normal case. The vault is now preserved across the rebuild, and a rebind that
still fails falls through to the no-secret handling instead of raising, so a
setup problem is not reported as an internal error.

**3. An abort was reported as a possible MITM.** One abort produced both of
these, three lines apart:

```
SMP stopped: your peer has not stored the passphrase yet.
   ...This is not a wrong-passphrase failure.
*** SMP FAILED - secrets did NOT match. Possible MITM. ***
```

The second contradicts the first and is the thing v10.15.0's error
classification was supposed to prevent — it was fixed in the session and
missed in the client's own status reporter. An `ABORT` is now its own branch
with its own wording; the MITM warning is kept for a genuine comparison
failure, which is what it is for.

**On the tests that missed all three.** Every v10.15.0 responder test called
`_check_smp_secret_required` directly with a fake `otr` returning `True`.
That tests the display and nothing else. The new tests bind the real
`_enh_handle_smp_tlv` to a minimal session with a real `RustSMP`, feed it a
real SMP1, and assert on the engine's phase and the queued response; the
abort/mismatch split is driven through the real `_report_smp`. All three
fixes were then mutation-tested by reverting them: all three now fail.

Python 2404 passed, 43 skipped, 1 xfailed. Rust 111 passed.

**Live-tested to here:** DAKE, pinning and the initiator prompt all worked on
two handsets. The responder prompt has still never been seen working, because
of defect 1 — both phones need this build before step 3 of
`SMP_UX_AUDIT.md` §8.3 can be run at all.

---

## v10.15.0 — guided SMP verification, and the core-API regression behind it

*2026-09-04.  `VERSION → 10.15.0`, `otrv4_core 0.10.27`.  No wire format change: SMP messages, the 0x03 Argon2id derivation and the abort TLV are byte-identical.  `SMP_ABORT` gains one optional diagnostic payload, which older peers ignore exactly as they ignored the last one.*

**The reported failure was not an SMP bug.**

```
[smp] start error: SMP start failed: 'builtins.RustSMPVault'
      object has no attribute 'store_from_bytearray'
```

`store_from_bytearray` is the correct method and it has existed since `otrv4_core 0.10.25`.  The handset was running client 10.14.0 against an older compiled core: `git pull` updates the Python, only `pip install ./Rust` updates the core, and nothing checked that the two agreed.  The mismatch surfaced as an `AttributeError` inside an executor thread at the first verification attempt, wrapped in two `RuntimeError`s, worded as though the protocol had failed.

The fix is `otrv4plus_coreapi.py`: the clients declare the core methods they require, with the version each arrived in, and the check runs at startup and names both the missing method and the command to rebuild.  A Python shim restoring the old `store(bytes(raw))` call was rejected — that call made an immutable copy of the passphrase the caller could not wipe, which is the whole reason `store_from_bytearray` replaced it.  `tests/test_smp_guided_flow.py::TestTheCoreApiContract` fails if a client calls a vault method the manifest does not declare, so the next regression of this shape is caught in CI rather than on a phone.

**Verification is now one command.**  `/smp` prompts for the passphrase (hidden) if none is stored, then verifies.  `/smp-secret` remains as the store-without-verifying form and is documented as the advanced one.  Nobody needs to know it exists.

**The responder no longer sees a failure when the truth is "you have not set a passphrase".**  A new engine phase, `SECRET_REQUIRED`, holds the received SMP1 instead of aborting on it, so once the passphrase is supplied the message that already arrived is answered — no restart, no second round trip over I2P.  `hold_smp1`, `resume_held_smp1_generate_smp2` and `discard_held_smp1` are in `Rust/src/smp.rs`, at the shared engine, so both clients see the same state.

**A peer can now open a prompt, which needed the security property re-stated rather than re-asserted.**  INV-06 used to read "no remote protocol message can arm local secret-input capture", and the simplest way to keep it true was for an SMP1 to arm nothing at all.  Making the responder flow automatic means a peer's message does put a prompt on the screen, so the invariant is now:

> Remote SMP messages may request local user interaction but can never capture arbitrary local input.

`otrv4plus_smpflow.py` is that boundary as a state machine.  A peer's SMP1 reaches `AWAITING_LOCAL_CONSENT` and stops.  The only edges into `AWAITING_SECRET` — the state in which a typed line is read as a passphrase — are `local_secret_needed` (the user typed `/smp`) and `local_consent` (the user typed `y`).  A chat message typed at a consent prompt is not `y`, so it falls through and is **sent as a message**.  That case is a test, because it is the one that matters: `test_an_ordinary_message_at_the_consent_prompt_is_just_a_message`.

**The IRC client still had the original defect.**  INV-06's test walked `otrv4plus_xmpp.py` only.  In `otrv4+.py`, completing a DAKE — which a *peer* initiates — armed `_set_pending("smp_secret", peer, …)`, and the next line typed became the shared secret, unmasked, into scrollback.  Removed, along with the dispatch branch that consumed it, so reintroducing it takes two edits and either one fails a test.

**Six states, six messages, and none of them lying about the others.**  Secret required, cancelled, declined, aborted, wrong passphrase, internal error.  An internal failure now says so and says "no secret was transmitted or stored" instead of reading like a mismatch; a wrong passphrase is still a genuine cryptographic failure and is still reported as one.

**Not live-tested.**  Every claim here is from the test suite on a development machine.  Two-handset validation over I2P — including the reversed roles and the ordinary-message case — is in `SMP_UX_AUDIT.md` §8 and has not been run.

Python 2386 passed, 43 skipped, 1 xfailed.  Rust 111 passed.

---

## v10.14.0 — /sendfile

*2026-09-01.  `VERSION → 10.14.0`, `otrv4_core 0.10.26`.  New capability; the encrypted-file format carries its own version byte, currently `1`.*

**XMPP only.**  The IRC client has no file transfer, imports nothing from the transfer module, and its OTR and TLV behaviour is untouched.  That is not a promise, it is `tests/test_file_transfer_boundary.py::TestTheFeatureIsXmppOnly`, which walks `otrv4+.py`'s AST for the import, greps it for the command and the prefix, and asserts `otrv4plus_xmpp.py` is the only file in the repository that references the module.

**Both peers need this build** to exchange files: a peer without `RustFileSender` cannot key a transfer.  Chat and voice with a v10.13.3 peer are unaffected.

**No second cryptographic system, and that was the main design decision.**  The audit's question was whether the existing session already provides an authenticated secret suitable for a transfer key.  It does: the double ratchet's brace key already folds ML-KEM-1024 shared secrets, so session state is already post-quantum and already DAKE-authenticated.  Running a second KEM exchange would have added a handshake, a transcript and a failure mode to reach a level the session already had.  The transfer key is derived from the session's **extra symmetric key** — the value OTRv4 reserves for exactly this kind of out-of-band use — with domain separation and the transfer id in the derivation.

**That key was being thrown away.**  `DakeSessionKeys.extra_sym_key` existed, was derived at KDF usage `0x1F`, and was zeroized inside `from_dake_keys` along with everything else the ratchet did not need.  It is now retained on the PyO3 wrapper as a `SecretBytes<32>`; the inner `DoubleRatchet` and all its derivations are untouched, so IRC behaviour is bit-identical.

**The Python side of the extra symmetric key was dead code, and weaker than it looked.**  `OTRv4TLV.EXTRA_SYMMETRIC_KEY` (`0x0009`) has a receive handler that derives its own key in Python — `sha3_512(session_id + b"OTRv4-EXTRA-SYM" + tlv.value)[:32]` — with no reference to the DAKE-derived value.  Nothing sends that TLV, `_extra_sym_key_cb` is never assigned, and `_last_extra_sym_key` is never read.  It was **not** built on: a Python-side key derivation is what INV-08 and INV-14 exist to prevent.  It is left in place for now because deleting it would change shared IRC/XMPP code for an XMPP feature; it is recorded here as a follow-up.

**`aead.rs` was the wrong tool and was not used.**  Its AES-256-GCM binding takes the key as a parameter, because it was written to replace `cryptography.AESGCM` in the storage classes where Python already held the key.  Using it here would have put the FileKey across the FFI on every chunk.  The new `Rust/src/filetransfer.rs` follows `voice.rs` instead: a Rust-owned `SecretBytes<32>` with no getter, `seal_chunk`/`open_chunk`, and `zeroize`.  Same `aes-gcm` crate; the difference is who owns the key.

**The format.**  64 KiB plaintext chunks, so a 1 GB file is 16384 chunks rather than 1 GB of RAM.  Nonce is `0x00000000 || UINT64BE(index)` — deterministic rather than random, which is safer here because the key is fresh per transfer and a counter cannot collide, where 96-bit random nonces have a birthday bound a large file could approach.  The AAD binds the format version, the transfer id, the chunk index and a **final flag**, so a chunk cannot be reordered, duplicated at another index, replayed into another transfer, or presented as the last one to truncate the file.  A zero-length file is still one authenticated chunk.

**Verification before placement, in six steps**, and the file is never decrypted into its destination: chunk tags, the final flag, the chunk count, SHA-256 of the ciphertext, SHA-256 of the plaintext, and the size on disk — then an atomic rename.  Any failure deletes the temporary file and drops the transfer.  A chunk that fails its tag aborts immediately rather than leaving a partial file waiting for chunks that can never verify.

**The filename is never a path.**  The output directory is fixed locally (`~/.otrv4plus/files/`, 0700, with `.incoming/` for partial work) and only a sanitised basename comes from the offer, so there is no peer-supplied path to traverse out of.  `../../private.key` becomes a filename, not a location.  A second file of the same name gets a suffix rather than replacing the first.

**Transport-independent by construction.**  The engine takes its byte pump as a parameter and is driven in tests by a plain list, not by XMPP — if that test ever needs slixmpp, the independence has been lost.  Phase A passes the OTR channel; a SAM-stream pump can be substituted later without touching the protocol, the format, the integrity checks or the storage handling.

**The transport boundary is explicit, and that is the part the torrent phase depends on.**  `ChunkTransport` has two methods, deliberately separate: `send_control` for offer/accept/decline/done/cancel, and `send_chunk` for one already-sealed chunk.  Splitting them means a bulk transport cannot accidentally carry signalling, or the reverse.  Inbound, every transport funnels through one `deliver_chunk` seam, so the ordering rule and the authentication are defined once and cannot diverge.  `OtrChunkTransport` is Phase A — both channels on the OTR channel, chunks base64'd into control messages, which is why its chunk size is 16 KiB rather than the format's 64 KiB.  **Replacing that one class is the whole of a transport upgrade.**  `tests/test_file_transfer_boundary.py` drives the same engine through a second transport that shares no framing with it, and asserts the plaintext hash is identical, that no chunk touched the control path, and that the engine's executable code names nothing XMPP.

**Three mutants survived the first pass.**  Two turned out to be equivalent — the separator strip is redundant with the character filter, and the chunk-count check is unreachable because the authenticated final flag fails first — and both are now marked as deliberate redundancy in the code rather than papered over with a contorted test.  The third was a real gap: nothing tested a **lying offer**.  Four tests were added for a sender that seals honestly and then misstates the plaintext hash, the ciphertext hash, the chunk count or the size.  Nine of eleven mutations are killed; the two equivalents are documented.

**Found while writing the tests, not fixed here.**  `DAKE1RateLimiter` documents itself as per-peer, but both call sites invoke `process_dake1(dake1_msg)` without the `peer_key` argument, so every peer shares the default bucket `"unknown"`.  It is a **global** limiter of 5 attempts per 60 seconds, and one peer exhausting it locks out DAKE1 from every other peer.  That is engine-wide behaviour affecting IRC and XMPP alike; file transfer has no business changing session establishment, so it is recorded rather than patched.

**`/sendfile` with no path opens the Android file picker.**  You have `termux-api`, so there is no reason to make anyone type `~/storage/dcim/Camera/20260901_143022.jpg`.  The picker runs in an executor because it waits for a human scrolling a gallery, which is far longer than anything else in this client may block for.  Two honest caveats, both surfaced in the client rather than buried: `termux-storage-get` hands over bytes and **not a name**, so the file is renamed from its magic number and a timestamp — cosmetically worse, marginally better for privacy, and `/sendfile <path>` still preserves a name exactly; and the apt package is only shell shims, so a missing **Termux:API app** is reported as the missing half rather than as a timeout.  The staged copy is plaintext, lives at 0600 under a `.picked/` directory separate from received files, and is unlinked as soon as the file is sealed — including when sealing raises.

**Termux cannot see your photos until you tell it to.**  Termux's home is inside the app's private data directory and has no view of Android storage, so `/sendfile photo.jpg` on a fresh install reports "no such file" and the fix is `termux-setup-storage` — a command a user has no reason to have heard of.  Nothing in the repository mentioned it.  The error now names it, but only on Android and only when `~/storage` is genuinely absent, so it never nags someone who simply mistyped.  `FILE_TRANSFER_TEST_PLAN.md` covers both directions: getting a file in (`~/storage/dcim/Camera/...`, or `termux-storage-get` for the graphical picker) and getting a received one back out — with what that costs, since copying from a 0700 private directory into shared storage makes the file readable by every app holding the storage permission.

**Verification.**  Python 2283 passed, 43 skipped, 1 xfailed (was 2109).  Rust 101 passed (was 87).  `tests/test_file_transfer_crypto.py` runs against real ratchets from a real DAKE, not stubs.  **No live XMPP or device testing** — nothing here has moved a file between two phones.

---

## v10.13.3 — the channel user list, and what its blue marker does not mean

*2026-08-31.  `VERSION → 10.13.3`, `otrv4_core` unchanged at `0.10.25`.  No wire change.*

**`/names` printed "[IRC line suppressed]" for every line.**  Not a policy, a bug: `Pager.display` measured each line, truncated it, and then printed a literal string instead of it.  One wrong argument, present since v10.11.0.  Every pager consumer was affected — **`/list` and `/help` were equally broken**, which is why the fix is one line and covers all three.  The NAMES rendering itself already existed and was never reached; it has been reworked rather than replaced.

**A second bug the first one was hiding.**  The pager truncates at `TERMINAL_WIDTH` using `len()`, which counts ANSI escape bytes as visible characters.  Now that coloured lines actually print, a long one would be cut about ten columns early *and* lose its reset sequence, bleeding colour into the rest of the terminal.  `_truncate_visible` measures visible columns and re-appends the reset.

**The user list.**  A summary line (`🔵 3 OTRv4+ • 94 other clients`), then Operators / Voiced / Users, with detected OTRv4+ users in blue and sorted to the top of their group so the actionable names are together.  **The total is the server's count, not the number of rows drawn** — the list is capped locally at 500 and the header says what it is a slice of.  Multi-prefix entries (`@+nick`) parse correctly; entries carrying a space, a NUL or a newline are dropped individually rather than costing the whole render.

**Selecting a user.**  Detected OTRv4+ users are numbered, and pressing 1–9 in the pager runs the normal `/otr <nick>` entry point.  It is a shortcut for typing the command, and it starts a DAKE like any other — it confers nothing by itself.

**Detection uses the mechanism the project already had, and two gaps in it.**  CTCP VERSION is deliberately refused, so the realname (gecos) sent at USER registration is this client's only identification channel; the server relays it in `RPL_WHOREPLY`, and `/names` sends `WHO` before `NAMES` to collect it.  Two of the three realname paths did not carry the version: a 27 Club nick advertised `Kurt Cobain (Nirvana) - 27 Club` and a NickServ-registered nick advertised the bare nick, so **two whole classes of OTRv4+ user were invisible to their own peers**.  Both now end with VERSION.  A detection mechanism the client does not consistently feed is not a detection mechanism.  The match also tightened from a bare `"OTRv4+" in realname` substring — which fires on `I don't use OTRv4+` typed into a gecos — to the tag plus a dotted version.

**The marker is identification, not authentication, and INV-20 is what keeps it that way.**  Anyone can put `OTRv4+ 10.13.3` in their own gecos; the server does not check it and neither can we.  It answers "is this peer likely to understand `/otr`".  The DAKE authenticates, TOFU pins identity, SMP authorises voice — the marker does none of those.  `format_names_list` is a pure function with no client to promote anything on, the voice module cannot see the map at all, and tests fail if any of that changes.

**`/whois` was reporting a claim it had made up.**  `Client:` printed our own `VERSION` whatever the peer was running, and `Name:` printed `TwentySevenClubNick.real_name(target)` — the *local* formatting of their nick, which returns `<nick> - OTRv4+ <version>` for any nick at all and is never equal to the bare nick, so the peer's actual realname was never displayed.  `/whois` on a mIRC user therefore reported them as an OTRv4+ client, which is precisely the nick-derived inference this release exists to avoid.  Both fields now come off the wire: `Client:` shows the version the peer advertises or `not advertised`, and `Name:` shows their realname.  `RPL_WHOISUSER` is the same reliable metadata as `RPL_WHOREPLY`, so a `/whois` now also refreshes that nick's marker — including clearing a stale one.

**Two smaller correctness fixes.**  A nick change now carries the OTRv4+ marker across (it is keyed by nick, so a rename would strip it from the person and leave it on a name nobody holds), and a QUIT drops it (someone else may take the nick, and a stale entry would mark them as an OTRv4+ client on no evidence).  `RPL_ENDOFNAMES` now clears its accumulator even when it arrives unsolicited on JOIN, where it previously grew for the life of the process and inflated the next `/names` total.

**Three mutants survived the first pass** and each was a real gap: nothing covered the NickServ realname branch, nothing checked that a malformed NAMES token failed to inflate the header count, and the truncation test was passing on a near-equivalent mutant.  Two tests added, one sharpened.  Fifteen mutations, all killed.

**Verification.**  Python 2109 passed, 43 skipped, 1 xfailed (was 2027).  Rust 87 passed, unchanged — no Rust was touched.  `tests/test_irc_names_list.py`, 79 tests.  **Not tested against a live IRC server.**

---

## Unreleased — transport policy

*Documentation, specification and tests only.  No code change, no wire change, no version bump: a peer on v10.13.2 is unaffected.*

**Why now.**  Three transports exist (I2P, Tor, clearnet TLS) and each was added under a different set of assumptions, written down in a different place or not at all.  Two more routes are wanted — a SOCKS5 proxy and a proxy chain under clearnet TLS — and the point of writing the rules before that code is that the rules are what the code will be built against.

**[TRANSPORT_POLICY.md](TRANSPORT_POLICY.md)** is the new authoritative document.  Five modes, a transition matrix, and the separation the rest of it hangs from: `TransportClass {I2P, TOR, CLEARNET_TLS}` is security-relevant and is what the UI reports; `Route {direct, proxy, proxy_chain}` is operational and sits *underneath* a class.  A proxy is not a fourth privacy tier next to I2P and Tor — it is a route beneath clearnet — and only the class would ever reach the cryptographic transcript, because two peers who chose different proxies must still be able to talk.

**The rule, stated once:** the transport class is fixed for the lifetime of a call; an endpoint may change within a class if the change is authenticated; a class change requires ending the call.  `MEDIAPATH` is the authenticated endpoint change, and it is what recovered the Wi-Fi-to-mobile transition — so "nothing may change mid-call" would have been the wrong rule.  I2P→TLS, Tor→TLS and TLS→I2P are forbidden, the last of those included because a silent *upgrade* is still a class change the peer did not agree to.  The matrix is an allowlist: an unlisted transition is forbidden, not undefined.

**Two sequences named so they stay forbidden:** `I2P fails → try Tor → try clearnet`, and `I2P is slow → switch to UDP`.  The second is the more dangerous, because it triggers on degraded rather than failed and therefore fires hardest on exactly the congested networks where nobody is watching.

**Encryption is not anonymity is not routing.**  Clearnet TLS 1.3 is strong encryption with no anonymity; calling it "less secure" is wrong.  Tor is not "the NSA one" and I2P is not "the most secure one".  A proxy operator can log, identify, inject or be compromised, so a proxy mode is never labelled anonymous — INV-19 fails if any document says otherwise.

**Voice over Tor is recorded as a decision with a reason, not as a gap.**  Tor carries TCP; voice here is constant-rate datagrams on a latency budget, and the SAM *stream* version was already unusable for speech.  A mode that connects and does not work is worse than no mode, because users select it and conclude the application is broken.  The condition for revisiting it is a real-time media transport for Tor, not a demonstration that packets traverse it.  Clearnet UDP media is refused on the same grounds in the other direction: the only reason to reach for it is latency, and latency is not worth anonymity.

**Three invariants added.**  INV-17 no fallback ladder (ENFORCED), INV-18 the class is fixed for the call (PARTIAL — enforced today by there being exactly one media class, with the transcript binding specified and deferred), INV-19 honest wording (ENFORCED).  `tests/test_transport_policy.py`, 29 tests.

**One existing test was wrong and is now right for a different reason.**  `test_xmpp_has_no_tor_path` asserted the absence of PySocks and was named for a fact that stopped being true when Tor XMPP landed.  The assertion is correct and the reason is better than the old one: PySocks routes by assigning `socket.socket` process-wide, so in this process it would capture the I2P SAM bridge and every voice media socket — a Tor XMPP session would silently drag the media path through Tor too.  Renamed to `test_tor_is_not_applied_process_wide`.

**Deferred, deliberately:** binding `TransportClass` into the voice key derivation (a wire break, needs its own version bump and cross-version tests), the `TransportClass`/`Route` Rust types, and proxy-chain media.  The proven I2P voice path is not destabilised to make the matrix symmetrical.

---

## v10.13.2 — the voice key path moves into Rust

*2026-08-28.  `VERSION → 10.13.2`, `otrv4_core 0.10.25`.  No wire change.*

**Both peers need this build.**  Not because the format moved — it did not — but because the media path is Rust-only from here: a peer whose `otrv4_core` predates `RustVoiceCipher` cannot make a call, and fails at startup rather than mid-call.  There is deliberately no Python fallback, since falling back would restore the thing this release fixes.

**Media keys.**  `VoiceFrameCrypto` kept its keys in a `bytearray` so they could be wiped, then handed each one to OpenSSL as `AESGCM(bytes(key))` — an immutable copy nothing could overwrite, which the AESGCM object retained anyway.  One per direction per sub-epoch: at `RATCHET_INTERVAL = 500` frames and 60 ms per frame, about 276 unwipeable copies over a 69-minute call.  Calling the existing `aes256gcm_encrypt(key, ...)` helper per frame would have been worse, putting the key into Python on every frame instead of every 500.  The keys are now `SecretBytes<32>` inside `RustVoiceCipher`, which rebuilds its cipher from the single copy that exists and zeroizes on drop.  No getter, and adding one would defeat the module.

**The voice X448 private scalar** was a `cryptography` object Python could neither wipe nor reach — the one private value in the voice path with no cleanup at all.  It is now `SecretBytes<56>` in `RustVoiceKex`: single-use, spent even when the agreement is refused (retrying with a different peer key is the shape of a small-subgroup probe), and carrying every check the Python version had — reflection, all-zero peer key, on-curve validation, and the RFC 7748 requirement that a degenerate shared secret abort rather than be used.

**The SMP passphrase wipe was being defeated one line before it ran.**  `set_smp_secret` built a wipeable bytearray, passed `bytes(raw)` to the vault, and then zeroed the bytearray in a `finally` — wiping the object that no longer mattered while the copy survived.  `RustSMPVault.store_from_bytearray` now takes the bytearray and zeroes the caller's buffer, including on the error path.

**Byte-for-byte compatible.**  Same HKDF-SHA512, same labels, same four-byte length prefixes.  Verified in both directions.

**Two things worth recording about how this went.**  The first Rust draft length-prefixed with eight bytes instead of four; every cross-implementation frame failed its tag, with no error and no clue — just silence on the call.  The parity test caught it.  Then, once `VoiceFrameCrypto` began delegating to Rust, that same test became Rust-against-Rust: a deliberately reintroduced eight-byte prefix passed clean.  Mutation testing found that, not reading.  The reference derivation is now rebuilt inside the test from primitives, and ten of its thirty-five tests fail on that mutant.

**The epoch root moved too.**  It is the input every media key derives from, so a copy of it is a copy of every key for that epoch — and it sat in a Python `bytearray` for the whole call.  `RustVoiceRoot` now owns it as `SecretBytes<64>`: Python holds a handle that can produce a cipher, a confirmation pair or an endpoint tag, and cannot produce the root.  The initial derivation, the rekey chaining, the confirmations and the endpoint tags all happen inside Rust, and the X448 / ML-KEM shared secrets are zeroed by Rust before the call returns rather than by a `finally` the caller has to remember.

**What did NOT move, deliberately.**  The rekey STATE MACHINE stays in Python: it is protocol logic, it owns the convergence properties fixed at v10.13.1, and putting freshly-audited behaviour through an unnecessary rewrite is how stable systems break.  Same for the frame header, AAD construction, replay window, jitter buffer and call state machine — none touch key material, all are proven on real calls.

**Tests that read secrets had to change, and are better for it.**  Assertions like "the committed root is unchanged" used to compare root bytes directly.  They now compare the confirmation pair, which is a deterministic function of the root and travels on the wire anyway — so equal confirmations mean equal roots and nothing else is revealed.  Where even that was not available, the property is asserted through its consequence: two calls that shared a media key would produce identical ciphertext for identical plaintext, so the test seals and compares.

**Verification.**  Python 1992 passed, 43 skipped, 1 xfailed (was 1934).  Rust 87 passed (was 77).  Android 82 passed, 37 skipped.  **No live XMPP or I2P testing** — everything was exercised through the PyO3 boundary and over loopback, and this release changes what encrypts every audio frame.

---

## v10.13.1 — security hardening: input capture, log boundary, rekey divergence

*2026-08-28.  `VERSION → 10.13.1`, `otrv4_core 0.10.24`.  No wire change.*

A hardening pass driven by a repository-wide security inventory.  Five findings, three of them real defects; sixteen invariants now enforced by tests rather than by prose.

**A remote peer could decide what your next keystroke meant.**  Completing a DAKE armed `_pending[peer] = "smp_secret"`, and `dispatch_line` consumed that state ahead of all command parsing with only `/quit` exempt.  The arming path ran from the inbound message handler, so a peer who started an OTR session could make the next line the user typed be swallowed and stored as a passphrase.  Masked and never transmitted, so not exfiltration — but a remote party choosing the meaning of local input.  Supplying the secret now needs `/smp-secret`, typed locally, and the request is single-use.  `tests/test_no_remote_input_capture.py` walks the inbound call graph transitively rather than checking a hand-maintained allow-list, because the previous test allowed `_apply_tofu` in its "local flows" set and passed while the property was false.

**A hand-rolled Python cipher, deleted.**  `otrv4plus_log.py` carried its own AEAD — a SHAKE-256 keystream XORed over the plaintext with a truncated HMAC-SHA3-512 tag — and a `persistent=True` mode that kept every line anyone typed, and its key, across sessions.  No caller ever set it; the docstring said XMPP did.  Deleted rather than re-based onto the Rust AES-256-GCM: in-memory scrollback that dies with the process has nothing to protect at rest, so removing the disk removes the cipher too.  Also removes the crash-remnant case, where ephemeral mode left files behind.

**The session transcript writes only what it recognises.**  It used to redact one line shape and write everything else verbatim, which fails open.  Now an allowlist: message bodies dropped, structural rules and known diagnostic tags kept, anything else recorded as `<unlogged line: N chars>`.  A sweep found no call site printing a secret value, so this closed a latent hole rather than an active leak.  `tests/test_log_boundary.py` drives realistic passphrases, keys, seeds and tokens through nine carrier shapes; a mutant that fails open fails 75 of its 97 tests.

**Credentials were in the config's `repr()`.**  `OTRConfig` is a dataclass, so `repr(cfg)` printed `sasl_pass` and `nickserv_pass`.  Found by a test doing exactly that and printing it in the failure message.  Both fields are now `repr=False`.  The residual limit is unchanged: Python `str` cannot be zeroized, and that is recorded as a limitation rather than papered over.

**Media rejections are classified by cause.**  Every rejection incremented `auth_fail` unless its exception text contained "replay", so `authfail=87` could mean a forged frame, a peer that had rekeyed ahead, a retired epoch, or a lost byte stream.  `FrameError` now carries a `reason` set at the raise site.  Only a failed AES-256-GCM tag counts as authentication failure.  Nothing is accepted that was not accepted before.

**Two rekey defects that could strand a call permanently.**  `abort_rekey` removed the pending epoch's cipher from the *receive* set — but the initiator commits as soon as the responder's tag verifies and only then sends REKEYCOMMIT, so it is already sending on the new epoch while the responder still has it pending.  A responder aborting on a timeout could no longer decrypt anything the peer sent.  Separately, an incoming REKEY had to name exactly `ours + 1`, so a responder that missed one REKEYCOMMIT was rejected forever — including the messages that would have repaired it.  A timeout abort now keeps the receive cipher (silence is not evidence; a failed tag still discards, because that is), and a bounded forward jump is accepted as a catch-up.  Committing still requires a valid confirmation tag, the epoch still only moves forward, and a jump beyond `VOICE_REKEY_MAX_CATCHUP` is still refused.

**Not fixed, and stated as such:** there is no positive acknowledgement proving both peers switched epochs.  Closing that needs a fourth message and therefore a wire change.  What replaces it is convergence rather than proof.

**One premise corrected.**  The brief for this work stated that IRC had Argon2-based SMP protection and XMPP did not.  That asymmetry has never existed: both transports call the same `SMPAutoRespondStorage` and the same `_derive_key`, and no commit in history wrote SMP secrets in plaintext on either.  The real defect was terminal echo, fixed at `a687ff2`.

**New:** `SECURITY_INVARIANTS.md` and `tests/security_invariants.py` — sixteen invariants, each naming the test that enforces it.  `tests/test_invariant_registry.py` fails if an invariant has no test, if a named test module does not exist, or if the document and the registry disagree.

**Verification.**  Python 1932 passed, 43 skipped, 1 xfailed (was 1633).  Rust 77 passed.  Mutation-tested: the input-capture, log-boundary and rekey fixes each fail their tests when reverted.  **No live XMPP or I2P testing** — everything here was exercised through the PyO3 boundary and over loopback.

---

## v10.13.0 — Argon2id SMP secret derivation (wire version 0x03)

*2026-08-26.  `VERSION → 10.13.0`, `otrv4_core 0.10.23`.*

**Both peers must be updated together.**  SMP wire version `0x03` derives a different secret scalar from the same passphrase than `0x02` did.  A pair where one side has pulled and the other has not aborts at the version check with a message that says so — it does **not** report a passphrase mismatch, because the passphrase is probably fine.  There is no negotiation and no downgrade.

**What was wrong.**  The SMP passphrase was stretched by 50,000 rounds of SHAKE-256 over the passphrase **alone**; the session ID and both fingerprints were bound in afterwards by a single HMAC.  Two problems, and the second is the worse one.  The work was CPU-only, so it parallelised freely on a GPU.  And because nothing user-specific entered the expensive part, `stretch(candidate)` was computable once and reusable against every OTRv4Plus user and every session that had ever run — after which testing a candidate against a captured SMP transcript cost one HMAC.  50,000 rounds bought far less than the number suggested.

**What replaced it.**  `Rust/src/smp.rs::stretch_argon2id`: Argon2id, m=64 MiB / t=3 / p=4, salted with `SHA3-512("OTRv4+SMP-ARGON2-SALT-v3" || 0x00 || LEN(session_id) || session_id || LEN(first_fp) || first_fp || LEN(second_fp) || second_fp)`.  Every salt field is length-prefixed, so `(session_id, fp, fp)` triples cannot be re-split into a colliding one.  The salt is deterministic and must be — both peers have to reach the same scalar and SMP has no message in which to carry a salt — but `session_id` is per-DAKE, so even the same two peers re-running SMP derive under a fresh salt.  Argon2 failure does not fall back to the weaker stretch; failing open there would undo the entire point.

**What did NOT change.**  The `0x02` derivation is retained byte-for-byte, pinned by a frozen test vector that was cross-checked against an independent Python implementation rather than against the Rust code.  Message layouts are identical between `0x02` and `0x03` — measured wire sizes unchanged at 5849 / 12096 / 6248 / 5472 bytes.  No other key schedule, no message authentication rule, no replay window, no ratchet, no DAKE, no voice cryptography.  Cost on this hardware: 0.192 s per derivation, run once per verification.

**Documentation retraction.**  `FEATURES.md` and `README.md` had both claimed an "Argon2id KDF protecting the SMP vault" running inside `otrv4_core`, and audit finding 6 was recorded closed on the same premise.  None of it was true: `argon2` was not a crate dependency, no Rust source referenced it, and `src/smp_vault.rs` is an in-memory zeroizing store with no key derivation in it.  The only real Argon2id was Python-side and at-rest.  The claim survived a documentation-synchronisation pass because the table was read and not checked.  Retracted in `dc82681`, then made true where it mattered here.  `tests/test_kdf_claims_are_true.py` now reads `Cargo.toml` and the Rust sources instead of the prose, and SECURITY.md carries the retraction as caveats 14 and 15.

**At-rest KDF downgrade is no longer silent.**  `otrv4+.py::_derive_key` caught every Argon2 failure with a bare `except Exception: pass` and fell through to scrypt, with the only notice an import-time print.  A 64 MiB allocation genuinely can fail on a pressured handset, so this was reachable.  The fallback is kept — losing access to your own SMP secrets is worse than a weaker KDF at rest, and the load path already tries both — but it warns once with the reason, and `kdf_backend()` reports which KDF actually ran.

**Also.**  The SMP wire byte is now pinned by `tests/test_protocol_version.py`, which `VERSIONING.md` had claimed for it without it being true.

**Verification.**  Python 1633 passed, 43 skipped, 1 xfailed.  Rust 77 passed (was 65).  Twelve new Rust tests cover the derivation directly — that the salt binds the session ID, that it binds the fingerprints, that it is role-independent, that field boundaries cannot collide, that Argon2 and the legacy stretch disagree, and that a mixed-version pair aborts with an actionable error.  Sixteen new Python tests in `tests/test_smp_argon2_wire_v3.py` drive the real compiled extension through all four SMP steps, plus three in `tests/test_protocol_version.py` pinning the wire byte.  **Not yet live-tested between two handsets** — the derivation is exercised through the PyO3 boundary and over loopback only.

---

## v10.12.0 — voice media liveness, authenticated endpoint recovery, documentation sync

*2026-08-25.  `VERSION → 10.12.0`, `otrv4_core 0.10.22`.*

**Encrypted voice over I2P now detects, diagnoses and recovers from a media path that stops.**  Before this release a call whose inbound media died stayed "up" indefinitely: the transmit side kept succeeding, because a datagram handed to the local SAM UDP bridge is accepted whether or not the session behind it still exists, so no counter anywhere went wrong.  The call looked healthy and carried nothing.

**Detection.**  A liveness watchdog runs in both transport modes, checking at the media probe cadence (5 s) and measuring silence since the last frame that *authenticated* — not since the last datagram that arrived, which a dead path can still produce.  A new `dgram_in` counter, incremented before every filter, disambiguates the previously ambiguous `rx=0`: `rx=0 dg=0` is a dead path, `rx=0 dg>0` is a live path with the fault above it.

**Recovery.**  When nothing is arriving at all, the endpoint is replaced: the old SAM session is closed, a new one built, and the new destination announced to the peer in a new `MEDIAPATH` control message.  The announcement is authenticated from the committed epoch root (`derive_endpoint_tag` over call_id, epoch, sequence, destination and role), so a stale, forged or rolled-back address is rejected.  No media key derives from the destination, so moving the address invalidates no key: the epoch, replay windows, ratchet and call identity all survive recovery untouched, and a packet already accepted stays rejected afterwards.  Recovery is confirmed by inbound media resuming, never by the clock.

**SAM-session-aware backoff (`b12c802`).**  A SAM session lives exactly as long as its control socket.  Measured on a real Wi-Fi→mobile transition, the diagnosis already read `SAM control socket open` — the session had never been destroyed, the router was rebuilding tunnels under a destination that was still ours — and rebuilding anyway cost 21.2 s plus ~20 s of our own `tx` at zero.  The rebuild is now held for `VOICE_RX_SESSION_HOLD_S` (30 s) while the control socket is open.  The user warning is **not** delayed, the dead horizon moves with the hold so the recovery window can never shorten, a closed or unknown socket is treated as gone and behaves exactly as before, and `OTRV4PLUS_RX_SESSION_HOLD_MS=0` disables it.

**Cold paths are no longer mistaken for broken ones (`09f800d`).**  Media first flowed at t=96 s on a live call while the watchdog fired at 26.6 s and rebuilt an endpoint that was merely still coming up, costing ~70 s of silence.  Until one frame has authenticated, `VOICE_RX_START_GRACE_S` (120 s) replaces the warning threshold and the dead horizon moves with it.

**Bounded.**  Worst case from media death to teardown is 465 s for a proven path and 795 s for one that never carried audio.  All four figures (held and unheld) are computed from the constants by `TestTheWorstCaseIsBounded`, which fails if `VOICE_MEDIA_PATH.md` and the code disagree.

**PyO3 thread-affinity crash fixed (`c98ba9b`).**  `DakeOutput` is `#[pyclass(unsendable)]`: it records its creating thread and panics if touched from another.  The OTR executor was a `ThreadPoolExecutor(max_workers=2)` directly contradicting its own "single thread" comment, so a DAKE could be started on one worker and continued on the other — `DakeOutput is unsendable, but sent to another thread`, a hard crash.  Serialised to one worker.  This protects more than the PyO3 requirement: OTR session processing is stateful, and two messages for one peer must not be processed concurrently regardless — ratchet state, skipped-message-key accounting, SMP state and DAKE state all depend on it.  The dead synchronous fallback `_handle_otr_in`, which would have re-introduced engine calls on the event loop, was deleted in `df7349d`; `tests/test_otr_thread_affinity.py` asserts it stays gone.

**XMPP keepalive no longer disconnects working streams (`5e8d4e8`).**  XEP-0199 IQ pings with a 30 s timeout over three I2P hops were declaring dead a stream that was carrying traffic — proved from logs showing rekeys committing 3.2–22 s before a "dead" verdict.  Quiet threshold 180 s, ping timeout 60 s, two consecutive failures required, and an inbound-stanza filter that counts *any* traffic as liveness.  Field-verified: 0 disconnects and 0 keepalive lines across a 31-minute call.

**Rekey no longer wedges on one lost message (`f129578`).**  A responder that lost a `REKEYACK` previously left both sides unable to rekey for the rest of the call.  Field-verified: 14 rekeys committed, 0 timeouts.

**Termux incoming-call UX (`d0bfa11`).**  Notification, ringtone and ACCEPT/DECLINE actions wired to the existing call state machine over a FIFO, with single-use call-bound tokens.  No UI string is a security predicate.

**Terminal and session UX (`648f089`).**  Mouth-to-ear readout colour-banded against ITU-T G.114 (green ≤400 ms, yellow ≤800 ms, red above); wrong login passwords re-prompt instead of failing the session; an OTR session whose peer leaves and does not return is cleared automatically, so `/otr` works on their return.

**Documentation synchronised and versioning made explicit.**  `VERSIONING.md` added.  Version strings, which had drifted to five different values across `otrv4+.py`, `otrv4plus_xmpp.py`, `Rust/Cargo.toml`, `Rust/pyproject.toml` and the README badge, were reconciled to one.  Stale wire figures corrected across the README (the Opus frame default moved 40 ms → 60 ms and the packet 199 B → 279 B in an earlier cycle without the documentation following).  `FEATURES.md` still listed voice as out of scope and is rewritten.  **Correction:** the "no Python `cryptography` dependency" claim from v10.7 no longer holds — `otrv4plus_voice.py` uses that library for the media AES-256-GCM, HKDF-SHA512 and X448.  The chat path remains Rust-only; the voice path does not, and every document that claimed otherwise now says so.

**XMPP gets a persistent identity and real TOFU; IRC deliberately does not.**  Both protocols regenerated their Ed448 identity every launch, and both wrote to the same `~/.otrv4plus/trust.json`.  For IRC that is correct — a nick is ephemeral, so a fingerprint pinned to one is pinned to nothing.  For XMPP it was not: a JID is durable, so a fingerprint that changed every restart carried no information, and because `add_trust` raises `FingerprintMismatchError` when the stored value differs, the *second* session with any peer you had trusted printed "This may indicate a MITM attack".  Every reconnect.  A warning shown that often is a warning that will be ignored the once it is real.  A complete TOFU implementation, `TrustDatabase.check_or_pin()`, had been sitting in the tree with zero callers because it could not work against an identity that never persisted.

  * **XMPP identity persists.**  One sealed Ed448 identity, reloaded every run.  It reuses the Android B1 mechanism rather than inventing a second one: `Rust/src/identity.rs` seals and unseals inside Rust, so the seed never becomes a Python object and no `get_seed()` accessor exists.  `otrv4plus_identity.py` adds only the Termux-side key custody and file handling.  **The at-rest protection is filesystem permissions, not a passphrase** — the DEK is a 0600 file, because Termux has no keyring — and that limit is stated wherever the feature is described rather than glossed as "encrypted at rest".  Loading fails closed: a record that will not open is never silently replaced, because regenerating would change our fingerprint with no signal and every peer holding a pin would see it as an attack we caused.
  * **XMPP trust is pinned.**  First contact shows the fingerprint and asks once.  A match afterwards asks nothing.  A **change** is reported, does not replace the stored pin, offers no `y`-answerable prompt, does not continue into SMP setup, and refuses voice for that peer until `/trust-reset <jid>` is typed deliberately.  TOFU is identity *continuity*: a matching pin authorises nothing, SMP remains the authentication mechanism, and `_smp_verified` remains the only gate on a call — the mismatch refusal is layered on top of it, never an alternative route through.
  * **IRC is unchanged and now writes nothing.**  Fresh identity every run, trust held in memory for the session so a `y` still sticks across a reconnect within one run, nothing on disk.  Removing the write is also what removes the false mismatch — the warning was not suppressed, the record that caused it stopped being created.
  * **The stores are separate.**  XMPP owns `~/.otrv4plus/xmpp/`; stored SMP passphrases are migrated there once, with the `.smp_seed` that decrypts them, and the legacy copies are left for IRC.

**SMP says why it stopped, without letting a peer capture your typing.**  A responder with no stored passphrase queued `SMP_ABORT` and returned in silence: it told its own user nothing, and the initiator saw a generic abort indistinguishable from a wrong passphrase — so the one failure a user can actually fix looked like the one they cannot.  The responder is now told what happened and which command fixes it, and the abort carries an optional `NOSECRET` reason so the initiator can say "your peer has not stored the passphrase yet" rather than "aborted".  The payload was previously empty and ignored, so an older peer drops it exactly as before; it is a diagnostic that only chooses wording, never a predicate, because it is text a peer controls.

  The obvious fix — prompting the responder for the secret — was deliberately **not** implemented.  `_pending[peer] = "smp_secret"` makes `dispatch_line` swallow the next line typed ahead of every command except `/quit`, so letting an inbound SMP1 arm it would let a peer decide that the user's next sentence, possibly meant for a different conversation, becomes a stored secret.  The secret is supplied only by an explicit local `/smp-secret <secret>`, and tests assert that nothing in the protocol engine can reach the prompt.

**Verification.**  Python `1483 passed, 43 skipped, 1 xfailed` (3.12, repo root).  Rust `65 passed`.  52 new tests across `tests/test_identity_and_tofu.py` and `tests/test_smp_no_secret.py`, mutation-tested with 13 mutations: 12 killed, and the 13th shown to be an equivalent mutant (the ephemeral-trust guard is deliberately duplicated in `__init__` and `_load`; removing *both* is killed, removing either alone changes nothing).  The SAM-session-hold invariants were mutation-tested: removing the hold, applying it when the session is gone, delaying the warning with it, failing to move the dead horizon, removing the rebuild gate, and changing the constant or the documented bound without the other each make the suite fail.

---

## v10.10.0 – v10.11.1 — released without changelog entries

These releases shipped the XMPP transport, its security hardening, the Tor
control-plane route, and the first working encrypted voice path, but no
changelog sections were written at the time.  Rather than reconstruct them after
the fact, they are recorded here as a gap.  The contemporaneous record is:

* **XMPP transport and hardening (v10.10.4)** — README *"XMPP transport"* and *"Security hardening"*.
* **Voice calling, hybrid voice key exchange, two-phase rekey, AAudio backend (v10.11.0)** — README *"Encrypted voice calls"*; `VOICE_AUDIT_REPORT.md`.
* **Voice security fixes (v10.11.1)** — README *"Security fixes in v10.11.1"*.
* Commit range `da691d1..624bbca` and the audit documents dated in that window.

---

## v10.9.2 — formal protocol specification + documentation pass

**`SPEC.md` added.**  A complete byte-level wire specification: exact field offsets and sizes for DAKE1/2/3 and the ClientProfile, the KDF construction with the full usage-ID table, the normative session-key derivation order, the hybrid PQC SMP construction (group params, length-prefixed wire encoding, group-element validation bounds, the 50,000-round secret derivation, the Schnorr ZKP construction, and the PQ binding layer), the fragmentation format, the DAKE/SMP state machines, normative security requirements, and the RFC 3526 prime in full.  The goal is that a qualified developer can write a compatible implementation in any language from this document alone, without reading the source.

**Documentation updated** for the hybrid PQC SMP across `README.md` (added a "Why OTRv4+ vs alternatives" comparison table and a 30-second pitch, and linked `SPEC.md` prominently), `SECURITY.md` (MITM and quantum-adversary rows note hybrid PQC SMP; memory table adds the SMP ML-KEM secret key, ML-DSA signing key, and `pq_binding_key` rows; new caveat documenting the construction and the variable-time ZKP scalar limitation), and `WHY.md` (SMP description rewritten, I2P timing corrected to the measured ~15–16 min).  `termux_install.sh` rewritten Rust-only.

Version strings aligned to 10.9.2 across `otrv4+.py` and `smp.rs`.  No protocol or wire change from v10.9.1.

---

## v10.9.1 — hybrid PQC SMP timeout + I2P transport tuning

**SMP session timeout raised 600 s → 2700 s (45 minutes).**  The hybrid PQC SMP wire overhead over I2P is substantial — SMP2 is 49 fragments of ML-KEM and ML-DSA material — and the initiator was timing out milliseconds before receiving SMP4 on a slow I2P path.  Measured end-to-end: full DAKE + SMP VERIFIED over I2P SAM (irc.postman.i2p) in ~15–16 minutes; under 6 minutes over TLS clearnet.

**I2P transport tuning (live-tested against irc.postman.i2p).**  Fragment payload reduced 450 → 380 bytes after the stricter postman line limit truncated the DAKE1 tail ("Invalid wire format"; reassembled 5310 vs 5940 chars on TLS confirmed truncation).  Send pacing changed from per-fragment delay to a batch strategy — 2 fragments then a 6-second pause (~0.33 lines/sec) — after 200 ms / 600 ms / 1200 ms per-fragment all still triggered Excess Flood disconnection.  Tor stays at 200 ms; TLS uses the token bucket.

**Per-panel scroll fix.**  `_scroll_history` was a single global list mixing all channels' terminal output, so Ctrl+P scrollback in one channel showed another channel's messages.  It is now rebuilt from the active panel's own history on every tab switch.

**IRCv3 typing notifications (P2P).**  `@+typing=active/done TAGMSG` sent on keypress/submit in private panels; received TAGMSG shows a transient "✍ is typing…" line.  Channel panels unaffected.

---

## v10.9.0 — hybrid post-quantum SMP

**The Socialist Millionaire Protocol is now hybrid post-quantum.**  The classical OTRv4 four-step Schnorr ZKP over the 3072-bit MODP group (RFC 3526 Group 15) is preserved verbatim and now runs alongside an ML-KEM-1024 + ML-DSA-87 binding layer.  Forging a false "verified" result requires breaking the 3072-bit discrete log, ML-KEM-1024, and ML-DSA-87 **simultaneously**; the construction is never weaker than classical SMP against a classical adversary.

**Construction.**  In SMP1 the initiator generates an ML-KEM-1024 keypair and an ML-DSA-87 keypair and appends the encapsulation key (1568 B) and ML-DSA-87 public key (2592 B) to the classical payload.  In SMP2 the responder encapsulates to derive `kem_ss`, derives `pq_binding_key = KDF(PQ_BRACE_KEY, domain || kem_ss || transcript_tag, 32)`, generates its own ML-DSA-87 keypair, and signs the entire SMP2 wire body under `pq_binding_key` as context.  SMP3/4 each verify the previous step's ML-DSA-87 signature before processing the classical fields, then sign their own output.  All KEM/DSA secret material is `ZeroizeOnDrop` and wiped immediately after use.

**Wire versioning.**  Byte 0 of each SMP message is `0x01` (classical) or `0x02` (hybrid PQ).  A version mismatch aborts the session — no silent downgrade.

**Critical bug fixed during development — KEM key mixing.**  The first hybrid implementation derived the SMP secret scalar from the KEM key as well as the passphrase.  But the initiator called `set_secret` **before** generating its ML-KEM keypair, so the KEM key was absent on the initiator side, while the responder received it in SMP1 and applied a re-bind step — so the two sides derived **different** secret scalars from the same passphrase and SMP failed with a false negative on every attempt, even though the ML-DSA-87 signatures all verified.  Unit tests missed it because they set up keypairs before `set_secret`; only live two-session testing caught it.  **Fix:** the KEM key was removed from the secret-scalar derivation entirely.  PQ security comes from `pq_binding_key` and the per-step ML-DSA-87 signatures; the secret scalar stays purely classical/symmetric.  After the fix, SMP VERIFIED over both TLS and I2P.

**Tests.**  15 hybrid-PQC SMP unit tests added (classical roundtrip, hybrid roundtrip, mismatched secrets in both modes, version-mismatch rejection, ML-DSA-87 context sign/verify, wrong-context rejection, ML-KEM-1024 encaps/decaps roundtrip, `pq_binding_key` determinism, PQ SMP with question field).  Combined suite 30+ Rust tests.

---

## v10.7.6 — Phase 5.4: constant-time SMP modular exponentiation

**The SMP modular exponentiation is now constant-time.**  SMP's `modpow` migrated from `num-bigint` (whose `modpow` running time depends on the exponent's bit pattern) to `crypto-bigint`'s `DynResidue` (Montgomery-form, constant-time in the exponent).  This closes a timing side-channel on the secret SMP exponents: the blinding scalars (a2/a3/b2/b3), the SMP secret itself, and the ZKP randomisers (r4b/r5b/r6b…).  This was the last open security-hardening item on the ROADMAP.

**Spec unchanged.**  The 3072-bit group (OTRv4 §5.3 — same prime, same order (p-1)/2, same generator g=2) is identical; only the *implementation* of exponentiation changed.  The wire format is byte-for-byte the same and interop with prior OTRv4+ versions is preserved.  Verified live: full DAKE + SMP VERIFIED over I2P with a peer running the previous build.

**Scope.**  All 15 secret-dependent `modpow` call sites now route through a constant-time `mod_exp` that internally uses `DynResidue`; `mod_inv` (Fermat `a^(p-2)`) inherits constant-time from it.  Public-value arithmetic (ZKP challenge/response reconstruction with `*`/`%`/`+`) and random sampling stay on `num-bigint` — there is no secret-dependent timing in those paths, so moving them would add risk for no security gain.  `num-bigint` therefore remains a dependency.

**Dependency.**  `crypto-bigint 0.5` promoted from a transitive dependency (already pulled in by the pqcrypto stack) to a direct `pq-rust`-gated dependency — no new crate compiled into the tree.

**Tests.**  Six SMP unit tests added (the crate had none before): `SMP_PRIME_CT` byte-equality against `SMP_PRIME`; `mod_exp` small known-answer (2¹⁰); `mod_exp` cross-checked against `num-bigint`'s reference `modpow` at full 384-byte width; `mod_inv` roundtrip; full SMP1→4 matching-secret VERIFIES; mismatched-secret FAILS.  These are build-time correctness gates — they caught a wrong-group-size bug during development (see below) before it could reach a live session.

**Bug fixed during development.**  `SMP_PRIME_BYTES` was declared `256` but the SMP prime is 3072-bit = **384 bytes**.  The first migration attempt used a 2048-bit `Uint`, which silently truncated the top 1024 bits of the prime; the `mod_exp` reference-cross-check and full-roundtrip tests failed deterministically and exposed it.  Corrected to `U3072` / `Uint<48>` / 384-byte width throughout.  The prior `num-bigint` code was never affected by the `256` mislabel because its `fixed_bytes` helper only pads up to a floor and never truncates, and real group elements already exceed 256 bytes.

`cargo test`: 26 passed (20 prior + 6 SMP), 0 warnings.  Live: DAKE + SMP VERIFIED over I2P with peer QuartzRoot.  VERSION → 10.7.6, otrv4_core 0.10.23.

---

## v10.7.5 — ClientProfile validity tightened to 14 days

The OTRv4 spec §4.1 recommends short ClientProfile lifetimes (weeks rather than years).  Earlier versions used a 365-day expiry that was inherited from the pre-ephemeral design and never revisited.  For OTRv4+, where the long-term identity key is regenerated at every launch, a 1-year profile validity widened the impersonation window without buying anything — peers see a fresh profile on every DAKE1 anyway.

**Changed.**  `ClientProfile.expires = self.created + 365 * 24 * 3600` → `self.created + self.VALIDITY_SECONDS`, where `VALIDITY_SECONDS = 14 * 24 * 3600`.  Two sites (constructor and `renew()`) now reference the single class-level constant, so they can't drift again.  Matches `otr4j`'s default.

No protocol or wire change.  Existing offline-cached profiles older than 14 days now require a fresh DAKE1 (which OTRv4+ would have done anyway because of session ephemerality).

---

## v10.7.4 — Phase 5.3k + 5.3i-D: Rust-core-only, the architectural finish line

**All C extensions retired.**  OTRv4+ now has a single cryptographic implementation surface: the Rust `otrv4_core` PyO3 module.  No second backend, no compile-time conditionals selecting between paths, no Python-vs-Rust comparison checks at boot.

**Phase 5.3k — file deletions and import removal.**
- `otrv4+.py`: the `otr4_ed448_ct` import block deleted.  A grep for `_ed448_ct.` member access was empty before deletion — the import was a defensive ground-truth that had no live callers anywhere in the codebase.  `ED448_CT_AVAILABLE` removed.  The `_sys.path.insert(...)` line was retained (still needed for `otrv4_core` import resolution).
- `git rm`: `otr4_crypto_ext.c`, `otr4_crypto_ext.so`, `otr4_crypto_ext.cpython-313-aarch64-linux-android.so`, `otr4_ed448_ct.c`, `otr4_ed448_ct.so`, `otr4_mldsa_ext.c`, `otr4_mldsa_ext.so` (the last set was orphaned since v10.6.18), `setup_otr4.py`.
- Test migration: seven test files in `tests/` (`test_mlkem_kat.py`, `test_property.py`, `test_differential.py`, `fuzz_harnesses.py`, `test_ratchet_torture.py`, `test_ring_android.py`, `test_attacks.py`) migrated from `import otr4_crypto_ext as _ossl` to `import otrv4_core as _ossl`.  The Rust module exposes `mlkem1024_keygen` / `_encaps` / `_decaps` with identical signatures, so the migration was a one-line import swap for six of them.  `test_attacks.py` additionally uses `_ossl.cleanse`, so it received a small `_OsslShim` providing the Rust ML-KEM functions plus a `ctypes.memset` cleanse.
- `git rm tests/test_otr.py` — this was a smoke test for all three retired C extensions' surfaces (bignum ops, `ring_sign`, `ed448_scalarmult`, `mldsa87_*`); after the migration it tested only deleted code.
- Documentation updated across `README.md`, `SECURITY.md`, `ROADMAP.md`, `CHANGELOG.md`, `FEATURES.md`, `DEVELOPMENT.md`, `MIGRATION.md`, `CONTRIBUTING.md`, and both `prebuilt/` READMEs.

**Phase 5.3i-D — `aead.rs` warning cleanup.**
The 13 deprecation warnings emitted by `aead.rs` since v10.6.19 were all uses of `aes-gcm 0.10`'s deprecated `GenericArray::from_slice` helper.  Fix: production sites now use `Aes256Gcm::new_from_slice(key)` (from the `KeyInit` trait, takes `&[u8]`, returns `Result<Self, InvalidLength>`) and convert the nonce slice to `&[u8; 12]` via `try_into()` then `Nonce::from(*nonce_arr)` (matching the actual `impl From<[u8; 12]> for GenericArray<u8, U12>` in `generic-array 0.14.7`).  Test sites use `Nonce::from(n)` directly since `n` is already `[u8; 12]`.  Restored the zero-warning Rust build that v10.6.18 originally achieved.

**Verified.**  `cargo test` 20 passed, 0 failed.  `cargo build` 0 warnings.  Live DAKE + SMP VERIFIED + multi-epoch ratchet across an I2P channel with peer `CopperFox`.

---

## v10.7.3 — Phase 5.3i-C: ML-KEM-1024 brace KEM moved to Rust

`MLKEM1024BraceKEM` (the double ratchet's post-quantum brace-key KEM) migrated from `_ossl.mlkem1024_*` to Rust `pqcrypto-mlkem 0.1.1`.  Same crate that already backs the DAKE KEM in `dake.rs`; the new `src/mlkem.rs` PyO3 module exposes three functions (`mlkem1024_keygen` / `_encaps` / `_decaps`) wrapping it.

**Subtlety.**  pqcrypto's `encapsulate(public_key)` returns `(SharedSecret, Ciphertext)` — the *opposite* tuple ordering from the C extension's `(ciphertext, shared_secret)`.  The Rust wrapper inverts the tuple to match the existing Python contract exactly; the existing Python callers and tests are unchanged.  Three Rust unit tests cover byte sizes against FIPS 203, full keygen→encaps→decaps shared-secret matching, and wrong-key rejection.

After this commit, `otr4_crypto_ext` had no remaining callers anywhere in the codebase.  The import block in `otrv4+.py` was removed; the `.c`/`.so` files were left in place for Phase 5.3k to delete.

`Rust/Cargo.toml`: `otrv4_core` version bumped 0.10.21 → 0.10.22 to reflect the new module.

---

## v10.7.2 — Phase 5.3i-B: `_ossl.cleanse` replaced with `ctypes.memset`

The OpenSSL-backed `_ossl.cleanse(bytearray)` zeroization helper replaced with a module-level `_secure_wipe(bytearray)` using `ctypes.memset` via a `c_char * len` view into the bytearray's buffer.  This is the standard dead-store-resistant wipe technique (memset through a `volatile`-ish indirection so LLVM cannot prove the writes are unobservable and elide them).

**Sites updated.**  Eight `_ossl.cleanse(...)` calls repointed to `_secure_wipe(...)`.  Two were deleted as redundant (`SecureMemory.zeroize` already wiped via `ctypes`; `_secure_file_destroy` already wiped its key buffer manually).

No third-party-library dependency for memory wiping anywhere in the codebase now — `ctypes` is stdlib, `zeroize::Zeroize` is in Rust.

---

## v10.7.1 — Phase 5.3i-A: dead bignum wrappers + `disable_core_dumps` migration

Four dead Python wrappers around the C extension's bignum surface deleted as part of the 5.3i lead-in.  All four were leftovers from the pre-Rust-SMP era when SMP arithmetic lived in Python and called into `otr4_crypto_ext.bn_*`.  Since the v10.6.x Rust SMP migration, SMP modular arithmetic has lived entirely inside `src/smp.rs` (using `num-bigint`); the wrappers had no callers.

- `_ct_mod_exp` (wrapper around `_ossl.bn_mod_exp_consttime`) — deleted.
- `_ct_mod_inv` (wrapper around `_ossl.bn_mod_inverse`) — deleted.
- `_ct_rand_range` (wrapper around `_ossl.bn_rand_range`) — deleted.
- `SHA3_512.hash_to_int` — deleted.  Referenced the long-removed `SMPConstants` class.

`disable_core_dumps()` migrated from `_ossl.disable_core_dumps` to Python `resource.setrlimit(RLIMIT_CORE, (0, 0))`.  Pure stdlib; no C extension call.

Python-only change; no Rust rebuild required.

---

## v10.7 — Phase 5.3h-D complete: Python cryptography library fully removed

**The Python `cryptography` library is no longer imported or used in any code path. Every asymmetric and symmetric cryptographic operation runs in the Rust `otrv4_core` core.**

v10.7 is the final stage of Phase 5.3h-D. Stages 1 and 2 (v10.6.20, v10.6.21) moved the last two live cryptography-library uses — Ed448 verification and the X448 ratchet DH — into Rust. v10.7 removes the dead code that still referenced the library and deletes the import.

### What was removed

**The pure-Python `OTRv4DAKE` fallback class — 863 lines.** This class was the original Python DAKE implementation, kept as a fallback for builds without the Rust core. It was already uninstantiable in practice:

- `RustDAKEAdapter.__init__` either succeeds with the Rust backend or raises `RuntimeError`. It never constructs `OTRv4DAKE`. The `_use_rust` flag was always `True` by the time any adapter method ran.
- The Rust ratchet (`RUST_RATCHET_AVAILABLE`) and Rust SMP have been mandatory since v10.6.11 — a build without the Rust core raises long before any DAKE fallback could matter. The Python DAKE could never actually carry a session to completion.

So `OTRv4DAKE` was ~860 lines of unreachable code plus, in `RustDAKEAdapter`, 12 dead `if not self._use_rust: return self._py_fallback.…` branches. All deleted.

**The `_use_rust` / `_py_fallback` machinery.** 12 dead guard blocks, the `self._use_rust` / `self._py_fallback` field declarations, the dangling end-of-`__init__` fail-fast block, and the `MLDSA87_AVAILABLE and self._use_rust` guard simplified to `MLDSA87_AVAILABLE`. Three debug-tag sites that read `_use_rust` for a "🦀/🐍" label are hardcoded to Rust.

**The cryptography library import.** The top-of-file block

```python
try:
    from cryptography.hazmat.primitives.asymmetric import ed448, x448
    from cryptography.hazmat.primitives import serialization
    ...
```

is gone, replaced by a comment recording that all crypto is now Rust-side.

### What was rescued and rewritten

**`_safe_b64decode`** was a `@staticmethod` on `OTRv4DAKE` with five callers (three inside the deleted class, two elsewhere — `_handle` paths around lines 11116 and 12497). It is lifted to a module-level function defined before `class DAKE1RateLimiter:`. All five callers repointed from `OTRv4DAKE._safe_b64decode(...)` to the bare `_safe_b64decode(...)`.

**`ClientProfile.__init__`** previously accepted legacy `ed448.Ed448PrivateKey` / `x448.X448PrivateKey` arguments and converted them to Rust handles via `isinstance` branches (a test-only path). Those branches are deleted (option B1): `ClientProfile` now accepts only `None` (generate a fresh Rust handle) or an already-constructed handle. The cryptography-library type hints on the `__init__` signature are stripped. Every runtime `ClientProfile()` call site constructs with no arguments, so nothing in production is affected.

**Four `serialization.Raw` sites removed.** `remote_long_term_pub` has held raw 57-byte Ed448 public-key bytes since v10.6.19 (Phase 5.3h-C), so the `.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)` calls in `get_fingerprint()`, `_get_remote_fp()`, and the two `pub_key_data` extraction sites were operating on raw bytes anyway (their surrounding `try/except` swallowed the `AttributeError`). Replaced with direct `bytes(...)` use. The `remote_long_term_pub` type hint changed from `Optional[ed448.Ed448PublicKey]` to `Optional[bytes]`.

### Net effect

883 lines removed from `otrv4+.py`. No Rust changes — the Rust core was already complete at the v10.6.21 state. The crypto surface of the project is now Rust (`otrv4_core`) plus two C extensions (`otr4_crypto_ext`, `otr4_ed448_ct`) slated for removal in Phase 5.3i / 5.3k. There is no OpenSSL-backed Python crypto anywhere.

### Files touched

- `otrv4+.py`: deleted `OTRv4DAKE` class and `_use_rust`/`_py_fallback` machinery; rescued `_safe_b64decode` to module scope; rewrote `ClientProfile.__init__` (B1); removed four `serialization.Raw` sites; removed the `from cryptography...` import; VERSION → `10.7`
- `README.md`: chip → v10.7; architecture box notes the library is removed; caveat about the cryptography library replaced; Quick start drops the `pip install cryptography` step
- `SECURITY.md`: known-issue 3 rewritten — the cryptography library is gone, with the v10.6.18→v10.7 removal sequence documented; memory-safety model updated
- `ROADMAP.md`: Phase 5.3h-D marked complete; 5.3i is now the largest remaining hardening item
- `FEATURES.md`: primitive table no longer lists any cryptography-library implementation
- `CHANGELOG.md`: this entry

### Build verification

```
cargo test --release --no-default-features --features pq-rust
# expected: 17 passed (5 ring_sig + 1 RFC 8032 Ed448 + 3 mldsa + 3 aead
#                      + 3 key_handles Ed448 + 2 X448)
```

`python otrv4+.py --debug` boots to the connect screen with no `NameError` or `ImportError` — the boot-check that confirms every reference to the deleted class and removed imports was caught. Live: DAKE + SMP verified over I2P.

---

## v10.6.21 — Phase 5.3h-D stage 2: X448 ratchet DH moved to Rust

**The double ratchet's X448 Diffie-Hellman now runs in the Rust core. No Python cryptography-library X448 remains in the message path.**

`RustBackedDoubleRatchet` performed its DH ratchet steps with `cryptography.x448` — `X448PrivateKey.generate()`, `.exchange()`, `X448PublicKey.from_public_bytes()` — running on every message after the first. These now use the Rust `otrv4_core` `X448KeyHandle`.

**No new Rust crypto.** `generate_x448_keypair()` and `X448KeyHandle.dh()` already existed (used by `ClientProfile` since the v10.6.12 handle work) and were already registered in `lib.rs`. Stage 2 was a Python swap plus two Rust test vectors.

### Python changes (seven edits in `RustBackedDoubleRatchet`)

- `__init__` and `from_dake_output`: `dh_ratchet_local` is now an `X448KeyHandle` from `generate_x448_keypair()`; `dh_ratchet_local_pub` from `handle.public_bytes()`.
- `_decrypt_new_dh`: receive-side and send-side DH via `handle.dh(peer_pub_bytes)`, which takes the raw 56-byte peer key directly.
- `_ratchet`: send-side forced ratchet step, same swap.
- The first-message remote-pub record stores raw 56 bytes only; `dh_ratchet_remote` (the object) is set to `None` — it was never read anywhere, every consumer uses `dh_ratchet_remote_pub` (the bytes).

### Correctness

X448 is RFC 7748 and fully deterministic — a given (clamped scalar, u-coordinate) pair has exactly one correct output. The `x448` crate clamps the scalar inside `Secret::from` (RFC 7748: `byte0 &= 252`, `byte55 |= 128`) and rejects low-order points, matching OpenSSL's behaviour. A v10.6.21 peer and an older cryptography-library peer therefore derive byte-identical DH secrets and the ratchet stays in sync.

Two Rust tests added to `key_handles.rs` as the build-time desync guard:

- `x448_rfc7748_known_answer` — the `x448` crate reproduces RFC 7748 §5.2's published X448 test vector. Since OpenSSL also implements RFC 7748, matching the vector means the two agree.
- `x448_handle_dh_is_symmetric` — two generated handles derive the same shared secret from each other.

### Files touched

- `Rust/src/key_handles.rs`: added `x448_rfc7748_known_answer` and `x448_handle_dh_is_symmetric` tests
- `Rust/Cargo.toml`: version 0.10.20 → 0.10.21
- `otrv4+.py`: seven ratchet edits; VERSION → `10.6.21`

### Build verification

```
cargo test --release --no-default-features --features pq-rust
# expected: 17 passed (15 prior + 2 X448)
```

Live: DAKE + sustained multi-message exchange both directions over I2P, across 5+ DH-ratchet epochs (DATA ratchet counter stepped 0→5). Every message decrypted clean — the proof that the Rust X448 swap is byte-correct against a live peer. The test spanned multiple I2P transport disconnects; the ratchet stayed in sync across them.

---

## v10.6.20 — Phase 5.3h-D stage 1: ClientProfile Ed448 verify moved to Rust

**The last security-critical Ed448 operation that used the Python cryptography library now runs in Rust.**

`ClientProfile.decode()` verified incoming-peer profile signatures with `ed448.Ed448PublicKey.from_public_bytes(pub).verify(sig, signed_data)`. It now calls a new Rust PyO3 function, `otrv4_core.verify_ed448_sig(pub_bytes, msg, sig_bytes) -> bool`.

### Correctness

`verify_ed448_sig` wraps `VerifyingKey::verify_raw` — the inherent pure-Ed448 verifier from `ed448-goldilocks-plus` 0.16. This is the exact counterpart of `Ed448KeyHandle::sign`, which calls `SigningKey::sign_raw`. ClientProfile signatures are produced by that same handle's `sign()` method (`encode()`, the `self.identity_key.sign(...)` call), so signer and verifier now use identical RFC 8032 pure-Ed448 framing with an empty context. A profile signed by any v10.6.x build verifies unchanged.

`verify_ed448_sig` returns `False` on a failed verification (bad signature, public key not a valid curve point) and raises `ValueError` only on structurally malformed input (wrong public-key or signature length), so the Python caller can distinguish a forged profile from malformed bytes.

### Crate API note

The `ed448-goldilocks-plus` 0.16 `VerifyingKey` is constructed via `VerifyingKey::from_bytes(&[u8; 57])`, not a `TryFrom<&[u8; 57]>` impl (the `TryFrom<PublicKeyBytes>` impl the compiler suggests is a pkcs8 wrapper). `Signature` is built from a slice via `Signature::try_from(&[u8])`, which checks length internally. Both were confirmed against the installed crate source rather than assumed.

### Files touched

- `Rust/src/key_handles.rs`: added `verify_ed448_sig` PyO3 function, a `#[cfg(test)]` module with three tests (`ed448_sign_then_verify_roundtrip`, `ed448_verify_rejects_tampered_msg`, `ed448_verify_rejects_bad_lengths`), and the `VerifyingKey` / `Signature` imports
- `Rust/src/lib.rs`: registered `verify_ed448_sig`
- `Rust/Cargo.toml`: version 0.10.19 → 0.10.20
- `otrv4+.py`: `ClientProfile.decode()` swaps to `_RustDAKE_module.verify_ed448_sig`; `_check_rust_requirements` requires it; VERSION → `10.6.20`

The `ed448` cryptography-library import was **not** removed at v10.6.20 — the legacy non-Rust DAKE paths still referenced it. It was removed at v10.7 when the dead `OTRv4DAKE` class that contained those paths was deleted.

### Build verification

```
cargo test --release --no-default-features --features pq-rust
# expected: 15 passed (12 prior + 3 key_handles Ed448)
```

Live: DAKE completes; the peer's ClientProfile signature verifies through the Rust path.

---

## v10.6.19 — Phase 5.3h, parts A2 + B + C

**Three of four production `cryptography` library use-classes retired. New Rust AEAD module. Startup migration for legacy orphan files.**

### Phase 5.3h scope reality check

Phase 5.3h was originally scoped as "one focused session, ~100-150 lines." Diagnostic showed this estimate was off by an order of magnitude: the `cryptography` library has 4 use classes (AESGCM, Ed448PublicKey, X448PrivateKey/PublicKey, serialization.Raw), totalling 40+ call sites with deep coupling to the ratchet's DH path.

v10.6.19 ships the three smaller sub-phases (A2 + B + C). The fourth (Part D — drop Ed448 verify, X448, and serialization.Raw) was multi-session and rescheduled; it shipped across v10.6.20, v10.6.21, and v10.7.

### Part A2 — legacy on-disk file cleanup

Startup migration in `main()` securely destroys orphan files from pre-`~/.otrv4plus/` builds:

- `~/.otrv4_vault` (633 bytes, no current code references it)
- `~/.otrv4_smp_secrets.json` (97 bytes, legacy SMP-secrets file at home root)
- `~/.otrv4_keys/` (legacy keys directory)

Uses the existing `_secure_file_destroy()` NIST SP 800-88r1 primitive: encrypt zeros with a fresh AES-256-GCM key, overwrite the file with ciphertext + tag, fsync, zeroize the key via `_ossl.cleanse`, then unlink. No-op for new installs.

### Part B — AES-256-GCM moved to Rust

New `Rust/src/aead.rs` exposes two PyO3 functions:

- `otrv4_core.aes256gcm_encrypt(key, nonce, plaintext, aad) -> bytes`
- `otrv4_core.aes256gcm_decrypt(key, nonce, ct_and_tag, aad) -> bytes`

Wraps the `aes-gcm` 0.10 crate. Wire-identical to `cryptography.hazmat.primitives.ciphers.aead.AESGCM`. Three live AESGCM call sites swapped: `SMPAutoRespondStorage._load/_save`, `SecureKeyStorage._encrypt_key/_decrypt_key`, and `_secure_file_destroy`. Files written by v10.6.18 decrypt cleanly under v10.6.19. Three new Rust unit tests.

### Part C — Ed448PublicKey wrap removed at six live sites

Six `Ed448PublicKey.from_public_bytes(...)` call sites (three in `RustDAKEAdapter`, three in `OTRv4IRCClient`) swapped from cryptography-library wrapping to raw bytes. `remote_identity_key` and `remote_long_term_pub` now hold raw bytes; the SHA3-512 fingerprint path uses the bytes mirror directly.

### `cryptography` library import diet

Dropped `AESGCM` (replaced by Rust) and `hashes` (confirmed unused). The `ed448` and `x448` imports remained at v10.6.19; they were removed later in Phase 5.3h-D.

### Files touched

- `Rust/src/aead.rs`: new file, ~165 lines including tests
- `Rust/src/lib.rs`: added `pub mod aead;` and two `add_function` registrations
- `Rust/Cargo.toml`: version 0.10.18 → 0.10.19
- `otrv4+.py`: AESGCM/hashes imports dropped; three AESGCM sites swapped; six Ed448PublicKey wrap sites replaced; `_check_rust_requirements` requires the aead functions; startup orphan-file migration; VERSION → `10.6.19`
- `README.md`, `SECURITY.md`, `ROADMAP.md`, `CHANGELOG.md`, `FEATURES.md`: updated

### Build verification

```
cargo test --release --no-default-features --features pq-rust
# expected: 12 passed (5 ring_sig + 1 RFC 8032 + 3 mldsa + 3 aead)
```

---

## v10.6.18 — Phase 5.3j + Phase 5.3g (ephemeral-by-design decided)

**`otr4_mldsa_ext` C extension retired; ML-DSA-87 now runs entirely on `pqcrypto-mldsa 0.1.2` via Rust PyO3 bindings.**

The Python `MLDSA87Auth` class is unchanged externally — same `PUB_BYTES = 2592`, `SIG_BYTES = 4627`, same wire-format guards across the four parse sites in `EnhancedOTR.{_handle_dake1, _handle_dake2, _handle_dake3_initiator, _handle_dake3_responder}`. Three call sites internal to the class now delegate to `_RustDAKE_module.mldsa87_keygen / mldsa87_sign / mldsa87_verify` instead of the deleted `_mldsa.mldsa87_*` C extension entry points.

The new Rust module `Rust/src/mldsa.rs` is a thin PyO3 wrapper over `pqcrypto-mldsa::mldsa87::{keypair, detached_sign, verify_detached_signature}`. Three unit tests in the same file: round-trip, tampered-message rejection, FIPS 204 byte-size assertions (2592 / 4896 / 4627).

### Wire format

Byte-identical to v10.6.17. Both v10.6.17 and v10.6.18 peers can DAKE with each other — same FIPS 204 ML-DSA-87 parameter set, same PQClean reference implementation underneath.

### Cargo.toml hardening

`pqcrypto-mldsa` is pinned to `default-features = false, features = ["std"]` to disable AVX2 and NEON SIMD code paths. Same trap that hit `pqcrypto-mlkem` in v10.6.16: the NEON path triggers `SIGILL` on Termux/aarch64 at first `mldsa87_keygen()` call.

### Phase 5.3g — ephemeral identity (DECIDED)

After consideration, OTRv4+ keeps ephemeral identities by design. Fingerprints regenerate at every launch; no persistent vault. Rationale documented in ROADMAP.md and SECURITY.md.

### Files touched
- `Rust/src/mldsa.rs`: new file, ~120 lines including tests
- `Rust/src/lib.rs`: added `pub mod mldsa;` and three `add_function` registrations
- `Rust/Cargo.toml`: pqcrypto-mldsa pinned to `default-features = false`, version 0.10.17 → 0.10.18
- `otrv4+.py`: removed `import otr4_mldsa_ext as _mldsa` block; `MLDSA87_AVAILABLE` reduced to a hardcoded `True`; three `_mldsa.*` calls in `MLDSA87Auth` swapped to `_RustDAKE_module.*`; `_check_rust_requirements` now requires `mldsa87_keygen/sign/verify`; VERSION → `10.6.18`
- `README.md`, `SECURITY.md`, `ROADMAP.md`, `FEATURES.md`: updated

### Build verification

```
cargo test --release --no-default-features --features pq-rust
# expected: 9 passed (5 ring_sig + 1 RFC 8032 + 3 mldsa)
```

---

## v10.6.17 — Phase 5.3f-narrow

**Boot-time cross-verify removed; RFC 8032 vectors now build-time gate.**

The Python boot helpers `_verify_ed448_rust_compat()` and `_verify_ring_sig_rust_compat()` are deleted. They previously generated a fresh Ed448 keypair via the cryptography library at every program start, signed a test message with both Rust and OpenSSL, and compared byte-for-byte.

Both functions and all four call sites are removed. Replacement: `Rust/src/test_vectors.rs` contains the RFC 8032 §7.4 "Blank" Ed448 vector as `const` arrays and a `#[cfg(test)]` harness that signs with `ed448-goldilocks-plus::SigningKey` and asserts byte-equality.

**Boot is faster** (saves ~200ms). Six obsolete boot-print lines no longer appear.

### Files touched
- `otrv4+.py`: deleted ~150 lines. VERSION → `10.6.17`.
- `Rust/src/test_vectors.rs`: new file, ~100 lines.
- `Rust/src/lib.rs`: added `pub mod test_vectors;`.
- `Rust/Cargo.toml`: version 0.10.16 → 0.10.17.

---

## v10.6.16 — ML-KEM migration

**`pqcrypto-kyber 0.8` (round-3 Kyber) replaced by `pqcrypto-mlkem 0.1.1` (FIPS 203 ML-KEM-1024).**

NIST finalised FIPS 203 in August 2024. The standard differs from round-3 Kyber in the Fujisaki-Okamoto domain-separator constants; algorithms and parameter sizes are otherwise identical. The `pqcrypto-mlkem` Rust API is drop-in compatible with `pqcrypto-kyber`.

### Cargo.toml carve-out

Pinned to `default-features = false, features = ["std"]` to select the portable PQClean C reference — the NEON path caused SIGILL at first `keypair()` call on Termux/aarch64.

### Wire compatibility

Wire-incompatible with v10.6.15 and earlier. Both peers must run v10.6.16+.

### Files touched
- `Rust/Cargo.toml`: dependency swap, version 0.10.14 → 0.10.16.
- `Rust/src/dake.rs`: 7 call sites renamed `pqcrypto_kyber::kyber1024::` → `pqcrypto_mlkem::mlkem1024::`.

---

## v10.6.15.5 — Cargo.toml: restore signing+pkcs8 features

**Latent silent build break exposed by `cargo clean`.**

An earlier hardening pass had set `ed448-goldilocks-plus` to `default-features = false, features = ["alloc"]`, silently dropping `signing` (which gates `SigningKey`) and `pkcs8`. The break was latent because the live `.so` kept running until a `cargo build` was forced. Fix restored `features = ["alloc", "signing", "pkcs8"]`.

---

## v10.6.15 — SMP race fix

**Tie-break by fingerprint when both peers run `/smp start` simultaneously.**

If both peers run `/smp start` near-simultaneously, each generates SMP1 locally before either receives the other's. Resolution: at SMP1 receive, if the engine is non-Idle, compare identity public bytes — lower fingerprint keeps initiator role, higher fingerprint yields, aborts its own `RustSMP`, rebuilds fresh, rebinds the secret from the `RustSMPVault`, and processes the incoming SMP1 as responder.

---

## v10.6.14 — `lazy_static` → `std::sync::LazyLock`

RustSec lists `lazy_static 1.5` as unmaintained. Replaced with stdlib `LazyLock` (stable since Rust 1.80). Three statics in `smp.rs` converted; all 31 call sites unchanged. MSRV raised to 1.80+.

---

## v10.6.13

**SMP regression fix from v10.6.12.**

v10.6.12 left seven Python call sites using the legacy `.public_key().public_bytes(...)` chain on what was now a Rust handle. One site, `EnhancedOTRSession.set_smp_secret`, read the local fingerprint through the broken chain and silently fell back to an empty bytes literal, diverging the SMP secret hash. All seven sites converted to `bytes(handle.public_bytes())`. No Rust changes.

---

## v10.6.12

**Phase 5.3e: long-term identity keys owned by Rust.**

`ClientProfile.identity_key` and `.prekey` are now `Ed448KeyHandle` and `X448KeyHandle` opaque PyO3 classes. Private bytes live inside Rust `SecretBytes<N>` (ZeroizeOnDrop). New Rust file `src/key_handles.rs` with `Ed448KeyHandle`, `X448KeyHandle`, `generate_ed448_keypair()`, `generate_x448_keypair()`. New `dake::PyDake::sign_profile_body_and_construct_with_handles` takes the handles directly. Wire-compatible with v10.6.11.

---

## v10.6.11

**Phase 5.4: Rust-only, no fallbacks, regression fix.**

OTRv4+ is now a thin Python wrapper around the `otrv4_core` Rust crate. No production codepath falls back to the C extension or the cryptography library for ring sig, Ed448 sign, DAKE, SMP, or ratchet. `_check_rust_requirements()` runs at module load and raises `ImportError` if the Rust core is missing or incomplete.

Note: the pure-Python `OTRv4DAKE` class was retained as nominal fallback code at v10.6.11, but `RustDAKEAdapter` already raised rather than constructing it — it was effectively dead from this version onward. It was formally deleted at v10.7.

---

## v10.6.10

**Phase 5.3d.** Bytearray + wipe in `RingSignature.sign()`. Contained a regression that broke DAKE3 (`_rust_ring_sign` called with a bare bytearray, rejected by PyO3). Fixed in v10.6.11.

---

## v10.6.9

**Phase 5.3c: Rust DAKE3 ring signature.** New file `src/ring_sig.rs` (~407 lines) implementing OTRv4 §4.3.3 Schnorr ring signature in pure Rust using `ed448-goldilocks-plus` and `sha3`.

---

## v10.6.8

**Phase 5.3b: dead-code disk persistence removal.** `_store_identity()` previously wrote encrypted private-key blobs to disk that nothing read back. Removed; one-shot migration overwrites and unlinks legacy `identity.ed448.bin` / `prekey.x448.bin`.

---

## v10.6.7

**Phase 5.3a-cleanup.** Added `ClientProfile.encode_unsigned()`. `RustDAKEAdapter.__init__` uses `sign_profile_body_and_construct` in a single FFI call.

---

## v10.6.6

**Phase 5.3a (Option A2): Ed448 sign via Rust.** Added `sign_profile_body_and_construct` and `ed448_sign_test` to the Rust DAKE class.

---

## v10.6.5

**Phase 5.2: `new_from_bytearrays`.** Rust constructor takes `Bound<PyByteArray>`, copies into `SecretBytes<N>`, then wipes the source bytearray in-place.

---

## v10.6.4

**Phase 5.1.** `RustDAKEAdapter.__init__` extracts identity and prekey private bytes into mutable bytearrays, wipes them after Rust copies into `SecretBytes`.

---

## v10.6.3

**Phase 4: DakeOutput opaque handle. 11/11 audit findings closed.**

DAKE session keys never cross the Python heap. The `DakeOutput` PyO3 handle holds them in a private `RefCell<Option<DakeSessionKeys>>` with no Python-visible accessor. `consume_into_ratchet()` moves them directly into the ratchet's owned `SecretBytes` fields, taking the actual `is_initiator` flag.

---

## Older versions

Earlier v10.6.x and v10.5.x focused on Rust SMP, Rust double ratchet, X448 ratchet bugs, fragment buffer collision fixes, and the C extension constant-time Ed448 path. See git history for detail.
