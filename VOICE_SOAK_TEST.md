# Voice soak test — engineering benchmark

A 4+ hour continuous encrypted voice call over I2P with 3-hop tunnels, run after
the MAC fix (`ded35ac`) and the subsequent Rust rebuild.

**What this document is.** A record of one observed run, for engineering
purposes. It is a stress test, not a security proof. Nothing here demonstrates
forward secrecy, post-compromise security, anonymity or metadata resistance;
those are design properties, and §B/§C separate them from what was measured.

**What this document contains.** Aggregate counters and timing only. No audio,
message content, keys, seeds, SMP secrets, fingerprints, destinations or other
private material — none was collected for this report and none should be added.

---

## A. Observed results

Reported from the run. Phrasing is deliberate: these are observations over one
session on one network path, not invariants.

| Metric | Observed |
|---|---|
| Duration | 4+ hours, continuous |
| Transport | I2P, 3-hop tunnels |
| Voice frames transmitted | ~365,000 |
| Packet loss | **0 observed** |
| Authentication failures | **0 observed** |
| Replay rejections | **0 observed** |
| Cryptographic rekeys | **117 successful** |
| Rekey interval | ~2 minutes |
| One-way latency | ~650 ms |
| Round-trip time | ~1.3 s |
| Jitter, typical | 10–30 ms |
| Jitter buffer | absorbed observed jitter; adaptive |
| Network congestion | recovered from occasional congestion |
| Jingle / RTP signalling exposed to the XMPP server | **none observed** |

### A.1 Internal consistency check

The reported figures were cross-checked against the constants in
`otrv4plus_voice.py`. They reconcile:

| Check | Source | Result |
|---|---|---|
| Frame duration | `VOICE_FRAME_MS = 40` | 25 frames/s |
| Session length from frame count | 365,000 × 40 ms | **14,600 s = 4.06 h** — consistent with "4+ hours" |
| Session length from rekey count | 117 × `VOICE_REKEY_SECONDS = 120` | 14,040 s = 3.90 h |
| Rekeys implied by duration | 14,600 s ÷ 120 s | ~122 — 117 observed, consistent allowing for setup and teardown |
| Wire rate | 199 B/frame × 25 fps | ~39.8 kbit/s one direction |

> **Geometry note (v10.12.0).** This run was made at the then-default 40 ms
> frame. The production default has since moved to 60 ms — 279 B/frame at
> 16.7 fps, ~37.2 kbit/s — chosen because I2P charges by the packet rather
> than the byte. The figures above are left as measured; they are a record of
> that run, not a description of the current wire format. See
> [Rust/VOICE_TUNING.md](Rust/VOICE_TUNING.md).

| Media bitrate | `VOICE_BITRATE = 24000` | 24 kbit/s Opus |

The two independent derivations of session length — from frame count and from
rekey count — agree to within 4%. That is a useful cross-check: the counters were
not transcribed from a single source.

**Not independently reproduced.** These figures come from the reported run. This
environment has no I2P router, no audio device and no second endpoint, so the
session could not be re-executed here. The arithmetic above is verification of
*internal consistency*, not of the measurements themselves.

### A.2 What the counters mean

- **0 observed authentication failures** — over ~365,000 frames, every frame's
  AEAD tag verified. Each frame is sealed under a per-epoch key with a
  `(epoch, counter)` nonce, so this exercises the key schedule across 117 epoch
  transitions as well as the steady state.
- **0 observed replay rejections** — the replay window rejected nothing, i.e. no
  duplicate or stale counter arrived. On a clean path this is the expected
  result; it says the window did not produce false positives under 4 hours of
  real jitter and reordering, which is the failure mode that would break a call.
- **117 successful rekeys** — the two-phase commit (`CURRENT → PENDING →
  CONFIRMED → COMMITTED`) completed 117 times with no aborted epoch and no
  observed media interruption.
- **~650 ms one-way** — consistent with 3-hop I2P tunnels in each direction.
  This is a transport property, not a codec or crypto property.

---

## A.3 Second run — v10.15.1, 2026-09-04, instrumented

A shorter run on the current build, kept because it is the first with
`--voice-debug` throughout, so every number below is from the client's own
counters rather than a summary. 16½ minutes, hung up deliberately.

| Metric | Observed |
|---|---|
| Duration | 990 s (16½ min), ended by `/hangup` |
| Transport | I2P datagrams, Opus 16 kHz mono, 60 ms frames, 24 kbit/s CBR |
| Packets | ~86 per 5 s throughout — the constant rate the shaping specifies |
| Packet loss (`drop`) | **0**, every window |
| Authentication failures (`authfail`) | **0**, every window |
| Replay rejections (`replay`) | **0**, every window |
| Unkeyed / stale / foreign packets | **0**, every window |
| Cryptographic rekeys | **7, all committed** |
| Rekey interval | ~124 s |
| Round-trip | p50 1046 ms, p95 1967 ms, p99 3815 ms, max 4977 ms (n=180) |
| One-way | ~420 ms early, ~550-580 ms by the end |
| Mouth-to-ear | ~700 ms early, ~855 ms by the end |
| Inter-arrival spacing (60 ms frames) | p50 69 ms, p95 128 ms, p99 211 ms, max 281 ms |
| Jitter buffer | 4-5 frames against a target of 3; `underrun=27 shed=313 overflow=0` |
| Loop lag | p50 1 ms, p99 10-13 ms, max 17 ms |

**The counters that matter for the crypto are all zero.** Seven key epochs,
sixteen minutes, and not one packet that failed its AEAD tag, replayed, or
arrived under a key the receiver did not have. Combined with the four-hour run
in §A, that is two independent sessions with no authentication failure.

### A.3.1 Rekey timing, and one outlier

| Rekey | Sent | Committed | Elapsed |
|---|---|---|---|
| 1 | 146.2 s | 150.9 s | 4.7 s |
| 2 | 270.9 s | 275.6 s | 4.7 s |
| 3 | 395.7 s | 399.4 s | 3.7 s |
| **4** | 519.4 s | 537.4 s | **18.0 s** |
| 5 | 657.4 s | 663.5 s | 6.1 s |
| 6 | 783.5 s | 786.7 s | 3.2 s |
| 7 | 906.7 s | 912.7 s | 6.0 s |

Median 4.7 s; rekey 4 took nearly four times that. It committed correctly and
nothing was lost, so this is a latency observation, not a failure.

**Late packets cluster around rekeys.** `late` is 0 in almost every window,
and non-zero in exactly these: `late=12` at 262 s (just before rekey 2),
`late=2` at 402 s (just after rekey 3), `late=9` at 533 s (inside rekey 4's
slow window), and `late=2/2/1` at 698-724 s (after rekey 5). The handshake and
the media share one I2P path, so the rekey's own packets push audio past its
playout deadline. Nothing was dropped — the buffer absorbed or shed them.

This is a plausible mechanism, not a proven one: one session cannot separate it
from ordinary I2P tunnel churn, and rekey 4's window also coincided with the
call's worst RTT excursion. It is recorded so a future run can check it.

### A.3.2 Where the latency actually goes

```
mouth-to-ear ~855 ms  =  network 576 ms  +  jitter buffer 229 ms  +  playout 51 ms
```

Local processing is **0 %** of the budget by the client's own accounting.
Per-stage medians: encode 5.6 ms, seal 0.2 ms, queue 0.3 ms, decrypt 0.3 ms,
decode 0.9 ms. **The cryptography costs half a millisecond of an 855 ms
budget** — sealing and opening together. Whatever makes an I2P call feel slow,
it is not the post-quantum crypto.

The jitter buffer is a quarter of the budget, and it is running above its own
target (4-5 frames against 3) because inter-arrival spacing has a long tail.
That is the buffer doing its job on a bursty transport; it is also the only
part of the 855 ms this project controls.

### A.3.3 The 45-second silent start

`call active` was printed at 26.2 s. The first packet left at ~71 s. In
between: mic captured normally, ~84 packets (about 5 s of audio) held in the
backpressure queue, eight `no audio received in 5 s` warnings, and then a
clean drain with `drop=0`.

The media path was waiting on I2P tunnel build, which the client warns takes
30-120 s — but it had already said the call was active. **The defect is the
message, not the mechanism**: nothing was lost and nothing misbehaved, but the
user was told the call was up 45 s before it could carry audio. Holding that
line until the first packet is sent would report what is actually true.

---

## B. Security properties claimed by design

These are properties the **design** aims at. The soak test is consistent with
them; it does not establish any of them.

| Property | Mechanism | Established by this test? |
|---|---|---|
| Media confidentiality | AES-256-GCM per frame, per-epoch keys | **No** — no attempt to break it was made |
| Media integrity / authenticity | AEAD tag on every frame | **No** — 0 failures on a clean path is not an integrity proof |
| Replay resistance | replay window over `(epoch, counter)` | **No** — no replays were injected |
| Forward secrecy across epochs | rekey ratchet, old roots wiped | **No** — key compromise was not simulated |
| Post-compromise security | hybrid X448 + ML-KEM-1024 rekey | **No** |
| Post-quantum protection | ML-KEM-1024 in the rekey path | **No** |
| Signalling privacy from the XMPP server | signalling rides the OTR data channel, not Jingle | **Partially** — see §B.1 |

### B.1 The signalling observation

"No Jingle or RTP call signalling exposed to the XMPP server" is a **structural**
property of the design: call setup rides inside the encrypted OTR data channel
rather than as XEP-0166 Jingle stanzas, and media rides an I2P SAM stream rather
than RTP the server can see. The observation is consistent with that and is
worth recording.

It is **not** a metadata-resistance result. The server still sees that two JIDs
exchanged encrypted messages, and their sizes and timing. A call produces a
distinctive traffic pattern — the signalling burst at setup and the ~2-minute
rekey cadence are both observable to anyone watching the message stream, even
without reading it. Whether that pattern is distinguishable from ordinary
messaging was **not tested** and should not be assumed.

---

## C. Properties requiring formal or security review

Not addressed by this test, and not claimed:

1. **Formal verification of the voice key schedule.** The two-phase rekey commit
   and the transcript binding are AI-generated compositions over reviewed
   primitives. 117 successful rekeys show the state machine does not deadlock or
   desynchronise on a real network; they say nothing about whether the
   construction is sound.
2. **Deniability (L1).** Open. The MAC-key revelation mechanism is now
   implemented and verified end to end (`MAC_FIX_REVIEW.md`), but formal OTR
   deniability is not demonstrated. Do not use "deniable" as a product claim.
3. **Traffic analysis / metadata resistance.** See §B.1. Not tested.
4. **Side channels.** No timing or cache analysis was performed. The prior audit
   lists constant-time measurement on the real target as outstanding.
5. **Adversarial network conditions.** The run was over a functioning path. No
   active attacker, no injected forgeries, no forced replays, no deliberate
   packet reordering or drops, no rekey interruption.
6. **Long-run counter behaviour.** 365,000 frames is far below the counter
   bounds; nothing about exhaustion was exercised.
7. **Cross-implementation compatibility.** One build talking to itself.

---

## D. What the test does support

Stated conservatively, the run is evidence for:

- **Stability.** The voice stack sustained a 4-hour call without crashing,
  desynchronising, or leaking a state-machine error into the media path.
- **Correctness of the rekey state machine under real conditions.** 117
  transitions with no aborted epoch, on a path with 10–30 ms jitter and
  occasional congestion.
- **The jitter buffer works.** It absorbed observed jitter without the call
  degrading, which is the practical bar for usability.
- **No regression from the MAC fix.** The call ran after the fix and the Rust
  rebuild, so the changed frame plaintext layout and the new MAC derivation did
  not break sustained media. OBSERVED, on one run, with both endpoints on the
  same build. It says nothing about a mismatched pair — see §F.
- **Usability at I2P latency.** ~1.3 s RTT is high for conversation and users
  will notice it, but the call remained functional for hours.

That is a meaningful engineering result. It is not a security result.

---

## E. Relevance to the Android work

- The measured latency and jitter are the numbers the Android call UI must be
  designed around. ~1.3 s RTT means push-to-talk-like conversational rhythm, and
  the UI should not imply telephone-grade responsiveness.
- The ~2-minute rekey cadence is invisible to the user and must stay that way —
  no UI event should surface on a rekey.
- A 4-hour call implies a long-lived foreground service and sustained CPU and
  radio use. **Battery consumption was not measured** and remains an open item
  for the Android phase.
- The run was on a desktop/Termux-class host, not inside an APK. It says nothing
  about behaviour under Android's Doze, App Standby or memory pressure.

---

## F. Frame revision (audit C1)

The latency work moved 8 bytes of the fixed padding slot into a sender
timestamp carried **inside** the AEAD. The packet stays 199 bytes, so nothing
about the observable traffic pattern changed — but the frame *plaintext* layout
did, and `VOICE_PROTOCOL_VERSION` was still `3`.

That was the more dangerous of the two version gaps this branch found. A
mismatched pair would have authenticated every frame successfully under GCM —
the layout change is inside the sealed region, not in the AAD — and the failure
would have surfaced only as `unpad_opus` misreading Opus data: garbled audio,
with nothing pointing at a version mismatch.

`VOICE_PROTOCOL_VERSION` is now `4`. `parse_media_header` rejects any other
revision before the AEAD runs, with an error naming the version.
TEST-VERIFIED in `tests/test_protocol_version.py::TestVoiceFrameVersion`:
revision 3 and every other value are refused at the header, the current
revision parses, and the plaintext layout the bump exists for is pinned
(`VOICE_PLAIN_LEN == 2 + VOICE_TS_LEN + VOICE_OPUS_SLOT`).

The soak run predates the version bump and was conducted with matched
endpoints, so it is unaffected by the change; the rekey cadence, jitter and RTT
figures in §A stand as recorded.
