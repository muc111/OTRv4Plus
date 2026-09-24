<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright (C) 2025-2026 muc111 -->

# Android foundation: root causes, changes, and what is still unverified

> OTRv4+ is an I2P-first private communications client. It has three surfaces:
> the IRC terminal client, the XMPP terminal client, and this — a **native
> Android app under construction**. The terminal clients running under Termux
> are the supported way to use OTRv4+ today; this app is not yet a replacement
> for them. See [README.md](README.md#project-status).

Covers the work from `d921c2b` to `347ce93` on
`claude/otrv4plus-android-spec-a3oq4d`.

**The foundation is NOT signed off.** Section 5 lists what remains, and the
handset gate at the end of it has not been attempted. Everything below
distinguishes three claims that are easy to blur:

| Tier | Meaning |
|---|---|
| **Executed** | A test runs the code and asserts its behaviour. |
| **Compiled** | CI builds it and assembles an APK. No test executes a line. |
| **Unverified** | Neither. Behaviour on a device is unknown. |

---

## 1. Root causes

### 1.1 One defect produced three of the reported symptoms

The keepalive's liveness probe called

```python
await self["xep_0199"].async_ping(host, timeout=...)
```

**slixmpp 1.17 has no `async_ping`.** It was removed upstream in favour of
`ping`. The call raised `AttributeError`; both clients classified any exception
that was not `IqError` as "the server did not answer"; so **every probe reported
a dead stream on a healthy connection.**

On Android the keepalive then acted on it. Two consecutive failures, 60 s
apart, and `_declare_stream_dead` cleared `is_connected` and closed a working
XMPP stream — roughly two minutes after connecting, whatever the user was
doing.

Everything downstream keys off `is_connected`, which is why one defect looked
like three:

| Symptom | Mechanism |
|---|---|
| Unexpected `DISCONNECTING` | The keepalive closed the stream; the service saw `connected == false` and moved to RECONNECTING/DISCONNECTING. |
| "presence unknown" for everyone | `ChatState.canSend()` is false while the link is down, and the UI refuses to claim knowledge of anyone's presence then. **Correct behaviour fed a wrong input.** |
| Add Contact did nothing | `ConnectionController._roster_call` refuses with `not_connected`. The UI was faithfully reporting a lie. |

**Why Termux survived the same line.** Its keepalive skips the probe entirely
while the stream is delivering traffic, so an active conversation never pings
at all — and the successful Termux session was an active conversation. A quiet
Termux session would have been reconnected every couple of minutes for no
reason. Same bug, different exposure.

**Why the test suite missed it.** `FakePing` provided `async_ping`. The real
plugin does not have it. Production called the absent method, the fake supplied
it, and every keepalive test passed against an API that does not exist.

Fixed in `otrv4plus_ping.py`, shared by both clients. Three outcomes are now
distinct where there were two: answered → alive, nothing came back → dead,
**could not ask → alive**. The third is the point: a client that cannot pose
the question has learned nothing, and manufacturing a disconnect out of its own
ignorance is the bug.

The Android transport also gained the traffic gate it was missing
(`KEEPALIVE_QUIET_S`), which is the terminal client's and the whole difference
in exposure.

### 1.2 Pending subscriptions were read and discarded

Separate from 1.1 and still true after it: a contact who has not yet approved
you is unknowable by design, and the app said only "presence unknown" —
indistinguishable from a broken connection.

`transport.roster()` read `subscription` and `_contact_view` dropped it. Two
fields were needed, not one: slixmpp keeps `pending_out` separately, because a
sent-and-unanswered request leaves `subscription` at `"none"`.

### 1.3 The sign-in screen asked for a domain the app already knew

The b32 destination was always internal. The screen's shape was the problem:
one "Address" field expecting `you@server.i2p`.

### 1.4 A message arriving in a pocket was marked read

Introduced by the service taking ownership of `ChatState`: `openConversation`
outlived the UI, so "alice's conversation is open" stayed true after the phone
was pocketed and an arriving message was marked read on that basis alone. The
unread badge was gone before the user ever looked.

### 1.5 POST_NOTIFICATIONS was declared and never requested

On API 33+ that means denied, and every notification was dropped silently —
including the foreground-service one. The connection would have run with
nothing on screen saying so.

---

## 2. Changes

| Component | What it does |
|---|---|
| `otrv4plus_ping.py` | **New.** The XEP-0199 round trip, shared by both clients. Finds whichever method this slixmpp has; keeps "could not ask" distinct from "no answer". |
| `android_bridge/transport.py` | Uses it; gains the inbound filter, `_stream_quiet_for`, and the traffic gate. Records presence, roster and keepalive events. |
| `otrv4plus_xmpp.py` | Same probe fix. Its quiet gate already existed. |
| `android_bridge/trace.py` | **New.** Bounded (4000) event ring. Redacts by key name; bans content-shaped keys. |
| `android_bridge/report.py` | **New.** Composes the trace, connection state and environment; sweeps the finished document again. |
| `android_bridge/connection.py` | `note`, `diagnostic_report`, `diagnostic_summary`. Traces every stage change and roster call. |
| `android_bridge/app.py` | `ContactView` carries `subscription` and `pending`. |
| `ui/DiagnosticsExport.kt` | **New.** FileProvider + Sharesheet. Writes bytes; renders nothing. |
| `connection/SignIn.kt` | **New.** Username/server resolution, in plain Kotlin. |
| `bridge/OtrCore.kt` | **New** `Subscription` enum. |
| `chat/InboundAlerts.kt` | **New.** When to interrupt; a count and nothing else. |
| `ui/ConnectScreen.kt` | Username field + server dropdown. |
| `ui/ConversationsScreen.kt` | "waiting for them to accept". |
| `MainActivity.kt` | Requests POST_NOTIFICATIONS; reports visibility from onStart/onStop. |

---

## 3. Tests

| Suite | Result |
|---|---|
| Python | **4358 passed**, 46 skipped, 1 xfailed |
| Kotlin (JVM, executed) | **230 passed** |
| Mutation (planted in real sources) | **34 planted, 34 caught** |
| CI — Rust cross-compile, licence gate, Kotlin tests, `assembleDebug`, APK publish | **green** (runs #53–#56) |

Re-planting the original ping bug now fails 6 tests. Before the fix it failed
none — which is the measure that matters.

---

## 4. What the diagnostic export contains, and what it cannot

Two independent mechanisms, because either alone is a single point of failure
for a file the user is about to attach to a bug tracker:

1. `trace` redacts field values **by key name** as they are recorded, and bans
   content-shaped keys (`body`, `message`, `text`, `plaintext`, …) outright.
2. `report._scrub` sweeps the **finished document** again, line by line,
   whichever layer wrote it.

Exception messages are never printed blindly: `failure.describe` selects the
detail by **type**, and frames are `basename:lineno in function`.

**JIDs and server addresses are included deliberately** — a roster, presence or
routing fault cannot be diagnosed without them — and the header of every file
says so in plain words.

---

## 5. What is NOT done

### 5.1 Physical device testing — the gate

**Not attempted.** There is no handset in this environment. The procedure is
`ANDROID_MESSAGING_DEVICE_TEST.md`; step 22a is the reported disconnect and
steps 26a–26i are the new capabilities.

Until that run happens, every claim above is *executed* or *compiled*, and
nothing is *verified*.

### 5.2 Two connection state models, not one

§26 asks for one authoritative state machine. There are still two: the Python
controller's stages (`idle`, `checking_router`, `building_tunnels`,
`connecting`, `authenticating`, `connected`, `failed`) and Kotlin's
`LinkPhase`. They are not *conflicting* — they describe different layers, and
the service's phase is derived from the transport's own `connected` — but they
are not unified either, and the brief asked for one model. **Not done.**

The mitigation shipped instead: every transition on both sides is recorded in
one trace with `state_before`/`state_after`, so the two are at least readable
as a single ordering. That answers the diagnostic half of §26 and not the
architectural half.

### 5.3 Add Contact: retry after reconnect

Add, remove, duplicate, invalid JID, not-connected and pending/accepted are
handled and reported. A contact added **while disconnected** is refused with a
sentence rather than queued for retry when the link returns. **Not done.**

### 5.4 Not attempted, and out of scope until the foundation is signed off

OTR DAKE on Android against Termux, SMP, encrypted messaging, file transfer,
audio. Untouched by this work, per the brief.

---

## 6. Preserved

No change to the protocol, the cryptography, the DAKE, SMP, the ratchet, the
trust model, the `?OTRv4F|` fragmentation wire format (`MAX_FRAGMENT = 6000`),
the Rust core, the OTR engine-boundary classification, `OtrMode`, or
`SEND_PLAINTEXT`. The transport boundary from `22fc255` is intact and no
terminal/TUI code was pulled into the Android application.

The Termux client changed in exactly one place — the same probe fix — because
the defect was shared. Its full suite passes.
