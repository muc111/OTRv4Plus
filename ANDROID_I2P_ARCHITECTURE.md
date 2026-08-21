# Android I2P architecture (working design)

Decision 3: proceed with the bundled-router architecture. This is the working
design, not an implementation — no transport code was changed, and no direct
non-I2P fallback was added.

Feasibility background, including why depending on the separately installed
i2pd app does not work, is in `ANDROID_I2P_FEASIBILITY.md`. This document
answers the twelve structural questions the decision asks.

**Scope note.** The specification is explicit that the calculator-disguise /
foreground-notification UX problem is *not* to be solved yet. §9 states the
constraint that shapes the design and stops there. Nothing here proposes hiding
or faking a notification: Android requires a visible notification for a
foreground service, and this design does not attempt to evade that.

---

## 1. Android process model

```
┌──────────────────────────────── APK ────────────────────────────────┐
│                                                                     │
│  :main process                          :i2p process                │
│  ───────────────                        ────────────────            │
│  MainActivity / Compose                 I2pRouterService             │
│  AppLockManager, Keystore, DEK          bundled libi2pd (C++)        │
│  Chaquopy / CPython 3.12                SAM bridge, loopback-bound   │
│  OTRv4+ Python orchestration                                        │
│  otrv4_core (Rust)                                                  │
│  identity, message store                                            │
│                                                                     │
│        ── AIDL / bound Service, control only ──▶                    │
│        ◀── SAM stream over a private socket ──                      │
└─────────────────────────────────────────────────────────────────────┘
```

**The router runs in a separate process of our own app**
(`android:process=":i2p"`), not in-process and not in another app.

Rationale, and it is the central design decision here: i2pd is a C++ anonymity
router, and it is a large attack surface. The project's main structural security
claim is `#![forbid(unsafe_code)]` over the cryptographic core. Putting a C++
network daemon in the same address space as the unwrapped data-encryption key
and the Rust key handles would undo much of that claim — a memory-safety failure
in the router would sit next to the identity seed.

A separate process gives:

- the router **no access** to the DEK, the identity, or the message store;
- a router crash that does **not** take down the app or the key material;
- independent OOM-kill accounting, so a router leak does not kill the UI;
- the SAM endpoint on a socket only our two processes can reach.

The cost is IPC, which is real work but is work we control — unlike the
cross-app case, which is blocked outright by per-UID loopback isolation.

---

## 2. Router lifecycle

| Phase | Behaviour |
|---|---|
| **Start** | Only on demand: when the user opens a conversation or places a call, never at app launch. Starting a router at launch would build tunnels for a user who may only be checking the time. |
| **Ready** | The service reports readiness when the SAM bridge accepts a `HELLO VERSION` and a `SESSION CREATE` succeeds — not merely when the process is up. Tunnel construction takes materially longer than process start. |
| **Idle** | Kept alive while any session or call is live, plus a configurable grace period so a brief close/reopen does not rebuild tunnels. |
| **Stop** | Explicit `stopService` after the grace period with no live sessions, on user sign-out, and on app relock. |
| **Relock** | **The router is stopped when the app relocks.** Tunnels are a live network identity; leaving them up while the app is locked would keep the user reachable and observable in a state the user believes is closed. |

The existing code already tolerates a slow router: `SAM_HELLO_TIMEOUT` 30s,
`SAM_SESSION_TIMEOUT` 300s, `SAM_CONNECT_TIMEOUT` 240s, `SAM_ACCEPT_TIMEOUT`
300s (`otrv4plus_voice.py`). No timeout changes are needed for Android.

---

## 3. Startup and shutdown

**Startup** is asynchronous and must be surfaced honestly. States:
`STOPPED → STARTING → BUILDING_TUNNELS → READY → STOPPING`.

The UI shows "connecting" until `READY`, and must not present a message as
sendable before then. Startup latency **[requires measurement on a device]** —
qualitatively it is dominated by tunnel construction, not process start, and the
first usable connection will lag app launch noticeably.

**Shutdown** must be graceful: close SAM sessions, let i2pd tear down tunnels,
then stop the process. An abrupt kill leaves tunnel state on the network side to
expire on its own. Android may not always allow a graceful path (see §7), so the
design must be correct under abrupt termination too — and it is, because SAM
sessions are `TRANSIENT` and per-call.

---

## 4. Crash recovery

The router process is expected to die sometimes: OOM kill, an i2pd bug, or
Android reclaiming a backgrounded process.

- The main process observes death through the bound-service `onServiceDisconnected`
  and through SAM socket errors.
- **No automatic restart loop.** Restart is attempted with exponential backoff
  and a ceiling, so a router that crashes on startup cannot become a battery
  drain. `otrv4plus_xmpp.py` already implements I2P-aware reconnect with
  exponential backoff; the same discipline applies here.
- Active calls are lost. `CallState.ENDED` is absorbing, so the existing state
  machine degrades cleanly rather than corrupting; the UI reports the call ended,
  not that it is still connected.
- **The app must never fall back to a non-I2P path** on router failure. Doing so
  would leak the user's IP address at exactly the moment they believe they are
  protected. Failure is reported as failure.

---

## 5. SAM connection and local port protection

The existing code connects to a SAM bridge at `127.0.0.1:7656`. On Android,
binding a TCP port on loopback is visible to **every** app on the device, so
keeping the literal port is the wrong choice for a bundled router.

**Design: a filesystem-invisible abstract unix domain socket** in the app's own
namespace (`LocalSocket` / `LocalServerSocket`), not a TCP port.

| Property | TCP `127.0.0.1:7656` | Abstract unix socket |
|---|---|---|
| Reachable by other apps | **Yes** | No |
| Reachable by the main process | Yes | Yes |
| Requires a port to be free | Yes | No |
| Collides with an installed i2pd app | **Yes** | No |

The SAM *protocol* is unchanged — the same `HELLO`/`SESSION CREATE`/`STREAM`
exchanges run over a different socket type. `otrv4plus_voice.py` already injects
its transport through `bind_host()` (`sam_open`, `sam_read_line`, `sam_parse`,
`sam_release`), so the Android host supplies socket-opening helpers and **no
voice or transport logic changes**. That seam is why this is a configuration
change rather than a rewrite.

If a TCP port must be used instead (for example because the chosen i2pd build
cannot be configured for a unix socket), it must bind `127.0.0.1` only, use an
ephemeral port communicated over the bound service rather than a fixed 7656, and
the design must record that other apps on the device can reach it.

---

## 6. Foreground service, notifications, battery

**A foreground service is required, not optional.** Android does not permit a
backgrounded process to hold long-lived network connections; a router with live
tunnels is precisely the case foreground services exist for.

- **Service type**: `connectedDevice` or `dataSync` are the plausible
  declarations. Final choice depends on Play policy at submission time and is a
  Phase 8 decision.
- **Notification**: mandatory and user-visible. On Android 13+ the app must also
  hold `POST_NOTIFICATIONS`.
- **The notification must be truthful.** It will say the app is running a
  background connection. This design does **not** attempt to hide it, disguise
  it as something else, or use any mechanism to evade the platform requirement.
  Doing so would violate Android platform requirements and likely Play policy,
  and the specification forbids it.
- **The tension with the calculator disguise is real and unresolved**, and is
  deliberately left unresolved here. The plausible shapes are: run the router
  only while a conversation or call is active (shortening but not removing the
  window), accept a visible notification, or reconsider the disguise. **This is a
  product decision for a later phase.**
- **Battery**: maintaining tunnels costs power continuously; Doze and App
  Standby will restrict a backgrounded app, and the foreground service is what
  keeps the router alive. Actual consumption **[requires measurement]** — no
  figure is given because none could be measured here.

---

## 7. Process death

| Event | Result |
|---|---|
| `:i2p` killed, `:main` alive | Tunnels lost; SAM errors surface; backoff restart; active calls end |
| `:main` killed, `:i2p` alive | The router is stopped — it must not outlive the app that owns it. The service stops itself when its last client unbinds. |
| Both killed | Everything is lost; the next launch starts LOCKED and the router is not started until after unlock |
| Device reboot | Nothing auto-starts. No `BOOT_COMPLETED` receiver: a router starting before the user has unlocked the app would put them on the network without their knowledge. |

**Identity survives all of these** — it is sealed on disk (decision B1) and does
not depend on the router. Tunnels and SAM sessions are ephemeral by design;
losing them costs reconnection time, not identity.

---

## 8. Clean relock behaviour

Relock is a security boundary, so it must reach the router:

```
AppLockManager -> LOCKED
      │
      ├── release the DataKeyHandle (already implemented and tested)
      ├── tear down OTR sessions
      └── stop I2pRouterService  ──▶ close SAM sessions, stop tunnels
```

Rationale: after relock the user believes the application is closed. Live I2P
tunnels would keep them reachable and network-observable in that state. The
router therefore stops on relock and restarts on the next unlock, paying the
tunnel-build cost again.

That cost is the reason the relock grace period exists (`AppLockManager`,
default 30s) — a brief app switch does not tear down the network.

---

## 9. Isolation from the UI and security state machine

| Component | Process | Holds key material? | Knows the lock state? |
|---|---|---|---|
| Compose UI | `:main` | No | Observes it |
| `AppLockManager`, Keystore, DEK | `:main` | **Yes** | Owns it |
| OTRv4+ Python + Rust core | `:main` | Yes (in Rust) | No |
| **i2pd router** | **`:i2p`** | **No** | **No** |

The router is told only "start" and "stop". It never learns the lock state, never
sees the DEK, never sees an identity, and never sees plaintext — OTR ciphertext
is what transits it, which is the point of the layering. The control interface is
a bound Service with a deliberately small surface: `start()`, `stop()`,
`status()`, and a readiness callback.

---

## 10. What is not decided

- **Service type declaration** — depends on Play policy at submission (Phase 8).
- **Startup latency, RAM, battery** — **[require measurement]**; no figures are
  invented.
- **Whether i2pd's embedded wrapper exposes SAM specifically**, as opposed to
  I2CP only. This is the cheapest decisive experiment and gates everything else.
- **i2pd's own OpenSSL version on Android** — see `LICENSING_AUDIT.md` §5.
- **The disguise/notification tension** — explicitly out of scope for now.

## 11. First implementation steps (Phase 8, not now)

1. Build `libi2pd` for arm64-v8a and confirm it links alongside CPython and the
   Rust core.
2. Confirm the embedded wrapper offers SAM with `STREAM ACCEPT` and `TRANSIENT`
   sessions.
3. Measure startup-to-ready, RSS and idle battery on a low-end device.
4. Implement `I2pRouterService` in `:i2p` with the bound-service control surface.
5. Supply Android socket helpers to `bind_host()` — no voice logic changes.
6. Wire router stop into `AppLockManager`'s relock path.
