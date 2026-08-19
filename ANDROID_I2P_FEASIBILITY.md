# Android I2P / SAM feasibility

Phase 2 deliverable for blocker **B3**. The instruction is explicit: do not
replace I2P with a direct transport to simplify Android development, and do not
weaken the transport. This establishes feasibility and proposes an architecture;
it changes no transport code.

**Evidence status.** Facts sourced from upstream documentation are marked
**[verified]** with a link. Everything about performance, memory and battery is
marked **[requires measurement]** — no numbers are given for those, because none
could be measured here (no Android device or SDK was reachable, see the Phase 2
report). Publishing invented figures for a transport decision would be worse
than publishing none.

---

## 1. What the code actually needs

Voice media rides a **single full-duplex I2P SAM TCP stream**
(`otrv4plus_voice.py`, the `_sam_*` helpers around lines 1876–1990). Signalling
rides ordinary XMPP message bodies. The XMPP transport itself can also be
tunnelled over SAM (`otrv4plus_xmpp.py`).

Concretely the app needs a **SAMv3 bridge reachable at `127.0.0.1:7656`**,
supporting:

| Requirement | Used for |
|---|---|
| `HELLO VERSION` handshake | `_sam_handshake` |
| `SESSION CREATE STYLE=STREAM` with `TRANSIENT` destination | per-call ephemeral identity |
| `STREAM ACCEPT` | callee parks waiting for the caller |
| `STREAM CONNECT` | caller dials the callee's `.b32` destination |
| Long-lived streams with idle keepalive | `SAM_SESSION_TIMEOUT` 300s, `SAM_ACCEPT_TIMEOUT` 300s |

Timeouts already in the code assume a slow, tunnel-building network:
`SAM_HELLO_TIMEOUT` 30s, `SAM_CONNECT_TIMEOUT` 240s. That matters below — the
app is already written to tolerate a router that takes minutes to become useful.

**Nothing in this list is Android-specific.** The question is purely how a SAM
bridge comes to exist on the device.

---

## 2. Options

### Option 1 — Bundle i2pd as a native library in our own process

i2pd is C++, **BSD 3-clause licensed** **[verified]**
([PurpleI2P/i2pd](https://github.com/PurpleI2P/i2pd)), and ships a
`libi2pd_wrapper` component intended for embedding in other applications
**[verified]**. It builds for Android via the NDK **[verified]**.

Note the upstream Android app,
[PurpleI2P/i2pd-android](https://github.com/PurpleI2P/i2pd-android), produces a
**standalone APK, not a reusable AAR** **[verified]** — so embedding means
building `libi2pd` ourselves from source against our own NDK toolchain and ABIs,
not consuming a published artifact.

**Licensing.** BSD-3 imposes no copyleft obligation, so it composes with a
commercially distributed app. Note the opposite direction: OTRv4+'s own Rust
core declares `license = "GPL-3.0"` (`Rust/Cargo.toml`), and the repository
LICENSE is GPL. That constrains *our* distribution terms regardless of i2pd, and
should be settled before a commercial release — it is a licensing question for
the product, not an I2P question.

**Pros**
- Single APK; no dependency on the user installing anything.
- Full lifecycle control: we start, stop and monitor the router ourselves.
- The SAM endpoint is inside our own process, so no other app on the device can
  reach it and no IPC surface is added.

**Cons**
- We take on shipping and maintaining a C++ anonymity router, including its
  security updates. That is a substantial ongoing obligation and a large new
  attack surface inside the app's own process.
- Native build complexity per ABI, on top of the Rust core and CPython.
- APK size grows again on top of CPython (~25–40 MB before I2P).
- A crash in i2pd takes the whole app down, including active sessions.

### Option 2 — Depend on the separately installed I2P app

Either [i2pd for Android](https://f-droid.org/packages/org.purplei2p.i2pd/)
(on F-Droid, actively released — 2.61.0 in July 2026 **[verified]**) or the Java
I2P Android app.

**Critical caveat.** The SAM bridge binds **localhost only** **[verified]**, and
on Android every app has its own UID and its own loopback view. A SAM bridge in
another app's process is therefore **not reachable at `127.0.0.1:7656` from our
process** the way it would be on a desktop. This is the single most important
technical finding in this report, and it invalidates the naive form of this
option.

Making it work would require the I2P app to expose the bridge through an Android
IPC mechanism (a bound `Service`, or a `LocalSocket`/unix socket in a shared
location) and for our app to speak SAM over that instead of a TCP socket. Upstream
i2pd-android does not document such an interface **[verified — not mentioned in
its documentation]**, so this likely needs upstream work or a fork.

Additionally, Java I2P does not enable SAM by default **[verified]** — it must be
turned on in the router console, which is not a step a consumer will complete.

**Pros**
- No router code in our APK; i2pd's own maintainers handle its updates.
- Much smaller APK.

**Cons**
- A hard external dependency the user must install and configure.
- The localhost-isolation problem above must be solved first.
- Router lifecycle is outside our control; Android may kill it independently.
- Fails the "polished consumer UX" goal in the product spec.

### Option 3 — Direct / TURN transport

**Explicitly out of scope.** The phase brief forbids it as a convenience, and it
would remove the metadata-privacy property that motivates I2P: peers would learn
each other's IP addresses, and the network path would become observable. Recorded
here only to note that it was considered and rejected, not deferred.

---

## 3. The ten questions asked

| # | Question | Answer |
|---|---|---|
| 1 | Can the router run inside the app process? | **Yes** — i2pd exposes `libi2pd_wrapper` for embedding **[verified]**. It is C++ in our process, with the reliability and attack-surface consequences that implies. |
| 2 | Can a bundled/local router provide the SAM endpoint? | **Yes for Option 1** (in-process, so `127.0.0.1:7656` works normally). **Not straightforwardly for Option 2** — per-UID loopback isolation blocks cross-app localhost access. |
| 3 | Permissions/resources required? | `INTERNET` only, which the app already needs. A long-running router requires a **foreground service** with an ongoing notification (Android 8+), and realistically `POST_NOTIFICATIONS` on 13+. No special or dangerous permission is needed. |
| 4 | Startup time? | **[requires measurement]** Qualitatively, I2P needs to build tunnels before any stream can be opened, and the existing code already budgets for this (`SAM_CONNECT_TIMEOUT` 240s, `SAM_SESSION_TIMEOUT` 300s). Expect the *first usable connection* to lag app start substantially. Must be measured cold, warm, and on a poor network. |
| 5 | Memory footprint? | **[requires measurement]** A router maintains tunnels, peer profiles and a netDB; this is not negligible next to CPython plus the Rust core. Must be measured against Android's per-app limits on a low-end device, since exceeding them means the OS kills the app. |
| 6 | Coexists with foreground-service requirements? | **Yes, and it requires one.** A router with live tunnels is exactly what a foreground service is for. `connectedDevice` or `dataSync` are the plausible service types; the ongoing notification is unavoidable and conflicts with the calculator disguise — see §5. |
| 7 | Preserves metadata/privacy properties? | **Option 1: yes**, unchanged — same router, same tunnels, same `.b32` destinations. **Option 2: yes** if the IPC problem is solved without weakening isolation. **Option 3: no**, which is why it is rejected. |
| 8 | Can the app manage router lifecycle? | **Option 1: fully** — start, stop, restart, health-check in-process. **Option 2: barely** — we can at best ask the other app to start. |
| 9 | What happens on process death? | The router dies with the process and all tunnels are lost. On restart, tunnel building starts from scratch, so there is a multi-minute window with no connectivity. Calls in progress are lost; the existing `CallState` machine already treats `ENDED` as absorbing, so this degrades cleanly rather than corrupting state. Android will kill a backgrounded process aggressively — the foreground service is what mitigates this, not eliminates it. |
| 10 | What if the router becomes unavailable? | The SAM helpers raise `SAMProtocolError` / socket errors, which surface as call setup failure. `otrv4plus_xmpp.py` already implements I2P-aware reconnect with exponential backoff. The UI must show "not connected" honestly rather than silently degrading — and must never fall back to a non-I2P path, which would leak the user's IP precisely when they believe they are protected. |

---

## 4. Recommendation

**Option 1 — bundle i2pd in-process — is the only option that meets the product
requirements**, because Option 2 is blocked by Android's per-UID loopback
isolation and Option 3 is forbidden.

It should be adopted **conditionally**, with these gates before committing:

1. **Build `libi2pd` for arm64-v8a** and confirm it links alongside the Rust core
   and CPython. Cheapest decisive experiment; do it first.
2. **Measure** startup-to-first-usable-stream, RSS, and battery over a 1-hour
   idle session on a low-end device. If RSS pushes the app near the OS kill
   threshold alongside CPython, the whole embedded approach is in question.
3. **Confirm the SAM feature set** i2pd's embedded wrapper exposes matches §1 —
   in particular `STREAM ACCEPT` with `TRANSIENT` sessions.
4. **Settle the GPL-3.0 licensing question** for the product as a whole.
5. **Decide the security trade**: a C++ router in-process is a large new attack
   surface next to a codebase whose selling point is `#![forbid(unsafe_code)]`.
   Running it in a **separate process** of our own app (`android:process=":i2p"`)
   keeps a router crash or compromise out of the process holding the keys, at
   the cost of needing IPC to reach SAM — which reintroduces problem 2 in a form
   we control. **This is the recommended shape**: our own second process, not
   in-process, not another app.

Note that gate 5's conclusion revises the naive reading of Option 1: the
recommendation is a bundled router in a **separate process of our own app**,
with SAM reached over a unix domain socket we control, rather than sharing an
address space with the key material.

---

## 5. Consequences the product owner must accept

- **The disguise leaks.** A foreground service posts a persistent, user-visible
  notification. A calculator with a permanent "running" notification and an I2P
  router in its process list is not disguised from anyone who looks. The
  calculator front (spec §3) and a bundled always-on anonymity router are in
  direct tension. Options: run the router only while a conversation or call is
  active, accept the notification, or reconsider the disguise. **This needs a
  product decision and it is not a small one.**
- **Battery.** Maintaining tunnels costs power continuously. **[requires
  measurement]**
- **First-use latency.** The first message after a cold start will not be
  instant. The UI must say so rather than appearing broken.
- **Ongoing maintenance.** Shipping i2pd means tracking its security releases.

---

## 6. What was not established

Honest gaps, all of which need a device or unblocked network access:

- No performance, memory or battery figures — none were measurable here.
- `go-i2p/i2p-android-sam`, an I2P-for-Android embedding example that provides a
  SAM API, was found in search but **could not be retrieved** (`i2pgit.org` is
  blocked by this environment's egress policy). It is the most directly relevant
  prior art and should be reviewed first in Phase 3.
- i2pd's Android build documentation (`docs.i2pd.website`) is likewise blocked;
  ABI coverage and minimum API level were not confirmed from upstream.
- Whether i2pd's embedded wrapper exposes SAM specifically, as opposed to I2CP
  only, is **not confirmed** and is gate 3 above.

---

## Sources

- [PurpleI2P/i2pd](https://github.com/PurpleI2P/i2pd) — BSD 3-clause licence, `libi2pd_wrapper`
- [PurpleI2P/i2pd-android](https://github.com/PurpleI2P/i2pd-android) — builds a standalone APK
- [i2pd on F-Droid](https://f-droid.org/packages/org.purplei2p.i2pd/) — actively released
- [SAM V3 specification](https://i2p.net/en/docs/api/samv3/) — protocol, default port 7656
- [go-i2p/i2p-android-sam](https://i2pgit.org/go-i2p/i2p-android-sam) — embedding example (not retrievable here)
