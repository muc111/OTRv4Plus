# Android device test: the first real connection

The target is not "the APK builds". It is this path, on a handset, with nothing
simulated in it:

```
APK → Chaquopy → android_bridge.connection → SAM → i2pd → I2P
    → hq4t24b7vkllfbk55e5xfocqhfi7hxprwc47zyuilbg6wgzikidq.b32.i2p → XMPP
```

Every leg of that is real code: the real `EnhancedSessionManager`, the real
`OtrApp`, and the `XmppTransport` from `22fc255`. There is no mock transport in
the app and no invented security state on the screen.

---

## 1. What this test is really asking

Two questions, and the first one is cheap.

**Can the app reach a SAM bridge that belongs to another app?**
`ANDROID_I2P_FEASIBILITY.md` §2 says no, and calls it "the single most
important technical finding in this report": that every Android app has its own
loopback view, so i2pd in Termux is unreachable at `127.0.0.1:7656` from our
process.

That claim is doubtful. Standard Android has no per-app network namespace —
that is `isolatedProcess` and separate users or work profiles, not ordinary apps
— and the routine counter-example is apps reaching Orbot's SOCKS proxy on
`127.0.0.1:9050` by explicit configuration, which is exactly this pattern.

**Check router** answers it in milliseconds. This is the whole reason that
button exists separately from **Connect**.

- If it reports **reachable**, the finding is wrong, and bundling i2pd (task
  #62) drops from a precondition to a convenience for users who would rather
  not run a router themselves.
- If it reports **refused** while i2pd is demonstrably listening, the finding is
  right, and `ANDROID_I2P_ARCHITECTURE.md` §1's bundled-router-in-a-separate-
  process design becomes the only path. Nothing is wasted either way: that
  design already exists and this test tells us whether we need it now.

**Does the full path carry a connection?** Everything after the probe.

---

## 2. Before you start

On the handset:

1. **i2pd running, with SAM enabled.** In Termux:
   ```bash
   pkg install i2pd
   # SAM is off by default. In ~/.i2pd/i2pd.conf (or /data/data/com.termux/files/usr/etc/i2pd/i2pd.conf):
   #   [sam]
   #   enabled = true
   #   address = 127.0.0.1
   #   port = 7656
   i2pd --daemon
   ```
   Confirm it is listening, from Termux:
   ```bash
   printf 'HELLO VERSION MIN=3.0 MAX=3.1\n' | timeout 5 nc 127.0.0.1 7656
   # expect: HELLO REPLY RESULT=OK VERSION=3.1
   ```
   If that does not answer, nothing below will work and the app is not the
   problem.

2. **Give i2pd time to integrate.** A router that started a minute ago has no
   tunnels. Ten minutes on first run is normal, longer on a slow connection.
   The app's Connect step is the one that needs them; the probe does not.

3. **An account on the server.** The test needs a real JID and password on
   `hq4t24…b32.i2p`. The app does not register accounts.

4. **Install the APK** from the `android-experimental` release, and check the
   build id matches what you meant to test — `Diagnostics` shows it.

---

## 3. The procedure

Each step has an expected result and a meaning. Record what actually happened,
including the wording, because the wording is half of what is being tested.

| # | Do | Expect | If it differs |
|---|---|---|---|
| 1 | Launch the app | The Connect screen, with the server shown and "The default server." beneath it | A failure card instead means the core did not start — open Diagnostics and export the report; that is a Phase 2 regression, not a connection problem |
| 2 | Check the server line | `hq4t24b7vkllfbk55e5xfocqhfi7hxprwc47zyuilbg6wgzikidq.b32.i2p` | A different or truncated address means the constant did not survive packaging |
| 3 | Check the SAM line | `127.0.0.1:7656` | — |
| 4 | Press **Check router** with i2pd **stopped** | "Reachable: no", code `refused`, and a sentence naming `sam.enabled` | Any other code is a finding; record it verbatim |
| 5 | Start i2pd, press **Check router** again | "Reachable: yes" and a SAM version, within a second | **This is the headline result.** `refused` here, with step 1's `nc` working, confirms the loopback finding |
| 6 | Type the JID and password, press **Connect** | State moves: Checking for an I2P router → Building I2P tunnels → Connecting to the server → Connected | Note *which* stage it stalls or fails at, and how long it sat there |
| 7 | Wait | Up to ~4 minutes at "Building I2P tunnels" is normal and not a fault | — |
| 8 | On success | "Connected", and the account shown | — |
| 9 | Press **Disconnect** | "Not connected", promptly | — |
| 10 | Press **Connect** again | Reconnects | A second connection failing where the first succeeded is a teardown bug |
| 11 | Rotate the screen while connected | Still connected | Losing the connection on rotation means state is being held in the wrong place |
| 12 | Background the app for a minute, return | Note what happens | Expected to survive for now; the foreground service (task #61) is what makes it reliable |

**Never blocks the UI thread.** At no point should the app show "isn't
responding". If it does, say so — that is a defect regardless of whether the
connection succeeded, and it means something reached the main thread that
should have been on `Dispatchers.IO`.

---

## 4. What to send back

The screen's text is selectable, and the Diagnostics screen exports a report.
For a failure, the useful thing is:

- the **stage** it reached (step 6's wording, not a paraphrase),
- the **reason** code,
- the **detail** sentence,
- roughly how long it sat there,
- and whether Termux's `nc` check still answers at the same moment.

That last one separates "the app cannot reach the bridge" from "the bridge
stopped", which are different bugs with no overlap.

**Do not send a password, and do not send a screenshot of the password field.**
The field never echoes, but a transcript of what was typed defeats that.

---

## 5. What this test does not prove

Worth stating, because a green connection is easy to over-read:

- **Nothing about encryption.** Connecting to a server establishes a transport,
  not a session. No DAKE has run, no peer has been authenticated, and the
  screen deliberately shows no security state for exactly that reason. OTR
  security appears with the conversation screen, derived from the engine.
- **Nothing about message delivery.** Sending needs a peer and a session.
- **Nothing about staying connected.** Android will kill a backgrounded process
  that has no foreground service. That is task #61.
- **Nothing about a bundled router.** This test uses whatever SAM bridge is
  configured. Bundling is task #62, and step 5 is what decides how urgent it is.
