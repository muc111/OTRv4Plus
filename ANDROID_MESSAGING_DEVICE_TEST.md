<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial -->
<!-- Copyright (C) 2025-2026 muc111 -->

# Android device test: messaging between Termux and the app

`ANDROID_DEVICE_TEST.md` ends where a connection succeeds, and says in so many
words that it proves nothing about messaging. This is the test that starts
there.

The target is a conversation: Termux sends, the app shows it in the right
conversation under the right name, the app replies, Termux receives it. Both
ends run the same engine and the same `?OTRv4F|` wire format, so a difference
between them is a bug in this application and not a protocol question.

```
Termux (otrv4+.py, alice)                    Android app (bob)
   EnhancedSessionManager                       EnhancedSessionManager
   otrv4plus_xmpp                               android_bridge.transport
            └──── otrv4plus_fragment (shared) ────┘
                         │
              SAM → i2pd → I2P → xmpp-elite.i2p
```

---

## 1. What is being tested, and what is not

**Being tested:** roster and presence, inbound routing, outbound sending,
history across navigation and rotation, the keepalive, reconnection, and
whether the security wording on screen matches what the engine actually
reports.

**Explicitly NOT being tested here:** whether messages are encrypted. Steps 1
to 16 run with **no OTR session**, which means the bodies are ordinary XMPP
traffic, readable by the server and by anything between it and each client. The
app says so on every one of those screens, and this document uses the word
*plaintext* rather than the word *secure* throughout, because that is what it
is. Encryption starts at step 17.

A second thing this document used to exclude is now **in** scope: survival in
the background. There is a foreground service (task #61) and history is sealed
at rest, so steps 22 and 26–31 assert that the connection, the credentials and
the conversation all outlive the UI — they no longer merely measure how bad it
is. Every one of those paths is **compiled and unit-tested but has never run on
a handset**, which is exactly why they are steps here.

---

## 2. Before you start

**Two identities, two clients.**

On the handset, in Termux:

```bash
# i2pd with SAM enabled -- see ANDROID_DEVICE_TEST.md §2 for the config.
i2pd --daemon

# The terminal client, as alice.
python3 otrv4+.py
```

In the app: the Connect screen, as **bob**, on the same server.

Both accounts must exist on the server already. Registration is not part of
this test.

**Have ready:** a way to record what you see (this document's tables are meant
to be filled in), and the Diagnostics screen, which exports a report.

**Do not record the password**, and do not photograph the password field. The
field does not echo; a transcript of what was typed defeats that.

---

## 3. The procedure

Record what actually happened, including wording — the wording is half of what
is being tested. An "expected" that is a claim about security is marked as
such.

### Connection and roster

| # | Do | Expect | If it differs |
|---|---|---|---|
| 1 | Connect the app as bob (`ANDROID_DEVICE_TEST.md` §3 steps 1-8) | "Connected", then the conversation list appears on its own | Stopping on the Connect screen means `onConnected` is not firing |
| 2 | Look at the conversation list | Either rows for everyone on bob's roster, or "No conversations yet" if the roster is empty | An empty list with a non-empty roster means the roster fetch or `applyRoster` is not running — export Diagnostics |
| 3 | Read the presence under each row | The word `online`, `offline`, or `presence unknown` | `offline` where you expect `presence unknown` is the bug from the original report: it claims knowledge nobody has |
| 4 | In Termux as alice, `/add bob@<server>` if not already on the roster, and accept on the app side if prompted | — | — |
| 5 | In the app, press **+** and add `alice@<server>` | A row for alice appears at once, with `presence unknown` | A row that never appears means `addContact` failed — Diagnostics |
| 6 | Wait for alice's presence to be granted, then watch the row | It changes to `online` within a few seconds of alice being available | Stuck on `presence unknown` after alice is demonstrably online is a presence-subscription defect. Note whether alice's client shows bob as online — asymmetry narrows it to one direction |

### Receiving

| # | Do | Expect | If it differs |
|---|---|---|---|
| 7 | From Termux as alice, send `hello from termux` | The app's alice row shows the message as a preview, a timestamp, and an unread badge of 1 | Nothing appearing at all: is the app still connected? Check the top bar before concluding anything |
| 8 | Open alice's conversation | The message, left-aligned, with the time and the words **not encrypted** beneath it | A message with no security wording, or reassuring wording, is a defect of the exact kind this project cannot ship |
| 9 | Read the line at the top of the conversation | "Not encrypted — anything sent here is readable by the server." | Any padlock icon anywhere is a defect |
| 10 | Go back to the list | The unread badge is gone | A badge that survives having read the conversation means `markRead` is not wired |
| 11 | From Termux, send a long message — 400 characters or so | It arrives whole, wrapping inside the bubble, with no horizontal scrolling | Truncation means the bubble is capping the body rather than the width |
| 12 | From Termux, send the same word twice, e.g. `ok` then `ok` | **Two** messages | One means de-duplication is collapsing distinct messages — a data-loss bug, worse than a duplicate |

### Sending

| # | Do | Expect | If it differs |
|---|---|---|---|
| 13 | Type a reply and press the keyboard's **Send** | The message appears once, right-aligned, and its status settles on `sent` or `queued — waiting for encryption` | Two bubbles for one press is the duplicate-send defect; `not sent` needs the reason from Diagnostics |
| 14 | Confirm in Termux | alice receives it | Arriving in the app but not in Termux points at the outbound path, not the UI |
| 15 | Press the **Send** button (not the IME action) with text in the box | Same behaviour as step 13 | A difference between the two routes means one of them skips the guard |
| 16 | Press **Send** with an empty box, and with only spaces | Nothing happens, no empty bubble | — |

### Encryption

Everything above is plaintext. This is where that changes.

| # | Do | Expect | If it differs |
|---|---|---|---|
| 17 | From Termux as alice, start the DAKE with bob (`/otr bob@<server>`) | The app's conversation security line changes to "Encrypted, but you have not verified who is on the other end." | A line still saying "Not encrypted" after the engine reports a session means the UI is not reading `securityState` |
| 18 | Send a message each way | Both arrive; the inbound one no longer says "not encrypted"; the outbound one says `sent, encrypted` | An outbound message labelled encrypted while the security line says otherwise is a contradiction — record both, verbatim |
| 19 | Type a message in the app *before* the DAKE completes (repeat 17 on a fresh pair if you have already finished) | Status reads `queued — waiting for encryption`, then becomes sent | `not sent` here is the original defect: the engine holding text is not a failure |
| 20 | Run SMP from Termux and complete it | The security line becomes "Encrypted and verified." | — |

### Lifecycle

| # | Do | Expect | If it differs |
|---|---|---|---|
| 21 | With a conversation open and text half-typed, rotate the screen | The conversation, the history and the half-typed draft all survive | Losing any of the three means state is in the composition rather than the ViewModel |
| 22 | Background the app for two minutes, return | Still connected. The connection notification was in the shade the whole time, saying only "Connected" | A disconnection here means the foreground service is not holding the process; check whether the notification was present at all, because on Android 13+ a refused notification permission hides it |
| 23 | Stop i2pd, watch the app for ~2 minutes | The app notices the stream is dead and says "Not connected"; the composer says nothing will be sent | Continuing to look connected for longer than about two minutes means the keepalive is not failing the stream |
| 24 | While disconnected, check a conversation | Presence reads `presence unknown` for everyone, not `offline`, and history is still there | — |
| 25 | Restart i2pd, reconnect | Connects again; history is still there | History lost on reconnect means it is being tied to the connection's lifetime |

### Background delivery, durability and credentials

Everything below is new, and **none of it has run on a device**. The Kotlin is
compiled by CI and the decision logic is unit-tested against fakes; whether the
AndroidKeyStore, the foreground service and the notification manager behave on
a real handset is what these steps are for. Treat a failure here as expected
information, not as a surprise.

| # | Do | Expect | If it differs |
|---|---|---|---|
| 26 | Background the app. From Termux, send one message. Wait 30 seconds | A notification appears reading exactly **"New message"** — with **no** sender, no JID and no preview | **A JID or a message body in the notification is a security defect.** Report it as one, with a screenshot cropped to the notification |
| 27 | Send two more from Termux without opening the app | The notification becomes "3 new messages" and does **not** ring again for each | A second and third sound means `setOnlyAlertOnce` is not doing its job |
| 28 | Open the app | The notification disappears; all three messages are in the conversation, in order, with the right sender | A message missing here is the serious one: it means the drain loop is not running while the UI is gone. Say which of the three |
| 29 | Lock the phone, have Termux send one more, look at the lock screen | **Nothing appears on the lock screen at all** — not even the app's name | Anything visible means the notification is not `VISIBILITY_SECRET`. Security defect |
| 30 | Force-stop the app from Android settings, then reopen it | It comes back **without asking for the password**, reconnects on its own, and the whole conversation history is still there | No history: the sealed store did not round-trip on this device — send `adb logcat` around the launch. Asked for the password: the credential did not round-trip. These are two different failures; say which |
| 31 | Sign out from the app, then reopen it | It asks for the password again, the conversation history is **gone**, and no arrival notification is left in the shade | History surviving a sign-out is a defect: it leaves one person's conversation on a phone the next person signs in on |

---

## 4. Known limitations, stated up front

Not defects — decisions, recorded so a tester does not spend an evening
re-discovering them.

- **History is now durable, and that is a thing to TEST rather than to work
  around.** It used to be memory-only; it is now written through a
  Keystore-sealed vault by `chat/PersistentMessageStore.kt`, owned by the
  foreground service. So losing history to a process kill is **a bug now**, not
  an expectation. None of this has run on a handset — CI compiles it and the
  JVM tests exercise the encoding and the store against a fake vault, but
  nothing has yet proved that the AndroidKeyStore seals and unseals a real
  record on a real device. That is TEST H.
- **The foreground service exists** (task #61), so a backgrounded connection is
  no longer at Android's mercy in the way it was. Untested on a device:
  whether it survives Doze, an aggressive OEM battery manager, or the user
  swiping the app away. Assume nothing; report what you see.
- **Notifications are a COUNT and nothing else.** "New message" or "3 new
  messages", no sender and no preview, hidden entirely on a lock screen. That
  is deliberate (`chat/InboundAlerts.kt`): a lock-screen line naming who just
  messaged this device undoes what the I2P tunnel under it is for. If you see a
  JID or a message body in a notification, that is a **security defect** —
  report it as one.
  - On Android 13+ the app asks for notification permission on first launch.
    Refusing it is supported and the app keeps working, but you will then see
    neither the arrival notifications nor the connection notification, so test
    the background steps with it granted.
- **No avatars.** A letter in a circle. Fetching avatars would be a network
  request per contact, which on an anonymity-oriented client is a new place to
  leak who you talk to.
- **Delivery receipts are not implemented.** `sent` means the engine accepted
  it, not that alice's client has it. Step 14 checks the rest by looking.

---

## 5. What to send back

For each step that differed: the number, what you saw **word for word**, and
whether the app was showing itself as connected at that moment.

For a message that did not arrive, the useful pair is what the app's security
line said and what the Termux client said at the same time — the two engines
disagreeing is a much narrower bug than "a message went missing".

Do not send passwords, and do not send message bodies you would not want
recorded. For a plaintext step, the body was already readable by the server;
that is not a reason to put it in a bug report as well.

---

## 6. What a clean run does and does not prove

A clean run proves the messaging path works between the two clients over I2P,
that history and drafts survive the lifecycle events Android actually produces,
that the connection and the conversation outlive the UI, that the sealed store
and the Keystore work on that device, and that the security wording tracks the
engine.

**Until it has been run, none of that is established.** The repository can
claim three things and no more: the Python and plain-Kotlin layers are
*executed* by tests; the Android-coupled layers are *compiled* by CI and an APK
assembles; and the handset behaviour is *unverified*. A passing CI run is not
evidence that the app works, and this document exists because nothing short of
running it is.

It does not prove that steps 1-16 were private. They were not, and the app says
so on screen. It does not prove anything about voice, file transfer, groups, or
about a conversation with more than one other person. And a green run on one
pair of handsets is one data point about I2P tunnel behaviour, not a
measurement of it.
