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

A second thing not tested: **survival in the background**. Android will kill a
backgrounded process with no foreground service. That is task #61, and step 22
measures how bad it currently is rather than asserting that it works.

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
| 22 | Background the app for two minutes, return | Note what you find: still connected, reconnecting, or restarted. History is expected to survive a *return*, and to be lost if Android killed the process | Loss on a plain return is a defect; loss after a process kill is the known limitation in §4 |
| 23 | Stop i2pd, watch the app for ~2 minutes | The app notices the stream is dead and says "Not connected"; the composer says nothing will be sent | Continuing to look connected for longer than about two minutes means the keepalive is not failing the stream |
| 24 | While disconnected, check a conversation | Presence reads `presence unknown` for everyone, not `offline`, and history is still there | — |
| 25 | Restart i2pd, reconnect | Connects again; history is still there | History lost on reconnect means it is being tied to the connection's lifetime |

---

## 4. Known limitations, stated up front

Not defects — decisions, recorded so a tester does not spend an evening
re-discovering them.

- **History does not survive the process being killed.** It is held in memory.
  The project's position is that message bodies are sealed at rest
  (`RecordType.MESSAGE` exists for it), the key for that comes from an app
  unlock that is not built yet, and a plaintext history file in the meantime is
  precisely the artefact the sealed design exists to prevent. See
  `chat/MessageStore.kt`. Losing history to a *process kill* is expected;
  losing it to navigation or rotation is a bug.
- **No foreground service** (task #61), so the connection is at Android's mercy
  when backgrounded.
- **No notifications.** A message arriving while the app is backgrounded is
  visible when you return, not before.
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
and that the security wording tracks the engine.

It does not prove that steps 1-16 were private. They were not, and the app says
so on screen. It does not prove anything about voice, file transfer, groups, or
about a conversation with more than one other person. And a green run on one
pair of handsets is one data point about I2P tunnel behaviour, not a
measurement of it.
