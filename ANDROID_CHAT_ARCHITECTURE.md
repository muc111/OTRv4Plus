<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial -->
<!-- Copyright (C) 2025-2026 muc111 -->

# Android chat layer: audit and architecture

`ANDROID_ARCHITECTURE_AUDIT.md` is the Phase 1 audit of the *repository*, and
its layer map stops at the bridge. This is the map of what sits above it: the
messaging application, as built.

---

## 1. What the audit found before any of this was written

The connection path worked. The application above it did not exist.

| Area | State before | Consequence on the handset |
|---|---|---|
| State ownership | Contacts, history, drafts and the poll loop all lived in `ChatScreen`'s composable body | Every one of them was discarded on rotation, theme change, locale change or navigation |
| Conversation list | None. A single screen with a peer field | No way to see who you could talk to, which is what "nothing seems to happen when I add alice" actually was |
| History | None. Messages were rendered from the last poll | A message scrolled past was gone |
| Outbound | `OtrApp.send_message` raised `not_encrypted` when no session existed | Sending before a DAKE looked like a failure, where Termux reports `[queued]` |
| Message identity | None | Nothing prevented a re-delivered event appearing twice, and nothing allowed the same word to be sent twice on purpose |
| Presence | Not surfaced | Reported as the original defect: "states user is offline" |
| Fingerprint change | `OtrEvent.FingerprintChanged` was produced by the engine and consumed by nothing | The engine's strongest warning was silently discarded — found during this work, fixed here |

Two further findings that shaped the design rather than being bugs:

- **`SecureStore` has no Kotlin implementation and no data-encryption key on
  Android.** `RecordType.MESSAGE = "otr.message"` is declared and
  `android_bridge/secure_store.py` has the AES-256-GCM implementation with
  record-bound AAD, but the key for it comes from an app unlock that is not
  built. So there is nowhere to put message bodies that is not plaintext on
  disk. See §5.
- **`androidx.*` is published only to Google's Maven repository**, which the
  development environment cannot reach. Anything importing it cannot be
  compiled or run outside CI. That is why the rules live where they do (§3).

---

## 2. The layer map, as built

```
┌─────────────────────────────────────────────────────────────────────┐
│ COMPOSE UI — describes what to draw, owns nothing                   │
│   MainActivity           enum Screen + openJid, both rememberSaveable│
│   ConversationsScreen    the list: rows, presence, unread, add       │
│   ConversationScreen     history, security line, composer            │
│   FingerprintAlertDialog blocking, undismissable                     │
│   ConnectScreen/About/DevShell                                       │
├─────────────────────────────────────────────────────────────────────┤
│ VIEWMODELS — survive Activity recreation                            │
│   ConnectionViewModel    owns ChaquopyOtrCore. The ONLY one.         │
│   ChatViewModel          poll loop, coroutine scope, redraw ticket   │
├─────────────────────────────────────────────────────────────────────┤
│ RULES — plain Kotlin, no Android, unit-tested (41 tests)            │
│   ChatState              routing · presence · drafts · send outcomes │
│   ChatModels             Message · Conversation · SecurityLabel · ids│
│   MessageStore           interface + InMemoryMessageStore (bounded)  │
├─────────────────────────────────────────────────────────────────────┤
│ BRIDGE — typed Kotlin over Chaquopy                                 │
│   OtrCore (interface) · ChaquopyOtrCore · SendOutcome                │
├─────────────────────────────────────────────────────────────────────┤
│ PYTHON — unchanged in kind                                          │
│   android_bridge.app      OtrApp.send_user_text                      │
│   android_bridge.connection · android_bridge.transport               │
│   otrv4plus_fragment (shared with Termux) · EnhancedSessionManager   │
├─────────────────────────────────────────────────────────────────────┤
│ RUST otrv4_core — authoritative for all crypto. Untouched.          │
└─────────────────────────────────────────────────────────────────────┘
```

**One core.** `ConnectionViewModel` constructs `ChaquopyOtrCore`; `MainActivity`
hands it to `ChatViewModel.attach`, which is idempotent. No screen constructs
one, and `attach` refuses to start a second poll loop over the same core —
two loops draining one event queue would lose every other message, because a
drain removes what it returns.

**Nothing live in navigation state.** `Screen` is an enum and `openJid` is a
`String?`; both are `rememberSaveable`. A `ChaquopyOtrCore` in a `remember` is
exactly what produced a second Python engine over one identity file on rotation
in an earlier version.

---

## 3. Why the rules are not in the ViewModel

Every interesting decision in a chat client is a decision about data: which
conversation an inbound message belongs to, whether a contact's presence is
known or merely unreported, whether an outgoing message is recorded once or
twice, what a send outcome means. None of it needs Compose, a Looper or a
device.

Put it in a `ViewModel` and it needs all three to run, because
`androidx.lifecycle` and `androidx.compose.runtime` cannot be resolved outside
an Android build here. Logic that cannot be run gets checked by reading it.

So the rules live in `ChatState`, plain Kotlin against plain data classes, and
`ChatViewModel` does only the Android half — polling, scope, and a `revision`
counter that tells Compose to look again. `tests/test_android_chat_ux.py`
enforces the split in both directions: `ChatState` may import nothing outside
`org.otrv4plus.*` and `kotlin.*`, and `ChatViewModel` may not contain
`store.`, `Presence.of(`, `SecurityLabel.forInbound(`, `substringBefore(`,
`compareByDescending` or `isBlank()`.

The payoff is measurable rather than rhetorical: all eight planted bypasses —
including the four the brief named — are caught by named, executed tests
(§7).

---

## 4. The security boundary

**Transport connectivity is not OTR security, and nothing in this layer can
turn one into the other.**

- `Conversation.security` is `Contact.security`, which is whatever the engine
  reported. `ChatState` never computes it.
- `SecurityLabel.forInbound` is the only route from engine state to a message
  label, its `when` is exhaustive with no `else`, and only `ENCRYPTED`,
  `FINGERPRINT` and `SMP_VERIFIED` map to `ENCRYPTED`.
- `FINGERPRINT_MISMATCH` maps to `UNKNOWN`, never `ENCRYPTED`. It is encrypted
  to *somebody*, and the somebody is the open question.
- An outgoing message is labelled `ENCRYPTED` only when the engine answers
  `SEND_ENCRYPTED`. `QUEUED` and `FAILED` both leave it `UNKNOWN`.
- A message keeps the label it had when it was sent or received. A later DAKE
  does not retroactively encrypt what went out in the clear.
- **There is no padlock.** The security line is a sentence, and
  "Encrypted, but you have not verified who is on the other end" and
  "Encrypted and verified" do not read the same — that distinction is the whole
  point of SMP.
- `SendState` and `SecurityLabel` are separate axes, so a delivered message
  cannot inherit reassurance from having been delivered.

`send_user_text` returns `SEND_ENCRYPTED` / `SEND_QUEUED` / `SEND_FAILED` and
mirrors the terminal client: `handle_outgoing_message` returning
`should_send=False` means the engine is *holding* the text until a session
exists, which is `[queued] will send once OTR is ready` in Termux and
`queued — waiting for encryption` here. It is not a failure and is not shown as
one. `OtrApp.send_message`'s `not_encrypted` raise is unchanged; no plaintext
send path was added.

Nothing sensitive reaches the UI: no password, key, session secret or exception
text. The fingerprint dialog shows fingerprints, which are public verification
material meant to be read aloud, and offers no button that re-pins a key.

---

## 5. Persistence — the decision that is not mine to make

History is `InMemoryMessageStore`, bounded to 500 messages per conversation,
held by the ViewModel. It survives navigation, rotation and Activity
recreation. **It does not survive the process being killed.**

That is deliberate. The project's declared position is that message bodies are
sealed at rest; the key for that comes from an app unlock that does not exist
yet; and the alternative in the meantime — a Room database or a JSON file of
plaintext bodies — is a permanent artefact that outlives the process, survives
an uninstall on some devices, and is readable by anything that reaches the
app's data directory. That is precisely what the sealed design exists to
prevent.

So `MessageStore` is an **interface**. A `SealedMessageStore` drops in behind
it when the unlock work lands, with no change above it. The tests run against
the interface, not against a database, because a persistence layer that can
only be tested on a device is a persistence layer that does not get tested.

**This needs a decision.** Either the app unlock is built before durable
history, or a plaintext store is explicitly accepted for a development build.
I have not chosen; the in-memory store is the option that closes no doors.

---

## 6. Threading and lifecycle

- Everything that crosses into Python is a **blocking** call and runs on
  `Dispatchers.IO`. Chaquopy's JNI calls are not interruptible by coroutine
  cancellation, so nothing on the main thread may wait on one.
- The poll loop runs in `viewModelScope` at 500 ms. Events are pulled rather
  than pushed because they are emitted on the transport's asyncio loop thread.
- `onCleared` cancels the poll loop. The connection is torn down by
  `ConnectionViewModel`, which owns it.
- Drafts live in `ChatState`, so half a typed message survives a presence update
  redrawing the list, switching conversations, and rotation.
- The optimistic message is appended once with a stable id and updated in
  place; the draft is cleared *before* the send, so a second tap during the
  round trip finds nothing to send.

---

## 7. Verification

| Layer | How it is verified |
|---|---|
| `ChatState`, `ChatModels`, `MessageStore` | 73 JVM unit tests, executed |
| The split, the UI wording, the security boundary on screen | 65 structural tests in `tests/test_android_chat_ux.py` |
| `OtrApp.send_user_text` | behavioural, against a fake engine and transport |
| Compose screens | **not executed anywhere** — see below |

Eight bypasses planted in the real sources, each caught by named tests: skip
persistence; skip the presence update; route every message to the active
conversation; send twice (two variants); report disconnection as offline; label
inbound messages from the connection; mark every conversation read on arrival.

**Honest limitation:** the Compose screens are covered only by structural
assertions. They import `androidx.*`, so they cannot be compiled here, and CI
compiles them but runs no instrumentation tests against them. Layout, scroll
behaviour and keyboard handling are verified on a handset, by
`ANDROID_MESSAGING_DEVICE_TEST.md`, and nowhere else.

---

## 8. What is deliberately not here

- **Voice.** The call UI and `RECORD_AUDIO` are separate work.
- **Groups/MUC.**
- **Notifications**, which need the foreground service (task #61).
- **Avatars.** A network request per contact is a new place to leak who you
  talk to on an anonymity-oriented client.
- **Delivery receipts.** `sent` means the engine accepted it.
- **Any change to the protocol, the engine, the transport boundary from
  `22fc255`, or the Rust core.** None was made.
