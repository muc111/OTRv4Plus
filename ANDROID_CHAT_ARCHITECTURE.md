<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
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

## 5. Persistence

> **Resolved.** This section described an in-memory store and a decision that
> had not been taken. Both are out of date as of the durability work; what
> follows replaces it. The reasoning that produced the interface is kept,
> because it is why the answer is a sealed store rather than a Room database.

History is `PersistentMessageStore`, which writes through `Vault` — on a device
an AES-256-GCM key generated in the AndroidKeyStore that never leaves it. It is
owned by `OtrConnectionService`, not by a ViewModel, and it **survives the
process being killed**.

The decision that was open was: build the app unlock first, or accept a
plaintext store for a development build. Neither, in the end. The credential
work produced a Keystore-backed vault for a different reason — a dropped tunnel
must not become a password prompt — and history goes in the same vault under a
different entry name, bound into the record's authenticated data so one cannot
be replayed as the other. No plaintext store was ever accepted, and the app
unlock is still worth building: it adds a second layer above `Vault` without
changing anything below it.

`MessageStore` remains an **interface**, and that is what made the swap a
drop-in. `InMemoryMessageStore` is still the test double and still what
`PersistentMessageStore` delegates to in memory; persistence is a write-through
layer over it, not a replacement. The tests run against the interface, because
a persistence layer that can only be tested on a device is one that does not
get tested.

What is stored is the message: body, direction, timestamp, security label,
send state. **No OTR private material, session key, ratchet state or trust
record goes in here** — those are Rust-owned, memory-only, and have no record
type to be written under (`ANDROID_STORAGE_AUDIT.md` rows 9–11).

The encoding escapes its own separators. A peer controls the message body, so
an unescaped record separator in one would end the record early and the
remainder would parse as a *new* message with attacker-chosen conversation,
direction and security label — a forged chat entry written by whoever can
message this device. `MessageCodecTest` plants exactly that payload; mutation
M12 removes the escaping and is caught.

An unreadable security label decodes to `UNKNOWN`, never `ENCRYPTED`. Vault
entry names are hashed, so a directory listing is not a contact list — which is
obfuscation, not a secrecy boundary, and `ANDROID_STORAGE_AUDIT.md` says so.

What the vault does **not** protect against is code running as this app on an
unlocked phone: `setUserAuthenticationRequired` is false, deliberately, because
the service reconnects with the screen off. That row of the threat table is
stated plainly in the storage audit rather than left to be inferred.

---

## 6. Threading and lifecycle

- Everything that crosses into Python is a **blocking** call and runs on
  `Dispatchers.IO`. Chaquopy's JNI calls are not interruptible by coroutine
  cancellation, so nothing on the main thread may wait on one.
- The drain loop runs at 500 ms in **`OtrConnectionService`'s** scope, not in
  `viewModelScope`. Events are pulled rather than pushed because they are
  emitted on the transport's asyncio loop thread.

  It moved there because the engine's event queue is **destructive** — a drain
  removes what it returns — so whoever drains it is the only thing that will
  ever see those events. A ViewModel does not exist while the UI is gone, so a
  message arriving with the app backgrounded was either dropped from the
  bounded queue or left sitting in it, and no amount of persistence further
  down would have helped: the message never reached the code that would have
  written it. There is exactly one drainer, and a structural test fails if
  `ChatViewModel` reads Python again.
- Each read in the loop is guarded **separately**. Four reads sharing one `try`
  was the handset bug: one raise discarded all four, the screen fell back to a
  default `ConnectionStatus`, and the app announced a disconnection it had
  never observed (`tests/test_android_poll_resilience.py`).
- `onCleared` releases the service *binding* and nothing else. The connection,
  the engine and the conversation belong to the service and outlive every
  screen; hanging up because a screen went away is the bug the service exists
  to fix.
- `ChatViewModel` is a redraw ticket and the outbound half of the composer. It
  ticks at 400 ms to recompose, calls `addContact` / `sendUserText` /
  `startSession`, and reads no state from Python at all.
- Drafts live in `ChatState`, so half a typed message survives a presence update
  redrawing the list, switching conversations, and rotation.
- The optimistic message is appended once with a stable id and updated in
  place; the draft is cleared *before* the send, so a second tap during the
  round trip finds nothing to send.

---

## 7. Verification

| Layer | How it is verified |
|---|---|
| `ChatState`, `ChatModels`, `MessageStore`, `MessageCodec`, `PersistentMessageStore`, `Vault`, `CredentialStore`, `ReconnectPolicy`, `InboundAlerts` | 184 JVM unit tests, **executed** |
| The split, the UI wording, the security boundary on screen | structural, `tests/test_android_chat_ux.py` |
| The poll's failure isolation | structural, `tests/test_android_poll_resilience.py` |
| The Keystore, the service, the drain loop's ownership | structural, `tests/test_android_durability.py` |
| Notification content and the permission request | structural, `tests/test_android_notifications.py` |
| `OtrApp.send_user_text`, message classification, plaintext-before-OTR | behavioural, against a fake engine and transport |
| Compose screens, `KeystoreVault`, `OtrConnectionService` | **compiled by CI, not executed anywhere** — see below |

25 bypasses planted in the real sources, each caught by named tests. Beyond the
original eight: a peer's body forging a stored message by unescaped separators;
an unreadable security label read as encrypted; history not written; the unread
count recomputed rather than restored; the vault entry name being the contact's
address; logout not forgetting; the password reaching `toString`; a duplicate
message notifying again; a non-message event notifying; interrupting the user
about a message on screen; the unseen count carrying across a visit; every
message in a burst ringing the phone.

**Honest limitation.** Three tiers, and they are not the same claim:

- *Executed* — the plain-Kotlin layers above, run by `testDebugUnitTest` in CI
  and by a local JVM harness, plus the whole Python suite.
- *Compiled only* — the Compose screens, `KeystoreVault`, `MainActivity` and
  `OtrConnectionService`. They import `androidx.*` or the Android framework, so
  CI compiles them and assembles an APK, and **no test executes a line of
  them.** Nothing here says the Keystore actually seals a record, that the
  foreground service survives Doze, or that a notification appears.
- *Not verified at all* — behaviour on a handset. Layout, scroll, keyboard,
  the connection surviving the app being backgrounded, and a message arriving
  while it is. The procedure is `ANDROID_MESSAGING_DEVICE_TEST.md`.

---

## 8. What is deliberately not here

- **Voice.** The call UI and `RECORD_AUDIO` are separate work.
- **Groups/MUC.**
- **Per-conversation notifications.** Arrivals are notified — that arrived with
  the foreground service — but as a *count only*, in one notification. No
  sender, no preview, and one notification id rather than one per conversation:
  a shade with one entry per person who messaged is a contact graph by
  cardinality, even with every name removed. `InboundAlerts.Alert` has a single
  integer field so there is nothing else to render.
- **Avatars.** A network request per contact is a new place to leak who you
  talk to on an anonymity-oriented client.
- **Delivery receipts.** `sent` means the engine accepted it.
- **Any change to the protocol, the engine, the transport boundary from
  `22fc255`, or the Rust core.** None was made.
