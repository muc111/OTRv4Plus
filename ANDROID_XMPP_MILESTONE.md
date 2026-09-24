<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright (C) 2025-2026 muc111 -->

# The XMPP foundation milestone: register, rooms, and a log that names nobody

> OTRv4+ is an I2P-first private communications client. It has three surfaces:
> the IRC terminal client, the XMPP terminal client, and this — a **native
> Android app under construction**. The terminal clients running under Termux
> are the supported way to use OTRv4+ today; this app is not yet a replacement
> for them. See [README.md](README.md#project-status).

Covers the work from `52da9ea` onward on
`claude/otrv4plus-android-spec-a3oq4d`, the milestone immediately before OTR
integration begins. It continues
[ANDROID_FOUNDATION_REPORT.md](ANDROID_FOUNDATION_REPORT.md) and uses the same
three tiers, because they are easy to blur and the difference is the whole
value of a report like this:

| Tier | Meaning |
|---|---|
| **Executed** | A test runs the code and asserts its behaviour. |
| **Compiled** | CI builds it and assembles an APK. No test executes a line. |
| **Unverified** | Neither. Behaviour on a device is unknown. |

**Automated verification complete; physical Android acceptance not performed.**
No handset has run this. Section 7 says exactly what that leaves open.

---

## 1. What was missing, and what it actually was

### 1.1 The Register button had no mechanism behind it

There was no registration code of any kind. The gap is worth naming precisely
because the wrong mechanism is easy to assume: **there is no web registration
page**, and there is no separate registration service. The account is created
over the XMPP stream itself, *before* authentication, using the
`jabber:iq:register` namespace — XEP-0077 in-band registration.

1. the client opens a stream and the server offers `<register/>` among its
   stream features;
2. the client asks for the registration form (`iq type='get'`);
3. the client submits `username` and `password` (`iq type='set'`);
4. the server answers with an empty result, or an error.

slixmpp implements steps 1–2 in `xep_0077` and fires a `register` event
carrying the form; the submission in step 3 is the caller's to build.

Two details decide whether this works at all.

**`force_registration` must be set.** Without it, `_handle_register_feature`
only attempts registration when nothing else has been negotiated. A server
advertising SASL alongside `<register/>` goes straight to authenticating an
account that does not exist, and the user is told their password is wrong —
for an account they were trying to create.

**The plugin must be registered before the stream comes up.** XEP-0077 happens
during stream negotiation; a plugin added afterwards never sees the feature go
past.

### 1.2 Neither service discovery nor rooms existed

`xep_0030` and `xep_0045` were not registered on the client. `client["xep_0045"]`
on a client that has not registered it raises, so there was nothing behind a
rooms screen — and nothing could find the MUC service, which is conventionally
`conference.<domain>` and conventionally is not (`rooms.`, `muc.` and `chat.`
are all in use).

### 1.3 The diagnostic log recorded who you are and who you talk to

This one is a reversal of a decision made deliberately in `675ef5b`, which
recorded JIDs and server names and argued for it in its own docstring: a
roster, presence or routing fault is *about* those values, and a report without
them is hard to diagnose.

That argument was right about diagnosis and wrong about the file. A diagnostic
exists to be shared — that is its purpose — and what it shared was the user's
account, everybody they talk to, and the I2P destination they talk through,
collected into one place with an invitation to post it into a bug tracker. On a
project whose reason for existing is that those three facts are nobody else's
business, that is the wrong side of the trade however useful it is.

---

## 2. What changed

### 2.1 Registration

| File | What it is |
|---|---|
| `otrv4plus_registration.py` | **New.** Local validation, and the translation from an XMPP error condition to a sentence. No network in it. |
| `android_bridge/transport.py` | `register_account()`, and `_enable_registration` on the client. |
| `android_bridge/connection.py` | `register()`, and the `registered` stage. |
| `bridge/ChaquopyOtrCore.kt` | `register()`, returning `RegistrationOutcome`. |
| `ConnectionViewModel.kt` | `register()`, off the main thread, refused while connected. |
| `ui/ConnectScreen.kt` | **Log in** and **Create account**. |

Three properties are load-bearing.

**It travels the same path a login does.** `_endpoint()` and `_make_client()`
are the same two calls `connect` makes — same SAM tunnel, same TLS decision,
same local-end host and port. Registration is not allowed to be the one
operation that reaches the network some other way, and the credential it sends
is the one that matters most.

**It does not then sign in.** Folded together, a registration that succeeded
and a login that failed would have one outcome between them, and the user could
not tell which half went wrong. On a network where the second half can take
four minutes, that is the difference between retyping a password and creating a
second account.

**`classify` never returns the exception's own text.** A slixmpp `IqError`
stringifies to something containing the stanza, which carries the JID being
registered — and this string is rendered on screen and pasted into bug reports.
The condition is read structurally and the sentence is chosen from a fixed
table.

Failures the user can actually meet, and what each says:

| Code | Cause | What the user is told |
|---|---|---|
| `conflict` | Username taken | "That username is already taken. Choose another." |
| `not_acceptable` | Server's own rules, or ours | The username or password may not meet its rules |
| `unsupported` | No in-band registration offered | "This server does not offer in-app registration." |
| `not_allowed` | Registration disabled | Creating accounts from the app is not allowed |
| `resource_constraint` | Rate-limited | "Try again later." |
| `timeout` | No answer | Names I2P as the likely reason |
| `network` | No router, no tunnel | "Could not reach the server." |

A server that never offers `<register/>` and lets us try SASL instead is
reported as `unsupported`, **not** as a bad password: there is no password to
be wrong yet.

### 2.2 Rooms and service discovery

| File | What it is |
|---|---|
| `otrv4plus_muc.py` | **New.** Affiliation and role, what each allows, and what a refusal means. No network in it. |
| `android_bridge/transport.py` | `discover_services`, `discover_rooms`, `join_room`, `create_room`, `leave_room`, `destroy_room`, `room_standing`, `joined_rooms`; `xep_0030`, `xep_0004` and `xep_0045` registered. |
| `android_bridge/connection.py` | The same eight, flattened to the `{ok, code, detail, value}` shape Kotlin reads. |
| `bridge/OtrCore.kt` | `DiscoveredService`, `RoomSummary`, `RoomStanding`, `RoomOutcome`. |
| `RoomsViewModel.kt`, `ui/RoomsScreen.kt` | **New.** |

**The permission model is two questions, not one.** Affiliation (owner, admin,
member, none, outcast) is long-term standing with the room and survives
leaving. Role (moderator, participant, visitor, none) is standing in this visit
and is assigned on join. Conflating them is the commonest way to get MUC wrong:

* an **owner who joined a moderated room as a visitor cannot speak** until
  given voice, and can still destroy the room;
* a **moderator who owns nothing cannot destroy** the room however much of it
  they run.

`otrv4plus_muc.privileges` derives both from XEP-0045 §5.1 and returns ten
booleans. The Kotlin side reads them and does not re-derive: a second
derivation could disagree with the first, and the disagreement would show up as
a button that fails minutes after it is pressed.

**Creating a room has a second step that is easy to drop.** XEP-0045 §10.1.2:
joining a room that does not exist creates it **locked**. The creator is in it
and nobody else can get in, which looks exactly like a room that works right up
until somebody is invited. An owner submitting the empty configuration form is
what unlocks it.

**Not knowing grants less.** An affiliation or role this module has not heard
of is treated as the weakest of its kind. A server answering something
unexpected must not produce a UI in which every button is enabled.

**A room is not encrypted, and the screen says so.** OTRv4+ is a two-party
protocol; a MUC message is fanned out by the service to everybody present, so a
room is plaintext to the server hosting it. That sentence is on the rooms
screen, once, plainly — an app that shows security state on one screen and says
nothing on another is inviting the wrong conclusion. No padlock, no security
badge and no fingerprint appears on that screen at all.

### 2.3 The diagnostic log

| File | What it is |
|---|---|
| `otrv4plus_alias.py` | **New.** Labels that replace identities. |
| `android_bridge/trace.py` | `_safe` aliases every field, centrally. |
| `android_bridge/report.py` | The finished report is swept again; the header states the policy. |

Every identity becomes a short label — `user-A`, `address-B`, `room-C` —
assigned in first-seen order and stable for the run. The timeline still reads:
*we asked for `user-A`'s presence, `user-A` never answered, `user-A` was
removed from the roster.* What it no longer says is who `user-A` is.

**A counter, not a hash.** A hash of a short identity is not a one-way function
in practice: localparts are short, domains are guessable, and `.b32.i2p`
addresses come from a published set, so anybody holding a candidate can hash it
and compare. A counter has no relationship to the value at all; the mapping
lives only in the memory of the running process, is never written down, never
exported, and dies with it. Labels are therefore not stable between runs and
two reports cannot be correlated — a property, not a defect.

**Applied centrally, in two passes.** By key name where the key says what the
value is (`jid`, `peer`, `server`, `destination`, `room` and their relatives),
and by shape everywhere else (JIDs, `.i2p` and `.onion` names, base32 and
base64 destinations, IPv4 and IPv6 literals embedded in a sentence). The second
is what catches an exception message quoting a host, which is the path nobody
remembers. Not by asking each call site: the call sites are the inbound
handler, the keepalive, the roster, the registration path and the Kotlin
bridge, and the first one to forget is the one whose fault ends up in the file.

What is checked against §7's list:

| Forbidden | Handled by |
|---|---|
| Usernames, bare and full JIDs | `_JID` shape, plus every person-shaped key |
| Passwords, tokens, session IDs | `SENSITIVE_KEY_HINTS` → `[REDACTED]`, unchanged |
| IPv4 and IPv6 addresses | `_IPV4`, `_IPV6` shapes |
| DNS hostnames, `.i2p`, `.onion` | `_I2P`, `_ONION` shapes, plus place-shaped keys |
| I2P destinations, tunnel identifiers | `_B32`, `_DEST64` shapes, `destination`/`tunnel` keys |
| Keys and cryptographic material | `SENSITIVE_KEY_HINTS`, unchanged |
| Message plaintext, file contents | `BANNED_KEYS`, unchanged |
| Contact lists, presence naming users | Aliased peers; `PresenceBook.__repr__` carries counts only |

A clock time is not an IPv6 address: the IPv6 pattern requires three
colon-separated groups rather than two, precisely so `12:34:56` survives.
Durations and timestamps are the commonest values in this log.

### 2.4 The login screen, and a Debug screen

The login screen used to render the SAM probe's raw output, the failure code,
whether the transport's worker thread was alive, and `inputs` — the literal
arguments that crossed into the transport. All of it is useful and none of it
belongs in front of somebody signing in: a login screen that says
`stream_failed` and `worker thread: alive` reads as broken even when it is
working, and it teaches people to ignore the words on it.

It moved to **Debug**, which now shows the live connection *before* the
start-up snapshot — the snapshot is taken at launch and is minutes old by the
time anything goes wrong. Debug is reachable from the login screen as well as
from the conversation list, and its Back goes to whichever the user came from.

Navigation now:

```
Log in ──► Conversations ──► Conversation(jid)
   │             │
   │             ├──► Rooms
   │             ├──► About & licences
   └─────────────┴──► Debug
```

### 2.5 Somebody who messaged you and was never added

An ordinary thing to happen, and the conversation already worked: a message
from a stranger is still a message, and it got a row from the union of the
roster and the store.

What was missing is the **explanation**. The server does not send us the
presence of somebody we have not subscribed to, so their availability reads
"presence unknown" — *permanently*, not slowly. Waiting does not fix it, and
nothing on screen said so. That leaves the user with the same conclusion every
unexplained unknown leaves them with: the app is broken.

`Conversation.saved` carries the fact and `canBeSaved` carries the remedy. The
conversation shows a line — *not in your contacts, so their availability stays
unknown* — and a **Save contact** button, which is what sends the subscription.
The list row says "not in your contacts" in place of "presence unknown",
because both are true and only one of them says what to do.

It is not dressed as an error: nothing is wrong. The button is disabled rather
than hidden while the link is down, because the remedy still exists and hiding
it would make the explanation read as a dead end.

One trap is pinned by a test. `ChatState.conversation(jid)` falls back when the
union has no row at all, and that fallback reports `saved = true` — claiming
`false` there would put a Save button in front of somebody who may already be a
contact whose roster entry has simply not arrived. The first version of that
line disagreed with the comment sitting above it; the test is what found it.

---

## 3. What is executed

| Suite | Tests | What it runs |
|---|---|---|
| `tests/test_registration.py` | 59 | `validate` and `classify` against fakes shaped like slixmpp's exceptions |
| `tests/test_android_registration.py` | 35 | The whole registration path through the transport, with a fake that negotiates XEP-0077 the way slixmpp does |
| `tests/test_android_registration_flow.py` | 29 | The controller: one result shape, never raises, leaves a live session alone |
| `tests/test_muc_rules.py` | 84 | Every affiliation × role combination, and every MUC error condition |
| `tests/test_android_rooms.py` | 50 | Discovery, join, create-and-unlock, leave, destroy, through the transport |
| `tests/test_android_rooms_flow.py` | 62 | The controller's shape and its local gate |
| `tests/test_diagnostic_privacy.py` | 86 | Labels, the shape sweep, and a built report containing no identity |
| `android/.../RegistrationOutcomeTest.kt` | 14 | Where a failure points the user |
| `android/.../RoomTypesTest.kt` | 20 | Finding the rooms service, and whether a retry is worth offering |
| `android/.../LinkPhaseTest.kt` | +6 | That the phase enum declares every stage the controller emits |
| `android/.../UnsavedSenderTest.kt` | 10 | A stranger's conversation, and where Save is and is not offered |

Totals for the run: **Python 4913 passed, 52 skipped, 1 xfailed**, alongside
four pre-existing failures that reproduce on an unmodified tree
(`test_identity_and_tofu`, `test_secret_at_rest`, `test_secret_never_echoes`,
`test_tip_address_relay` — all environmental). **JVM harness: 293 executed, all
green.**

Several of these bind the fakes against **real slixmpp** — that a
`PresenceError` is what a failed join raises and an `asyncio.TimeoutError` is
what a silent one raises, that `leave_muc` is not a coroutine while `destroy`
and `set_room_config` are, that `XEP_0077.default_config` carries both flags
the transport sets. That discipline exists because of `async_ping`: every test
passed while the handset failed, because the fake had been written from the
same wrong assumption as the code it stood in for. **A fake is only evidence if
it is wrong in the same places the real thing is.**

### 3.1 Mutation testing

The suites above were checked by planting bugs and confirming something
notices. See section 6.

---

## 4. What is only compiled

Everything in Compose. `dl.google.com` is blocked in the build environment, so
the Android Gradle Plugin does not resolve and `:app:testDebugUnitTest` is
unavailable until CI; no composable can be executed here.

`ConnectScreen.kt`, `RoomsScreen.kt`, `DevShellScreen.kt`, `MainActivity.kt`,
`ConversationScreen.kt` and `RoomsViewModel.kt` are covered by source-reading
tests (`tests/test_android_login_and_register_ui.py`,
`tests/test_android_rooms_ui.py`) and first compiled in CI.

**CI runs #57 and #59 are green**: the login screen, the Debug screen, the
rooms screen and the unsaved-sender banner all compile and the APK assembles.

### 4.1 What CI caught that nothing here could

Run #58 failed `:app:compileDebugKotlin`:

```
ChaquopyOtrCore.kt:353 Returns are prohibited for functions with an
expression body. Use block body '{...}'.
```

`leaveRoom` and `destroyRoom` were written as expression bodies containing
`?: return notPrepared()`, which is not legal Kotlin. The local plain-Kotlin
harness cannot compile `ChaquopyOtrCore.kt` at all — the file needs Chaquopy,
which needs the Android Gradle Plugin, which needs `dl.google.com` — so a
compiler had never seen it.

This is worth recording rather than quietly fixing, because it is the exact
shape of the limitation in section 4. The source-reading tests check what a
file *says*; only a compiler checks that it is Kotlin. Both were true here: the
tests passed and the file did not compile.

Looking for the same pattern elsewhere turned up a second fault of a different
kind. `RoomsViewModel.core` was a plain `var` assigned when the service binding
lands, and the rooms screen asked for discovery from `LaunchedEffect(Unit)`. A
plain field does not recompose, so a Rooms screen opened in the window before
the binding landed would call `discover()` against a null core, return
silently, and never try again — an empty rooms screen for the life of that
screen, with nothing saying why. `core` is snapshot state now and the effect is
keyed on it.

That is genuinely weaker than executing them. The project's answer to that
weakness is to keep the **decisions** out of the composables: `SignIn`,
`RegistrationOutcome`, `RoomStanding`, `RoomOutcome` and
`otrv4plus_muc.privileges` all decide something, are all dependency-free, and
are all tested by being run. What is left in a composable is layout.

---

## 5. What is unverified

Everything that needs a handset, an I2P router and a real server. Some of it
now has an answer — see §7.0, which records a handset session that got through
sign-in, the roster, contacts, presence, conversations and rooms. What is
**still** open:

* whether `xmpp-elite.i2p` offers XEP-0077 at all, and what it says if it does;
* whether a created room is usable by a second account — the locked-room path
  in 2.2 is derived from the XEP and exercised against a fake, not against a
  service;
* whether a DAKE completes between a handset and a peer. The control that asks
  for one was dropping the handshake it generated; that is fixed and
  unit-tested, and a fix is not an observation.

Answered by that session, and moved out of this list rather than left standing:
the server does host a MUC service and the app discovers it with nothing typed;
the SAM tunnel does survive the extra round trips discovery adds; and the
screens do work on a real display.

---

## 6. Mutation testing

**33 bugs planted, 32 caught.** In `otrv4plus_muc.py`,
`otrv4plus_registration.py`, `otrv4plus_alias.py`, `android_bridge/trace.py`,
`android_bridge/report.py`, `android_bridge/transport.py` and
`android_bridge/connection.py`, each run against the suites in section 3. The
interesting ones:

* speaking decided by affiliation rather than role;
* destroying decided by role rather than affiliation;
* an outcast keeping their privileges;
* an unrecognised affiliation taken at face value;
* a refusal-by-presence read as a timeout;
* the stanza's own text returned as the displayed sentence;
* a foreign exception's `.code` mistaken for one of ours;
* `force_registration` left false, so SASL wins the race;
* the XEP-0077 plugin never registered;
* a created room left locked;
* a server that never offered registration reporting success;
* the registration stream left dialling;
* a malformed room address costing an I2P round trip;
* the alias pass removed, so identities reach the log raw;
* the label derived from the value rather than from a counter;
* case differences splitting one person into two labels;
* `jid=alice@host` matched whole, splitting one account into two labels;
* the IPv6 pattern loosened so a clock time is scrubbed as an address;
* values never truncated.

### 6.1 The one that survives, and why it is not a gap

Making `_connection_fields` print the status **JID** raw does not fail any
test — because `_scrub`'s shape sweep catches it anyway. The mutated code is
still correct for a JID-shaped value; that is defence in depth doing its job,
not a test that is missing.

The case the shape sweep genuinely *cannot* catch is a **clearnet bare
hostname**: `chat.example.com` is not a JID, not `.i2p`, not `.onion` and not
an IP literal, so only the key-name pass keeps it out of the file. The profile
allows a clearnet server, so this is a configuration somebody can be in.
Mutating `server` instead of `jid` **is** caught, by
`test_a_clearnet_server_is_aliased_by_its_key_not_its_shape`.

### 6.2 A finding from the mutation run

`_DEST64` is broader than "an I2P destination": it matches any unbroken run of
80+ base64-ish characters, so a long opaque token that is not an address is
aliased too. This was noticed when a test using 600 `z`s came back as
`address-D`.

It is left that way, and the reasoning is now in the source. In a log whose
lines are stages, codes, counts and stack frames, an eighty-character word with
no spaces in it is overwhelmingly likely to be an address or a key. The cost of
a false positive is a label where a meaningless blob used to be; the cost of a
false negative is the destination this device talks to, in a file the user is
about to share. `TestALongUnbrokenTokenIsTreatedAsAnAddress` pins both halves:
the blob is aliased, and ordinary prose and stack-frame lists are not.

---

## 7. The handset gate

**Automated verification complete; physical Android acceptance PARTIAL.**

### 7.0 Status, as of the 0.4.0 build

A handset session (Android 15, arm64-v8a) against the live server got through
the whole messaging path, and the app is no longer at the "does it start"
stage. What it showed working:

* signing in, with visible progress for the length of an I2P round trip;
* the roster loading — contacts with their real subscription and presence,
  **without a message having to arrive first**;
* adding a contact, reaching the server and surviving the next poll;
* 1:1 conversations, both directions;
* Rooms: the MUC service discovered with nothing typed, a room created by
  name, and navigation into it.

Every one of those was broken in some way in the builds before it, and none of
the breakages were where they looked: the contact list was empty because
`slixmpp.roster.RosterItem` has no `.get()` and one `AttributeError` discarded
the entire roster (`a315c66`), and the Rooms button only became reachable once
a message arrived because an empty list changed a layout branch (`dfe1338`).

The same session found two more, both fixed in 0.4.0 and neither re-tested on
a device yet:

* the app attempted a connection on launch, before anybody had signed in, and
  the only way to the login form was to cancel it;
* tapping **OTRv4+** generated DAKE1 and dropped it — `OtrApp.start_session`
  never handed the payload to the transport, so nothing left the device while
  every layer above reported success.

**Gate items 4 is closed by that session. 9, 10 and 11 remain open, and 11 is
now the one that matters most**: the defect behind it is fixed and unit-tested,
and a fix is not an observation. 1–3 (registration), 5–7 (a room shared with a
second account) and 8 (reading a full export) have not been run.

### 7.0a Status, as of rc.1 (reported by the owner)

A later handset run with a Termux peer proved **OTRv4+ end to end** (the DAKE
completes and messages flow encrypted both ways), **SMP to verified**, the
Termux client keeping its verified state, and **encrypted file transfer**
with hashes checked. That closes **item 11**. Item 10, whether a call from
the APK carries real audio, is now the gate that matters. Items 1–3, 5–9 have
not been run.

### 7.0b Status, as of rc.4 (reported by the owner)

Two handsets running the app made **two-way voice calls** to each other over
I2P, heard in both directions. That closes **item 10** (the audio is real,
not silence) for app-to-app calls, and a call between the app and a Termux
client on another phone worked in both directions too. Items 1–3 and 5–9
remain open.

### 7.1 The list

This milestone is not signed off. `ANDROID_MESSAGING_DEVICE_TEST.md` is the
procedure; the additions this milestone needs are:

1. Create an account from the app on a server that offers XEP-0077. Confirm the
   account exists by logging in with it afterwards.
2. Attempt to create the same account twice. Confirm the second attempt says
   the username is taken, and says it in reasonable time.
3. Attempt registration against a server that does not offer it. Confirm it
   reports that, and not a bad password.
4. Open Rooms. Confirm the service is found without anything being typed.
5. Create a room, then join it from a **second account**. This is the
   locked-room check and it cannot be done with one account.
6. Leave the room. Confirm it still exists.
7. Destroy the room as its owner. Confirm the Delete control was not offered to
   the second account.
8. Export a diagnostic log after all of the above and **read it**. Confirm it
   contains no account name, no contact name, no room name, no server address,
   no `.b32.i2p` destination and no IP address — and that it is still enough to
   follow what happened.

9. Have a **second account ask to see your presence**, and watch the banner.
   Under the shipped `ACCEPT` policy it must say they *can now* see you and
   offer Revoke — not offer to decline something the server already approved.
   Tap Revoke and confirm the subscription is actually gone, not just the
   banner. Then sign in as a different account and confirm no trace of the
   request appears.
10. **Confirm audio is real, not silence.** `test_android_audio_path.py
    ::test_a_present_backend_is_not_silently_replaced` asserts that when
    AAudio is available, asking for it yields it rather than a fallback that
    would transmit silence. That test **cannot run off-device** and has never
    been executed anywhere — see `SKIP_AUDIT.md`, where it is the one skip of
    46 with no coverage in any configuration. A call that connects and carries
    nothing audible is the failure it is looking for.

11. **Tap "Start OTRv4+" and confirm a DAKE actually runs.** Until this
    milestone nothing in the Android UI could ask for encryption at all —
    `ChatViewModel.startSession` had no caller and nothing outside `crypto/`
    imported the encryption package, so every 1:1 sent plaintext forever
    unless the far side initiated. The control exists now; only a handset can
    show that it reaches the engine. Confirm the security line moves from
    "Not encrypted" to "Encrypted, but you have not verified who is on the
    other end", and that a message sent afterwards is reported as encrypted
    rather than plaintext. Then open a **room** and confirm the control is
    replaced by a sentence rather than offering a protocol that cannot work
    there.

Steps 8, 10 and 11 are the ones that cannot be delegated to CI. The tests assert
the rules this milestone wrote down; only a person reading a real export can
say whether the rules were the right ones, and only a handset can say whether
the audio path produced sound.
