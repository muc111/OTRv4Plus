<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright (C) 2025-2026 muc111 -->

# Android device test: the release candidate

**Build under test:** the release APK of `0.7.0-experimental.rc.1` (versionCode
11), published by CI with its SHA-256 in the release notes. Check the hash
before installing. Steps that need `adb shell run-as` (45, and the file
listings) need the **debug** APK from the same release, because a release
build is not debuggable.

Everything below the checklist was implemented and tested **without a
handset**. The Python half ran against the real engine and the real Rust core;
the Kotlin half is compiled and unit-tested by CI. What none of that can reach
is listed here, as steps a person runs. **None of the hardware steps has been
run for this build.** Each step names what would falsify the implementation,
not what would merely look right.

## Release-candidate checklist

| Area | Verified automatically (CI, every run) | Requires hardware | Status |
|---|---|---|---|
| First launch | APK builds; contents inspected (`inspect_apk.py`); core imports under Chaquopy in the debug diagnostics | §9 steps 55–57 | NOT RUN |
| Identity and fingerprint (new each launch, B1) | `test_peer_fingerprint_is_stable.py`, `test_android_termux_interop.py` (fingerprints agree both ways; Android identity not persisted) | §9 steps 58–60 | NOT RUN |
| XMPP over I2P | Transport against a fake forwarder; no direct fallback in any failure mode (`test_android_transport_lifecycle.py`) | §10 steps 61–63 | NOT RUN |
| OTR (DAKE) | Real DAKE through the bridge, fragmented, both initiators (`test_android_termux_interop.py`, `test_smp_android_interop.py`) | §10 step 64, §11 | NOT RUN |
| Fingerprint verification / SMP | Real SMP runs Android↔Android and Android↔Termux, success, failure, abort | §1, §9 step 60, §10 step 66 | NOT RUN |
| SMP Cancel | Fixed in this build (the engine had no abort); real-engine test | §10 step 66 | NOT RUN |
| Normal messaging, ratchet | 60 alternating messages and bursts across platforms | §10 step 64 | NOT RUN |
| Reconnect | Transport reconnect builds a fresh tunnel; a new session requires re-verification | §10 step 65 | NOT RUN |
| Roster | Roster read on the loop thread; malformed roster survivable | §10 step 62 | NOT RUN |
| Rooms | Room path separated from OTR (`test_android_room_chat.py`) | §8 steps 50–54 | NOT RUN |
| Calls, two-way audio | Voice keys in Rust; gate closed unless verified; integer bounds | §2, §3 | NOT RUN |
| Background, lock screen, incoming ringing | Notification content and channel (Kotlin unit tests) | §6 steps 31–34 | NOT RUN |
| File picker, file transfer | Real transfers through the bridge (`test_android_files.py`) | §4 | NOT RUN |
| JPEG, PNG, WebP metadata | Scrubbers against real fixtures (`test_metadata_scrub.py`) | §5 steps 24–28, 28a, 28b | NOT RUN |
| HEIC and video limitation | "Cannot check" path tested | §5 step 28b, 29 | NOT RUN |
| Wipe & Exit, relaunch after wipe | `test_wipe_and_exit.py` (Rust handles destroyed, disk tree removed, nothing resurrects) | §7 steps 35–49 | NOT RUN |
| Two-device interoperability | Android↔Termux and Android↔Android protocol runs, in one process | §11 steps 67–70 | NOT RUN |

Do not mark a row passed until its hardware steps have been run on this build
and reported as below.

---

## 0. Setup

Two handsets, **A** and **B**, each with this APK and a working SAM bridge
(see `ANDROID_DEVICE_TEST.md` §2). Both signed in to accounts that have each
other on their rosters.

---

## 1. The SMP gate, as the user sees it

1. Open the conversation A→B with no OTR session.
   **Expect:** no Call control and no Send-a-file control. The plaintext
   banner offers the handshake.
2. Start OTR. Do not verify.
   **Expect:** "Call — verify this contact first" and "Send a file — verify
   this contact first", both **disabled**. The conversation list row reads
   "Encrypted, unverified".
3. Run SMP to completion on both sides.
   **Expect:** both controls enable. The list row reads "Verified".
4. From B, before verifying from B's side, try to call A. *(Requires a
   build or a terminal client that will send an INVITE unverified.)*
   **Expect:** A does not ring.

## 2. Microphone permission — handset only

5. Fresh install. Tap Call.
   **Expect:** the system microphone dialog. Deny it.
   **Expect:** "Calls need the microphone. This call was not started." No
   call begins.
6. Tap Call again.
   **Expect:** an in-app explanation first ("A call needs the microphone…"),
   then the system dialog. Deny again.
7. Tap Call a third time.
   **Expect:** a dialog saying Android will not ask again, with **Open
   settings** — NOT a silent no-op. Open settings, grant, return, tap Call.
   **Expect:** the call starts.
8. Rotate the phone while the explanation dialog is showing.
   **Expect:** the dialog survives and no call is started by the rotation.

## 3. Calls — two handsets, I2P

9. A calls B.
   **Expect on A:** "Calling — building the private route, this can take a
   minute or two" for up to ~2 minutes. The app stays responsive; messages
   still arrive during the tunnel build.
   **Expect on B:** "Incoming call" with Answer and Reject.
10. B answers.
    **Expect:** both move through "Connecting" / "Confirming keys" / "Opening
    the audio path" to "Connected". The timer starts at 0s **when
    "Connected" appears** — not when A pressed Call.
11. Speak on both sides for 30 s. **Audio must be audible both ways.**
    This is the AAudio gate recorded in `tests/test_android_audio_path.py`;
    it has never been exercised.
12. A ends the call.
    **Expect:** both return to no call bar within a few seconds.
13. A calls, B rejects.
    **Expect:** A's call ends; no "Connected" ever shown.
14. A calls, B does nothing for 5 minutes.
    **Expect:** A's call times out and ends on its own.
15. During an active call, put B in airplane mode for 60 s.
    **Expect:** the call ends or recovers; it does not show "Connected" with
    no audio indefinitely.
16. During an active call, sign out on A.
    **Expect:** B's call ends. On A, after signing back in, no call bar.
17. During an active call, rotate A.
    **Expect:** the call continues; rotation neither ends nor restarts it.
18. Check the conversation on both sides after all of the above.
    **Expect:** no `?OTRv4-CALL:` text anywhere in the conversation.

## 4. Files — two handsets

19. A: Send a file → pick a document with the system picker.
    **Expect:** no storage permission prompt at any point.
20. B sees "<name> — <size>" with Accept and Decline. Accept.
    **Expect:** a progress bar on both sides; the file lands in the app's
    private directory; its bytes match the original.
21. Repeat and Decline. **Expect:** nothing lands on B.
22. Send a 20 MB file. **Expect:** the connection survives the transfer —
    keepalives continue, messages still arrive during it.
23. Check the conversation. **Expect:** no `?OTRv4-FILE:` text, and no base64.

## 5. Metadata — handset camera

24. On A, take a photo with the camera app with location tagging **on**.
    Send it.
    **Expect:** "This image carries N bytes of metadata — typically where and
    when it was taken… Remove it before sending?"
25. Choose **Remove and send**. On B, inspect the received file with any EXIF
    viewer. **Expect:** no GPS, no camera make/model, no date taken. The
    image looks the same.
26. Repeat with **Send as it is**. **Expect:** B's copy carries the GPS.
27. Repeat and dismiss the dialog (back button).
    **Expect:** nothing is sent.
28. Send a screenshot (usually no EXIF). **Expect:** no question is asked.
28a. Send a PNG that carries text chunks (many editors add them; an image
    saved from a web page often has them). **Expect:** the metadata question;
    after Remove and send, B's copy has no `tEXt`/`iTXt`/`eXIf` chunks.
28b. If the camera app can save HEIC (often "High efficiency" in its
    settings), send a HEIC photo. **Expect:** no scrub is offered; the notice
    says the app cannot check this kind of file. Send a WebP image that
    carries EXIF, if you have one: **Expect:** the metadata question, as for
    JPEG.
29. Send a PDF. **Expect:** it is sent, with a notice that the app cannot
    check this kind of file — not silence.
30. After all of the above, inspect A's app cache `outbox/` directory
    (`adb shell run-as org.otrv4plus.android ls cache/outbox`).
    **Expect:** empty. No staged or scrubbed copies left behind.

## 6. Ringing in the background — two handsets

31. On B, press Home so the app is in the background (signed in). A calls B.
    **Expect:** B shows a heads-up notification reading "Incoming call" and
    rings or vibrates according to the "Calls" notification channel. It does **not**
    name A.
32. Repeat with B's screen locked.
    **Expect:** the phone rings; the lock screen shows no call content.
33. Let the call time out, and separately have A hang up while B is ringing.
    **Expect:** in both cases the notification disappears on its own.
34. Repeat 31 with A **not** SMP-verified on B.
    **Expect:** nothing at all on B — no notification, no ring.

## 7. Wipe & Exit — two handsets

What it should do and why is in `ANDROID_WIPE_AND_EXIT.md`. Use A as the
device being wiped and B as its peer.

35. A and B: sign in, start OTR, and complete SMP on both sides.
36. Exchange a few messages so A has history, and add B as a saved contact.
37. (Optional) Start a call A→B and leave it active.
38. (Optional) Start a file transfer B→A, accept on A, and wipe while it is
    part way through.
39. On A: Connect screen → **Wipe & Exit**. **Expect:** a confirmation that
    says it cannot be undone and lists what is lost. Press Cancel once.
    **Expect:** nothing happens. Press Wipe & Exit again and confirm.
40. **Expect:** A's app closes within a few seconds and is gone from Recents;
    no notification from the app remains (no "connected", no unread count, no
    incoming call). On B the call (step 37) ends and the transfer (step 38)
    stops.
41. Relaunch A. **Expect:** the login screen, with no account filled in.
42. **Expect:** no conversation with B, no history, no saved contacts.
43. Sign in to the same account. **Expect:** B's conversation shows no OTR
    session (padlock open), and no SMP verification.
44. **Expect:** no call bar or call state for B; no transfer rows.
45. `adb shell run-as org.otrv4plus.android ls -la files/ files/vault cache/`
    **Expect:** `vault/` empty or recreated empty; no `.otrv4plus/files`
    content from before; `cache/outbox` empty.
46. **Expect:** notification channel settings you changed before the wipe are
    unchanged, and the microphone permission is still granted.
47. Start OTR with B again. **Expect:** B is told A's fingerprint changed (a new
    identity) and must verify again.
48. Complete SMP. **Expect:** a completely new, working session: messages, a
    call and a file all work as in sections 3–4.
49. Wipe & Exit again with nothing connected. **Expect:** it still closes
    cleanly and the next launch is again empty.

---

## What to send back

For each step: pass / fail, and for any fail the exported error log
(Debug → Share error log). For step 11, say explicitly whether audio was
heard in each direction.

## 8. Rooms — two handsets

50. On A: Rooms → wait for discovery (it can take a minute over I2P; the
    screen says it is working). **Expect:** the server's room service is
    found and its rooms listed, or "Nothing is advertised here".
51. Create or join a room on A and on B. **Expect:** the room opens with a
    red line "Room — not end-to-end encrypted…" and **no** Start OTR,
    Verify, Call or Send-file controls.
52. **Expect:** "N in this room"; Show lists both nicknames, moderators first.
53. Send a line from each side. **Expect:** it appears on the other with the
    sender's nickname above it and "Not encrypted" under it; your own line
    appears once, not twice.
54. Toggle airplane mode on A for 30 s, then let it reconnect. **Expect:**
    typing in the room does not claim to send until A has rejoined.

For step 40, report how long the app took to close. For step 45, paste the
listing.

## 9. First launch and identity — one handset

55. Install the release APK on a phone that has never had OTRv4+. Launch it.
    **Expect:** the sign-in screen, no connection attempt before sign-in.
56. About screen. **Expect:** the version reads `0.7.0-experimental.rc.1+core.…`,
    the Identity paragraph says the identity is new each launch, and the
    third-party notices open.
57. Sign in. **Expect:** progress for the length of an I2P round trip, then
    the roster.
58. Start OTR with a peer and note your fingerprint as the peer sees it.
59. Force-stop the app and relaunch. Start OTR again. **Expect:** the peer is
    warned your key changed (a Termux peer that pinned you; an Android peer
    keeps no pins across its own restart).
60. Complete SMP. **Expect:** "Identity verified … This lasts until the app
    closes". Relaunch: **Expect:** no longer verified.

## 10. Messaging, reconnect and roster over I2P — two handsets or one plus Termux

61. With the I2P router app stopped, press Connect. **Expect:** an error that
    names the router/SAM bridge. Nothing connects any other way.
62. Start the router; connect. **Expect:** the roster with real presence.
63. Leave it idle 10 minutes. **Expect:** still connected (keepalive).
64. Start OTR and exchange 30 messages each way, including one over 6000
    characters. **Expect:** all arrive, in order, once.
65. Toggle airplane mode for 60 s. **Expect:** reconnects by itself; the OTR
    session must be re-established, and the conversation shows **not
    verified** until SMP is run again.
66. Start SMP and press **Cancel** before the other side answers.
    **Expect:** both sides stop showing a verification in progress; the
    conversation stays unverified; Call and Send-a-file stay disabled.

## 11. Android ↔ Termux — one handset, one Termux client

67. Termux client (`otrv4plus_xmpp.py`) and the APK on different accounts,
    both over I2P. From Android, start OTR. **Expect:** Termux shows the DAKE
    completing and the fingerprint the Android About/verify screen shows.
68. From Termux, `/otr` to the Android account. **Expect:** same, other way.
69. `/smp` from Termux; answer on Android. Then Verify from Android and answer
    in Termux. **Expect:** VERIFIED on both, both times.
70. With the session verified, `/call` from Termux and a call from Android;
    `/sendfile` from Termux and a file from Android. **Expect:** audio both
    ways and files both ways.

## What this does not cover

- **Trading.** `?OTRv4-TRADE:` messages are now kept out of the conversation,
  but trading is not implemented on Android at all.
- **Full-screen incoming-call UI.** An incoming call raises a heads-up
  notification ("Incoming call", hidden on the lock screen), not a
  full-screen ringing activity. A full-screen intent would put a call screen
  over the lock screen, which is a disclosure decision, not a wiring one.
- **Formats other than JPEG, PNG and WebP** are never scrubbed. HEIC/HEIF
  and video (MP4, 3GP, MOV) keep metadata as items inside an ISO-BMFF `meta`
  box; they are sent with the "cannot check" notice, never described as clean.
