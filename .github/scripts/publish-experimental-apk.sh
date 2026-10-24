#!/usr/bin/env bash
#
# Publish the debug APK as a rolling EXPERIMENTAL prerelease.
#
# ROLLING, not versioned: one tag, `android-experimental`, replaced on every
# green build. That is the honest shape for what this is. A version number
# implies a release someone stands behind, and this project does not yet have
# a release process for the APK -- so a stream of v0.4.1, v0.4.2 tags would be
# claiming one. One tag that always means "the newest build that passed CI"
# claims exactly what is true.
#
# The reason given here used to be "nobody has yet run this APK on a handset".
# That is no longer the reason, because it is no longer true -- see the body
# below -- and it is corrected rather than left standing.
#
# Corrected a second time for rc.4: the body still said OTR, SMP and file
# transfer had never run on a device after the owner's rc.1 handset run had
# proved all three against a Termux peer (recorded in
# docs/ANDROID_CALL_AND_FILE_DEVICE_TEST.md and the rc.2 CHANGELOG entry). That
# line was no longer true. Corrected again when the owner reported two-way
# calls working app to app and app to Termux.
#
# THE BODY OF THIS FILE IS THE EMAIL. GitHub sends release notes to watchers,
# so what is written below is what somebody reads before deciding whether to
# trust a binary. Every claim in it is either something CI asserts on this run
# or something reported from a handset, and the "not verified" list is the part
# that must stay accurate as things move off it.
#
# Provenance is not lost to the rolling tag: the commit, the run, and the
# asset's SHA-256 are all in the release body, and the filename carries the
# short commit SHA, so a downloaded APK can always be traced back to a build.
#
set -euo pipefail

APK=$(find apk -name '*.apk' -print -quit)
RAPK=$(find apk-release -name '*.apk' -print -quit)
if [ -z "$APK" ] || [ -z "$RAPK" ]; then
    echo "::error::the debug or release .apk is missing from the artifacts; nothing to publish"
    exit 1
fi

SHORT="${GITHUB_SHA:0:7}"
OUT="otrv4plus-${SHORT}-debug.apk"
ROUT="otrv4plus-${SHORT}-release.apk"
MANIFEST="otrv4plus-${SHORT}-release-contents.sha256.txt"
cp "$APK" "$OUT"
cp "$RAPK" "$ROUT"
cp apk-release/apk-contents.sha256.txt "$MANIFEST"

SHA256=$(sha256sum "$OUT" | cut -d' ' -f1)
RSHA256=$(sha256sum "$ROUT" | cut -d' ' -f1)
SIZE=$(du -h "$OUT" | cut -f1)
RSIZE=$(du -h "$ROUT" | cut -f1)
SIGNED_WITH=$(cat apk-release/signing-key.txt 2>/dev/null || echo unknown)
if [ "$SIGNED_WITH" = "owner" ]; then
    SIGNING="signed with the project owner's release key"
else
    SIGNING="signed with the CI runner's DEBUG key -- no release key is configured, so an update from one build to the next may need an uninstall first"
fi

# Read the core version from the Rust crate rather than hardcoding it here,
# so this cannot drift into claiming a version the binary does not contain.
CORE=$(grep -m1 '^version' Rust/Cargo.toml | cut -d'"' -f2)

# Same rule for the app's own version: read from the build file, not restated.
# `versionName` is a Kotlin template that interpolates the crate version, so
# the literal `$rustCoreVersion` is substituted with what was just read --
# which is exactly what Gradle does, and keeps this from claiming a version
# the binary does not carry.
APP=$(grep -m1 'versionName *=' android/app/build.gradle.kts | cut -d'"' -f2)
APP="${APP/\$rustCoreVersion/$CORE}"
CODE=$(grep -m1 'versionCode *=' android/app/build.gradle.kts | tr -dc '0-9')
if [ -z "$APP" ] || [ -z "$CODE" ]; then
    echo "::error::could not read versionName/versionCode from build.gradle.kts"
    exit 1
fi

# A release candidate gets its own tag, kept; everything else replaces the
# rolling one. The version is read from the build file, never typed here.
VERSION="${APP%%+*}"
case "$VERSION" in
    *.rc.*) TAG="android-v${VERSION}"; KIND="release candidate" ;;
    *)      TAG="android-experimental"; KIND="development build" ;;
esac

# The screens job's images (made-up data), when it produced them. Attached to
# the release and shown in its notes; a release without them is still a
# release.
SHOTS=()
SHOTS_MD=""
for f in screens/android-*.png; do
    [ -f "$f" ] || continue
    SHOTS+=("$f")
    name=$(basename "$f")
    SHOTS_MD="${SHOTS_MD}<img src=\"https://github.com/${GITHUB_REPOSITORY}/releases/download/${TAG}/${name}\" width=\"230\" alt=\"${name%.png}\"> "
done
if [ -n "$SHOTS_MD" ]; then
    SHOTS_MD="${SHOTS_MD}

<sub>The app's real screens, drawn by CI from made-up conversations (the app blocks screenshots on a phone).</sub>
"
fi

cat > notes.md <<EOF
# ⚠️ EXPERIMENTAL — a ${KIND}, not a release

\`${APP}\` — built from \`${GITHUB_SHA}\`. Android 8.0 or newer.

**Download \`${ROUT}\`** (below). The first sign-in takes a few minutes while
the built-in I2P router joins the network.

${SHOTS_MD}
---

## Verified on a real device — ✅ what works

Reported from a handset: two Android 15 phones (arm64-v8a, a Pixel and a
Xiaomi) by the project owner, against the project's server
\`otrv4plus.i2p\`, over the **built-in I2P router** (no other I2P app
installed), and with the Termux client. Each row says what was confirmed; a
later regression is marked in its row. Builds since are in the next table.

| Area | What was confirmed |
|---|---|
| Connection | Sign in and create an account over I2P; the built-in router starts and carries everything |
| Contacts | Adding contacts, presence, the People list |
| 1:1 chat | OTRv4+ end to end, app ↔ app and app ↔ Termux |
| Identity check | SMP verification, app ↔ app and app ↔ Termux |
| Files | Encrypted file transfer, hashes checked on arrival |
| Group files | Sending files to a secure group (confirmed rc.89) |
| 1:1 calls | Two-way voice calls between two handsets running this app, and between this app and the Termux client. **Regressed:** over the built-in router calls stopped connecting (\`call_tunnel\`); fixed in rc.162, to be re-tested (next table) |
| Secure groups | Post-quantum MLS groups, group messages both ways — **tested with four members** (two phones, each with the app and Termux); about 100 is the measured ceiling (see Known limits) |
| Group check | Group verification with a shared passphrase |
| Group calls | Two-way group voice calls (re-confirmed rc.89) |
| Location | Location pins from GPS only, received as a card (rc.73; since rc.80 only to verified contacts and groups — re-confirmed rc.89) |
| Profile picture | Setting a profile picture from a phone photo; contacts receive it (rc.89 — the server log shows both the picture and its announcement stored and delivered) |
| Moderation | Signed in as the server admin, Delete shows on every room (rc.88); an ordinary member sees Leave only (rc.83) |
| Voice notes | Voice notes in **My voice** and **Synthetic** (rc.81: no whistle, a random voice per note; Disguised removed) |
| Voice note ends | Record a note and press Stop straight after your last word: it takes about two seconds longer to prepare, and when played (sent and received bubbles, phone and desktop) the last word is there in full (rc.125) |
| Calls in the report | Make or answer a call, then Diagnostics → report: the call's steps are listed (component `call`: ringing, keys_confirmed, active or the failure and its reason), with no names or addresses (rc.126) |
| Voice note waveform | A voice-note bubble (sent and received, phone and desktop) shows the note's waveform between Play and the length; pressing Play fills the bars in from the left as it plays, the time counts up, and the bubble goes back to Play at the end (rc.127) |
| Clean teardown | Sign in, chat with a contact so the conversation is encrypted, then Profile → Wipe & Exit (or sign out): it completes, and opening the app again shows no old session with that contact (rc.128) |
| Group member to 1:1 | In a secure group, open ⋯ on someone else's message: **Add to contacts** (when they are not one yet) sends them a contact request; **Message privately** opens a 1:1 chat with them. Neither appears on your own messages or in an ordinary room (rc.129) |
| Room people | In the Welcome room tap **People**: a sheet lists everyone under Moderators / Participants / Visitors with counts, a search box when there are 8 or more, and each person's address. **Add** sends a contact request, **Message** opens a 1:1 chat; someone the room hides the address of shows "This room does not show their address" and no buttons. Same on the desktop (People panel beside the room) (rc.130) |
| Chat kinds | Chats list: 1:1 chats tinted blue, encrypted groups green, public rooms (Welcome) amber, each with a stripe on the left and its kind in words under the name. With more than one kind there are chips at the top (All · People (n) · Groups (n) · Public (n)); a chip shows only that kind. Check light and dark theme: names stay readable (rc.131) |
| Security update | Nothing to see: the ctutils crate updated for RUSTSEC-2026-0385 (a constant-time fix). Check that 1:1 chats, a group message and a call still work as on rc.131 (rc.132) |
| Bundled router | Nothing to see: the bundled I2P router is rebuilt from the same pinned sources. With no I2P app on the phone, sign in over I2P: the app starts its own router and connects (rc.133) |
| Repository layout | Nothing to see: the Python sources moved into a folder of their own. Sign in, send a message, make a call and send a voice note as on the previous build (rc.134) |
| Code split, step 1 | Nothing to see: the terminal client's output code moved to its own module. On the phone, sign in, chat and call as on the previous build (rc.135) |
| Code split, step 2 | Nothing to see on the phone: the terminal client's SMP, TUI and admin code moved to modules of their own. Sign in, verify a contact with SMP and call as on the previous build (rc.136) |
| Code split, step 3 | Nothing to see on the phone: more of the terminal client moved to modules of their own (tunnels, connection, presence, files, trades). Sign in over I2P, send a file and a voice note as on the previous build (rc.137) |
| Code split, step 4 | Nothing to see on the phone: the terminal client's Termux setup moved to its own module. Make a call and record a voice note as on the previous build (rc.138) |
| Engine without the IRC client | The APK is a little smaller: it no longer carries the IRC client, which the app never used. Sign in, open a chat with a contact, verify with SMP and call as on the previous build (rc.139) |
| Transport split | Nothing to see: the app's server code is now in several modules. Sign in, create an account on a test server, join a room, change your picture and see the Welcome room as on the previous build (rc.140) |
| App core split | Nothing to see: the app's Python core is now in several modules. Chat, verify with SMP, call, send a file and a voice note, use a secure group, then Wipe & Exit on a test account, as on the previous build (rc.141) |
| Controller split | Nothing to see: the connection controller is now in several modules. Join a room, create and leave a secure group, start a group call and change your picture as on the previous build (rc.142) |
| Call failures shown | Call a verified contact. If the call cannot go out, a line now says why (for example that its I2P tunnels could not be built) instead of nothing happening. Report the exact line (rc.143) |
| Ban tools for admins | Sign in as an account that is NOT a server admin and open a contact's profile: there are no ban buttons. As an admin they are there (rc.143) |
| Open a received picture | Receive a photo, close and reopen the app, open the chat: the "File received" line has Open. Open shows the picture and, under it, a Metadata line ("none" for a stripped photo) (rc.144; the viewer has used tabs since rc.166) |
| Failures say something | Call a contact whose phone is offline or not verified, send to a group while signed out: each says what went wrong instead of nothing (rc.145) |
| Failure codes in the report | Make a call fail (contact offline), then Profile → Diagnostics → export: the report starts with "Failures seen" listing the code (for example call_tunnel), how often and when (rc.146) |
| Your own I2P router first | With i2pd or the I2P app running (SAM on), sign in: the connection screen says it is using the I2P router already on this phone. Stop it and sign in again: the built-in router starts (rc.147) |
| PDFs in a sealed box | Receive a PDF and open it: the pages show as before. A PDF with links or scripts lists them under the page and in the "Open with another app" warning (rc.148; the viewer has used tabs since rc.166) |
| Code split, step 5 | Nothing to see on the phone: the terminal clients' longest functions are split up. Sign in, chat, verify and call as on the previous build (rc.149) |
| Code split, step 6 | Nothing to see: sign-in code is split into named steps. Sign in over I2P, then with a wrong password, and check each says what happened as on the previous build (rc.150) |
| Code split, step 7 | Nothing to see: the conversation screen's code is in four files. Open a chat, a room and a secure group; verify, call, send a file and a voice note as on the previous build (rc.151) |
| Zoom in the viewer | Open a received photo or PDF: pinch, drag, double-tap and the − / 100% / + buttons zoom it; the Metadata line under it scrolls when long (rc.152; the viewer has used tabs since rc.166) |
| Chats that need you | Ask this phone to verify from another one: that chat pulses yellow in the list with "⚑ Verification requested", and so does the Chats tab, until you answer (rc.152) |
| Code split, step 8 | Nothing to see: the Rooms screen is in parts. Open Rooms, create and delete an encrypted group, join a plain room, as on the previous build (rc.153) |
| Any-year birthdays | Profile → edit, Birthday -450000-01-01, save: it is kept and shown. 2023-02-29 is refused (rc.154) |
| Code split, step 10 | Nothing to see: the chat list and the conversation screen are in parts. Open a chat, use ⋮ (profile, block), accept an invitation, change the theme, as on the previous build (rc.155) |
| Code split, step 11 | Nothing to see: the app's navigation is in parts. Move between Chats, People, Rooms and Profile; open a contact's profile from People and press Back (returns to People), as on the previous build (rc.156) |
| Security fixes G1, G2, X1 | Nothing new to see on the phone: this build repairs the previous one and closes three tracked issues (see docs/SECURITY_ISSUES.md). Sign in, chat, verify and call as before (rc.157) |
| Pictures | Profile pictures from phone photos in their usual formats, converted and fitted to 96 x 96 / 8 KB (rc.87) |
| Rooms | Room discovery, creating and joining a room; earlier messages loaded from the server archive (rc.68) |
| Message actions | Reply, correct, delete for everyone, react — 1:1, rooms and secure groups (rc.68–rc.69) |
| Joining a group | After accepting an invitation the room shows *setting up end-to-end encryption* until it is ready, never "not encrypted" (rc.81) |
| Verification | A moving progress bar on both phones while verifying, 1:1 and groups (rc.81) |
| Calls | The phone icon turns green once the call path is ready; no crash on hang-up; a group call that goes one-way repairs itself (rc.74–rc.77) |
| Sign-in | The first connection says it is **setting up (2–5 minutes, normal)**, never "Connection lost" (rc.82) |
| Background | The app stays connected in the background |
| App | Bottom bar on every main screen; the 📎 and 🎤 buttons in the composer |
| Wipe | **Wipe & Exit, including deleting the account from the server** |

## NOT verified — 🧪 built, still to be tested on phones

| Area | What to test | Since |
|---|---|---|
| Password-protected group | Create a secure group **with a room password**, invite someone: they join without typing it (it comes with the invitation, encrypted); if it does not arrive they are **asked for it** instead of an error | rc.90 |
| Group status and call limit | A new group reads **"Encrypted Chat \| 0/1 users verified"**; the count rises only as verification succeeds (you count once a verification you took part in succeeds); a group of **6 or more has no call button** ("Text only") | rc.84–rc.90 |
| Signed in elsewhere | Sign in with the same account on a second device: the first shows **"Your account is also signed in on another device"**; as server admin, **Sign out other devices** ends the second session (your own stays up) | rc.91 |
| One session per account | With `mod_otrv4plus_one_session` and `max_resources = 1` (docs/SECURITY_SESSIONS.md), sign in on a second device: it gets in, and the first says **"Signed out: this account signed in on another device"** and does **not** reconnect by itself. Drop the connection (airplane mode) and reconnect: you get straight back in | rc.95 |
| Sign out | Shows the sign-in screen at once (the teardown carries on in the background). There is no Disconnect: the app stays connected until Sign out or until it is closed | rc.95, rc.100 |
| Built-in router stays warm | With the built-in router: Cancel a sign-in, then sign in again: it connects without the 5-10 minute warm-up | rc.100 |
| Sound and vibration | App in the background: a message, a verification request and a group invitation each sound **and vibrate**; the notification says only "New message", "Verification requested" or "Group invitation" (no name), and nothing shows on the locked screen. App open in another chat: a tone and a buzz. Phone on vibrate: buzz only; on silent: nothing | rc.102 |
| Password rooms | Rooms: tap Join on a room marked 🔒: the password is asked for first; a wrong one asks again in red; the right one joins. An encrypted group you have not been invited to says to ask for an invitation instead of joining | rc.113 |
| Ask to join | Rooms: three sections (your encrypted groups; encrypted groups on the server; plain rooms, marked not encrypted). Ask to join on a group you are not in: a member sees "… asks to join" with Invite / Dismiss; Invite sends the invitation. New encrypted groups offer no password | rc.114 |
| Sign-in retries | Sign in with the built-in router: the attempts count should be lower and "sign-in" shorter than before | rc.115 |
| People only | People tab: no rooms (nothing @conference.…), only accounts | rc.116 |
| Rooms list and bans | Rooms tab lists rooms again (Look again if it has not answered). As the admin, after installing mod_otrv4plus_moderation: another person's profile shows Moderation; ban for 1 day, they are signed out and their app says until when; Unban lets them back. Hidden rooms show on the admin's Rooms tab | rc.117 |
| No transit | Built-in router: sign-in as fast as rc.117, and less battery over a day with the app left running | rc.118 |
| Regressions | Fresh install, built-in router: no red line while it sets up, however many tries. Rooms: Delete as creator and as admin removes the room; as a member only Leave; a refusal says why. Group header and Rooms say MLS+ | rc.119 |
| Admin delete | After updating mod_otrv4plus_moderation on the server: as the admin, Delete a room someone else made (Rooms tab); it disappears for everyone | rc.120 |
| Admin delete after reconnect | As the admin, sign in, wait for a reconnect (or toggle flight mode), then Delete a hidden room someone else made; it disappears for everyone | rc.121 |
| Deleted rooms gone | After updating the module: as the admin, Rooms → Refresh no longer lists rooms already deleted; Delete on one that was already gone says so (not in red) and removes it from the list | rc.122 |
| Server list clean | After updating the module: as the admin, Delete a room that `muc:list("conference.<host>")` in `prosodyctl shell` still lists after it was deleted (its tombstone): it leaves `muc:list` | rc.123 |
| Voice notes | Send a voice note to a verified contact: it shows in your chat as a voice-note bubble with Play; Play replays it. On the other phone (or the desktop app) it arrives without an Accept/Decline prompt, as a bubble that plays; no "file received" line. Same in a secure group. Close and reopen the app: both bubbles are still there and still play | rc.124 |
| Change password | Profile → **Change password…**: a wrong current password is refused without contacting the server; a good change says **"Password changed"**; then close the app and open it again: it signs in with the new password without asking; another device with the old password cannot sign in | rc.96 |
| Pictures and profiles | Tap a contact's picture in the chat list, or at the top of their chat: their profile opens; Back returns to where you were. Tap the profile picture: it fills the screen; tap to close | rc.97 |
| Busy group | In a secure group where several people send at once (or after reconnecting to a busy group), every message arrives; none silently missing | rc.93 |
| Invite several | In a secure group, "Invite people online…": tick several, "Invite N people"; each gets an invitation and those who accept join | rc.94 |
| Location | Before verification 📍 explains and the GPS never starts; a mock-location app's position; typing a Plus Code; "Open in maps app" | rc.73–rc.80 |
| Photos | The "hidden information" question strips a camera photo's location | — |
| Network change | Reconnecting by itself after switching between Wi-Fi and mobile data | — |
| Desktop app | The desktop (Linux/Qubes) client against the same server | — |
| Post-quantum ratchet (v2) | Both phones on this build or newer: chat for a while in both directions; every message arrives. Messages grow to about 2.5 KB once the ratchet has taken its first step, after 100 messages in one direction or a day; keep chatting past that | rc.158 |
| Post-quantum sign-in to a chat (v2) | Both phones on this build: open a chat; it becomes encrypted as before (the first handshake is a little larger). Contact's profile → Reset trust asks first and then forgets their keys; the next chat pins them again. A phone on an older build is now refused with a sentence saying both need this version | rc.159 |
| Inviting people online | In a secure group → Invite people online, tick someone who is NOT your contact: the group says a contact request was sent; once they accept, the invitation arrives on their phone. Ticking a contact still sends at once. Signing in to a clearnet or .onion server (with Orbot) starts no I2P router | rc.160 |
| Sign in again after Sign out | Sign out, then sign in again at once (also after the account was taken over by another phone): it connects, over I2P too, without restarting the app | rc.161 |
| Calls over the built-in router | Both phones on this build, no separate I2P app: call, answer on the other phone; you hear each other within a minute or two. A retry right after a failed call is not refused | rc.162 |
| Deleted groups | Phone A creates a group with B and C, then deletes it: on B and C it disappears from the list within seconds, with its messages; reconnecting does not bring it back. Same for a plain room A owns | rc.163 |
| Viewer buttons | Open a received photo and a PDF: Open with another app, − / 100% / + and Previous / Next are all above the navigation bar and can be tapped | rc.164 |
| Save to device | Open a received photo or PDF → Save to device…: read the warning, choose Downloads, save. Open it in Files. Wipe & Exit, reinstall: the saved copy is still in Downloads | rc.165 |
| Viewer tabs | Open a photo taken with location on: Metadata lists GPS position, camera and time, and scrolls to the end. Hidden content says nothing follows the picture; a photo with a ZIP appended (cat photo.jpg x.zip > y.jpg) shows its size and says ZIP. A PDF lists its findings | rc.166 |
| Viewer tabs (fix) | As rc.166; the Metadata tab no longer lists a SHA-256 | rc.167 |
| Wipe & Exit text | Profile → Wipe & Exit: the confirmation says files saved with Save to device are not touched; cancel | rc.168 |
| Never plaintext 1:1 | Send a message to a contact who is offline: it shows as waiting and arrives encrypted once they are online. Send to an account on another XMPP app without OTRv4+: it waits, the chat says why, nothing arrives unencrypted | rc.169 |

## ⚠️ Known limits

- **A synthetic voice is harder to recognise, not impossible.** Measured
  against a speaker-recognition network (see \`docs/VOICE_NOTES.md\`), Synthetic
  is the strongest. What you *say* — words, accent, background — can still
  identify you. Where it matters, type.
- **I2P is slow to start.** Building tunnels takes 30–120 s; the first start
  of the built-in router 2–5 minutes.
- **Group size: about 100 members.** Measured, not set: a new member joins
  with a message carrying the whole group's post-quantum keys, about 9.4 KB
  per member, and the app refuses any group message over 1 MB, so joins
  stop at roughly 100. Only four members have been tested on phones. Every
  group change also goes through the server room, so big groups are slow on
  a server with the default room rate limits. Server admins can measure
  their own server with the terminal client's stress test (`docs/STRESS_TEST.md`).
- **Group calls are for groups of up to 5 members.** Each phone sends its
  audio to every other phone directly over I2P, so a larger group has no
  call button and stays text only (rc.84).
- Secure groups made before rc.27 must be re-created to add members.
- **Both phones need rc.159 or newer.** Since protocol v2 (post-quantum
  ratchet and authentication) an older build is refused, with a sentence
  saying so; there is no fallback to the old protocol.
- **A file saved to the device is outside the app.** Save to device writes a
  decrypted copy where you choose; Wipe & Exit does not delete it.
- **Not independently audited.** The cryptography has been tested and reviewed
  by the developer with AI assistance; see \`docs/SECURITY_ISSUES.md\` for what
  is open.

The full gate list is \`docs/ANDROID_XMPP_MILESTONE.md\` §7; the device-test
procedures are \`docs/ANDROID_MESSAGING_DEVICE_TEST.md\` and
\`docs/ANDROID_CALL_AND_FILE_DEVICE_TEST.md\`.

## Verified by CI

Asserted on every run rather than assumed:

- The project configures, and both \`assembleDebug\` and \`assembleRelease\`
  complete. The **release** APK is R8-minified, strips every \`android.util.Log\`
  call, is not debuggable (read from its manifest), and does not contain the
  debug diagnostics screen.
- Both APKs are **unpacked and inspected** (\`.github/scripts/inspect_apk.py\`):
  the right Python modules and none of the terminal-only, test or retired ones;
  the pinned Python packages and none of the removed ones (argon2-cffi, cffi,
  cryptography, aiodns); the Rust core for both ABIs with no test-only or
  legacy API compiled in; the NOTICE; no key, credential or secret-store file.
  The release APK's full content list with a SHA-256 per file is attached.
- The release APK's signature is verified with \`apksigner\`: ${SIGNING}.
- The Rust core (\`otrv4_core\` ${CORE}) is cross-compiled for \`arm64-v8a\` and
  \`x86_64\`, and its \`DT_NEEDED\` names \`libpython3.12.so\` — the libpython
  Chaquopy actually installs.
- That core is **present inside this APK**. This is checked by unpacking the
  APK, not inferred from the build succeeding — an earlier build assembled
  perfectly green with no Rust core in it at all.
- The bundled Python requirement list is the complete dependency closure,
  re-resolved on every run.
- The Kotlin unit tests pass.

## The server (Prosody): what it needs

Found while testing against \`otrv4plus.i2p\`. The app copes with each of
these where it can, but the server settings decide how well:

- **\`muc_limits\` on the conference component.** With its defaults it
  refuses any room message over 5664 characters and allows about one
  message every two seconds. Every secure-group message is larger than that
  (post-quantum keys and signatures), so the app splits group messages into
  4000-character pieces. Since rc.27 it sends them **fast** (10 at once,
  then 4 a second) and, when the server bounces one, **slows that room
  down** to the default limit's pace for 5 minutes and sends again whatever
  the room did not echo back. A group therefore works on a stock server,
  but adding a member is ~1 s on a relaxed server against ~20 s on the
  defaults. **Recommended:** remove \`muc_limits\` from
  \`Component "conference.<host>"\`, or set at least
  \`muc_event_rate = 5\`, \`muc_burst_factor = 10\` (Prosody's names for the
  limit's rate and burst) and \`muc_max_char_count\` of 5664 or more.
- **A TLS certificate for every host**, \`<host>\` and \`conference.<host>\`,
  named \`<host>.crt\`/\`.key\` in Prosody's \`certs\` folder, readable by the
  prosody user (\`prosodyctl check certs\`). Without one Prosody refuses the
  TLS handshake and the app reports \`tls_failed\`. Over I2P and Tor the
  certificate is not checked: a \`.b32.i2p\` or \`.onion\` address is itself
  the server's key, and for a name like \`otrv4plus.i2p\` the app pins the
  destination it first reached and refuses a different one (X1). Wherever
  the certificate is not checked, the app signs in with SCRAM only, never a
  plain password.
- **Accounts live on the host name.** \`aliases\` is not a Prosody option:
  an account must be \`user@otrv4plus.i2p\`, not \`user@<b32>.b32.i2p\` (the
  app maps the latter for the built-in server).
- **Profiles are public on the server.** Prosody's \`vcard\` module lets any
  user of the server read any user's profile; the Profile screen says so.
  Pictures (XEP-0084, PEP) are contacts-only.

**An I2P router is built in** (new in rc.45): i2pd, with only its SAM
bridge listening, on loopback, on a random port. The app uses an I2P app
already running on the phone when its SAM bridge answers on the usual port,
and starts its own otherwise, so no separate I2P app is needed. It relays no
traffic for others (no transit tunnels, since rc.118), is never a floodfill,
opens no ports on your home router (no UPnP), and is
kept running between connections (a router started cold cannot be reached
for minutes) and stopped on Sign out, Wipe & Exit and when the app is closed. The icon is a
**placeholder** (AI-generated, no licence asserted -- see \`docs/ASSETS.md\`).

\`docs/ANDROID_XMPP_MILESTONE.md\` §7 is the open gate list, item by item;
\`docs/ANDROID_MESSAGING_DEVICE_TEST.md\` is the procedure;
\`docs/ANDROID_CHAT_ARCHITECTURE.md\` §7 records what is and is not covered by tests.

## Install

Two APKs are attached:

- **\`${ROUT}\`** — the release candidate. Use this for validation.
- **\`${OUT}\`** — the same commit as a debug build, which adds the
  integration diagnostics screen. Use it if the release APK misbehaves and you
  need to see why.

The release APK is ${SIGNING}. Android will ask you to allow installation from
an unknown source.

- **minSdk 26** (Android 8.0). Both ABIs are in the one file, so there is no
  variant to choose.
- The first connection takes a while. Building an I2P tunnel is 30-120+
  seconds and the app says so while it waits; that is the network, not a hang.
  The very first start of the built-in router takes longer (it has to join
  the I2P network: usually 2 to 5 minutes); the connect screen shows how long
  it has been going.
- If something does go wrong, the **Debug** screen — "Open diagnostics" on the
  connect screen, "Debug" from the conversation list — has **Share error log**
  and **Export start-up report**. Both are designed to be shareable: JIDs,
  server names, I2P destinations and IP addresses are replaced with labels,
  and message bodies never enter them at all. \`logcat\` is still there if the
  app does not get far enough to show a screen.

## Provenance

| | |
|---|---|
| app version | \`${APP}\` (versionCode ${CODE}) |
| commit | \`${GITHUB_SHA}\` |
| workflow run | [#${GITHUB_RUN_NUMBER}](${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}) |
| built | $(date -u '+%Y-%m-%d %H:%M UTC') |
| release APK | \`${ROUT}\` (${RSIZE}) |
| release sha256 | \`${RSHA256}\` |
| debug APK | \`${OUT}\` (${SIZE}) |
| debug sha256 | \`${SHA256}\` |
| release contents | \`${MANIFEST}\` (SHA-256 of every file inside the release APK) |

\`\`\`
sha256sum ${ROUT} ${OUT}
\`\`\`

Built from this repository by \`.github/workflows/android.yml\` on a
GitHub-hosted runner. Source for this binary is the commit above; the software
is dual-licensed AGPL-3.0 + commercial (see \`LICENSE\`), and the
documentation is CC BY-SA 4.0 (see \`LICENSING.md\`).
EOF

echo "=== release notes ==="
cat notes.md
echo "====================="

# Delete and recreate rather than upload --clobber: the asset filenames carry
# the commit SHA, so clobbering would leave every previous build's APK
# attached and it would stop being obvious which one is current. For a
# release-candidate tag this replaces a rerun of the same candidate only.
if gh release view "$TAG" >/dev/null 2>&1; then
    echo "replacing the existing $TAG release"
    gh release delete "$TAG" --yes --cleanup-tag
fi

gh release create "$TAG" "$ROUT" "$OUT" "$MANIFEST" "${SHOTS[@]}" \
    --title "Android ${VERSION} — ${KIND} (experimental)" \
    --notes-file notes.md \
    --prerelease \
    --target "$GITHUB_SHA"

echo "published $TAG: $ROUT ($RSHA256), $OUT ($SHA256)"

# ONE APK ON THE RELEASES PAGE. The owner's instruction: older builds must
# not stay available to be installed by mistake. Only after the new release
# exists -- deleting first could leave the page with nothing on it if the
# upload failed -- every OTHER Android release (android-v*, and the rolling
# android-experimental) is deleted together with its tag. Only Android APK
# releases are touched; nothing else on the page is.
gh release list --limit 200 --json tagName --jq '.[].tagName' |
    grep -E '^android-(v|experimental$)' |
    while read -r old; do
        if [ "$old" != "$TAG" ]; then
            echo "removing superseded release $old"
            gh release delete "$old" --yes --cleanup-tag ||
                echo "::warning::could not remove $old"
        fi
    done
