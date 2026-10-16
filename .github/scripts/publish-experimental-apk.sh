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
# ANDROID_CALL_AND_FILE_DEVICE_TEST.md and the rc.2 CHANGELOG entry). That
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

cat > notes.md <<EOF
# ⚠️ EXPERIMENTAL — a ${KIND}, not a release

\`${APP}\` — built from \`${GITHUB_SHA}\`. Android 8.0 or newer.

**Download \`${ROUT}\`** (below). The first sign-in takes a few minutes while
the built-in I2P router joins the network.

---

## Verified on a real device — ✅ what works

Reported from a handset: two Android 15 phones (arm64-v8a, a Pixel and a
Xiaomi) by the project owner, against the project's server
\`otrv4plus.i2p\`, over the **built-in I2P router** (no other I2P app
installed), and with the Termux client.

| Area | What was confirmed |
|---|---|
| Connection | Sign in and create an account over I2P; the built-in router starts and carries everything |
| Contacts | Adding contacts, presence, the People list |
| 1:1 chat | OTRv4+ end to end, app ↔ app and app ↔ Termux |
| Identity check | SMP verification, app ↔ app and app ↔ Termux |
| Files | Encrypted file transfer, hashes checked on arrival |
| 1:1 calls | Two-way voice calls between two handsets running this app, and between this app and the Termux client |
| Secure groups | Post-quantum MLS groups, group messages both ways — **tested with four members** (two phones, each with the app and Termux). No size limit is set; larger groups are not yet tested |
| Group check | Group verification with a shared passphrase |
| Group calls | Two-way group voice calls |
| Location | Location pins from GPS only, received as a card (rc.73; since rc.80 only to verified contacts and groups) |
| Voice notes | Voice notes in **My voice** |
| Rooms | Room discovery, creating and joining a room |
| App | Bottom bar on every main screen; the 📎 and 🎤 buttons in the composer |
| Wipe | **Wipe & Exit, including deleting the account from the server** |

## NOT verified — 🧪 built, still to be tested on phones

| Area | What to test | Since |
|---|---|---|
| Synthetic voice notes | **Synthetic** was rebuilt: no whistle, every note's voice drawn from the phone's own random generator, changing through the note. **Disguised is gone** (rc.81): the choice is Synthetic or My voice. Record the same sentence in both and compare | rc.77–rc.81 |
| Verification progress | A moving bar on **both** phones (and the desktop and terminal) from the moment verification starts until it ends, 1:1 and groups | rc.81 |
| Joining a secure group | After accepting an invitation the room shows *setting up end-to-end encryption* with a bar, never "not encrypted"; typing is held until it is ready | rc.81 |
| Ready-to-call phone | The phone icon should turn **green on both phones** within a few minutes of signing in, in any chat; a call placed while green should start without the 30–120 s wait | rc.76–rc.77 |
| Hang-up | No crash when hanging up 1:1 and group calls (the Pixel crashed in rc.74) | rc.75 |
| Group-call recovery | If one side stops hearing the other, the call repairs itself (at most twice). Send the diagnostics report from **both** phones after a group call | rc.74 |
| Message actions | Reply, correct, delete for everyone, react — 1:1, rooms and secure groups | rc.68–rc.69 |
| Room history | Earlier room messages loaded from the server archive | rc.68 |
| Profile picture | A photo from the camera (HEIC, rotated) as your picture | rc.72 |
| Group files | Sending a file to a secure group | rc.54 |
| Location | Only sent once the contact (or every group member) is verified — before that 📍 explains and the GPS never starts; a mock-location app's position; typing a Plus Code; "Open in maps app" | rc.73–rc.80 |
| Photos | The "hidden information" question strips a camera photo's location | — |
| Staying connected | Background survival, reconnect after a network change | — |
| Desktop app | The desktop (Linux/Qubes) client against the same server | — |

## ⚠️ Known limits

- **A synthetic voice is harder to recognise, not impossible.** Measured
  against a speaker-recognition network (see \`VOICE_NOTES.md\`), Synthetic
  is the strongest. What you *say* — words, accent, background — can still
  identify you. Where it matters, type.
- **I2P is slow to start.** Building tunnels takes 30–120 s; the first start
  of the built-in router 2–5 minutes.
- **Group size.** A secure group has no member limit (up to 16 can be
  added at once), but only four have been tested. Every member receives
  every group change through the server room, and post-quantum keys make
  those changes large, so big groups (hundreds) will be slow on a server
  with the default room rate limits — see the server section below.
- **Group calls take at most 5 people**: each phone sends its audio to
  every other phone directly over I2P.
- Secure groups made before rc.27 must be re-created to add members.

The full gate list is \`ANDROID_XMPP_MILESTONE.md\` §7; the device-test
procedures are \`ANDROID_MESSAGING_DEVICE_TEST.md\` and
\`ANDROID_CALL_AND_FILE_DEVICE_TEST.md\`.

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
  TLS handshake and the app reports \`tls_failed\`. The app accepts any
  certificate over I2P, because the .b32.i2p address already proves the
  server.
- **Accounts live on the host name.** \`aliases\` is not a Prosody option:
  an account must be \`user@otrv4plus.i2p\`, not \`user@<b32>.b32.i2p\` (the
  app maps the latter for the built-in server).
- **Profiles are public on the server.** Prosody's \`vcard\` module lets any
  user of the server read any user's profile; the Profile screen says so.
  Pictures (XEP-0084, PEP) are contacts-only.

**An I2P router is built in** (new in rc.45): i2pd, with only its SAM
bridge listening, on loopback. With "I2P router: Automatic" (the default) the
app uses an I2P app already running on the phone when its SAM bridge answers,
and starts its own otherwise, so no separate I2P app is needed. It relays a
little traffic for others (bandwidth class L, at most 50 transit tunnels),
is never a floodfill, opens no ports on your home router (no UPnP), and is
stopped on Disconnect, Sign out and Wipe & Exit. The icon is a
**placeholder** (AI-generated, no licence asserted -- see \`ASSETS.md\`).

\`ANDROID_XMPP_MILESTONE.md\` §7 is the open gate list, item by item;
\`ANDROID_MESSAGING_DEVICE_TEST.md\` is the procedure;
\`ANDROID_CHAT_ARCHITECTURE.md\` §7 records what is and is not covered by tests.

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

gh release create "$TAG" "$ROUT" "$OUT" "$MANIFEST" \
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
