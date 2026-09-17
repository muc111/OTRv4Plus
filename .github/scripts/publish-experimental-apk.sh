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

TAG="android-experimental"

APK=$(find apk -name '*.apk' -print -quit)
if [ -z "$APK" ]; then
    echo "::error::no .apk in the downloaded artifact; nothing to publish"
    exit 1
fi

SHORT="${GITHUB_SHA:0:7}"
OUT="otrv4plus-${SHORT}-debug.apk"
cp "$APK" "$OUT"

SHA256=$(sha256sum "$OUT" | cut -d' ' -f1)
SIZE=$(du -h "$OUT" | cut -f1)

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

cat > notes.md <<EOF
# ⚠️ EXPERIMENTAL — a development build, not a release

This is an automated build, published so it can be tested. It is not a
release, it is not supported, and it should not be used to protect anything
real.

**The messaging client now works on a handset.** Sign-in, contacts, presence
and conversations have been used on a real device against the live server.
What is still unverified is listed below, and that list -- not a guess about
quality -- is why this remains marked experimental.

The headline gap is **OTR itself**: no handshake has been observed completing
between a handset and a peer. Until it has, treat everything this APK sends as
unencrypted beyond the I2P tunnel.

For a client that is known to work end to end today, including OTR and voice,
**Termux remains the reference implementation**. See the README.

---

## Verified on a real device

Reported from a handset (Android 15, arm64-v8a):

- the APK installs and launches;
- Chaquopy starts CPython 3.12 and \`import otrv4_core\` succeeds on the real
  ABI;
- \`EnhancedSessionManager\` constructs with a persistent identity;
- the SAM probe, the I2P tunnel, the XMPP connection and SASL authentication
  complete against the live server;
- **signing in**, with the button showing progress for the length of an I2P
  round trip rather than looking ignored;
- **the roster loads**: contacts appear, with their real subscription and
  presence, without a message having to arrive first;
- **adding a contact** reaches the server and survives the next poll;
- **1:1 conversations** open and carry messages in both directions;
- **rooms**: the MUC service is discovered without anything being typed, a
  room can be created by name, and the app navigates into it.

Two defects found by that session are fixed in this build: the app no longer
attempts to connect before anybody has signed in, and the OTRv4+ control now
puts the handshake on the wire instead of generating it and dropping it.

## Verified by CI

Asserted on every run rather than assumed:

- The project configures and \`assembleDebug\` completes.
- The Rust core (\`otrv4_core\` ${CORE}) is cross-compiled for \`arm64-v8a\` and
  \`x86_64\`, and its \`DT_NEEDED\` names \`libpython3.12.so\` — the libpython
  Chaquopy actually installs.
- That core is **present inside this APK**. This is checked by unpacking the
  APK, not inferred from the build succeeding — an earlier build assembled
  perfectly green with no Rust core in it at all.
- The bundled Python requirement list is the complete dependency closure,
  re-resolved on every run.
- The Kotlin unit tests pass.

## NOT verified, and the reason this is still experimental

- **OTR end to end.** No DAKE has been observed completing between a handset
  and a peer. The control that asks for one was dropping the handshake it
  generated; that is fixed and unit-tested in this build, and it has not run
  on a device. Do not read "the runtime starts" as "OTR works".
- **Voice.** Verified under Termux, which is a different process model. The
  test that would show the APK transmits real audio rather than silence
  cannot run off-device and has never been executed anywhere.
- **Background survival, and reconnect** after a transient failure.
- **The subscription banner**: what the app shows when somebody else asks to
  see your presence.
- **A room shared with a second account.** Rooms have been created and
  entered from one handset; the locked-room path needs two.

Also absent by design at this stage: **no in-APK I2P router** and no signed
release build.

\`ANDROID_XMPP_MILESTONE.md\` §7 is the open gate list, item by item;
\`ANDROID_MESSAGING_DEVICE_TEST.md\` is the procedure;
\`ANDROID_CHAT_ARCHITECTURE.md\` §7 records what is and is not covered by tests.

## Install

Debug-signed, so it sideloads without adb. Android will ask you to allow
installation from an unknown source.

- **minSdk 26** (Android 8.0). Both ABIs are in the one file, so there is no
  variant to choose.
- The first connection takes a while. Building an I2P tunnel is 30-120+
  seconds and the app says so while it waits; that is the network, not a hang.
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
| size | ${SIZE} |
| sha256 | \`${SHA256}\` |

\`\`\`
sha256sum ${OUT}
\`\`\`

Built from this repository by \`.github/workflows/android.yml\` on a
GitHub-hosted runner. Source for this binary is the commit above; the project
is dual-licensed AGPL-3.0 + commercial (see \`LICENSE\`).
EOF

echo "=== release notes ==="
cat notes.md
echo "====================="

# Delete and recreate rather than upload --clobber: the asset filename carries
# the commit SHA, so clobbering would leave every previous build's APK
# attached and it would stop being obvious which one is current.
if gh release view "$TAG" >/dev/null 2>&1; then
    echo "replacing the existing $TAG release"
    gh release delete "$TAG" --yes --cleanup-tag
fi

gh release create "$TAG" "$OUT" \
    --title "Experimental Android APK — development build" \
    --notes-file notes.md \
    --prerelease \
    --target "$GITHUB_SHA"

echo "published $OUT ($SHA256)"
