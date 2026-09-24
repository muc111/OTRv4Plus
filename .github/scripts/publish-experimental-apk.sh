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
# app-to-app calls working; app-to-Termux calls are still open.
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

\`${APP}\` — built from \`${GITHUB_SHA}\`.

A **release candidate** means every repository-level gate is closed: the
secrets the terminal clients keep at rest are held by the Rust core, the
dependency audit is clean, the documentation licence is decided, the icon's
origin is recorded, and the release variant is built and its contents
inspected on this run. It is still **not a release** and it is still
EXPERIMENTAL: encrypted chat, identity verification, file transfer and
two-way voice calls between two copies of the app have been proved on
handsets, and the smaller items below are still open.

---

## Verified on a real device

Reported from a handset (Android 15, arm64-v8a) by the project owner,
against the live server over I2P, with a Termux client as the peer:

- **OTRv4+ end to end**: the DAKE completes between the handset and the
  Termux client, and messages flow encrypted in both directions;
- **identity verification (SMP)**: SMP completes to verified between the
  handset and the Termux client, and the Termux client keeps the verified
  state;
- **encrypted file transfer** between the handset and the Termux client
  completes, with the file's hashes checked on arrival;
- **two-way voice calls between two handsets running this app** (accounts
  Alice and Bob): both directions heard, over I2P;
- **OTRv4+ between two handsets running this app** completes; over I2P it
  takes a minute or more, and this build shows the handshake's progress;
- the APK installs and launches; Chaquopy starts CPython 3.12 and
  \`import otrv4_core\` succeeds on the real ABI; \`EnhancedSessionManager\`
  constructs (with a new identity on each launch, by design -- decision B1);
- the SAM probe, the I2P tunnel, the XMPP connection and SASL authentication
  complete against the live server;
- **signing in**, the **roster** (real subscription and presence, without a
  message having to arrive first), **adding a contact**, and **1:1
  conversations** in both directions;
- **rooms**: the MUC service is discovered without anything being typed, a
  room can be created by name, and the app navigates into it.

No cryptography runs in Kotlin or Python: every session, SMP and file key is
held by the Rust core.

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

## NOT verified, and the reason this is still experimental

- **Voice calls between the app and a Termux client.** App-to-app calls
  work (above); a call with the Termux client on the other end has not been
  run yet.
- **What this version adds on top**, not yet run on a handset: automatic
  OTRv4+ only toward clients that advertise OTRv4Plus, the People list, file
  progress with ETA, the in-app viewer, Wipe & Exit from the conversation
  list, and the theme. See CHANGELOG.md for this version.
- **Background survival, and reconnect** after a transient failure.
- **The subscription banner**: what the app shows when somebody else asks to
  see your presence.
- **A room shared with a second account.** Rooms have been created and
  entered from one handset; the locked-room path needs two.
- **Metadata stripping of a handset camera photo**, and a re-run of Wipe &
  Exit: \`ANDROID_CALL_AND_FILE_DEVICE_TEST.md\` lists every step, separating
  what CI has verified from what needs hardware.

Also absent by design at this stage: **no in-APK I2P router** (an I2P router
app with SAM enabled must be running on the phone). The icon is a
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
