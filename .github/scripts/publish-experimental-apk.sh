#!/usr/bin/env bash
#
# Publish the debug APK as a rolling EXPERIMENTAL prerelease.
#
# ROLLING, not versioned: one tag, `android-experimental`, replaced on every
# green build. That is the honest shape for what this is. A version number
# implies a release someone stands behind, and nobody has yet run this APK on
# a handset -- so a stream of v0.3.1, v0.3.2 tags would be claiming a
# release process this does not have. One tag that always means "the newest
# build that passed CI" claims exactly what is true.
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

cat > notes.md <<EOF
# ⚠️ EXPERIMENTAL — a development build, not a release

This is an automated build, published so it can be tested. It is not a
release, it is not supported, and it should not be used to protect anything
real.

Earlier builds carried the line "this APK has never been run". That is no
longer true and has been corrected rather than quietly dropped: the APK has
been installed and launched on a handset, and a substantial part of the
runtime is now verified there. What has NOT been verified is listed below, and
that list is the reason this is still marked experimental.

For a client that is known to work end to end today, **Termux remains the
reference implementation**. See the README.

---

## Verified on a real device

Reported from a handset (Android 15, arm64-v8a):

- the APK installs and launches;
- Chaquopy starts CPython 3.12 and \`import otrv4_core\` succeeds on the real
  ABI;
- \`EnhancedSessionManager\` constructs with a persistent identity;
- the SAM probe, the I2P tunnel, the XMPP connection and SASL authentication
  complete against the live server;
- a message sent from a Termux peer reached the handset over I2P.

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

- **Plaintext messaging in both directions.** Implemented and unit-tested; the
  device gate is open.
- **Roster and presence** on the handset.
- **Background survival, and reconnect** after a transient failure.
- **OTR end to end.** No DAKE has been observed completing between a handset
  and a Termux peer. Do not read "the runtime starts" as "OTR works".
- **Voice.** Verified under Termux, which is a different process model. Do not
  read "voice works" as "voice works in the APK".

Also absent by design at this stage: **no in-APK I2P router** and no signed
release build.

\`ANDROID_MESSAGING_DEVICE_TEST.md\` is the procedure for the open gates;
\`ANDROID_CHAT_ARCHITECTURE.md\` §7 records what is and is not covered by tests.

## Install

Debug-signed, so it sideloads without adb. Android will ask you to allow
installation from an unknown source.

- **minSdk 26** (Android 8.0). Both ABIs are in the one file, so there is no
  variant to choose.
- Expect it to crash. If it does, \`logcat\` is the useful part — it says
  whether the interpreter started and whether the Rust core loaded.

## Provenance

| | |
|---|---|
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
