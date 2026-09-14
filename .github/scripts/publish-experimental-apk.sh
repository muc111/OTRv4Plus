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
# ⚠️ EXPERIMENTAL — this APK has never been run

This is an automated build, published so it can be tested. **No device or
emulator has ever installed or launched it.** It is not a release, it is not
supported, and it should not be used to protect anything real.

If you are looking for OTRv4+ as something to actually use: **the supported
environment is Termux**, not this APK. See the README.

---

## What is actually verified

CI proves this much, and asserts each one rather than assuming it:

- The project configures and \`assembleDebug\` completes.
- The Rust core (\`otrv4_core\` ${CORE}) is cross-compiled for \`arm64-v8a\` and
  \`x86_64\`, and its \`DT_NEEDED\` names \`libpython3.12.so\` — the libpython
  Chaquopy actually installs.
- That core is **present inside this APK**. This is checked by unpacking the
  APK, not inferred from the build succeeding — an earlier build assembled
  perfectly green with no Rust core in it at all.
- The bundled Python requirement list is the complete dependency closure,
  re-resolved on every run.
- The Kotlin security-layer unit tests pass.

## What is NOT verified

Everything that needs hardware:

- that the app starts;
- that the embedded CPython interpreter initialises;
- that \`import otrv4_core\` succeeds on a real ABI;
- that AAudio opens a stream;
- that any OTR session is ever established.

Also absent by design at this stage: **no in-APK I2P router**, no signed
release build, and **no voice testing inside the APK** — voice is verified
under Termux, which is a different process model. Do not read "voice works"
as "voice works in the APK".

\`ANDROID_PHASE2_REPORT.md\` §14 tracks these as open gates.

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
    --title "Experimental Android APK — never run on a device" \
    --notes-file notes.md \
    --prerelease \
    --target "$GITHUB_SHA"

echo "published $OUT ($SHA256)"
