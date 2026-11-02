<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial -->
<!-- Copyright (C) 2025-2026 muc111 -->
# CAPTCHA registration — pre-test gate handover

**Branch:** `captcha-registration` · **Tip:** `a6b402b` · cut from `dev`
(`378f856`). **GATE VERDICT: NOT PASSED in the build container** — the source
is verified and all three *source* paths compile/test clean, but the three
end-user **artifacts cannot be produced in this container** (reasons below), so
they must be built on the human's side / CI before device testing. Everything
needed to do that is here.

## Commits added on top of the CAPTCHA commit

| Commit | What |
|---|---|
| `c5219b7` | **CAPTCHA support** (XEP-0077/0158/0231), unchanged — the reviewable feature commit |
| `db1f0e0` | docs: correct `CRYPTO_SOURCE_OF_TRUTH` crate names (pqcrypto→ml-kem/ml-dsa/ed448-goldilocks-plus) |
| `83e0ebc` | clippy: drop redundant clone in seeded ML-KEM keygen (the addendum's `clone_on_copy`) |
| `09ef037` | clippy: clear the `--all-features` cascade (`is_multiple_of`, `expect_err`) |
| `cd8ae07` | security: re-check GHSA-36hh-v3qg-5jq4 for the new `.step_by(` sites |
| `27a4b95` | fix(desktop): import `RegistrationCaptcha` in `DesktopCore` (CAPTCHA compile fix found by this gate) |
| `a6b402b` | test: document the suite's CI configuration + guard-test trap (`tests/README.md`) |

## What was verified here (clean checkout, recorded toolchains)

Toolchain: rustc/cargo **1.97.0**, maturin **1.15.0**, JDK **21.0.12.1**,
Gradle **8.14.3** (Kotlin 2.0.21, Compose 1.7.3), Python **3.12.3**. Host:
x86_64 Linux. MSRV **1.91** (≤ 1.97). `#![forbid(unsafe_code)]` holds on both
`otrv4_core` and `otrv4-mls` (they compile).

| Target | Result here |
|---|---|
| **Rust core** (`cargo test --release --features mls`) | **208 passed, 0 failed** |
| **otrv4-mls** (`cargo test --release --features reference-interop`) | **82 passed, 0 failed** (incl. OpenMLS reference cross-check) |
| **clippy** both crates `--all-targets --all-features -- -D warnings` | **clean** |
| **Python suite** vs CI test wheel, CI env | **8370 passed, 48 skipped, 0 failed** |
| **Release-guard subset** vs shipping wheel | **52 passed, 0 failed** |
| **Desktop Kotlin** `compileKotlin` + `compileTestKotlin` | **BUILD SUCCESSFUL** |
| **TUI CAPTCHA temp-file lifecycle** (pure Python) | **verified** — image written → prompted → removed, no residue, incl. cancel/EOF |

## What could NOT be produced here (why the gate is not passed)

1. **Android APK** — no Android SDK/NDK in the container (`ANDROID_HOME` empty,
   no `sdkmanager`/`adb`), and the agent proxy returns **403 for
   `dl.google.com`** (Google Maven), which the APK's `androidx.*` and Chaquopy
   deps need. Cannot build or install here.
2. **Desktop runnable binary** — Kotlin **compiles**, but producing/running the
   app needs Compose Desktop's `androidx.*` **runtime** jars from Google Maven,
   same 403. `gradle test`/`packageDistributionForCurrentOS` fail at dependency
   resolution, not at any assertion. GUI launch is also not possible headless.
3. **Termux arm64 build** — this host is x86_64; no arm64 toolchain/Termux. The
   TUI *logic* (identical pure-Python on arm64) is verified here.

These are environment limits, not code defects. On CI (open network + SDK) and
on the human's machines they build; the commands are below.

## Build the three artifacts (run where network + SDK exist)

**Android APK** (CI `android.yml`, or locally with Android SDK+NDK, JDK 17):
```sh
cd android && ./gradlew :app:assembleRelease   # or assembleDebug
# APK: android/app/build/outputs/apk/release/app-release.apk
```

**Desktop** (JDK 21, open network):
```sh
cd desktop && gradle packageDistributionForCurrentOS
# installer under desktop/build/compose/binaries/main/<deb|dmg|msi>/
# or: gradle run   (launches the app)
```

**Termux / TUI** (on the phone, arm64):
```sh
cd Rust && ./build.sh          # builds + installs otrv4_core for Termux
python client/otrv4plus_xmpp.py --jid you@conversations.im --register --no-i2p
```

**Host Rust wheels built & verified here** (x86_64 — evidence, NOT the
distributables): release `sha256 bc7076389ff701597ed0c79652f1f994b6984ae58b2727f9ce59dc4afcc451c7`,
test `sha256 a312a39eed4f791c9cb2fd0e55bc983f1dbeac1d84743eeb0b8f9fc8b09e6c49`
(maturin embeds build metadata, so a rebuild's hash will differ; build from
tip `a6b402b`).

## What to test, and what to expect

### CAPTCHA registration (the new feature)
- On a server that needs a CAPTCHA (e.g. conversations.im), **Create account**
  shows the challenge **image inline** and a text box. Type the characters →
  the account is created and you are signed in.
- The image is rendered **only** from the inline bits-of-binary the server
  already sent. If a server offers the image as an `http(s)` URL instead, the
  app **refuses** and says to use the server's web page — **no fetch, password
  not sent**. (This is the security invariant; do not expect the image to load
  from a URL.)
- Desktop/Android show the prompt in the Connect screen; Termux saves the image
  to a temp file, prints its path, asks for the answer, then **deletes** it.
- A wrong answer → the server rejects it; the app surfaces "not accepted" and
  (TUI) offers a fresh challenge. Blank/Cancel releases the held stream.
- Clearnet exposure note: registering on a public server is a clearnet
  connection and reveals your IP to that server, exactly as before; I2P/Tor
  registration still never touches DNS or a web fetch.

### Regression surface to confirm unchanged (F1–F7, cross-version)
- **F1** hedged ML-DSA signing — signatures verify; two signatures of the same
  message differ (non-deterministic).
- **F2** MLS size caps — oversized key packages / welcomes / messages are
  refused, same bound on both sides of the binding.
- **F3** hybrid-only client — 1:1 and groups negotiate the hybrid suite
  (0xF0A1); the non-hybrid 0x0906 is test-only and must not appear on the wire.
- **F6** composite signatures bind both component public keys — a
  swapped-key signature is rejected.
- **F7** an undecodable ML-DSA key is refused before `from_expanded` (no abort).
- **Cross-version old↔new:** a peer on the pre-PQ build and a peer on this build
  interoperate for the v1 handshake only; two PQ-capable peers use the hybrid
  ratchet. There is **no wire-format change in this branch** — it adds
  registration CAPTCHA handling only — so an existing account and existing
  chats/groups behave exactly as on `dev`.
- Smoke the rest end to end on all three platforms: 1:1 chat, MLS group
  messages, audio call, file transfer, GPS, voice notes.

## Residual known issues (sign-off)
- **`Rust/.cargo/audit.toml`** still lists the removed pqcrypto RUSTSEC ignores;
  they now match nothing (pqcrypto is out of `Cargo.lock`). Harmless, flagged in
  `CRYPTO_SOURCE_OF_TRUTH.md`, left for a separate audit-config cleanup.
- Artifact production for the three targets is **not** done here (see above).

**Bottom line:** source is green on every path this container can run, and the
CAPTCHA feature is verified end-to-end through the Python engine and compiles on
every front end. The gate is **not** passed only because the APK, desktop
binary and Termux arm64 build cannot be emitted in this container. Build those
three from tip `a6b402b` where network and the Android SDK are available, then
device-test per the notes above.
