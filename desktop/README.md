# OTRv4Plus desktop

This is the Android app's interface, built for a Linux desktop and for a Qubes
qube with no network. It uses Compose for Desktop with Material 3, the Android
app's dark purple theme, and a two-pane layout: a list on the left and the
conversation on the right.

![A verified conversation](docs/chat.jpg)

The screenshots come from `gradle test`, which renders the app driven by
a scripted engine (CI uploads them on every change).

```
┌──────────── this window (JVM, Compose) ────────────┐  JSON lines   ┌──── engine process (Python + Rust) ────┐
│ screens, dialogs, the Android chat rules           │ ───────────▶  │ desktop_bridge.host                    │
│ (ChatState, Verification, CallUi, ...)             │ ◀───────────  │  → android_bridge (OtrApp, controller) │
│ NO keys, NO cryptography                           │   stdin/out   │  → otrv4_core (Rust): every key, every │
└────────────────────────────────────────────────────┘               │    cipher, every proof                 │
                                                                     └────────────────────────────────────────┘
```

* **The window is a separate process from the keys.** The GUI starts the
  engine (`desktop_bridge/host.py`) as a child process, sends it commands,
  and shows the events it reports. It never holds an identity key, a
  ratchet, a session secret or a group key. The only secrets that pass
  through it are the ones you type, the account password and an SMP
  passphrase, and those go straight to the engine. A bug in the user
  interface layer (Compose, Skia, the JVM) therefore cannot read your keys.
* **One engine everywhere.** The engine process runs the same Python and
  Rust as the Android app (through Chaquopy) and as the Termux/Ubuntu
  terminal client. It talks the same wire protocol, so the desktop app,
  the APK and Termux all talk to each other.
* **Shared rules, not copied ones.** About 55 plain-Kotlin files from the
  Android app are compiled straight from `android/` (see the
  `sharedFromAndroid` list in `build.gradle.kts`). They cover:
  * the engine models and events (`OtrCore.kt`);
  * the chat state machine (`ChatState.kt`);
  * the security wording and badges;
  * when verification, calls and files are offered;
  * the connection problem lines;
  * the theme tokens.

  `tests/test_desktop_bridge.py` checks that those files stay free of
  Android imports. It also checks that the desktop reads every engine
  event the same way the Android bridge does.

## Status

This is the first version. Working now:

* sign-in, with the same status wording as the Android Connect screen;
* the chat list with security badges and unread counts;
* the conversation view: encrypted and plaintext labels on every message,
  queued and failed sends, and automatic OTRv4+ with a handshake progress
  bar;
* **Encrypt**;
* **Verify** (SMP), both starting a check and answering one;
* **Call**, with the engine's gate and its reason, and answering and hanging
  up;
* **files**: a picker, the remove-hidden-information choice, and
  accepting or declining incoming files with progress;
* **People**: contacts and subscription requests;
* **Rooms**: joining a room, creating an encrypted MLS group, and group
  invites;
* **Settings**: your fingerprint, the theme, and Wipe & Exit.

Still to do:

* chat history on disk (it is in memory only for now; the Android app
  encrypts its history store with the Keystore, and the desktop
  equivalent still needs a vault);
* avatars and profile editing;
* group verification and group calls in the room view;
* notifications.

## Build and run

```sh
cd desktop
gradle desktopLib        # jars in build/desktop-lib
OTRV4PLUS_ENGINE="python3 -s -m desktop_bridge.host" \
  java -cp 'build/desktop-lib/*' org.otrv4plus.desktop.MainKt   # run from the repo root
```

Set `OTRV4PLUS_ENGINE` to the command that starts the engine. The packaged
default is `/usr/lib/otrv4plus/otrv4plus-engine`.

`gradle test` drives the app against a scripted engine, covering sign-in,
receiving, sending and the boundary rules. It also renders each screen to
`build/screens/*.png` with no display needed. CI
(`.github/workflows/desktop.yml`) runs it on every change and uploads the
screens as the `desktop-screens` artifact.

## Versions

Compose Multiplatform 1.7.3 with Kotlin 2.0.21, the same Kotlin as the
Android app.

Two repositories are used:

* Maven Central, for Compose, Skia and kotlinx;
* Google's Maven, restricted to `androidx.*` (Compose for Desktop's JVM
  builds of `androidx.collection`, `androidx.annotation` and
  `androidx.lifecycle` are published only there).

The offline Qubes build takes every jar from the cache the fetch step built.
Each jar is checked against `gradle/verification-metadata.xml`, which holds
the SHA-256 of 125 components. CI wrote it. A strict build in a second
environment, which fetched its Maven Central jars over a different path,
matched every one of them.

On Qubes, `qubes/packaging/build-desktop.sh` builds the
`otrv4plus-desktop` package offline. `qubes/README.md` covers the rest of
the setup.
