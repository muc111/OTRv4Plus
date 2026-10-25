# OTRv4Plus desktop

This is the Android app's interface, built for a Linux desktop and for a Qubes
qube with no network. It uses Compose for Desktop with Material 3, the Android
app's dark purple theme, and a two-pane layout: a list on the left and the
conversation on the right.

![A verified conversation](docs/chat.jpg)

![An encrypted group: verification and members](docs/group.jpg)

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

Working now:

* **Sign-in**, with the same status wording as the Android Connect screen.
* **Chats**: security badges, unread counts and contact pictures.
* **Conversations**:
  * every message is labelled encrypted or plaintext, with queued and
    failed sends marked;
  * automatic OTRv4+, with handshake progress shown;
  * **Encrypt**;
  * **Verify** (SMP): start a verification or answer one;
  * **Call**, behind the engine's gate, which gives its reason when it
    refuses; answer and hang up;
  * **Files**: a picker, a choice to strip hidden information, and
    accept or decline with progress;
  * **Open** on a received file: the in-app viewer, with the Android
    viewer's three tabs (File, Metadata, Hidden content) and Save to….
    Pictures and text are shown; other kinds are not opened, and their
    Metadata and Hidden content tabs still work.
* **Profiles**: click a contact's picture or name to see their XMPP
  profile (read-only). Settings has your own picture and profile:
  * your picture is cut to a square, scaled to 96 px and re-encoded
    before it is published;
  * the profile fields are the ones `android_bridge/profile.py` defines;
  * the screen says that a profile is public.
* **Pictures**: contacts' avatars are built here from pixels that the
  engine's bounded decoder has already decoded. A received picture is
  decoded by Skia only when you click **Open** on it (never on arrival),
  from a transient decrypted copy that is deleted when the viewer closes.
* **Encrypted groups**, working the same way as the Android app:
  * **Verify group**, using the shared passphrase, with progress and a
    time estimate;
  * **Call the group** once members are verified;
  * when someone calls: **Join**;
  * during a call: **Pause** and **Hang up**;
  * a members panel showing each member's verified state, plus invite
    over OTRv4+, remove, verify members, leave, and delete for everyone.
* **People**: contacts and subscription requests.
* **Rooms**: join a room, create an encrypted MLS group, accept group
  invites.
* **Notifications**, under the Android rules:
  * they say "New message", "N new messages" or "Incoming call", and
    never who or what;
  * messages are announced only while the window is not in front;
    calls (1:1 and group) are announced always;
  * delivered with `notify-send`, which dom0 shows on Qubes.
* **Settings**: fingerprint, theme, joining group calls automatically,
  and Wipe & Exit.

Chat history is kept in memory only, by choice: nothing is written to
disk.

## Install on Ubuntu or Debian

Ubuntu 24.04+ or Debian 13+. Everything is built from source on your
machine; nothing prebuilt is downloaded except the toolchains. One line:

```bash
# dev (newest; matches the current Android test APK):
sudo apt install -y git && git clone -b dev https://github.com/muc111/OTRv4Plus.git ~/OTRv4Plus && bash ~/OTRv4Plus/desktop/install.sh
# main (the last stable release):
sudo apt install -y git && git clone -b main https://github.com/muc111/OTRv4Plus.git ~/OTRv4Plus && bash ~/OTRv4Plus/desktop/install.sh
```

Both ends of a conversation need the same protocol: `main` has v2 since
2026-10-25, and a clone from before that is refused by `dev` and the APK. Already have the clone? `bash ~/OTRv4Plus/desktop/install.sh`.
Running it again later pulls the branch you are on and rebuilds; keys and
settings in `~/.otrv4plus` stay. Switch branch with
`git fetch origin dev && git checkout dev` (or `git checkout main`), then run it again.
`--no-run` installs without starting the app.

[`install.sh`](install.sh) is short; read it first if you like. It:

1. installs `git python3 python3-venv build-essential curl libopus0
   pulseaudio-utils openjdk-21-jdk i2pd` with apt (asks for sudo);
2. installs Rust with rustup if `cargo` is missing (the distributions'
   `rustc` is too old);
3. runs `Rust/build.sh`: the Rust core and the engine's `.venv`, ending with
   `BUILD OK`;
4. builds the app with the Gradle wrapper (`desktopLib`); every jar is
   checked against `gradle/verification-metadata.xml`;
5. adds `~/.local/bin/otrv4plus-desktop` and an "OTRv4+" menu entry, then
   starts the app.

For I2P the router must be running: `sudo systemctl enable --now i2pd`.
CI runs the same script on a clean Ubuntu 24.04 (`desktop.yml`, `install`).

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
