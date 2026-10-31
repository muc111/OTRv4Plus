<p align="center">
  <img src="icon.png" width="160" alt="OTRv4+">
</p>

<h1 align="center">OTRv4+</h1>

<p align="center"><strong>Private chat, groups, files and voice calls over I2P, on a server you can run yourself.<br>No phone number. Android, Linux desktop and terminal.</strong></p>

<p align="center">
<code>v10.31.0 · Rust core 0.13.2 · Android 0.7.0 (pre-release) · Desktop 0.14.11 (pre-release) · chat (X448 + ML-KEM-1024, AES-256-GCM) · group chat (MLS: X448 + ML-KEM-1024, Ed448 + ML-DSA-87, AES-256-GCM) · hybrid PQC SMP (ML-KEM-1024 + ML-DSA-87 + ZKP) · voice (X448 + ML-KEM-1024, AES-256-GCM) · I2P SAM · AAudio · TUI</code>
</p>

OTRv4+ is an open-source, end-to-end encrypted messenger built on XMPP and the I2P network. Anyone can run the server: an ordinary Prosody XMPP server behind i2pd. The app ships pointing at a public test server (`otrv4plus.i2p`) so you can try it straight away. That is a default, not a lock-in: change one field and it talks to your own. Tor and TLS also work for chat.

**Security status: extensively tested and hardened through developer-led and AI-assisted analysis, but not independently audited.**
Treat it as experimental. See [Security assessment and audit status](#security-assessment-and-audit-status) for what that covers and what it does not.

### Why another messenger?

- **Your server, your rules.** Plain XMPP (Prosody) behind I2P: no company in the middle, no phone number, no account tied to who you are. The free [Prosody modules](prosody/) add sign-up limits, bans and one session per account.
- **I2P built in.** The Android app carries its own I2P router, so there is nothing else to install. The server's location stays hidden, and so do the users'.
- **Post-quantum by default.** 1:1 chat, encrypted groups (MLS), identity verification and voice all pair classic X448/Ed448 with ML-KEM-1024 and ML-DSA-87.
- **Verify the person, not just the key.** Built-in SMP: two people confirm each other with a secret they agreed in person. Groups are verified the same way, by their creator.
- **Leaves as little behind as it can.** Messages can be made deniable afterwards (Publish Chat Keys), and Wipe & Exit destroys keys and checks the files are gone. On desktop, where a system key store is available, it deletes the master key there, so leftover files cannot be opened.
- **Same protocol everywhere.** The Android app, the Linux desktop app and the terminal clients for Termux and Linux all talk to each other.

### Try it

1. **Android:** install the APK from the [Releases page](https://github.com/muc111/OTRv4Plus/releases) and create an account on the default server. The first start takes a few minutes while it joins I2P.
2. **Linux desktop:** one line, see [Desktop app](#desktop-app-ubuntu-debian-qubes-os).
3. Add a friend, press **Verify** together, and chat, call or send a file.

### Run your own server

Prosody, an i2pd server tunnel in front of it, and the free [modules and limits script](prosody/): four steps in [docs/RUN_A_SERVER.md](docs/RUN_A_SERVER.md). One 2015 ThinkPad carried 1,600 users online ([stress test](docs/STRESS_TEST.md)). Then change the server on the app's sign-in screen, or pass `--server <address>.b32.i2p` to the terminal client.

**XMPP Guard (commercial, sold separately).** A real-time security dashboard and tripwire for the server, running entirely on the box at `127.0.0.1:7071`. It shows attacks, uptime and I2P health, hashes usernames, and alerts on file tampering, IP leaks and takeovers, with a hardening audit and sandboxing. It is not in this repository. Features: [docs/XMPP_GUARD.md](docs/XMPP_GUARD.md).

## Screenshots

| Desktop: a verified conversation | Desktop: an encrypted group |
|---|---|
| ![A verified conversation](desktop/docs/chat.jpg) | ![An encrypted group, its verification and members](desktop/docs/group.jpg) |

<p><img src="android/docs/android-1-chats.png" width="180" alt="Android: chats"> <img src="android/docs/android-2-chat.png" width="180" alt="Android: a verified conversation"> <img src="android/docs/android-3-group.png" width="180" alt="Android: an encrypted group"> <img src="android/docs/android-4-people.png" width="180" alt="Android: people"><br><sub>Android, left to right: chats, a verified conversation, an encrypted group, people. Both apps' screenshots are rendered by their tests from made-up accounts.</sub></p>

## Android app (experimental)

**Download:** open the
[Releases page](https://github.com/muc111/OTRv4Plus/releases). Only the
newest Android build is kept there, so the one you see is the one to test.

1. Under **Assets**, tap `otrv4plus-<commit>-release.apk` (the `-debug.apk`
   is for diagnostics); optionally check its `release sha256`.
2. Open it and allow installs when Android asks. If Android refuses an
   update, uninstall the old build first (builds use a CI signing key).

**No separate I2P app is needed.** The app has an I2P router built in
(i2pd, SAM bridge on loopback only, relaying nothing for others). It uses an
I2P app already running on the phone when one answers, and its own router
otherwise. The first
start takes a few minutes (it joins I2P), later ones a minute or two. Android 8+.

**What has been tested on a phone:** sign-in, contacts, 1:1 chat, rooms, OTRv4+ encryption, SMP identity verification, encrypted file transfer with a Termux peer, two-way voice calls (app to app, and app to Termux; a regression over the built-in router is fixed in rc.162, to be re-tested), group voice calls, end-to-end encrypted group chat (four accounts on two phones: two in the app, two in Termux, all sending and receiving), and account creation and login on an ordinary clearnet server (yax.im, over TLS with the certificate verified).
**Not yet tested on a phone:** the newest additions listed in [CHANGELOG.md](CHANGELOG.md). The step-by-step test list is [docs/ANDROID_CALL_AND_FILE_DEVICE_TEST.md](docs/ANDROID_CALL_AND_FILE_DEVICE_TEST.md).

## Project status

| Area | Status |
|---|---|
| Chat over I2P, TLS | Working, tested live between two peers |
| Chat over Tor | Implemented, not yet tested against a real hidden service |
| Hybrid PQC handshake, ratchet and SMP | Working, not externally reviewed |
| File transfer | Working (XMPP) |
| Voice over I2P | Working between two phones, in Termux and in the app; still being tuned |
| Android app | Chat, OTRv4+, SMP, files and calls (to the app and to Termux) tested on phones |
| Encrypted group chat (MLS) | Working: four clients (two Android, two Termux) on two phones send and read each other's messages, on the hybrid post-quantum suite. Group voice calls tested on phones (rc.89). Ordinary rooms (and the Welcome room) are plain XMPP rooms that the server can read. See [Encrypted group chat](#encrypted-group-chat-mls) |
| Security review | Extensive developer-led and AI-assisted review, fuzzing, and known-answer and cross-implementation testing; **no paid independent audit yet**. See below, [docs/CRYPTO_AUDIT_2026-09.md](docs/CRYPTO_AUDIT_2026-09.md) and [docs/SECURITY_AUDIT_2026-10-11.md](docs/SECURITY_AUDIT_2026-10-11.md) |

## Security assessment and audit status

OTRv4+ has had extensive developer-led security review and hardening: Rust unit and
integration tests, ML-KEM-1024 known-answer tests and a cross-check against Go's
`crypto/mlkem`, X448/Ed448 differential tests, cargo-fuzz on every Rust parser of
untrusted input, attack and property tests, Python and Kotlin suites, `cargo audit`
in CI, threat-model and Rust-authority reviews, AI-assisted review, and physical tests
on Android. Findings were fixed, each with a regression test.

It has **not** had a paid independent third-party audit or a formal external
cryptographic assessment, and that work is not equivalent to one. Known limitations:
[docs/SECURITY_ISSUES.md](docs/SECURITY_ISSUES.md) (A1 and A2 are addressed by protocol v2,
which both peers must run; 1:1 chats can publish the keys that authenticated their messages, a mechanism not yet independently reviewed: SPEC §5.8). The evidence, layer by layer: [SECURITY.md](SECURITY.md#security-assessment-and-audit-status); the latest claim-by-claim audit: [docs/AUDIT_CLAIM_MATRIX.md](docs/AUDIT_CLAIM_MATRIX.md).

## Cryptography

Hybrid classical + post-quantum cryptography: X448 with ML-KEM-1024 for key
agreement, Ed448 with ML-DSA-87 for authentication, keying established
AES-256-GCM for the message itself. Unlike the Ed448 ring signature, the
handshake's ML-DSA-87 signatures are attributable: taking part can be proven ([SPEC §10.1](docs/SPEC.md)).

What actually encrypts a message, top to bottom:

```
        X448  +  ML-KEM-1024              key agreement (DAKE)
  Ed448 ring signature  +  ML-DSA-87      authentication (ML-DSA-87 both ways)
                  |
                  v
      OTRv4+ double ratchet (v2)          fresh ML-KEM-1024 secrets folded into
      SHAKE-256 key schedule              the root key, from the first DH step
                  |
                  v
             AES-256-GCM
                  |
                  v
       encrypted OTR message
```

All of this runs in the Rust core (`otrv4_core`). Python handles networking
and Kotlin handles the Android screens; neither holds session keys. SMP
(identity verification) is also hybrid post-quantum and runs in Rust.

Details, design notes and caveats are in [docs/TECHNICAL.md](docs/TECHNICAL.md) and
[docs/SPEC.md](docs/SPEC.md).

## Encrypted group chat (MLS)

> **MLS+** — MLS (RFC 9420) on a hybrid post-quantum ciphersuite (`0xF0A1`, X448 + ML-KEM-1024 / Ed448 + ML-DSA-87). Not interoperable with standard MLS.

Secure groups use **MLS+** through OpenMLS, with every primitive from the same Rust core: hybrid KEM **X448 + ML-KEM-1024**, composite signature **Ed448 + ML-DSA-87** (both must verify), AES-256-GCM, HKDF-SHA-384 (ciphersuite 0xF0A1). Standard MLS suites have no post-quantum protection; these groups resist "record now, decrypt later". The XMPP room carries only `?OTRv4MLS1:` ciphertext. Invitations and Welcomes travel inside 1:1 OTRv4+ sessions; keys move on at every membership change and on a timer; a removed member reads nothing after the removal; messages typed while a group resyncs wait instead of being lost. The server still sees the room, its members and message timing. 0xF0A1 is in the IANA private-use range (0xF000–0xFFFF), which is the correct place for a suite that isn't registered; the hybrid constructions are this project's own, not independently audited. Details: [docs/TECHNICAL.md](docs/TECHNICAL.md#encrypted-group-chat-mls), [docs/MLS_SECURITY_HARDENING.md](docs/MLS_SECURITY_HARDENING.md).

**Known limits**
- **MLS+ is not standard MLS.** Groups use an unregistered ciphersuite (`0xF0A1`, in the IANA private-use range) and cannot be joined by Wire, Element, or any other RFC 9420 implementation.
- **About 100 members per group.** A Welcome carries the whole ratchet tree (~9.4 KB per member) and the core refuses MLS+ messages over 1 MiB, so joins stop near 100 members ([docs/STRESS_TEST.md](docs/STRESS_TEST.md)).

## Quick start

**Pick a branch; every command below names one.** Both ends of a conversation need the same one.

| Branch | What it is |
|---|---|
| `dev` | Newest. The Android test APK on the Releases page is built from it. |
| `main` | Stable: `dev` once tested on devices, merged now and then, so it can be behind. Has protocol v2 since 2026-10-25; a `main` clone older than that is refused by the current APK. |

`git pull` stays on your branch. Switch a clone: `git fetch origin dev && git checkout dev` (or `git checkout main`), then build again.

### Desktop app (Ubuntu, Debian, Qubes OS)

Built from source on your machine. **Ubuntu 24.04+ / Debian 13+**, one line (re-run to update):

```bash
# dev (matches the current APK):
sudo apt install -y git && git clone -b dev https://github.com/muc111/OTRv4Plus.git ~/OTRv4Plus && bash ~/OTRv4Plus/desktop/install.sh
# main (stable):
sudo apt install -y git && git clone -b main https://github.com/muc111/OTRv4Plus.git ~/OTRv4Plus && bash ~/OTRv4Plus/desktop/install.sh
```
- **Run it:** your applications menu → **OTRv4+**, or `otrv4plus-desktop` in a terminal (in `~/.local/bin`; log out and in once if the command is not found). The installer starts it the first time; the window title shows the desktop version.
- **Update:** **Desktop needs only `desktop/install.sh`.** Run it again: it pulls (no separate `git pull`), installs apt packages and Rust if missing, runs `Rust/build.sh` for you and refreshes the menu entry. `Rust/build.sh` alone builds only the core for the terminal clients below. Details: [desktop/README.md](desktop/README.md#install-on-ubuntu-or-debian). Qubes OS 4.2: [qubes/README.md](qubes/README.md).

### Termux, Ubuntu and other Linux (terminal clients)

**1. Install the tools.** Python 3.12 or newer is required.

On **Termux**: `pkg install python rust openssl clang git`

On **Ubuntu 24.04+ / Debian 13+** (Rust from rustup; the distribution's rustc is too old):

```bash
sudo apt install git python3 python3-venv build-essential curl libopus0 pulseaudio-utils
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
. "$HOME/.cargo/env"     # puts Rust on this terminal's PATH (new terminals have it)
```

Do not `pip install` anything: `build.sh` uses the project's own `.venv`. For calls on Termux: `pkg install libopus termux-api`.

**2. Download and build the Rust core** (slower the first time on a phone):

```bash
git clone -b dev https://github.com/muc111/OTRv4Plus.git    # or -b main (see Pick a branch)
cd OTRv4Plus/Rust
bash build.sh
cd ..
```

It ends with `BUILD OK`; keep Termux open while it runs ([details](docs/TECHNICAL.md#buildsh-in-detail)).

**3. Update later:** `git pull`, then `cd Rust && bash build.sh` again. Keys and settings live in `~/.otrv4plus` and survive updates.

**4. Networks.** I2P: a router with SAM on port 7656 (the I2P app with "Use SAM bridge" on, or `sudo apt install i2pd`). Tor: Orbot or `tor`, SOCKS on 9050.

**5. Run it.**

XMPP over I2P (chat, files and voice):

```bash
PYTHONMALLOC=malloc .venv/bin/python otrv4plus_xmpp.py \
  --jid you@yourserver.i2p --peer friend@yourserver.i2p
```
Add `--server <address>.b32.i2p` if the server name does not resolve; `--voice-debug` for call stats.

IRC (defaults to `irc.postman.i2p` over I2P; `-s irc.libera.chat` for TLS):
`PYTHONMALLOC=malloc .venv/bin/python otrv4+.py`

**6. First commands** (XMPP; IRC uses the same `/otr` and `/smp`):

```
/otr              start an encrypted session
/smp              verify identity with a passphrase agreed in person
/call             encrypted voice call (after SMP); /answer, /hangup
/sendfile <path>  encrypted file (after SMP; asks y/n to strip metadata)
/status           session, trust and verification state
/help             every command
```

Encrypted group chat (XMPP): `/group create mls3`, `/group invite mls3 bob`,
`y` to join, then just type; the creator's `/group verify mls3` sets the
passphrase and checks every member, then `/group call mls3` or `/sendfile`.
App: Rooms, "Create encrypted group"; the creator presses Verify group in its chat.
Building on musl (Alpine), every option and all commands: [docs/TECHNICAL.md](docs/TECHNICAL.md).

## Documentation

[docs/TECHNICAL.md](docs/TECHNICAL.md) (full reference) · [docs/SPEC.md](docs/SPEC.md) (wire protocol) · [SECURITY.md](SECURITY.md) (threat model, known issues) · [CHANGELOG.md](CHANGELOG.md) · [docs/MLS_SECURITY_HARDENING.md](docs/MLS_SECURITY_HARDENING.md) (group chat design) · [docs/OTRV4PLUS_CAPABILITY.md](docs/OTRV4PLUS_CAPABILITY.md) (who can receive OTRv4+) · [docs/PROSODY_USER_DISCOVERY.md](docs/PROSODY_USER_DISCOVERY.md) (People list, Welcome room) · [CONTRIBUTING.md](CONTRIBUTING.md) · [all documents](docs/README.md)

Running a server: [docs/STRESS_TEST.md](docs/STRESS_TEST.md) · [docs/SERVER_HARDENING.md](docs/SERVER_HARDENING.md) (limits, one-command install) · [docs/XMPP_GUARD.md](docs/XMPP_GUARD.md) (commercial security dashboard) · [docs/SECURITY_SESSIONS.md](docs/SECURITY_SESSIONS.md) (one session per account)

**Relationship to OTR.** OTRv4+ is an independent implementation and extension of
OTRv4, not affiliated with, endorsed by, or connected to the original OTR
developers or otr.cypherpunks.ca, and uses none of their code, artwork or
logos. It is not wire-compatible with stock OTRv4 ([SPEC §0](docs/SPEC.md)).

## License

OTRv4+ is dual-licensed: `AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial`.

- [AGPL-3.0](LICENSE) is the default. You may use, change and share it; if you
  distribute it or run a modified version as a network service, you must
  offer your source.
- A [commercial licence](LICENSE-COMMERCIAL.md) is available for closed-source
  use.

Releases up to and including v10.16.2 were published under GPL-3.0, and
anyone who received them keeps those GPL-3.0 rights permanently. The move to
AGPL-3.0 applies from v10.17.0 onward. It does not, and could not, take back
rights already granted.

Documentation is licensed under [CC BY-SA 4.0](LICENSES/CC-BY-SA-4.0.txt).
Third-party attributions are in [NOTICE](NOTICE), which must be included with
any binary you distribute. [LICENSING.md](LICENSING.md) has the full picture.
