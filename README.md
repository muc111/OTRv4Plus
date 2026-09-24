<p align="center">
  <img src="icon.png" width="160" alt="OTRv4+">
</p>

<h1 align="center">OTRv4+</h1>

<p align="center"><strong>Private messaging and voice over I2P</strong></p>

<p align="center">
<code>v10.30.0 · Rust crypto core · chat (X448 + ML-KEM-1024, AES-256-GCM) · hybrid PQC SMP (ML-KEM-1024 + ML-DSA-87 + ZKP) · voice (X448 + ML-KEM-1024, AES-256-GCM) · I2P SAM · AAudio · TUI</code>
</p>

OTRv4+ is an open-source client for end-to-end encrypted chat, file transfer
and voice calls. It is built around the I2P network and needs no phone number.
Tor and TLS also work for chat.

It is an experimental, single-author project with no external security
review. Do not rely on it where your safety depends on it.

## Android app (experimental)

**Download:** open the
[Releases page](https://github.com/muc111/OTRv4Plus/releases). Only the
newest Android build is kept there, so the one you see is the one to test.

1. Under **Assets**, tap `otrv4plus-<commit>-release.apk`. That is the one to
   install. The `-debug.apk` is only needed for diagnostics.
2. Optional: check the file against the `release sha256` value in the
   release notes.
3. Open the downloaded file and allow installs from your browser or file
   manager when Android asks.
4. If an older build is installed and Android refuses the update, uninstall
   the old one first. Builds are signed with a CI key, not a release key.

**Before you sign in** you need an I2P router on the phone with the SAM
bridge turned on (for example the I2P app from F-Droid or Google Play, with
"Use SAM bridge" enabled in its settings). The first connection can take one
to two minutes while I2P builds its tunnels.

Works on Android 8.0 and newer, including the Pixel 7.

**What has been tested on a phone:** sign-in, contacts, 1:1 chat, rooms,
OTRv4+ encryption, SMP identity verification, encrypted file transfer with a
Termux peer, and two-way voice calls between two phones running the app.
**Not yet tested on a phone:** a call between the app and Termux, and the
newest additions listed in [CHANGELOG.md](CHANGELOG.md). The step-by-step test list
is [ANDROID_CALL_AND_FILE_DEVICE_TEST.md](ANDROID_CALL_AND_FILE_DEVICE_TEST.md).

## Project status

| Area | Status |
|---|---|
| Chat over I2P, TLS | Working, tested live between two peers |
| Chat over Tor | Implemented, not yet tested against a real hidden service |
| Hybrid PQC handshake, ratchet and SMP | Working, not externally reviewed |
| File transfer | Working (XMPP) |
| Voice over I2P | Working between two phones, in Termux and in the app; still being tuned |
| Android app | Chat, OTRv4+, SMP, files and app-to-app calls tested on phones |
| Group encryption | Not implemented. Rooms are ordinary XMPP rooms that the server can read. See [MLS_FEASIBILITY.md](MLS_FEASIBILITY.md) |
| External security review | None |

## Cryptography

Hybrid classical + post-quantum cryptography: X448 with ML-KEM-1024 for key
agreement, Ed448 with ML-DSA-87 for authentication, keying established
AES-256-GCM for the message itself. OTR's Ed448 ring-signature deniability is
kept.

What actually encrypts a message, top to bottom:

```
        X448  +  ML-KEM-1024              key agreement (DAKE)
  Ed448 ring signature  +  ML-DSA-87      authentication: deniable, then hybrid PQ
                  |
                  v
      OTRv4+ double ratchet               a fresh ML-KEM-1024 exchange at
      SHAKE-256 key schedule              EVERY DH ratchet step, not just once
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

Details, design notes and caveats are in [TECHNICAL.md](TECHNICAL.md) and
[SPEC.md](SPEC.md).

## Quick start (Termux)

Termux on Android is the reference client.

```bash
pkg install python rust openssl clang git
git clone https://github.com/muc111/OTRv4Plus.git
cd OTRv4Plus/Rust
cargo build --release --features extension-module,pq-rust
cp target/release/libotrv4_core.so ../otrv4_core.so
cd ..
PYTHONMALLOC=malloc python otrv4+.py --debug
```

Python 3.12 or newer is required. For I2P, run an I2P router with the SAM
bridge on port 7656. For voice, also run `pkg install libopus termux-api` and
`pip install opuslib`. The XMPP client, voice calls, musl builds and every
command are covered in [TECHNICAL.md](TECHNICAL.md).

## Documentation

- [TECHNICAL.md](TECHNICAL.md): the full technical reference
- [SPEC.md](SPEC.md): wire-level protocol specification
- [SECURITY.md](SECURITY.md): threat model and known issues
- [CHANGELOG.md](CHANGELOG.md): what changed in each version
- [OTRV4PLUS_CAPABILITY.md](OTRV4PLUS_CAPABILITY.md): how the app decides who can receive OTRv4+
- [PROSODY_USER_DISCOVERY.md](PROSODY_USER_DISCOVERY.md): the People list and the Welcome room
- [CONTRIBUTING.md](CONTRIBUTING.md): how to contribute

## License

OTRv4+ is dual-licensed:

```
AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
```

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
