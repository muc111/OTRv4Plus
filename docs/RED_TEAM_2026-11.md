<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright (C) 2025-2026 muc111 -->

# Red-team pass, 2026-11-14

The audit before this one ([AUDIT_2026-11.md](AUDIT_2026-11.md)) asked "is
the code correct?". This one asks what an attacker would actually do: someone
who wants to read messages, find who is talking, find the server, or get onto
a phone, and who does not care about the cryptography if there is a way
round it. It describes the code at `rc.204`.

Like every audit here it is the developer's, AI-assisted, and not an
independent one.

## What this pass could and could not do

It read source: this repository, slixmpp 1.17.0 (the XMPP library the apps
ship), and Prosody 0.12.4 and 13.0.7. Where it claims a weakness, the
weakness was reproduced first and there is a test.

It did **not** find unknown holes in Prosody, Lua, OpenSSL, i2pd, expat or
Android by examining their binaries, and nothing here should be read as
saying they have none. Finding those takes fuzzing and reverse engineering
against the built targets, for weeks, by people who do only that. What a
project like this can do about unknown holes is the rest of this page: make
the server hard to find, make each parser an outsider can reach smaller, and
make a successful break-in yield as little as possible.

**A phone that is itself compromised is outside what any app can defend.**
Commercial spyware of the Graphite and Pegasus kind takes over the operating
system, then reads the screen, the keyboard and the app's memory. End-to-end
encryption ends at the screen. What reduces that risk is on the phone, not in
this app: a current, supported device with updates installed; Lockdown Mode
(iOS) or Advanced Protection (Android 16); restarting the phone regularly,
since many such implants do not survive a restart; and not opening links or
files from strangers in any app. What this app contributes is small attack surface
of its own (below), and no cloud backup of anything.

## Found and fixed

| | Attack | Who can do it | Fixed by |
|---|---|---|---|
| R1 | Reach the XML parser's DTD and entity code | The server; on clearnet, anyone on the path before TLS is up | `android_bridge/xmlguard.py` |
| R2 | Be accepted as the server without proving knowledge of the account | Whoever the app connects to | `android_bridge/sasl_hardening.py` |
| R3 | Freeze the app, or weaken the login proof, by naming the iteration count | Whoever the app connects to | same |
| R4 | (hardening) login nonce from a non-cryptographic generator | n/a | same |
| R5 | Reach any native image codec on the phone at sign-up | A server the user tries to register on | `android_bridge/captcha.py` |
| R6 | Find a hidden server's real address | Anyone on the internet; any account on the server | `HIDDEN_SERVICE=1`, docs |
| R7 | Attach to the app's I2P session from another program on the device | Any local program | `client/otrv4+.py` |
| R8 | Sign-in times written to the server log by our own module | Whoever later reads the server's disk | `prosody/mod_otrv4plus_one_session.lua` |

### R1. A DTD in the XMPP stream reached expat

slixmpp passes every byte from the socket to expat. Expat accepts a
`<!DOCTYPE ...>` at the start of a stream and expands the entities it
declares (a test keeps this as a fact: `test_expat_would_have_expanded_the_
entity`). XMPP forbids DTDs (RFC 6120 §11.1), but slixmpp does not refuse
them. A stream starts three times per sign-in (connect, after STARTTLS, after
login), and the first is before any encryption on a clearnet route, so the
party able to do this is not only the server.

Why it matters: expat's DTD and entity handling is where most of its
memory-safety and recursion advisories have been (for example CVE-2024-8176,
a stack overflow through nested entities, fixed in expat 2.7.0). Which expat
a phone carries was not visible; the diagnostic report now prints it.

Fix: a guard reads the bytes before the parser does. `<!` must open a comment
or a CDATA section; anything else, or a NUL byte (which is how UTF-16 and
UTF-32 would have hidden the markup), closes the connection before the
deciding byte is passed on. It also cuts off a single stanza that grows past
16 MiB. Tested at every possible split between network reads. Both the apps'
client and the terminal client are built on it.

### R2. "Signed in" without the server's proof (slixmpp 1.17.0)

In SCRAM the server ends by sending a signature only the holder of the
account's stored keys can make. slixmpp checked it in the last step, but
chose the step by counting: a server that answered the client's *first*
message with `<success/>`, carrying text shaped like a challenge, was run
through the challenge step, which raises nothing, and the session was marked
authenticated. Reproduced against the unmodified library.

What it was worth to an attacker: over I2P and Tor the certificate is not
checked, so this signature is the only cryptographic evidence, beyond the
address itself, that the far end is the real server. A fake server at a wrong
or substituted address could hold a client "signed in" and feed it a roster
and presence. It could not read or forge messages (those are end-to-end, and
a changed contact key is flagged), and the address pinning in
[SECURITY_ISSUES.md](SECURITY_ISSUES.md) is a separate defence.

Fix: `<success/>` is honoured only after the challenge step and only once
the signature has verified; otherwise the connection is closed and the user
is told the server did not prove itself (`server_not_proven`, not retried).
Worth reporting upstream to slixmpp; the three SCRAM items here are in their
code, not ours.

Limit that remains: SCRAM without channel binding can be relayed by a party
sitting between the app and the real server. Python cannot do the TLS 1.3
binding (`tls-exporter`). The defence against that party is the I2P or onion
address, which is itself a key.

### R3. The server chose the cost of the login

The server names the PBKDF2 iteration count and slixmpp ran any value, in a
Python loop, on the thread that runs everything else. A count of 1 makes the
proof the client sends cheap to brute-force offline by whoever received it;
a count in the billions stops the app until it is killed. Counts outside
4,096 to 2,000,000 now end the connection, and the work is done by
`hashlib.pbkdf2_hmac` (identical output, tested against RFC 5802's vector),
so a legitimately high count costs a fraction of a second instead of
seconds.

### R4. Nonce

The client nonce came from `random.random()`. It now comes from the system
CSPRNG. No practical attack was built on it.

### R5. Any image codec, at sign-up

The sign-up CAPTCHA is the one image the phone's native decoder is given
from a server the user has not yet trusted. The code checked the *declared*
type against a list, but Android's decoder ignores declarations and picks a
codec from the data. A server could call a WebP, HEIF, BMP, ICO or camera-raw
file "image/png" and reach that codec. Those codecs are where image-borne
exploits have lived (the 2023 WebP hole, CVE-2023-4863, found in use
against iPhones, is the known example).

Fix: the first bytes decide. Only PNG, JPEG and GIF pass, whatever the
server calls them, and the type passed on is the one found. Avatars were
already safe by design: they never touch a native decoder
(`android_bridge/avatar.py`).

### R6. A hidden server that was not hidden

The most serious finding, and it is in the instructions rather than the
code. [RUN_A_SERVER.md](RUN_A_SERVER.md) said to install Prosody and put an
i2pd tunnel in front. As installed, Prosody:

- listens on every network address, so a scan of the internet finds a
  machine that answers for the hidden name and presents its certificate;
- federates, so one message from any account to a domain the sender owns
  makes the server connect there from its real address.

Either one turns "find the server" from hard into trivial, and finding the
server is the first step of every attack on it. Fixed by a `HIDDEN_SERVICE=1`
mode in `prosody/install-server-limits.sh` (loopback only, federation off, no
OS name), a warning on every run if either is open, and a must-do step in the
guide with the command that checks it. [SERVER_HARDENING.md](SERVER_HARDENING.md)
also now lists what a break-in or a seizure would find on the disk and the
line that removes each item.

**Whether the project's own server was exposed is not something this pass
could see.** Two commands answer it; they are in "For the server's operator"
below.

### R7. The I2P session name

The built-in router accepts SAM commands from any program on the device
(SAM has no login; the port is random and loopback-only, and nothing else is
open). The session name is what stops another program attaching to our
session. It carried 32 random bits, few enough for a program that keeps
trying. It carries 128 now.

### R8. Names in the server log

`mod_otrv4plus_one_session` wrote the full address each time an account
signed in again. It no longer does.

## Tried, and held

**Reading messages.** Nothing found. The server and the network see
ciphertext. No path was found that sends a 1:1 message unencrypted (it is
queued instead), accepts a downgrade to the classical handshake, or accepts a
changed contact key without saying so.

**The server forging messages into a chat.** Carbons and archive results are
accepted only from the user's own account; a roster push only from the
account or the server; none of them carries anything the encryption layer
would treat as authentic.

**Taking the password off the wire.** Over I2P and Tor only SCRAM is
allowed, so the password itself is never sent. On clearnet the certificate
is verified, and removing STARTTLS makes the connection fail, not fall back.

**A stranger crashing or stalling the app.** First-contact handshakes are
rate-limited per sender and capped in number; fragments, files, voice notes
and group messages are bounded in size and count; a stanza is now bounded
too (R1).

**Other apps on the phone.** One exported activity; no exported service,
receiver or provider; the screen is not capturable; nothing is in Android's
backup. A program on the same phone can still reach the router's SAM port
and use the router for its own traffic; it cannot read ours.

**Opening things.** No link in a message is turned into something tappable,
and nothing is fetched to preview it. A location opens in another app only
after a warning. A received file is shown inside the app, by what its first
bytes say it is, and leaves the app only through "Open with another app".

**The server modules.** The moderation commands are offered to admins only
and checked by Prosody, not by the module; a ban closes live sessions and
cannot be resumed past.

## Known and not fixed

These are properties of the design or of XMPP. They are listed so nobody
assumes otherwise.

1. **The server sees who talks to whom, and when.** It routes the messages.
   It also sees approximate sizes (padding is random, not to fixed sizes) and
   so can tell a call or a file from a text. Self-hosting for people you
   trust is the mitigation; I2P hides *where* everyone is, not the social
   graph, from the server.
2. **A watcher of both ends of an I2P connection can correlate timing.**
   True of every low-latency anonymity network.
3. **One client can exhaust the server's sign-in allowance.** The limits are
   server-wide because I2P hides clients from Prosody
   ([SERVER_HARDENING.md](SERVER_HARDENING.md), "What these limits do not
   stop").
4. **A server answers whether an account name exists.**
5. **The server can withhold or delay messages.** It cannot alter them
   unnoticed.
6. **A seized, unlocked phone shows everything on it.** The app lock and
   wipe exist for the locked case.
7. **A picture you open from a contact is decoded by the phone's own
   codec, inside the app.** It takes an accepted file and a tap, from someone
   whose key you hold, but a contact's phone can be compromised too. PDFs are
   already rendered in an isolated process; images (JPEG, PNG, GIF, WebP) are
   not yet.
8. **Builds are signed with a test key** until the release key is set up
   (AUDIT_2026-11.md, O1), so an update cannot yet be verified as coming from
   the same signer.

## For the server's operator

In order of importance. The first two take one minute.

1. **Is Prosody reachable from outside?** On the server:
   `sudo ss -ltnp | grep -E 'lua|prosody'`. Every line should begin
   `127.0.0.1` or `[::1]`. Anything else: run the install script with
   `HIDDEN_SERVICE=1`.
2. **Is federation off?** `grep -n -A6 modules_disabled` on the config
   should show `"s2s"`. If not, same command.
3. **If either was open,** assume the address may have been recorded.
   Scanners keep history. Moving the service to a new address is the only
   way to be sure; whether that is worth it is the operator's call.
4. Firewall, log level, `account_activity`, `cloud_notify`, a separate admin
   account: [SERVER_HARDENING.md](SERVER_HARDENING.md).
5. Do not change `password_hash` on a server with accounts; it locks
   everyone out.
6. Keep Prosody, i2pd and OpenSSL updated. A build from source is updated
   only when rebuilt.

## What would add real assurance next

- Decoding received pictures in the isolated process the PDF viewer uses
  (item 7 above).
- Fuzzing the stanza handlers and the bridge's parsers in CI, as the Rust
  core already is.
- An independent review of `xmlguard` and `sasl_hardening`, which now stand
  between the network and two parsers.
- Reproducible builds, so the published APK can be checked against the
  source.
- An independent audit. Still the largest gap.
