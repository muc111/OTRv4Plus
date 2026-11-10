# Run your own OTRv4+ server

An OTRv4+ server is an ordinary Prosody XMPP server with i2pd in front of it.
The app's default, `otrv4plus.i2p`, is a public test server; pointing the
clients at your own takes one field.

The reference server (the T450) runs Prosody built from source; a packaged Prosody and the tunnel below are the standard setup but have not been tried on it.

If you have run Prosody before, this is the familiar setup with i2pd in front:

1. **Prosody:** install it as usual (`sudo apt install prosody`, or from source), with a VirtualHost for your server name.
2. **An i2pd server tunnel** to Prosody's client port, in `/etc/i2pd/tunnels.conf`:
   ```ini
   [xmpp]
   type = server
   host = 127.0.0.1
   port = 5222
   keys = xmpp.dat
   i2p.streaming.maxConnsPerMinute = 10
   ```
   Restart i2pd. Its web console (Server tunnels) shows the new `.b32.i2p` address: that is your server.
3. **Limits and modules (recommended):** `cd ~/OTRv4Plus && sudo bash prosody/install-server-limits.sh` installs the three modules and the limits, checks the config, and restores the backup if the check fails. It was written and measured on Prosody built from source in `/usr/local`; for a packaged Prosody, set `PROSODYCTL` if needed. Details: [SERVER_HARDENING.md](SERVER_HARDENING.md).
4. **Point the clients at it:** in the app, change the server on the sign-in screen; in the terminal client, `--jid you@yourserver --server <address>.b32.i2p`.

Optional: the People list and Welcome room need [PROSODY_USER_DISCOVERY.md](PROSODY_USER_DISCOVERY.md).

## Why host it yourself, and where

**What a big provider has to do, and you may not.** A company running a
messenger for the public holds many people's data in one place. That makes
it the obvious place to serve legal demands, and at its scale it may be
designated under surveillance or online-safety laws, with compliance teams to
match. A server you run for yourself and people you know holds far less, and
is a much smaller target.

**What your server can and cannot see.**
- Messages, group chats, files and calls are end-to-end encrypted: the
  server relays them and cannot read them.
- Over I2P it never learns anyone's IP address.
- What it does hold:
  - account names and contact lists;
  - who is in which room, and when someone is online;
  - offline messages, still encrypted, until they are delivered.
- Keep that small: archive only what you need, and keep no logs you do not
  read.

**Running a server does not put you outside the law.** Three places' laws
can reach it:
- the country the machine is in;
- the country you live in;
- the hosting company's country. A provider can be served directly, and can
  hand over or image the machine without asking you.

I2P hides the server from its users, not from whoever hosts it. Hosting at
home, or with a provider in a country you chose on purpose, is a real
decision.

**Some differences between countries.** This is general information that
changes over time, **not legal advice**; check the current law for your
case.
- **Personal use is treated differently.** Data-protection law (the GDPR in
  the EU and similar laws elsewhere) generally does not apply to purely
  personal or household use. Hosting accounts for other people, or for the
  public, usually brings duties: security, deletion on request, and
  breach handling.
- **Switzerland.**
  - Data protection: the revised Federal Act on Data Protection (2023).
  - Surveillance law (BÜPF/LSCPT) puts its heaviest duties on telecom
    providers, and lighter ones on providers of "derived communication
    services".
  - A 2025 government proposal to extend those duties to more online
    services drew public objections from privacy services; check where it
    stands.
- **United Kingdom.**
  - The Investigatory Powers Act 2016 (amended 2024) allows notices that
    require a provider to help with interception and, in some cases, to
    change its service, with secrecy obligations.
  - The Online Safety Act 2023 gives Ofcom powers over user-to-user
    services.
- **Ireland (EU).**
  - The GDPR applies to personal data you handle for others.
  - Irish data-retention law (amended in 2022 after EU court rulings)
    targets providers of electronic communications services.
  - EU proposals to require scanning of private messages have been debated
    for several years.

Whatever the country, end-to-end encryption means what is not on the
server cannot be handed over: no message, call or file can be read from it.

## Capacity

On one 2015 ThinkPad T450 running Prosody, measured with the built-in stress
test (encrypted groups of 20, each user sending a message a minute, local
connections; I2P not yet measured): 800 users online used 37% of one core and
303 MB, delivery 0.31 s typical and 0.56 s for the slowest 5%, ~100%
delivered; **1,600 users** used about 40% (p95 0.5 s). The server is capped at
1,600 online, 10 sign-ins a second and 5,000 accounts. Method and raw
results: [STRESS_TEST.md](STRESS_TEST.md); limits:
[SERVER_HARDENING.md](SERVER_HARDENING.md).

## Monitoring

[XMPP Guard](XMPP_GUARD.md), sold separately, is a security dashboard and
tripwire for exactly this setup. The modules above work without it.
