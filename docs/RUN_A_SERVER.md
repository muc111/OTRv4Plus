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
