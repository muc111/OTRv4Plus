# XMPP Guard: a security dashboard for your OTRv4+ server

XMPP Guard is the commercial server companion to OTRv4+: a real-time
security dashboard and tripwire for a Prosody XMPP server published over
I2P with i2pd. **It is not part of this repository and not distributed
from it.** The messenger, the Prosody modules in [`prosody/`](../prosody)
and everything else here stay free and open source (AGPL-3.0, or the
commercial licence in [LICENSING.md](../LICENSING.md)).

This page describes **XMPP Guard 3.1.2**. Anything marked *Planned* is not
in it yet.

## Design

- **Four services plus maintenance mode.** The dashboard, the event
  collector (`mod_xmppguard` over local UDP), the sentinel, and the health
  checker run together; maintenance mode suspends the sentinel's alerting
  while you make changes, and switches itself back on after
  `maintenance_minutes`.
- **Fully offline.** Python standard library only. It makes no outside
  requests, and nothing it serves leaves the machine: the dashboard is on
  `127.0.0.1:7071`.
- **Read-only towards Prosody and i2pd.** It never changes their
  configuration. The only thing it writes is its own maintenance flag.
- **Works with Prosody logging off.** `mod_xmppguard` sends events over
  local UDP (`127.0.0.1:5299`), authenticated with a shared secret. If the
  dashboard is down, events are dropped, never written to disk.
- **Private by default.**
  - Usernames arrive as keyed HMAC-SHA256 hashes (`user·xxxxxx`).
  - Message content and contacts are never seen.
  - Three storage modes: `alerts` (the default: warnings, without device
    addresses), `all`, or `none`.
- **Per-device without logs.** It ties events to individual I2P clients
  through the per-destination `127.x.y.z` addresses that i2pd's
  `enableuniquelocal` gives each one.
- **A dashboard that works anywhere.** Live updates (server-sent events),
  charts, dark, light or automatic theme, 5-minute, 15-minute and 1-hour
  windows, and it fits a phone screen.
- **Optional dashboard login** (`[dashboard]` user and password).
- Endpoints: `/`, `/api/state`, `/api/stream`, `/api/alerts` (export),
  `/healthz`.

## Attack detection

Thresholds are set in `config.ini`.

- **Brute force**, per device and spread across many devices.
- **Probing:** connections that never try to log in, per device and
  distributed.
- **Connection floods**, server-wide (5% of the user cap per minute) and per
  client.
- **Too many concurrent connections** (90% of the online cap).
- **Slow-connection attacks:** unauthenticated connections held open for
  more than 90 seconds.
- **Account farming and mass registration.** It also alerts on registration
  attempts while sign-up is closed, and raises a critical alert if an
  account actually gets created then.
- **Capacity:** 90% of the account or online cap, and every refused sign-in
  or sign-up, including refusals from `mod_otrv4plus_capacity`.
- **Unknown devices:** an optional `[clients]` allowlist with one-click
  "allow". New-device alerts exist but are off by default, because I2P apps
  use a fresh destination each session.
- **Spoofed events** sent with the wrong secret.
- **Anomalies:** traffic spikes, Prosody memory growth, and federation (s2s)
  activity on an I2P-only server.

## Compromise tripwires

The sentinel checks every 3 seconds.

- **Egress leak:** Prosody opening any connection that is not to localhost,
  which could reveal the server's real IP address.
- **Takeover:** Prosody or i2pd starting a shell or an interpreter.
- **File integrity:**
  - a SHA-256 baseline of the Prosody and i2pd binaries, modules, configs
    and i2pd tunnel files;
  - a new or changed module or binary is **critical**, and a config edit is
    **serious**;
  - tunnel files that briefly disappear during an i2pd restart do not raise
    a false alarm.
- **New network listeners.** i2pd's own router port is allowed; any other
  new port alerts.
- **Maintenance mode.** While it is on, your own changes silently become the
  new baseline. It switches itself off after `maintenance_minutes`. It can be
  turned on from the dashboard, and the repository's
  `prosody/install-server-limits.sh` turns it on before it touches Prosody.
- **Clock check** (NTP or chrony).

## Service health

Kept separate from the threat level, so an outage is never mistaken for an
attack, or the other way round.

- Prosody down or restarted, the XMPP port closed, i2pd down or restarted.
- XMPP unreachable: no working inbound tunnels for 2 minutes.
- Duplicate Prosody or i2pd instances running.

## Hardening audit

Checked live against your actual configuration. Every failing item shows
the exact config line to fix it, with a copy button.

- **Prosody:**
  - listening on loopback only, federation off, TLS, password hashing;
  - the registration throttle and account cap, the online cap, and whether a
    loaded module actually enforces each cap;
  - stanza size limit, web endpoints, connection logging, message archive
    retention.
- **i2pd:**
  - tunnel length and quantity, and connections per minute per client;
  - maximum simultaneous connections against your user cap;
  - floodfill mode, router reachability, and HTTP or SOCKS proxies running
    on the server's own router.
- **Anonymity:**
  - version and OS cloaking, clock readout cloaking, Prosody running as
    root;
  - the egress lock, and the Prosody and i2pd sandboxes, each scored out of
    5.

## Active defences (bundled)

- **`mod_cloak`** hides or fakes the software name and version, the OS (a
  decoy "ejabberd"), the server clock (hidden, or rounded to the minute) and
  uptime.
- **`mod_user_limits`:** `max_registered_users` and `max_online_users`.
- **`harden.sh`** installs systemd drop-ins with automatic rollback, and has
  `--show` and `--undo`:
  - **Prosody:** a kernel egress lock to localhost only, plus the full
    sandbox.
  - **The sandbox (Prosody and i2pd):** read-only filesystem, no new
    privileges, no writable-and-executable memory, the `@system-service`
    system calls only (native architecture), and restricted socket types.
    It also hides home folders, devices and kernel tunables, and drops
    capabilities when the service runs as a non-root user.
  - **i2pd:** its writable paths are found automatically. If i2pd fails
    under the sandbox, the script prints why before rolling back.

## Router and host views

- Inbound and outbound tunnels for the XMPP destination with round-trip
  times, router bandwidth, status and caps, tunnel build success, and known
  routers.
- A connected-now table and a device history.
- A `prosody.err` viewer with filters.
- CPU and memory charts for the host, Prosody and i2pd.

## Measured cost

On the ThinkPad T450 stress-test server, XMPP Guard used about 4–6% of one
CPU core during the 1,200-user run, and was ruled out as the cause of the
1,990-user overload ([STRESS_TEST.md](STRESS_TEST.md)).

## Works with the free OTRv4+ server modules

These are in this repository, free, and do not need XMPP Guard:

- **`mod_otrv4plus_capacity`:** the online cap (1,600, as measured on the
  T450); login pacing (10 a second, burst 40), refused cheaply before TLS;
  30 registrations an hour server-wide; 5,000 accounts in total. XMPP Guard
  shows its refusals as "At capacity".
- **`mod_otrv4plus_moderation`:** admin-only commands to ban permanently,
  lift a ban, check a ban, list every room (hidden ones included) and
  destroy any room. Bans survive restarts.
- **`mod_otrv4plus_one_session`:** one session per account, and the newest
  sign-in wins, so a stale I2P session, or someone with a stolen password,
  cannot lock the owner out.
- **`prosody/install-server-limits.sh`:** installs the three modules and the
  limits, backs up the config, and rolls back if `prosodyctl check config`
  fails. Running it twice changes nothing.

See [SERVER_HARDENING.md](SERVER_HARDENING.md).

## Planned

Not in 3.1.2:

- Signed, reproducible releases.
- Encrypted config backups with one-click restore from the dashboard.
- A second login factor for the dashboard (hardware key or TOTP).
- A tamper-evident, hash-chained alert log, so an intruder cannot quietly
  edit or delete the record of what they did.
- Signed evidence export: a snapshot of the triggering events, the file
  hashes that changed and their timestamps, signed by the server, for an
  operator to keep or hand to a lawyer or law enforcement. Evidence to
  attribute an attack through lawful channels, never a payload that reaches
  back to the attacker.
- Private alert delivery: an end-to-end encrypted XMPP message to an admin
  account, with no outside push service.
- Decoy accounts and rooms that look real and alert the moment they are
  touched, and connection tarpits that cost an attacker time without
  reaching their machine.
- Behavioural fingerprinting that profiles an attack campaign (per-session
  destination, timing, pattern) to help block and report it, entirely
  within I2P.
- A daily or weekly summary.
- Invite-code sign-up for private groups.
- An update and advisory checker that works from a signed version list and
  reports only on the box.

## Getting XMPP Guard

XMPP Guard is sold separately from this repository. To ask about it, open
an issue titled `XMPP Guard enquiry` at
<https://github.com/muc111/OTRv4Plus/issues>, or see
[LICENSE-COMMERCIAL.md](../LICENSE-COMMERCIAL.md) for other ways to get in
touch.
