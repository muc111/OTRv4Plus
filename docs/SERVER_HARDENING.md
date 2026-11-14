# Hardening an OTRv4+ Prosody server

Limits that keep one machine within what it can carry, and stop account
creation being used to flood it. Written for the ThinkPad T450 server
(Prosody from source in `/usr/local`, i2pd in front); the settings apply to
any Prosody behind I2P.

## The one command

On the T450 (Prosody from source in `/usr/local`), everything below in one
go -- the three modules, the limits, and the room rate raised to 10:

```bash
cd ~/OTRv4Plus && git pull && sudo bash prosody/install-server-limits.sh
```

If XMPP Guard (i2pd-dash) is installed, the script turns on its maintenance
mode first, so its own changes become XMPP Guard's new baseline instead of
integrity alerts. It backs up `prosody.cfg.lua` first, runs `prosodyctl check config` and
puts the backup back if that fails, restarts Prosody and prints the settings
it ended with and any new error-log lines. Running it again changes nothing.
Override a value from the environment, e.g. `sudo LOGIN_RATE=20 bash
prosody/install-server-limits.sh`.

## Keep the server's address hidden

For a server reached **only through I2P or Tor**. Two Prosody defaults give
its real address away, and neither is mentioned by Prosody's own setup,
because an ordinary XMPP server wants both. Checked against the source of
Prosody 0.12.4 and 13.0.7.

**1. Prosody listens on every address.** `core/portmanager.lua` binds the
client port (5222) and the server-to-server port (5269) to `*` and `::`
unless told otherwise. Anyone who connects to the machine's public address
gets a server that answers for its hidden name and presents its certificate.
Internet-wide scanners record exactly that, so the hidden name leads
straight to the address.

**2. Federation is on.** `s2s` loads by itself (`core/modulemanager.lua`).
With it, a message from any account to `someone@a-domain-the-sender-owns`
makes the server look that domain up and connect to it, from its real
address. One message from one free account is enough.

Both are closed by:

```bash
cd ~/OTRv4Plus && git pull && sudo HIDDEN_SERVICE=1 bash prosody/install-server-limits.sh
```

which sets, before any `VirtualHost`:

```lua
interfaces = { "127.0.0.1" }      -- i2pd's tunnel connects to 127.0.0.1:5222
modules_disabled = { "s2s" }      -- "Communication with remote domains is not enabled"
hide_os_type = true               -- mod_version stops naming the OS
```

Then check, on the server:

```bash
sudo ss -ltnp | grep -E 'lua|prosody'     # every line should start 127.0.0.1 or [::1]
```

If a line still shows `0.0.0.0`, `*` or `[::]`, a narrower option is
overriding the global one (`c2s_interfaces`, `s2s_interfaces`,
`https_interfaces`): remove it. The script prints the same warning whenever
it runs, with or without `HIDDEN_SERVICE`.

**3. A firewall that refuses everything inbound** except i2pd's own port
(`port` in `/etc/i2pd/i2pd.conf` if you set one; otherwise the port its web
console shows in the router's external address). It costs nothing and covers
the day a config edit undoes step 1. If you reach the machine over SSH, allow
that **before** enabling the firewall, or you lock yourself out:

```bash
sudo ufw default deny incoming
sudo ufw allow <i2pd port>          # TCP and UDP
sudo ufw allow ssh                  # only if you administer it remotely
sudo ufw enable
```

**4. Say less about the machine.** `version`, `uptime` and `time` are in
Prosody's default `modules_enabled` and answer anyone signed in: the exact
Prosody version (which advisories apply), how long since the last restart
(matches a power cut or an ISP outage to the server), and the server's clock.
The apps use none of them. Remove the three lines from `modules_enabled`.

A block at the firewall or by `interfaces` cannot be undone from an XMPP
account; a kernel-level block on Prosody making outbound connections at all
is stronger still, and is what [XMPP Guard](XMPP_GUARD.md)'s egress lock
adds.

## What a break-in or a seizure would find

End-to-end encryption means no message, call or file can be read from the
server. What is there is who, and when. Each of these is on by default
somewhere and can be reduced:

| On the server | Why it is there | To reduce it |
|---|---|---|
| Sign-in and sign-out times, per account, in `prosody.log` | Prosody's default `log = { info = "prosody.log"; ... }` records "Authenticated as ..." and "Client disconnected" | `log = { error = "prosody.err" }`: errors only. Our modules log counts, and names only for admin actions (bans, room deletions) |
| Last-seen time per account, in storage | `account_activity`, new in Prosody 13's default `modules_enabled` | Remove it from `modules_enabled` unless you use it to prune dead accounts |
| Push registrations | `cloud_notify`, also new in 13's default list. The apps do not use push | Remove it |
| Contact lists, room memberships | The roster and rooms are the service | Nothing to remove; this is the metadata the server exists to hold |
| Undelivered messages (still encrypted) | Offline storage, and `mam` if you enabled it | `archive_expires_after = "1d"` if `mam` is on (default one week) |
| Password verifiers | SCRAM stored keys, never the password | See below |

**Passwords.** Prosody stores a salted PBKDF2 verifier (`internal_hashed`).
Someone who copies the account store can test guesses offline; the iteration
count sets the price of each guess. `default_iteration_count` is 10,000 by
default. Raising it is safe: it applies to passwords set from then on, and
existing accounts keep working.

```lua
default_iteration_count = 100000
```

Do **not** change `password_hash` on a server that already has accounts.
It is one switch for the whole server, the stored verifiers are specific to
the hash, and every existing account would be locked out
(`plugins/mod_auth_internal_hashed.lua`). On a brand-new server with no
accounts, `password_hash = "SHA-256"` is the better choice.

**The admin account.** `admin_adhoc` lets an account in `admins = { ... }`
change any user's password, read any user's contact list, and load any
module on disk, from an XMPP client, over the network. Whoever gets that
account's password, or its unlocked phone, gets all of that; loading `s2s`
undoes step 2 above. So:

- Make the admin account a separate one, used only to administer, with a
  long password used nowhere else and the app lock on.
- If you administer from the server's own shell (`prosodyctl shell`), remove
  `admin_adhoc` from `modules_enabled`. Banning, unbanning and room
  moderation in the apps keep working (they come from
  `mod_otrv4plus_moderation`). What stops is the admin's list of who is
  online and the terminal client's XEP-0133 commands.

**The machine.**
- Full-disk encryption (LUKS). Without it, whoever takes the machine reads
  everything above without a password. It protects a machine that is
  switched off, not one that is running.
- Prosody as its own user, never root (the packaged service already is).
- Security updates. A packaged Prosody gets them with the system's
  (`unattended-upgrades`); one built from source gets them only when you
  rebuild, so watch <https://prosody.im/security/>. The same goes for i2pd
  and OpenSSL.
- A systemd sandbox for Prosody and i2pd (`NoNewPrivileges`,
  `ProtectSystem=strict`, `PrivateTmp`, `MemoryDenyWriteExecute`,
  `SystemCallFilter=@system-service`) limits what a hole in either can
  reach. XMPP Guard's `harden.sh` installs and tests one.

## What these limits do not stop

Stated so nobody relies on them for it:

- **One determined client can lock others out for a while.** Sign-in pacing
  and the registration limit are server-wide, because Prosody cannot tell
  I2P clients apart. Someone who opens connections faster than `login_rate`
  uses up the allowance for everyone, and 30 junk registrations use up the
  hour's sign-ups. i2pd's per-destination limit (below) slows one client,
  and a client that makes a new destination for each attempt gets round it.
  Invitation-only sign-up is the answer to the second; there is none yet for
  the first that does not also cost honest users.
- **A server can be asked whether an account name exists.** SCRAM answers
  differently for an unknown name, and registration says "already taken".
  Both are how XMPP works.
- **An unknown hole in Prosody, Lua, OpenSSL or i2pd.** Nothing on this page
  finds one. What it does is make the server hard to find (the section
  above), make a hole yield less (this section), and keep the fix one
  update away.

## What protects the server today

| Protection | State | What it does |
|---|---|---|
| `mod_muc_limits` | On (`muc_event_rate = 5`, `muc_burst_factor = 10`) | Caps messages per room per second. The only limit that has ever refused traffic in a test: in the second 100-user run (STRESS_TEST.md). |
| One session per account | On once `mod_otrv4plus_one_session` is installed (SECURITY_SESSIONS.md) | One device per account, newest wins. |
| `LimitNOFILE=65536` | On (systemd drop-in) | Room for thousands of connections. |
| Online cap, sign-up limits | **New:** `mod_otrv4plus_capacity` below | Not set until installed. |

To see what your configuration has, on the server:

```bash
grep -nE 'modules_enabled|limits|registration|c2s_|muc_|max_' /usr/local/etc/prosody/prosody.cfg.lua
```

## The fact that shapes everything: I2P hides who is connecting

Every client reaches Prosody through i2pd's server tunnel, so to Prosody
**every connection comes from 127.0.0.1**. Prosody never sees an address
per user. Anything "per IP" in Prosody, such as its registration throttle,
is therefore one limit shared by everyone. That is not wrong, but it has to
be chosen as a server-wide limit, which is what the module below does. Only
i2pd sees the connecting I2P destination (see the i2pd section).

## `mod_otrv4plus_capacity`: online cap and sign-up limits

[`prosody/mod_otrv4plus_capacity.lua`](../prosody/mod_otrv4plus_capacity.lua):

| Option | Default | Effect |
|---|---|---|
| `max_online_users` | `1600` | A new person signing in when this many are online is refused with `resource-constraint`. The apps say "The server is full… The app keeps trying and gets in when someone leaves." Someone already online who reconnects is never refused. `0` turns it off. 1,600 is what the T450 carried in [STRESS_TEST.md](STRESS_TEST.md) (2026-10-20); raise it only as far as a run on your machine shows. |
| `login_rate` | `10` | New sign-ins let in per second; `login_burst` (`40`) of them at once. Anyone over the rate is told "busy" at the very first step, before TLS or the password check, so turning them away costs almost nothing. The apps say "The server is busy letting people in, a few at a time" and retry after a randomised delay, so the crowd arrives spread out. `0` turns it off. |
| `max_registrations_per_hour` | `30` | New accounts per hour, server-wide. Above it, sign-up says "The server is refusing new accounts right now. Try again later." Failed attempts (a name already taken) do not count. `0` turns it off. |
| `max_registered_users` | `5000` (`install-server-limits.sh`; the module's own default is `0`, none) | Accounts in total: a backstop against sign-ups filling the disk, on top of the hourly limit. At 30 an hour, 5,000 takes about a week to reach. |
| `gc` | `{ mode = "generational" }` | Not ours: Lua's garbage collector. With the default, a 1,990-user run stayed at 100% for an hour after joining stopped; with this, 1,600 users recovered from a join burst within two minutes. `install-server-limits.sh` sets it. |

Install:

```bash
cd ~/OTRv4Plus && git pull
sudo cp prosody/mod_otrv4plus_capacity.lua /usr/local/lib/prosody/custom_modules/
```

In `prosody.cfg.lua`, before any `VirtualHost`, with the other options:

```lua
max_online_users = 1600
login_rate = 10
login_burst = 40
max_registrations_per_hour = 30
max_registered_users = 5000
gc = { mode = "generational" }
```

Add `"otrv4plus_capacity";` to `modules_enabled`, then:

```bash
sudo prosodyctl check config && sudo systemctl restart prosody
```

Each refusal of a sign-in or account is logged at `warn` in
`/usr/local/var/log/prosody/prosody.err`, so you can see when the limits are
reached. Paced sign-ins are logged at `info`.

**Sign-in pacing: why and how much.** When the server restarts, every phone
drops at the same moment and comes back together. Each sign-in costs a TLS
handshake and a password check, and then the person's rooms and secure
groups are rejoined, all on Prosody's one core. At `login_rate = 10`, 2,000
people are back in about 3½ minutes, at a steady load instead of one spike.
The apps also spread their retries by ±25%, so they do not all knock at the
same second. To tune it, restart Prosody with a stress test running
(STRESS_TEST.md) and watch `pidstat`. If Prosody stays well under 80% while
everyone signs back in, raise `login_rate`; if it pins at 100%, lower it.
The stress test retries "busy" like the apps and reports how many sign-ins
were paced.

**Is 2,000 right for the T450?** The stress test measured steady chat at
about 0.046% of one core per user, about 1,700 users at 80% of Prosody's
one core, at one message per user per minute. Real people send far less, so
2,000 online is likely fine for chat. Two things are not yet measured:
everyone reconnecting at once after a restart (joining was the expensive
part of every test), and i2pd's own CPU with 2,000 real I2P clients. Start
at 1,000 and raise it once a real I2P test shows the headroom.

## `mod_otrv4plus_moderation`: bans and every room, for admins

[`prosody/mod_otrv4plus_moderation.lua`](../prosody/mod_otrv4plus_moderation.lua)
gives this server's admins (the `admins = { ... }` list) four ad-hoc
commands, offered to nobody else:

| Command | What it does |
|---|---|
| Ban an account | Permanently: the account's sessions close at once, and every sign-in is refused until an admin lifts the ban. Timed bans were removed (2026-10-25); a timed ban stored by an earlier build still ends on its date. A ban never deletes or changes the account. Admins and yourself cannot be banned. |
| Lift a ban | The account can sign in again straight away. |
| Ban status | Whether an account is banned, and until when. |
| List all rooms | Every room on the rooms service, hidden ones included. |
| Destroy a room | Any room on the rooms service. The app uses it when the server refuses an admin's ordinary Delete because it does not count the admin as owner of other people's rooms (check: in `prosodyctl shell`, `room:get_affiliation("admin@…")` is `nil`). |

In the app, an admin sees **Moderation (server admin)** on other people's
profiles (Ban permanently, Unban), and every room,
hidden ones marked, on the Rooms tab. A banned person's app says they are
banned and stops trying. Bans are kept in Prosody's storage, so they survive a
restart; each is logged at `warn` in `prosody.err`.

The one command above installs and enables it. If the rooms service is not
`conference.<domain>`, set `otrv4plus_muc_host = "rooms.example.i2p"`.

## Prosody settings worth adding

```lua
-- Close connections that have not signed in within 3 minutes. Over I2P a
-- sign-in takes up to ~90 s, so not lower.
c2s_timeout = 180

-- Per-connection bandwidth cap (mod_limits, part of Prosody): one client
-- cannot flood the server. Generous enough for secure-group invitations,
-- which are the largest bursts (about 9.4 KB per member).
modules_enabled = { --[[ ...the existing list... ]] "limits"; }
limits = {
    c2s = { rate = "100kb/s"; burst = "5s"; };
}
-- NOT YET STRESS-TESTED with large groups. An invitation into a group of
-- N carries the whole tree, about 9.4 KB per member: ~940 KB for 100
-- members, about twice what a 5 s burst at 100 kb/s allows. mod_limits slows
-- the sender down rather than dropping data, so the invite should still
-- arrive, seconds later; check that with a stress step that invites into
-- groups of 100 before relying on it, and raise `rate` if invites time out.

-- Only accounts on this server create rooms.
restrict_room_creation = "local"
```

After enabling `limits`, re-run one stress step (STRESS_TEST.md) to confirm
delivery is unchanged.

On a server reached only through I2P or Tor, federation must be off; that
is a matter of the server's address, not of load. See "Keep the server's
address hidden" above.

**Stronger sign-up control, if abuse starts:** Prosody's invitations
(`mod_invites` with `registration_invite_only = true`) allow sign-up only with
an invite link. The app does not yet support invite links, so this would
also stop in-app sign-up. It is the next step if the hourly limit is not
enough.

## i2pd, the front door

i2pd is the only part that sees each client's I2P destination. In
`/etc/i2pd/tunnels.conf`, on the XMPP server tunnel (`type = server`,
`port = 5222`):

```ini
# New streams per minute from one client destination (0 = unlimited, the
# default). Over the limit, i2pd drops the connection attempt.
i2p.streaming.maxConnsPerMinute = 10
# Streams open at once on this tunnel; the default, 2048, is above the
# 1,600 online cap, so it only needs raising with the cap.
# i2p.streaming.maxConcurrentStreams = 2048
```

An earlier version of this page said `maxconns = 10`. i2pd has no such
option and ignored the line silently; the names above are the ones i2pd
reads (`libi2pd/Destination.h`, applied per remote destination in
`libi2pd/Streaming.cpp`). The limit is weaker
than it looks: the app makes a new I2P destination for each session, so a
determined client can rotate. It still stops a single runaway client.

For capacity: an I2P server with thousands of users needs its tunnels and
bandwidth sized up. In `/etc/i2pd/i2pd.conf`, raise `bandwidth` (for example
`bandwidth = P`) if the machine's connection allows. On the server tunnel,
`inbound.quantity = 8` and `outbound.quantity = 8` add tunnels. Consider
`notransit = true` on the server: it stops carrying other people's I2P
traffic, which leaves its CPU and bandwidth for your users.

## Operating system

Already set: `LimitNOFILE=65536`. Worth adding to the same drop-in
(`/etc/systemd/system/prosody.service.d/limits.conf`), so a fault in Prosody
cannot take the whole laptop's memory:

```ini
[Service]
LimitNOFILE=65536
MemoryMax=2G
```

Then `sudo systemctl daemon-reload && sudo systemctl restart prosody`. The
800-user test peaked at about 300 MB.

Prosody runs on one CPU core whatever the machine has, so on the T450's four
cores it can use at most about 25% of the laptop's CPU. It cannot take the
whole laptop's CPU by itself.
