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

[`prosody/mod_otrv4plus_capacity.lua`](prosody/mod_otrv4plus_capacity.lua):

| Option | Default | Effect |
|---|---|---|
| `max_online_users` | `1600` | A new person signing in when this many are online is refused with `resource-constraint`. The apps say "The server is full… The app keeps trying and gets in when someone leaves." Someone already online who reconnects is never refused. `0` turns it off. 1,600 is what the T450 carried in [STRESS_TEST.md](STRESS_TEST.md) (2026-10-20); raise it only as far as a run on your machine shows. |
| `login_rate` | `10` | New sign-ins let in per second; `login_burst` (`40`) of them at once. Anyone over the rate is told "busy" at the very first step, before TLS or the password check, so turning them away costs almost nothing. The apps say "The server is busy letting people in, a few at a time" and retry after a randomised delay, so the crowd arrives spread out. `0` turns it off. |
| `max_registrations_per_hour` | `30` | New accounts per hour, server-wide. Above it, sign-up says "The server is refusing new accounts right now. Try again later." Failed attempts (a name already taken) do not count. `0` turns it off. |
| `max_registered_users` | `0` (none) | Accounts in total. Left off: an account that is not signed in costs nothing, and the online cap and the hourly sign-up limit are what protect the machine. |
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
max_registered_users = 0
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

[`prosody/mod_otrv4plus_moderation.lua`](prosody/mod_otrv4plus_moderation.lua)
gives this server's admins (the `admins = { ... }` list) four ad-hoc
commands, offered to nobody else:

| Command | What it does |
|---|---|
| Ban an account | For 1 to 3650 days, or permanently (0). The account's sessions close at once, and every sign-in is refused until the ban ends. Admins and yourself cannot be banned. |
| Lift a ban | The account can sign in again straight away. |
| Ban status | Whether an account is banned, and until when. |
| List all rooms | Every room on the rooms service, hidden ones included. |
| Destroy a room | Any room on the rooms service. The app uses it when the server refuses an admin's ordinary Delete because it does not count the admin as owner of other people's rooms (check: in `prosodyctl shell`, `room:get_affiliation("admin@…")` is `nil`). |

In the app, an admin sees **Moderation (server admin)** on other people's
profiles (Ban for N days, Ban permanently, Unban), and every room,
hidden ones marked, on the Rooms tab. A banned person's app says until when
and stops trying. Bans are kept in Prosody's storage, so they survive a
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

-- Only accounts on this server create rooms.
restrict_room_creation = "local"
```

After enabling `limits`, re-run one stress step (STRESS_TEST.md) to confirm
delivery is unchanged.

If the server does not federate with other XMPP servers (an I2P-only server
usually does not), turn federation off. That removes a whole listener:

```lua
modules_disabled = { "s2s" }
```

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
# Connections per minute from one I2P destination (0 = unlimited).
maxconns = 10
```

Check the option name against your i2pd version (`man i2pd` or the i2pd
documentation, tunnels configuration) before relying on it. It is weaker
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
