# Stress-testing your own Prosody server

A hidden mode of the terminal client loads **your own** server with simulated
users. They form a single end-to-end encrypted (MLS) group and chat in it.
It's for finding where the server, or the group, starts to struggle.

## Who can run it

**Only an administrator of the server.** The test accounts are created with
the server's own admin command (XEP-0133 `add-user`). Prosody runs that
command for its admins and refuses everyone else, so the server enforces
this, not the client.

You are asked for the admin password; it is never read from the command line.
When the run ends, every test account is deleted again (`delete-user`)
unless you pass `--keep`.

## Run it — on the server machine

The bots connect straight to Prosody on `127.0.0.1:5222`, not over I2P.
The aim is to load Prosody; hundreds of I2P tunnels would only load i2pd.

```bash
cd ~/OTRv4Plus
# First a short trial: 20 users, 10 minutes
python3 otrv4plus_xmpp.py --stresstest --admin alice@otrv4plus.i2p --users 20 --minutes 10

# Then the real run: 100 users added 16 at a time every 2 minutes, for 2 hours
nice -n 10 python3 otrv4plus_xmpp.py --stresstest --admin alice@otrv4plus.i2p \
    --users 100 --batch 16 --ramp 120 --minutes 120
```

| Option | Default | Meaning |
|---|---|---|
| `--users` | 50 | Simulated users |
| `--minutes` | 60 | How long to run |
| `--interval` | 120 | Average seconds between one user's messages (jittered: chat, not a flood) |
| `--groups` | 1 | Split the users into this many groups, each its own room. Server capacity is measured with many groups; one group tops out at ~100 members |
| `--batch` / `--ramp` | 1 / 10 | Most users added in one change, and seconds between adds in each group. 1 is how the app adds people (one at a time, as they accept) |
| `--observers N` | all | Only the first N users decrypt the chat; the rest skip it (they still process every group change). Saves this machine's CPU (see below) |
| `--keep` | off | Keep the test accounts afterwards |
| `--csv FILE` | `stresstest-<time>.csv` | One row of numbers per minute |

Every minute it prints a line and appends a CSV row:

- members, and users online;
- messages sent;
- **delivery %**: messages decrypted by the other members, out of those expected;
- **latency p50/p95**: time from sending to the other side decrypting;
- group changes (commits) made;
- **room errors**: messages the room refused, usually its rate limit;
- disconnects;
- joins refused;
- **undecryptable**: messages a member could not decrypt;
- **lost**: room pieces the app's pacer gave up on after its retries;
- **harness lag**: how long this process's own loop stalled. Several seconds
  means the numbers measure this machine's bots, not the server.

The messages are made-up one-liners about invented news stories, for example
*"Did you see the piece on the night bus trial?"*. They are built on this
machine and MLS-encrypted, so the server only ever carries ciphertext.
Nothing is fetched from the internet.

## What to expect

- **A group stops accepting new members at about 100.** This is measured,
  not a server limit. With the app's post-quantum suite, the message a new
  member joins with (the MLS *Welcome*) carries the whole group tree, about
  9.4 KB per member: 196 KB at 17 members, 634 KB at 65. The core refuses
  any MLS message over 1 MiB. The run prints `JOIN REFUSED at N members`
  when it reaches that point. Text chat between the members already in the
  group goes on.
- **Adding 16 people at once is about 270 KB** of group change. It goes
  through the room in about 70 pieces, paced like the app paces them.
  `room errors` show when the server's room rate limit (`muc_limits`) pushes
  back.
- **This machine is doing the users' crypto as well as running the server.**
  Every message is decrypted by every member. Watch the stress-test process
  in `htop` next to Prosody, and use `--observers 10` on a big run so the
  laptop isn't mostly measuring itself.

## First measurement (ThinkPad T450, 2026-10-16)

100 users, added 16 at a time every 2 minutes, one line each per ~20 s.

| | Result |
|---|---|
| Group size | All **100** joined; none refused. The ceiling is just above 100 (the Welcome at 100 members is ~940 KB of the 1 MiB limit). |
| Prosody, steady chat at 100 members | Under 50% of one core, in short bursts; idle in between |
| Prosody, adding 16 people to a group of 81-90 | **100% of one core for about 4 minutes**, memory 60 MB → 180 MB (peak 260 MB). The commit (~270 KB) goes to ~90 occupants and each new member gets a ~900 KB Welcome. |
| Prosody memory after the run | Stayed at ~180 MB (Lua keeps what it allocated); a restart returns it |
| Errors | No room errors, no disconnects |
| Latency and delivery | Up to 49 members: 100% delivered, p95 under 1 s. From 65 members, latency rose to ~23 s and delivery fell to ~35% (both explained below). |

**Why delivery fell: a real bug, now fixed (rc.93).** The CSV showed no
undecryptable messages outside the minutes when members were added, so the
lines were not failing to decrypt: they were never put back together. A chat
line here is two pieces (post-quantum signatures make it ~6.5 KB). The
receiving side held at most 64 half-received messages **shared by every
sender**, and dropped the oldest when full. With ~90 members' pieces
interleaved, about two thirds were thrown away. The app uses the same code,
one per connection, so a busy secure group, or catching up on history after
reconnecting, could lose messages silently. Each sender now has its own
budget of 16 and the shared limit is 1024; a sender over budget loses only
its own oldest piece. This also closes the documented weakness where one
contact could push out another's half-received handshake.

**The ~23 s latency was the test process.** Prosody idled between bursts
every ~25 s. Every bot decrypted every chat line, even with
`--observers 10`: ~10 000 post-quantum MLS decryptions per burst in one
Python process. Non-observers now skip chat lines, and the **harness lag**
column shows when the test process is the bottleneck.

**Undecryptable bursts at group changes** (48, 2400, 2784): chat sent just
before a change arrived after it, and the new epoch cannot read the old one.
With 23 s of lag many lines were in flight; in normal use it is the few
seconds around adding someone.

**Second run (same evening, after those fixes).** Harness lag stayed under
half a second and latency at 100 members was **0.2 s median, 0.5 s p95**.
Prosody used **~29% of one core** steady with 100 members sending ~300
lines a minute (each delivered to 100 occupants), and ~100% for about five
minutes while members 81-97 were added. Delivery still read ~43% with no
undecryptable messages: the test's own pacing never saw the room's
refusals (they arrive as `type="error"`, not as room messages) and never
re-sent them, so it showed "room errors 0". The test now uses the app's own
`RoomPacer`, which slows down on a refusal and re-sends anything the room
refused or did not echo, and it counts refusals and pieces given up on
(`lost`). If `room errors` climbs, the server's `mod_muc_limits` is
refusing the traffic; see below.

**What it means for real groups:** adding many people at once to a large
group is the expensive operation for the server. The app adds people one at
a time, as they accept their invitations, so each change is ~1/16 of the
size measured here.

## Capacity: many groups of 20 (T450, 2026-10-16)

Every user in a group of ~20, added one at a time as the app does, sending
one line a minute (far more than real people send). Local connections, no
I2P. Steady = the minutes after everyone had joined.

| Users | Groups | Prosody steady (one core) | Prosody memory | Latency steady p50 / p95 | Delivered steady |
|---|---|---|---|---|---|
| 200 | 10 | ~8.5% | 53 MB | 0.11 s / 0.23 s | ~100% |
| 400 | 20 | ~17.5% | 106 MB | 0.17 s / 0.34 s | ~100% |
| 800 | 40 | ~37% | 303 MB | 0.31 s / 0.56 s | 99.8-100.5% |
| 1,200 ¹ | 60 | ~28.5% (peak 40%) | 262 MB | 0.23 s / 0.42 s | 98.6-101.6% |

¹ 2026-10-18, run c4cde6: `--users 1200 --groups 60 --batch 1 --ramp 15
--observers 2`, the default `--interval 120` (one line per user every two
minutes, ~600 lines a minute) where the rows above sent one a minute.
Per line sent it matches them: **about 0.047% of one core per line a
minute** to a group of 20 (800 lines/min = 37%, 600 lines/min = 28.5%).
Joining (1,200 people into 60 groups in 20 minutes, ~60 additions a minute)
ran Prosody at 65-90%, peaks 100%. All 1,200 accounts were deleted at the
end. XMPP Guard was running throughout (~4-6% of a core of its own).

**Steady chat grows in a straight line: about 0.046% of one core per user.**
No room errors, no disconnects and no refused joins in any run.

**Prosody uses one core, whatever the machine has.** It runs as a single
Lua process, so "100% of one core" is its limit even though the T450 has
four. The whole laptop never went above ~55% CPU, and only because the test
process was on it too.

**Adding people is what costs.** While 800 people joined 40 groups in 16
minutes (~50 additions a minute), Prosody ran at 60-100% of one core. Once
everyone had joined it dropped to ~37%.

**The bad numbers in the 800 run's joining phase came from the test
process, not the server.** The test is one Python process. It sat at
95-100% of a core and fell up to 45 s behind ("harness lag"):

- **Undecryptable:** new members were processing their Welcome late. Room
  traffic sent before they had joined is unreadable to them, as it should be.
- **Delivered above 100%:** late lines were counted in a later minute's
  window.
- **lost 94 / 92 / 65:** pieces the pacer gave up re-sending while the
  process was stalled.

Within a minute of the lag clearing, every figure was clean. For larger
runs, run the test on a second machine, or split it into two runs with
different `--groups`.

**Memory is not a limit.** Prosody used ~0.38 MB per user (303 MB at 800).
Lua keeps what it allocated until a restart. The test itself used 2.4 GB.
vmstat's low "free" is page cache, which the kernel hands back.

**What the T450 can carry, keeping Prosody under 80% of its one core:**

- Steady chat at this test's rate (one line per user per minute): about
  **1,700 users**.
- Recommended planning figure: **about 1,000 users**. That leaves room for
  join bursts and for everyone reconnecting at once after a restart.
  Real people send far less than a line a minute, so this is conservative
  for chat.
- Still unmeasured: the I2P router. Every real user arrives through I2P
  tunnels, and the router's CPU is probably the next limit. Measure it with
  real I2P clients before going past a few hundred users.

### Big groups growing together are what saturates Prosody (2026-10-18)

Same 1,200 users in **15 groups of 80, added 8 at a time** (`--groups 15
--batch 8 --ramp 10`): Prosody sat at 99-100% of its core from the first
minute, loopback carried ~6 MB/s, groups stalled at ~375 members after 12
minutes, p95 latency reached 52 s, and the run was stopped. Every MLS+ add
carries the new member's KeyPackage (~9 KB: ML-KEM-1024 and ML-DSA-87 keys
and an ML-DSA-87 signature), so a batch of 8 is a ~75 KB commit fanned out
to every member, and each Welcome carries the whole tree. Fifteen groups
doing that at once is more than one core can route. The app adds people one
at a time as they accept, so this pattern is a test artefact, but it is
the server's worst case: **many large groups growing at the same moment.**

**XMPP Guard was not the cause:** with all four of its services stopped,
Prosody stayed at 100%.

### 1,990 users: overload that did not recover (2026-10-18, run a9ae40)

`--users 1990 --groups 100 --batch 1 --ramp 25 --observers 2 --minutes 75`,
test and server on the same T450. Prosody reached 99.9% of its core by
minute 12 and **stayed there for the remaining hour**, even after joining
had all but stopped (minutes 65-74: 1,914 of 1,990 joined, ~0 commits,
~900 lines a minute). Latency p50 rose to 100-160 s, Prosody's memory
climbed from 240 MB to 1 GB, and the test process ran at ~98% of a core.
The battery ran out at minute 74, before the accounts were deleted.

Once Prosody fell behind it did not catch up: undelivered traffic piled up
in memory, the Lua garbage collector had ever more to walk, and the bots
re-sent what they thought was lost (400-2,000 pieces a minute).

### 1,600 users with the generational collector (2026-10-20, run 5496d9)

Prosody restarted with `gc = { mode = "generational" }` in its config;
`--users 1600 --groups 80 --batch 1 --ramp 60 --observers 2 --minutes 75`.

| Phase | Prosody (one core) | Latency p50 / p95 | Memory |
|---|---|---|---|
| Joining, groups up to ~12 members (min 1-11) | 25-55% | 0.13-4 s / 0.2-10 s | 129-245 MB |
| Joining, groups 13-20 members (min 12-34) | 80-100% | 5-48 s / 16-92 s | 258-500 MB |
| **Steady, all 1,600 joined (min 36-74)** | **37-41%** (peaks ~50%) | **0.30 s / 0.52 s** | 463 MB |

~800 lines a minute, 99-101% delivered, 0 room errors, 0 refused joins, all
1,600 accounts deleted at the end. Per line the steady cost matches every
earlier run (**~0.05% of one core per line a minute** to a group of 20).

**The overload recovered this time:** at minute 34 the last member joined
and within two minutes Prosody was back to ~38% with normal latency. On
2026-10-18, without the setting, Prosody stayed at 100% for an hour after
joining stopped. Keep `gc = { mode = "generational" }` on the server.

Joining costs more as groups grow (each Welcome carries the whole tree), so
80 additions a minute saturated the core once groups passed ~13 members.

### 1,800 users (2026-10-20, run b05ab3)

Same settings, `--users 1800 --groups 90 --batch 1 --ramp 60 --observers 2
--minutes 85`; Prosody not restarted since the 1,600 run (417 MB at start).

| Phase | Prosody (one core) | Latency p50 / p95 | Memory |
|---|---|---|---|
| Joining, groups up to ~11 members (min 1-10) | 37-70% | 0.15-5 s / 0.2-15 s | 417 MB |
| Joining, groups 12-20 members (min 11-66) | 85-100% | 13-147 s / 30-181 s | 393-764 MB |
| **Steady, all 1,800 joined (min 67-84)** | **45-50%** (peaks ~60%) | **0.35 s / 0.58 s** | 741 MB |

~895 lines a minute, 99-101% delivered, 0 room errors, 0 commit failures, 0
refused joins, all 1,800 accounts deleted. Steady cost again **~0.053% of
one core per line a minute**. Recovery after the last join took one minute.

The joining phase is what grows faster than linearly: saturated for 22
minutes at 1,600 and 52 minutes at 1,800, because every addition to a fuller
group costs more and the backlog slows the additions down. Ninety groups of
20 forming within an hour is far beyond what real users do; rejoining
groups one already belongs to (after a restart) needs no MLS additions.

**Planning figures for the T450 (one Prosody, generational GC):** steady
chat at a line every two minutes uses ~40% of the core for 1,600 and ~47%
for 1,800, so ~2,000 would use ~53%. The limit is bursts (many groups growing at once, a
mass reconnect), which now saturate the core for their duration but
recover. The I2P router remains unmeasured.

## The room rate limit (`mod_muc_limits`)

Prosody's `mod_muc_limits` caps how many messages **one room** accepts per
second from occupants who are not room members or admins. The T450 runs
`muc_event_rate = 5`, `muc_burst_factor = 10`: 5 per second per room, bursts
of 50. A secure-group line is two pieces, so a room takes about 2.5 lines a
second before it starts refusing. The app slows down and re-sends; the test
does the same and counts the refusals (`room errors`). Each room has its own
budget, so ten groups have ten times the room.

## Watching the laptop and Prosody

Run these in other terminals while the test runs.

**Set Prosody's log back to `warn` first.** Debug logging writes every
stanza to disk and would be most of the load:

```bash
sudo sed -i 's/min = "debug"/min = "warn"/' /usr/local/etc/prosody/prosody.cfg.lua
sudo systemctl restart prosody
```

| What | Command |
|---|---|
| Overall CPU, memory, per-process | `htop` (F4 to filter on `prosody` / `python3`) |
| Prosody alone, every 5 s | `pidstat -u -r -p $(pgrep -f 'lua.*prosody' \| head -1) 5` (package `sysstat`) |
| Memory, swap, run queue, every 5 s | `vmstat 5` |
| Disk writes (logs, room archive) | `sudo iotop -o` |
| Open connections | `ss -s` and `ss -tn state established '( sport = :5222 )' \| wc -l` |
| Inside Prosody | `sudo prosodyctl shell`, then `c2s:count()`, `server:memory()`, `muc:list("conference.otrv4plus.i2p")`; leave with `quit` |
| Room-limit refusals | `sudo grep -c 'muc_limits\|resource-constraint' /usr/local/var/log/prosody/prosody.log` |
| Temperature / throttling (T450) | `watch -n5 sensors` (package `lm-sensors`) |

To log the whole run for later comparison with the CSV:

```bash
pidstat -u -r -p $(pgrep -f 'lua.*prosody' | head -1) 10 > prosody-usage.txt &
vmstat -t 10 > vmstat.txt &
```

**Signs it is degrading:**

- latency p95 climbing past a few seconds;
- delivery % falling below 100;
- room errors or disconnects appearing;
- Prosody's CPU pinned near 100% of one core (Prosody is mostly single-threaded);
- swap use growing in `vmstat`.

## If a run is interrupted

Ctrl-C stops it and still deletes the accounts. If the process is killed
outright, the leftover accounts are named `stress-<run>-NNN`. Remove them
with the admin command, or run
`sudo prosodyctl deluser stress-<run>-000@otrv4plus.i2p` for each.

## Removing leftover rooms and accounts

Runs before rc.95 left their rooms behind on servers that make rooms
persistent by default (the T450 does, so real groups survive restarts).
Runs now create their rooms as not persistent and destroy them at the end.

To clear old ones, open the Prosody console with `sudo prosodyctl shell`.
`MUC` below is your rooms component, for example `conference.otrv4plus.i2p`.
To find it: `grep -n Component /usr/local/etc/prosody/prosody.cfg.lua`.
Lines starting with `>` run as Lua inside Prosody. Count first, then
delete; every one matches only names starting with `stress-`.

```
> local n=0 for r in prosody.hosts["MUC"].modules.muc.each_room() do if r.jid:match("^stress%-") then n=n+1 end end return n
> local l={} for r in prosody.hosts["MUC"].modules.muc.each_room() do if r.jid:match("^stress%-") then l[#l+1]=r end end for _,r in ipairs(l) do r:destroy(nil,"stress test cleanup") end return #l
> local um=require"core.usermanager" local n=0 for u in um.users("otrv4plus.i2p") do if u:match("^stress%-") then n=n+1 end end return n
> local um=require"core.usermanager" local l={} for u in um.users("otrv4plus.i2p") do if u:match("^stress%-") then l[#l+1]=u end end for _,u in ipairs(l) do um.delete_user(u,"otrv4plus.i2p") end return #l
```

The first and third lines only count. Run the counts again afterwards;
both should be 0.

## Welcome room presence load (`--welcome`, added 2026-10-21) -- not yet measured

Every real app joins the public Welcome room, where everyone sees everyone
(that is its purpose: who is online, who to add). The runs above never put
the bots there, so the 1,600 cap reflects groups only. A join in a room of N
people is told to all N and sends the newcomer all N, so filling it costs
about N^2 presence stanzas (~2.5 million at 1,600), plain text or not; MLS
group joins cost the phones' CPU and a few large stanzas instead.

`--welcome` makes every bot also join Welcome, `--welcome-rate` a second
(default 2), during the measured run. Each minute adds `welcome_in`,
`welcome_failed` and `welcome_join_p50_s`/`p95_s` (until the whole occupant
list arrived). Real people in Welcome see the bots: turn XMPP Guard's
maintenance mode on and run it when nobody relies on the room. Suggested:
400, then 800, then 1,600 users (`--groups` = users / 20), and compare the
join times and Prosody's CPU with the group-only runs above.

## Running the bots on another device (a phone in Termux), 2026-10-21

Bots on the server compete with Prosody for the same CPU. To keep the server
clean, run them elsewhere -- a Pixel 7 in Termux works -- and reach Prosody
through a **reverse** SSH tunnel: the server connects out to the phone and
carries its own `127.0.0.1:5222` across, so nothing new listens on the server
and Prosody stays loopback-only.

On the phone (Termux from F-Droid), once:

```bash
pkg install python rust openssl clang git openssh
git clone https://github.com/muc111/OTRv4Plus.git
cd OTRv4Plus/Rust && bash build.sh && cd ..
passwd                      # a password for Termux's SSH server
```

Each run, three terminals:

1. phone: `termux-wake-lock; sshd` (Termux's SSH server, port 8022)
2. server: `ssh -p 8022 -N -R 5222:127.0.0.1:5222 <phone-wifi-ip>` (the tunnel;
   `ip addr` in Termux shows the phone's address)
3. server: `python3 tools/prosody_load_log.py --csv server-400.csv`
   (Prosody's CPU and memory each minute: the stress test cannot see the
   server's process from the phone)

then on the phone:

```bash
cd ~/OTRv4Plus && python otrv4plus_xmpp.py --stresstest --admin alice@otrv4plus.i2p \
    --users 400 --groups 20 --minutes 40 --welcome --csv welcome-400.csv
```

Close the OTRv4+ app on the phone first (the run signs in as the admin, and
the server allows one session per account), keep the phone on its charger,
and stop `sshd` (`pkill sshd`) and the tunnel (Ctrl-C) afterwards.
