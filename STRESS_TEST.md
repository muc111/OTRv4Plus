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
