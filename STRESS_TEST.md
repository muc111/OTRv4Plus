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
| `--batch` / `--ramp` | 16 / 60 | Users added per group change, and seconds between changes. Ramping shows where things degrade |
| `--observers N` | all | Only the first N users decrypt the chat, which saves this machine's CPU (see below) |
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
- joins refused.

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
