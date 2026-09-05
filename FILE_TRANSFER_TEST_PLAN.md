# /sendfile — two-phone validation plan

The ten steps to run on real devices before the torrent transport is built,
in order, smallest first. Nothing in this document has been run: it is the
plan, and the results column is empty until it is.

**Do not start with the 45 MB video.** Phase A carries chunks over the OTR
channel, so a large file is slow by design; running it first tells you nothing
you did not already know and hides the failures that matter.

## Before you start

Both phones need **v10.14.0** — a peer without `RustFileSender` cannot key a
transfer and will refuse rather than fail halfway.

```bash
cd ~/OTRv4Plus && git pull
python3.12 -m pip install --break-system-packages ./Rust
python3.12 -c "import otrv4_core; print(otrv4_core.file_transfer_format_version())"   # 1
```

Start XMPP over I2P as usual, `/otr <peer>`, and complete SMP. **A file cannot
be offered or accepted without SMP verification** — the same gate voice uses,
reading the same `_smp_verified` predicate.

Received files land in `~/.otrv4plus/files/`. Work in progress lives in
`~/.otrv4plus/files/.incoming/` and must never appear in the first directory.

## Getting a file into Termux in the first place

### The easy way: `/sendfile` with no path

Inside the OTR session, just type:

```
/sendfile
```

The Android file picker opens. Tap a photo, a video, anything. It is staged
privately, sealed, and offered to the peer — no paths, no `termux-setup-storage`,
no typing filenames. This is the way to run steps 2, 3, 4 and 10.

Three things to know:

* **It waits, and it says so.** `termux-storage-get` does not block until you
  choose; it hands the intent to the Termux:API app and exits at once, and the
  file lands seconds later when the chooser closes. The client polls for it
  and prints `[file] waiting for your choice` while it does. Backing out of
  the chooser writes nothing, which is indistinguishable from a slow choice,
  so a cancelled pick costs the full three-minute wait before it reports
  `no file chosen`. Choosing something is immediate.
* **The original filename does not survive.** The picker hands over bytes and
  not a name, so the file is renamed from its magic number and a timestamp —
  your peer sees `image-20260901-143022.jpg`, not `IMG_2891.jpg`. Cosmetically
  worse, marginally better for privacy: camera filenames carry sequence
  numbers and a name someone typed can say more than they meant. Use
  `/sendfile <path>` when the exact name matters.
* **It needs the Termux:API app, not just the package.** `pkg install
  termux-api` installs shell shims; the picker is drawn by the Termux:API app
  from F-Droid. If only half is present the client says which half.

### Status: working on hardware as of 2026-09-05

`/sendfile` completes between two Android handsets over I2P. It took four
releases to get there and every one of the four defects was found by running
it, not by reading it:

| | Found on device |
|---|---|
| v10.16.1 | the picker returned before the human did, so a file was never staged |
| v10.16.2 | the whole file was sent on the event loop, starving the keepalive |
| v10.17.1 | the receiver throttled the transfer as if it were a flood, and never told the sender it had given up |
| v10.18.0 | a completed transfer printed nothing at all |

The test suite passed throughout. That is the point worth remembering about
this feature: every one of those was invisible to it.

### What you should see while it runs

Both ends report, once a second, from the moment the transfer is accepted:

```
[file] ↓ holiday-photo.jpg [████░░░░░░] 40% · 784.8 KB/1.9 MB · 21.2 KB/s · ETA 0:54
```

`↓` is receiving, `↑` is sending. Rate and ETA appear once there is a second
of history to divide by — before that they are genuinely unknown and are left
out rather than guessed. The last line always reads `100%`.

Completion is announced on both sides, and this is the line to look for:

```
[file] received holiday-photo.jpg (1.9 MB) — hashes verified, saved to ~/.otrv4plus/files/…
```

**"hashes verified" is the part that matters.** The file is only placed once
the plaintext and ciphertext hashes both check out; a transfer that ends any
other way says so instead. Before v10.18.0 none of this was printed, so a
silent finish meant either success or a stall and there was no way to tell.

### How fast it goes, and why it is not faster

A transfer is paced at 8 stanzas a second, so a 340 KB file takes roughly half
a minute of steady sending. That is deliberate on both ends:

* The receiver rate-limits inbound messages to 20 per 5 s, and raises that to
  120 per 5 s only while an accepted transfer with that peer is running. The
  sender stays below the raised figure so ordinary chat, SMP and the
  keepalives still fit alongside the transfer.
* Sending happens one chunk per turn of the event loop. Before v10.16.2 the
  whole file went out in one unbroken run inside the inbound message handler,
  which starved the keepalive loop and disconnected the stream mid-transfer.

**There is no retransmit.** The chunk AEAD is a sequence, so chunk N cannot be
opened before N-1 and a gap can never be filled in. A lost chunk abandons the
transfer with one message asking you to send the file again — it does not
stall, and it does not report the same fault once per remaining chunk.

### The explicit way: by path

Termux starts with **no access to Android storage at all**. Its home is
`/data/data/com.termux/files/home`, and your photos are not in it. `/sendfile
photo.jpg` will simply report no such file until you do this once, per phone:

```bash
termux-setup-storage          # Android shows a permission dialog — accept it
ls ~/storage
```

That creates `~/storage/` with symlinks into shared storage:

| Path | What is there |
|---|---|
| `~/storage/dcim` | camera photos and video (`~/storage/dcim/Camera/`) |
| `~/storage/downloads` | the Downloads folder |
| `~/storage/pictures` | screenshots, saved images |
| `~/storage/movies` | video |
| `~/storage/shared` | the root of internal shared storage |

Then send by path — `/sendfile` expands `~`, so this works as typed:

```
/sendfile ~/storage/dcim/Camera/20260901_143022.jpg
/sendfile ~/storage/downloads/report.pdf
```

Tab completion does not exist in the client, so `ls ~/storage/dcim/Camera/ |
tail` in a second Termux session is the quick way to get an exact name.

**Or pick it from a graphical file chooser.** You have `termux-api` installed,
so:

```bash
termux-storage-get ~/to-send.jpg      # opens the Android picker, copies it here
```

then `/sendfile ~/to-send.jpg`. Useful for step 3, where you want a filename
with spaces or an emoji in it without typing the path by hand.

## Getting a received file back out

Received files land in `~/.otrv4plus/files/`, which is inside Termux's private
data directory at mode 0700. **The Android gallery and every other app cannot
see it.** That is deliberate — it is the whole reason the directory is not
`~/storage/downloads` — but it means you cannot tap a received photo to view
it.

To view one you have to copy it out:

```bash
cp ~/.otrv4plus/files/photo.jpg ~/storage/downloads/
termux-media-scan ~/storage/downloads/photo.jpg    # make the gallery notice it
```

**Understand what that costs.** The copy leaves a 0700 directory that only
Termux can read and lands in shared storage, readable by every app that holds
the storage permission, and backed up or synced by anything watching that
folder. The encryption protected the file in transit; once you copy it there,
it is an ordinary file on the phone. Copy out what you want to look at, not
everything.

For steps 1–2 of the plan you do not need to copy anything: `sha256sum` reads
the file where it is, and that is the actual test.

## The commands

```
/sendfile                        open the Android picker and send what you choose
/sendfile <path>                 send a specific file, keeping its name
/transfer                        list transfers, both directions
/transfer accept <id>            accept an offer (first 8 hex chars is enough)
/transfer decline <id>
/transfer cancel <id>
```

## The ten steps

| # | Step | What to run | Pass condition |
|---|---|---|---|
| 1 | **Tiny text file** | `echo hello > test.txt` then `/sendfile test.txt` | Arrives; `sha256sum` matches both sides |
| 2 | **Binary file** | `/sendfile` and pick a photo | Byte-identical; opens correctly in a viewer |
| 3 | **Awkward filename** | by path: `touch ~/"photo of café (1).jpg"` and send it; repeat with an emoji | Lands under a sanitised name, no error, nothing outside `~/.otrv4plus/files/` |
| 4 | **Larger file** | ~5 MB | Completes; watch how long it takes and write the number down |
| 5 | **Cancellation** | `/sendfile` a ~20 MB file, `/transfer cancel <id>` mid-flight from **each** side in turn | `.incoming/` empty; nothing in `files/`; both sides report cancelled |
| 6 | **Interrupted connection** | start a ~20 MB transfer, put the sender in flight mode for 30 s, restore | Either it resumes or it fails cleanly. **Either is a pass; a half-file in `files/` is not** |
| 7 | **Duplicate / replayed chunk** | see below | Rejected, transfer abandoned, `.incoming/` empty |
| 8 | **Corrupted ciphertext** | see below | Rejected as an authentication failure, not as a size or hash error |
| 9 | **Wrong metadata** | see below | Refused before or at placement; nothing in `files/` |
| 10 | **The 45 MB video** | only once 1–9 pass | Arrives byte-identical, however long it takes |

## Verifying each transfer

Not "the file arrived" — that is the weakest possible check. On both phones:

```bash
# sender
sha256sum ~/path/to/original

# receiver
sha256sum ~/.otrv4plus/files/<name>

# and, on the receiver, the thing that matters as much:
ls -la ~/.otrv4plus/files/.incoming/     # must be empty
ls -la ~/.otrv4plus/files/               # must contain no .part or .tmp
```

A `.part` file visible in `~/.otrv4plus/files/` at any point is a **failure**
even if the transfer later completes: it would mean an incomplete file was
presented as a finished one.

## Steps 7–9, concretely

These need the sender to misbehave, which the normal client will not do. Run
them from a Python shell on the sender phone against the same live session —
the manager is reachable as `client._file_manager` and its transport as
`client._file_manager.transport`.

**7 — duplicate chunk.** After accepting, send chunk 0 twice:

```python
t = client._file_manager.outgoing[list(client._file_manager.outgoing)[0]]
tr = client._file_manager.transport
tr.send_chunk(t.peer, t.offer.transfer_id, 0, t._sealed[0])
tr.send_chunk(t.peer, t.offer.transfer_id, 0, t._sealed[0])   # again
```

Expected on the receiver: `chunk 1 arrived out of order` — the index is
authenticated, so a replay cannot masquerade as the next chunk.

**8 — corrupted ciphertext.** Flip a byte before sending:

```python
bad = bytearray(t._sealed[0]); bad[7] ^= 0xFF
tr.send_chunk(t.peer, t.offer.transfer_id, 0, bytes(bad))
```

Expected: `chunk 0 failed authentication — transfer abandoned`, and
`.incoming/` empty. Specifically **not** a hash or size complaint: the AEAD
tag must catch it first, before anything is written.

**9 — wrong metadata.** Offer with a hash that does not match what will be
sent:

```python
fields = t.offer.encode().split("|")
fields[8] = "ab" * 32                      # a lie about the plaintext hash
client._file_manager.transport.send_control(t.peer, "OFFER", "|".join(fields))
```

Expected: the transfer runs and then fails at the end with
`plaintext hash mismatch`, with nothing placed in `files/`.

## What a pass actually establishes

That the lifecycle works over a real network between two real devices, and
that every failure path removes its temporary file. It does **not** establish
that Phase A is fast enough for video — step 4's timing is the number that
decides whether the torrent transport is worth building, and step 10 is there
to confirm it completes rather than to make it pleasant.

## What to record

For each step: pass or fail, the two SHA-256 values, elapsed time for steps 4
and 10, and anything printed that was not expected. Steps 4 and 10 timings are
the input to the transport decision; everything else is correctness.
