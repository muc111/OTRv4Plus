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

## The commands

```
/sendfile <path>                 offer a file to the peer in the active chat
/transfer                        list transfers, both directions
/transfer accept <id>            accept an offer (first 8 hex chars is enough)
/transfer decline <id>
/transfer cancel <id>
```

## The ten steps

| # | Step | What to run | Pass condition |
|---|---|---|---|
| 1 | **Tiny text file** | `echo hello > test.txt` then `/sendfile test.txt` | Arrives; `sha256sum` matches both sides |
| 2 | **Binary file** | a small PNG or JPG | Byte-identical; opens correctly in a viewer |
| 3 | **Awkward filename** | `photo of café (1).jpg`, and one with an emoji | Lands under a sanitised name, no error, nothing outside `~/.otrv4plus/files/` |
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
