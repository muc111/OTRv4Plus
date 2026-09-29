# Physical test plan: pre-merge handset validation

**Status: NOT RUN.** This is the checklist for the handset session that must
happen before `claude/otrv4plus-android-spec-a3oq4d` can be merged. Nothing
below has been performed on a phone. Every item names what automated work
already covered, so a failure on the handset points at the gap rather than
at the whole feature.

**Equipment.** Two Android phones (A, B) with the APK from the branch's latest
Android CI run; one Termux peer (T) on the same branch; the project's Prosody
server over I2P. Optional: a clearnet TLS XMPP account and Tor (Orbot) for the
voice transport rows.

**Record for every step:** PASS / FAIL / NOT RUN, the time, and on FAIL the
exported diagnostic report (Debug → Export). Screenshots of any Settings
storage figures.

---

## 0. Transport selection and X1 (first, before anything else)

Automated coverage: `tests/test_transport_route.py`,
`tests/test_x1_destination_pinning.py`, `ReconnectPolicyTest`.

1. **Clearnet `yax.im` (no CAPTCHA), then `07f.de`.** Fresh install.
   Another server… → `yax.im`, a new username. First press **Test server**
   (no password needed). **Pass:** "Server test: reached",
   `registration_available`, `Reached: tcp_connected,tls_established,
   xmpp_stream,registration_form`. Then a strong password, **Create
   account**. **Pass:** "Account created", or a named server refusal
   (`conflict`, `not_allowed`, ...) -- never `network`. Debug → trace must
   show `dns_plan srv=found targets=xmpp.yax.im:5222`, `tcp_connected`,
   `tls_established certificate=verified`, `form_received`, `submitted`,
   `accepted`. Then **Log in**: connected. Repeat for `07f.de`: expect
   `dns_plan ... targets=xmpp.07f.de:5222`, and if it wants a CAPTCHA,
   `registration_captcha_required` with "Your password was not sent".
   On FAIL, export the diagnostic report: the `failed_at` line names the
   stage and the OS reason (e.g. `tcp_failure reasons=ENETUNREACH`).
   Try once on Wi-Fi and once on mobile data (IPv6 differs).
2. **Clearnet failure is named.** A non-existent domain → a DNS/TCP/TLS
   failure sentence, never a router one.
3. **Default I2P server, router running.** "Checking for an I2P router" then
   tunnels; login works. Debug trace: `destination_accepted basis=first use`,
   then `destination_pinned`. Log out, log in again: `basis=pinned`.
4. **I2P without a router.** Fails at "Checking for an I2P router" in
   milliseconds (unchanged).
5. **X1 warning (only if a second destination can be arranged**, e.g. by
   editing the router's address book to point the name elsewhere). **Pass:**
   "Security warning: the server's address changed" with both addresses; no
   automatic retry; "Keep the old address" leaves it refused; "Trust new
   address…" asks again and does not connect by itself.
6. **Onion (optional, Orbot).** Without Orbot: "Checking for Tor" fails with
   `tor_unavailable`, no clearnet attempt. With Orbot: connects.

---

## 1. Wipe & Exit (the 11.28 MB report)

Covered automatically: ordering, crypto destroyed in Rust before teardown,
every Python root and the diagnostics trace cleared, no state recreated after
the wipe (`tests/test_wipe_and_exit.py`, `WipeAndExitTest`). **Not** covered:
what Android's Settings reports afterwards, and flash residue (never claimed).

1. On A: sign in, exchange ≥20 messages with B, verify with SMP, receive two
   files (one image, one PDF), open each once, join a room and a secure
   group, start and end one call.
2. Settings → Apps → OTRv4+ → Storage: record **User data** and **Cache**.
3. Wipe & Exit, confirm. The app must close and leave Recents.
4. Settings → Storage again: record User data and Cache. **Pass:** User data
   at the size of a fresh install (record that figure first on a spare
   install); Cache ≈ 0. **If available** (`adb shell run-as` on a debug build):
   list `files/ cache/ databases/ shared_prefs/ no_backup/ code_cache/`; only
   the system `lib` link may remain.
5. Relaunch: a **new fingerprint** (compare with the one noted in step 1), no
   conversations, no contacts, no received files, no rooms or groups, no
   saved account, not verified with B (B must see a fingerprint change).

## 2. SMP

Covered automatically: SMP after chat adds no message; success; wrong secret;
already verified; cooldown; retry after it; simultaneous start; late and
mid-run abort; three-failure lock (Rust); dual-bridge Android↔Termux engine.

1. A↔B: ≥5 ordinary encrypted messages each way first.
2. A starts SMP with a question. **Pass:** no blank bubble on either side; B
   is asked for the answer; both show verified.
3. New session (Disconnect/reconnect on A): verification must NOT carry over.
4. Wrong answer from B: both show failed. Retry immediately → "wait" message.
   Retry after 30 s → works.
5. Three wrong answers in a row (30 s apart): the third locks; a fourth start
   is refused with a reason.
6. Cancel mid-run on A: neither side verified; chat keeps working.
7. Both press Verify at once: one run; answering it verifies both.
8. Repeat 2 and 4 **A↔T** (Termux), both directions.

## 3. Reconnect and handshake recovery

Covered automatically: lost DAKE1/2/3, peer restart, glare, replayed
handshake, rate-limited recovery, verification not carried to new keys, no
plaintext on any of those paths.

1. A↔B encrypted and verified; exchange messages.
2. Toggle A's network (Wi-Fi → mobile → Wi-Fi), then airplane mode 60 s.
   **Pass:** reconnects, OTR re-establishes without a user action or with one
   "Start", messages flow encrypted, verification shows as needing SMP again.
3. Force-stop B mid-conversation, relaunch: A's next message recovers the
   session (no plaintext, no stuck "in progress").
4. Where practical, drop one handshake message (airplane mode during Start)
   and retry: recovery within the rate limit, no loop.
5. Both press Start simultaneously: exactly one session, working.

## 4. File transfer

Covered automatically: container sealing, byte-flip/truncate/reorder
refusal, open/save/export bridge paths, overwrite, the Chaquopy dict-decode
regression, Welcome/room isolation.

1. A→B: image and PDF. B sees the incoming prompt, Accepts, sees progress.
2. B: **Open** each (viewer shows it; nothing left in `cache/view` after
   closing, if inspectable). **Save** to Downloads; save again with the same
   name → replaced, not "name (1)".
3. Corrupted transfer: cut the network mid-transfer on A; B shows failed, no
   partial file listed as received.
4. A→T and T→A once each.

## 5. Voice

Covered automatically: counters' definitions, SMP gate at answer on both
sides, media crypto and rekey (host), telemetry summary.

For each transport available (I2P required; clearnet TLS and Tor optional):
1. Unverified peer: the call button says SMP is required; no call starts.
2. Verified: A calls B, B answers; two-way audio within the documented setup
   time. Record the summary line (played / missing / shed / dropped).
3. Long call: ≥15 min on I2P; record the counters at the end.
4. Failure: turn B's network off mid-call; both sides end the call with a
   reason; a new call works afterwards.

## 6. People, Welcome room, deletion

Covered automatically: history-on-join delivery (the dropped-message bug),
People list relations/search/details, Welcome creation wording, deletion
cutoff against history replay.

1. The **People (n)** button sits beside Connected; tap → list with search;
   type part of a name → filtered; tap a row → details; Add on an
   "Online — Add" row sends a request (B sees "Wants to add you").
2. Welcome room: joined automatically after sign-in and listed in Chats;
   messages sent in it **before** A joined (room history) appear after
   joining. If the server has none: the create offer shows the not-E2EE
   warning; a refusal says the server's settings prevented it.
3. Delete a 1:1 chat (long press): gone; contact still in People; stays gone
   after reconnect; a new message brings it back.
4. Delete a room chat and stay in the room: reconnect → the old history does
   **not** reappear; a new room message brings the chat back with only new
   lines. "Delete and leave" leaves the room; nothing claims server deletion.

## 7. MLS secure groups

### 7a. Termux A + Termux B + Android C in one group

Build each Termux core with MLS: `cd Rust && bash build.sh` (it runs
`maturin develop --release --features mls`; the import line must say
`secure groups (MLS): yes`). All three on the same XMPP server, which must
offer a MUC service (e.g. `conference.<domain>`). Room used below:
`circle@conference.<domain>`. Record PASS/FAIL per step.

1. **OTRv4+ first.** A: `/otr <B>` and `/otr <C>`; B: `/otr <C>`. Optionally
   `/smp` each pair (verified members show as `verified`).
2. **Create.** A: `/group create circle@conference.<domain>`. **Pass:**
   `[group circle@...] created (epoch 0)`.
3. **Invite.** A: `/group invite circle@... <B>` and `/group invite
   circle@... <C>`. **Pass:** B prints `invites you to the secure group`;
   C shows the invitation on its conversation list.
4. **Accept.** B: `/group accept circle@...`; C: Accept on the phone.
   **Pass:** B prints `joined (epoch N)`, C shows the group; A prints
   `member_added` twice. `/group members circle@...` on A and B lists all
   three with the same epoch.
5. **All three talk.** A: `/group say circle@... from A`; B: `/group say
   circle@... from B`; C: type in the group. **Pass:** every message appears
   on the other two, marked encrypted; the server/room never shows text.
6. **Remove.** A: `/group remove circle@... <B>`. **Pass:** B prints `you
   were removed`; A and C show a new epoch.
7. **Removed member cannot read.** C then A send a message. **Pass:** A and
   C read both; B prints nothing for them (B is still in the room, receiving
   ciphertext it cannot decrypt).
8. **Restart.** A: `/quit`, start the client again, reconnect. **Pass:**
   `1 secure group(s) restored: circle@...`; C sends; A reads it; A replies;
   C reads it.
9. **Plaintext refused.** From any ordinary client join `circle@...` and
   send plain text. **Pass:** A and B print `room_plaintext_refused`, never
   the text; C does not show it.
10. **Wipe.** B: `/wipe`. **Pass:** the client exits; `~/.otrv4plus` is
    empty; starting again shows no secure groups.
11. **Offline miss (documented limitation).** With B's client stopped
    (after `/quit`), A: `/group rekey circle@...` twice, then messages. Start
    B. **Expected:** if the room history no longer holds those commits, B
    prints `could not be decrypted ... remove you and invite you again` and
    shows nothing wrong; recovery is remove + re-invite (steps 6, 3, 4).

### 7b. Android-only checks

Covered automatically: in-process groups (create, add, remove, removed
member cannot decrypt, concurrent commits, persistence, HPKE cross-check),
bridge event paths.

1. A creates a secure group; invites B and T (or a third phone). All three
   exchange messages. **Pass:** each shows the others' messages as encrypted.
2. Add a fourth member; they read new messages only.
3. Remove B; B cannot read messages sent after removal (B's app shows
   removed / no new messages).
4. Identity: each member's OTRv4+ verification state is shown; an unverified
   member is marked.
5. Restart A and reconnect: the group and its history persist and new
   messages decrypt.
6. A public/discoverable room is NOT E2EE unless it is a secure group: check
   the room screen says which.

## 8. Not part of this session

Physical flash erasure (never claimed), router-applied tunnel length (not
measured; the app only requests it). X1 is implemented and covered by §0.
