# Wipe & Exit (Android)

What it destroys, in what order, what it keeps, and what the guarantee is.
The policy is code: `android/.../security/WipeAndExit.kt` (executed by
`WipeAndExitTest`), `android_bridge/app.py` `OtrApp.wipe`,
`otrv4+.py` `EnhancedSessionManager.wipe`, and `android_bridge/wipe.py`.
Enforced as **INV-28** in [SECURITY_INVARIANTS.md](SECURITY_INVARIANTS.md).

**Handset status: not yet run on a device.** Everything below is host-tested
(Python, Rust and the plain-Kotlin plan) or checked from source; the
end-to-end run is step 35–49 of
[ANDROID_CALL_AND_FILE_DEVICE_TEST.md](ANDROID_CALL_AND_FILE_DEVICE_TEST.md).

## Three operations

| | Disconnect | Sign out | Wipe & Exit |
|---|---|---|---|
| Connection, tunnel, calls, transfers | ended | ended | ended |
| OTR sessions | ended | ended | **destroyed in Rust** |
| Saved account (JID, password) | kept | forgotten | **destroyed** |
| Message history, saved contacts | kept | this account's forgotten | **destroyed** |
| Vault key (AndroidKeyStore) | kept | kept | **deleted** |
| Received files; leftovers of older builds under `~/.otrv4plus` | kept | kept | **destroyed** |
| Identity / fingerprint | per process | per process | **destroyed**; a new one next launch |
| App | stays open | stays open | **process ends** |

Disconnect is never described as erasing anything. On the Connect screen the
three are separate buttons; the one that used to be labelled "Sign out" but
only disconnected is now labelled **Disconnect**. Wipe & Exit asks first and
says that it cannot be undone.

## Order

Each step is attempted even if an earlier one failed; a second request does
nothing. The process ending is the last step, always attempted.
(`WipeAndExit.Step`; changed 2026-09-28 -- see "The 11.28 MB report" below.)

1. **A. Stop background work.** The vault is **latched** first (`LatchedVault`:
   from here it refuses every write and read, and the latch waits for a write
   already in progress), then the drain loop (which writes arriving messages
   to the vault) and the reconnect loop are cancelled, so nothing writes back
   or reconnects behind the wipe. From here the service ignores every start
   request, and a screen opened in this process closes at once.
2. **B. Destroy every secret in Rust** (`OtrApp.wipe_crypto`), before anything
   that can wait on the network:
   1. *Calls*: force-closed, locally (`CallBridge.destroy_keys`): audio
      streams stopped, key schedule and key exchange zeroized. No END is
      sent -- it could not be encrypted once the keys are gone.
   2. *Transfers*: each FileKey holder zeroizes; each partial file is closed
      and unlinked.
   3. *OTR*, **on the transport's loop thread**: every ratchet (keys, DH
      handle, pending ML-KEM brace keypair), SMP state machine and vault,
      in-flight DAKE state and any unconsumed `DakeOutput`, and the identity
      and prekey handles are zeroized **in Rust, explicitly** -- not left to
      the garbage collector. The engine then refuses every entry point.
3. **Notifications**: all cancelled.
4. **Memory**: the conversation list, drafts, roster, rooms, call states,
   verification states and unread count.
5. **Vault**: the AndroidKeyStore key is deleted, then the vault files.
6. **C. Stop the subsystems** (`OtrApp.wipe`): call manager, SAM sessions and
   loop; the XMPP stream, I2P tunnel and loop thread; the room memberships
   and the in-memory diagnostics trace; the Python-side files (`~/.otrv4plus`,
   i.e. `files/.otrv4plus` under Chaquopy, and the engine's default log
   directory `~/.otrv4`, which Android does not write today) overwritten once
   with random bytes, fsync'd and unlinked. Bounded by network timeouts, which
   is why every secret is already gone.
7. **D. Wipe app storage** (`AppDataWipe`): **every entry** in the app's
   private data directory -- `files/` (the vault, the Python home, the
   extracted Python runtime), `cache/`, `code_cache/`, `databases/`,
   `shared_prefs/`, `no_backup/`, any `app_*` directory -- and in the
   app-specific external directories (`Android/data/org.otrv4plus.android/`).
   Not a list of known files. Symbolic links are removed, never followed; the
   system's `lib` link (the installed native libraries) is preserved. Before
   and after are measured (`AppDataWipe.Result`, sizes only).
8. **Exit**: the service stops (so it is not restarted as sticky), the task is
   removed from Recents, and the process is killed.

### The 11.28 MB report (2026-09-28)

A handset showed ~11.28 MB of user data and ~254 KB of cache in Settings after
Wipe & Exit. The wipe then deleted a list of known locations -- the vault
directory, the contents of `cache/`, and `~/.otrv4plus` -- and **kept by
design** `files/chaquopy/` (the extracted Python runtime: most of those
megabytes) and `shared_prefs/` (the theme). It never looked at `code_cache/`
(which Settings counts as cache), `databases/`, `no_backup/`, `app_*`
directories a library creates, or app-specific external storage. And the
Rust destruction ran sixth, after local steps, where the rule is that it runs
first. Both are fixed: the sweep is generic (step 7) and Rust goes first
(step 2). `AppDataWipeTest` populates a directory laid out like
`/data/data/<package>` with ~11.5 MB across all of those locations, plus a
link planted to point outside, and requires nothing to be left but the
system `lib` link.

### Verifying it on a device

The unit test proves the sweep; only a device proves the app. With a debug
build (`run-as` needs one):

```
adb shell run-as org.otrv4plus.android du -a . | sort -n | tail -40   # before
# use the app: sign in, chat, verify with SMP, receive a file, open diagnostics
adb shell run-as org.otrv4plus.android du -a . > before.txt
# Wipe & Exit in the app; the process ends
adb shell run-as org.otrv4plus.android find . -mindepth 1 | grep -v '^./lib$'
# expected: no output (the lib link is the system's)
adb shell dumpsys package org.otrv4plus.android | grep -i -A3 "dataDir"
# Settings > Apps > OTRv4+ > Storage: user data and cache should read 0 B
# (Settings may show a few KB for the empty directories Android recreates).
# Relaunch: the login screen, no contacts, no history, a new fingerprint.
```

### Why local state goes before the engine (the "conversations reappear" report)

Up to rc.1 the order was engine, notifications, memory, vault. The engine
step ends calls and closes the XMPP stream and the I2P tunnel, and each of
those waits on a network timeout (`CALL_TIMEOUT` 30 s, `CLOSE_TIMEOUT` 5 s),
so it can take tens of seconds. For all of that time the process was alive
with the conversation list in memory and every record still in the vault:

* reopening the app in that window showed every conversation, because the
  Activity read the still-populated `ChatState` of the still-running process;
* anything that ended the process in that window (the system, a force stop,
  a crash in the teardown) meant the memory and vault steps never ran, and the
  conversations were still there on every later launch;
* the drain loop is cancelled, not joined, so a message it was already
  storing could be written after the vault was cleared.

Memory, vault and cache are local and take milliseconds, and the engine reads
neither the vault nor `ChatState`, so they now run first; the vault is
latched before anything else; and `MainActivity` refuses to build a screen
while a wipe is in progress. `WipePersistenceTest` reproduces the report
(conversations → restart → present → wipe → restart → absent → restart →
absent, with the vault's contents inspected) and the late-write race.

### Why the engine is wiped on the loop thread

`DakeOutput` is `#[pyclass(unsendable)]`. PyO3 lets only its creating thread
touch it, and dropping it from any other thread **leaks it instead of
zeroizing it**. DAKE outputs are created while an inbound frame is processed,
which on Android happens on the transport's loop thread, so that is where the
wipe runs (`XmppTransport.run_on_loop_thread`). `test_wipe_and_exit.py` runs a
handshake on one thread and asserts the wipe ran there with no leak warning.

## Storage audit

Every place the app keeps state, classified. The authoritative list is
`WipeAndExit.STORES`; the test requires every entry except system-managed
state to name the step that destroys it. Step 7 does not depend on this list
being complete -- it removes every entry -- but the list is how a reader
knows what is there.

| Category | What | Where | Wipe step |
|---|---|---|---|
| Sensitive, persistent | Account credentials | vault `account.credentials` | Vault |
| Sensitive, persistent | Message history + index | vault `chat.<account>.*` | Vault |
| Sensitive, persistent | Saved contacts | vault `contacts.<account>` | Vault |
| Sensitive, persistent | Vault sealing key | AndroidKeyStore `otrv4plus.vault.v1` | Vault |
| Sensitive, ephemeral | Sessions, ratchets, DAKE, SMP | Rust | Crypto (B) |
| Sensitive, ephemeral | Identity and prekey | Rust (not persisted on Android) | Crypto (B) |
| Sensitive, ephemeral | Call keys, key exchanges | Rust / voice manager | Crypto (B) |
| Sensitive, ephemeral | Transfer keys, partial files | Rust / transfer manager | Crypto (B) |
| Sensitive, ephemeral | Trust pins, SMP auto-respond | Python engine | Crypto (B) |
| Sensitive, persistent | Received files | `files/.otrv4plus/` | Subsystems (C), then storage (D) |
| Sensitive, ephemeral | Audio, SAM, stream, tunnel, loop thread | Python transport | Subsystems (C) |
| Sensitive, ephemeral | Presence, OTR mode per peer | Python facade | Subsystems (C) |
| Sensitive, ephemeral | Conversation, drafts, roster, unread | `ChatState` | Memory |
| Sensitive, ephemeral | Notifications | NotificationManager | Notifications |
| Temporary | Outbox, scrubbed copies, diagnostics, "open with" hand-offs | `cache/` | Storage (D) |
| App data | Python runtime (re-extracted on launch) | `files/chaquopy/` | Storage (D) |
| App data | Theme | `shared_prefs/otrv4plus.ui.xml` | Storage (D) |
| App data | Anything else: `code_cache/`, `databases/`, `no_backup/`, `app_*` | data dir | Storage (D) |
| App data | App-specific external storage | `Android/data/<package>/` | Storage (D) |
| Sensitive, ephemeral | Python trace and error log | process memory | Exit |
| Sensitive, ephemeral | Recents snapshot | system | Exit |
| System-managed (kept) | Notification channel settings | system | -- |
| System-managed (kept) | Granted permissions | system | -- |
| System-managed (kept) | Installed APK and its `lib` link | package manager | -- |

Ratchet and session keys are never persisted (`RecordType.NEVER_PERSISTED`).
Files the user explicitly saved to shared storage (Downloads, a document the
picker chose) are the user's and are not touched.

## The guarantee, stated precisely

**Cryptographic erasure, for the vault.** Every vault record is AES-256-GCM
under a key generated in the AndroidKeyStore that has never left it (in a TEE
or secure element where the hardware has one). Deleting that key makes every
record unopenable, from this app, from a backup, or from a flash block the
controller has not yet erased. This is the strong guarantee and it does not
depend on the flash.

**Best-effort overwrite, for the Python-side files.** Received files (and
any pre-0.7.0 key-storage leftovers) are overwritten once and unlinked. On
flash, wear levelling and the translation layer may leave the old block until
the controller erases it; no app can prevent that, and this document does not
claim otherwise. What bounds the exposure is Android's file-based encryption
of app-private storage. The received files are the user's own decrypted
content — the same as any file they chose to keep.

**Memory.** Every Rust object holding a secret is told to zeroize before its
Python reference goes, and the tests check each object reports itself
destroyed *while the test holds a reference to it*. That proves the wipe
invokes the destruction; it cannot prove no copy exists elsewhere in the
process — that is the Rust core's `ZeroizeOnDrop` contract. Python `str`
values the user typed (the account password, an SMP secret) cannot be
overwritten by any means. The process is then killed, which releases the
interpreter and everything it held.

**Not covered.** A screenshot or screen recording the user or the system took;
anything the recipient has; server-side state (the XMPP server keeps the
roster and may have offline messages, which are OTR ciphertext).

## After a wipe

The next launch is a first launch: login screen, no contacts, no history, a
new identity and fingerprint. Peers will see the new key and must verify again
with SMP. The theme is back to its default. Notification channel settings and
granted permissions remain: they are the system's, not app storage.

**Signing in to the same account again brings back the server's roster, not
the history.** The conversation list shows every roster contact so a
conversation can be started with them, and the roster is held by the XMPP
server, not by the device. After a wipe those rows reappear with no messages,
no preview and no verification. That is server state, which a local wipe
does not and cannot remove; removing a contact from the server roster is a
separate, explicit action. Rooms are not rejoined: the app keeps no room
bookmarks, locally or on the server.
