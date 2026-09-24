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

1. **Stop background work.** The vault is **latched** first (`LatchedVault`:
   from here it refuses every write and read, and the latch waits for a write
   already in progress), then the drain loop (which writes arriving messages
   to the vault) and the reconnect loop are cancelled, so nothing writes back
   or reconnects behind the wipe. From here the service ignores every start
   request, and a screen opened in this process closes at once.
2. **Notifications**: all cancelled.
3. **Memory**: the conversation list, drafts, roster, rooms, call states,
   verification states and unread count.
4. **Vault**: the AndroidKeyStore key is deleted, then the vault files.
5. **Cache**: files staged for sending, metadata-scrubbed copies, exported
   diagnostics.
6. **Wipe the engine**, while the transport still exists:
   1. *Calls*: each is ended, then anything left is force-closed, which stops
      the audio streams and zeroizes the key schedule and key exchange; the
      call event loop is drained, stopped and closed.
   2. *Transfers*: each FileKey holder is told to zeroize; each partial file is
      closed and unlinked.
   3. *OTR*, **on the transport's loop thread**: every ratchet (keys, DH
      handle, pending ML-KEM brace keypair), SMP state machine and vault,
      in-flight DAKE state and any unconsumed `DakeOutput`, and the identity
      and prekey handles are zeroized **in Rust, explicitly** — not left to the
      garbage collector. In-memory trust pins and SMP auto-respond secrets are
      cleared. The engine then refuses every entry point.
   4. *Transport*: closed (stream, I2P tunnel, loop thread).
   5. *Python-side files*: `~/.otrv4plus` (received files, partial transfers,
      and any leftovers of builds before 0.7.0, which wrote a key-storage
      seed) and the configured file directory,
      each file overwritten once with random bytes, fsync'd and
      unlinked. Symlinks are removed, never followed.
7. **Exit**: the service stops (so it is not restarted as sticky), the task is
   removed from Recents, and the process is killed.

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
`WipeAndExit.STORES`; a store missing from it is a store the wipe does not
know about, and the test requires every non-configuration entry to name the
step that destroys it.

| Category | What | Where | Wipe step |
|---|---|---|---|
| Sensitive, persistent | Account credentials | vault `account.credentials` | Vault |
| Sensitive, persistent | Message history + index | vault `chat.<account>.*` | Vault |
| Sensitive, persistent | Saved contacts | vault `contacts.<account>` | Vault |
| Sensitive, persistent | Vault sealing key | AndroidKeyStore `otrv4plus.vault.v1` | Vault |
| Sensitive, persistent | Received files (the engine itself writes nothing since 0.7.0) | `~/.otrv4plus/` | Engine |
| Sensitive, ephemeral | Sessions, ratchets, DAKE, SMP | Rust | Engine |
| Sensitive, ephemeral | Identity and prekey | Rust (not persisted on Android) | Engine |
| Sensitive, ephemeral | Trust pins, SMP auto-respond | Python engine | Engine |
| Sensitive, ephemeral | Call keys, audio, SAM | Rust / voice manager | Engine |
| Sensitive, ephemeral | Transfer keys, partial files | Rust / transfer manager | Engine |
| Sensitive, ephemeral | Stream, tunnel, loop thread | Python transport | Engine |
| Sensitive, ephemeral | Presence, OTR mode per peer | Python facade | Engine |
| Sensitive, ephemeral | Conversation, drafts, roster, unread | `ChatState` | Memory |
| Sensitive, ephemeral | Notifications | NotificationManager | Notifications |
| Temporary | Outbox, scrubbed copies | cache `outbox/` | Cache |
| Temporary | Exported diagnostics | cache `diagnostics/` | Cache |
| Sensitive, ephemeral | Python trace and error log | process memory | Exit |
| Sensitive, ephemeral | Recents snapshot | system | Exit |
| Configuration (kept) | Chaquopy runtime, bundled code | `files/chaquopy/` | — |
| Configuration (kept) | Notification channel settings | system | — |
| Configuration (kept) | Granted permissions | system | — |

The app writes no SharedPreferences, DataStore or SQLite/Room database.
Ratchet and session keys are never persisted (`RecordType.NEVER_PERSISTED`).

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
with SMP. Notification channel settings and granted permissions remain.

**Signing in to the same account again brings back the server's roster, not
the history.** The conversation list shows every roster contact so a
conversation can be started with them, and the roster is held by the XMPP
server, not by the device. After a wipe those rows reappear with no messages,
no preview and no verification. That is server state, which a local wipe
does not and cannot remove; removing a contact from the server roster is a
separate, explicit action. Rooms are not rejoined: the app keeps no room
bookmarks, locally or on the server.
