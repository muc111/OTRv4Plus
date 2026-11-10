# App lock with a passphrase: audit and design

Status: **Android built (2026-11-09); desktop and terminal not yet.**
§7 says what was built and where it differs from this design. Sections 1-6
are the audit and design as written on 2026-11-06.

The request: a Molly-style app passphrase. Local data under a 256-bit key that
the passphrase unlocks. The passphrase flushed from memory once it has been
used. Settings for the auto-lock timeout, change passphrase and remove
passphrase. This document records what the code does today, whether the
request is feasible, and how to build it without overclaiming.

---

## 1. What is encrypted at rest today (audited)

| Data | Platform | Cipher | Where the key lives |
|---|---|---|---|
| Account password, message history (`vault`) | Android | AES-256-GCM, name bound as AAD | AndroidKeyStore key (TEE/StrongBox), non-exportable, **no user authentication** |
| Identity keys (`identity-vault`) | Android | sealed in Rust, then the vault | same Keystore key |
| Contact pins (`trust-vault`) | Android | the vault | same Keystore key |
| Secure-group state (`groups-*.sealed`) | Android | AES-256-GCM (Rust) | **`groups.dek`, a 32-byte key file beside it** |
| Received files (`*.otrv`) | Android | AES-256-GCM container (Rust) | **files DEK, a 32-byte key file beside them** |
| Partial transfers (`*.part`) | all | AES-256-GCM | `RunKey`, process memory only, never written |
| Every key file under `~/.otrv4plus` | desktop | key files wrapped (`at_rest.rs`) | 256-bit KEK in Secret Service / Keychain (`key_custody`); plain if neither is available |
| Key files | terminal / Termux | none | plain files, mode 0600 |

What works well:

- DEKs and KEKs are held in Rust (`SecretBytes` / `Zeroizing`, zeroized on
  drop). Python works through handles and never holds their bytes.
- Rust already has the primitive an app lock needs.
  `set_key_wrapping_key(kek)` installs a 32-byte KEK, copying it and zeroing
  the `bytearray` it came from. `clear_key_wrapping_key()` forgets it again.
  After that, no wrapped key file opens in this process.
- Argon2id (the `argon2` crate, `zeroize` feature) is compiled into every
  build through the default `pq-rust` feature, so Android has it too.

## 2. Already designed, not yet built

`android/.../security/` holds the Phase 2 contracts for exactly this
request:

- **`AppLockManager` + `LockState`** — the lock state machine and relock
  timer. The timer uses a monotonic clock and fails closed if the clock goes
  backwards. Relocking releases the key handle.
- **`UnlockCredentialService`** — credential → Argon2id → KEK → unwrap DEK.
  The credential arrives as a `CharArray` so it can be wiped. A wrong
  passphrase and a corrupted record fail identically. A change of passphrase
  re-wraps the DEK and re-encrypts no data.
- **`AttemptThrottle`** — slows repeated wrong guesses.
- **`KeystoreManager` / `DataKeyHandle` / `SecureStore`** — key custody
  behind an opaque handle.
- **`Argon2idParams`** — enforces a 32-byte output and at least 8 MiB of
  memory. It ships `NEEDS_CALIBRATION` (t=3, 64 MiB, p=4, `calibrated=false`).

None of these has a production implementation, and nothing in the app
uses `AppLockManager`. That was left deliberately fail-closed. **The work is
to implement these contracts, not to invent new ones.**

## 3. Findings

**F1 — the app lock is not built** (§2).

**F2 — on Android, group state and received files are not covered by the
Keystore.**
- `groups.dek` and the files DEK are plain key files beside the data they
  protect.
- The desktop wraps those same files under its keyring KEK; Android never
  installs a KEK (`key_custody` is desktop-only).
- They are protected only by the app sandbox and Android's own file-based
  encryption. A forensic extraction of an unlocked (after-first-unlock)
  phone reads them.
- This is weaker than the vault, and inconsistent with it. The app lock fixes
  it as a side effect, because the lock installs one KEK over every key file
  (§4).

**F3 — passwords are held as Kotlin `String`.**
- The sign-in and change-password screens (`ConnectScreen`,
  `ChangePasswordSection`) keep the XMPP password in `mutableStateOf("")`.
- A `String` cannot be overwritten. It stays in the heap until garbage
  collection, and can be copied by the GC on the way.
- The passphrase input must never become a `String`. These two screens
  should follow it.

**F4 — the Argon2id parameters are placeholders.** Release must measure them
on a low-end phone and ship them with `calibrated = true`. The existing
release checklist already requires this.

**F5 — keys can reach swap.**
- Rust zeroizes keys, but does not `mlock` them.
- Android swaps to compressed RAM (zram), so a page holding a key could be
  copied there before it is zeroized.
- `mlock` on the few key pages fits inside Android's small per-process lock
  limit.

**F6 — the Keystore key can be used while the phone is locked.**
`setUserAuthenticationRequired(false)` is deliberate: the background service
must reconnect with the screen off. The passphrase layer is what will protect
the data. The passphrase key's Keystore half should add
`setUnlockedDeviceRequired(true)` on Android 9 and later, so it cannot be
used while the phone itself is locked.

## 4. Feasible: yes. The design

### Key hierarchy

```
passphrase ──Argon2id(salt, calibrated cost)────────────► P   (256 bits)
salt ───────HMAC-SHA-256 inside AndroidKeyStore/StrongBox► H   (256 bits; key never leaves the chip)
KEK  = HKDF-SHA-512(P ‖ H, info = "otrv4plus app-lock v1")     (256 bits)

DEK  = 256 random bits, made once at enrolment
on disk: salt ‖ AES-256-GCM_KEK(DEK)     (the AEAD tag is the verifier;
                                          nothing to compare a guess against)

unlocked: DEK → Rust only
          · installed as the key-wrapping key (set_key_wrapping_key), which
            opens every key file: identity, groups, files, SMP, pins
          · opens the Kotlin vault through a DataKeyHandle
```

**Why `H` matters.** Argon2id alone would let anyone who copies the files
guess passphrases on a GPU farm. `H` is computed inside the phone's secure
hardware by a key that cannot be exported. So every guess has to run on the
phone itself, paying the Argon2id cost and the `AttemptThrottle` delays.
Without the phone, the KEK is a full 256-bit unknown.

### Unlock, and flushing the passphrase

Each hop keeps the passphrase for as short a time as possible and wipes what
it held.

1. **Typing.** A passphrase field that writes keystrokes into a `CharArray`
   and draws dots. It never builds a `String`. The keyboard is told password
   type, no autocorrect, and `IME_FLAG_NO_PERSONALIZED_LEARNING`, so the
   keyboard app does not learn the passphrase. `FLAG_SECURE` is already set
   on the activity.
2. **Kotlin.** The `CharArray` is encoded to a UTF-8 `ByteArray` and the
   `CharArray` is zeroed. That buffer goes through Chaquopy as a Python
   `bytearray` (never `bytes`, which cannot be wiped), and the Java array is
   zeroed.
3. **Rust.** The bytes are copied into `Zeroizing` memory and the
   `bytearray` is zeroed, the same pattern as `set_key_wrapping_key`.
4. **Derivation.** Argon2id, whose working memory is zeroized by the
   crate's `zeroize` feature, then the hardware HMAC, then HKDF.
5. **Cleanup.** `P`, `H` and the KEK are dropped and zeroized the moment the
   DEK is unwrapped. **From then on, no copy of the passphrase or the KEK
   exists in any layer.** Only the DEK remains, in Rust, `mlock`ed (F5).

### Locking means signing out

While the app is locked, nothing can decrypt anything, so the app cannot stay
connected. Lock runs the existing sign-out path, and then:

- ends OTR sessions with their closing messages, so deniability holds;
- calls `clear_key_wrapping_key()`;
- seals and drops group state and closes the vault `DataKeyHandle`, which
  zeroizes the DEK;
- clears the conversation screens' in-memory caches.

**Nothing sent to you while locked is lost.**
- 1:1 senders queue the message until you are online with an OTRv4+ session.
  They never fall back to plaintext.
- Secure-group messages replay from the room's history when you rejoin.

The cost: no notifications while locked. This is the same trade-off Molly
makes.

### Settings

- **App lock** — on or off.
  - Turning it on enrols: a passphrase and a fresh DEK. Existing vault
    entries and key files are re-wrapped under it.
  - Turning it off requires the current passphrase, and re-wraps the DEK
    under the Keystore key alone, which is today's protection.
- **Lock after the app is in the background** — immediately, 30 s, 1 min,
  5 min, 15 min, or 1 h. Uses the existing grace timer. **Lock now** is a
  separate action.
- **Change passphrase** — requires the current one. Re-wraps the 32-byte DEK
  only, so it is instant whatever the amount of data.
- **Wrong-passphrase handling** — `AttemptThrottle` backoff. An optional,
  off-by-default "erase after N failed attempts" runs Wipe & Exit.
- **No recovery.** A forgotten passphrase means the data is gone. That is
  what makes the lock worth having, and enrolment must say so before it
  finishes.

## 5. What "256-bit" means, honestly

- **Keys.** The DEK, the KEK and every cipher are AES-256. Argon2id and HKDF
  output 256 bits.
- **Someone with a copy of the files but not the phone** faces a 256-bit
  unknown, because the hardware half `H` cannot be extracted.
- **Someone with the phone** is limited by the passphrase. A 12-character
  random passphrase carries about 70–80 bits, not 256. Every guess runs on
  the phone, pays the Argon2id cost and is throttled. The passphrase strength
  meter must state this, not imply 256 bits.
- **While unlocked,** the DEK is in RAM. Code running as this app, or anyone
  who can read its memory, can use it. No app-level design avoids this,
  because unlocked means the data is readable.
- **Zeroizing shortens how long a secret is held. It is not a guarantee.**
  The JVM, the keyboard app and the kernel can keep copies we cannot reach.
  The design keeps the passphrase out of `String`, wipes every buffer we
  control, and keeps the DEK in Rust. It does not claim the memory is clean.

## 6. Build plan

1. **Rust `AppLock`.**
   - Functions: enrol, unlock, rewrap and disable.
   - Keys held in `mlock`ed memory.
   - Unlock installs the key-wrapping key; lock zeroizes everything.
   - Tests: wrong passphrase, tampered record, rewrap, and that zeroization
     happens.
2. **Android Keystore half.**
   - A `KeystoreManager` implementation with a non-exportable HMAC key,
     StrongBox where present.
   - `setUnlockedDeviceRequired(true)`.
   - The detected `SecurityLevel` shown in Settings.
3. **Wiring.**
   - `AppLockManager` driven by the activity lifecycle.
   - Lock leads to sign-out and zeroize.
   - The `UnlockCredentialService` implementation.
   - Calibrate Argon2id on a low-end phone (F4).
4. **Screens and Settings.**
   - The `CharArray` passphrase field.
   - Unlock, enrolment and change-passphrase screens.
   - Settings: app lock on/off, timeout, lock now.
   - Move the XMPP password fields to the same input (F3).
5. **Desktop and terminal.**
   - The same Rust `AppLock`.
   - On the desktop, the passphrase wraps the KEK instead of, or on top of,
     the keyring.
   - The terminal gains its first protection beyond 0600 files.

## 7. What was built (Android, 2026-11-09)

| Piece | Where |
|---|---|
| Data key, KEK derivation, record, vault layer | `Rust/src/app_lock.rs` (tests in the file) |
| Python surface for Kotlin | `android_bridge/app_lock.py`, `tests/test_app_lock.py` |
| Hardware HMAC (StrongBox, else TEE) | `AppLockKeystore` in `security/KeystoreVault.kt` |
| Vault layer | `security/LockLayerVault.kt` (`LockLayerVaultTest`) |
| Set-up, unlock, change, off, lock, auto-lock | `security/AppLock.kt` |
| Screens | `ui/AppLockScreens.kt`: unlock screen, own profile → App lock |

**As designed:**
- KEK = HKDF-SHA-512(Argon2id(passphrase) ‖ H), where H = HMAC-SHA-256(salt)
  inside the Keystore. The passphrase key is `setUnlockedDeviceRequired`
  where the phone allows it.
- The 256-bit DEK is made and held in Rust. Subkeys of it are:
  - the key-wrapping key for every key file;
  - the key for an inner AES-256-GCM layer on every vault record (default,
    identity and trust sections), bound to the record's name.
- The record is 113 bytes: header, nonce, and the wrapped DEK. The AEAD tag
  is the only verifier. A wrong passphrase and a damaged record fail the same
  way. The Argon2id cost is stored in the record and bounded when read.
- The passphrase field is an `EditText` read into a `CharArray`. It never
  builds a `String`, autofill is off, and the keyboard is told not to learn
  it. Kotlin, Python and Rust each zero their copy. Python and Rust accept
  only a `bytearray`.
- **Locking signs out, then the process ends.** The connection is closed,
  Rust zeroizes the DEK, and no JVM or Python heap survives.
- A locked vault **throws**; it never answers "nothing stored". This is what
  stops a new identity being made over a sealed one.
- Turning the lock off re-wraps the DEK under a second Keystore key alone,
  with no unlocked-device requirement. That is the protection the app had
  before the lock. The data is not re-encrypted.
- Change passphrase re-wraps the 32-byte DEK only.
- Wrong guesses go through `AttemptThrottle`. The counter is persistent and
  survives a restart.
- Wipe & Exit deletes both Keystore keys and the record.

**Different from the design, and why:**
- **No `mlock` (F5 stays open).** The crate is `#![forbid(unsafe_code)]`;
  `smp_vault` dropped its `mlock` for the same reason. Ending the process on
  lock is the mitigation.
- **Set-up is two steps.** `enrol` makes the key and returns the record.
  `commit` starts using the key only after the record is synced to disk. A
  crash in between loses nothing.
- **Existing records are sealed at set-up** (`sealAllSections`). Any record
  missed is sealed the next time it is read.
- **Key files are wrapped on their next read** (`at_rest` re-wraps a plain
  key file in place once a KEK is installed), not all at once. Until a key
  file is next used it keeps its old protection: the sandbox and Android's
  file encryption.
- **No "Immediately" auto-lock.** Leaving the app for a file picker, the
  camera or a permission prompt would lock it. The shortest choice is 30 s.
  An auto-lock never ends a call in progress; it waits for the call to end.
- **The auto-lock timer may fire late under Doze.** The check made when the
  app returns uses a clock that counts sleep, and locks before anything is
  shown. That check is what the lock relies on.
- **The Phase 2 contracts are not all used.** `AttemptThrottle`, `LockState`'s
  rule (late callbacks cannot unlock) and `SecurityLevel` are used. The DEK
  lives in Rust, so `DataKeyHandle` / `KeystoreManager` / `AppLockManager`,
  which assumed a Kotlin-held handle, are replaced by `AppLockCrypto` and
  `AppLock`.
- **The passphrase is not Unicode-normalised.** Normalising would need a
  `String`. The same keyboard gives the same bytes; a different keyboard
  might not.

**Still open:**
- F4: Argon2id is t=3, 64 MiB, p=4, not yet measured on a low-end phone.
- The XMPP password fields still use `String` (F3).
- No "erase after N failed attempts" option.
- Desktop and terminal.
