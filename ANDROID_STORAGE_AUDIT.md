# Sensitive storage audit

Phase 2 deliverable (§13). Every sensitive data category the current codebase
handles, what happens to it today, and what replaces it on Android.

The rule this document exists to enforce: **the existing plaintext storage
architecture must not be carried into Android by default.** Anything not
assigned a replacement below is a gap, not an omission.

Verified against the source, not from memory. Paths and mechanisms were
enumerated from the actual write sites in `otrv4+.py`, `otrv4plus_log.py` and
`otrv4plus_xmpp.py`.

---

## Summary table

| # | Data | Current storage | Current encryption | Key source | Plaintext exposure | Android replacement | Phase |
|---|------|-----------------|--------------------|------------|--------------------|---------------------|-------|
| 1 | **OTR identity (Ed448 seed, X448 prekey)** | **not persisted at all** | n/a | n/a | none on disk; regenerated every launch | `SealedStore` record `otr.identity`, DEK wrapped by Keystore | 2 (interfaces) / 4 (vault) |
| 2 | **Device seed** (`~/.otrv4plus/keys/.device_seed`) | file, mode 0600 | **none — plaintext 32 bytes** | itself: it *is* the credential | **full** — whoever reads the file derives the storage key | deleted; replaced by Keystore-wrapped DEK | 4 |
| 3 | **Stored keys** (`~/.otrv4plus/keys/*.bin`) | files, 0600 | AES-256-GCM (Rust) | Argon2id/scrypt over the plaintext device seed (#2) | effectively full — key material is one file read away | `SealedStore`, same AEAD, Keystore-held key | 4 |
| 4 | **Trust database** (`~/.otrv4plus/trust.json`) | JSON file | **none — plaintext** | n/a | **full** — peer JIDs and pinned fingerprints readable | `SealedStore` record `otr.trust` | 4 |
| 5 | **SMP auto-respond secrets** (`~/.otrv4plus/smp_secrets.json`) | file | AES-256-GCM (Rust) | same plaintext device-seed pattern as #2 | effectively full | `SealedStore` record `otr.smp`; reconsider persisting at all | 4 |
| 6 | **Channel / message logs** (`~/.otrv4plus/logs/channels/*.enc`) | files | **hand-rolled AEAD** — SHAKE-256 keystream XOR + HMAC-SHA3-512 truncated to 16 bytes | **plaintext key file** `~/.otrv4plus/channel_log.key` (0600) | effectively full — and this file holds **complete message bodies** | `SealedStore` record `otr.message` using the Rust AES-256-GCM; bespoke construction removed | 4 |
| 7 | **Application log** (`~/.otrv4plus/logs/otrv4plus.log`) | rotating file, 0600 | **none — plaintext** | n/a | protocol state and errors; no message bodies observed | no file logging in release; dev-only structured logging | 2 (bridge) / 3 |
| 8 | **Session transcript log** (`~/.otrv4plus/logs/session-*.log`) | file | **none — plaintext** | n/a | **redacted** — `_LOG_CONTENT_RE` replaces bodies with `<message body redacted: N chars>` | removed on Android | 2 |
| 9 | **Ratchet state** (root/chain/brace keys) | **memory only, inside Rust** | n/a — `SecretBytes`, `ZeroizeOnDrop` | n/a | **none** | unchanged; **must never be persisted** | — |
| 10 | **Session keys** (DAKE output) | **memory only, Rust→Rust move** | n/a | n/a | **none** on the live path (see M3) | unchanged | — |
| 11 | **SMP protocol state** (exponents, ML-KEM/ML-DSA keys) | memory only, `RustSMPVault` | n/a — `SecretVec`, zeroized | n/a | **none** in production builds (read-back is `test-only-kdf`-gated) | unchanged | — |
| 12 | **Contact list / roster** | not stored locally — fetched from the XMPP server | n/a | n/a | none locally | `SealedStore` record `otr.contact` for local cache | 6 |
| 13 | **Call metadata** (peers, times, durations) | not persisted; in-memory `VoiceCallSession` | n/a | n/a | none | `SealedStore` record `otr.call`, or do not persist | 8 |
| 14 | **Voice audio** | **never written to disk** — captured, encoded, sealed, transmitted | n/a | n/a | **none** | unchanged; must stay non-persistent | — |
| 15 | **Application configuration** (`OTRConfig`) | constructed in memory; CLI-driven | n/a | n/a | none sensitive today | `SealedStore` record `app.config` once settings exist | 4 / 12 |
| 16 | **Authentication metadata** (throttle counters) | does not exist yet | n/a | n/a | n/a | `SealedStore` record `auth.metadata` — must be encrypted, or an attacker resets the throttle by clearing a file | 4 |
| 17 | **Termux bootstrap marker + `.bashrc` edit** | `~/.otrv4plus/.bootstrap-v*`, appends to the user's shell profile | none | n/a | none sensitive | not applicable on Android; must not ship | 2 |

---

## The four that matter most

**#2 / #3 — the device seed is the whole storage key.** `SecureKeyStorage`
derives its AES key with Argon2id (or scrypt) from a 32-byte seed that sits
next to the ciphertext in plaintext. The KDF adds nothing against an attacker
with filesystem access: they read the seed and derive the same key. This is the
single largest at-rest weakness, and it is exactly what Android Keystore fixes —
the wrapping key becomes non-exportable, so possession of the files stops being
sufficient.

**#4 — the trust database is plaintext JSON.** Peer identifiers and their pinned
fingerprints, in the clear. That is a contact graph: who the user talks to, and
enough to detect when they change identity. It leaks association even though it
contains no key material.

**#6 — the message log is the worst combination.** It holds full message bodies,
under a **bespoke AEAD** (SHAKE-256 keystream XOR plus a 16-byte truncated
HMAC-SHA3-512), keyed by a **plaintext file** in the same directory. The
specification forbids inventing constructions, and the key file makes the
encryption decorative regardless of the construction's quality. It is not
obviously broken as a design — encrypt-then-MAC, domain-separated, random 96-bit
nonce per record — but there is no reason to keep a hand-rolled scheme when
`aes256gcm_encrypt` is already in the Rust core and already used by the other
two stores.

Note also that `print()` is globally shadowed and routes **every UI line** into
this log. The separate session log (#8) does redact bodies; the channel log does
not. On Android that file *is* the message database.

**#9–#11, #14 — what is already right.** Ratchet state, session keys, SMP state
and voice audio never touch disk. That is the correct policy and Android must
not weaken it. `RecordType.NEVER_PERSISTED` encodes this in the Kotlin layer so
that a future contributor cannot quietly add a "cache the ratchet for faster
resume" feature: there is no record type to write it under, and a test asserts
there never is.

---

## Android storage policy

Every category above resolves to one of three outcomes:

1. **Sealed record.** `SealedStore` / `AesGcmSealedStore`, AES-256-GCM with a
   fresh CSPRNG 96-bit nonce per operation, AAD binding record type, record id,
   schema version and key id, under a DEK wrapped by a Keystore key.
2. **Not persisted.** Ratchet state, session keys, SMP state, voice audio.
   Enforced by having no record type.
3. **Removed.** Termux bootstrap, shell-profile edits, file logging, the session
   transcript log, the bespoke channel-log AEAD, and the plaintext device seed.

Nothing sensitive may reach `SharedPreferences`, plaintext SQLite, assets,
resources, the manifest, logs, clipboard, screenshots or backups.
`android:allowBackup="false"` plus matching `dataExtractionRules` are already
set, so a sealed record cannot be copied off the device to a place where the
Keystore key that protects it does not exist.

---

## What is still open

- **#1 identity persistence is blocked on a security decision** — see
  `SECURITY_ISSUES.md` entry B1-seed. A Rust-generated seed cannot be exported,
  so persisting an identity requires either generating the seed in Python
  (weakening the boundary) or adding Rust-side sealing (recommended).
- **#5** — whether SMP secrets should be persisted at all deserves review. They
  exist for auto-respond convenience; storing a verification secret at rest
  weakens the property SMP provides.
- **#13** — call metadata is currently not persisted. Introducing a call history
  would create a new sensitive category; the default should be not to.
- **Migration** — there is no migration path from the existing desktop layout,
  and none is proposed. An Android install starts fresh. If importing a desktop
  identity is ever wanted, it is a separate design with its own threat model.
