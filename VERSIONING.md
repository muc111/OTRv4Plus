# Versioning

OTRv4+ had a versioning *convention* long before it had this document: a
`v10.MINOR.PATCH` line, bumped by hand, recorded in `CHANGELOG.md`. What it did
not have was a written rule about which files carry a version and which ones
must never be touched — and by v10.12.0 five files disagreed about what version
the project was on. This document exists so that cannot happen quietly again.

## Three tracks, deliberately not one number

| Track | Where | Current | Why it is separate |
|---|---|---|---|
| **Client** | `otrv4+.py` `VERSION`, `otrv4plus_xmpp.py` `XMPP_VERSION` | `10.25.3` | The thing a user runs and a peer must match. |
| **Crypto core** | `Rust/Cargo.toml`, `Rust/pyproject.toml` | `0.10.28` | A crate with its own release history; it is `0.x` because its API is not stable for outside consumers. |
| **Android app** | `android/app/build.gradle.kts` | `0.3.0-phase2+core.10.14.0` | An APK at an earlier maturity than the Termux client. Its own track, with the client version it embeds recorded as semver build metadata. |

The crate and the client are bumped together at a release, so a changelog entry
reads `VERSION → 10.14.0, otrv4_core 0.10.26`. The Android `versionCode` is a
monotonically increasing integer because Android requires that; it carries no
other meaning.

## What the client number means

Semantic versioning, with one project-specific reading of MAJOR.

- **MAJOR** — reserved. It is not the wire-break signal, because OTRv4+ has
  never promised cross-version wire compatibility (see below), so breaking the
  wire cannot be what distinguishes a major release.
- **MINOR** — new capability. Voice calling, the XMPP transport, the hybrid PQ
  SMP were each MINOR bumps.
- **PATCH** — fixes and hardening within an existing capability.

### Wire compatibility is not encoded in the version

> Both peers must run the **same** version. There is no fallback path, no
> negotiation, and no interoperability with stock OTRv4.

That policy predates this document and is unchanged by it. It means the version
string is a *release* identifier, not a compatibility predicate — the wire
formats carry their own version bytes for that, and those are what a peer
actually checks.

## Version numbers that are NOT release versions

These are wire-format revisions. They are compatibility predicates, they are
pinned by `tests/test_protocol_version.py`, and **they must never be bumped to
mark a release**:

| Constant | Value | Meaning |
|---|---|---|
| `OTRConstants.PROTOCOL_VERSION` | `4` | ClientProfile / DAKE format |
| `OTRv4DataMessage.PROTOCOL_VERSION` | `0x0005` | data-message format (incremented by the MKmac fix) |
| `VOICE_PROTOCOL_VERSION` | `4` | voice frame header |
| SMP wire byte | `0x01` / `0x02` / `0x03` | classical / hybrid-PQ (SHAKE stretch) / hybrid-PQ (Argon2id stretch) |

Bumping one of these invalidates every peer that speaks the old format. Bump it
when, and only when, that format actually changes — and add a test that pins the
new value, as the existing ones do.

## Releasing

1. Decide MINOR or PATCH from the rule above.
2. Update every file in the table at the top. All of them, in one commit.
3. Add a `CHANGELOG.md` section: version, date, what changed, and the verification
   actually run (test counts from a real run, not from the previous entry).
4. Update the README badge and any "as of vX.Y.Z" line in `FEATURES.md`,
   `DEVELOPMENT.md` and `SPEC.md`.
5. Leave the wire constants alone unless the wire genuinely changed.

A grep that should return one version and no other:

```bash
grep -rn 'VERSION = "OTRv4+\|^XMPP_VERSION\|^version' \
     otrv4+.py otrv4plus_xmpp.py Rust/Cargo.toml Rust/pyproject.toml
```

## Dependency versions are part of the release

Three of the four version numbers above are ours to choose. The fourth kind —
the version of a dependency in `Rust/Cargo.lock` — is not, and it is the one
that has security consequences, so it gets a rule of its own.

**A dependency on the cryptographic or Python/Rust boundary is pinned by the
lock file, and the lock file is release evidence.** `Cargo.toml` records an
intent (`pyo3 = "0.29"`); `Cargo.lock` records what was compiled into the
artifact someone is running. When a release claims an advisory is remediated,
the lock is what backs the claim — `tests/test_dependency_advisories.py`
asserts against the lock for that reason, and asserts the manifest floor
separately so a later `cargo update` cannot walk back to a vulnerable release.

**PyO3 compatibility, as of v10.19.0 (pyo3 0.29.2):**

| Constraint | Value | Where it is enforced |
|---|---|---|
| Rust MSRV | 1.85 (ours; pyo3 0.29 needs 1.83) | `rust-version` in `Rust/Cargo.toml` |
| Python floor, ABI | `abi3-py39` | `Rust/Cargo.toml` features |
| Python floor, source | **3.12** — `otrv4+.py` uses PEP 701 f-string spacing | `requires-python` in `Rust/pyproject.toml` |

The two Python floors differ on purpose and it is not a mistake to fix in
passing: the *extension module* is abi3 and loads on 3.9+, while the *client
source* does not parse below 3.12. Dropping `abi3-py39` to match would give up
forward compatibility of the compiled `.so` across interpreter versions for no
gain.

A PyO3 bump is a PATCH or MINOR of the crate depending on whether our own API
moved, but it is never a silent one: it needs the full procedure in
[DEVELOPMENT.md](DEVELOPMENT.md#upgrading-pyo3) and a `SECURITY.md` entry if an
advisory prompted it.

## Why v10.14.0

v10.13.3 → v10.14.0 is a MINOR bump: a new capability. `/sendfile` sends an
encrypted file over an authenticated XMPP session. `otrv4_core` moves to
`0.10.26` alongside it, because the file cryptography is a new Rust module.

**XMPP only.** The IRC client has no file transfer, imports nothing from the
transfer module, and its OTR and TLV behaviour is unchanged — the feature
rides a prefixed OTR message body exactly as voice signalling does, which is
why it needed no change to the shared engine at all.

**Both peers need this build** to exchange files, for the usual reason: a
peer without `RustFileSender` cannot key a transfer. Chat and voice between a
v10.13.3 peer and a v10.14.0 peer are unaffected.

The encrypted-file format carries its own version byte (`FILE_FORMAT_VERSION`,
currently `1`), independent of the client version. That byte is in the AAD of
every chunk, so it cannot be changed without both sides noticing.

## Why v10.13.3

v10.13.2 → v10.13.3 is a PATCH bump: a fix and its hardening within an existing
capability. `otrv4_core` was **unchanged at 0.10.25** — nothing in that release
touched Rust, so bumping the crate would have claimed a release it did not have.

The client number moves for two reasons, one of them visible on the wire:

* `/names`, `/list` and `/help` printed the literal string
  `[IRC line suppressed]` in place of every line, from v10.11.0 onwards.
* the realname (gecos) this client advertises at registration now always ends
  with the version. It did not for 27 Club nicks or for a NickServ-registered
  nick, so those users were undetectable as OTRv4+ by their peers. Other IRC
  users will see the changed realname, which is why this is a client-version
  change rather than a silent fix.

Neither is a protocol change. A v10.13.2 peer and a v10.13.3 peer interoperate
exactly as before — the same-version rule above is unaffected by this release,
though it still applies for every other reason.

## Why v10.13.2

A PATCH bump: no new capability, and nothing on the wire moved.  Voice media
keys and the voice X448 private scalar moved from Python into Rust-owned
zeroizing memory, and the SMP passphrase stopped being copied into an
immutable `bytes` on its way to the vault.  The media-key derivation is
byte-identical -- same HKDF-SHA512, same labels, same four-byte length
prefixes -- and `tests/test_voice_rust_parity.py` proves it against a
reference built from primitives rather than from the code under test.

**Both peers must run the same build anyway.**  Not because the format
changed, but because this is the first release where the media path is
Rust-only: a peer whose `otrv4_core` predates `RustVoiceCipher` cannot make a
call at all, and fails at startup rather than mid-call.

## Why v10.13.1

A PATCH bump: security hardening within existing capabilities, no new
capability and no wire change.  SMP wire version `0x03` is untouched; the
media frame format is untouched.  The changes are a remotely armable input
capture removed, a hand-rolled Python cipher deleted, the log boundary made
fail-closed, media rejections classified by cause, and two rekey
state-machine defects fixed.  Sixteen security invariants are now enforced by
`tests/security_invariants.py` and `SECURITY_INVARIANTS.md`.

Both peers should still be updated together, for the same reason as always:
the rekey fixes change what one side does with the other's messages, and a
mixed pair gets the old behaviour in one direction.

## Why v10.13.0

v10.12.0 → v10.13.0 is a MINOR bump: SMP wire version `0x03` derives the secret
scalar with Argon2id, salted with the session ID and both fingerprints, where
`0x02` stretched the passphrase alone through 50,000 rounds of SHAKE-256. That
is new capability — memory-hardness, and a salt that makes a precomputed
dictionary worthless — not a fix to existing behaviour.

It is *not* MAJOR. Under the rule above, breaking the wire is not what makes a
release major, because OTRv4+ has never promised cross-version compatibility.
Nothing else changed: no other key schedule, no message authentication rule, no
replay window, no ratchet, no voice cryptography. The `0x02` derivation is
retained byte-for-byte and pinned by a frozen test vector, so the change is
confined to which stretch a `0x03` session selects.

It is not PATCH, because `0x03` is a new wire format and both peers must be
updated together for SMP to complete at all.

### Why v10.12.0

v10.11.1 → v10.12.0 was a MINOR bump: end-to-end encrypted voice over I2P moved
from "newest and least-tested surface" to a path with detection, diagnosis and
authenticated recovery around it, and none of that existed in v10.11.1.

It is *not* MAJOR. No cryptographic primitive, key schedule, media
authentication rule, replay window, call-identity binding or endpoint
authentication changed in this cycle — the recovery work changes **when** a
media endpoint is replaced, never what protects it. It is not PATCH either,
because `MEDIAPATH` is a new authenticated control message and the recovery
state machine is new behaviour, not a fix to old behaviour.
