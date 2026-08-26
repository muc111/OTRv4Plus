# Versioning

OTRv4+ had a versioning *convention* long before it had this document: a
`v10.MINOR.PATCH` line, bumped by hand, recorded in `CHANGELOG.md`. What it did
not have was a written rule about which files carry a version and which ones
must never be touched — and by v10.12.0 five files disagreed about what version
the project was on. This document exists so that cannot happen quietly again.

## Three tracks, deliberately not one number

| Track | Where | Current | Why it is separate |
|---|---|---|---|
| **Client** | `otrv4+.py` `VERSION`, `otrv4plus_xmpp.py` `XMPP_VERSION` | `10.13.0` | The thing a user runs and a peer must match. |
| **Crypto core** | `Rust/Cargo.toml`, `Rust/pyproject.toml` | `0.10.23` | A crate with its own release history; it is `0.x` because its API is not stable for outside consumers. |
| **Android app** | `android/app/build.gradle.kts` | `0.3.0-phase2+core.10.13.0` | An APK at an earlier maturity than the Termux client. Its own track, with the client version it embeds recorded as semver build metadata. |

The crate and the client are bumped together at a release, so a changelog entry
reads `VERSION → 10.13.0, otrv4_core 0.10.23`. The Android `versionCode` is a
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
