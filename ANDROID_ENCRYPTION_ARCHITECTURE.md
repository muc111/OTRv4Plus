<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright (C) 2025-2026 muc111 -->

# Three encryption systems, one boundary

> OTRv4+ is an I2P-first private communications client. It has three surfaces:
> the IRC terminal client, the XMPP terminal client, and a **native Android app
> under construction**. The terminal clients running under Termux are the
> supported way to use OTRv4+ today. See [README.md](README.md#project-status).

This document covers the Android client's encryption architecture, the account
boundary underneath it, and — plainly — what is not implemented.

Three tiers are used throughout, because they are easy to blur and the
difference is the whole value of a document like this:

| Tier | Meaning |
|---|---|
| **Executed** | A test runs the code and asserts its behaviour. |
| **Compiled** | CI builds it and assembles an APK. No test executes a line. |
| **Not implemented** | Named in the type system, and does nothing. |

---

## 1. The account boundary

Everything below assumes this, because an encryption architecture on top of
leaky storage protects nothing.

### 1.1 The defect

Bob was signed in with a conversation with Alice. Dave signed in on the same
handset and Alice ↔ Bob was still there.

The storage schema had no account in it:

```
Conversations ──► Messages
```

A conversation was identified by the **peer's** JID alone, so Bob's history
with Alice and Dave's history with Alice were one vault entry, under one name,
in one global index. Two accounts talking to the same person was not a case the
schema could represent.

### 1.2 The shape it has now

```
Account ──► Conversations ──► Messages
```

`AccountScope` supplies the account half of every vault entry name. A
cross-account read is not something the UI must remember to avoid — it is
something the storage cannot express.

* **Bare JID, case-folded.** The resource is per-session, so
  `bob@host/phone` and `bob@host/desktop` are one account; splitting them would
  halve a person's history at every reconnect.
* **Hashed.** Vault entry *names* are not sealed, only values are. A listing of
  `chat.bob@server.i2p.<peer>` would be a plaintext record of who uses this
  phone and who they talk to. This is **not** a security boundary — anybody
  holding the file can confirm a guessed JID — it stops the names being a
  contact list.
* **`AccountScope.NONE` is a real value**, not null and not "the last account".
  A store bound to it reads nothing and writes nothing, which closes the window
  between the process starting and an identity being established.

`ChatState.bindAccount` is the boundary for state that never reaches a disk —
roster, drafts, open conversation, unread — and `ChatState.accepts` is the
ingestion guard for a listener held by a replaced session.
`OtrConnectionService.enterAccount` applies both at the single point every
route to an authenticated session passes through.

Pre-existing history is **deleted, not migrated**: the old scheme recorded no
account, so nothing in the data says whose it is.

**Executed**, by `AccountIsolationTest` (29 tests). Re-planting the defect —
the account contributing nothing to the key — fails 9 of them.

---

## 2. The provider boundary

```
                     EncryptionProvider
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
  OtrV4PlusProvider   Omemo2Provider       MlsProvider
     1:1, native      group + 1:1, XMPP    group, prototype
        │                   │                   │
  Rust OTRv4+ core    python-omemo /       MlsTransport
   (DAKE, SMP,          twomemo                 │
    ratchet)          (NOT PRESENT)      I2P datagrams
```

`EncryptionProvider` is a **question surface, not a crypto API**. Nothing on it
takes or returns key material. The only things crossing the line are a
conversation reference, a body, and a state.

That constraint is what makes the MLS boundary cheap later: an interface that
leaked OTR's session handle or OMEMO's device id would need a third shape for
MLS, which is the rewrite this design exists to avoid.

### 2.1 What the UI may ask

Is it available here; what is the state; establish; encrypt; decrypt; forget
this account. Six questions, identical for all three.

### 2.2 No silent downgrade

There is no "encrypt, or send plaintext if you cannot". `EncryptionOutcome` has
no success-with-plaintext case and cannot be given one without changing the
interface file. `EncryptionSelector.mayFallBack` returns `false` for every
pair, and is a function rather than a missing feature so a test can point at
it.

`EncryptionSelector.defaultFor` returns **null**, never `EncryptionKind.NONE`,
when nothing is usable. "We could not offer you encryption" and "you chose to
send in the clear" are different facts.

### 2.3 Shape decides what is offered

| | 1:1 | Group/MUC |
|---|---|---|
| OTRv4+ | **default** | not applicable |
| OMEMO 2.0 | offered | **default** |
| MLS | not applicable | not implemented |

OTRv4+ in a room is not a weaker option but a meaningless one: OTR is a
two-party protocol and a MUC message is fanned out by the service to everybody
present. MLS in a 1:1 would be a second answer to a question OTRv4+ already
answers, with SMP and a verified fingerprint.

**Executed**, by `EncryptionArchitectureTest` (43 tests).

---

## 3. OTRv4+ — unchanged

`OtrV4PlusProvider` is an **adapter, not a reimplementation**. The DAKE, the
ratchet, SMP, X448, ML-KEM, ML-DSA and the Rust core are exactly where they
were. Nothing in `otrv4plus_*` or in the Rust core changed to make the
abstraction fit; if it had, the abstraction would be the wrong shape.

**The security ladder is not flattened.** `SecurityState` has four rungs and
the mapping keeps the distinction SMP exists for:

| SecurityState | EncryptionState | Meaning |
|---|---|---|
| `PLAINTEXT` | `INACTIVE` | nothing established |
| `ENCRYPTED` | `ACTIVE` | the DAKE ran; **nobody checked who answered** |
| `FINGERPRINT` | `ACTIVE` | a fingerprint was seen, not confirmed |
| `SMP_VERIFIED` | `VERIFIED` | the peer proved who they are |
| `FINGERPRINT_MISMATCH` | `FAILED` | encrypted, and that is not the point |

If `ENCRYPTED` and `SMP_VERIFIED` both read as "encrypted", SMP has no product
meaning at all.

`encrypt` reports **readiness**, not ciphertext. OTRv4+ does not expose
encryption as a separate step — the engine owns the session and `sendUserText`
encrypts and fragments in one call. Pulling those apart to satisfy an interface
would mean a second code path through the most security-critical part of the
application.

**Executed** for the adapter. The protocol itself is covered by the existing
suite and is unchanged by this milestone.

---

## 4. OMEMO 2.0 — half implemented, and which half

### 4.1 What is present

`otrv4plus_omemo` implements the XMPP half of XEP-0384 (`urn:xmpp:omemo:2`):

* device lists at `urn:xmpp:omemo:2:devices` and bundles at
  `urn:xmpp:omemo:2:bundles`, over PEP;
* **recipient derivation from room membership, never from presence** — see
  below;
* which bundles must actually be fetched, so a session is not rebuilt per
  message (on I2P that is a round trip per device per message);
* stale-device-list detection;
* room anonymity capability detection;
* failure classification into codes the UI renders.

**The rule that matters.** A recipient set built from the occupant list a UI is
showing silently excludes anyone offline, with no error anywhere — the sender's
message simply never arrives for someone. `recipients_for_room` takes
membership and device lists and **has no presence parameter at all**, so the
rule is enforced by the signature rather than by remembering to obey it. It
returns the members whose device list is missing rather than dropping them.

The second form of the same mistake — leaving out the sender's own other
devices — is covered too: the message is delivered, the recipient reads it, and
it is unreadable on the sender's laptop, which looks like data loss.

**Executed**, by `tests/test_omemo_rules.py` (54 tests).

### 4.2 What is NOT present, and exactly why

**The cryptography.** There is no key agreement, no ratchet, and no encryption
of any kind. `Omemo2Provider` reports `Availability.NOT_IMPLEMENTED` and every
operation fails with `EncryptionError.UNAVAILABLE`.

This is a **build blocker, not a design gap**. OMEMO 2's cryptography is
implemented by `python-omemo` / `twomemo`, the reference implementations, and
writing a second Double Ratchet for a security product is the worst kind of
wheel to reinvent. The dependency chain is:

```
slixmpp-omemo 2.2.0
  └── twomemo 2.1.0  (urn:xmpp:omemo:2)
        ├── X3DH 1.3.0 ──────┐
        ├── DoubleRatchet 1.3.0 ──► cryptography, pydantic
        ├── XEdDSA 1.2.0 ──► libxeddsa  (C library)
        └── protobuf
```

Verified against PyPI on 2026-09-16:

| Package | Android wheel on PyPI | Note |
|---|---|---|
| `xeddsa` 1.2.0 | **none** | CFFI binding to `libxeddsa`, a C library |
| `cryptography` | **none** | Rust extension |
| `pydantic-core` | **none** | Rust extension |
| `protobuf` | **none** | pure-Python fallback exists |

Each would have to be cross-compiled for `arm64-v8a` and `x86_64`, the way
`otrv4_core` already is. That is tractable — CI has the NDK toolchain and
already cross-compiles a Rust extension — and it is packaging work, not
protocol work. Whether Chaquopy's own index supplies any of them could not be
checked from the build container, which does not have network access to
`chaquo.com`; that is the first thing to establish.

**Not claimed:** interoperability with any other OMEMO client. Nothing has been
tested against anything, because there is nothing to test yet.

---

## 5. MLS — a boundary, not an implementation

```
MLS group state
       ↓
MLS protocol engine          ← does not exist
       ↓
MlsTransport                 ← exists, this is the point
       ↓
I2P datagram transport
       ↓
I2P
```

`MlsProvider` reports `Availability.NOT_IMPLEMENTED` for a group and
`NOT_APPLICABLE` for a 1:1 — two different "no", because one is a permanent
design decision and the other is a temporary gap.

**Why write the seam now.** A named provider that says "not implemented" is
checkable: the selector filters it out of every menu and a test asserts it
never appears as usable. A missing provider is not checkable, and the first
thing anyone adding one would do is discover whether the abstraction fits —
which is the discovery this file makes cheap.

`MlsProvider` holds an `MlsTransport` it never uses, deliberately. A version
taking no transport would be free to grow a direct dependency on XMPP or on
Android the moment somebody implemented it.

**Why datagrams.** MLS handshake and application messages are self-contained;
it is a message protocol, not a byte stream. I2P repliable datagrams fit
directly, and framing them onto the SAM stream the XMPP client uses would mean
inventing a length prefix and a reassembler for something that already has
message boundaries. It also keeps the two apart operationally: the XMPP stream
carries the user's account and is authenticated to a server, and MLS group
traffic has no business sharing that session.

**When it is implemented:** the engine must not know about Android and must not
know about XMPP MUC. It talks to `MlsTransport` and nothing else.

**Not claimed:** anything. No interoperability, no key schedule, no group
operations.

---

## 6. Cryptographic separation

Each provider owns its own state. There is no shared key material, no shared
session store, no shared ratchet, and no method on `EncryptionProvider` through
which one provider could reach another's.

| Question | Answer |
|---|---|
| Can OMEMO access OTRv4+ private state? | No — no reference exists |
| Can MLS access OMEMO private state? | No |
| Can an account boundary reach into the OTR session store? | No — `OtrV4PlusProvider.forgetAccount` is deliberately a no-op; the engine's teardown belongs with the connection |
| Is any key reused across providers? | No |

`forgetAccount` clears that provider's own state and never another's.

---

## 7. Privacy in diagnostics

Unchanged from the previous milestone and extended to the new layers.
`otrv4plus_alias` replaces every identity with a label (`user-A`, `address-B`,
`room-C`) centrally, in `trace._safe`, before anything is recorded.

Everything new here follows the same rule:

* `otrv4plus_omemo.classify` never returns an exception's text — an OMEMO error
  can carry a JID, a device id and key material;
* `Device.__repr__` prints the device id and not the account;
* `MlsTransport.TransportOutcome.code` is a short code, never a message from
  below, because a SAM error text can contain an I2P destination;
* every sentence in `CODES` is checked by test to contain no `@` and no `.i2p`.

---

## 8. Status summary

| Component | Status |
|---|---|
| Account isolation | **Executed** — 29 tests, defect re-planted and caught |
| Chat layout fix | **Compiled** — 17 source tests; not verified on a screen |
| Provider abstraction | **Executed** — 43 tests |
| OTRv4+ adapter | **Executed** |
| OMEMO XMPP layer | **Executed** — 54 tests |
| OMEMO cryptography | **Not implemented** — dependency chain has no Android wheels |
| OMEMO MUC encryption | **Not implemented** — recipient derivation is executed; nothing encrypts |
| MLS provider | **Not implemented** — boundary only |
| MLS transport | **Not implemented** — interface only |

**No physical handset acceptance has been performed for any of it.**
