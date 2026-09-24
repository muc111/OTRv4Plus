# MLS feasibility study for OTRv4Plus group chat

**Status: study only. OTRv4Plus contains no MLS implementation, and no screen
claims one.** `MlsProvider` (Android) is a named seam that reports
`NOT_IMPLEMENTED`, and `EncryptionSelector` filters it out of every menu. Rooms
are XMPP MUC and are not end-to-end encrypted. The app says so and never calls
them MLS.

This report was written from the repository and from public specifications.
The live Prosody server is reachable only over I2P, and this development
environment could not reach it. Everything below about that server is
therefore marked **not inspected**, and the checks that remain are listed in
§19. Library facts (licences, cipher-suite support) are the maintainers'
published positions as understood when this was written. Re-check them before
starting any stage in §20.

---

## 1. Current Prosody support

**Not inspected.** The repository has no Prosody configuration, and the
server's version, module list and MUC settings could not be read. The code does
show:

* the server answers XEP-0030 disco and hosts a MUC component, which the rooms
  screen finds through disco (`XmppTransport.discover_services`) rather than
  guessing `conference.<domain>`;
* MAM support is probed read-only (`XmppTransport.archive_support`: `urn:xmpp:mam:2`,
  retract, moderate), and the answer is shown to the user.

Stock Prosody has no MLS awareness. An MLS design would have to treat it as an
untrusted relay and store (§6).

## 2. Relevant XMPP standards and extensions

* **RFC 9420** (MLS protocol) and **RFC 9750** (MLS architecture) are
  published IETF standards.
* **XMPP transport for MLS:** as far as this study could establish, the XSF has
  published no standards-track XEP for MLS. There have been experimental and
  inbox proposals, and interoperable client support is not established.
  **Verify the current XSF state before stage 3.**
* Standards the design would reuse: XEP-0045 (MUC) as the membership and
  presence channel; XEP-0313 (MAM) for storing ciphertext history; XEP-0060 or
  XEP-0163 (PubSub/PEP) for publishing KeyPackages; XEP-0030 and XEP-0115 for
  advertising MLS capability per resource (the same per-resource rule as
  `otrv4plus_caps`).
* OMEMO 2 (XEP-0384) is a different protocol. It is not MLS and is not a
  substitute. `Omemo2Provider` is likewise a non-functional seam.

## 3. Current MUC architecture

* Python `XmppTransport` joins, creates (and unlocks), leaves and destroys
  rooms through slixmpp `xep_0045`. Errors are classified by `otrv4plus_muc`.
* Room messages are **plaintext to the server**. The UI states this, and rooms
  are listed apart from 1:1 conversations.
* Room history deletion is local, plus honest reporting of what the server
  archive keeps (`ANDROID_CHAT_DELETION.md`).
* There is no group key, no group state and no per-member cryptographic
  identity.

## 4. Current OTRv4Plus architecture

* 1:1 only. It uses the OTRv4-style DAKE with an X448 + ML-KEM-1024 hybrid and
  Ed448 + ML-DSA-87 signatures, a double ratchet, and SMP. All secrets are in
  the Rust core (`Rust/src`) behind opaque handles and are explicitly
  zeroized.
* Python handles XMPP, SAM and orchestration only. Kotlin handles UI and the
  platform only.
* Calls use AES-256-GCM voice over I2P datagrams, keyed from the OTR session.
  Files are chunked AEAD inside the session.
* New in this cycle: per-resource capability discovery (`OTRV4PLUS_CAPABILITY.md`).
  An MLS feature would be advertised and discovered the same way.

## 5. What MLS adds

* Group key agreement that is efficient at size (a TreeKEM ratchet tree),
  instead of N pairwise OTR sessions.
* Forward secrecy and post-compromise security for groups, via epochs, updates
  and commits.
* Authenticated membership: every add and remove is a signed, ordered commit,
  and every member agrees on the member list for each epoch.
* It does **not** add deniability, which OTR has. It does not hide membership,
  timing or sizes from the server (§16). It does not replace SMP-style
  identity verification: credentials still need out-of-band checking.

## 6. Server requirements

MLS needs a **delivery service** (DS) that orders commits, and an
**authentication service** (AS) that binds credentials to identities.

* Ordering: for each group, commits must be applied in one agreed order. A MUC
  relays messages in arrival order but does not reject a second commit for the
  same epoch. Clients would therefore need a deterministic rule (for example,
  first commit seen for epoch *n* wins; later ones are discarded and their
  proposals re-sent), or the server would need a module that enforces it.
  Stock Prosody has no such module (**not inspected** on the live server).
* KeyPackage storage: PEP/PubSub nodes, one KeyPackage per use, with
  replenishment.
* Offline delivery of Welcome and commit messages: MUC does not queue for
  offline occupants, so this needs direct messages (offline storage) or MAM.
* All of this has to work over I2P, where latency makes commit races more
  likely than on clearnet.

## 7. Client requirements

* A Rust MLS engine that owns every secret: the tree, epoch secrets, the
  signature key and the HPKE init keys. Python and Kotlin would only see
  opaque group handles and ciphertext bytes, as with OTR today.
* Persistent group state, encrypted at rest (§11). Android today deliberately
  keeps OTR identity in memory only (B1: new identity per launch). MLS group
  membership **cannot** follow that model: a member who forgets their leaf
  secrets leaves the group. This is a real design conflict (§19).
* Capability discovery per resource. Only resources advertising an exact
  OTRv4Plus-MLS feature may be added.
* UI that states membership, epoch changes, and "not end-to-end encrypted"
  for plain MUC, with no silent fallback.

## 8. Rust libraries

| Library | Maintainer | Notes |
|---|---|---|
| **OpenMLS** | OpenMLS project (Phoenix R&D, Cryspen and others) | RFC 9420; pluggable crypto providers (RustCrypto, libcrux); active; has had external review. |
| **mls-rs** | AWS Labs | RFC 9420; pluggable crypto; used in production at AWS; supports custom cipher suites and extensions. |

**Cipher suites:**

* RFC 9420 defines `MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448` (0x0004), which
  matches this project's classical primitives.
* Neither RFC 9420 suite is post-quantum. PQ and hybrid suites (ML-KEM, X-Wing)
  are IETF drafts at the time of writing. Library support for them is
  experimental or absent. **Verify.**
* ML-DSA credentials are not in RFC 9420.

Matching OTRv4Plus's PQ posture would therefore need a custom or draft suite,
and custom suites break interoperability with every other MLS client.

## 9. Licences

* OpenMLS: MIT.
* mls-rs: Apache-2.0 OR MIT.

Both are compatible with this project's AGPL-3.0-only OR commercial dual
licence, provided the commercial licence text permits permissively licensed
dependencies (it should, but check). **Verify** each transitive dependency with
`cargo deny` / `cargo audit`, as is already done for `Cargo.lock`.

## 10. Interoperability

There is no interoperable XMPP MLS ecosystem to join (§2). An OTRv4Plus MLS
would talk only to OTRv4Plus, as the 1:1 protocol does. A custom PQ suite
would cut interoperability further. The claim to make is "OTRv4Plus ↔
OTRv4Plus group E2EE", never "MLS-compatible".

## 11. Persistence

Group state must survive app restarts, or members fall out of groups.

* Rust would serialise group state, encrypted under a key held in the Android
  Keystore (the existing `KeystoreVault` pattern), and zeroize it in memory
  when the group is closed.
* Wipe & Exit must destroy this state, and the group should see a leave or
  removal.
* This conflicts with B1 (ephemeral identity per launch) and needs an owner
  decision (§19).

## 12. History and MAM

* MLS gives a new joiner **no** access to messages from before their epoch.
  That is intended.
* MAM can store ciphertext. A member returning from offline replays commits in
  order, then messages. If the archive retention is shorter than the offline
  period, the member can no longer catch up and must be re-added.
* The server archive holds ciphertext plus metadata. Deletion semantics stay as
  in `ANDROID_CHAT_DELETION.md`: local deletion is not server deletion.

## 13. Multi-device

In MLS every device is its own leaf. Alice's phone and her Termux client are
two members, each with its own credential. That fits the per-resource model
already used for OTR capability. Linking devices to one person needs either an
AS-level binding or user-visible "Alice (phone)" / "Alice (Termux)" members.
Removing a lost device requires a commit from another member.

## 14. Recovery

* A lost device means removal plus a re-add with a new leaf. No history is
  recovered, by design.
* Corrupt local state means the member leaves and rejoins.
* A fork from diverging commits needs the deterministic ordering rule (§6)
  plus a resync path (re-join by Welcome). Without one, the group splits
  silently. This is the largest practical risk on high-latency I2P.

## 15. Authentication

MLS authenticates credentials, not people.

* Basic credentials, meaning the signature key bound to a JID, prove key
  continuity, not identity.
* The project's standard for identity is SMP or fingerprint comparison. For
  groups this would mean a per-member verification state ("verified via SMP in
  your 1:1 with Alice", using the OTR session to confirm her MLS signature key)
  or out-of-band fingerprint checks. Until then, the UI must show members as
  unverified.

## 16. Metadata exposure

Even with genuine MLS, the XMPP server and anyone watching it see:

* **membership**: occupant JIDs and resources, joins and leaves, and who
  commits adds and removes;
* **timing**: when each member sends, and when commits happen;
* **traffic patterns and sizes**: message counts and ciphertext lengths
  (padding helps only partly);
* **identifiers**: room JID, group ID, epoch numbers and sender leaf indices
  (unless encrypted as PrivateMessage), and KeyPackage publication.

I2P hides network location from the server. It does not hide any of the above.

## 17. Migration

* A plain MUC room cannot become an MLS group in place without every member
  consenting and supporting it. Stages would be: (a) a new "E2EE group" type,
  separate from rooms; (b) creation only when every invitee's resource
  advertises the feature; (c) no mixed plaintext and E2EE rooms.
* If a group is marked E2EE-required and a member or resource cannot do MLS,
  the client refuses to send to that group and says why. **It never falls
  back to plaintext MUC.**

## 18. Security risks

* A second, parallel crypto stack increases the attack surface. It must live in
  Rust, with no duplicated primitives: reuse the existing zeroize, AEAD and
  hash crates where the library allows.
* Commit races and forks on I2P, and state loss from B1.
* Custom PQ suites combine draft specifications with a less-reviewed code path.
* A malicious server can reorder, drop or withhold commits (denial of service,
  but not confidentiality loss) and sees all metadata (§16).
* UI risk: users reading "group E2EE" as "verified members". §15 addresses this.

## 19. Blockers

1. **No access to the live Prosody**: its version, modules, MUC configuration,
   MAM retention and PubSub availability were not inspected.
2. **No published XMPP MLS standard**, so there is no interoperability target.
3. **Post-quantum parity**: RFC 9420 suites are classical. Matching ML-KEM and
   ML-DSA needs draft or custom suites.
4. **Persistence against B1**: MLS membership requires persistent state. The
   owner must decide whether groups are allowed to break B1, for example
   persistent group state while the 1:1 identity stays ephemeral.
5. **Delivery ordering on MUC**: this needs a client rule or a server module.
6. **No physical multi-device test setup** was available.

## 20. Staged implementation plan (if approved)

1. **Decide.** The owner rules on B1 against persistent group state, and on a
   classical suite (0x0004, interoperable) or a draft PQ suite. Check the live
   server's modules, MAM retention and PEP.
2. **Rust spike, no UI.** Behind a feature flag, wrap the chosen library in the
   core. Expose opaque `GroupHandle` operations only (create, add, remove,
   commit, encrypt, decrypt) and zeroize every secret. Test two to four
   in-process members, including forks and resync.
3. **Transport.** Carry MLS messages in MUC and direct messages; publish
   KeyPackages over PEP; advertise an exact feature via disco and caps,
   resource by resource; add a deterministic commit-ordering rule. Integration
   tests over a local Prosody.
4. **Persistence and wipe.** Encrypted group state through the Keystore vault;
   Wipe & Exit destroys it; test crash recovery.
5. **Verification.** Bind MLS credentials to OTR-verified identities and show
   per-member verification state.
6. **UI.** A separate "Encrypted group" type with membership, epoch and
   verification shown. No MLS wording anywhere until stages 2–5 pass on two
   physical devices over I2P.
7. **Physical validation.** A group of at least three members over I2P,
   including offline catch-up, removal and device loss. Only then drop
   "experimental".

Until stage 7 passes, rooms stay plain MUC and are labelled "not end-to-end
encrypted".
