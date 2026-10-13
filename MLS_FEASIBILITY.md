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
   ML-DSA needs draft or custom suites. *Decided: the draft PQ suite, see
   section 21.*
4. **Persistence against B1**: MLS membership requires persistent state. The
   owner must decide whether groups are allowed to break B1, for example
   persistent group state while the 1:1 identity stays ephemeral. *Decided:
   group state and its signing key persist, encrypted in the Keystore vault
   and destroyed by Wipe & Exit; the 1:1 identity stays fresh per launch.*
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

## 21. Stage 2 result: the Rust provider (2026-09-24)

**Owner decisions.** Ciphersuite `MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87`
(0x0907, draft-ietf-mls-pq-ciphersuites) on OpenMLS 0.9.0, with the core's own
primitives. Group state persists (section 19, item 4).

**What exists.** `Rust/mls` (crate `otrv4-mls`), separate from `otrv4_core`
like `opus-codec`, because it needs one `unsafe` FFI call and the core keeps
`#![forbid(unsafe_code)]`.

| MLS needs | Supplied by |
|---|---|
| ML-KEM-1024 | PQClean via `pqcrypto-mlkem` 0.1.1, as the core. Seeded key generation calls PQClean's `crypto_kem_keypair_derand`, which the crate compiles but does not export (the only `unsafe`). |
| ML-DSA-87 | PQClean via `pqcrypto-mldsa` 0.1.2, as the core's DAKE (FIPS 204, empty context). |
| AES-256-GCM, HKDF/HMAC/SHA-384 | `aes-gcm` 0.10, `hkdf`/`hmac` 0.12, `sha2` 0.10, the core's versions. |
| HPKE (RFC 9180) composition | `hpke-rs` 0.7 over our backend at stage 2; replaced at stage 3 by `src/hpke.rs` (section 22). |
| Randomness | the OS (`getrandom`). |

Any other suite, hash, AEAD, KEM or signature scheme is refused with an error.
Signing keys live in a `SignatureKeyPair` that wipes on drop and never prints
key bytes.

**One new primitive implementation.** `hpke-rs` derives ML-KEM seeds with
SHAKE-256 from `libcrux-sha3` (Apache-2.0, formally verified), a hard
dependency of `hpke-rs`. It is used only for that derivation, and the result is
cross-checked below.

**Tests** (`cargo test --release` in `Rust/mls`, run by the Python workflow):

* A three-member group: create, add two members in one commit, join from the
  Welcome, messages in all directions, a member's key update, removal. The
  removed member cannot read the next epoch or export its secrets. Every
  message goes through its wire bytes.
* A tampered message is rejected. Other suites are refused.
* **Independent cross-check** against OpenMLS's reference provider
  (`openmls_rust_crypto`: RustCrypto `ml-dsa` and a separate ML-KEM,
  test-only). Derived HPKE public keys are identical, HPKE seal/open and
  export work in both directions, ML-DSA-87 signatures verify in both
  directions, and a mixed group (one member on each provider) joins, talks and
  follows a key update.

**Not done at stage 2.** Stages 3 to 7. See section 22 for where they
stand now.

**Before it ships (stage 2 note, resolved in section 22).** `hpke-rs` and
`hpke-rs-crypto` are MPL-2.0. Rather than ask the owner to accept a
file-level copyleft component under the commercial licence, stage 3
replaced them in the build.

## 22. Stages 3–6 result (2026-09-28)

Status labels: **automated** = covered by tests that run in CI; **not
physically verified** = no handset or live server has run it yet. Stage 7
(physical validation) has not started, so nothing here is claimed to work
over I2P between phones.

### What changed from the plan in section 20

| Plan | Done instead | Why |
|---|---|---|
| KeyPackages published over PEP | KeyPackage, invitation and Welcome sent **inside an encrypted OTRv4+ 1:1 session** (`?OTRv4-MLS:` bodies) | The session authenticates who sent the KeyPackage, which is the identity binding stage 5 needs. PEP would publish a key per account for anyone to fetch (enumeration) and bind it to nothing. |
| State in the Keystore vault | Sealed by Rust under a key derived from `FileDek` (a 0600 key file in app-private storage) | Keeps the MLS secrets inside Rust end to end; the Keystore path would hand the plaintext state or its key to Kotlin. Weaker at rest than a hardware-backed key: anyone who can read app-private storage can open it. Recorded as a limitation. |
| hpke-rs | `Rust/mls/src/hpke.rs` | Removes an MPL-2.0 component, a second SHA-3 (libcrux-sha3) and an unmaintained proc-macro from the build. hpke-rs stays a dev-dependency and `tests/hpke_cross.rs` checks the new code against it byte for byte. |

### Stage 3: transport (automated; not physically verified)

* `otrv4_core.RustMlsClient` (`Rust/src/mls_group.rs`, feature `mls`, on in
  the APK and wheel builds) wraps `otrv4-mls`. It returns wire bytes, the
  plaintext of received messages, and public facts (members, epoch,
  fingerprints). No key or secret has a getter. Inputs are bounded.
* `android_bridge/groups.py` moves bytes: room bodies are
  `?OTRv4MLS1:` + base64 of an MLS message, fragmented with the same
  fragmenter as 1:1 frames (an add-commit or a Welcome is about 26 KB,
  well over the I2P stanza size that motivated fragmenting).
* Commit ordering is "the room decides" (stage 2). The transport now passes
  our own room reflection up for MLS frames only, because that is how a
  commit learns it won; a plain room's reflection is still dropped.
* No plaintext fallback: a secure room's send is MLS or `SEND_FAILED`; a
  plaintext body in a secure room is never shown (`room_plaintext_refused`);
  an undecryptable frame (history from before we joined, replay, stale
  epoch, tampering) is dropped and counted.

### Stage 4: persistence and wipe (automated)

* `MlsClient::export_sealed / import_sealed`: identity, signing key, every
  group, and any commit still waiting for the room, as CBOR in zeroizing
  buffers, sealed with AES-256-GCM under an HKDF-derived key, with the
  account bound as associated data. A wrong key, another account, any
  flipped byte, truncation or extension refuses; nothing partial opens.
* Reload is tested mid-conversation, with a pending commit, and against a
  stale snapshot (a rolled-back member cannot read a later epoch).
* Wipe & Exit (`OtrApp.wipe_crypto`) destroys the Rust state and removes the
  sealed file and its key file.

### Stage 5: identity binding (automated)

* A member is **verified** only when their MLS fingerprint (SHA-384 of the
  signature public key) arrived over an SMP-verified OTRv4+ session with
  that JID; **bound** when it arrived over any OTRv4+ session; otherwise
  shown by name only.
* A joiner checks that the group holds, for the inviter, the key the
  inviter sent over OTRv4+; otherwise the join is refused
  (`inviter_fingerprint_mismatch`).
* An uninvited KeyPackage adds nobody; an unsolicited Welcome joins nothing.

### Stage 6: UI (compiles in CI; not physically verified)

* Rooms screen: "Create end-to-end encrypted group".
* Conversation header: the MLS statement instead of "not end-to-end
  encrypted", members with verified / key over OTRv4+ / not verified, invite
  by address, remove.
* Chat list: invitation banners, accepted or declined explicitly.
* Received group messages are labelled ENCRYPTED only when MLS decrypted
  them.

### Tests

`Rust/mls`: 35 (client, group, interop against OpenMLS's reference provider,
HPKE cross-check against hpke-rs, persistence). Python:
`tests/test_secure_groups.py` (17, simulated room with reflection, drop,
replay, tamper, concurrent commits, restart, wipe),
`tests/test_secure_groups_bridge.py` (4, real OtrApp bridges with a real
OTRv4+ DAKE and SMP). Kotlin: `SecureGroupStateTest` (5).

### The terminal client (Termux) is a member too

`otrv4plus_groups.py` puts the terminal XMPP client in the SAME groups as the
app: it drives the unchanged `android_bridge.groups.SecureGroups` over the
same Rust `RustMlsClient`, with the same `?OTRv4MLS1:` room framing,
fragmentation and `?OTRv4-MLS:` setup signals inside OTRv4+. There is no
second wire format and no MLS code in Python. The terminal adds only the
XEP-0045 room join (an instant room, nick = localpart), `/group` commands and
`/wipe`. A terminal /quit keeps the sealed group state
(`~/.otrv4plus/xmpp/groups/`); /wipe destroys it. The Rust core must be built
with `--features mls` (Rust/build.sh does). Tested with two terminal clients
and one `OtrApp` over real OTRv4+ DAKEs in `tests/test_termux_groups.py`;
Rust: `a_standalone_proposal_is_queued_then_committed`,
`a_tampered_copy_is_refused_and_spends_the_generation`.

### Still open

* **Stage 7, physical**: three or more members over I2P, offline catch-up,
  removal, reconnect, restart.
* **Offline catch-up**: a member offline when a commit is sent misses it and
  cannot decrypt later epochs; there is no resync yet other than being
  removed and re-invited. The room's history replay does not help (MLS
  keeps no past-epoch secrets).
* **A tampered copy spends the genuine message's key.** OpenMLS deletes a
  sender's generation key on first use, so a corrupted copy that arrives
  BEFORE the genuine message makes the genuine one undecryptable. Fail
  closed, never a wrong acceptance; the effect equals the relay dropping the
  message, which it can do anyway. Pinned by a Rust test.
* **Verification badges after a restart**: which members were bound over an
  SMP-verified session is kept in memory only, so after a restart members
  show as unverified until re-bound. Membership and keys are unaffected.
* **Leaving** is local: MLS has no self-removal a member completes alone, so
  others list the leaver until one of them commits the removal.
* **At rest**: the sealing key is a file beside the state (see above).
* **Interoperability** with other MLS clients is not claimed: the
  ciphersuite is a draft.

