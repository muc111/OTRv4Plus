# Post-quantum decisions for the deniability work

Written before the code it governs (2026-10-26), as the task required. Each
item lists the options, the threat model they were judged against, the
choice, the rationale, the residual accepted, and, where the most secure
option does not fit the current architecture, the migration path.
References are given by author and year. They were written from memory and
must be checked before this file is quoted anywhere outside the project.

**Threat model, common to all items.**
- **Q:** an active network adversary who will have a cryptographically
  relevant quantum computer: harvest now, attack later. Q forges Ed448 and
  breaks X448 once it has the computer, but not ML-DSA-87, ML-KEM-1024 or
  SHAKE-256.
- **J:** a judge or other third party shown a transcript by one participant
  or by the server. J holds no keys except those published.
- Groups are up to ~100 members, every one of whom holds the transcript.

---

## (a) Epochal signatures for groups (F4)

**Options.**
1. **Epoch key release (as shipped).** The MLS leaf signing key is
   rotated by a self-update every 50 messages or 30 min. The retired private
   key is published inside the group 10 min after the rotation lands, or at
   once on Make Group Deniable.
2. **A forward-secure signature construction.** One long-lived public key,
   with a signing key that evolves and erases its past, e.g. hash-based
   XMSS or LMS (NIST SP 800-208), or the Hülsing and Weber (2024) epochal
   constructions built on that idea.
3. **Time-lock release.** The epoch's key is published at the start of the
   epoch inside a puzzle (Rivest, Shamir and Wagner 1996) that opens after
   about the epoch's length. No publisher is needed.

**Judged against.**
- J must not be able to attribute a signature once its epoch is over.
- Q must not be able to forge a signature during an epoch, or before its
  release.
- No member's live key may be exposed early.
- It must work with OpenMLS 0.9 and the composite Ed448 + ML-DSA-87
  ciphersuite rule ("both halves must verify").

**Choice: option 1, kept as shipped.**

**Rationale.**
- Option 2 inverts the property. Forward security means a later compromise
  cannot forge the past, while deniability needs the past to be forgeable.
  An epochal scheme built on it still needs a release step, so it adds
  nothing over option 1 on that axis.
- Option 2 also carries risks option 1 does not:
  - Stateful hash-based signatures are broken by one state reuse. That
    includes a restored backup, which is exactly the failure a phone app
    invites.
  - They are not an MLS signature scheme. Using one means a new private
    ciphersuite and abandoning the composite rule.
  - A 2024 epochal construction has had less scrutiny than FIPS 204.
- Option 3 fails the threat model outright:
  - RSW rests on factoring, so Q opens the puzzle early. That exposes a
    live key, which is impersonation, not just deniability.
  - In the random-oracle model, a puzzle cannot be much cheaper to make
    than to solve (Mahmoody, Moran and Vadhan 2011), so no cheap hash-only
    PQ time-lock exists.
  - Lattice-based time-locks are not mature.
- Option 1 uses only FIPS 204, the existing composite scheme and MLS's own
  rotation:
  - A rotated key no longer verifies in the group, because the room orders
    the rotation commit before the publication (`retired_key_tests`).
  - The cost for ~100 members is one update commit per member per period,
    with an update path of O(log n) HPKE ciphertexts (≈7 for 100 members),
    plus one publication message.

**Residual accepted.** Release needs the member online after the rotation
(a publisher: themselves). A signature that a member captured and leaked
before publication was valid evidence when captured, and stays so to anyone
who trusts the capture. That residual is cryptographic: no release can undo
a verification already made. It is worded so in workstream 2.

**Recommendation for 1:1: keep F4's mechanism group-only.** The 1:1
attribution comes from the DAKE's long-term ML-DSA-87 signature
(SPEC §10.1). Making that epochal needs:
- a per-epoch key and a publisher on every client;
- a certificate chain whose links are themselves released
  (`research/epochal-mldsa/ANALYSIS.md` §1a);
- changes to the pinning of A2.

The more secure route for 1:1 is to remove the signature rather than to
publish it later: KEM-based implicit authentication (item e, migration
path). That needs no publisher and leaves nothing to release.

---

## (b) ML-DSA parameter set: epoch keys vs long-term keys

**Options.** ML-DSA-87 (NIST category 5), -65 (category 3), -44 (category 2)
(FIPS 204).

**Judged against.**
- **Epoch keys.** A forgery matters only during the key's live window: one
  rekey period plus the delay, at most about 40 min. After release anyone
  can sign anyway, so long-term forgery resistance buys nothing for them.
- **Long-term identity keys** (DAKE v2, pinned under A2). A forgery at any
  time impersonates the owner in every future session. These need the
  widest margin.

**Choice: ML-DSA-87 for both.**

**Rationale.**
- **For long-term keys** there is no argument for less.
- **For epoch keys** the shorter window does argue that -65 would be enough
  against generic attacks, and it would save about 1.3 KB per signature
  (3309 B vs 4627 B) and 640 B per public key. But three things outweigh
  that saving:
  1. The risk to lattice signatures is a structural cryptanalytic advance,
     not brute force. Such an advance reduces every parameter set, and -87
     keeps the most margin when it does.
  2. The epoch key is the MLS leaf key, fixed by the composite ciphersuite
     code point (Ed448 + ML-DSA-87). A different set means a second private
     code point and two signature paths in the provider. That is more code
     on the security boundary for a bandwidth saving.
  3. Forward security (key erasure) is orthogonal to parameter strength. It
     does not argue for a smaller set.

**Residual accepted.** About 4.6 KB per group signature, and ≈4.9 KB per
published key (expanded form).

**Migration path:** publish the 32-byte seed instead of the expanded key.
That cuts each F4 publication from 57 + 4896 B to 57 + 32 B. It needs the
ML-DSA half generated from a seed: RustCrypto `ml-dsa` or libcrux in place
of `pqcrypto-mldsa`, which CRYPTO_AUDIT §8 item 2 already recommends for
other reasons. Not done here.

---

## (c) Composite signatures under epochal release

**Question.** Does release weaken "both halves must verify"? If only the
ML-DSA half were epoch-scoped, it would become forgeable after release while
Ed448 stayed binding. Deniability would then be void: a classical J can
still check Ed448.

**Finding, groups (F4).** Both halves are already scoped together. The
composite leaf key is generated, rotated, retired and published as a unit:
the publication carries the whole composite secret, the 57-byte Ed448 seed
and the ML-DSA-87 key (`MlsClient::reveal_retired`). The receiver accepts a
pair only if the composite signs for the composite public key
(`is_consistent`). A forgery from a published key therefore satisfies both
halves. The rule is untouched, and nothing is asymmetric.

**Decision: scope both halves; never release one alone.** A new Rust test,
`a_publication_carries_both_halves_of_the_composite_key`, pins this. It
checks the publication is accepted only as a whole composite pair, and that
a forgery from it verifies under both halves.

**Finding, 1:1 (DAKE).** The 1:1 composite is asymmetric by design, and the
asymmetry is what SPEC §10.1 documents:
- the Ed448 half is a 2-member ring signature, deniable;
- the ML-DSA-87 half is a plain signature under a long-term key,
  attributable.

So the handshake is exactly as attributable as its ML-DSA half. That is not
a conflict with this work, since nothing is released in 1:1, but it is why
participation is not deniable. It also means any 1:1 fix must change the
ML-DSA half (item e). Releasing nothing there leaves the asymmetry
documented, not hidden.

---

## (d) A1: the brace-key combiner and its interleaving with loss

**Current construction (v2, SPEC §5.1-5.2).**
```
brace_key    = KDF_1(0x16, brace_key || mlkem_ss, 32)
seed         = KDF_1(0x11, root_key || dh_secret || brace_key, 64)
KDF_1(u, v)  = SHAKE-256("OTRv4" || u || v)
```

**Options.**
1. **Keep:** concatenate, then hash, with SHAKE-256.
2. **A dual-PRF / HKDF combiner** (Bindel, Brendel, Fischlin, Goncalves and
   Stebila 2019).
3. **An X-Wing-style combiner** (Barbosa et al. 2024) that also hashes in
   the X448 public keys and the ML-KEM ciphertext.

**Judged against.** Q, who breaks X448 later, must learn nothing about a
message key once one ML-KEM secret has entered the root after the
compromise. That is PQ post-compromise security.

**Choice: keep option 1; no change before external review.**

**Rationale.**
- SHAKE-256 over a domain-separated concatenation is a secure combiner in
  the random-oracle model whenever either input is uniform. That is the
  standard argument, and it is what options 2 and 3 also rely on for their
  hash step.
- Option 3's extra inputs address KEM-combiner robustness when a component
  KEM is not IND-CCA (Giacon, Heuer and Poettering 2018). ML-KEM's
  Fujisaki-Okamoto transform already binds its ciphertext into the shared
  secret. The KEM item and the DH header are bound into each message's AEAD
  (SPEC §5.1, §5.4), so tampering fails before anything is folded.
- Changing the derivation is a wire break for every v2 session, to gain a
  property the review may or may not ask for.

**Residual accepted (and the review item).** SPEC §5.1 states it: an
encapsulation key is advertised once. If every message of that chain is lost
and the side then takes a forced step, no new ML-KEM secret enters in that
direction for the rest of the session. The X448 ratchet still recovers
classically.

**Candidate fix, for the reviewer:** re-advertise an outstanding key on
every new chain until it is answered. Not implemented: the answer-once
state machine must be re-proved under loss and reordering. That is
CRYPTO_AUDIT §7 item 3, the interleaving question, which is exactly what
needs a cryptographer.

---

## (e) A2: first contact is trust-on-first-use. Is there a PQ fix?

**Options.**
1. **A PQ PAKE** (e.g. KEM-based PAKEs, Beguinet, Chevalier, Pointcheval,
   Ricosset and Rossi 2023).
2. **A deniable authenticated KEM / KEM-based implicit authentication**
   (Hashimoto, Katsumata, Kwiatkowski and Prest 2021; Brendel, Fiedler,
   Günther, Janson and Stebila 2022).
3. **Out-of-band verification**: the existing hybrid SMP, or comparing
   fingerprints.

**Judged against.** A Q-capable man-in-the-middle at the very first contact
between two people who share nothing yet.

**Finding: no cryptographic primitive closes TOFU.** Authenticating a party
you share nothing with is impossible without a trusted third party or some
prior shared information. Every option needs one of those:
- A PAKE needs a shared password. That is what SMP already uses, after
  first contact.
- A deniable AKE authenticates long-term keys, but someone still has to
  vouch that the key is Bob's.

So TOFU is a property of the trust model, not of the primitives, and no
PQC choice removes it.

**Choice.**
- **First contact: keep TOFU plus the hybrid SMP.** SMP is the PAKE-shaped
  answer and is already post-quantum:
  - ML-KEM-1024 binding;
  - ML-DSA-87 under keys made fresh for each run, so its signatures
    attribute to nobody;
  - it runs inside the encrypted session.

  The app already marks a contact unverified until SMP succeeds.
- **The deniability split: adopt option 2 later, for a different reason.**
  KEM-based implicit authentication removes the attributable ML-DSA-87
  signature from the DAKE while keeping PQ authentication of known keys.
  That is the route to participation deniability (§10.1) that needs no
  publisher.

**Migration path (option 2).**
1. A long-term ML-KEM-1024 key per identity, pinned like the ML-DSA key is
   today (A2's pinning carries over, and so does its limit: on Android and
   the desktop the pins last one run of the app until SECURITY_ISSUES.md P1
   is fixed).
2. The DAKE authenticates each side by decapsulation of a KEM ciphertext to
   that key, folded into the session key. There are no signatures, so the
   transcript is simulatable.
3. Ship it as protocol v3, behind the same negotiation byte mechanism, with
   v2 refused only after review.

It changes the DAKE, so it needs the external review CRYPTO_AUDIT §7 items
1-2 already ask for. Not implemented here.

**Residual accepted.** A substituted key at first contact is caught only by
SMP or by comparing fingerprints. This is the shared residual of A2, L1 and
X1; see "Shared residual: unauthenticated first contact" in
SECURITY_ISSUES.md.

---

## Summary of decisions

| Item | Decision | Changes code now? |
|---|---|---|
| (a) | Epoch key release via MLS rotation (as shipped); time-lock and FS signatures rejected; group-only, not 1:1 | No |
| (b) | ML-DSA-87 for epoch and long-term keys; seed-form publication is the migration | No |
| (c) | Both composite halves scoped and released together (already so); pinned by a new Rust test | Test only |
| (d) | Keep the SHAKE-256 concatenation combiner; the §5.1 loss residual goes to the reviewer | No |
| (e) | TOFU cannot be closed by a primitive; keep SMP; KEM-based implicit auth (v3) is the route to participation deniability | No |

None of (a)-(e) changes the epoch key design that workstreams 3 and 4
test. Those concern the 1:1 L1 close, which (a) keeps separate from F4.
