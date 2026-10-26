# Epochal ML-DSA for OTRv4Plus: research prototype

Status: research prototype (`research/epochal-mldsa`). It is not part of any
release, not built by CI, and does not change the app.

## 1. The deniability claim under test (written first)

**C (communication deniability).** Let `pk_N` be a member's ML-DSA-87 key
for group `G`, epoch `N`. Once epoch `N`'s signing key has been released,
a valid signature under `pk_N` does not show that the member produced it,
even to a verifier who trusts `pk_N` belonged to that member. Every party
holding the release can produce signatures that verify under `pk_N` for
epoch `N`. That includes a party who was never a member.

C is meant to cover what the current design gives up (SPEC §10.1): the fact
that a session or group epoch was authenticated by a particular member. It
does **not** add content deniability. That already comes from releasing the
symmetric MAC keys (L1, SPEC §5.8) and is not re-tested here.

C holds only while three conditions hold. Each is a test, or is stated as
outside what the tests can show:

- **C1, during the epoch.** Before release, only the key holder can sign, so
  members get the authentication they need. Test 1.
- **C2, after release.** Anyone can sign for epoch `N`. Test 2. Signing is
  FIPS 204 hedged: `ML-DSA.Sign_internal` over the external message
  `0 ‖ |ctx| ‖ ctx ‖ M`, with a fresh 32-byte randomiser from the OS. A
  forger with the release runs the same algorithm on the same key, so the
  forgery is generated exactly as the holder's signatures are.
- **C3, contained.** A release forges only its own epoch. Not the next one
  (test 3), not the previous one (test 4), and not across the epoch boundary
  in either direction (test 6). Otherwise releasing one key would release
  the future, and authentication would be lost.

**Group binding.** A key counts for `G` at epoch `N` only if its binding
tag verifies under that epoch's MLS epoch authenticator (test 5). This
proves "registered by a member of `G` at epoch `N`". It does not prove
which member, and it is symmetric, so it is deniable by construction.

**What the tests cannot show, and C therefore does not claim:**
- That the binding of `pk_N` to a person is deniable. That depends entirely
  on how `pk_N` reached the other members (§5). The group-binding tag proves
  membership, not identity. A per-member binding that proves identity, such
  as an MLS leaf signature under a long-term key, would re-attribute.
- That a release reached anyone. Release is a publication problem (§3).
- That the server, the network or a member's device kept no other evidence.

## 1a. The handshake: the test that matters

Releasing MAC keys works at the message layer. In OTRv4Plus the attribution
lives elsewhere: in the v2 DAKE's ML-DSA-87 signature over the handshake
transcript, under a long-term key that is never released (SPEC §10.1). That
is why the app says Make Chat Deniable "does not hide that you two talked".
So C is tested here on **handshake transcripts**, shaped as the v2 DAKE
signs them: initiator, responder, both ephemeral keys, session id
(`handshake_transcript`):

- **h1.** During the epoch, a handshake signature under Alice's `pk_N` can
  only come from her key. Another member's key does not verify as hers.
- **h2.** After `ξ_N` is released, an outsider holding only the release
  makes handshake signatures that verify as Alice's, bound to the group, for
  handshakes she never ran. That includes other ephemeral keys and session
  ids with Bob, and a handshake with Carol, whom she never talked to. Her
  real handshake still verifies, but it is now one of arbitrarily many that
  do, so the signature no longer shows that she took part, or with whom.
- **h3.** The release does not reach the next epoch's handshakes.

**The residual this exposes: how `pk_N` is tied to Alice.** The test
`limitation_a_long_term_certificate_of_the_epoch_key_stays_evidence`
certifies `pk_N` with a long-term ML-DSA key, the obvious way to make it
"Alice's". That certificate is never released. After the epoch it still
proves Alice held `pk_N` in group `G` at epoch `N`: the handshake is
deniable, but the certificate's statement is not. Options, in order of what
they leave attributable:

1. **A certificate chain by released keys.** `sk_{N-1}` certifies `pk_N`,
   and the root `pk_1` is pinned by TOFU or SMP, as identity keys are
   today. Each certificate becomes forgeable when its signer's key is
   released, so after release nothing remains attributable except the
   pinned root, which nobody else holds. Not built here.
2. **A long-term certificate over nothing peer- or group-specific.** A
   global per-epoch key: the certificate then proves only "Alice was active
   in epoch `N`", not with whom. It is still a liveness fact. Here `pk_N`
   is group-specific, so it would prove membership of `G`.
3. **No certificate:** `pk_N` delivered inside an already-deniable channel
   (the Ed448 ring signature DAKE, or the MLS epoch authenticator, which
   proves membership only; test `limitation_...membership_not_which_member`).

## 2. Key lifecycle, derived from C

| Requirement | Lifecycle rule (prototype) |
|---|---|
| C1: only the holder signs during `N` | `ξ_N`, the 32-byte FIPS 204 seed, is secret; only `pk_N` and its binding tag are distributed. |
| C2: anyone signs after release | Release publishes `ξ_N`, the whole private key in seed form (32 B). Anyone rebuilds `sk_N = KeyGen_internal(ξ_N)`. |
| C3: next epoch not derivable | A one-way chain: `s_{N+1} = SHA3-256("chain" ‖ s_N)` and `ξ_N = SHA3-256("sign" ‖ s_N ‖ H(G) ‖ N ‖ auth_N)`. Releasing `ξ_N` releases neither `s_N` nor anything after it. |
| C3: previous epoch not derivable | `s_N` is erased once `s_{N+1}` exists. `ξ_{N-1}` came from `s_{N-1}`, which cannot be computed from `s_N` or `ξ_N`. |
| C3: no crossing the boundary | Every signature carries the FIPS 204 context `"OTRv4+ epochal v1" ‖ H(G) ‖ N`. A signature for one epoch cannot verify as another, even under the same key. |
| C3: only closed epochs released | Releasing the current or a future epoch is refused. The key is erased from the signer once released. |
| Group binding | `tag_N = SHA3-256("bind" ‖ auth_N ‖ H(G) ‖ N ‖ member ‖ H(pk_N))`. Only holders of `auth_N`, the MLS epoch authenticator, can make or check it. |

## 3. Assumptions and failure modes

**Assumptions.**
- ML-DSA-87 is EUF-CMA (FIPS 204).
- SHA3-256 is a PRF and one-way, as used here.
- The MLS epoch authenticator is known only to members of that epoch
  (RFC 9420 §8.7).
- Forward security here comes from the key-evolving chain plus erasure.
  It is not a forward-secure signature scheme in the
  Bellare-Miner/Itkis-Reyzin sense: there is no single long-term public key.
  Each epoch has a fresh `pk_N` that must be distributed (§5).

**Failure modes.**
- **Trusted publisher.** Release needs someone online at the epoch's close
  to publish `ξ_N`: the member, the group, or a bulletin board. A member who
  goes offline, crashes or refuses leaves `ξ_N` unreleased, and that epoch's
  signatures stay attributable. A malicious member is unaffected, since
  members can keep their own transcripts anyway. This is the same exposure as
  F4 and L1 in OTRv4Plus today.
- **Timelock variant.** The release becomes automatic if `ξ_N` is published,
  at the start of `N`, inside a time-lock puzzle (Rivest-Shamir-Wagner) that
  takes about the epoch's length to open. That removes the trusted publisher.
  The costs:
  - one party must actually spend the sequential work, roughly a CPU-day per
    member-epoch for a 24 h epoch, or nobody learns `ξ_N`;
  - hardware speed varies a lot, so "24 h" means anywhere from hours to days;
  - RSW is not post-quantum: a quantum adversary factors the modulus and
    opens the puzzle early, which breaks C1. That is the property ML-DSA was
    chosen for;
  - a PQ time-lock needs other assumptions, which we have not reviewed.
  Not implemented; documented only.
- **Clock skew.** Epochs here are indexed by MLS epoch and a declared epoch
  id, not wall-clock time; "24 h" is a policy on when the next epoch starts.
  If a verifier accepts signatures by wall-clock time, skew between members
  creates a window where one believes `N` is closed and another still signs
  in it. The prototype verifies against an explicit epoch id. Verifiers must
  not use wall-clock time.
- **Epoch-boundary races.** A message signed late in `N` and delivered after
  `ξ_N` is released is indistinguishable from a forgery. That is C2, so
  receivers must refuse epoch-`N` signatures once the release of `N` has
  been seen. The prototype provides this as `verify_unreleased` (test `at_the_boundary_a_receiver_refuses_a_released_epoch`).
  In MLS the room's ordering resolves it: release is posted after the commit
  that opens `N+1`.
- **Release before the epoch is closed** would hand out a live key (a C1
  failure). Refused by the API (test).
- **Forgery cuts both ways.** After a release, anyone can produce messages
  and handshakes that verify for that epoch (C2, h2), including someone
  fabricating "evidence" that Alice said or did something. That is the
  property, not a bug. The same transcript cannot prove Alice's authorship,
  and it cannot prove a fabrication is hers either: after release, no
  signature from that epoch is evidence in either direction. The exposure is
  social, not cryptographic: a reader who does not know the key was
  released may believe a forgery. The MAC-key release of L1 has the same
  shape for content. It is stated in docs/SECURITY_ISSUES.md (L1, "Forgery
  cuts both ways"), not in the app's dialog.

## 4. Departures from the academic definition

Hülsing and Weber ("Epochal signatures for deniable group chats", IEEE S&P
2024). Our reading, to be checked against the paper before any citation in
user-facing material: they define an epochal signature scheme with one
long-lived verification key, where signatures become forgeable once their
epoch has passed. Their constructions build that forgeability in, and
verifiers check against time.

**Departures, and why:**
- **A fresh `pk_N` per epoch, not one long-lived key.** It is implementable
  now with a standard FIPS 204 ML-DSA-87 and no new primitive. The cost is
  distributing `pk_N` each epoch (2592 B per member). MLS already
  distributes a member's signing key in the leaf, and F4 rotates it.
- **Forgeability by publication, not built in.** It needs a publisher (§3),
  where their constructions do not.
- **Hedged, not deterministic, signing** (fresh randomiser, FIPS 204's
  default). A forger therefore produces signatures with the same
  distribution as the holder's. With deterministic signing, the holder's
  signature on `M` would be unique and a forger's byte-identical. That is
  harmless but makes
  distinguishability arguments awkward; we keep the FIPS 204 hedged shape.

## 5. Content vs communication deniability, and the comparison

| Property | Current OTRv4Plus (MAC release + ML-DSA-87 attribution) | Epochal ML-DSA (this prototype) |
|---|---|---|
| Content deniability (who wrote what) | Yes, 1:1: MKmac released on the wire (L1, wire audit). Groups: retired leaf keys published (F4). | Unchanged: not provided by this scheme, still needs L1/F4. |
| Communication deniability (that A took part) | No: v2 DAKE ML-DSA-87 signatures under long-term keys are attributable for ever (SPEC §10.1). MAC release does not touch them. | For handshake signatures under `pk_N` once `ξ_N` is released (h2, tests 2-4, 6), provided `pk_N`'s link to A is itself deniable (§1a). A long-term certificate of `pk_N` re-attributes it. |
| Authentication during the epoch | Long-term ML-DSA-87 plus Ed448 ring signature. | Per-epoch ML-DSA-87 (test 1); group binding by the epoch authenticator (test 5). |
| Sender authentication against other members | MLS leaf signature (rotated, F4). | Not by the binding tag: it proves membership only. Needs a per-member binding, and that binding decides whether C still holds. |
| Trusted party | None for content (keys go on the wire); server confirmation only. | A publisher at each epoch close, or a time-lock (§3). |
| Post-quantum | Yes (ML-KEM-1024, ML-DSA-87). | Yes, except the time-lock variant. |
| Wire cost per member-epoch | none extra | `pk_N` 2592 B + tag 32 B distributed; release 32 B (seed) |
| CPU per member-epoch | none extra | 1 ML-DSA-87 keygen (about 0.8 ms measured, release build, x86-64) + 1 SHA3 chain step; signing about 0.7 ms and verifying about 0.14 ms are the same as today's ML-DSA-87 |

The decisive row is the binding. In 1:1 OTRv4Plus, A's long-term ML-DSA key
is pinned by TOFU or SMP. If `pk_N` were certified by that long-term key,
the certificate would attribute A to epoch `N` for ever, and C would fail
for the reason SPEC §10.1 gives today. C holds only if `pk_N` is
authenticated deniably:
- by `sk_{N-1}`, which is released later, so the certificate chain becomes
  forgeable link by link;
- or inside an already-deniable channel (the OTR DAKE ring signature, or the
  MLS group via the epoch authenticator).

## 6. The tests, against the claim

`cargo test --offline --release` in `research/epochal-mldsa` (17 tests, all
passing):

| Test | Shows |
|---|---|
| `t1_a_signature_verifies_during_its_epoch` | C1 |
| `t2_after_release_a_forged_signature_for_that_epoch_verifies` | C2. The forger holds only the release board. |
| `t3_a_forgery_for_epoch_n_plus_1_with_epoch_n_s_key_does_not_verify` | C3, forward |
| `t4_releasing_epoch_n_does_not_enable_forgery_of_n_minus_1` | C3, backward. Epoch `N-1` still authenticates the holder's real signatures. |
| `t5_a_non_member_key_fails_group_binding` | group binding |
| `t6_an_epoch_n_signature_does_not_verify_under_epoch_n_plus_1_s_key` | C3, boundary, including relabelling |
| `only_a_closed_epoch_can_be_released_and_once` | no live key released; erased on release |
| `keys_only_go_forward_and_differ_per_epoch_and_group` | one-way chain; unlinkable across groups |
| `a_release_carries_32_bytes_and_nothing_of_the_chain` | release size |
| `at_the_boundary_a_receiver_refuses_a_released_epoch` | the boundary-race rule |
| `limitation_the_binding_proves_membership_not_which_member` | **asserts the limit**: a member can bind a key under another member's name |
| `the_schedule_is_24h_by_default_and_configurable` | the epoch policy |
| `cost_per_member_epoch` | the measurements above |
| `h1_during_the_epoch_a_handshake_signature_attributes_it_to_the_key_holder` | §1a: authentication of the handshake during the epoch |
| `h2_after_release_handshakes_alice_never_ran_verify_as_hers` | §1a: **the fact of communication** is forgeable after release, including the peer's identity |
| `h3_the_release_does_not_reach_the_next_epoch_s_handshakes` | §1a: contained |
| `limitation_a_long_term_certificate_of_the_epoch_key_stays_evidence` | **asserts the limit**: a long-term certificate of `pk_N` re-attributes what it binds |

Test 2 shows forgeability **by verification**: the forged signature passes
every check a verifier can run. Whether a judge would also accept that the
release happened is outside what code can test.

## 7. Recommendation

**No-go for integration now; go for a second, narrower prototype: the
certificate chain of §1a option 1, in a DAKE-shaped handshake.**

What this prototype shows: the handshake signature, the thing that proves
"that you talked", becomes forgeable after release (h2), and only for its
epoch (h3). The mechanism works at the layer where attribution lives, which
MAC-key release does not reach.

Why not integrate yet:
1. **The key-to-person link decides the claim, and it is untested.** A
   long-term certificate of `pk_N` re-attributes (asserted by a test). The
   group binding the brief specifies (epoch authenticator) proves
   membership, not sender, so MLS-style authentication needs a per-member
   binding. The design that keeps that binding deniable is the
   certificate chain in §1a, which this prototype does not build.
2. In 1:1, the attribution in question comes from the v2 DAKE's long-term
   ML-DSA-87 signature. Replacing it with epoch keys changes the DAKE. That
   is a protocol change SPEC §10.1 already says needs expert review, against
   the established alternative of KEM-based implicit authentication, which
   needs no publisher at all.
3. A publisher is needed per member-epoch (§3), and the time-lock option is
   not PQ.

Cost if integrated, measured on this prototype's code paths:
- One extra ML-DSA-87 keygen per member per epoch.
- 2.6 KB per member per epoch, distributed through the group.
- 32 B per release.
- One new state per member and group: the chain state plus unreleased seeds
  (32 B each).
- In the codebase, about 300-500 lines of Rust (this prototype: about 310
  lines of library, 260 of tests): a new keying layer under the
  MLS provider, or under the DAKE. Plus a release schedule and verifier
  state ("refuse epochs whose release has been seen") on every client, and a
  wire format.

The next prototype should test that after `ξ_{N-1}` and `ξ_N` are
released, no statement anyone can verify links `pk_N` to Alice, other than
the pinned root, which only her contacts hold. It should also measure what
the chain adds to the handshake.

For groups, F4 (rotate and publish the retired leaf key) already delivers
the core of C2 and C3 within RFC 9420. Its keys are composite Ed448 +
ML-DSA-87, published as 57 + 4896 B private halves. Releasing them in seed
form (57 + 32 B) would cut each publication by about 55x. That needs the
ML-DSA half generated from a seed: RustCrypto `ml-dsa`, as here, instead of
`pqcrypto-mldsa`, which does not expose one. Worth doing if F4 is kept.
