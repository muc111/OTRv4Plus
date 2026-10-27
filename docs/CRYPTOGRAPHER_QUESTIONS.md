# Questions for a cryptographer

What this project cannot settle by testing. Each question is stated so it
can be answered yes or no, or with a counterexample. Each also says what
the code would change under either answer.

The constructions are in docs/SPEC.md; the code is in `Rust/src`. The
audit that produced this list is in:
- docs/AUDIT_CLAIM_MATRIX.md: rows marked EXTERNAL;
- docs/AUDIT_THREAT_MODEL.md.

Notation:
- **A** and **B** are the parties; **J** is a third party shown a
  transcript.
- **MKenc** is a message's AES-256-GCM key, **MKmac** the 64-byte key of
  its outer MAC (OTRv4 §4.4.2).
- MKmac = KDF(MKenc), one-way (SPEC §5.3).

## Q1. The retirement predicate (SPEC §5.8, L1)

**Question.** Is it true that a MAC key published under R1-R3 can never
again verify a message its publisher would accept? Consider every
interleaving of loss, reordering, eviction at `MAX_MESSAGE_KEYS` (2000)
and DH steps.

The rule:
- **R1:** the message was received, and its AEAD tag verified.
- **R2:** the stored skipped MKenc was deleted (evicted at the bound, or
  at close).
- **R3:** close.

A sender never retires the key of a message it sent.

**The interleaving the audit cannot rule out, stated exactly.**
1. An attacker alters only the outer MAC of a genuine data message *m*.
2. B's AEAD tag verifies, so R1 commits: the replay cache records
   `(dh_pub, msg_num)`, and MKmac(*m*) is retired and later published.
3. B then refuses *m*'s outer MAC.
4. The genuine *m*, delivered afterwards, is refused as a replay.

So the key is published while the only message it authenticated was never
accepted. The code treats that as harmless: nothing can be verified with
the key, because the replay cache refuses every copy (SECURITY_ISSUES.md
L1, residuals). Is there a variant in which a copy of *m* with a different
`(dh_pub, msg_num)` could still be accepted? A late message from an older
chain is decrypted on the skipped path and retired there (R1); we believe
not.

**What the answer changes.**
- **Yes:** the claim in SECURITY_ISSUES.md L1 can move from RESOLVED-CODE
  toward RESOLVED-CLAIM, provided Q2 is also answered.
- **No, with a counterexample:** the retirement point moves from the AEAD
  commit to after the outer MAC (`ratchet.rs`, `decrypt_same_dh`,
  `decrypt_new_dh`, the skipped path), and a regression test is added for
  the interleaving.

## Q2. What publishing MKmac gives, with AES-GCM keyed by MKenc

**Question.** Does publishing MKmac, while AES-GCM stays keyed by the
unpublished MKenc, give OTR-style transcript deniability, and nothing
stronger?

**The capability, stated exactly.** A holder of all published MKmacs
- **can:** compute a valid outer MAC over any authenticated region (any
  header, any ciphertext bytes)
  (`test_a_published_key_lets_anyone_mac_an_altered_copy_of_an_observed_message`);
- **cannot:**
  - produce an AES-GCM ciphertext and tag that would decrypt under MKenc;
  - decrypt;
  - link a chosen plaintext to a ciphertext. B refuses its forgeries
    (`test_residual_the_receiver_refuses_a_frame_only_the_outer_mac_was_forged_for`).

**The sub-question that matters.** In OTRv4 the outer MAC is the only
authenticator of the ciphertext, so releasing MKmac makes the whole entry
forgeable. Here the GCM tag is a second authenticator, under a key the two
parties hold and never publish.

Suppose J is given MKenc by B, to check that a plaintext matches a
ciphertext. Then J learns "A or B produced this". Is that exactly
symmetric-key deniability? And does the MKmac release then add nothing
beyond letting an outsider re-MAC ciphertext it cannot interpret? If so,
the deniability rests on the symmetric keys (SPEC §10.1, "either party
could have produced any message"), and the release is a weaker,
OTRv4-compatible extra.

**What the answer changes.**
- **"OTR-style, no stronger":** the L1 wording stays as it is (mechanism
  only), and the review becomes the citation.
- **"Weaker than OTR because of the GCM tag":**
  - either publish a key that makes the GCM tag forgeable too, which needs
    a construction where publishing it reveals nothing about other
    messages (a design change: a separate per-message tag key derived
    beside MKenc and published);
  - or document that deniability here is symmetric only, and drop the
    MKmac release's prominence.

## Q3. Offline deniability of the v2 DAKE (A2, SPEC §4.3, §10.1)

**Question.** Is there any setting in which the v2 DAKE is offline-deniable
for participation? In v2 both parties sign the transcript with long-term
ML-DSA-87 keys, beside a 2-member Ed448 ring signature.

**Our understanding, to confirm or refute.** ML-DSA-87 is EUF-CMA against
classical adversaries as well, so J, classical or quantum, can verify that
A's long-term key signed a transcript naming B's profile and ephemeral
keys. Offline participation deniability therefore fails in every setting.
The ring signature does not help, because the ML-DSA signature sits beside
it.

Content deniability is untouched: no signature covers a message key or a
message (§10.1). The v1 handshake signed with an ML-DSA key made per
handshake, committed in DAKE1 and not certified. Would its ring signature
alone have been offline-deniable in the classical setting?

**What the answer changes.**
- **Confirmed:** SPEC §10.1 and every surface already say "it does not
  hide that you talked"; nothing changes, and Q6 is the route.
- **Refuted, showing deniability in some setting:** SPEC §10.1 gains that
  setting as a precise statement. Until a test can show it, no app text
  changes.

## Q4. The A1 combiner and its interleaving with loss (SPEC §5.1-5.2)

**The construction.**
```
brace_key = SHAKE-256("OTRv4" || 0x16 || brace_key || mlkem_ss)[0..32]
seed      = SHAKE-256("OTRv4" || 0x11 || root_key || dh_secret || brace_key)[0..64]
```

**Question (a).** Is `seed` indistinguishable from random to an adversary
who knows `dh_secret` (X448 broken later)? Assume `mlkem_ss` from an
unbroken ML-KEM-1024 entered `brace_key` at this step or any earlier one.
Assume the KEM item and the DH header are bound into each message's AEAD.

**Question (b).** After the P2 fix (SECURITY_ISSUES.md), a new sending
chain starts only after the peer has stepped. The peer steps only on a
message of our current chain, and each such message carries our
encapsulation key. We therefore believe an adversary can keep fresh ML-KEM
secrets out of the root only by dropping every message in a direction,
which also stops the X448 ratchet. Is there an interleaving of loss and
reordering in which a direction keeps stepping its X448 ratchet while no
ML-KEM secret enters?

**What the answer changes.**
- **(a) no:** move to a dual-PRF combiner (docs/PQC_DECISIONS.md (d),
  options 2 and 3). That is a wire break, so it needs a new
  `PQ_RATCHET_VERSION`.
- **(b) a counterexample:** re-advertise an outstanding encapsulation key
  on every new chain until it is answered (the candidate fix in
  PQC_DECISIONS (d)), with a regression test for the interleaving.

## Q5. F4 containment: what keeps a published group key dead

**The facts the question rests on** (Rust/mls/src/client.rs,
`f4_containment_tests`):
- the published key is one member's retired composite Ed448 + ML-DSA-87
  leaf key in one group, both halves, made fresh at each self-update
  (`a_publication_carries_both_halves_of_the_composite_key`,
  `epoch_N_plus_1_key_cannot_be_derived_from_epoch_N_key`);
- a member refuses an old-epoch message because OpenMLS keeps no past epoch.
  Both group configurations set `max_past_epochs(0)` explicitly
  (`max_past_epochs_is_zero_in_every_group_config`). With one past epoch
  kept, a member in the later epoch accepts a message signed with the
  published key
  (`a_message_signed_with_a_released_epoch_key_is_rejected_by_a_client_in_a_later_epoch`
  fails under that mutant);
- a member that has not yet processed the rotation accepts such a message as
  the publisher's
  (`residual_a_member_that_has_not_processed_the_rotation_accepts_the_retired_key_until_it_does`).
  So since 2026-10-27, publication waits until every other member has
  acknowledged the rotation by a message that verified in its epoch or later
  (SPEC §10, requirement 11;
  `publication_waits_until_every_member_has_acknowledged_the_rotation`).

**Question.** F4 containment depends on the receiver's past-epoch policy
(OpenMLS `MaxEpochs(0)`) and on every member having deleted past-epoch
secrets at commit. If a later client or ciphersuite sets a non-zero
past-epoch policy, a released key becomes a live forgery tool for that
epoch. Which of these is right?
- (a) the zero policy is acceptable as a documented invariant of the
  implementation;
- (b) the protocol should mandate zero past epochs at the wire level;
- (c) publication should always wait for acknowledgement, so that the
  policy is never load-bearing.

Today the code does (a) and part of (c). The acknowledgement shows only that
a member processed the rotation, not that it deleted the old epoch: a member
whose client kept past epochs would acknowledge and still accept old-epoch
messages. So the zero policy is still load-bearing for every honest member's
own acceptance. A secondary question: does releasing one composite secret
expose anything about other composite keys? No key material is shared
between leaves.

**What a "yes" changes in the code.**
- **(a):** nothing. SPEC §10 requirement 11 is the citation, and F4 stays
  RESOLVED-CODE with containment conditional on acknowledgement.
- **(b):** the group context gains an extension that states the policy
  (e.g. "past epochs kept: 0"), which every member checks at join and at
  each commit. A group whose context says otherwise is refused. This is a
  new group extension type, so a new MLS+ group version; existing groups are
  re-created.
- **(c):** the acknowledgement has to carry a statement of deletion that the
  publisher can rely on. That is only a promise, not a proof. The code then
  changes the acknowledgement's content, not when it is sent.

**What a "no" changes in the code.** If none of (a)-(c) suffices, F4
publication is turned off: `reveal_retired` is never called, the button is
removed from the apps, and F4 returns to OPEN until a different
construction is reviewed.

**What neither answer resolves.**
- A signature captured and verified before the release stays attributable
  (`residual_a_signature_checked_before_release_still_checks_after_it`).
- The forgers are only the members who received the publication
  (`residual_only_the_groups_members_receive_the_published_key`).
- The 1:1 v2 handshakes that carry the invitation, the KeyPackage and the
  Welcome are participation-attributable (Q3). Whether J can attribute a
  leaf key to a person through them is Q6's business.
- A modified client that keeps past epochs is not detectable by honest
  members under any of (a)-(c).

## Q6. A KEM-based v3 handshake

**The design** (docs/PQC_DECISIONS.md (e)):
- a long-term ML-KEM-1024 key per identity, pinned like the ML-DSA key;
- each side authenticated by decapsulating a KEM ciphertext to that key,
  folded into the session key;
- no signatures, so the transcript is simulatable.

**Questions.**
- (a) Is it sound: mutual authentication of pinned long-term keys,
  key-compromise impersonation resistance, and forward secrecy with
  ephemeral X448 and ML-KEM?
- (b) Is it offline-deniable for participation in the classical and the
  post-quantum settings? If so, under which assumptions?
- (c) Is it worth building before Q5 is answered, given that it removes
  the attributable 1:1 handshakes, which are what binds the group leaf key
  to a person?

**What the answer changes.**
- **(a) and (b) yes:** implement it as protocol v3 behind the negotiation
  byte. It inherits A2's pinning, kept across restarts since the P1 fix
  (2026-10-27).
- **(c) yes:** it comes before any further F4 work.

## Q7. SMP's ML-DSA binding (SPEC §6.7)

**The construction.** SMP signs `pq_binding_key || message` with pure
ML-DSA-87 (empty FIPS 204 context), under a key made fresh for each run
(`pq_smp_each_run_signs_with_fresh_ml_dsa_keys`). The binding key is a
fixed 32 bytes. A code comment called this "equivalent to the ML-DSA-87
context API". The audit found that false, and the comment is corrected:
- the FIPS 204 context is encoded as `0 || len(ctx) || ctx || M`;
- `pqcrypto-mldsa` 0.1.2 does offer it.

**Question.** Is prefixing a fixed-length secret binding key to the
message a sound domain separation for SMP's signatures? In particular,
across the SMP2/3/4 bodies, and against a signature from another protocol
under the same fresh key (there is none today)?

**What the answer changes.**
- **Yes:** nothing.
- **No:** move to the FIPS 204 context (`detached_sign_ctx`), which is a
  new SMP wire version.
