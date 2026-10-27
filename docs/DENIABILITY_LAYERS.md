# Deniability layers

For an external reviewer of SPEC §5.8 who does not want to read
`Rust/src/ratchet.rs`. Three mechanisms, three different things they aim to
deny. None is claimed as a property in docs/SECURITY_ISSUES.md: all three
are RESOLVED-CODE or a stated limitation, and the app's words describe the
mechanisms only. J is a third party shown a transcript by a participant or
by the server. The precise questions for the reviewer are
docs/CRYPTOGRAPHER_QUESTIONS.md.

| Layer | Mechanism | What J can no longer establish | What J can still establish | Residual | Gate |
|---|---|---|---|---|---|
| **L1: 1:1 content** (SPEC §5.8) | Each message's MAC key is retired by its receiver (R1 received, R2 skipped key deleted, R3 close) and published in the `revealed_mac_keys` field, outside the ciphertext. Closing messages carry the rest; our server is asked to confirm them before the new session starts (it starts either way, and the app says whether it was confirmed). | Who wrote any given line of a closed session. Anyone holding the traffic can re-MAC it, and both parties always held the keys. | **That the two identities talked:** the handshake's ML-DSA-87 signatures, under long-term keys (row 3). The ciphertext, timing and size of each line, and that the session was closed. | Expert review of the rule. A **partial close**: a lost closing part leaves its range provable until re-sent. The **kill-to-confirmation window**: a crash after `retire_all`, before confirmation, leaves that close provable. A **peer that never closes**: our last lines it received stay provable. An **unanswered confirmation**: re-sent up to 40 times while the app runs. TOFU (shared residual). | `tests/test_l1_revelation_gate.py` (T1-T8), `ratchet::l1_retirement`, `tests/test_deniability_wire_audit.py` (outsider audit, incl. `TestMultiPartClose`), `tests/test_deniable_confirmation.py`, `TestCrashDuringClose`, the asserted residuals in docs/AUDIT_TEST_INTEGRITY.md |
| **F4: group content** (MLS_SECURITY_HARDENING §1) | Each rekey rotates the member's composite Ed448 + ML-DSA-87 leaf key. The retired key, both halves, is published inside the group 10 min later, or at once on Publish Group Keys. | From the release on: who signed any message of that epoch. Any member who received the publication could have made the signature; a non-member could not (it is encrypted to the members). | **Any signature captured and verified before the release**, for ever. That the member was in the group (the MLS tree, the room). | **Permanent and cryptographic**: a capture before release stays attributable. Release needs the member online. Past 16 retired keys the oldest go unpublished. No copy may say "past messages are deniable". | `retired_key_tests` (incl. `a_publication_carries_both_halves_of_the_composite_key`, `residual_a_signature_checked_before_release_still_checks_after_it`, `residual_only_the_groups_members_receive_the_published_key`), `tests/test_f4_group_key_publication.py`, `DeniableChatTest`, `tests/test_deniable_wording.py` |
| **A2 / §10.1: participation** | None. The v2 DAKE signs the transcript with each side's long-term ML-DSA-87 key, for PQ authentication. The Ed448 ring signature beside it is deniable; the ML-DSA half is not. | Nothing. | **That the two identities ran a handshake with each other**, and its ephemeral keys and time. | Accepted for PQ authentication. The route to removing it is KEM-based implicit authentication (protocol v3), which needs review. Epochal ML-DSA was prototyped and not adopted (`research/epochal-mldsa/ANALYSIS.md`). | `dake::pq_auth_tests`, `tests/test_pq_auth_v2.py` (the authentication), SPEC §10.1 (the cost) |

**Reading the table.**
- L1 and F4 make content unprovable. Neither touches participation, which
  only a change to the handshake can address.
- None of the three can make an already-verified capture unverified.
- After a release, forgery is open to anyone holding the keys, including
  someone fabricating "evidence". The transcript then proves neither
  authorship nor fabrication.
- **The device keeps a record of participation too (P1).** Each account's
  contact pins (fingerprints and ML-DSA key hashes) are kept sealed on the
  device, so a handset or desktop account that is opened shows whom the
  account has talked to under which key. That is participation, which the
  A2 row already concedes, not content. Wipe & Exit destroys it
  (docs/SECURITY_ISSUES.md P1).
- TOFU sits under all three. See "Shared residual" in SECURITY_ISSUES.md;
  no primitive closes it (PQC_DECISIONS.md (e)).

**What a reviewer is asked to settle** (CRYPTO_AUDIT_2026-09 §7):
1. That R1-R3 retire a key only when nothing can be verified with it any
   more, under loss, reordering and DH steps, so that no published key is
   still live.
2. That publishing MKmac while AES-GCM stays keyed by the unpublished
   message key gives the OTR notion of transcript deniability, and no more.
3. Whether the 2-member ring plus an attributable ML-DSA signature leaves
   the DAKE offline-deniable in the classical setting.
