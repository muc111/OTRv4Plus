# Tracked security issues

Open issues carried by the OTRv4+ codebase, with current behaviour, impact, and
what would resolve each. This file exists so that known gaps stay visible
instead of being rediscovered, and so that no gap is described as fixed until a
regression test demonstrates it.

Status vocabulary:

- **OPEN** — present in the shipped code, not remediated.
- **MITIGATED** — cannot currently be reached, but the underlying code remains.
- **RESOLVED** — a defect fixed, with a regression test named here. Used for
  bugs; it asserts no security property beyond the fix.
- **RESOLVED-CODE** — a security mechanism is implemented and its behaviour
  is tested, but **no property is claimed** for it. It waits for review, or
  its residuals are too large for a defensible sentence. The tests show what
  the code does, not that it achieves the property.
- **RESOLVED-CLAIM** — the mechanism is tested **and** a worded claim is
  defensible: a regression gate demonstrates the claim and names its
  residual. Only these may be described to users as providing the property.

## Shared residual: unauthenticated first contact (TOFU)

A2 (PQ authentication), L1 (deniability) and X1 (server identity) all rest on
the first contact being genuine:
- **A2:** the peer's ML-DSA-87 key is pinned on the first v2 handshake.
- **L1:** the session whose keys are published is with whoever that first
  handshake reached.
- **X1:** a server's I2P destination is pinned on first successful use.

An active adversary at that first contact is pinned as the genuine party.
Later checks then protect the adversary's position: they catch a change, not
a substitute that was there from the start. Fixing TOFU fixes all three.

No primitive can close it. Authenticating a party with whom nothing is
shared needs a trusted third party or a pre-shared secret
(docs/PQC_DECISIONS.md (e)). The mitigation is out-of-band verification:
the hybrid SMP, or comparing fingerprints. Each issue below refers here
instead of restating it.

| ID | Title | Severity | Status |
|----|-------|----------|--------|
| L1 | MAC-key revelation reveals all-zeros; deniability not achieved | Design | **RESOLVED-CODE** (2026-10-26). No property is claimed: the app describes the mechanism and its residuals; no deniability property is stated (audit 2026-10-26; the earlier "deniability pending external audit" wording is withdrawn from every surface). Mechanism: an exact retirement rule in the Rust ratchet (SPEC §5.8: R1 received, R2 skipped key deleted, R3 close; never a sender's own key), publication only as the encoded wire field, closing publication on End chat & publish keys, sign-out, Wipe & Exit, quit, the peer's end and errors, for every session. Gate: `tests/test_l1_revelation_gate.py` (T1-T8), `ratchet::l1_retirement`, `tests/test_mac_revelation_end_to_end.py`, `tests/test_deniability_wire_audit.py` (an outsider re-MACs every line from the wire alone), `tests/test_deniable_confirmation.py` (the server confirms the closing messages before the new session), `TestMultiPartClose`, `TestCrashDuringClose`, `tests/test_deniable_wording.py`, and the asserted residuals `test_residual_the_receiver_refuses_a_frame_only_the_outer_mac_was_forged_for`, `test_residual_a_peer_that_never_closes_leaves_our_lines_provable`, `test_residual_unconfirmed_the_new_session_starts_anyway_and_the_app_says_so`, `test_every_line_is_covered_across_dh_steps`. Both copies of the chat go (owner, 2026-10-27), on the button only: the presser's app sends a "keys published" message inside the session before closing it, and each side's app removes the chat's earlier messages once its own closing messages are confirmed by its own server; sign-out, quit and the contact ending the session clear nothing (`tests/test_keys_published_clears_history.py`, `DeniableChatTest`, `TestKeysPublishedReachTheTerminal`). Residuals: expert review of the rule; a lost closing part (partial close); the kill-to-confirmation window; an unanswered confirmation (the new session starts anyway); a peer that never closes; TOFU (shared residual) |
| U1 | Signed out, About -> back reached the signed-in chat list, and the device's identity fingerprint could be read before any login | Medium (privacy: device-account binding) | **RESOLVED** (2026-10-26) -- the bridge withholds the fingerprint until a login succeeds (`OtrApp.local_fingerprint`, security details, the desktop host's start-up message); Android shows only public screens while signed out and About goes back to sign-in; sign-out keeps nothing to navigate back to; the desktop and terminal show no fingerprint before login. `tests/test_u1_signed_out_surfaces.py`, `AuthGateTest`. Its residual (one identity shared by accounts) is resolved by F2 |
| F2 | Two accounts used one after the other in one app process (Android, desktop) or on one machine (terminal) presented the same long-term identity key, which every DAKE1 carries past the server: the accounts could be linked | Medium (privacy) | **RESOLVED** (2026-10-26) -- one identity per account (SPEC §3.1): a non-persisted identity is replaced, old handles zeroized in Rust, when a connection is prepared for a different account, before any byte is sent as it; the terminal keeps one sealed record per account, named by a hash. Key generation and sealing unchanged. `tests/test_f2_per_account_identity.py` |
| F3 | After F2, every sign-in on Android and the desktop showed a new fingerprint (identity per process): contacts were warned of a key change at each restart and verification had to be redone | Medium (usability of TOFU) | **RESOLVED** (2026-10-26) -- each account's random identity is kept per install, sealed in Rust, on Android also in the Keystore vault (SPEC §3.1): the same account on the same install keeps its fingerprint; accounts stay unlinkable. `tests/test_f3_stable_account_identity.py`. Residual: kept on the phone between runs, so code running as the app on an unlocked phone can use it |
| F4 | Secure-group (MLS) signatures were evidence for ever: every member's message carries a signature a third party can check, and a rekey only stopped the key signing more (docs/MLS_SECURITY_HARDENING.md §1, D1) | Medium (deniability) | **RESOLVED-CODE** (2026-10-26), not reviewed, no claim. **Containment conditional on acknowledgement before publication** (option A, 2026-10-27). Retired signing keys are published to the group (epochal signatures), after a delay or on "Publish Group Keys", built and checked in Rust; the keys never reach Python. `retired_key_tests` (incl. `a_publication_carries_both_halves_of_the_composite_key` and the asserted residuals `residual_a_signature_checked_before_release_still_checks_after_it`, `residual_only_the_groups_members_receive_the_published_key`), `tests/test_f4_group_key_publication.py`, `DeniableChatTest`, `tests/test_deniable_wording.py`.<br>**Containment.** The invariant, in the code's terms: a published key (one member's retired leaf key in one group, made at that member's self-update and in use until the next one, so possibly several epochs; there is no per-epoch key) can produce only signatures that verify under its own retired public key, i.e. forgeries for a transcript of what it signed. It signs nothing a member accepts after its retirement, no other key is derived from it, a message it signed in a closed epoch is refused by a member in a later epoch, and it is no key in any other group. **The condition, stated:** a member that has not processed the rotation is still in the old epoch and accepts a message signed with the old key and encrypted under that epoch's secrets, which every member holds (`residual_a_member_that_has_not_processed_the_rotation_accepts_the_retired_key_until_it_does`, the gap demonstrated). On `dev` from 2026-10-26 to this fix the key was published anyway, and a lagging member accepted such a message as the publisher's (run on the `5231cbc` code, docs/AUDIT_CLAIM_MATRIX.md row 2.5); F4 was never in a release. So a key is published only after every other current member has shown it is past the rotation: a message from it that verified in the rotation's epoch or later. Each member sends an acknowledgement after another member's rotation; any message counts; members who joined later need not, members removed are not waited for (`publication_waits_until_every_member_has_acknowledged_the_rotation`, `what_a_retired_key_waits_for_survives_a_restart`; in the apps `test_publish_group_keys_waits_for_a_member_who_is_offline`, `test_the_delay_does_not_publish_past_a_member_who_is_offline`, `test_each_member_acknowledges_another_members_rotation_and_shows_nothing`, `test_an_acknowledgement_that_could_not_go_is_sent_by_maintain`, `test_the_apps_show_who_the_keys_wait_for`, and in `DeniableChatTest` `while earlier keys wait for members the button is not offered and says why`). The button is disabled while keys wait and says for how many members. **Containment is enforced by** SPEC §10 requirement 11, which is implemented as two things: (1) acknowledgement before publication; (2) `max_past_epochs(0)`, stated in both group configurations. The library default is not load-bearing after option A: the setting is explicit, and a test checks it (`max_past_epochs_is_zero_in_every_group_config`). Tests 1-5 (`client::f4_containment_tests`): `releasing_epoch_N_key_cannot_sign_for_epoch_N_plus_1`, `epoch_N_plus_1_key_cannot_be_derived_from_epoch_N_key`, `a_message_signed_with_a_released_epoch_key_is_rejected_by_a_client_in_a_later_epoch` (behaviour, and the configuration's effect), `max_past_epochs_is_zero_in_every_group_config` (source check only: renamed 2026-10-27 from `the_epoch_authenticator_is_checked_before_any_group_message_is_accepted`, which named a check MLS does not make and a behaviour only test 3 shows), `epoch_keys_are_not_shared_between_groups`. **Mutations** (2026-10-27; Rust 8 run, 7 killed, 1 equivalent; Python 4 run, 4 killed, docs/AUDIT_TEST_INTEGRITY.md round 6): self-update keeps the old key, killed by tests 1 and 2; `max_past_epochs(1)` in both configurations, killed by tests 3 and 4 and by the gap test; a group reuses another group's key, killed by test 5; publication does not wait, killed by the two waiting tests and the gap test; a commit counts as everyone's acknowledgement, killed by the same three; a message counts for the epoch after its own, killed by `publication_waits_...`; the waiting state is not sealed faithfully, killed by `what_a_retired_key_waits_for_survives_a_restart`; a departed leaf's record is kept, equivalent (only current leaves are consulted, and a leaf filled again is overwritten at the join). Residuals: (cryptographic, permanent) a signature captured and verified before the release stays attributable for ever; release only makes the key's signatures forgeable from then on; the forgers are the group's members who received the publication, not anyone. (Containment) it relies on every member's client deleting past epochs, which no member can verify of another; a modified client that keeps them can forge only toward members still in the old epoch, and publication waits until there are none. (Availability) publication needs every member to come online after the rotation, and the publisher's app to be running; a member on a client from before acknowledgements never sends one, so nothing is published in that group until that member updates or is removed; an acknowledgement sent in an epoch that a later commit closes before it arrives is lost, and the member's next message or acknowledgement stands in for it. Past 16 retired keys per group the oldest are wiped unpublished (`retired_keys_are_bounded_and_published_in_batches`). (Cost) each acknowledgement is an ordinary group message, about 6.5 KB in two room pieces (the composite signature), so one per member per rotation. Every member's copy of the group goes on Publish Group Keys (owner, 2026-10-27): once the presser's keys are out, its app posts a group message saying so and each member's app removes the group's earlier messages; automatic publications clear nothing (`test_publish_group_keys_clears_every_members_copy_once_the_keys_are_out`, `test_the_members_copies_wait_until_the_keys_are_published`, `test_an_automatic_publication_clears_nothing`). |
| N1 | The route chosen from the server name (route.py) was followed by the code written to follow it, but not enforced on the process: a library, a mistyped flag or a new feature could open another socket or resolve a name | Medium (anonymity) | **RESOLVED for the app's own code** (2026-10-26) -- a process-wide audit hook (`otrv4plus_egress`) enforces the route from the gate every sign-in, account creation and server test passes first: on I2P and Tor only loopback and the configured bridge are reachable and nothing is resolved; no `.i2p` or `.onion` name reaches DNS on any route. `tests/test_n1_network_isolation.py`. Residual: the bundled i2pd is a separate process with its own reseed and router links; not yet confirmed by a device packet capture |
| M3 | Legacy DAKE path can hand session keys to Python as PyBytes | Medium | **RESOLVED** |
| G1 | `RustDAKEAdapter.is_expired()` is a stub; DAKE handshake timeout absent | Low | **RESOLVED** (2026-10-24) -- `tests/test_dake_timeout.py`; `test_08_dake_timeout` no longer an expected failure |
| G2 | Two divergent copies of `otrv4_testlib.py`; which loads depends on collection order | Low | **RESOLVED** (2026-10-24) -- one copy, `tests/otrv4_testlib.py`; `tests/test_dake_timeout.py::test_there_is_one_test_library` |
| B1-seed | Persisting an identity requires the seed to exist in Python | Design | **RESOLVED** |
| A1 | Ratchet brace key is never folded into root/chain keys (SPEC §5.2 not implemented): no post-quantum post-compromise recovery | Design / High (spec divergence) | **MITIGATED** (2026-10-24) -- mitigated by the new v2 ratchet, which rotates ML-KEM secrets about every round trip once the first DH ratchet step has happened (after 100 messages in one direction or 24 hours; before it the handshake's ML-KEM secret protects the keys) and folds each into the root (SPEC §5.1-5.2; `ratchet::pq_ratchet`, `tests/test_pq_ratchet_v2.py`). A peer without v2 is refused by default (`require_pq_v2`, code `pq_v2_required`), so the v1 derivation is no longer reached; its code remains for that switch and stays pinned by `ratchet::audit_brace_folding`. Kept listed as a known limitation: the combiner and its interleaving with loss want expert review (CRYPTO_AUDIT §7 item 3), and SPEC §5.1 states a residual |
| A2 | DAKE post-quantum authentication is initiator-only and strippable by an active quantum adversary | Design / Medium | **RESOLVED-CLAIM** (2026-10-24, claim narrowed by the audit of 2026-10-26 and restored by the P1 fix of 2026-10-27; claim: the v2 handshake authenticates both sides with ML-DSA-87 and refuses downgrade or key change for a pinned contact, across restarts, on Android (with a working Keystore), the desktop and the terminal; Android rc.159; requires both peers to list `PQ_RATCHET_VERSION` 0x50 and `PQ_AUTH_VERSION` 0x51) -- each identity has one long-term ML-DSA-87 key, sealed beside it; the responder signs the transcript in DAKE2 (`KDF_1(0x06, DAKE1 \|\| DAKE2-to-signature)`: both ephemeral X448 keys, the initiator's ML-KEM key and the responder's ciphertext, both profiles, both ML-DSA keys) and the initiator verifies it before DAKE3 or any data; the initiator signs DAKE3; both mandatory. An older peer is refused outright (`pq_v2_required`), and a known contact's ML-DSA key is pinned, so dropping or changing it under the same Ed448 identity is refused (`pq_downgrade`, `pq_key_changed`) even with the policy relaxed. SPEC §4.3. `dake::pq_auth_tests`, `mldsa::tests`, `tests/test_pq_auth_v2.py`, `tests/test_p1_trust_pins_per_run.py`. Residuals: TOFU (shared residual); on Android without a working Keystore the pins last one run (P1). Deniability cost: SPEC §10.1 |
| A3 | Crafted `.otrv` header overflowed `8 * p` before bounding p: process abort (overflow-checks + panic=abort) | Medium (DoS) | **RESOLVED** -- `container::tests::a_huge_lane_count_is_refused_not_an_overflow`; found by `fuzz/container_header` |
| A4 | Ring verifier accepted the identity point as a ring member (signable by anyone) | Low | **RESOLVED** -- `ring_sig::audit_identity_point` |
| A5 | Profile expiry and degenerate identity key enforced only in Python | Low | **RESOLVED** -- `dake::profile_tests` |
| A6 | Ring signature scalars reduced mod Q, so every signature had malleable re-encodings | Low / Info | **RESOLVED** -- `ring_sig::audit_identity_point::a_non_canonical_scalar_is_refused` |
| P1 | On Android and the desktop the contact pins were never checked, and lived in memory: a contact under a new identity was accepted in any run, and after a restart any changed key was a first contact, without a warning | High (authentication) | **RESOLVED** (found 2026-10-26, fixed 2026-10-27) -- the bridge checks the pin when a session comes up (`_check_contact_pin`): a changed key is FINGERPRINT_MISMATCH, `FingerprintChanged`, the pin kept, nothing queued sent. Each account's pins are kept sealed (`android_bridge.account_trust`): Android in the Keystore vault's own trust section, the desktop in 0600 files; apart from identities, server pins and history; destroyed by Wipe & Exit; a record that will not open is refused (`trust_unavailable`), retried, never replaced. `tests/test_p1_trust_pins_per_run.py` (24 tests; 14 mutants killed). Residuals: no working Keystore on Android, pins for one run; the terminal's pins are one record per install (P1 section). Follow-up the same day: the terminal client's pins sealed too, and refused when they will not open (`tests/test_terminal_trust_sealed.py`) |
| W1 | Wipe & Exit did not check its own file wipe: a file left behind, or one that could only be unlinked, was reported the same as a clean wipe, and the desktop closed with "Wiped." whatever happened. The overwrite was also untested | Medium (data at rest) | **RESOLVED-CODE** (2026-10-30). `_secure_file_destroy` overwrites once with CSPRNG bytes on flash and three times (zeros, ones, random, each fsync'd) on a disk Linux reports as rotational; anything not known to spin counts as flash. It raises if the file survives its unlink. `android_bridge.wipe.verify` looks under every state root afterwards; `verified` is true only with nothing left and no unlink-only file. Android fails the STOP_SUBSYSTEMS step on an unverified wipe (`WipeReport.ok`); the desktop exits only on a verified wipe and otherwise stays open and says what is left. `tests/test_secure_file_destroy.py` (bytes read at each fsync; 17 mutants killed), `WipedMessageTest`. Residuals: flash wear levelling can keep the old block whatever the overwrite does -- no file-level method reaches it, so the purge-grade guarantee is the Android vault's cryptographic erase, not this; the desktop's key files were plain 0600 files beside the data -- since 2026-10-30 they are wrapped by a key-wrapping key kept in the platform key store and deleted first at Wipe & Exit (crypto-erase; `tests/test_key_custody.py`, Rust `at_rest` KEK tests; 11 mutants killed); the server pins file, plaintext JSON until then, is sealed under its own wrapped key file (`TestThePinsFileIsSealed`; 5 mutants killed); a 1:1 file arriving in the apps is sealed chunk by chunk under a per-run RunKey (256 random bits made in Rust, never written) and resealed straight into its container, so its `.part` is never plaintext and one left by a crash opens under no key (`tests/test_partial_file_sealed.py`; 4 mutants killed); group files the same, pieces in any order, each record bound to its index (`TestAGroupFileIsNeverPlaintextOnDisk`; 4 mutants killed) -- the desktop viewer's temporary copy is still plaintext while it is open, but on Linux it is in RAM ($XDG_RUNTIME_DIR, else /dev/shm; `ViewDirectoryTest`), never on the disk unless swapped; on macOS and Windows it is beside the received files until closed, but only where a keyring is reachable (Secret Service, macOS login Keychain), whose own file is encrypted under the login password; hardware stores (TPM 2.0, Secure Enclave, Windows CNG) and Windows are not implemented yet |
| P2 | A forced DH step toward a remote key already stepped toward could not be followed by the peer: every later message failed to decrypt, silently. Reached by the 101st message from one side after a DH round trip (measured; up to the 200th with no DH step yet), or by a chat open across two 24-hour boundaries | High (availability; silent message loss) | **RESOLVED** (2026-10-26) -- one send step per remote key (`RustBackedDoubleRatchet._forced_toward`). `tests/test_p2_forced_steps.py` (every test fails on the old engine), Rust `pq_ratchet::p2_a_second_send_step_toward_the_same_remote_key_cannot_be_followed`. Residual: a peer on an older build can still take the double step |
| X1 | With TLS certificate checks off (I2P, .onion), a server reached by a human-readable `.i2p` NAME is bound only by the router's address book; a substituted server can offer only SASL PLAIN and capture the XMPP account password | Medium | **RESOLVED-CLAIM** (Android and the terminal client; claim: a changed destination receives no byte, and no password is sent where certificate checks are off) -- both options, combined: the resolved destination is pinned per server name and a changed one is refused before STREAM CONNECT (nothing reaches it; explicit, confirmed re-approval of exactly that destination), and SASL is SCRAM-only wherever certificate checks are off. `tests/test_x1_destination_pinning.py`, `tests/test_x1_terminal_client.py`. Residuals: TOFU (shared residual); SCRAM guessing and first registration (X1 section). An unreadable pins file is refused, never read as empty (residual 5, fixed 2026-10-27; `TestAnUnreadablePinsFileIsRefused`). NOT yet confirmed by a handset login |

---

## L1 — MAC-key revelation reveals all-zeros

The action is **End chat & publish keys…** (Android, desktop) and `/deniable` (the
terminal). It was called "Make Chat Deniable…" until 2026-10-27, and the code
keeps that name in its identifiers (`make_chat_deniable`, `made_deniable`).
It was renamed because a label that names a property the code does not
demonstrate is a claim (docs/AUDIT_CLAIM_MATRIX.md 1.10).
`DeniableChatTest` and `tests/test_deniable_wording.py` pin the new labels.

**Status: RESOLVED-CODE, 2026-10-26.** The mechanism is implemented and
tested end to end; this file claims no property for it until the external
review of the retirement rule (SPEC §5.8; docs/CRYPTOGRAPHER_QUESTIONS.md
Q1, Q2). The app describes the mechanism and its residuals; no deniability
property is stated. The audit of 2026-10-26 withdrew the earlier
"deniability pending external audit" from the Android and desktop dialog
and the terminal's `/help`; `DeniableChatTest` and
`tests/test_deniable_wording.py` hold every surface to that. See
docs/DENIABILITY_LAYERS.md and docs/AUDIT_CLAIM_MATRIX.md §1.

### What the mechanism does, and what it does not cover

What it is for: a copy of a closed chat held by someone else -- the
contact's, or a recording of the traffic -- should not prove who wrote
what. Whether it achieves that is the review question. What the tests show
rests on four things:

1. **Symmetric authentication.** Every message is authenticated with keys
   both sides hold (SPEC §10.1), so either party could have produced any
   message in the transcript.
2. **Every line's MAC key goes on the wire.** It is sent in the
   `revealed_mac_keys` field, after the MAC and outside the ciphertext, so
   anyone can read it without a key. `tests/test_deniability_wire_audit.py`
   is an outsider holding only the frames two real apps sent. For every line,
   in both directions, it finds a revealed key that re-MACs it. That
   includes a line lost on the way and one delivered out of order, whichever
   side pressed the button. No key is on the wire before its message was
   delivered. Nothing revealed authenticates the new session. A negative
   control shows the last lines stay provable if the closing messages are
   lost.
3. **Whether the closing messages arrived is asked, not assumed.** Publish
   Chat Keys asks our server to confirm it received them, then starts
   the new session whatever the answer (within 15 s); the result says
   whether the server confirmed. The server answers a XEP-0199 ping only
   after reading everything before it. Wipe & Exit and sign-out end the
   stream and wait for the server's end. Unconfirmed closing messages are
   kept in memory only -- never written to disk -- and sent again, up to
   40 times while the app runs
   (Android, desktop; the terminal 5 times). Gate:
   `tests/test_deniable_confirmation.py` (real slixmpp against a scripted
   server, including
   `test_residual_unconfirmed_the_new_session_starts_anyway_and_the_app_says_so`
   and `test_a_closing_message_is_given_up_after_its_tries`),
   `tests/test_closing_messages_arrive.py`.
4. **The rule itself** (SPEC §5.8): `tests/test_l1_revelation_gate.py`
   (T1-T8) and `ratchet::l1_retirement`.

**Not covered, and said so in the app:**
- **Having talked.** The v2 handshake's ML-DSA-87 signatures are
  attributable under long-term keys (SPEC §10.1), so a transcript shows that
  both took part. The confirmation text says "It does not hide that you two
  talked".
- **Delivery to the contact.** The server's confirmation is the furthest the
  app can know. A contact who never comes back online may never receive
  their copy of the keys. The keys are on our server and on the wire either
  way.
- **The second closing.** Each side publishes the keys of what it received,
  so complete coverage needs the contact's app to close too. It does as soon
  as it reads our closing message (the audit covers both sides). A contact
  whose app never closes keeps the MAC keys of what we sent unrevealed:
  exactly the lines it received after it last sent anything
  (`test_residual_a_peer_that_never_closes_leaves_our_lines_provable`).
  That copy is still not proof against us, by point 1; a recording of the
  traffic still shows those lines came from one of the two of us.
- **Residual: the kill-to-confirmation window.** The re-sending lives in
  memory only. If the process dies between `retire_all` and the server's
  confirmation, the keys are retired and wiped, never published, and that
  close's transcript stays provable. Exactly the lines the lost closing
  messages would have covered, as `TestCrashDuringClose`
  (`tests/test_l1_crash_during_close.py`) shows with a real process killed by
  SIGKILL. Persisting the closing messages so they could be sent on the next
  launch was considered and rejected: it would leave a record on the device
  of whom the chat was just made deniable with. The app reports such a close
  as unconfirmed before the window opens (`made_deniable_unconfirmed`).
- **Residual: a partial close.** A close with more than 2000 retired keys
  goes out in several closing messages, each publishing its own range,
  oldest first. A lost part leaves exactly its range provable until the
  client re-sends it; it keeps every part until the server confirms. Gate:
  Rust `ratchet::l1_retirement::a_close_over_the_bound_is_several_messages`,
  `::each_part_publishes_only_its_own_range_oldest_first`,
  `::residual_a_lost_later_part_takes_its_range_with_it`, and
  `TestMultiPartClose` in `tests/test_deniability_wire_audit.py`. There, the
  outsider's audit rejects a transcript whose second part is missing, and
  accepts it once the part is re-sent.
- **Forgery cuts both ways.** Once the keys are public, anyone holding the
  traffic can produce lines whose MAC verifies for that closed session,
  including someone fabricating "evidence" against you. The transcript then
  proves neither your authorship nor that a fabrication is not yours. That is
  the property; the remaining risk is a reader who does not know the keys
  were published. MAC release does not touch the handshake's ML-DSA
  signature, which is why "that you talked" stays provable. The research
  prototype `research/epochal-mldsa` (not in the app) tests whether epochal
  ML-DSA keys can close that gap; see its ANALYSIS.md.

### What was wrong, last

The all-zeros placeholder was fixed on 2026-09-28: the receiver's MAC key
(MKmac, OTRv4 §4.4.2) was revealed in its next message. Three things still
stood between that and a claim this file can mark resolved:

1. **Premature revelation.** At every DH ratchet step the ratchet also queued
   the MAC key of the last message it had SENT. The peer could still be waiting
   for that message, or holding it as a skipped key.
2. **No retirement on deletion or close.** A message that never arrived had
   its MAC key published by nobody, even after its skipped key was evicted;
   and nothing was published when a session ended. Past 50 queued keys the
   oldest were wiped without ever being published.
3. **The boundary.** Retired keys crossed to Python as a list of `bytes`.

### The rule (SPEC §5.8)

A MAC key is retired only when nothing can be verified with it any more:

- **R1** its message was received and authenticated (the replay cache then
  refuses a second copy);
- **R2** its message never arrived and the skipped message key is deleted:
  evicted at `MAX_MESSAGE_KEYS` (2000, the existing bound), or at close;
- **R3** close (`retire_all`): R2 for every skipped key still held, after which
  the ratchet decrypts nothing.

A sender never retires the key of a message it sent: only the receiver knows
when that message is finished with. DH steps use no MAC key, and no key from a
chain position not yet used is ever retired. This is the four-part predicate
the issue asked for: not a current receiving key; no skipped key depends on
it (each MAC key depends only on its own message key); the peer's one message
that used it has been received (R1) or can never be (R2, R3); and no DH step
depends on it.

### What ships

- `Rust/src/ratchet.rs`: a private retired queue (each key boxed, wiped in
  place as it is written into the field, wiped on drop); `retire_all`;
  `encrypt_final` (closing messages of up to 2000 keys, repeated until the
  queue is empty, then the ratchet is closed). The Python result carries only
  `reveal_field`, the encoded wire field; MKmac stays a `MessageMacKey` handle.
- A late message from an older chain whose skipped key is still held is
  decrypted on the skipped path instead of failing as a DH step (it used to
  be refused, so its key was never retired by receipt).
- The engine: `close_with_revelation` runs in `_cleanup_resources`, so every
  path that destroys a ratchet publishes first; `make_deniable`; sign-out,
  quit and Wipe & Exit close every session with DISCONNECTED;
  `take_final_revelations` hands the closing messages to the client; an ended
  session is never reused by a new handshake.
- The clients send them: Android and desktop (`app_deniable.py`; after each
  inbound frame, at sign-out, at Wipe & Exit before the transport closes) and
  the terminal client (`/deniable`, `/quit`). "End chat & publish keys…" in every
  established 1:1 chat on Android and desktop, `/deniable [jid]` in the
  terminal. Offline, the closing messages are kept in memory only and sent
  when the connection is back; they are never written to disk (see "the
  kill-to-confirmation window": a closing message on disk would record whom
  the chat was made deniable with), so if the app ends first they are lost.
  The keys are retired and wiped in Rust all the same. Gate:
  `TestCrashDuringClose::test_no_mac_key_is_on_disk_after_the_kill`,
  `::test_the_next_launch_holds_no_key_and_re_sends_nothing`.

### Regression gate

`tests/test_l1_revelation_gate.py`:

| | Test |
|-|------|
| T1 | `TestT1PositiveDeniability::test_a_published_key_lets_anyone_mac_an_altered_copy_of_an_observed_message` (renamed by the audit: it forges the outer MAC only), `::test_residual_the_receiver_refuses_a_frame_only_the_outer_mac_was_forged_for` |
| T2 | `TestT2NoPrematureRevelation::test_a_long_conversation_with_loss_and_dh_steps_publishes_nothing_early`, `::test_a_sender_never_publishes_the_key_of_its_own_message`, `::test_the_check_catches_a_transcript_that_reveals_early` (mutation) |
| T3 | `TestT3SkippedMessages::test_unpublished_while_held_across_a_dh_step_then_published_late`, `::test_a_skipped_key_deleted_at_close_is_published` |
| T4 | `TestT4PublishedKeysAreNotHeld::test_a_published_key_is_no_longer_held`, `::test_close_leaves_nothing_retired_nothing_skipped_and_no_ratchet` (renamed from `TestT4Zeroization` by the audit: it shows the key is not held; the overwrite is zeroize-on-drop, not observable) |
| T5 | `TestT5PublishChatKeys::test_final_publication_disconnect_and_a_fresh_session_sharing_no_key` (renamed by the audit from `..._fresh_unlinked_session`), `::test_no_session_no_action` |
| Residuals | `TestL1Residuals::test_residual_an_altered_outer_mac_costs_the_message_and_its_key_is_published` |
| T6 | `TestT6SignOutWipeQuit::test_every_session_publishes_before_its_keys_go[sign_out]`, `[wipe]`, `::test_the_peers_closing_message_after_our_end_starts_no_handshake`, `::test_offline_the_keys_are_still_retired_and_wiped`, `::test_the_bridge_sends_them_before_the_transport_goes`, `::test_the_bridge_sends_each_closing_message_once` (renamed by the audit: it never tested an offline transport) |
| T7 | `TestT7WireCompatibility::test_a_peer_reading_the_field_by_shape_only_accepts_real_keys`, `::test_the_field_is_outside_what_the_mac_covers`, `::test_a_peer_implementing_it_accounts_for_every_key_it_is_shown` |
| T8 | `TestT8NoMacKeyBytesInPython::test_the_ratchet_hands_over_the_field_and_handles_only`, `::test_a_mac_key_handle_has_no_bytes`, `::test_no_production_path_unpacks_the_field_into_keys`, `::test_the_deniable_paths_move_wire_text_only` |

Rust: `ratchet::l1_retirement` (R1, no sender reveal across DH steps, skipped
keys held across a DH step, late old-chain message, R2 eviction, R3 close,
closed ratchet, T4 wipe, queue bound). The T4 accessor `holds_mac_key` exists
only in test builds; `tests/test_release_guard.py` asserts a release wheel has
none. Also `tests/test_mac_revelation_end_to_end.py`, `test_reveal_ordering.py`,
`test_revealed_mac_crosscheck.py`, and `DeniableChatTest` (the UI words).

### Residuals

- **Expert review of the retirement rule** (SPEC §5.8) before any claim of
  deniable messaging; the dialog and `/help` describe the mechanism, say it
  has not been independently reviewed, and name the copy made before the
  publication and the close that does not finish.
- The MAC key of the outer OTRv4 MAC is published; AES-GCM, the primary
  authenticator, is keyed by the message key, which is never published. A
  third party with a published key can forge the outer MAC of a transcript
  entry, which is the OTR sense of transcript deniability; it cannot produce a
  ciphertext the receiver would have decrypted
  (`test_residual_the_receiver_refuses_a_frame_only_the_outer_mac_was_forged_for`).
- A message whose outer MAC fails after its AEAD tag verified has its MAC key
  retired anyway (R1 commits at the AEAD); the replay cache refuses any second
  copy, so nothing can be verified with it. An attacker who alters one outer
  MAC therefore costs that one message, silently, and its key is published
  (`TestL1Residuals::test_residual_an_altered_outer_mac_costs_the_message_and_its_key_is_published`;
  docs/CRYPTOGRAPHER_QUESTIONS.md Q1).
- TOFU: see "Shared residual" above. v2's ML-DSA handshake signatures are
  attributable (SPEC §10.1): participation is not deniable, independently of
  this item (docs/DENIABILITY_LAYERS.md).

### The closing messages leave before the connection does (2026-10-26)

Owner: on Wipe & Exit every chat must publish its MAC keys before the wipe.
The engine already did the cryptographic part. Every MAC key is retired and
each session's closing message is made before anything is destroyed, and the
closing messages are sent while the connection is still up. What was **not**
ensured is that they left the device. `send` only queues a stanza in slixmpp,
and the teardown then **aborted** the client (Wipe & Exit) or closed the I2P
tunnel right after slixmpp's non-blocking `disconnect()` (sign-out). With real
slixmpp, an abort drops a queued stanza.

Now sign-out and Wipe & Exit end the stream properly
(`XmppTransport._end_stream`):
1. slixmpp's send queue is drained;
2. our `</stream:stream>` goes after it;
3. the server's end is awaited, bounded by `END_OF_STREAM_TIMEOUT`.

An XMPP server answers the end of a stream only after reading everything
before it, and TCP and I2P streams are ordered. So its answer confirms that
every closing message reached the server. Wipe & Exit reports this as
`closing_confirmed`. Gate: `tests/test_closing_messages_arrive.py`, using real
slixmpp against a scripted server on loopback:
- an abort drops the message (the old behaviour);
- the new end of stream delivers it before the end, and waits for a slow
  server;
- a server that never answers costs the bound, not a hang;
- the wipe ends the stream before closing.

Limits:
- Confirmed **to the server**, not to the peer. A peer who is offline, or
  whose server does not store messages, may never receive its closing
  message. Offline at the press, the closing messages wait in memory and go
  when the connection is back (`test_offline_at_the_press_they_go_when_it_is_back`);
  if the app ends first, the keys are retired and wiped but published
  nowhere.
- If the server does not answer within the bound, the wipe carries on.
  Nothing waits longer than that, and the report says the closing was not
  confirmed.

---

## U1 — Signed-out navigation reached signed-in screens and the device fingerprint

**Status: RESOLVED, 2026-10-26.**

### What happened

Device report: signed out (credentials cleared, not wiped), the next launch on
the sign-in screen, overflow -> About & licences, then back: the app landed on
the empty chat list, a signed-in surface, and from there the device's identity
fingerprint could be read. The About screen's back always went to the chat
list. The desktop sign-in screen also showed the fingerprint, and the desktop
host announced it in its start-up message, before any login.

Why it matters: the fingerprint is the device's long-term identity key. Read
before a login, it can later be matched with the server's record of a login
from this device -- "this device was used by that account".

### The fix

- **The bridge is the gate.** `OtrApp.local_fingerprint()` -- and the
  `local_fingerprint` of security details, and the desktop host's `ready`
  message -- is "" until `note_signed_in(account)`, which the connection
  controller calls only after the server accepted the login. `shutdown`
  (sign-out), `disconnect`, and Wipe & Exit clear it first.
- **Android navigation.** Every screen goes through `AuthGate.shown`: while
  signed out only Sign in, About & licences and Debug render; anything else
  shows Sign in. About's back (button and swipe) goes to Sign in while signed
  out. The service's `signedIn` is set only when a connection succeeds and
  cleared at the account boundary (another account, sign-out, wipe); the
  view-model clears it at once on Sign out. When sign-out lands, the open
  chat, the profile shown, the tab and the identity read for the profile are
  dropped (`SignedOutReset`, `ChatViewModel.forgetIdentity`).
- **Desktop.** No fingerprint on the sign-in screen; it is read after a login
  succeeds and cleared before disconnect.
- **Terminal.** `/identity` withholds the fingerprint until the XMPP session
  has started (authenticated) and again from `/quit`.

Sign-out remains distinct from Wipe & Exit, which is unchanged.

### Regression gate

`tests/test_u1_signed_out_surfaces.py`:

| | Test |
|-|------|
| U1-T1 | `test_u1_t1_about_goes_back_to_sign_in_while_signed_out`; `AuthGateTest` `U1-T1 back from About while signed out is sign-in` |
| U1-T2 | `test_u1_t2_only_public_screens_render_while_signed_out`, `test_u1_t2_sign_out_keeps_nothing_to_navigate_back_to`, `test_u1_t2_signed_in_means_a_login_succeeded_for_this_account`; `AuthGateTest` `U1-T2 no signed-in screen can be shown while signed out` |
| U1-T3 | `test_u1_t3_the_bridge_gives_no_fingerprint_while_signed_out`, `test_u1_t3_no_public_screen_reads_a_fingerprint`, `test_u1_t3_the_profile_forgets_what_it_showed` |
| U1-T4 | `test_u1_t4_the_desktop_host_announces_no_fingerprint_before_login`, `test_u1_t4_the_desktop_screens_show_none_before_login`, `test_u1_t4_the_terminal_withholds_it_until_signed_in` |
| U1-T5 | `test_u1_t5_a_successful_login_brings_it_back`, `test_u1_t5_only_a_successful_connect_signs_in`, `test_u1_t5_an_address_that_is_not_an_account_signs_nobody_in`; `AuthGateTest` `U1-T5 signed in everything is reachable` |
| U1-T6 | `test_u1_t6_sign_out_then_another_account`, `test_u1_t6_shutdown_and_wipe_sign_out_first`, `test_u1_t6_the_engine_holds_no_previous_session_for_the_next_account` |

The navigation tests pin the Compose wiring at source level and run the rule
on the JVM; there is no instrumented (on-device) test of the back stack in
this repository. A device check is listed in the release notes.

### Residual

Resolved by F2. (As first written, this said the identity was per device. It
was per app process on Android and desktop -- `OTRConfig()` does not persist
it -- and per machine in the terminal client; either way two accounts could
share one.)

---

## F2 — One identity per account

**Status: RESOLVED, 2026-10-26.**

### What was wrong

The fingerprint is `SHA3-512(Ed448 identity public key)`, and that public key,
with the pinned ML-DSA key, travels in the ClientProfile of every DAKE1 -- an
`?OTRv4` message body the XMPP server relays and can read (on I2P there is no
TLS at all). On Android and the desktop the engine's identity is not persisted
and lives as long as the process; the terminal client keeps one sealed
identity for the machine. Two accounts used one after the other therefore
presented one key, linking them for the server and for any peer of both.

### Why not a derived fingerprint

Proposed first: show `KDF(device key || username)` as the fingerprint. It was
not done: it would change only the string people compare, while the server and
every peer still see the same raw key in DAKE1. A residual marked resolved by
it would have been a false claim.

### The fix (SPEC §3.1)

- **Android, desktop** (identity per process): `OtrApp.bind_identity_account`
  runs in `controller_for`, which every sign-in and account creation calls,
  before anything is sent. The first account takes the start-up identity,
  which nobody has seen; another account gets new Ed448 and ML-DSA identities
  (`EnhancedSessionManager.rotate_identity`, the same generation code), the old
  handles zeroized in Rust, every session and handshake of the old identity
  ended deniably (L1), in-memory pins discarded. The fingerprint stays dark
  until the new account's own login (U1).
- **Terminal** (persistent identity): one sealed record per account,
  `identity.<h>.sealed`, `h` a domain-separated SHA3-256 of the bare JID, so
  the JID is not in the file name. The record from before is kept by the
  first account to sign in afterwards, so its contacts see no key change.

Key generation and sealing are unchanged; only which account an identity
belongs to is. The fingerprint is a hash of a public key: no private or
seed material crosses from Rust.

### Regression gate

`tests/test_f2_per_account_identity.py`: rotation gives a new key and zeroizes
the old handles; the old identity's sessions and pins go; a persisted identity
is never rotated; **two accounts in one process present different keys in
DAKE1, as the peer sees them**; the same account on two devices has two keys;
the same account again keeps its key; a switch hides the old fingerprint until
the new login; junk never rotates; every connection binds before anything is
sent; the terminal's records are per account, named by hash, the old record
claimed once, and two accounts load two real identities while one account
keeps its own across runs. Also `VerificationTest` (the About text says each
account has its own identity).

---

## F3 — The same account on the same install keeps its identity

**Status: RESOLVED, 2026-10-26.**

### What was wrong

F2 gave each account its own identity, but on Android and the desktop that
identity still lived only as long as the process. A handset test confirmed it:
two accounts, both with a new fingerprint at every sign-in. Every contact saw a
key-change warning after each restart, which trains people to dismiss the
warning TOFU depends on.

### Why not a key computed from the username and the device

Asked for first: compute the identity so it is the same for username + device.
A key computed from inputs that are not secret (a device ID, a serial, the
username) is a key anyone who learns them can compute. It would also need a
production entry point that takes raw seed material, which the release guard
forbids. Not done.

### The fix (SPEC §3.1)

Each account's identity is random, made by Rust on its first sign-in on this
install, sealed and opened inside Rust under the install's 0600 key file
(the existing `create_sealed_identity_under` / `seal_mldsa_identity_under`
path the terminal client uses), and kept:

- **Android:** in the Keystore vault, sealed again under a key in the
  AndroidKeyStore, in a vault directory of its own (clearing chat history
  cannot reach it). Kotlin sees only Rust-sealed ciphertext.
- **Desktop:** as 0600 files under `~/.otrv4plus/identity`.

`OtrApp.bind_identity_account` opens the account's identity before anything
is sent as it (`EnhancedSessionManager.adopt_identity`). The identity presented
until then is zeroized, its sessions end and in-memory pins go. A record that
will not open is refused (`identity_unavailable`), never replaced.
Wipe & Exit deletes the Keystore key and destroys `~/.otrv4plus`, so the
next sign-in creates a new identity.

### Regression gate

`tests/test_f3_stable_account_identity.py`:
- every sign-in to the same account on one install shows the same
  fingerprint, on Android and the desktop;
- the peer sees the same key after a restart;
- switching back to an account brings its identity back, and case or
  resource do not make another;
- two accounts present different keys on the wire; the same account on
  another install has another key; a reinstall or wipe gives a new one;
- the vault holds two records per account, named by hash, not containing the
  public key, and they will not open without this install's key file;
- the desktop records are 0600 files under the wiped root;
- a tampered record is refused and nothing is replaced;
- the identity presented before is zeroized;
- the desktop host and the Android core install the store; the identity vault
  is separate from chat history and destroyed by Wipe & Exit;
- without a store, F2's behaviour remains;
- the terminal's record names are unchanged.

Also `VerificationTest` (About says the identity is kept per account on this
install, and that reinstalling, Wipe & Exit or an unusable keystore change it).

### Residuals

- The identity now stays on the phone between runs. A powered-off phone, a
  copy of its files or a backup (backups are off) holds only ciphertext under
  the Keystore key. Code running as the app on an unlocked phone can use the
  identity, as it can use the saved password: background reconnect needs both
  without the user present (KeystoreVault).
- The desktop has no keystore: the records and the key file are protected by
  the user account's file permissions only, like the terminal client's.
- The verified mark is still not saved; a verification lasts until the app
  closes, and the app says so.
- A record that will not open shows as a connection failure and is retried.
  It is not replaced; Wipe & Exit starts over.

---

## N1 — The route is enforced on the whole process

**Status: RESOLVED for the app's own code, 2026-10-26.**

### The rules

| Server name | Route | May reach | Name resolution |
|-------------|-------|-----------|-----------------|
| `*.i2p`, `*.b32.i2p` | I2P over SAM | loopback and the configured SAM bridge only | none (the router resolves `.i2p` names, inside I2P) |
| `*.onion` | Tor SOCKS5 | loopback and the configured SOCKS port only | none (the name travels inside SOCKS CONNECT) |
| anything else | TLS, certificate and hostname checked | any | DNS (SRV first) |
| every route | | never a `.i2p` / `.onion` name directly | never a `.i2p` / `.onion` name |

`android_bridge.route` chose this from the name before; nothing enforced it.
Now `otrv4plus_egress` installs a CPython audit hook (PEP 578) that refuses
`socket.connect`, `sendto`, `sendmsg` and every resolver call (forward and
reverse) that the active route does not allow. A refusal is an `OSError`; it
cannot be bypassed from Python, libraries included. slixmpp's aiodns (c-ares,
which resolves outside Python's socket layer) is switched off on the I2P and
Tor routes, and the APK does not ship it at all. The rule is entered in the
route gate that sign-in, account creation and the server test all pass first,
so no authentication or registration byte goes out before it; sign-out leaves
it. The terminal client enters it before opening any tunnel, and refuses
`--no-i2p` for an `.i2p` server rather than sending the name to a resolver.

**Router choice stays localhost-only.** A local I2P app's SAM bridge on
127.0.0.1:7656 is preferred (SAM HELLO probe, loopback only); otherwise the
bundled router, whose SAM listens on 127.0.0.1 only. No LAN address, scan or
discovery is tried. A SAM bridge elsewhere is used only when typed into the
desktop's connection settings, must be an IP address (a name would need DNS),
and the screen warns that SAM has no authentication.

### Regression gate

`tests/test_n1_network_isolation.py`: the rule's table for every route;
hidden names refused on every route; an explicit bridge elsewhere must be an IP
and is the only exception; real `connect`, `sendto`, `getaddrinfo`,
`gethostbyname`, `gethostbyaddr` and asyncio lookups refused on I2P and Tor;
`.i2p` lookups refused on clearnet; aiodns off on hidden routes; the rule in
force before the bridge is even probed, for `.i2p`, `.b32.i2p` and `.onion`;
a hostname bridge refused before any lookup; sign-in, account creation and the
server test all pass the gate first; **the whole SAM path, through the Android
transport and the real forwarder against a scripted SAM bridge, touches only
loopback and resolves nothing**; the Kotlin probe asks only 127.0.0.1:7656,
with no LAN or discovery code; the bundled router listens on loopback with its
HTTP, proxy, control and UPnP interfaces off; sign-out stops it and leaves the
route; the APK carries the rule and no networking library beyond slixmpp and
PySocks. Also `test_i2p_naming_no_dns.py`, `test_tor_transport.py`,
`test_tls_follows_transport.py`, `test_route_parity.py`.

### Scope and residuals

- **The bundled router is its own process.** i2pd reseeds over HTTPS on its
  first start (resolving the reseed hosts through the system resolver) and
  then talks to other I2P routers over UDP/TCP: that is I2P working, and it
  never carries the server's name. None of it happens when a local I2P app on
  127.0.0.1:7656 is used. The rule above binds the app's own code.
- **Not yet confirmed by a device capture.** A PCAPdroid capture of an `.i2p`
  account should show only the router's peer traffic (and its reseed, on a
  first start) and no port 53 from the app. Listed in the release notes.
- Android's own services (for example the location provider behind a shared
  position) are the system's, not the app's.

---

## M3 — Legacy DAKE path can hand session keys to Python

**Status: RESOLVED. Compiled out of production builds.**

Regression tests: `tests/test_release_guard.py::test_production_artifact_exposes_no_legacy_dake_session_keys`
and `::test_production_dakeresult_exposes_no_secret_getters`.

The five `Dakeresult` secret getters and `PyDake::generate_dake2` /
`process_dake2` / `get_session_keys` are behind the `legacy-dake-keys` Cargo
feature, OFF by default. They are **absent from a production artifact**, not
merely undocumented. `Rust/build.rs` refuses to build with the feature unless
`OTRV4PLUS_ALLOW_LEGACY_DAKE_KEYS=1` is set explicitly. The live DAKE
implementation is unchanged — `generate_dake2_output` / `process_dake2_output`
use a different internal path and were not touched.

Verified across three wheels: production (guard passes), legacy without opt-in
(guard **fails**, catching the surface), legacy with opt-in (passes).

The original analysis, retained for the record:

### What exists

`Rust/src/dake.rs` exposes `PyDakeSessionKeys` with PyBytes getters for
`root_key`, `chain_key_a`, `chain_key_b`, `brace_key` and `mac_key`, reachable
through `PyDake.get_session_keys()` and the legacy `generate_dake2` /
`process_dake2`. The safe path — `generate_dake2_output` / `process_dake2_output`
— returns an opaque `DakeOutput` whose keys move Rust-to-Rust via
`consume_into_ratchet()` and never become PyBytes.

### Every caller, checked

Production Python calls `RustDAKEAdapter.generate_dake2` / `process_dake2`
(`otrv4+.py`), each of which runtime-feature-detects:

```python
use_output_api = hasattr(self._rust, "generate_dake2_output")
if use_output_api:
    ...                      # opaque DakeOutput; no key bytes
else:
    result = self._rust.generate_dake2(...)
    self._session_keys = self._unpack_session_keys(result, ...)   # PyBytes
```

`_unpack_session_keys` is the only code that reads those getters. The
`hasattr` check that guards it **cannot be false in any importable build**:
`_check_rust_requirements()` (`otrv4+.py:70`) raises `ImportError` at import
time unless both `generate_dake2_output` and `process_dake2_output` are present
on `RustDAKE`. A build missing them cannot get far enough to reach the fallback.

The legacy branch is therefore **dead code on the live path**, confirmed by
reading the gate rather than inferred.

Outside production, the only callers were `tests/test_attacks.py` and
`tests/test_otrv4_integration.py`, both of which have been migrated (see
`tests/test_otrv4_integration.py::test_04/05/06`, which now assert the opposite
property: that `brace_key`, `root_key`, `chain_key_*` and `mac_key` are *absent*
from the session-keys dict).

### Does Android require it?

No. `android_bridge/app.py` never touches session keys; the bridge's contract
is that no secret crosses into Kotlin, and a test asserts `OtrApp` exposes no
key-shaped accessor.

### Does it expose secrets across the boundary?

Only if executed, which it cannot be. The hazard is latent rather than live: a
future refactor that relaxed the import gate, or added a caller, would silently
re-open a PyBytes path for root and chain keys.

### Disposition

**Recommend (B): gate the legacy entry points behind an explicit test-only
Cargo feature**, reusing the `test-only-kdf` mechanism now enforced by
`Rust/build.rs`, so a production build cannot compile them at all.

Rationale for B over the alternatives:

- **(A) remove outright** — cleanest, but `generate_dake2`/`process_dake2` are
  also the only DAKE entry points some Rust-side tests use, and deleting them
  is a larger change than Phase 2 should make to the crypto core.
- **(C) replace with opaque handles** — already done; `*_output` is that
  replacement. Nothing further to build.

Not executed in Phase 2 because it touches `dake.rs`, and the phase brief
requires the disposition to be documented and agreed rather than applied
unilaterally. It is a small, self-contained change once approved.

---

## G1 — DAKE handshake timeout is a stub

**Status: RESOLVED (2026-10-24).** `is_expired()` now counts from the
handshake's first move out of IDLE (DAKE1 sent or received), on the monotonic
clock, against `timeout` (default `UIConstants.DAKE_TIMEOUT`, 120 s). IDLE,
ESTABLISHED and FAILED never expire: an established session's age remains
`is_session_expired()`'s question. Tests: `tests/test_dake_timeout.py` (in
flight, not started, over, wall clock ignored); `test_08_dake_timeout` passes
and is no longer marked as an expected failure. Removing the check fails both.

The original analysis, retained for the record:

`RustDAKEAdapter.is_expired()` unconditionally returns `False`. The `timeout`
attribute callers may set is never read, and `UIConstants.DAKE_TIMEOUT = 120.0`
is defined but referenced nowhere in the codebase. The pure-Python `OTRv4DAKE`
that carried this mechanism was deleted at v10.7 and the behaviour was not
carried over.

**Impact today is nil**: `is_expired()` has no production callers. The separate
`is_session_expired()` — age of an *established* session — is implemented
correctly and is called (`otrv4+.py:5825`).

The hazard is that a future caller gets a silent "never expired". A half-open
DAKE would then be retained indefinitely, which on a mobile client is a
resource-exhaustion concern rather than a confidentiality one.

Tracked visibly as an expected failure:
`tests/test_otrv4_integration.py::test_08_dake_timeout`. It is marked
`@unittest.expectedFailure` with the reasoning inline, so the gap shows up in
every test run instead of being deleted.

Implementing it is a behaviour change and needs sign-off; it was deliberately
not done as part of a test repair.

---

## G2 — Two divergent copies of `otrv4_testlib.py`

**Status: RESOLVED (2026-10-24).** When the root-level tests moved into
`tests/` (code tidy-up, phase 2), the root copy went with them: there is one
`otrv4_testlib.py`, in `tests/`, and
`tests/test_dake_timeout.py::test_there_is_one_test_library` fails if a
second appears anywhere in the tree.

The original analysis, retained for the record:

`otrv4_testlib.py` exists in both the project root and `tests/`, with
substantially different implementations (~286 differing lines; the root version
uses `_SMPMathStub` classes patched into the namespace, the `tests/` version
defines `SMPMath` directly).

Which one a test imports **depends on collection order**: `tests/conftest.py`
puts the project root ahead of `tests/` on `sys.path`, but
`tests/test_attacks.py` front-loads `tests/` at import time. So a single-file
run and a full-suite run can load different code.

This was found because a repair applied to one copy appeared to work in
isolation and failed in the full suite. It is a correctness hazard for the test
suite rather than for the product.

**Interim mitigation:** the v10.7 migration helper block is kept byte-identical
in both copies, so the suite is deterministic either way.

**Proposed fix:** make one canonical and have the other re-export it, or delete
the unused copy after confirming which symbols each provides. Deferred because
unifying them is a larger change than a test repair should carry, and the two
implementations are not trivially interchangeable.

---

## B1-seed — Persisting an identity requires the seed in Python

**Status: RESOLVED. Option B implemented — sealing happens inside Rust.**

**Now in use beyond Android (v10.12.0).** The XMPP client persists its
identity through this same mechanism via `otrv4plus_identity.py`, so the
seed stays inside Rust on Termux too. What differs from the Android design
is key custody: the DEK is a 0600 file rather than a Keystore-wrapped key,
so the at-rest protection there is filesystem permissions. IRC persists no
identity at all and is unaffected.

Regression tests: `tests/test_rust_identity_sealing.py` (35 tests covering all
nine required proofs).

`Rust/src/identity.rs` seals and unseals the identity using the crate-internal
accessors, so only ciphertext crosses into Python. No `get_seed()` accessor was
added. Writing the proofs found that PyO3 keeps a `#[staticmethod]`
Python-visible regardless of `pub(crate)`, so `from_seed_bytes` was still a seed
*injection* path; it and `from_priv_bytes` are now behind `test-only-kdf`, and
`identity.rs` uses `from_seed_internal` / `from_priv_internal`, which are not
PyO3 methods at all.

Residual, recorded rather than glossed: the DEK itself is still a Python `bytes`
because the provider hands it down to Rust. The **seed** is not, which is what
the decision required. Phase 4 should shorten that path by passing the unwrapped
DEK straight from Kotlin into Rust over JNI.

The original analysis, retained for the record:

Decision B1 (persistent identity) is approved, but there is a boundary in the
way:

`generate_ed448_keypair()` creates the seed **inside Rust** and there is no
PyO3 accessor that returns it — `expose_seed_slice()` is `pub(crate)`. An
identity generated the production way therefore cannot be persisted at all. The
only reconstruction path is `Ed448KeyHandle.from_seed_bytes(seed)`, whose own
docstring describes itself as "test/internal use; production calls
`generate_ed448_keypair` instead so the seed is never observed from Python at
all."

**Option A — generate the seed in Python**, seal it, reconstruct via
`from_seed_bytes`. No Rust change; works today. Costs the documented property
that private key bytes never appear on the Python heap: the seed is a Python
object at creation and again at every load, and CPython offers no reliable
zeroization for it.

**Option B — seal and unseal inside Rust.** An additive `storage.rs` exposing
`seal_ed448_handle(handle, dek) -> bytes` and
`unseal_ed448_handle(blob, dek) -> Ed448KeyHandle`. Only ciphertext crosses the
boundary; the seed never enters Python. Uses the existing AES-256-GCM and
`SecretBytes` — no new primitive. This is what the Phase 1 report proposed.

**Recommendation: B.** It preserves the boundary that is the codebase's main
structural security claim, and the additional work is small and additive.

`android_bridge/identity.py` is written so this is a swap: `IdentityKeyStore`
is the interface, and the package ships no concrete implementation. The test
double in `tests/test_android_identity.py` uses Option A and is explicitly
marked development/test only.

---

## S1 — The APK's Python packages were pinned by version, not by content

**Status: RESOLVED, 2026-10-30** (owner's question on Python's exposure to
poisoned packages).

### What was wrong

The APK's four third-party packages (PySocks, slixmpp, pyasn1,
pyasn1-modules) were pinned by version only, and Chaquopy's pip fetched them,
and slixmpp's build tools, from the index on each build. An index serving a
different file under the same version would have reached the APK unnoticed.
The Qubes build already checked its wheels by SHA-256.

### The fix

`android/app/python-lock.txt` names every third-party file by SHA-256: the
four that ship and the tools slixmpp's sdist is built with.
`tools/fetch-apk-python.sh` downloads them with `pip --require-hashes` into
`android/app/wheels`, and every CI job that builds runs it first. The Gradle
pip block sets `--no-index`, so Chaquopy installs only from that directory.
Versions are at least two weeks old when pinned, with one exception (owner,
2026-10-30): a release that fixes a published advisory (CVE, GHSA, RUSTSEC)
or replaces a yanked release is taken at once. The same rule applies to the
Rust lockfiles.

### Regression gate

`tests/test_apk_python_hashes.py`: `TestTheLock` (each shipped package locked
at the installed version, every entry a full SHA-256, the build tools locked),
`TestNothingElseCanBeInstalled` (`--no-index`, `--require-hashes`, the fetch
before Gradle in every building job, the Rust core checked by name), and
`test_a_file_that_does_not_match_the_lock_is_refused` (with
`OTR_NETWORK_TESTS=1`: pip refuses a mismatching file).

### Residuals

- A hash only proves the file is the one pinned; a release that was already
  malicious when pinned is not caught. The two-week age rule narrows this,
  except for security fixes, which are taken at once.
- otrv4_core is built in CI from this repository and is not in the lock; the
  Rust crates it uses are pinned by Cargo.lock checksums.
- The desktop's and Termux's Python packages are separate (the Qubes build is
  locked; a Termux install uses pip as the user runs it).

## P1 — Contact pins: never checked by the apps, and kept only for one run

**Status: RESOLVED, 2026-10-27** (found by the audit of 2026-10-26,
docs/AUDIT_THREAT_MODEL.md §4; widened while fixing it).

### What was wrong

`TrustDatabase` keeps two pins per contact:
- the Ed448 fingerprint (`check_or_pin`: a change raises
  `FingerprintMismatchError`);
- the ML-DSA key under that identity (`check_or_pin_pq`: `pq_downgrade`,
  `pq_key_changed`; A2).

Two things were wrong on Android and the desktop:
1. **The fingerprint pin was never checked.** Found writing the fix: only
   the terminal client calls `check_or_pin`. The bridge never did, its
   `note_fingerprint_mismatch` had no caller, and the engine has no
   mismatch security level. So the app's FINGERPRINT_MISMATCH state, its
   "Their key has changed" text and `FingerprintAlertDialog` could not be
   reached. A contact under a whole new identity was accepted, in any run:
   A2's ML-DSA pin is keyed by the Ed448 identity, so a new identity was
   "the ordinary fingerprint change".
2. **The pins lived in memory.** The engines were built with `OTRConfig()`,
   whose `persist_trust` is False, so after a restart every contact was a
   first contact again.

The audit's first P1 test checked `TrustDatabase` directly and missed (1):
it showed the database refusing a change, not the app consulting it.

### The fix

**The check.** `OtrApp._check_contact_pin` runs when a session first comes
up (`_session_settled`), as the terminal's does:
- first contact: pinned;
- the same key: nothing;
- another key: the pin is **not** replaced; the contact shows as
  FINGERPRINT_MISMATCH; `FingerprintChanged` is emitted (the existing
  blocking warning); nothing queued is sent. Calls and files are refused
  (`fingerprint_changed`), even after a shared-secret check in that
  session, until Reset trust. The call gate already had that case,
  unreachable until now; the file gate read only the SMP result and now
  checks the mismatch too, so the two cannot drift.

The session stays up, so the new key can be checked with SMP. The user
accepts a new key only through Reset trust, after checking with the
contact. If the open session is the one whose key changed, Reset trust
pins that session's keys, the ones the user checked: the fingerprint, and
the ML-DSA key its handshake pinned under the new identity
(`TrustDatabase.accept_new_key`). Then it sends what was queued. Neither
half is left empty for the next handshake to fill. With no such session,
Reset trust forgets the pins as before (the way past an A2 refusal). A pin that cannot be kept ends the session (`trust_unavailable`):
the next start would otherwise be a first contact again.

**The store** (`android_bridge.account_trust`; owner's design, 2026-10-27):
- **Apart.** A trust store of its own: not the identity vault (F3), not
  the X1 server pins, not chat history. On Android it is the Keystore
  vault's `trust-vault` section, its own directory under the same Keystore
  key. On the desktop it is 0600 files under `~/.otrv4plus/trust`.
- **The F3 sealing path, not the F3 directory.** Records are AES-256-GCM
  in Rust under a 0600 key file Rust creates (`TermuxFileDekProvider`,
  `AesGcmSealedStore`), with their own key file `trust/trust.dek`. Each
  record is bound to its name, a domain-separated hash of the account, so
  one account's pins cannot be replayed into another's slot. The pins are
  public values but show whom the user talks to, so they are sealed.
- **Per account.** `bind_identity_account` opens the account's record
  first, before anything about the identity changes. Switching account
  detaches the old record and attaches the new one.
- **Wipe & Exit destroys it.** On Android, `KeystoreVault.destroy` deletes
  the key, then every section, `trust-vault` included. On both platforms
  `~/.otrv4plus` (the key file, the markers, the desktop records) is under
  `wipe.python_state_roots`.
- **A record that will not open is refused, retried, never replaced**
  (`trust_unavailable`), as F3's identity is. On Android the vault answers
  None both for "never written" and for "will not open", so an empty
  marker per record (`trust/<name>.present`) says one was written. Only a
  real KeystoreVault gets a trust store. On the in-memory fallback a device
  whose Keystore does not work keeps pins for one run instead of being
  refused at every start.
- **Kept, then answered.** A pin that could not be written fails the check
  (`TrustDatabase.StoreFailed`) and is written again before the next
  check.
- **What is kept:** the fingerprint, the ML-DSA key hash, and the user's
  "They match" confirmation. The SMP verified mark still belongs to the
  session (`Verification.VERIFIED_UNTIL`).

### Gate

`tests/test_p1_trust_pins_per_run.py`, 24 tests:
- after a restart (Android, desktop) a changed fingerprint is
  FINGERPRINT_MISMATCH, with `FingerprintChanged`, and nothing queued goes
  to it (`test_after_a_restart_a_changed_fingerprint_is_refused`);
- after a restart a changed or dropped ML-DSA key is refused;
- the same contact is still accepted;
- a new identity is caught within one run;
- Reset trust pins the key that was checked, both halves, and only that
  one, and sends what waited; the dialog says so (`ProfileIdentityTest`);
- calls and files are refused during a mismatch, even after SMP
  (`test_calls_and_files_are_refused_while_the_key_does_not_match`);
- "They match" is kept;
- pins are per account;
- the store is apart from identities, server pins and history, with its
  own key file;
- the record is sealed, names no JID, and is bound to its account;
- an unopenable record (tampered, or a vault that cannot open it) is
  refused, twice, and nothing is replaced;
- a pin that cannot be kept fails and is retried;
- **Wipe & Exit destroys the trust store**
  (`test_wipe_and_exit_destroys_the_trust_store`,
  `test_android_destroys_the_trust_section_with_the_key`);
- the wiring on both platforms;
- the Keystore-fallback residual, asserted;
- the terminal unchanged.

Mutation: 14 mutants of the fix, each killed (docs/AUDIT_TEST_INTEGRITY.md).

### Found on a handset (2026-10-27): refused, with no way out

Create account for `hen@otrv4plus.i2p` on the owner's phone answered "This
account's saved contact keys on this device would not open" (before the
fix below, a bare "PyException"). The state behind it: an Android marker
naming a record the vault no longer opens. Two ways in, both now closed:
- **a Wipe & Exit cut short.** The vault and its key go at DESTROY_VAULT;
  the markers lived in Python's home until WIPE_APP_DATA, after the
  engine's teardown. A process ended in between left markers behind. The
  markers, the trust key file and the desktop records are now removed in
  `wipe_crypto`, before the vault is destroyed
  (`test_wipe_crypto_removes_the_trust_markers_before_the_vault_is_destroyed`);
- **two Keystore keys.** The default, identity and trust sections open from
  different threads at start-up, and `loadOrCreateKey` was not
  synchronized: two openers finding no key could each make one, the second
  replacing the first. It is now `@Synchronized`.

Which of the two happened on that phone is not known; the diagnostic trace
now records the cause (`identity trust_unavailable`, with `reason`
`marker_without_record` or `unseal_failed`).

**Create account is not stopped by it** (owner's second report, the same
day). Registration is a username and a password sent to the server; it
signs nothing with the account's OTR identity and checks no contact pin, so
a bind refusal does not apply to it
(`test_a_refused_bind_does_not_stop_create_account`). Sign-in, where the
identity and the pins are used, stays refused.

**After a successful Create account the stale keys go by themselves**
(owner's decision, 2026-10-27). The server's yes confirms the username was
free, so contact keys saved under it on this device belong to an earlier,
different account and serve no one. They are discarded at that moment,
opening or not, with a notice ("An old account's contact keys were found
and cleared."), and the sign-in that follows goes ahead. Only there:
`ConnectionController._register` calls `discard_stale_account_trust` after
the server's success and nowhere else; a refused registration discards
nothing (`test_create_account_clears_stale_unopenable_keys_and_signs_in`,
`test_create_account_clears_stale_readable_keys_too`,
`test_a_refused_create_account_discards_nothing_and_sign_in_stays_refused`,
`test_the_stale_discard_runs_only_after_a_confirmed_create_account`).

The rule still holds for sign-in: a record that will not open is refused,
every time, and never replaced by itself. On a phone nobody can move a file aside, so
the refusal now offers **Forget saved contact keys…**: two presses, and the
dialog says what it costs (every contact of the account is a first contact
again, to be compared once more). It is the phone's equivalent of the
terminal's "move the file aside" (`OtrApp.forget_account_trust`;
`test_a_marker_whose_record_is_gone_is_refused_until_the_user_forgets_it`).

### Follow-up: the terminal client (2026-10-27)

The terminal client kept its pins in plaintext in
`~/.otrv4plus/xmpp/trust.json`, and a file that would not parse loaded as
empty. That is P1's failure in the third client: every pinned contact a
first contact, with no warning. It now meets the same rules:
- **Fails closed.** A plaintext trust file that is there and will not open
  (not JSON, empty, not a table) is refused (`TrustDatabase.StoreUnavailable`),
  never read as empty, and the client does not start, as for an identity.
  This holds for any persistent trust database.
- **Sealed.** The XMPP config names a trust key file
  (`trust_dek_path`, `~/.otrv4plus/xmpp/trust/trust.dek`). The pins are
  then one sealed record beside it, on the apps' sealing path
  (`android_bridge.account_trust.for_terminal`), in a directory apart from
  the identity's. `persist_trust` keeps its meaning; IRC still keeps its
  pins in memory and writes nothing.
- **Moved in once.** On the first start, a plaintext `trust.json` is read
  (one that will not open is refused and left as it is), sealed, read
  back, and only then removed. If both files exist and say the same, the
  plaintext one is removed; if they differ, neither is touched and the
  client refuses to start, saying which file to move aside.
- `/trust` says where the pins are (`TrustDatabase.where`).

Gate: `tests/test_terminal_trust_sealed.py` (18 tests).
`test_a_plaintext_trust_file_that_will_not_open_is_refused_not_emptied`
fails on the old code. A terminal started from `client/` alone opens its
sealed pins (`test_a_terminal_started_from_client_alone_opens_its_sealed_pins`;
the engine now imports `otrv4plus_repo`, which the guard
`tests/test_client_finds_the_bridge.py` required). 8 mutants of the
follow-up, each killed.

### Residuals

- **No working Keystore (Android).** The vault falls back to memory, so
  there is no trust store and the pins last one run, as before
  (`test_residual_without_a_working_keystore_the_pins_last_one_run`).
- **The terminal client's pins are one record for the install**, as its
  `trust.json` was, not one per account. Kept that way so that moving the
  file in loses no account's pins.
- **Going back to a build before the follow-up** finds no `trust.json`, and
  that build reads a missing file as a first run: every contact is a first
  contact there. The next start of a current build then finds both files
  differing and refuses (above). Nothing in the current build can prevent
  what an older build does.
- **The record's name is a hash of the account.** No file or vault entry
  names the JID, but the name is an unkeyed hash, so whoever holds the
  files can confirm a guessed account. F3's identity records are named the
  same way (`account_tag`).
- **A record on the device of whom the user talks to.** Sealed, but code
  running as the app on an unlocked phone can read it, as it can the chat
  history. Wipe & Exit removes it.
- TOFU at the very first contact: the shared residual.

---

## P2 — A forced DH step the peer could not follow

**Status: RESOLVED, 2026-10-26** (found by the audit, writing a residual
test for SPEC §5.1; docs/AUDIT_THREAT_MODEL.md §7).

### What happened

At every rekey boundary (`REKEY_INTERVAL`, 100 messages in one direction,
or `REKEY_TIMEOUT`, 24 hours), the engine forced a send-side DH step
toward the peer's current key, even when it had already stepped toward
that key:
- by an earlier forced step;
- or by the receive step that answers a new key from the peer, which also
  makes our sending chain.

The peer cannot follow a second step toward its own unchanged key. Its
receive step uses the key it made after our first step. From then on every
message failed to decrypt: `handle_incoming_message` returned None, the
session still showed as up, and nothing told either user.

Two ordinary ways in (measured with real engines at the production
interval, 2026-10-27; `test_the_boundary_is_the_101st_message_after_a_dh_round_trip`):
- **a one-way run.** `message_counter_send` counts every message a side
  sends and resets only at a forced step, so a side forces a step when
  the counter reaches 100 (measured: its 101st message, then every 100
  after it). After
  a DH round trip (the peer's reply carried a new key, which follows a
  rekey), the 101st message from one side with no reply was the first
  that failed. With no DH step yet in the session, the first forced step
  is harmless and the second one fails: the 200th one-way message after a
  single exchange (199 after two, 198 after three: the earlier messages
  count). Earlier wording ("100 messages from one side after a round
  trip") was off by one and did not say the round trip had to be a DH one;
- a chat left open across two 24-hour boundaries with an exchange between
  them (the timer step, the peer's reply with a new key, then the next
  timer step).

Reproduced with real engines: a two-day session failed on day three in
both directions, and a randomised burst test lost 235 messages. A network
adversary that drops one direction reaches it too.

### The fix

`RustBackedDoubleRatchet._forced_toward` (`client/otrv4+.py`, used by
Android, the desktop and the terminal) remembers the remote key our last
send step went toward. It is set by a forced step and by the receive step
(`_decrypt_new_dh`). A forced step toward that same key is not taken; the
next step comes from the peer's reply, as in the double ratchet. The Rust
core is unchanged.

### Gate

- `tests/test_p2_forced_steps.py`:
  - bursts both ways across many boundaries all decrypt;
  - one way past two boundaries after a round trip;
  - a chat open for two days;
  - one forced step per remote key.

  Each fails on the old engine.
- Rust `pq_ratchet::p2_a_second_send_step_toward_the_same_remote_key_cannot_be_followed`
  pins the constraint: the Rust ratchet does not refuse such a step, so the
  engine must never take it.

### Residuals

- A peer on an older build still takes the double step, and our side cannot
  follow it either. "Older" means any v2 build before this fix, the
  released rc.184 included: it lists 0x50 and 0x51, so `pq_v2_required`
  does not refuse it (v1 peers are refused already). The residual is real,
  reached by ordinary use, and transient: it ends when the peer updates.
  Accepting the step would need the Rust receive path to try the previous
  local key. Not done: the owner decided (2026-10-27) to leave the crypto
  core alone. Matrix row 3.10.
- SPEC §5.1's "lost encapsulation-key chain, then a forced step" residual
  described this double step. With the fix it is no longer reachable, and
  the residual is reworded there.

---

## X1 — Password to a substituted `.i2p` server

**Status: RESOLVED-CLAIM on Android (2026-09-28) and the terminal client
(2026-10-24). The claim: a changed destination receives no byte, and no
password is sent where certificate checks are off. It is demonstrated by
the tests below, which mutation-check both layers, with the residuals
named. Not yet exercised by a handset login (PHYSICAL_TEST_PLAN.md §0).**

### The defect

A short `.i2p` name is bound to a destination by the router's address book,
which a subscription feed, a jump service or a first registrant can
influence. Over I2P the transport turns TLS certificate checks off, because
there is no CA for `.i2p`. The client then authenticated with whatever SASL
mechanism the server offered -- including PLAIN, which is the password
itself. A substituted destination therefore collected the account password.
Message content was never exposed (DAKE-authenticated, TOFU-pinned end to end).

### The fix: both options, combined

**B. Destination pinning** (`android_bridge/server_pins.py`). The identity of
an I2P server is its destination -- the `.b32.i2p` hash of the full
destination the router returned -- never its name.

* The first destination a name resolves to is pinned when that connection
  (or registration) succeeds: trust on first use.
* Every later attempt is checked inside the SAM connect, between `NAMING
  LOOKUP` and `SESSION CREATE` (`I2PSAMConnection.connect(verify_destination=)`).
  A different destination raises before any session or stream exists, so
  **not one byte -- no credential -- reaches it**. The failure is
  `i2p_destination_changed` (registration: `server_identity_changed`) and
  names both addresses.
* Nothing retries it in the background (`ReconnectPolicy.NEEDS_THE_USER`).
  The connect screen shows a security warning with both addresses; "Trust new
  address" needs a second confirmation, approves only the destination that
  was refused, and does not connect -- the user logs in again, and the new
  destination becomes the pin only if that succeeds.
* A typed `.b32.i2p` is checked against the destination the router returns
  for it. `.onion` v3 names are self-authenticating and not pinned.
* Pins are public data (names and hashes), stored at
  `~/.otrv4plus/server_pins.json` (0600) and destroyed by Wipe & Exit.
* The transport refuses a forwarder that cannot run the check.

**A. SCRAM only where certificate checks are off**
(`transport._restrict_to_scram`). slixmpp's `feature_mechanisms` is limited to
SCRAM-SHA-512/256/1 (with and without -PLUS); `encrypted_plain` and
`unencrypted_plain` are off. Verified on the wire against the real slixmpp
1.17 plugin: a server offering only PLAIN (or LOGIN, DIGEST-MD5) gets no
`<auth>` at all and the attempt fails as `no_safe_auth_mechanism`; with SCRAM
offered, the first message carries `n=<user>,r=<nonce>` and never the
password. slixmpp also refuses SCRAM on a stream without TLS, so an I2P
server that skips STARTTLS gets nothing. SCRAM is mutual: a server that does
not hold the credential cannot complete it.

Clearnet (`clearnet_tls`) keeps slixmpp's default: CA-verified certificate,
hostname checked; PLAIN is allowed only inside that verified TLS, and the
transport refuses to send a password or a registration form if TLS was not
negotiated (`tls_required`).

### Residual risks, stated

1. **TOFU:** see "Shared residual" above. If the very first resolution is
   already substituted, layer A still keeps the password off the wire, but:
2. **A SCRAM exchange with an impostor permits an offline guessing attack**
   on a weak password: the impostor picks the salt and iteration count and
   receives the client proof, against which it can test guesses offline. It
   never receives the password itself. Use a strong, unique password.
3. **Registration over I2P on first contact** sends the NEW account's
   password inside the XEP-0077 form over TLS to an unpinned destination.
   After the first success the destination is pinned and later
   registrations are protected.
4. ~~The terminal client accepts whatever the server offers.~~ Resolved
   2026-10-24: `otrv4plus_xmpp.py` restricts SASL to SCRAM wherever certificate
   checks are off (I2P, .onion, `--insecure-tls`), and checks every resolved
   I2P destination with the same rule as the app
   (`android_bridge.server_pins.check_destination`), on start-up and on every
   reconnect. A changed destination is shown with both addresses; only typing
   the new address in full approves it, and a reconnect never retries one.
   Residuals 1-3 apply to it as to the app.
5. ~~A pins file that will not open is read as empty.~~ **Fixed
   2026-10-27, with regression tests named below.** Found the same day,
   checking P1's neighbours: `ServerPins._load` kept nothing, so the next
   connection to a changed destination was a first visit, not a refused
   change (the password stayed protected by SCRAM-only; the destination
   check did not hold for that connection). Now P1's rule applies, refused,
   never replaced:
   - a missing file is a first run, and the connection proceeds;
   - a file that will not open, will not parse, or is not the shape pins
     have (a table of name -> `{"b32": a .b32.i2p address, "since": an
     integer}`; one malformed entry refuses the file) is refused
     (`server_pins.PinsUnreadable`). The connection stops before the
     forwarder starts, so before HELLO, SESSION CREATE and NAMING LOOKUP,
     and before any byte reaches the router (`i2p_server_pins_unreadable`).
     The file is named, and never rewritten, replaced or backed up: nothing
     is pinned or approved over it. It is read again at the next attempt,
     after the user has moved it aside or restored it;
   - the app shows the X1 warning in this form: it names the file and
     offers nothing to approve, since approving would rewrite it. The
     reconnect loop does not retry it (`ConnectProblem.NEEDS_YOU`);
   - the terminal applies the same rule through `check_destination`, at
     start (`_server_identity`, before the SAM forwarder) and on every
     reconnect (its `preflight`), and stops with the file named;
   - a shipped server address and a typed `.b32.i2p` never consult the
     pins (their check is the address itself), so they still connect;
   - Wipe & Exit still destroys the file.

   Server pins are public data (names and destination hashes). They are not
   sealed, by decision.

   Tests: `TestAnUnreadablePinsFileIsRefused` in
   `tests/test_x1_destination_pinning.py`:
   `test_a_corrupt_pins_file_refuses_the_connection_and_names_the_file`,
   `test_a_missing_pins_file_is_a_first_run_and_proceeds`,
   `test_a_structurally_invalid_pins_file_refuses` (seven shapes),
   `test_the_refusal_fires_before_naming_lookup_and_session_create`,
   `test_the_file_is_read_again_once_it_is_moved_aside_and_never_rewritten`,
   `test_a_shipped_or_typed_b32_server_does_not_consult_the_pins`,
   `test_the_warning_names_the_file_and_offers_nothing_to_approve`,
   `test_registration_is_refused_too`,
   `test_wipe_still_destroys_a_pins_file_that_would_not_open`. In
   `tests/test_x1_terminal_client.py`:
   `test_the_terminal_applies_the_same_rule_via_check_destination`,
   `test_the_terminal_refuses_an_unreadable_pins_file_before_the_router_is_asked`,
   `test_a_terminal_reconnect_stops_at_an_unreadable_pins_file`,
   `test_a_missing_pins_file_is_a_first_run_for_the_terminal`. Kotlin:
   `ConnectProblemTest` (`an unreadable server pins file is an error at
   once and says nothing was sent`) and `ReconnectPolicyTest` (`an
   unreadable server pins file stops the retry loop`).

   Mutation: disabling the refusal (the file read as empty again) fails 15
   of these tests. 12 mutants of the fix: 8 killed, 4 equivalent (the
   second guards against writing, pinning or approving over an unreadable
   file, and Wipe & Exit's reset, which no public path reaches;
   docs/AUDIT_TEST_INTEGRITY.md round 5). The test that asserted the
   residual, `test_residual_an_unreadable_pins_file_makes_the_next_connection_first_use`,
   is removed with it.

### Tests

`tests/test_x1_destination_pinning.py` runs the real forwarder and the real
`I2PSAMConnection` against a scripted SAM bridge that plays the XMPP server
at each destination and records every byte: first use pins A; reconnect to
A is allowed; after the name is re-pointed at B the attempt is refused, no
`SESSION CREATE` or `STREAM CONNECT` follows the lookup, B receives zero
bytes and the password never reaches it; registration is blocked the same
way; approval is only for the refused destination and does not re-pin until
a successful connect; the SCRAM restriction is checked on the real slixmpp
plugin. Disabling either layer fails 15 of those tests (checked by mutation
on 2026-09-28). `ReconnectPolicyTest` pins that the refusal is not retried.

`tests/test_x1_terminal_client.py` covers the terminal client: SCRAM-only on
the real slixmpp plugin for I2P, .onion and `--insecure-tls` (and not for a
verified clearnet server); the shared rule agreeing with the app's own check
in every case; first use pinned only after sign-in, a change refused, and
approval only by typing the new address; reconnects using the same check.
Removing the SCRAM restriction or the change check each fails 3 of them
(checked by mutation on 2026-10-24).

