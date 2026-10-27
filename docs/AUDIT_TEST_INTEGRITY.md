# Audit: test integrity, with mutation results

Audit and hardening pass, 2026-10-26. For every test class that a claim
in docs/AUDIT_CLAIM_MATRIX.md rests on, this records:
1. what the test actually demonstrates, in one sentence;
2. whether it fails when the code it covers is broken (mutation);
3. whether its name says what it demonstrates;
4. whether each residual SECURITY_ISSUES.md names for its issue is
   asserted by a test, or noted as untestable.

## How the mutation was done

The mutants ran in a scratch worktree of `dev` (round 1 at `24dfadc`,
round 2 at `dba6b2c`). The harness, outside the repository:
1. applies one change, which must match exactly once;
2. for a Rust ratchet change, builds a wheel and loads it through
   `PYTHONPATH` (the working venv is never touched);
3. runs the test files that gate the rule, plus `cargo test`
   (`l1_retirement`, or the whole MLS crate);
4. records every failing test, then restores the file.

A mutant is **killed** when at least one test fails. A control run of
every test set on the unmutated code was green first. 34 mutants were run
(29 in round 1, 5 new in round 2), plus 2 Kotlin wording mutants.

## Mutation results

### Round 1 (`24dfadc`)

| Mutant | Rule it breaks | Result | Killed by (first of n) |
|---|---|---|---|
| RM1a no R1 (same chain) | a received message's MAC key is retired | killed (48) | `TestMultiPartClose::test_a_lost_second_part_leaves_exactly_its_range_provable` |
| **RM1b no R1 after a DH step** | the first message of a new DH chain is retired | **SURVIVED** | -- (see round 2) |
| RM2 no R1 on the skipped path | a late message is retired | killed (5) | `test_a_lost_and_an_out_of_order_line_are_covered_too` |
| RM3 the sender reveals its own key | a sender never retires its own key | killed (29) | `test_a_key_is_never_on_the_wire_before_its_message_was_delivered` |
| RM4 R3 drops held skipped keys | held skipped keys are retired at close | killed (4) | `TestT3SkippedMessages::test_a_skipped_key_deleted_at_close_is_published` |
| RM5 R2 evicts silently | an evicted skipped key is retired | killed (1) | `l1_retirement::r2_an_evicted_skipped_key_is_published` |
| **RM6 the field copies, never takes** | a published key leaves the queue (T4) | **detected by hang only** | every close loops forever (memory grows without bound); the processes were stopped by hand. T4's assertion is never reached. Under CI's per-test timeout that is a failure |
| RM7 a closing message carries 50 | up to 2000 keys per closing part | killed (6) | `TestMultiPartClose::test_bobs_close_is_two_parts_each_with_its_own_range` |
| RM8 the ratchet is never closed | closed after the last part | killed (3) | `l1_retirement::after_close_the_ratchet_decrypts_nothing_and_sends_once` |
| RM9 a held skipped key published early | nothing published early | killed (6) | `TestT3SkippedMessages::test_unpublished_while_held_across_a_dh_step_then_published_late` |
| PM1 confirmation always yes | confirmed only when the server answers | killed (4) | `test_unconfirmed_it_says_so_keeps_them_and_sends_them_again` |
| PM2 offline closings dropped | offline closing messages are kept | killed (1) | `test_offline_at_the_press_they_go_when_it_is_back` |
| PM3 never gives up | a closing message is given up after its tries | killed (1), by a 15-minute timeout | `test_a_closing_message_is_given_up_after_its_tries` |
| PM4 Publish Chat Keys sends nothing | the closing messages are sent | killed (14) | `TestMultiPartClose` |
| **PM5 `_cleanup_resources` skips publication** | termination and failure publish | **SURVIVED** | -- (see round 2) |
| **PM6 the peer's end skips publication** | we publish when the peer ends it | **SURVIVED** | -- (see round 2) |
| PM7 closings not IGNORE_UNREADABLE | closing messages are flagged | killed (5) | `TestT5PublishChatKeys::test_final_publication_disconnect_and_a_fresh_session_sharing_no_key` |
| **PM8 closing frames written to disk** | nothing of the close on disk (kill window) | **SURVIVED** | -- (see round 2) |
| PM9 no way to ask is yes | not knowing is never yes | killed (2) | `test_offline_at_the_press_they_go_when_it_is_back` |
| PA1 a changed ML-DSA key allowed | A2: `pq_key_changed` | killed (2) | `test_a_different_ml_dsa_key_is_refused` |
| PA2 an ML-DSA downgrade allowed | A2: `pq_downgrade` | killed (1) | `test_dropping_post_quantum_authentication_is_refused` |
| PX1 no SCRAM restriction | X1: no password where certificates are off | killed (4) | `TestScramOnlyOnTheWire::test_a_server_offering_only_plain_gets_nothing` |
| PX2 the app ignores the pin | X1: a changed destination refused | killed (11) | `TestReapproval`, `TestSubstitutionIsBlocked` |
| PX3 the terminal ignores the pin | X1, terminal rule | killed (3) | `test_first_use_pins_after_sign_in_and_a_change_is_refused` |
| PF1 never published | F4: `maintain` publishes after the delay | killed (1) | `test_a_rekey_retires_the_old_key_and_maintain_publishes_it_after_the_delay` |
| **MM1 receiver skips the pair check** | F4: each private half signs for its public half | **SURVIVED** | -- (see round 2) |
| MM2 receiver accepts the current key | F4: a key in use is not retired | killed (1) | `retired_key_tests::a_key_in_use_or_a_mismatched_pair_is_not_accepted` |
| MM3 private halves zeroed | F4: the publication carries the private halves | killed (2) | `retired_key_tests::a_rotation_retires_the_old_key_and_its_publication_reaches_the_members` |
| MM4 a retired key is dropped | F4: kept until published | killed (5) | `retired_key_tests::a_publication_carries_both_halves_of_the_composite_key` |

### Round 2 (`dba6b2c`, after the fixes below)

| Mutant | Result | Killed by |
|---|---|---|
| RM1b no R1 after a DH step | **killed** | `test_every_line_is_covered_across_dh_steps` (new) |
| PM5 `_cleanup_resources` skips publication | **killed** | `test_a_session_ending_by_termination_or_failure_publishes_too[terminate, failure]` (new) |
| PM6 the peer's end skips publication | survived: **equivalent** | the peer's DISCONNECTED path also runs `_cleanup_resources`, whose publication is idempotent. The explicit call is a second guard |
| PM5+6 both | **killed** (20+) | the wire audit, T5, T6 |
| PM8 closing frames written to disk | **killed** | `TestCrashDuringClose::test_no_mac_key_is_on_disk_after_the_kill` (strengthened) |
| MM1 receiver skips the pair check | **killed** | `a_key_in_use_or_a_mismatched_pair_is_not_accepted` (a new case: right Ed448 half, another key's ML-DSA half) |
| PP1 the P2 guard removed | **killed** | `tests/test_p2_forced_steps.py` (3), `test_every_line_is_covered_across_dh_steps` |
| PP2 the receive step not counted (P2) | **killed** | as PP1 |
| PT1 app pins persisted (the P1 assertion inverted) | **killed** | `test_the_app_engines_are_built_with_a_trust_database_in_memory` (since removed: it asserted the residual P1 fixed; see Round 3) |
| PW1 the terminal claims a property | **killed** | `test_deniable_wording.py::test_the_terminal_words_state_no_property_and_name_the_residuals` |

### Kotlin wording mutants (`DeniableChatTest`)

| Mutant | Result |
|---|---|
| KM1: the dialog no longer says "It does not hide that you two talked" | killed |
| KM2: "Deniability pending external audit." re-added | killed |

### Round 3: the P1 fix (2026-10-27)

Each mutant was applied to the fix and `tests/test_p1_trust_pins_per_run.py`
run against it.

| Mutant | Result |
|---|---|
| PF1 no pin check when a session comes up | killed |
| PF2 the account's record not attached at bind | killed |
| PF3 the Android marker not consulted (an unopenable record read as absent) | killed |
| PF4 the outbox flushed despite a mismatch | killed |
| PF5 a store failure swallowed | killed |
| PF6 an unsaved pin not retried before the next check | killed |
| PF7 the mismatch not shown (no SessionStateChanged) | killed |
| PF8 the desktop host without a trust store | killed |
| PF9 the in-memory Keystore fallback given a store | killed |
| PF10 Reset trust does not pin the checked key | killed |
| PF11 Reset trust does not send what waited | killed |
| PF12 Reset trust drops the ML-DSA pin of the checked session | killed |
| PF13 Reset trust removes the entry, then pins the fingerprint only | killed |
| PF14 the file gate ignores the mismatch (calls refuse it, files did not) | killed |

**Existing tests the fix touched.** One changed its setup, not its
assertion. `test_the_pinned_fingerprint_survives` (contact removal) pinned
a made-up fingerprint "rather than hoping the handshake did it". The fixed
app's handshake now pins the real one, and a different pin over it is
refused by design. The test now asserts the handshake pinned the session's
key, confirms that key, and checks, as before, that removing the contact
keeps it. One source check, `test_the_save_path_is_guarded_not_the_call_sites`
(IRC never writes a trust file), failed on the first version of the fix.
The code was reordered to satisfy it, not the test: the in-memory guard
comes first in `TrustDatabase._save`, and the sealed store is the one place
an in-memory database writes.

**A test-integrity miss, found by the fix.** Round 2's P1 tests called
`TrustDatabase` directly. `test_within_one_run_a_changed_key_is_refused`
passed, and the matrix rated the claim "true within one run of the app".
No app code called `check_or_pin`, so the apps did not refuse a changed
fingerprint even within a run. The database was tested, not the app. The
tests now drive two real `OtrApp`s over a wire
(the link in `tests/test_deniability_wire_audit.py`), so PF1 and PF4 fail them; a
database-level test would have passed both.

**Summary.**
- Round 1: 29 mutants. 22 were killed by an assertion and 1 by a timeout
  (PM3). RM6 was detected only by a hang. 5 survived: RM1b, PM5, PM6, PM8,
  MM1.
- Round 2: every survivor is killed by a new or strengthened test, except
  PM6, which is equivalent.
- Round 3 (P1): 14 mutants, 14 killed.
- Round 4 (the terminal follow-up): 8 mutants, 8 killed: the fail-open
  load restored, the table check removed, the plaintext file kept after
  the move, differing files resolved silently, an unopenable sealed record
  read as empty, a corrupt plaintext file moved in as empty, the XMPP
  config without its trust key file, the engine without `otrv4plus_repo`
  (a terminal started from `client/` could not have started). Two existing
  guards failed on the first version and were satisfied by changing the
  code: `test_no_client_passes_persistent` (the opener now takes
  `persistent` from the config) and
  `test_every_client_module_that_imports_the_bridge_asks_for_the_path_first`.
- Round 5 (X1 residual 5, the server pins refused when they will not
  open): 12 mutants, 8 killed, 4 equivalent. Disabling the refusal (the
  file read as empty again) fails 15 tests across the app and the
  terminal. Killed: the refusal off; the app's pre-flight off (the refusal
  then comes only after NAMING LOOKUP: 9 fail); malformed entries filtered
  instead of refused (5); the terminal's start pre-flight off (2); its
  reconnect pre-flight off (1); `check` answering NEW over an unreadable
  file (2); the warning without the file (1); the file not read again
  after it is moved aside (1). Equivalent: the guards against writing,
  pinning or approving over an unreadable file, and Wipe & Exit's reset of
  the unreadable state. No public path reaches them (`check` raises before
  anything is pending or recorded, and the next read after the wipe finds
  no file); they stay as second locks on the writer.
- Round 6 (F4 containment, 2026-10-27): 12 mutants, 11 killed, 1
  equivalent.
  - Rust (`Rust/mls/src/client.rs`), 8. Killed: the self-update keeping the
    old key (tests 1 and 2); `max_past_epochs(1)` in both configurations
    (test 3, the renamed test 4, the gap test); a group reusing another
    group's key (test 5); publication not waiting (the two waiting tests
    and the gap test); a commit counting as everyone's acknowledgement
    (the same three); a message counting for the epoch after its own
    (`publication_waits_...`, after a case was added where the lagging
    member spoke before the rotation: it survived the first version); the
    waiting state sealed wrong (`what_a_retired_key_waits_for_survives_a_restart`).
    Equivalent: a departed leaf's record kept (only current leaves are
    read, and a refilled leaf is overwritten at the join).
  - Python (`android_bridge/groups.py`), 4. Killed: members never
    acknowledging (6 tests); a waiting Publish Group Keys request dropped
    when nothing is publishable yet (4); an acknowledgement not retrying
    publication (4); `maintain` not sending an owed acknowledgement
    (`test_an_acknowledgement_that_could_not_go_is_sent_by_maintain`,
    added: it survived first).
  - Test 4, `the_epoch_authenticator_is_checked_before_any_group_message_is_accepted`,
    killed only the past-epoch mutant, and only through its source check;
    its name claimed a check MLS does not make. Renamed
    `max_past_epochs_is_zero_in_every_group_config`, a source check only
    (listed as renamed in `tests/test_security_doc_references.py`).
  - The older `retired_key_tests` publish right after a rotation. Their
    helper gained the acknowledgement the protocol now requires; no
    assertion changed.
- The test that asserted the residual,
  `test_residual_an_unreadable_pins_file_makes_the_next_connection_first_use`,
  failed on the fix by design and was removed with it (listed as removed in
  `tests/test_security_doc_references.py`).
- P2's trigger was measured at the production interval and pinned
  (`test_the_boundary_is_the_101st_message_after_a_dh_round_trip`, which
  fails with the P2 guard removed). The documented "100 messages after a
  round trip" was off by one and missed that the round trip has to carry a
  new DH key.

## The tests, one by one

| Test (class) | What it demonstrates, in one sentence | Name honest? | Change made |
|---|---|---|---|
| `TestT1PositiveDeniability` | A key published in a later message verifies the observed message's outer MAC, and lets a third party put a valid outer MAC on an altered copy; the receiver refuses that copy. | **No**: "forges a message really observed" claimed more than a forged outer MAC | Renamed `test_a_published_key_lets_anyone_mac_an_altered_copy_of_an_observed_message`; residual test added |
| `TestL1Residuals` (new) | An altered outer MAC makes the receiver refuse the message, the genuine copy is then a replay, and its key is published. | yes | new |
| `TestT2NoPrematureRevelation` | No published key verifies a message its publisher had not received, over a lossy conversation with DH steps; the predicate catches a doctored transcript. | yes | -- |
| `TestT3SkippedMessages` | A held skipped key stays unpublished across DH steps and is published after a late receipt or a close. | yes | -- |
| `TestT4PublishedKeysAreNotHeld` | A published key is no longer held by the ratchet (test-build accessor), and close leaves nothing retired or skipped. | **No**: was `TestT4Zeroization`; it cannot see an overwrite | Renamed; the overwrite is noted as zeroize-on-drop |
| `TestT5PublishChatKeys` | The final publication covers every received line, is IGNORE_UNREADABLE, ends the peer's side too, and no old key verifies the new session. | **No**: "fresh_unlinked_session" was broader | Renamed `..._fresh_session_sharing_no_key` |
| `TestT6SignOutWipeQuit` | Sign-out, wipe, termination and failure publish before keys go; the bridge sends each closing message once, before the transport closes. | **No**: one test was named "...drops_them_offline" and never tested offline | Renamed `test_the_bridge_sends_each_closing_message_once`; termination and failure added (PM5) |
| `TestT7WireCompatibility` | The field is outside the MAC; real keys of the right length; a peer accounts for every key shown. | yes | -- |
| `TestT8NoMacKeyBytesInPython` | The ratchet hands Python the encoded field and handles; no production path unpacks keys. Partly a source-level check. | yes | -- |
| wire audit (`tests/test_deniability_wire_audit.py`) | An outsider holding only the frames finds each line's MAC key on the wire after a close, never before delivery, and none for the new session. | yes, but the scripts never reached a DH step (RM1b survived) | `test_every_line_is_covered_across_dh_steps`, `test_residual_a_peer_that_never_closes_leaves_our_lines_provable` added |
| `TestMultiPartClose` | A close over 2000 keys is two parts; losing part 2 leaves exactly its range provable until re-sent. | yes | -- |
| `TestCrashDuringClose` | After SIGKILL between retire_all and confirmation: no key on disk, nothing re-sent, and exactly the lost close's lines stay provable. | yes, but the on-disk check missed a frame written as wire text (PM8 survived) | The check now decodes any `?OTRv4` frame on disk |
| `tests/test_deniable_confirmation.py` | The transport's confirmation is a real ping answered after the closing message; unconfirmed messages are kept, re-sent and given up after their tries. | **No**: `..._starts_only_after_the_server_confirmed` covered only a server that answers | Renamed `test_the_new_session_starts_after_the_server_is_asked`; `test_residual_unconfirmed_the_new_session_starts_anyway_and_the_app_says_so` added |
| `tests/test_p1_trust_pins_per_run.py` (new; rewritten by the P1 fix) | First: the app engines keep pins in memory. Now: through real apps over a wire, a changed key after a restart is FINGERPRINT_MISMATCH and nothing queued goes to it; the store is sealed, per account and apart; an unopenable record is refused; Wipe & Exit destroys it. | the first version **no**: "within one run a changed key is refused" tested the database, not the app | rewritten through `OtrApp` |
| `tests/test_p2_forced_steps.py` (new) | Bursts, one-way runs past two boundaries and a two-day chat all decrypt; every test fails on the old engine. | yes | new |
| `retired_key_tests` (Rust, F4) | Rotation retires the key; the publication reaches members, forges, cannot sign into the group, is refused for a current or mismatched key, is bounded and batched. | yes, but the ML-DSA-half check was untested (MM1) | Spliced-key case added; two residual tests added |
| `tests/test_f4_group_key_publication.py` | The bridge publishes after the delay, at once on Publish Group Keys, never shows it as text, and only fingerprints leave Rust; since 2026-10-27, never before every member has acknowledged the rotation. | yes | -- |
| `f4_containment_tests` (Rust, F4) | The published key forges only its own transcripts; signs nothing accepted later; derives nothing; refused in a later epoch; per group; the gap for a lagging member; publication waits for every member, across a restart. | yes, after round 6; test 4 renamed (its old name overstated it) | case added for M6 |
| `tests/test_pq_auth_v2.py` (A2) | Both ends pin the ML-DSA key; a downgrade or a changed key is refused, within one process. | yes (across restarts: `tests/test_p1_trust_pins_per_run.py`) | -- |
| X1 classes | A changed destination receives no byte; SCRAM only where certificates are off; pins persist (server pins, unlike P1). | yes | -- |
| `DeniableChatTest` (Kotlin) | The dialog's words, history deletion and group words. | **No**: "the words claim what the tests show and no more" pinned the presence of a property claim | Renamed `the words describe the mechanism and its residuals and state no property`; pins the absence of property words |

## Residuals: asserted, or noted as untestable

| Issue | Residual (SECURITY_ISSUES.md) | Asserted by | Or: why not testable |
|---|---|---|---|
| L1 | expert review of the rule | -- | not testable; docs/CRYPTOGRAPHER_QUESTIONS.md Q1 |
| L1 | outer MAC only; AES-GCM unforgeable | `test_residual_the_receiver_refuses_a_frame_only_the_outer_mac_was_forged_for` | -- |
| L1 | a MAC failing after its AEAD tag: retired anyway | `TestL1Residuals::test_residual_an_altered_outer_mac_costs_the_message_and_its_key_is_published` | -- |
| L1 | partial close | `TestMultiPartClose::test_a_lost_second_part_leaves_exactly_its_range_provable`, `l1_retirement::residual_a_lost_later_part_takes_its_range_with_it` | -- |
| L1 | kill-to-confirmation window | `TestCrashDuringClose::test_residual_the_transcript_of_an_unconfirmed_close_is_still_provable` | -- |
| L1 | an unanswered confirmation | `test_residual_unconfirmed_the_new_session_starts_anyway_and_the_app_says_so`, `test_a_closing_message_is_given_up_after_its_tries` | -- |
| L1 | the second closing (a peer that never closes) | `test_residual_a_peer_that_never_closes_leaves_our_lines_provable` | -- |
| L1 | delivery to the contact | -- | beyond our server; not observable by the client |
| L1 | the queue bound (4000) | `l1_retirement::the_retired_queue_keeps_up_to_its_bound_and_never_drops_early` | -- |
| L1, A2, X1 | TOFU at first contact | `test_both_ends_pin_the_others_long_term_ml_dsa_key` shows what is pinned | no test can show that a pinned key is the person's |
| A2 | pins last one run without a working Keystore (P1, after the fix; before it, on every Android and desktop install) | `test_residual_without_a_working_keystore_the_pins_last_one_run` | -- |
| P1 | the terminal's `trust.json` was plaintext and failed open on a corrupt file | fixed by the follow-up: `test_a_plaintext_trust_file_that_will_not_open_is_refused_not_emptied`, `test_a_sealed_record_that_will_not_open_is_refused_and_not_replaced` | -- |
| P1 | going back to an older build after the move: that build reads no `trust.json` as a first run | `test_both_files_differing_are_refused_and_neither_is_touched` (the current build's side) | what an older build does cannot be tested from this one |
| F4 | a capture before release stays attributable | `residual_a_signature_checked_before_release_still_checks_after_it` | that a third party *trusts* a capture time is not testable |
| F4 | the forgers are the members only | `residual_only_the_groups_members_receive_the_published_key` | -- |
| F4 | the 16-key bound | `retired_keys_are_bounded_and_published_in_batches` | -- |
| F4 | needs the app running | `test_a_rekey_retires_the_old_key_and_maintain_publishes_it_after_the_delay` shows publication only from `maintain` | that an offline app publishes nothing follows from that; not separately tested |
| X1 | SCRAM offline guessing | -- | an offline dictionary attack is outside the code; stated |
| X1 | ~~an unreadable pins file read as empty~~ fixed 2026-10-27 | `TestAnUnreadablePinsFileIsRefused`, `test_the_terminal_applies_the_same_rule_via_check_destination` | -- |
| X1 | a damaged pins file blocks sign-in to a pinned name until it is moved aside (the cost of the fix) | `test_a_corrupt_pins_file_refuses_the_connection_and_names_the_file` | -- |
| X1 | first registration unpinned | -- | stated; the pinning tests start from first use |
| A1 / §5.1 | the lost-Ek residual | reworded: unreachable since P2 (`tests/test_p2_forced_steps.py`) | the combiner is Q4 |
| N1 | i2pd reseed; no device capture | -- | a separate process; needs a PCAPdroid capture on a phone |
| P2 | an older peer's double step | Rust `p2_a_second_send_step_toward_the_same_remote_key_cannot_be_followed` (the constraint) | accepting it would need a crypto-core change |

## Findings this produced

1. **Four claim gates were weaker than their names or docs said, now
   fixed:**
   - RM1b: the wire audit never crossed a DH step;
   - PM5: termination and failure untested;
   - PM8: the crash test's disk check;
   - MM1: the ML-DSA-half check.
2. **Six names said more than their tests showed, now renamed:** T1, T4,
   T5, one T6 test, one confirmation test, and the Kotlin wording test.
3. **Two mutants are detected only by a hang** (RM6, PM3). Both are real
   failures under CI's per-test timeout. RM6 also shows that a broken
   queue never terminates a close; that is a robustness note, not a
   security one.
4. **PM6 is equivalent:** two guards for one publication, by design.
