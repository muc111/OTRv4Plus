# Audit: claim/code matrix

Audit and hardening pass, 2026-10-26, on `dev` from `ca81787` (prototype
commits up to `24dfadc` included). For each protection the repository
claims, it lists:
- the sentence, verbatim;
- where it is stated;
- the code that does it;
- the test that proves it;
- the residual that limits it;
- a status.

The code was read first. The documents were treated as claims to check.

**Status values.**
- **DEMONSTRATED**: a test proves the sentence, and the residual is named
  where the sentence is.
- **PARTIAL**: a test proves a narrower sentence than the one written.
- **UNSUPPORTED**: no test proves it, or the code does the opposite.
- **EXTERNAL**: needs a cryptographer (docs/CRYPTOGRAPHER_QUESTIONS.md).

Every PARTIAL and UNSUPPORTED row names its fix in the Fix column. **E** is
a document change, applied in this pass. **F** is a status change in
docs/SECURITY_ISSUES.md. **T** is a new or strengthened test
(docs/AUDIT_TEST_INTEGRITY.md). The status shown is the status **before**
the fix. Where a row's tests were mutation-checked, the result is in
docs/AUDIT_TEST_INTEGRITY.md.

**Scope.** Every protection claim in:
- `README.md`, `SECURITY.md`;
- `docs/SPEC.md` §3.1, §4.3, §5.1-5.2, §5.8, §10.1;
- `docs/SECURITY_ISSUES.md`;
- `docs/MLS_SECURITY_HARDENING.md` §1 and §6;
- `docs/PQC_DECISIONS.md`, `docs/DENIABILITY_LAYERS.md`;
- the changelog entries since the deniability work began (rc.182-rc.186);
- the user-visible strings of Make Chat Deniable and Make Group Deniable
  (Android and the desktop share `DeniableChat.kt`), and the terminal's
  `/help`.

The rest of `docs/TECHNICAL.md` and older changelog entries were not
audited line by line. Older entries are dated records, not current claims.

## 1. One-to-one content deniability (L1)

| # | Claim (verbatim) | Where | Code | Test(s) | Residual(s) | Status | Fix |
|---|---|---|---|---|---|---|---|
| 1.1 | "1:1 deniability of what was said, pending external audit" | README.md:77 | `ratchet.rs` retirement, `app_deniable.py` | none proves a deniability *property*; L1 is RESOLVED-CODE | the §5.8 rule unreviewed | **UNSUPPORTED** | E: describe the mechanism |
| 1.2 | "so a copy of the chat -- your contact's, or a recording of the traffic -- no longer proves who wrote what: anyone holding it could have forged it" | `DeniableChat.BODY` (Android, desktop) | as 1.1 | `test_deniability_wire_audit.py` shows every line's outer MAC is re-computable from the wire once the closing messages arrived | a copy made before publication; an unconfirmed close; a partial close; a peer that never closes; the rule unreviewed | **PARTIAL**: the test proves "the outer MAC of every line can be recomputed by anyone holding the frames", not "no longer proves who wrote what" | E: owner's mechanism wording |
| 1.3 | "Your server confirms it received them first." | `DeniableChat.BODY` | `confirm_closings` | `test_the_server_confirms_and_the_closing_message_came_first` | when the server does not answer in 15 s the new session starts anyway (`make_chat_deniable` with `restart`) | **PARTIAL** | E |
| 1.4 | "Then this encrypted session ends and a new one starts, unlinked to the old one." | `DeniableChat.BODY` | `end_session`, new DAKE | T5 `test_final_publication_disconnect_and_a_fresh_session_sharing_no_key` (named "..._fresh_unlinked_session" before this pass); wire audit `test_the_new_session_is_not_authenticated_by_anything_revealed` | the new handshake is signed by the same long-term ML-DSA-87 identity, so the two sessions are linked by who ran them | **PARTIAL**: no key in common is shown; "unlinked" is broader | E |
| 1.5 | "Your messages stay encrypted: only their authentication keys are published." | `DeniableChat.BODY` | `take_reveal_field` publishes MKmac only; MKmac = KDF(MKenc) | T7 `test_the_field_is_outside_what_the_mac_covers`, T8 | MKmac does not reveal MKenc only if the KDF is one-way (assumption) | **DEMONSTRATED** (the published field is MKmac only) | -- |
| 1.6 | "It does not hide that you two talked: starting a session is signed." | `DeniableChat.BODY`, terminal `/help` | `dake.rs` v2 signatures | `dake::pq_auth_tests`, `tests/test_pq_auth_v2.py` | -- (it is a limitation) | **DEMONSTRATED** | -- |
| 1.7 | "This chat's history is deleted from this device, so only the new session's messages are shown." | `DeniableChat.BODY` | `DeniableChat.apply` -> `ChatState.clearHistory` | `DeniableChatTest` (vault entry gone, restart keeps it gone) | copies outside the app | **DEMONSTRATED** | -- |
| 1.8 | "Deniability pending external audit." | `DeniableChat.BODY`; terminal `/help` ("Deniability pending external audit") | -- | none; L1 is RESOLVED-CODE | -- | **UNSUPPORTED** (states a property; the file claims none) | E: "Not independently reviewed." |
| 1.9 | "your server has not yet confirmed the message that publishes them; the app keeps sending it until it does" | `DeniableChat.outcome("made_deniable_unconfirmed")` | `resend_unconfirmed_closings` (`CLOSING_MAX_TRIES = 40`, every 30 s); kept in memory only | `test_a_closing_message_is_given_up_after_its_tries` shows the **opposite**; `TestCrashDuringClose` shows nothing is sent after a restart | gives up after 40 sends; lost when the app closes | **UNSUPPORTED** | E |
| 1.10 | "Make this chat deniable?" (title); "Make Chat Deniable…" (action) | `DeniableChat.TITLE`, `.ACTION` | -- | -- | the action names a property | **PARTIAL**: the title is a property question | E: title reworded; the action label is the owner's feature name, flagged in SUMMARY.md |
| 1.11 | "/deniable [jid] publish this chat's MAC keys once your server confirms (a copy then no longer proves who wrote what; it does not hide that you talked) ... Deniability pending external audit" | `client/otrv4plus_xmpp.py:2682` | terminal `make_deniable` | `test_the_terminal_confirms_the_same_way` | as 1.2 | **PARTIAL** / **UNSUPPORTED** (as 1.2 and 1.8) | E |
| 1.12 | "The claim is that a copy of a closed chat held by someone else ... does not prove who wrote what." | SECURITY_ISSUES.md L1 "What the claim rests on" | -- | -- | -- | **UNSUPPORTED**: the same entry is RESOLVED-CODE, "no property is claimed" | E/F: "What the mechanism does" |
| 1.13 | "Make Chat Deniable waits until our server confirms it received them before the new session starts." | SECURITY_ISSUES.md L1 point 3; CHANGELOG rc.186 | `make_chat_deniable` | `test_the_new_session_starts_after_the_server_is_asked` (named "..._starts_only_after_the_server_confirmed" before this pass) covers only a server that answers | an unanswered ping costs 15 s, then the new session starts | **PARTIAL** | E; T (rename, plus a residual test) |
| 1.14 | "Without a network the closing messages are dropped; the keys are retired and wiped all the same." / "Offline, the closing messages are dropped" / "Without a network they are dropped" | SPEC §5.8 Close; SECURITY_ISSUES.md L1 "What ships"; `app_deniable.py` docstring | `_send_closing` keeps them: `return False # offline: kept, sent when back` | `test_offline_at_the_press_they_go_when_it_is_back` shows the **opposite** | kept in memory only, never on disk (`TestCrashDuringClose`): lost if the app ends first | **UNSUPPORTED** (stale) | E: "kept in memory only", never "kept" alone |
| 1.15 | "No peer is reached offline, either: there the keys are retired and wiped but published nowhere (T7)." | SECURITY_ISSUES.md L1 "Limits" | as 1.14 | as 1.14; and T7 is wire compatibility, not offline | -- | **UNSUPPORTED** (stale, wrong reference) | E |
| 1.16 | "A closing message not confirmed is kept and sent again until it is, or until the client gives it up. A client MUST NOT report the keys as published before confirmation." | SPEC §5.8 Confirmation | `app_deniable.py`, terminal `_confirm_then_restart` | `test_unconfirmed_it_says_so_keeps_them_and_sends_them_again`, `test_a_closing_message_is_given_up_after_its_tries`, `test_no_way_to_ask_is_never_read_as_yes` | kill window | **DEMONSTRATED** | -- |
| 1.17 | R1-R3 "each of which ends every use the key can have" | SPEC §5.8 | `retire`, `retire_skipped`, `retire_all` | T2, T3, `ratchet::l1_retirement` | review of the rule | **EXTERNAL** (Q1); the mechanism is DEMONSTRATED | -- |
| 1.18 | "The queue holds at most 4000; past that the oldest is wiped unpublished" | SPEC §5.8 | `MAX_RETIRED = 2 * MAX_MESSAGE_KEYS` | `the_retired_queue_keeps_up_to_its_bound_and_never_drops_early` | stated | **DEMONSTRATED** | -- |
| 1.19 | "A new handshake always creates a new session: nothing of an ended one -- ratchet, instance tags -- is reused, so the new transcript has no cryptographic link to the old one." | SPEC §5.8 Close | `end_session`; a new DAKE | T5 | as 1.4 | **PARTIAL** | E |
| 1.20 | "Publishing it ... lets anyone forge that message's outer MAC, so a transcript of MACs stops being evidence of who wrote what." | SPEC §5.8 | as 1.1 | T1, wire audit | the second half is the deniability property | first half **DEMONSTRATED**; second half **EXTERNAL** (Q2) | -- |
| 1.21 | "A third party with a published key can forge the outer MAC of a transcript entry ... it cannot produce a ciphertext the receiver would have decrypted." | SECURITY_ISSUES.md L1 Residuals | AES-GCM keyed by MKenc | T1 forges the outer MAC; **no test** shows the receiver refuses the forgery | -- | **PARTIAL**: the second half was untested | T: `test_residual_the_receiver_refuses_a_frame_only_the_outer_mac_was_forged_for` |
| 1.22 | "A contact whose app never closes keeps the MAC keys of what we sent unrevealed." | SECURITY_ISSUES.md L1 "The second closing" | sender never retires its own keys | wire audit covers both sides when both close; **no test** asserts this residual | stated | **PARTIAL** (residual not asserted) | T: `test_residual_a_peer_that_never_closes_leaves_our_lines_provable` |
| 1.23 | "If the process dies between `retire_all` and the server's confirmation, ... that close's transcript stays provable." | SECURITY_ISSUES.md L1 | in-memory book | `TestCrashDuringClose` | stated | **DEMONSTRATED**, but its no-key-on-disk check missed a base64 wire frame (B) | T: strengthened |
| 1.24 | "A close with more than 2000 retired keys goes out in several closing messages ... A lost part leaves exactly its range provable" | SECURITY_ISSUES.md L1; SPEC §5.8 | `encrypt_final` | `TestMultiPartClose`, `l1_retirement::{a_close_over_the_bound_is_several_messages, each_part_publishes_only_its_own_range_oldest_first, residual_a_lost_later_part_takes_its_range_with_it}` | stated | **DEMONSTRATED** | -- |
| 1.25 | "Make Chat Deniable waits for your server to confirm ... before the new session starts." / "sends them again until the server confirms" / "One-to-one deniability, pending external audit" | CHANGELOG rc.186 | as 1.3, 1.9 | as 1.3, 1.9 | as 1.3, 1.9 | **PARTIAL** / **UNSUPPORTED** | E: correction note in the entry |

## 2. Group content deniability (F4)

| # | Claim (verbatim) | Where | Code | Test(s) | Residual(s) | Status | Fix |
|---|---|---|---|---|---|---|---|
| 2.1 | "then publishes your earlier ones to its members, so a copy of the group shown after that no longer proves who signed what" | `GroupDeniable.BODY` | `MlsClient::reveal_retired` (an MLS application message, encrypted to the members) | `retired_key_tests` (a published key forges a signature its public key accepts) | the forgers are the members who received the publication; a capture verified before release stays attributable; the member must be online; more than 16 retired keys and the oldest go unpublished | **PARTIAL**: proves "members can forge"; the sentence is a property | E |
| 2.2 | "New messages are signed with the new key, which stays secret." | `GroupDeniable.BODY` | `reveal_retired` publishes only `retired` | `retired_key_tests` (current key refused; never published) | -- | **DEMONSTRATED** | -- |
| 2.3 | "Earlier keys are also published by themselves some minutes after each automatic key change." | `GroupDeniable.BODY` | `maintain`, `REVEAL_DELAY_SECONDS` = 600 | `test_a_rekey_retires_the_old_key_and_maintain_publishes_it_after_the_delay` | needs the app running and online | **DEMONSTRATED** | -- |
| 2.4 | "Pending external audit." | `GroupDeniable.BODY` | -- | -- | -- | **UNSUPPORTED** (F4 is RESOLVED-CODE) | E: "Not independently reviewed." |
| 2.5 | "A published key cannot sign into the group any more." | MLS_SECURITY_HARDENING.md §1 | rotation commit first in room order | `retired_key_tests` | -- | **DEMONSTRATED** | -- |
| 2.6 | "The window in which a capture is still attributable is the rekey period (at most 50 messages or 30 minutes) plus the delay (10 minutes), or none after Make Group Deniable." | MLS_SECURITY_HARDENING.md §1 | -- | -- | a signature captured before Make Group Deniable was capturable while its key was secret | **PARTIAL**: "none" is wrong. The press shortens how long a key stays secret from then on; it does nothing for what was already captured | E |
| 2.7 | "Deniability: OTRv4+ is deniable (DAKE, ring signatures, published MAC keys)." | MLS_SECURITY_HARDENING.md §6 | -- | -- | SPEC §10.1: participation is attributable; L1 claims nothing | **UNSUPPORTED** | E |
| 2.8 | "a break of either half alone does not break confidentiality or authentication" | MLS_SECURITY_HARDENING.md §6 | `provider::composite_verify`, `hpke` | `provider::both_halves_must_verify`, `hpke::hybrid_binds_both_halves` | the constructions are unreviewed | **EXTERNAL** (Q4, Q5); the mechanism is DEMONSTRATED | -- |
| 2.9 | "The server never sees a JID–key link." | MLS_SECURITY_HARDENING.md §6 | `PURE_CIPHERTEXT_WIRE_FORMAT_POLICY`; KeyPackages and Welcomes inside OTRv4+ | **no test** | -- | **UNSUPPORTED** (no gate) | E: describe the mechanism |
| 2.10 | "Optional key publication (owner decision) ... **Recommendation:** do 1 and 2 now, and decide on 3." / "D1 → rotate only ...; publishing old keys is deferred." / "M2b optional" | MLS_SECURITY_HARDENING.md §1, §7, §8 | F4 shipped | -- | -- | **UNSUPPORTED** (stale: superseded by F4) | E: marked superseded |
| 2.11 | F4 row: residual "a signature captured and verified before the release stays attributable for ever" | SECURITY_ISSUES.md | -- | `a_publication_carries_both_halves_of_the_composite_key` | residuals missing from the entry: members only; online; the 16-key bound | **PARTIAL** (incomplete residual list) | F: residuals added |
| 2.12 | "Any member could have made the signature." | DENIABILITY_LAYERS.md (F4 row) | as 2.1 | as 2.1 | the forger set is the members who received the publication | **DEMONSTRATED** | E: the forger set named |

## 3. Participation and the handshake (A2, SPEC §10.1)

| # | Claim (verbatim) | Where | Code | Test(s) | Residual(s) | Status | Fix |
|---|---|---|---|---|---|---|---|
| 3.1 | "the v2 handshake authenticates both sides with ML-DSA-87" | SECURITY_ISSUES.md A2 | `dake.rs` | `dake::pq_auth_tests`, `tests/test_pq_auth_v2.py` | TOFU | **DEMONSTRATED** | -- |
| 3.2 | "and refuses downgrade or key change for a pinned contact" / "a known contact's ML-DSA key is pinned, so dropping or changing it ... is refused" | SECURITY_ISSUES.md A2; SPEC §4.3 (5); SECURITY.md Protocol security ("pinned per contact") | `TrustDatabase.check_or_pin_pq` | `test_dropping_post_quantum_authentication_is_refused`, `test_a_different_ml_dsa_key_is_refused` (one process) | **Android and the desktop keep the trust database in memory** (`OTRConfig().persist_trust` is False; `ChaquopyOtrCore.kt:109`, `desktop_bridge/host.py:375`), so every pin is gone at the next start. Only the terminal persists it (`persist_trust=True`) | **PARTIAL**: true within one run of the app; across restarts on the terminal only | F: new issue **P1** (OPEN); E; T: an asserted-residual test |
| 3.3 | "Peer identity silently swapped between XMPP sessions — Fingerprint pinned on first contact; a change is reported, never auto-accepted" | SECURITY.md defends table | `TrustDatabase.check_or_pin` | the pinning tests (one process) | as 3.2: after a restart of the app the new key is a first contact | **PARTIAL** | E; F: P1 |
| 3.4 | "Post-quantum deniability is NOT provided ... A transcript therefore shows that both parties took part" | SPEC §10.1 | -- | -- | -- | **DEMONSTRATED** (a limitation, stated) | -- |
| 3.5 | "The Ed448 ring signature itself remains deniable." / "Ed448 ring signatures ... are OTR's deniable authentication" | SPEC §10.1; TECHNICAL.md | `ring_sig.rs` | `ring_sig` tests (soundness only) | -- | **EXTERNAL** (Q3) | -- |
| 3.6 | "either party could have produced any message in the transcript" | SPEC §10.1 | symmetric chain keys | -- | -- | **EXTERNAL** (Q2) | -- |
| 3.7 | "ML-DSA-87 under keys made fresh for each run, so its signatures attribute to nobody" | PQC_DECISIONS.md (e) | `smp.rs` `mldsa_keygen` per run | **no test** that two runs use two keys | -- | **PARTIAL** (code only) | T: `smp` test |
| 3.8 | "This is equivalent to the ML-DSA-87 context API without requiring pqcrypto_mldsa to expose a context-parameter interface." | `Rust/src/smp.rs` comment | `mldsa_sign_with_context` prepends the context | -- | FIPS 204's context is `0 ‖ len(ctx) ‖ ctx ‖ M`, not `ctx ‖ M`; and `pqcrypto-mldsa` 0.1.2 does expose `detached_sign_ctx` | **UNSUPPORTED** (comment wrong on both counts; the construction is a domain-separated message, not the FIPS 204 context) | E: comment corrected; Q (CRYPTOGRAPHER_QUESTIONS 7) |
| 3.9 | "A2's pinning carries over" (to a v3 KEM key) | PQC_DECISIONS.md (e) | -- | -- | inherits 3.2 | **PARTIAL** | E |

## 4. First contact (TOFU) and server identity (X1)

| # | Claim (verbatim) | Where | Code | Test(s) | Residual(s) | Status | Fix |
|---|---|---|---|---|---|---|---|
| 4.1 | "No primitive can close it." | SECURITY_ISSUES.md TOFU; PQC_DECISIONS.md (e) | -- | -- | -- | **EXTERNAL** (a reasoned argument, not testable) | -- |
| 4.2 | "a changed destination receives no byte, and no password is sent where certificate checks are off" | SECURITY_ISSUES.md X1 | `server_pins.py`, `transport._restrict_to_scram`, `otrv4plus_xmpp.py` | `TestSubstitutionIsBlocked`, `TestScramOnlyOnTheWire`, `tests/test_x1_terminal_client.py` | TOFU; SCRAM offline guessing; first registration | **DEMONSTRATED** (re-checked by mutation in B) | -- |
| 4.3 | Server pins survive a restart | X1 "Pins are public data ... stored at `~/.otrv4plus/server_pins.json`" | `server_pins.py` | `TestPersistence::test_pins_survive_a_restart_and_are_private` | -- | **DEMONSTRATED** (unlike 3.2, server pins are persisted) | -- |
| 4.4 | "Active MITM at first contact — Hybrid PQC SMP zero-knowledge proof out-of-band" | SECURITY.md | `smp.rs` | the SMP suites | needs the user to run SMP with a secret shared out of band | **DEMONSTRATED** (mechanism; it defends only when used) | -- |

## 5. Key boundary and memory

| # | Claim (verbatim) | Where | Code | Test(s) | Residual(s) | Status | Fix |
|---|---|---|---|---|---|---|---|
| 5.1 | "Python handles networking and Kotlin handles the Android screens; neither holds session keys." | README.md | `DakeOutput`, `MessageMacKey` handles | `tests/test_release_guard.py`, T8, `tests/test_rust_identity_sealing.py` | the DEK (B1); the voice ML-KEM key (SECURITY.md caveat 11) | **DEMONSTRATED** for session keys | -- |
| 5.2 | "the ML-KEM decapsulation key is the one secret still Python-side (see caveat 11)" | SECURITY.md defends table | -- | -- | B1 residual: the at-rest DEK is also a Python `bytes` | **UNSUPPORTED** ("the one") | E |
| 5.3 | "The private halves never reach Python or Kotlin." | MLS_SECURITY_HARDENING.md §1 (F4) | `revealed_fingerprints` | `test_only_fingerprints_come_out_of_rust` | -- | **DEMONSTRATED** | -- |
| 5.4 | "Compromised endpoint after message is sent: Skipped message keys cached for up to 1000 messages" | SECURITY.md | `MAX_SKIP = 1000` per gap, `MAX_MESSAGE_KEYS = 2000` held | `ratchet` skipped-store bound tests | -- | **PARTIAL**: up to 2000 are held (1000 per gap) | E |

## 6. Assessment statements

| # | Claim (verbatim) | Where | Evidence | Status | Fix |
|---|---|---|---|---|---|
| 6.1 | "several independent layers of automated validation, each of which runs on every change" | SECURITY.md | cargo-fuzz is in no workflow; the table also lists AI review and physical tests | **UNSUPPORTED** | E |
| 6.2 | "`Rust/src` (151 core tests), `Rust/mls` (33)"; "6,300+ tests"; "Counts are as of 2026-09-28" | SECURITY.md | dated; current counts in SUMMARY.md (D) | **DEMONSTRATED** as dated, stale | E: current counts |
| 6.3 | "Security status: ... not independently audited." | README, SECURITY.md | -- | **DEMONSTRATED** | -- |

## 7. Other user-facing protections spot-checked

| # | Claim (verbatim) | Where | Test(s) | Status |
|---|---|---|---|---|
| 7.1 | "Your message waits and goes only once an encrypted session is up; it is never sent unencrypted." | `FailureText.kt` | `tests/test_outbox_no_plaintext.py` | **DEMONSTRATED** |
| 7.2 | "a removed member reads nothing after the removal" | README.md | `test_group_delete_removes_everyone.py::test_a_removed_member_cannot_read_what_follows`, `test_group_calls.py::test_a_removed_member_cannot_hear_after_the_commit` | **DEMONSTRATED** |
| 7.3 | "composite signature **Ed448 + ML-DSA-87** (both must verify)" | README.md | `provider::both_halves_must_verify` | **DEMONSTRATED** |
| 7.4 | "these groups resist 'record now, decrypt later'" | README.md | `hpke::hybrid_binds_both_halves` | **EXTERNAL** (construction unreviewed, and the README says so) |
| 7.5 | "Two accounts ... cannot be linked by their key" | SECURITY_ISSUES.md F2; Verification text | `tests/test_f2_per_account_identity.py` (keys on the wire differ) | **DEMONSTRATED** |
| 7.6 | "relaying nothing for others" (built-in router) | README.md | `test_android_bundled_router.py::test_no_transit_never_floodfill` | **DEMONSTRATED** (config) |

## Totals (before fixes)

63 rows, each counted once under its weakest status:

| Status | Rows |
|---|---|
| DEMONSTRATED | 25 |
| PARTIAL | 16 |
| UNSUPPORTED | 15 |
| EXTERNAL | 7 |

## After the fixes

Every PARTIAL and UNSUPPORTED row was dealt with in this pass:
- **Reworded to what is demonstrated (E).** Rows 1.1-1.4, 1.8-1.15, 1.19,
  1.25, 2.1, 2.4, 2.6, 2.7, 2.9, 2.10, 3.3, 3.8, 3.9, 5.2, 5.4, 6.1 and
  6.2. Each sentence now states the mechanism, or the narrower thing a
  test shows, and its residual.
- **Strengthened by a test (T).** Rows 1.13, 1.21, 1.22, 1.23 and 3.7.
  Each now has a test that asserts the sentence or its residual; see
  docs/AUDIT_TEST_INTEGRITY.md.
- **Narrowed and tied to a new OPEN issue (F).** Rows 3.2, 3.3 and 3.9:
  A2's claim now holds within one run of the app on Android and the
  desktop, across runs on the terminal. The restart case is
  docs/SECURITY_ISSUES.md **P1**, asserted by
  `tests/test_p1_trust_pins_per_run.py`.
- **Residuals added to the entry (F).** Rows 2.11 and 2.12: F4's
  forger set, the online requirement and the 16-key bound.

None of the EXTERNAL rows moved; they are docs/CRYPTOGRAPHER_QUESTIONS.md.
