# Audit and hardening pass, 2026-10-26: summary

On `dev`, from `ca81787` (and the research prototype commits after it, up
to `24dfadc`). `main` (rc.184, `7db66ad`) is out of scope and untouched.

The pass checked every protection the repository claims against the code,
the tests and the documented residuals. Its success condition was not that
deniability is proven. It was that no sentence states a protection the
code, the tests and the named residuals do not jointly support.

The record:
- [AUDIT_CLAIM_MATRIX.md](AUDIT_CLAIM_MATRIX.md): 63 claims;
- [AUDIT_TEST_INTEGRITY.md](AUDIT_TEST_INTEGRITY.md): 36 mutants;
- [AUDIT_THREAT_MODEL.md](AUDIT_THREAT_MODEL.md);
- [CRYPTOGRAPHER_QUESTIONS.md](CRYPTOGRAPHER_QUESTIONS.md).

## What the pass found

**Two new issues, both in docs/SECURITY_ISSUES.md:**
- **P2 (High, RESOLVED).** A forced DH step toward a key the engine had
  already stepped toward could not be followed by the peer. Every later
  message failed to decrypt, silently. It was reached by 100 messages from
  one side after a round trip, or by a chat open across two days.
  - Found while writing a residual test for SPEC §5.1, whose residual it
    turned out to be.
  - Fixed in the engine every client shares; the Rust core is unchanged.
  - Gates: `tests/test_p2_forced_steps.py` (each test fails on the old
    engine) and a Rust constraint test.
- **P1 (High, RESOLVED 2026-10-27; filed as Medium).** On Android and the
  desktop, contact pins (fingerprint and ML-DSA) lasted one run of the
  app, so after a restart a changed key was a first contact.
  - Widened while fixing it: the apps never checked the Ed448 fingerprint
    pin at all. Only the terminal client called `check_or_pin`. So a
    changed key went unreported within a run too. This pass's first test
    called the database directly and missed it
    (docs/AUDIT_TEST_INTEGRITY.md).
  - Fixed: each account's pins are kept sealed in a store of their own
    (the F3 sealing path; not the identity vault, not the X1 server pins).
    The apps check the pin when a session comes up, show
    FINGERPRINT_MISMATCH and send nothing queued until the user resets
    trust. A record that will not open is refused, never replaced. Wipe &
    Exit destroys the store.
  - Gates: `tests/test_p1_trust_pins_per_run.py`, through real apps over a
    wire. `test_after_a_restart_a_changed_fingerprint_is_refused` fails on
    the old code; `test_wipe_and_exit_destroys_the_trust_store` proves the
    wipe. 14 of 14 mutants killed.
  - Residuals: an Android device whose Keystore does not work keeps pins
    for one run; the terminal's `trust.json` is plaintext; TOFU.
  - The claim matrix was then re-run end to end
    (docs/AUDIT_CLAIM_MATRIX.md, "Re-run after P1"). It found one stale
    sentence left from row 1.14, and two places where the P1 fix itself
    weakened a neighbour (the file gate, the Reset trust dialog). All three
    are fixed and gated. No row went down.

## (a) Claims downgraded

| Claim | Was | Now |
|---|---|---|
| L1 in the app: Android/desktop dialog, terminal `/help` | "deniability pending external audit"; "no longer proves who wrote what: anyone holding it could have forged it" | the mechanism and its residuals: "Not independently reviewed. A copy made before the keys are published, or a close that does not finish, can still be proof." |
| L1 in README.md | "1:1 deniability of what was said, pending external audit" | the chats "can publish the keys that authenticated their messages, a mechanism not yet independently reviewed" |
| L1 in SECURITY_ISSUES.md | "The claim is that a copy ... does not prove who wrote what" | "What the mechanism does": the aim, and what the tests show |
| Make Chat Deniable waits for confirmation | "waits until our server confirms ... before the new session starts" (SECURITY_ISSUES, CHANGELOG rc.186) | it *asks*, then starts the new session whatever the answer, and says which |
| Re-sending unconfirmed closing messages | "keeps sending it until it does" (the dialog), "until the server confirms" (CHANGELOG) | up to 40 times while the app runs (the terminal: 5), from memory only; lost if the app closes |
| Offline closing messages | "dropped" (SPEC §5.8, SECURITY_ISSUES L1, `app_deniable.py`) | kept **in memory only, never written to disk**, and sent when back while the app runs; lost if it ends first. The code did that already. The privacy decision is unchanged: nothing on the device records whom a chat was made deniable with (`TestCrashDuringClose`) |
| The new session | "unlinked to the old one", "no cryptographic link" | "shares no key with the old one"; both handshakes are signed by the same identities |
| F4 in the app | "so a copy of the group shown after that no longer proves who signed what. Pending external audit." | "so any of them can make signatures under those keys too ... Not independently reviewed." |
| F4 window (MLS_SECURITY_HARDENING §1) | "... or none after Make Group Deniable" | Make Group Deniable shortens how long keys stay secret from the press on; it does nothing for a capture already made |
| MLS_SECURITY_HARDENING §6 | "OTRv4+ is deniable (DAKE, ring signatures, published MAC keys)" | no deniability property is claimed for either; why |
| MLS_SECURITY_HARDENING §6 | "The server never sees a JID–key link." | the design gives it none; no test checks it end to end |
| A2 (SECURITY_ISSUES, SPEC §4.3, SECURITY.md) | refuses a downgrade or a key change "for a pinned contact" | within one run of the app on Android and the desktop, across runs on the terminal (P1). **Restored by the P1 fix**: across restarts on Android (with a working Keystore), the desktop and the terminal |
| SECURITY.md, defended adversaries | a changed fingerprint "is reported, never auto-accepted" | the same, plus: on Android and the desktop only within a run (P1). That was itself too generous: the apps did not check at all. **Restored by the P1 fix** |
| SECURITY.md, validation | "layers of automated validation, each of which runs on every change" | the suites, `cargo audit` and Clippy run in CI; fuzzing, reviews and physical tests by hand |
| SECURITY.md, memory | the ML-KEM key is "the one secret still Python-side" | that and the at-rest key-encryption key (B1-seed) |
| SECURITY.md, skipped keys | "cached for up to 1000 messages" | 1000 per gap, 2000 held |
| SPEC §5.1 residual | "the key stays outstanding ... The X448 ratchet is unaffected." | that scenario was P2's double step, which broke the session; unreachable since the fix; reworded |
| `smp.rs` comment | the binding is "equivalent to the ML-DSA-87 context API" | domain separation in the message, not the FIPS 204 context (Q7) |
| MLS_SECURITY_HARDENING §1, §7, §8 | publication "deferred", "optional", "decide on 3" | marked superseded by F4 |

## (b) Tests strengthened

- **Gaps found by mutation, closed:**
  - RM1b: no test crossed a DH step for R1
    (`test_every_line_is_covered_across_dh_steps`);
  - PM5: termination and failure never tested
    (`test_a_session_ending_by_termination_or_failure_publishes_too`);
  - PM8: the crash test's disk check missed a frame written as wire text
    (strengthened);
  - MM1: the receiver's ML-DSA-half check was untested (a spliced-key
    case).
- **Renamed to what they show:**
  - T1: `test_a_published_key_lets_anyone_mac_an_altered_copy_of_an_observed_message`;
  - T4: `TestT4PublishedKeysAreNotHeld`;
  - T5: `..._fresh_session_sharing_no_key`;
  - T6: `test_the_bridge_sends_each_closing_message_once`;
  - `test_the_new_session_starts_after_the_server_is_asked`;
  - the Kotlin wording test.
- **New gates:**
  - `tests/test_deniable_wording.py`: no surface states a deniability
    property;
  - `tests/test_security_doc_references.py`: every path, SPEC section and
    test cited in the security record exists.
- **Mutation results:**
  - round 1 (29 mutants): 23 killed, RM6 detected by a hang, 5 survived;
  - round 2: every survivor killed, except one equivalent mutant (PM6);
  - all 5 new mutants killed, and both Kotlin wording mutants.

## (c) Residuals added (each with a test that asserts it)

| Issue | Residual | Test |
|---|---|---|
| L1 | the receiver refuses a frame only the outer MAC was forged for | `test_residual_the_receiver_refuses_a_frame_only_the_outer_mac_was_forged_for` |
| L1 | an altered outer MAC costs the message, and its key is published | `TestL1Residuals::test_residual_an_altered_outer_mac_costs_the_message_and_its_key_is_published` |
| L1 | a peer that never closes leaves our last lines provable | `test_residual_a_peer_that_never_closes_leaves_our_lines_provable` |
| L1 | unconfirmed, the new session starts anyway | `test_residual_unconfirmed_the_new_session_starts_anyway_and_the_app_says_so` |
| F4 | a signature checked before release still checks after it | `retired_key_tests::residual_a_signature_checked_before_release_still_checks_after_it` |
| F4 | only the members receive the published key | `retired_key_tests::residual_only_the_groups_members_receive_the_published_key` |
| F4 | needs the app running; the 16-key bound | (entry; `retired_keys_are_bounded_and_published_in_batches`) |
| A2 | pins last one run without a working Keystore (P1, after the fix) | `test_residual_without_a_working_keystore_the_pins_last_one_run` |
| P2 | an older peer's double step | Rust `p2_a_second_send_step_toward_the_same_remote_key_cannot_be_followed` |

## (d) What is now demonstrably true

Each item is shown by a named test that fails when the code is broken
(docs/AUDIT_TEST_INTEGRITY.md):
- **The L1 mechanism.** After a close whose closing messages arrived, the
  outer MAC of every line can be recomputed from the wire alone:
  - in both directions;
  - across DH steps, loss and reordering;
  - for a close over 2000 keys;
  - never before the message was delivered.

  Nothing published authenticates the new session, and a forged frame is
  refused.
- **L1's limits.** The residual cases (partial close, crash before
  confirmation, unanswered confirmation, a peer that never closes)
  behave exactly as documented.
- **F4.** A rotation retires the composite key; its publication reaches
  the members and lets them forge under it. It cannot sign into the
  group. A current or inconsistent key is refused, and a capture made
  before release still verifies.
- **P2.** A session survives one-way runs and days open.
- **A2.** A changed or dropped ML-DSA key is refused within a run, and
  across runs on the terminal.
- **X1.** A changed destination receives no byte, and no password is sent
  where certificates are off.
- **No surface states a deniability property.**
- **The Rust boundary holds.** The production wheel exposes no raw-key,
  seed-injection, legacy DAKE or MAC-key accessor; the release guard
  passes against it.

## (e) What still requires a cryptographer

docs/CRYPTOGRAPHER_QUESTIONS.md, each a yes/no question with what either
answer changes in the code:
- **Q1.** The R1-R3 retirement predicate, with the one interleaving the
  audit cannot rule out stated exactly.
- **Q2.** What MKmac publication gives when AES-GCM's tag is a second,
  unpublished authenticator: possibly only symmetric deniability.
- **Q3.** Offline participation deniability of the v2 DAKE. We expect it
  fails in every setting.
- **Q4.** The SHAKE-256 combiner, and the loss interleaving after P2.
- **Q5.** F4. The premise in the brief was corrected: both composite
  halves are epoch-scoped. What is long-lived is the attributable 1:1
  handshakes around the group.
- **Q6.** A KEM-based v3 handshake.
- **Q7.** SMP's message-prefix binding.

## (f) Build and test status

Local runs, on the final tree:

| What | Result |
|---|---|
| `cargo build --release` (Rust/) | OK |
| `cargo test --release` (Rust/) | **199 passed, 0 failed** |
| `cargo clippy --release --all-targets -D warnings`: default, `mls`, and `raw-key-test-api,mls` | clean, all three |
| `cargo build --features legacy-dake-keys` without opt-in | **refused, as required**: `REFUSING TO BUILD: legacy-dake-keys is enabled`, exit 101 |
| `cargo test --release` (Rust/mls) | **70 passed, 0 failed** (29 + 8 + 5 + 4 + 4 + 11 + 9) |
| `cargo clippy` (Rust/mls) | clean |
| Full Python suite (`pytest tests`, test wheel) | **8114 passed, 0 failed, 0 errors, 47 skipped**, 1 deselected (the raw-key production check, run below against the production wheel); 317 files, per-file table below |
| `pytest tests/test_l1_revelation_gate.py -v` | **27 passed** (T1-T8 plus `TestL1Residuals`) |
| `pytest tests/test_release_guard.py -v` against the **production** wheel | **12 passed, 4 skipped** (the skips are the opt-in confirmations): no vault read-back, raw KDF, legacy DAKE methods, Dakeresult getters, seed injection or raw-key entry point; no gated symbol in the object file |
| `pytest tests/test_release_guard.py` against the test wheel | 12 passed, 4 skipped (it confirms the test build is the test build) |
| Production wheel smoke test | `otrv4_core-0.13.2-cp39-abi3` built without test features: no `generate_dake2` / `process_dake2` / `get_session_keys`, no Dakeresult getters, no `from_seed_bytes`, no `holds_mac_key`. **OK** |
| Kotlin `DeniableChatTest` (JVM harness) | 9 passed |
| Desktop type-check (`desktop/src`, Kotlin, no Compose plugin) | no type error; only the known "Couldn't inline Column" back-end error of the harness |
| Research prototype `tools/prove.sh` | 38 passed; 11/11 mutants killed; OpenSSL 8/8 (research/epochal-mldsa/RESULTS.md) |
| Android `gradle assembleDebug` | **not run here**: this container has no Android SDK. It runs in CI's Android workflow (`:app:assembleDebug` and `:app:assembleRelease`); results below |
| Desktop `desktop/install.sh` | **not run here** (it installs system packages). It runs in CI's Desktop workflow on a clean Ubuntu; results below |

CI on the pushed head of `dev`:

| Workflow | Result |
|---|---|
| Android (assembleDebug, assembleRelease, unit tests) | **success** on `dfeec16`: unit tests, assembleDebug, assembleRelease, both ABIs' core and router ([run 40376935225](https://github.com/muc111/OTRv4Plus/actions/runs/40376935225)) |
| Desktop (install, flow test, screens) | **success** on `dfeec16`: Compose build, flow test, screens, and desktop/install.sh on a clean Ubuntu 24.04 ([run 40376935475](https://github.com/muc111/OTRv4Plus/actions/runs/40376935475)) |
| Python (the suite) | **success** on `dfeec16` ([run 40376935364](https://github.com/muc111/OTRv4Plus/actions/runs/40376935364)) |
| Research (the prototype's prove.sh) | **success** on `24dfadc`, the last change under research/ ([run 40362508728](https://github.com/muc111/OTRv4Plus/actions/runs/40362508728)); its path filter did not fire for this pass |

## Owner decisions

1. **The action's name. Decided 2026-10-27: renamed.** "Make Chat
   Deniable…" and "Make Group Deniable…" named a property the code does
   not demonstrate. They are now **Publish Chat Keys…** and **Publish
   Group Keys…**, with the confirm button "Publish keys". The labels name
   the mechanism, as the dialogs do; `DeniableChatTest` and
   `tests/test_deniable_wording.py` pin them. The terminal's `/deniable`
   command keeps its name: its `/help` describes the mechanism.
2. **P1. Decided 2026-10-27: built.** The pins are persisted sealed per
   account, in a store separate from the identity vault and the X1 pins,
   sharing F3's sealing path but not its directory. Wipe & Exit destroys
   both stores; an unopenable record is refused, retried, never replaced.
   A2's claim says "across restarts" on Android and the desktop again.
3. **P2 and older peers. Decided 2026-10-27: the Rust core is left alone.**
   The residual is recorded in the matrix instead. It comes from *older v2
   builds* (before `884b054`), not from v1 peers, so `pq_v2_required` does
   not refuse them. It is real, not theoretical: an older build reaches it
   by ordinary use. It is transient: it ends when that peer updates.

<details>
<summary>Per-file results of the full Python suite (317 files)</summary>

| File | Passed | Failed | Errors | Skipped |
|---|---|---|---|---|
| `tests/test_aaudio_close_race.py` | 2 | 0 | 0 | 0 |
| `tests/test_android_account_teardown.py` | 15 | 0 | 0 | 0 |
| `tests/test_android_attention_alerts.py` | 13 | 0 | 0 | 0 |
| `tests/test_android_audio_path.py` | 13 | 0 | 0 | 1 |
| `tests/test_android_bridge.py` | 97 | 0 | 0 | 0 |
| `tests/test_android_bridge_surface.py` | 5 | 0 | 0 | 0 |
| `tests/test_android_bundled_router.py` | 12 | 0 | 0 | 0 |
| `tests/test_android_calls.py` | 63 | 0 | 0 | 0 |
| `tests/test_android_chat_deletion.py` | 8 | 0 | 0 | 0 |
| `tests/test_android_chat_layout.py` | 17 | 0 | 0 | 0 |
| `tests/test_android_chat_ux.py` | 97 | 0 | 0 | 0 |
| `tests/test_android_ci_paths.py` | 15 | 0 | 0 | 0 |
| `tests/test_android_connection_controller.py` | 63 | 0 | 0 | 0 |
| `tests/test_android_connection_lifecycle.py` | 44 | 0 | 0 | 0 |
| `tests/test_android_connection_profile.py` | 62 | 0 | 0 | 0 |
| `tests/test_android_connection_service.py` | 33 | 0 | 0 | 0 |
| `tests/test_android_dependency_licences.py` | 56 | 0 | 0 | 0 |
| `tests/test_android_diagnostics.py` | 27 | 0 | 0 | 0 |
| `tests/test_android_durability.py` | 28 | 0 | 0 | 0 |
| `tests/test_android_error_log_ui.py` | 41 | 0 | 0 | 0 |
| `tests/test_android_event_mapping.py` | 15 | 0 | 0 | 0 |
| `tests/test_android_eventlog.py` | 24 | 0 | 0 | 0 |
| `tests/test_android_failure_report.py` | 27 | 0 | 0 | 2 |
| `tests/test_android_files.py` | 76 | 0 | 0 | 0 |
| `tests/test_android_first_launch.py` | 3 | 0 | 0 | 0 |
| `tests/test_android_handshake_progress.py` | 6 | 0 | 0 | 0 |
| `tests/test_android_identity.py` | 0 | 0 | 0 | 36 |
| `tests/test_android_login_and_register_ui.py` | 50 | 0 | 0 | 0 |
| `tests/test_android_notifications.py` | 33 | 0 | 0 | 0 |
| `tests/test_android_online_users_discovery.py` | 7 | 0 | 0 | 0 |
| `tests/test_android_people_screen.py` | 7 | 0 | 0 | 0 |
| `tests/test_android_poll_resilience.py` | 21 | 0 | 0 | 0 |
| `tests/test_android_presence_and_keepalive.py` | 32 | 0 | 0 | 0 |
| `tests/test_android_registration.py` | 35 | 0 | 0 | 0 |
| `tests/test_android_registration_flow.py` | 29 | 0 | 0 | 0 |
| `tests/test_android_report_export.py` | 4 | 0 | 0 | 0 |
| `tests/test_android_room_chat.py` | 26 | 0 | 0 | 0 |
| `tests/test_android_room_passwords.py` | 22 | 0 | 0 | 0 |
| `tests/test_android_rooms.py` | 72 | 0 | 0 | 0 |
| `tests/test_android_rooms_flow.py` | 86 | 0 | 0 | 0 |
| `tests/test_android_rooms_ui.py` | 60 | 0 | 0 | 0 |
| `tests/test_android_sam_probe.py` | 19 | 0 | 0 | 0 |
| `tests/test_android_signin_ux.py` | 20 | 0 | 0 | 0 |
| `tests/test_android_signout_relogin.py` | 4 | 0 | 0 | 0 |
| `tests/test_android_startup_cost.py` | 19 | 0 | 0 | 0 |
| `tests/test_android_sync.py` | 20 | 0 | 0 | 0 |
| `tests/test_android_termux_interop.py` | 23 | 0 | 0 | 0 |
| `tests/test_android_theme.py` | 5 | 0 | 0 | 0 |
| `tests/test_android_transport.py` | 75 | 0 | 0 | 0 |
| `tests/test_android_transport_lifecycle.py` | 41 | 0 | 0 | 0 |
| `tests/test_android_voice_backend.py` | 18 | 0 | 0 | 0 |
| `tests/test_android_welcome_room.py` | 32 | 0 | 0 | 0 |
| `tests/test_apk_extension_naming.py` | 4 | 0 | 0 | 0 |
| `tests/test_apk_python_deps.py` | 11 | 0 | 0 | 0 |
| `tests/test_apk_python_sources.py` | 12 | 0 | 0 | 0 |
| `tests/test_app_identity.py` | 18 | 0 | 0 | 0 |
| `tests/test_asset_provenance.py` | 3 | 0 | 0 | 0 |
| `tests/test_attacks.py` | 100 | 0 | 0 | 0 |
| `tests/test_audio_backend.py` | 61 | 0 | 0 | 0 |
| `tests/test_auth_retry.py` | 18 | 0 | 0 | 0 |
| `tests/test_avatar_safety.py` | 90 | 0 | 0 | 0 |
| `tests/test_burst_alignment.py` | 25 | 0 | 0 | 0 |
| `tests/test_call_notification.py` | 46 | 0 | 0 | 0 |
| `tests/test_call_refusal_reasons.py` | 5 | 0 | 0 | 0 |
| `tests/test_call_sam_endpoint.py` | 4 | 0 | 0 | 0 |
| `tests/test_call_trace.py` | 3 | 0 | 0 | 0 |
| `tests/test_change_password.py` | 16 | 0 | 0 | 0 |
| `tests/test_chaquopy_dict_access.py` | 50 | 0 | 0 | 0 |
| `tests/test_chat_security_marker.py` | 18 | 0 | 0 | 0 |
| `tests/test_ci_watches_what_it_tests.py` | 3 | 0 | 0 | 0 |
| `tests/test_clearnet_registration.py` | 38 | 0 | 0 | 0 |
| `tests/test_client_finds_the_bridge.py` | 2 | 0 | 0 | 0 |
| `tests/test_closing_messages_arrive.py` | 7 | 0 | 0 | 0 |
| `tests/test_controller_retire.py` | 5 | 0 | 0 | 0 |
| `tests/test_conversation_row_security.py` | 14 | 0 | 0 | 0 |
| `tests/test_crypto_source_of_truth.py` | 5 | 0 | 0 | 0 |
| `tests/test_dake1_rate_limit.py` | 20 | 0 | 0 | 0 |
| `tests/test_dake3_rust_authority.py` | 13 | 0 | 0 | 0 |
| `tests/test_dake_recovery.py` | 18 | 0 | 0 | 0 |
| `tests/test_dake_timeout.py` | 5 | 0 | 0 | 0 |
| `tests/test_datagram_transport.py` | 35 | 0 | 0 | 0 |
| `tests/test_deniability_wire_audit.py` | 11 | 0 | 0 | 0 |
| `tests/test_deniable_confirmation.py` | 11 | 0 | 0 | 0 |
| `tests/test_deniable_wording.py` | 2 | 0 | 0 | 0 |
| `tests/test_dependency_advisories.py` | 25 | 0 | 0 | 0 |
| `tests/test_desktop_audio_host.py` | 4 | 0 | 0 | 0 |
| `tests/test_desktop_bridge.py` | 18 | 0 | 0 | 0 |
| `tests/test_desktop_compose_skipping.py` | 1 | 0 | 0 | 0 |
| `tests/test_desktop_file_viewer.py` | 21 | 0 | 0 | 0 |
| `tests/test_desktop_sees_who_is_online.py` | 3 | 0 | 0 | 0 |
| `tests/test_diagnostic_export.py` | 68 | 0 | 0 | 0 |
| `tests/test_diagnostic_privacy.py` | 86 | 0 | 0 | 0 |
| `tests/test_differential.py` | 18 | 0 | 0 | 0 |
| `tests/test_disconnect_is_immediate.py` | 7 | 0 | 0 | 0 |
| `tests/test_dispatch_families.py` | 4 | 0 | 0 | 0 |
| `tests/test_f2_per_account_identity.py` | 15 | 0 | 0 | 0 |
| `tests/test_f3_stable_account_identity.py` | 18 | 0 | 0 | 0 |
| `tests/test_f4_group_key_publication.py` | 10 | 0 | 0 | 0 |
| `tests/test_failure_codes_registered.py` | 8 | 0 | 0 | 0 |
| `tests/test_failures_reach_the_screen.py` | 3 | 0 | 0 | 0 |
| `tests/test_file_export.py` | 4 | 0 | 0 | 0 |
| `tests/test_file_transfer_boundary.py` | 73 | 0 | 0 | 0 |
| `tests/test_file_transfer_crypto.py` | 33 | 0 | 0 | 0 |
| `tests/test_file_transfer_pacing.py` | 33 | 0 | 0 | 0 |
| `tests/test_file_transfer_states.py` | 11 | 0 | 0 | 0 |
| `tests/test_file_transfer_storage.py` | 91 | 0 | 0 | 0 |
| `tests/test_final_boss.py` | 9 | 0 | 0 | 0 |
| `tests/test_fragment_interop.py` | 30 | 0 | 0 | 0 |
| `tests/test_fragment_wire_format.py` | 78 | 0 | 0 | 0 |
| `tests/test_function_length.py` | 5 | 0 | 0 | 0 |
| `tests/test_gain.py` | 91 | 0 | 0 | 0 |
| `tests/test_gated_build_is_uniform.py` | 4 | 0 | 0 | 0 |
| `tests/test_group_call_watchdog.py` | 5 | 0 | 0 | 0 |
| `tests/test_group_calls.py` | 22 | 0 | 0 | 0 |
| `tests/test_group_delete_removes_everyone.py` | 6 | 0 | 0 | 0 |
| `tests/test_group_entry_requests.py` | 22 | 0 | 0 | 0 |
| `tests/test_group_files.py` | 21 | 0 | 0 | 0 |
| `tests/test_group_invite_end_to_end.py` | 12 | 0 | 0 | 0 |
| `tests/test_group_invite_online.py` | 7 | 0 | 0 | 0 |
| `tests/test_group_invite_reaches_desktop.py` | 6 | 0 | 0 | 0 |
| `tests/test_group_keys_banner.py` | 5 | 0 | 0 | 0 |
| `tests/test_group_members_view.py` | 10 | 0 | 0 | 0 |
| `tests/test_group_vectors.py` | 43 | 0 | 0 | 0 |
| `tests/test_group_verify_from_the_chat.py` | 6 | 0 | 0 | 0 |
| `tests/test_group_verify_once.py` | 8 | 0 | 0 | 0 |
| `tests/test_harness_audit.py` | 28 | 0 | 0 | 2 |
| `tests/test_i2p_destination.py` | 20 | 0 | 0 | 0 |
| `tests/test_i2p_naming_no_dns.py` | 62 | 0 | 0 | 0 |
| `tests/test_i2p_server_refusals.py` | 18 | 0 | 0 | 0 |
| `tests/test_i2p_short_names.py` | 48 | 0 | 0 | 0 |
| `tests/test_identity_and_tofu.py` | 43 | 0 | 0 | 0 |
| `tests/test_identity_report.py` | 13 | 0 | 0 | 0 |
| `tests/test_import_diagnostics.py` | 13 | 0 | 0 | 0 |
| `tests/test_import_does_not_exit.py` | 18 | 0 | 0 | 0 |
| `tests/test_install_branches.py` | 6 | 0 | 0 | 0 |
| `tests/test_invariant_registry.py` | 119 | 0 | 0 | 0 |
| `tests/test_irc_dake_stages.py` | 33 | 0 | 0 | 0 |
| `tests/test_irc_exit_notice.py` | 2 | 0 | 0 | 0 |
| `tests/test_irc_fragment_pacing.py` | 138 | 0 | 0 | 0 |
| `tests/test_irc_guided_smp.py` | 53 | 0 | 0 | 1 |
| `tests/test_irc_history_privacy.py` | 35 | 0 | 0 | 0 |
| `tests/test_irc_names_list.py` | 80 | 0 | 0 | 0 |
| `tests/test_irc_nick_session_diagnostic.py` | 24 | 0 | 0 | 0 |
| `tests/test_irc_panel_replay.py` | 16 | 0 | 0 | 0 |
| `tests/test_irc_reconnect_preserves_otr.py` | 36 | 0 | 0 | 0 |
| `tests/test_irc_smp_command_routing.py` | 27 | 0 | 0 | 0 |
| `tests/test_irc_smp_responder_resume.py` | 38 | 0 | 0 | 0 |
| `tests/test_jid_canonicalisation.py` | 79 | 0 | 0 | 0 |
| `tests/test_jitter_latency.py` | 48 | 0 | 0 | 0 |
| `tests/test_jitter_target_estimator.py` | 26 | 0 | 0 | 0 |
| `tests/test_join_request_creator_decides.py` | 3 | 0 | 0 | 0 |
| `tests/test_join_request_prompt.py` | 4 | 0 | 0 | 0 |
| `tests/test_kdf_claims_are_true.py` | 22 | 0 | 0 | 0 |
| `tests/test_keepalive_ping_api.py` | 21 | 0 | 0 | 0 |
| `tests/test_kotlin_imports.py` | 2 | 0 | 0 | 0 |
| `tests/test_l1_crash_during_close.py` | 4 | 0 | 0 | 0 |
| `tests/test_l1_revelation_gate.py` | 27 | 0 | 0 | 0 |
| `tests/test_latency_colour.py` | 26 | 0 | 0 | 0 |
| `tests/test_latency_decomposition.py` | 18 | 0 | 0 | 0 |
| `tests/test_licence_declarations_agree.py` | 59 | 0 | 0 | 0 |
| `tests/test_licensing_scope.py` | 6 | 0 | 0 | 0 |
| `tests/test_location_pins.py` | 6 | 0 | 0 | 0 |
| `tests/test_log_boundary.py` | 107 | 0 | 0 | 0 |
| `tests/test_loudness_knobs.py` | 10 | 0 | 0 | 0 |
| `tests/test_mac_key_revelation.py` | 17 | 0 | 0 | 0 |
| `tests/test_mac_key_stays_in_rust.py` | 6 | 0 | 0 | 0 |
| `tests/test_mac_revelation_end_to_end.py` | 9 | 0 | 0 | 0 |
| `tests/test_master_protocol_verifier.py` | 13 | 0 | 0 | 0 |
| `tests/test_media_config.py` | 30 | 0 | 0 | 0 |
| `tests/test_media_liveness.py` | 42 | 0 | 0 | 0 |
| `tests/test_media_path_accounting.py` | 40 | 0 | 0 | 0 |
| `tests/test_media_recovery.py` | 144 | 0 | 0 | 0 |
| `tests/test_media_reject_classification.py` | 16 | 0 | 0 | 0 |
| `tests/test_message_actions.py` | 8 | 0 | 0 | 0 |
| `tests/test_message_to_a_non_contact.py` | 5 | 0 | 0 | 0 |
| `tests/test_metadata_scrub.py` | 41 | 0 | 0 | 0 |
| `tests/test_mlkem_cross_implementation.py` | 10 | 0 | 0 | 0 |
| `tests/test_mlkem_kat.py` | 15 | 0 | 0 | 0 |
| `tests/test_mls_plus_labeling.py` | 7 | 0 | 0 | 0 |
| `tests/test_moderation_client.py` | 7 | 0 | 0 | 0 |
| `tests/test_muc_destroy.py` | 5 | 0 | 0 | 0 |
| `tests/test_muc_rules.py` | 84 | 0 | 0 | 0 |
| `tests/test_musl_build_config.py` | 24 | 0 | 0 | 0 |
| `tests/test_n1_network_isolation.py` | 46 | 0 | 0 | 0 |
| `tests/test_new_chat_lists_who_is_online.py` | 4 | 0 | 0 | 0 |
| `tests/test_no_legacy_data_format.py` | 2 | 0 | 0 | 0 |
| `tests/test_no_parallel_crypto.py` | 31 | 0 | 0 | 0 |
| `tests/test_no_remote_input_capture.py` | 22 | 0 | 0 | 0 |
| `tests/test_no_unresolved_globals.py` | 105 | 0 | 0 | 0 |
| `tests/test_notification_tap_asks.py` | 11 | 0 | 0 | 0 |
| `tests/test_one_router_path.py` | 8 | 0 | 0 | 0 |
| `tests/test_otr_message_classification.py` | 23 | 0 | 0 | 0 |
| `tests/test_otr_thread_affinity.py` | 14 | 0 | 0 | 0 |
| `tests/test_otrv4_integration.py` | 14 | 0 | 0 | 0 |
| `tests/test_otrv4plus_capability.py` | 36 | 0 | 0 | 0 |
| `tests/test_otrv_container_bridge.py` | 8 | 0 | 0 | 0 |
| `tests/test_outbox_no_plaintext.py` | 12 | 0 | 0 | 0 |
| `tests/test_p1_trust_pins_per_run.py` | 4 | 0 | 0 | 0 |
| `tests/test_p2_forced_steps.py` | 4 | 0 | 0 | 0 |
| `tests/test_pdf_isolation.py` | 5 | 0 | 0 | 0 |
| `tests/test_peer_address_mistakes.py` | 15 | 0 | 0 | 0 |
| `tests/test_peer_fingerprint_is_stable.py` | 5 | 0 | 0 | 0 |
| `tests/test_peer_gone_otr.py` | 26 | 0 | 0 | 0 |
| `tests/test_phase11_protocol_regressions.py` | 5 | 0 | 0 | 0 |
| `tests/test_plaintext_before_otr.py` | 19 | 0 | 0 | 0 |
| `tests/test_playback_attributes.py` | 12 | 0 | 0 | 0 |
| `tests/test_playout_instrumentation.py` | 17 | 0 | 0 | 0 |
| `tests/test_pq_auth_v2.py` | 18 | 0 | 0 | 0 |
| `tests/test_pq_ratchet_v2.py` | 6 | 0 | 0 | 0 |
| `tests/test_presence_after_adding_a_contact.py` | 17 | 0 | 0 | 0 |
| `tests/test_presence_per_resource.py` | 7 | 0 | 0 | 0 |
| `tests/test_presence_state.py` | 57 | 0 | 0 | 0 |
| `tests/test_profile_identity.py` | 6 | 0 | 0 | 0 |
| `tests/test_profile_vcard.py` | 23 | 0 | 0 | 0 |
| `tests/test_property.py` | 35 | 0 | 0 | 0 |
| `tests/test_prosody_moderation_module.py` | 5 | 0 | 0 | 0 |
| `tests/test_protocol_version.py` | 37 | 0 | 0 | 0 |
| `tests/test_pyo3_boundary.py` | 44 | 0 | 0 | 0 |
| `tests/test_qubes_packaging.py` | 9 | 0 | 0 | 0 |
| `tests/test_qubes_relay.py` | 8 | 0 | 0 | 0 |
| `tests/test_ratchet_torture.py` | 5 | 0 | 0 | 0 |
| `tests/test_readme_matches_the_code.py` | 26 | 0 | 0 | 0 |
| `tests/test_reconnect_does_not_duplicate.py` | 13 | 0 | 0 | 0 |
| `tests/test_registration.py` | 59 | 0 | 0 | 0 |
| `tests/test_rekey_divergence.py` | 18 | 0 | 0 | 0 |
| `tests/test_rekey_recovery.py` | 20 | 0 | 0 | 0 |
| `tests/test_release_guard.py` | 11 | 0 | 0 | 4 |
| `tests/test_release_notes.py` | 21 | 0 | 0 | 0 |
| `tests/test_removing_a_contact.py` | 19 | 0 | 0 | 0 |
| `tests/test_reveal_ordering.py` | 15 | 0 | 0 | 0 |
| `tests/test_revealed_mac_crosscheck.py` | 20 | 0 | 0 | 0 |
| `tests/test_room_actions.py` | 15 | 0 | 0 | 0 |
| `tests/test_room_destroy.py` | 23 | 0 | 0 | 0 |
| `tests/test_room_history_on_join.py` | 9 | 0 | 0 | 0 |
| `tests/test_room_history_own_and_corrections.py` | 6 | 0 | 0 | 0 |
| `tests/test_room_listing.py` | 6 | 0 | 0 | 0 |
| `tests/test_room_occupant_counts.py` | 16 | 0 | 0 | 0 |
| `tests/test_room_password_prompts.py` | 4 | 0 | 0 | 0 |
| `tests/test_rooms_service_discovery_retry.py` | 3 | 0 | 0 | 0 |
| `tests/test_rooms_tab_flashes.py` | 3 | 0 | 0 | 0 |
| `tests/test_route_parity.py` | 3 | 0 | 0 | 0 |
| `tests/test_rust_identity_sealing.py` | 36 | 0 | 0 | 0 |
| `tests/test_rust_owns_secrets.py` | 201 | 0 | 0 | 0 |
| `tests/test_rust_security.py` | 31 | 0 | 0 | 1 |
| `tests/test_rust_security_adversarial.py` | 17 | 0 | 0 | 0 |
| `tests/test_rust_zeroization.py` | 18 | 0 | 0 | 0 |
| `tests/test_sam_session_held_between_attempts.py` | 6 | 0 | 0 | 0 |
| `tests/test_secret_at_rest.py` | 19 | 0 | 0 | 0 |
| `tests/test_secret_never_echoes.py` | 20 | 0 | 0 | 0 |
| `tests/test_secure_group_actions.py` | 10 | 0 | 0 | 0 |
| `tests/test_secure_groups.py` | 74 | 0 | 0 | 0 |
| `tests/test_secure_groups_bridge.py` | 10 | 0 | 0 | 0 |
| `tests/test_security_doc_references.py` | 33 | 0 | 0 | 0 |
| `tests/test_send_queue_bounds.py` | 13 | 0 | 0 | 0 |
| `tests/test_server_limits_installer.py` | 3 | 0 | 0 | 0 |
| `tests/test_session_teardown.py` | 16 | 0 | 0 | 0 |
| `tests/test_shed_does_not_manufacture_gaps.py` | 7 | 0 | 0 | 0 |
| `tests/test_signed_in_elsewhere.py` | 16 | 0 | 0 | 0 |
| `tests/test_signin_status.py` | 4 | 0 | 0 | 0 |
| `tests/test_smp_after_messages.py` | 8 | 0 | 0 | 0 |
| `tests/test_smp_android_interop.py` | 35 | 0 | 0 | 0 |
| `tests/test_smp_argon2_wire_v3.py` | 16 | 0 | 0 | 0 |
| `tests/test_smp_end_to_end.py` | 20 | 0 | 0 | 0 |
| `tests/test_smp_guided_flow.py` | 73 | 0 | 0 | 0 |
| `tests/test_smp_no_secret.py` | 13 | 0 | 0 | 0 |
| `tests/test_spdx_headers_on_new_files.py` | 4 | 0 | 0 | 0 |
| `tests/test_spec_matches_code.py` | 17 | 0 | 0 | 0 |
| `tests/test_speech_clarity.py` | 12 | 0 | 0 | 0 |
| `tests/test_stresstest.py` | 13 | 0 | 0 | 0 |
| `tests/test_stresstest_cleanup.py` | 5 | 0 | 0 | 0 |
| `tests/test_stresstest_welcome.py` | 4 | 0 | 0 | 0 |
| `tests/test_suite_integrity.py` | 9 | 0 | 0 | 0 |
| `tests/test_teardown_other_thread.py` | 1 | 0 | 0 | 0 |
| `tests/test_terminal_alerts.py` | 13 | 0 | 0 | 0 |
| `tests/test_terminal_sync.py` | 6 | 0 | 0 | 0 |
| `tests/test_termux_group_files.py` | 19 | 0 | 0 | 0 |
| `tests/test_termux_groups.py` | 52 | 0 | 0 | 0 |
| `tests/test_termux_outbox.py` | 4 | 0 | 0 | 0 |
| `tests/test_tip_address_relay.py` | 113 | 0 | 0 | 0 |
| `tests/test_tls_follows_transport.py` | 14 | 0 | 0 | 0 |
| `tests/test_tor_transport.py` | 16 | 0 | 0 | 0 |
| `tests/test_trade_courier.py` | 86 | 0 | 0 | 0 |
| `tests/test_transport_failclosed.py` | 12 | 0 | 0 | 0 |
| `tests/test_transport_isolation.py` | 17 | 0 | 0 | 0 |
| `tests/test_transport_loop_sends.py` | 2 | 0 | 0 | 0 |
| `tests/test_transport_policy.py` | 29 | 0 | 0 | 0 |
| `tests/test_transport_route.py` | 73 | 0 | 0 | 0 |
| `tests/test_tunnel_length.py` | 27 | 0 | 0 | 0 |
| `tests/test_u1_signed_out_surfaces.py` | 16 | 0 | 0 | 0 |
| `tests/test_venv_reexec.py` | 6 | 0 | 0 | 0 |
| `tests/test_viewer_zoom_and_attention.py` | 8 | 0 | 0 | 0 |
| `tests/test_voice_24k.py` | 15 | 0 | 0 | 0 |
| `tests/test_voice_audio_integration.py` | 49 | 0 | 0 | 0 |
| `tests/test_voice_authorization.py` | 12 | 0 | 0 | 0 |
| `tests/test_voice_call_summary.py` | 62 | 0 | 0 | 0 |
| `tests/test_voice_counters.py` | 16 | 0 | 0 | 0 |
| `tests/test_voice_frame_geometry.py` | 16 | 0 | 0 | 0 |
| `tests/test_voice_gate_at_answer.py` | 3 | 0 | 0 | 0 |
| `tests/test_voice_integer_bounds.py` | 14 | 0 | 0 | 0 |
| `tests/test_voice_note_messages.py` | 11 | 0 | 0 | 0 |
| `tests/test_voice_note_tail.py` | 8 | 0 | 0 | 0 |
| `tests/test_voice_notes.py` | 16 | 0 | 0 | 0 |
| `tests/test_voice_rust_parity.py` | 53 | 0 | 0 | 0 |
| `tests/test_voice_security.py` | 118 | 0 | 0 | 0 |
| `tests/test_warmpath.py` | 12 | 0 | 0 | 0 |
| `tests/test_wipe_and_exit.py` | 43 | 0 | 0 | 0 |
| `tests/test_wipe_server_account.py` | 6 | 0 | 0 | 0 |
| `tests/test_x1_destination_pinning.py` | 26 | 0 | 0 | 0 |
| `tests/test_x1_terminal_client.py` | 10 | 0 | 0 | 0 |
| `tests/test_xmpp_admin_forms.py` | 61 | 0 | 0 | 0 |
| `tests/test_xmpp_double.py` | 3 | 0 | 0 | 0 |
| `tests/test_xmpp_keepalive.py` | 33 | 0 | 0 | 0 |
| `tests/test_xmpp_plain_echo.py` | 24 | 0 | 0 | 0 |
| `tests/test_xmpp_session_lifecycle.py` | 21 | 0 | 0 | 0 |
| `tests/test_xmpp_sync.py` | 25 | 0 | 0 | 0 |
| `tests/test_xmpp_tag_colour.py` | 22 | 0 | 0 | 0 |
| `tests/test_xmpp_transcript_shape.py` | 23 | 0 | 0 | 0 |

</details>
