# Audit: threat model, walked against the code

Audit and hardening pass, 2026-10-26. The threat model is SECURITY.md:
"What OTRv4+ tries to defend against" and "What OTRv4+ does not defend
against". SPEC.md §1 lists primitives only and states no adversary, so this
document takes the adversaries from SECURITY.md and from the residuals
docs/SECURITY_ISSUES.md names.

For each layer:
- the adversary assumed;
- what the layer denies it;
- a concrete attack: what the adversary sees, what it tries, what the code
  does, and what a test shows.

Only the attacks the residuals already name were walked, plus the two the
walk itself turned up. Nothing was added to look thorough.

**Two new findings, both filed in SECURITY_ISSUES.md:**
- **P1 (Medium, OPEN).** On Android and the desktop, contact pins last one
  run of the app.
- **P2 (High, RESOLVED in this pass).** A forced DH step the peer could not
  follow silently broke a session after two days, or after 100 messages
  from one side.

## 1. One-to-one content (L1)

**Adversary.** J, a third party shown a transcript. J holds either the
peer's copy or a recording of the traffic (the server, a network observer).
J wants to show that Alice wrote line *m*. J holds no key.

**What the layer denies J.** After a close whose closing messages arrived,
the outer MAC of every line can be recomputed from the wire alone. So the
MAC does not single out Alice. AES-GCM is keyed by the message key, which is
never published. This is the mechanism; the property is Q2 in
docs/CRYPTOGRAPHER_QUESTIONS.md.

| Attack | J sees / tries | The code | The test | Matches the docs? |
|---|---|---|---|---|
| Verify the MAC after close | every frame; recomputes each line's MAC | each line's MKmac is in a later `revealed_mac_keys` field | `test_every_line_in_both_directions_has_its_mac_key_on_the_wire`; `test_every_line_is_covered_across_dh_steps` (new) | yes |
| Forge a line the receiver accepts | uses a published key on an altered frame | outer MAC valid; refused (replay at the same position, AEAD at the next); the session is unharmed | `test_residual_the_receiver_refuses_a_frame_only_the_outer_mac_was_forged_for` (new) | yes, now tested |
| **Partial close** | drops part 2 of a two-part close (network adversary) | each part kept until the server confirms; re-sent | `TestMultiPartClose::test_a_lost_second_part_leaves_exactly_its_range_provable` | yes: exactly part 2's range stays provable until the re-send |
| **Crash before confirmation** | the app dies after `retire_all` (or is made to: battery, OOM) | the book is in memory only; nothing is re-sent at the next launch | `TestCrashDuringClose` (its on-disk check strengthened: it now also finds a closing frame written as wire text) | yes: that close stays provable |
| **Second-closing gap** | Bob's app never processes Alice's closing message | Alice's closing covers Bob's lines; Bob holds the keys of Alice's last lines, unpublished | `test_residual_a_peer_that_never_closes_leaves_our_lines_provable` (new) | yes, now tested: exactly the lines after Bob's last message |
| The server never answers the ping | Alice's ping unanswered | after 15 s the new session starts anyway; the result says "unconfirmed"; the closing messages are kept in memory only and re-sent up to 40 times while the app runs | `test_residual_unconfirmed_the_new_session_starts_anyway_and_the_app_says_so` (new), `test_a_closing_message_is_given_up_after_its_tries` | **no**: "waits until the server confirms" and "keeps sending until it does" were wrong. Wording corrected (E) |
| Offline at the press | no transport | kept in memory only (never on disk), sent when back while the app runs | `test_offline_at_the_press_they_go_when_it_is_back` | **no**: SPEC §5.8 and SECURITY_ISSUES said "dropped". Corrected |

A recording held by the server, of lines whose keys were never published
(any of the residual rows), verifies under a key only Alice and Bob held.
It shows the line came from one of the two. That is OTR's starting point,
not a new leak. The peer's own copy proves nothing against Alice, since
Bob could have made it.

## 2. Group content (F4)

**Adversary.** J, shown a group transcript by a member, wants to show that
Alice signed message *m*.

**What the layer denies J.** Once Alice's retired leaf key has been
published, any member who received the publication can produce signatures
under it. A transcript shown after that does not single out Alice.

| Attack | J sees / tries | The code | The test | Matches? |
|---|---|---|---|---|
| **Pre-publication capture** | a member forwards a signed message to J while the key is still secret; J verifies it at once | nothing can undo a verification already made | `residual_a_signature_checked_before_release_still_checks_after_it` (new) | yes: permanent, as MLS_SECURITY_HARDENING §1 says. The "window ... or none after Publish Group Keys" sentence was wrong and is corrected |
| A non-member forges after release | not in the group; wants the published key | the publication is an MLS message encrypted to the members | `residual_only_the_groups_members_receive_the_published_key` (new) | yes; the forger set (members) is now named |
| A member offline at rekey time | publication due after 10 min; the app is not running | nothing is published until `maintain` runs; past 16 retired keys the oldest go unpublished | `retired_keys_are_bounded_and_published_in_batches` | yes; the residual added to the F4 row |
| A published key signs into the group | a member tries to post with the released key | the tree holds the new key; refused | `the_published_key_forges_old_signatures_but_cannot_sign_into_the_group` | yes |

## 3. Participation (A2, SPEC §10.1)

**Adversary.** The server, or anyone recording DAKEs. It wants to show that
Alice's identity ran a handshake with Bob's.

**What the layer denies it.** Nothing, by design.

| Attack | Sees / tries | The code | The test | Matches? |
|---|---|---|---|---|
| Verify the DAKE's ML-DSA signatures | DAKE1-3; Alice's long-term ML-DSA key, in her profile | the signatures verify under long-term keys | `dake::pq_auth_tests` | yes; stated in SPEC §10.1, the dialogs and the README |
| Link two accounts on one device by that key | DAKE1 from each account | one identity per account | `tests/test_f2_per_account_identity.py` | yes |

## 4. First contact (TOFU) and every contact after a restart (P1)

**Adversary.** An active man-in-the-middle on the XMPP path: the server,
or whoever controls the route. It substitutes its own keys in a DAKE.

**What the layer denies it.** After the first contact, a changed Ed448
fingerprint is refused (`FingerprintMismatchError`). So is a changed or
dropped ML-DSA key under the same Ed448 identity (`pq_key_changed`,
`pq_downgrade`). SMP detects a substitute at any time, if the two people
run it.

| Attack | Tries | The code | The test | Matches? |
|---|---|---|---|---|
| **TOFU at first contact** | substitutes at the very first DAKE | the substitute is pinned | `test_both_ends_pin_the_others_long_term_ml_dsa_key` (pinning); no primitive closes it (PQC_DECISIONS (e)) | yes; shared residual |
| Substitute later, in the same run | another key mid-run | refused | `test_dropping_post_quantum_authentication_is_refused`, `test_a_different_ml_dsa_key_is_refused`, `test_within_one_run_a_changed_key_is_refused` | yes |
| **Substitute after the app restarts (P1)** | waits for the Android or desktop app to restart (a reboot, an update, the OS ending the process), then substitutes | `OTRConfig()` has `persist_trust=False`, so the app's trust database is in memory and empty. **The substitute is pinned as a first contact, with no warning** | `test_residual_after_a_restart_of_the_app_a_changed_key_is_a_first_contact` (new, asserts it) | **no**. SECURITY.md says a change "is reported, never auto-accepted"; A2 says a pinned contact's key change is refused. True within a run; on the terminal, across runs too. **Filed as P1, OPEN** |

**P1 is not fixed here.** Fixing it needs a persisted, sealed, per-account
trust store, the way F3 keeps identities. That is a storage feature, not a
correction. Until then, A2's claim and SECURITY.md are worded to match:
pins hold for one app run on Android and the desktop, and across runs in
the terminal client. The proposal is in the P1 entry.

## 5. Transport (N1, X1)

**Adversary.** A network or DNS observer; a substituted `.i2p` address-book
entry; a library that opens its own socket.

| Attack | Tries | The code | The test | Matches? |
|---|---|---|---|---|
| A `.i2p` name to DNS | any resolver call on an I2P route | the audit hook refuses it | `tests/test_n1_network_isolation.py` | yes, for the app's own code; i2pd's reseed is its own process; no device capture yet |
| Substituted destination | re-points the name | refused before `SESSION CREATE`; zero bytes reach it | `TestSubstitutionIsBlocked` (re-checked by mutation in this pass) | yes |
| Collect the password | offers PLAIN only | no `<auth>` sent | `TestScramOnlyOnTheWire` | yes; SCRAM offline guessing stays a residual |

## 6. Identity at rest (F2, F3)

**Adversary.** The server linking accounts; someone with the device's files.

| Attack | Tries | The code | The test | Matches? |
|---|---|---|---|---|
| Link two accounts | compares DAKE1 keys | per-account identity | `test_f2_per_account_identity.py` | yes |
| Read the identity from a copy of the files | copies the vault | Rust-sealed, plus the Keystore on Android | `test_f3_stable_account_identity.py` | yes; code running as the app on an unlocked phone can use it (stated) |

## 7. The A1 combiner under loss (SPEC §5.1)

**Adversary.** Q records everything and breaks X448 later. Q also drops
messages, to keep fresh ML-KEM secrets out of the root.

**The documented residual.** Lose every message of the chain that carries
Alice's encapsulation key, then let her side take a forced step. Then "the
key stays outstanding and v2 adds no new ML-KEM secret in that direction
... The X448 ratchet is unaffected."

**What the walk found (P2).** The forced step in that scenario was a
**second send step toward the same remote key**. The peer cannot follow
it: its receive step uses the key it made after the first one. So the X448
ratchet was not unaffected. Every later message failed to decrypt, with
`handle_incoming_message` returning None and the session still shown as up.

This needed no adversary. The same double step happened to ordinary use:
- any 100 messages from one side after a DH round trip;
- or a chat left open across two 24-hour boundaries with a normal exchange
  between them.

Reproduced with real engines: a two-day session broke on day three, in both
directions, and a randomised burst test failed 235 messages.

**Fixed in this pass** in the engine every client shares
(`client/otrv4+.py`). The Rust core is untouched. At most one send step goes
toward each remote key (`_forced_toward`, set by a forced step and by the
receive step); the next step comes from the peer's reply.

Gates:
- `tests/test_p2_forced_steps.py`: every test fails on the old engine and
  passes now;
- Rust `pq_ratchet::p2_a_second_send_step_toward_the_same_remote_key_cannot_be_followed`
  pins the constraint at the Rust level.

**Consequence for SPEC §5.1.** With the fix, a new sending chain starts
only after the peer has stepped. The peer steps only on receiving a message
of our current chain, and every message of that chain carries the
encapsulation key. So the scenario in the residual can no longer be
reached. The residual is reworded. The combiner itself remains Q4.

**Interop.** A peer on an older build can still take the double step, and
our side cannot follow it either. This fix stops this build producing it;
accepting it from an old peer would need a change in the Rust receive
path. That is not made here and is recorded on P2.
