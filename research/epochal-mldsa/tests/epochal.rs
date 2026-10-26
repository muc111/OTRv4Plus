// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
//! The six required properties (ANALYSIS.md §1, C1-C3 and group binding),
//! then what the lifecycle adds and what it deliberately does not claim.

use epochal_mldsa::*;

const ALICE: &[u8] = b"alice@example.test";
const MALLORY: &[u8] = b"mallory@example.test";

fn epoch(n: u64) -> GroupEpoch {
    // Stands in for the MLS epoch authenticator: distinct per epoch, known
    // to that epoch's members.
    let mut auth = [0u8; 32];
    auth[..8].copy_from_slice(&n.to_be_bytes());
    auth[31] = 0xA7;
    GroupEpoch { group_id: b"team@conference.example.test".to_vec(), epoch_id: n, authenticator: auth }
}

/// Alice with keys for epochs 1..=last; the board where releases appear.
fn alice(last: u64) -> (EpochSigner, Vec<PublicKey>) {
    let mut s = EpochSigner::new(ALICE, [7u8; 32], 1);
    let pks = (1..=last).map(|n| s.epoch_keygen(n, &epoch(n)).unwrap()).collect();
    (s, pks)
}

// ── the six required tests ───────────────────────────────────────────────────

#[test]
fn t1_a_signature_verifies_during_its_epoch() {
    let (s, pks) = alice(1);
    let sig = sign(s.signing_key(1).unwrap(), b"hello, epoch 1");
    assert!(verify(&pks[0], b"hello, epoch 1", &sig));
    assert!(verify_bound(&pks[0], &epoch(1), b"hello, epoch 1", &sig));
    assert!(!verify(&pks[0], b"another message", &sig), "bound to its message");
}

#[test]
fn t2_after_release_a_forged_signature_for_that_epoch_verifies() {
    let (mut s, pks) = alice(2);
    let mut board = ReleaseBoard::default();
    board.publish(s.release_epoch_key(1).unwrap());
    // A third party with only the board: never a member, never Alice.
    let forged = board.forge_with_released_key(ALICE, 1, b"a line alice never wrote").unwrap();
    assert!(verify(&pks[0], b"a line alice never wrote", &forged));
    assert!(verify_bound(&pks[0], &epoch(1), b"a line alice never wrote", &forged),
            "indistinguishable from hers by verification");
}

#[test]
fn t3_a_forgery_for_epoch_n_plus_1_with_epoch_n_s_key_does_not_verify() {
    let (mut s, pks) = alice(3);
    let mut board = ReleaseBoard::default();
    board.publish(s.release_epoch_key(1).unwrap());
    let forged = board.forge_across(ALICE, 1, 2, b"posing as epoch 2").unwrap();
    assert!(!verify(&pks[1], b"posing as epoch 2", &forged));
    assert!(board.forge_with_released_key(ALICE, 2, b"x").is_none(), "2 was not released");
}

#[test]
fn t4_releasing_epoch_n_does_not_enable_forgery_of_n_minus_1() {
    let (mut s, pks) = alice(3);
    let mut board = ReleaseBoard::default();
    board.publish(s.release_epoch_key(2).unwrap());
    let forged = board.forge_across(ALICE, 2, 1, b"posing as epoch 1").unwrap();
    assert!(!verify(&pks[0], b"posing as epoch 1", &forged));
    assert!(board.forge_with_released_key(ALICE, 1, b"x").is_none(), "1 was not released");
    // And epoch 1 still authenticates Alice's real signatures.
    let real = sign(s.signing_key(1).unwrap(), b"real");
    assert!(verify(&pks[0], b"real", &real));
}

#[test]
fn t5_a_non_member_key_fails_group_binding() {
    let (_s, pks) = alice(1);
    // Mallory is not a member: she does not hold epoch 1's authenticator,
    // so she binds her key under one she made up.
    let mut wrong = epoch(1);
    wrong.authenticator = [0x55; 32];
    let mut m = EpochSigner::new(MALLORY, [9u8; 32], 1);
    let mpk = m.epoch_keygen(1, &wrong).unwrap();
    let sig = sign(m.signing_key(1).unwrap(), b"let me in");
    assert!(verify(&mpk, b"let me in", &sig), "her signature is a valid ML-DSA signature");
    assert!(!verify_group_binding(&mpk, &epoch(1)));
    assert!(!verify_bound(&mpk, &epoch(1), b"let me in", &sig), "but not a member's");
    assert!(verify_group_binding(&pks[0], &epoch(1)), "Alice's binds");
    assert!(!verify_group_binding(&pks[0], &epoch(2)), "and only to its own epoch");
}

#[test]
fn t6_an_epoch_n_signature_does_not_verify_under_epoch_n_plus_1_s_key() {
    let (s, pks) = alice(2);
    let sig = sign(s.signing_key(1).unwrap(), b"said in epoch 1");
    assert!(!verify(&pks[1], b"said in epoch 1", &sig));
    let mut relabelled = sig.clone();
    relabelled.epoch_id = 2;
    assert!(!verify(&pks[1], b"said in epoch 1", &relabelled), "relabelling does not help");
}

// ── the lifecycle ────────────────────────────────────────────────────────────

#[test]
fn only_a_closed_epoch_can_be_released_and_once() {
    let (mut s, _pks) = alice(2);
    assert_eq!(s.release_epoch_key(2).err(), Some(ReleaseError::NotClosed), "2 is open");
    assert_eq!(s.release_epoch_key(3).err(), Some(ReleaseError::NotClosed), "3 is future");
    assert!(s.release_epoch_key(1).is_ok());
    assert!(s.signing_key(1).is_none(), "erased as it was released");
    assert_eq!(s.release_epoch_key(1).err(), Some(ReleaseError::Unknown));
}

#[test]
fn keys_only_go_forward_and_differ_per_epoch_and_group() {
    let (mut s, pks) = alice(3);
    assert!(s.epoch_keygen(2, &epoch(2)).is_err(), "no going back");
    let fps: Vec<_> = pks.iter().map(|p| p.vk.encode().to_vec()).collect();
    assert_ne!(fps[0], fps[1]);
    assert_ne!(fps[1], fps[2]);
    let mut other = epoch(1);
    other.group_id = b"other@conference.example.test".to_vec();
    let mut s2 = EpochSigner::new(ALICE, [7u8; 32], 1);
    let opk = s2.epoch_keygen(1, &other).unwrap();
    assert_ne!(opk.vk.encode().to_vec(), fps[0], "same chain, another group: unlinkable keys");
}

#[test]
fn a_release_carries_32_bytes_and_nothing_of_the_chain() {
    let (mut s, _pks) = alice(3);
    let r = s.release_epoch_key(1).unwrap();
    assert_eq!(r.seed.len(), 32);
    // The next epoch's seed is not any obvious function of the released one.
    let r2 = s.release_epoch_key(2).unwrap();
    assert_ne!(r.seed, r2.seed);
}

#[test]
fn at_the_boundary_a_receiver_refuses_a_released_epoch() {
    let (mut s, pks) = alice(2);
    let late = sign(s.signing_key(1).unwrap(), b"signed late in epoch 1");
    let mut board = ReleaseBoard::default();
    assert!(verify_unreleased(&board, &pks[0], &epoch(1), b"signed late in epoch 1", &late));
    board.publish(s.release_epoch_key(1).unwrap());
    assert!(!verify_unreleased(&board, &pks[0], &epoch(1), b"signed late in epoch 1", &late),
            "after the release it may be a forgery, so it is refused");
}

#[test]
fn a_signature_whose_declared_epoch_is_not_its_key_s_is_refused() {
    // The context already binds the epoch cryptographically; the declared
    // epoch_id is what a receiver files the signature under (and checks
    // releases against). It must not be able to say another epoch.
    let (s, pks) = alice(2);
    let mut sig = sign(s.signing_key(1).unwrap(), b"filed under 1");
    assert!(verify(&pks[0], b"filed under 1", &sig));
    sig.epoch_id = 2;
    assert!(!verify(&pks[0], b"filed under 1", &sig), "under its own key, declared as 2");
}

#[test]
fn a_key_binds_only_to_a_group_state_of_its_own_epoch_even_with_the_same_authenticator() {
    // Defence in depth: MLS gives each epoch its own authenticator, but the
    // binding must not rest on that alone. A state labelled with another
    // epoch is refused even if its authenticator were reused.
    let (_s, pks) = alice(1);
    let mut relabelled = epoch(1);
    relabelled.epoch_id = 2;
    assert!(!verify_group_binding(&pks[0], &relabelled));
}

// ── what it does NOT give (ANALYSIS §1, §7): asserted, so it is not claimed ──

#[test]
fn limitation_the_binding_proves_membership_not_which_member() {
    // Bob is a member, so he holds the epoch authenticator, and can bind a
    // key of his own under ALICE's name. The binding tag cannot tell.
    let mut bob = EpochSigner::new(ALICE, [3u8; 32], 1);   // Bob's chain, Alice's name
    let fake = bob.epoch_keygen(1, &epoch(1)).unwrap();
    assert!(verify_group_binding(&fake, &epoch(1)));
    let sig = sign(bob.signing_key(1).unwrap(), b"I am alice");
    assert!(verify_bound(&fake, &epoch(1), b"I am alice", &sig));
}

#[test]
fn cost_per_member_epoch() {
    let start = std::time::Instant::now();
    let (s, pks) = alice(10);
    let keygen = start.elapsed() / 10;
    let t = std::time::Instant::now();
    let sig = sign(s.signing_key(1).unwrap(), b"m");
    let sign_t = t.elapsed();
    let t = std::time::Instant::now();
    assert!(verify(&pks[0], b"m", &sig));
    let verify_t = t.elapsed();
    println!("keygen {keygen:?}/epoch, sign {sign_t:?}, verify {verify_t:?}, pk {} B, sig {} B, release 32 B",
             pks[0].vk.encode().len(), sig.bytes.len());
}

#[test]
fn the_schedule_is_24h_by_default_and_configurable() {
    let day = EpochSchedule::default();
    assert_eq!(day.epoch_at(0), 1);
    assert_eq!(day.epoch_at(24 * 3600 - 1), 1);
    assert_eq!(day.epoch_at(24 * 3600), 2);
    let hourly = EpochSchedule { start_unix: 1000, duration_secs: 3600 };
    assert_eq!(hourly.epoch_at(1000 + 3 * 3600 + 5), 4);
}

// ── the handshake: the test that matters for "that you talked" ──────────────

const BOB: &[u8] = b"bob@example.test";
const CAROL: &[u8] = b"carol@example.test";

fn transcript(responder: &[u8], tag: u8) -> Vec<u8> {
    handshake_transcript(ALICE, responder, &[tag; 56], &[tag ^ 0xFF; 56], &[tag; 32])
}

#[test]
fn h1_during_the_epoch_a_handshake_signature_attributes_it_to_the_key_holder() {
    let (s, pks) = alice(1);
    let real = transcript(BOB, 1);
    let sig = sign(s.signing_key(1).unwrap(), &real);
    assert!(verify_bound(&pks[0], &epoch(1), &real, &sig));
    // Nobody else's key yields a signature that verifies as Alice's.
    let mut other = EpochSigner::new(BOB, [5u8; 32], 1);
    other.epoch_keygen(1, &epoch(1)).unwrap();
    let not_hers = sign(other.signing_key(1).unwrap(), &real);
    assert!(!verify(&pks[0], &real, &not_hers));
}

#[test]
fn h2_after_release_handshakes_alice_never_ran_verify_as_hers() {
    let (mut s, pks) = alice(2);
    let real = transcript(BOB, 1);
    let real_sig = sign(s.signing_key(1).unwrap(), &real);
    let mut board = ReleaseBoard::default();
    board.publish(s.release_epoch_key(1).unwrap());
    // An outsider fabricates handshakes: with Bob under other ephemerals and
    // session ids, and with Carol, whom Alice never talked to.
    for (who, tag) in [(BOB, 2u8), (BOB, 3), (CAROL, 4)] {
        let fake = transcript(who, tag);
        let forged = board.forge_with_released_key(ALICE, 1, &fake).unwrap();
        assert!(verify_bound(&pks[0], &epoch(1), &fake, &forged),
                "a handshake that never happened verifies as Alice's");
    }
    // Her real one still verifies -- and is now one of arbitrarily many that
    // do, so it no longer shows that she ran it, nor with whom.
    assert!(verify(&pks[0], &real, &real_sig));
}

#[test]
fn h3_the_release_does_not_reach_the_next_epoch_s_handshakes() {
    let (mut s, pks) = alice(3);
    let mut board = ReleaseBoard::default();
    board.publish(s.release_epoch_key(1).unwrap());
    let fake = transcript(BOB, 9);
    let forged = board.forge_across(ALICE, 1, 2, &fake).unwrap();
    assert!(!verify(&pks[1], &fake, &forged), "epoch 2's handshakes stay attributable");
}

#[test]
fn limitation_a_long_term_certificate_of_the_epoch_key_stays_evidence() {
    // If pk_N is certified by Alice's LONG-TERM key (as the v2 DAKE's
    // ML-DSA identity key would naturally be used), the certificate is never
    // released: after the epoch, it still proves Alice held pk_N in this
    // group at this epoch. The handshake is deniable; the certificate's
    // statement is not. So pk_N must be authenticated some other way, or
    // certified with nothing peer- or group-specific in it (ANALYSIS §1a).
    use ml_dsa::{ExpandedSigningKey, MlDsa87, B32};
    let long_term = ExpandedSigningKey::<MlDsa87>::from_seed(&B32::from([1u8; 32]));
    let (mut s, pks) = alice(2);
    let cert_body = [pks[0].group_hash.as_slice(), &pks[0].epoch_id.to_be_bytes(),
                     pks[0].vk.encode().as_slice()].concat();
    let cert = long_term.sign_deterministic(&cert_body, b"cert").unwrap();
    let mut board = ReleaseBoard::default();
    board.publish(s.release_epoch_key(1).unwrap());
    assert!(long_term.verifying_key().verify_with_context(&cert_body, b"cert", &cert),
            "after the release the certificate still verifies: membership stays attributable");
}
