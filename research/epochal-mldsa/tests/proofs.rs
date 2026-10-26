// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
//! The claim C (ANALYSIS.md §1), shown in ways that do not depend on the
//! prototype grading its own work:
//!
//! * P1, exact indistinguishability. For the same randomiser, a forger's
//!   signature is byte for byte the holder's, and the key a forger rebuilds
//!   is the holder's key. Signing is a deterministic function of (key,
//!   message, randomiser) and the randomiser is uniform, so the two output
//!   distributions are identical: no test, however statistical, can tell a
//!   forgery from a real signature. Not a sampling argument.
//! * P2, independent verification. Holder and forger signatures, and the
//!   cross-epoch forgeries that must fail, run through PQClean, which
//!   shares no code with the RustCrypto implementation the prototype uses
//!   (and which tests/conformance.rs shows agrees with NIST).
//! * P3, the derivation is the one ANALYSIS §2 writes down: the chain, the
//!   seed, the key and the binding tag are recomputed here from the
//!   formulas alone and compared with what the library releases and
//!   publishes, and pinned as known answers.
//! * An export of public data only (keys, contexts, messages, signatures,
//!   expected outcomes) for a third verifier outside Rust:
//!   vectors/verify_openssl.py runs it through OpenSSL.

#![allow(deprecated)] // to_expanded: comparing the holder's and the rebuilt key.

use epochal_mldsa::*;
use pqcrypto_mldsa::mldsa87;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};
use sha3::{Digest, Sha3_256};

const ALICE: &[u8] = b"alice@example.test";
const BOB: &[u8] = b"bob@example.test";
const CAROL: &[u8] = b"carol@example.test";
const GROUP: &[u8] = b"team@conference.example.test";
const CHAIN_SEED: [u8; 32] = [7u8; 32];

fn epoch(n: u64) -> GroupEpoch {
    let mut auth = [0u8; 32];
    auth[..8].copy_from_slice(&n.to_be_bytes());
    auth[31] = 0xA7;
    GroupEpoch { group_id: GROUP.to_vec(), epoch_id: n, authenticator: auth }
}

fn alice(last: u64) -> (EpochSigner, Vec<PublicKey>) {
    let mut s = EpochSigner::new(ALICE, CHAIN_SEED, 1);
    let pks = (1..=last).map(|n| s.epoch_keygen(n, &epoch(n)).unwrap()).collect();
    (s, pks)
}

/// Deterministic, distinct randomisers and messages for the proofs.
fn rnd(i: u64) -> [u8; 32] {
    Sha3_256::digest([b"rnd".as_slice(), &i.to_be_bytes()].concat()).into()
}

fn message(i: u64) -> Vec<u8> {
    let len = (i as usize * 37) % 700;
    (0..len).map(|j| (j as u64 ^ i) as u8).collect()
}

fn pqclean_verifies(pk: &PublicKey, ctx: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let pk = mldsa87::PublicKey::from_bytes(&pk.vk.encode()).unwrap();
    match mldsa87::DetachedSignature::from_bytes(sig) {
        Ok(sig) => mldsa87::verify_detached_signature_ctx(&sig, msg, ctx, &pk).is_ok(),
        Err(_) => false,
    }
}

// ── P1 ───────────────────────────────────────────────────────────────────────

#[test]
fn p1_a_forgery_is_byte_identical_to_the_holders_signature_for_the_same_randomiser() {
    const EPOCHS: u64 = 4;
    const PER_EPOCH: u64 = 64;
    let (mut s, pks) = alice(EPOCHS + 1);
    // The holder signs, and her expanded keys are recorded, before release.
    let mut real = Vec::new();
    let mut held = Vec::new();
    for n in 1..=EPOCHS {
        let sk = s.signing_key(n).unwrap();
        held.push(sk.expanded().to_expanded().to_vec());
        for i in 0..PER_EPOCH {
            real.push((n, i, sk.sign_with_rnd(&message(i), &rnd(n * 1000 + i))));
        }
    }
    let mut board = ReleaseBoard::default();
    for n in 1..=EPOCHS {
        board.publish(s.release_epoch_key(n).unwrap());
    }
    for n in 1..=EPOCHS {
        let rebuilt = board.rebuild(ALICE, n).unwrap();
        assert_eq!(rebuilt.to_expanded().to_vec(), held[(n - 1) as usize],
                   "epoch {n}: the rebuilt key is the holder's key, all 4896 bytes");
        assert_eq!(rebuilt.verifying_key().encode(), pks[(n - 1) as usize].vk.encode());
    }
    for (n, i, sig) in &real {
        let forged = board.forge_with_rnd(ALICE, *n, &message(*i), &rnd(n * 1000 + i)).unwrap();
        assert_eq!(forged.bytes, sig.bytes, "epoch {n}, message {i}: byte-identical");
        assert!(verify_bound(&pks[(*n - 1) as usize], &epoch(*n), &message(*i), &forged));
    }
    assert_eq!(real.len() as u64, EPOCHS * PER_EPOCH);
}

#[test]
fn p1_the_randomiser_is_live_two_signatures_of_one_message_differ() {
    // Hedged signing: without a fresh randomiser P1 would compare a
    // deterministic signature with itself. Show it is not.
    let (s, pks) = alice(1);
    let a = sign(s.signing_key(1).unwrap(), b"same message");
    let b = sign(s.signing_key(1).unwrap(), b"same message");
    assert_ne!(a.bytes, b.bytes);
    assert!(verify(&pks[0], b"same message", &a) && verify(&pks[0], b"same message", &b));
}

// ── P2 ───────────────────────────────────────────────────────────────────────

#[test]
fn p2_pqclean_accepts_the_holders_and_the_forgers_signatures_alike() {
    let (mut s, pks) = alice(3);
    let real = sign(s.signing_key(1).unwrap(), b"said by alice");
    let mut board = ReleaseBoard::default();
    board.publish(s.release_epoch_key(1).unwrap());
    let forged = board.forge_with_released_key(ALICE, 1, b"never said by alice").unwrap();
    let ctx1 = context(&pks[0].group_hash, 1);
    assert!(pqclean_verifies(&pks[0], &ctx1, b"said by alice", &real.bytes));
    assert!(pqclean_verifies(&pks[0], &ctx1, b"never said by alice", &forged.bytes));
    // And a forged handshake with someone she never talked to.
    let hs = handshake_transcript(ALICE, CAROL, &[4; 56], &[0xFB; 56], &[4; 32]);
    let fhs = board.forge_with_released_key(ALICE, 1, &hs).unwrap();
    assert!(pqclean_verifies(&pks[0], &ctx1, &hs, &fhs.bytes));
}

#[test]
fn p2_pqclean_rejects_every_forgery_outside_the_released_epoch() {
    let (mut s, pks) = alice(3);
    let mut board = ReleaseBoard::default();
    board.publish(s.release_epoch_key(2).unwrap());
    for target in [1u64, 3] {
        let forged = board.forge_across(ALICE, 2, target, b"posing").unwrap();
        let pk = &pks[(target - 1) as usize];
        assert!(!pqclean_verifies(pk, &context(&pk.group_hash, target), b"posing", &forged.bytes),
                "release of 2 forging {target}");
    }
    // A real epoch-1 signature, presented as epoch 2's.
    let e1 = sign(s.signing_key(1).unwrap(), b"said in 1");
    assert!(!pqclean_verifies(&pks[1], &context(&pks[1].group_hash, 2), b"said in 1", &e1.bytes));
    // Under its own key but another epoch's context.
    assert!(!pqclean_verifies(&pks[0], &context(&pks[0].group_hash, 2), b"said in 1", &e1.bytes));
}

// ── P3 ───────────────────────────────────────────────────────────────────────

/// ANALYSIS §2's H: SHA3-256 over length-prefixed parts.
fn spec_h(parts: &[&[u8]]) -> [u8; 32] {
    let mut d = Sha3_256::new();
    for p in parts {
        d.update((p.len() as u32).to_be_bytes());
        d.update(p);
    }
    d.finalize().into()
}

/// ξ_N from the formulas alone: s_1 = chain seed, s_{N+1} = H("chain", s_N),
/// ξ_N = H("sign", s_N, H("group", G), N, auth_N).
fn spec_xi(n: u64) -> [u8; 32] {
    let mut s_n = CHAIN_SEED;
    for _ in 1..n {
        s_n = spec_h(&[b"chain", &s_n]);
    }
    let gh = spec_h(&[b"group", GROUP]);
    spec_h(&[b"sign", &s_n, &gh, &n.to_be_bytes(), &epoch(n).authenticator])
}

#[test]
fn p3_the_released_seeds_and_published_keys_follow_the_written_derivation() {
    const N: u64 = 6;
    let (mut s, pks) = alice(N + 1);
    for n in 1..=N {
        let r = s.release_epoch_key(n).unwrap();
        assert_eq!(r.seed, spec_xi(n), "ξ_{n}");
        let pk = &pks[(n - 1) as usize];
        assert_eq!(key_from_release_seed(&spec_xi(n)).verifying_key().encode(), pk.vk.encode(),
                   "pk_{n} = KeyGen_internal(ξ_{n})");
        let gh = spec_h(&[b"group", GROUP]);
        assert_eq!(pk.group_hash, gh);
        let tag = spec_h(&[b"bind", &epoch(n).authenticator, &gh, &n.to_be_bytes(), ALICE,
                           &spec_h(&[pk.vk.encode().as_slice()])]);
        assert_eq!(pk.binding, tag, "binding tag of epoch {n}");
    }
}

#[test]
fn p3_known_answers_pin_the_derivation() {
    // Frozen from the formulas above; pk_1 is KeyGen_internal(ξ_1), whose
    // conformance tests/conformance.rs shows.
    // Any change to the chain, the labels, the encoding or the key
    // generation shows up here.
    assert_eq!(hex::encode(spec_xi(1)),
               "202694d6525e4c8d6652c5f365ab0715ae77466d7ac9154e7c197382d162595d");
    assert_eq!(hex::encode(spec_xi(2)),
               "6fa03803bce1b70d9311420b9a45f4234c3a5e1200d9d6dd8d7b15be0503ba7f");
    let pk1 = key_from_release_seed(&spec_xi(1)).verifying_key().encode();
    assert_eq!(hex::encode(Sha3_256::digest(pk1)),
               "a07f102b6bae9a2f492d1a96b69d3e41cd1bde0e9b6f01abb404ddda4d241ee1");
}

#[test]
fn p3_each_epoch_s_seed_is_fresh_no_release_equals_another_or_a_chain_state() {
    // What the tests can show about one-wayness: no released value is any
    // other epoch's seed or any chain state. That ξ_N reveals nothing of
    // s_{N+1} is SHA3-256's preimage resistance, an assumption, not a test.
    const N: u64 = 32;
    let (mut s, _pks) = alice(N + 1);
    let released: Vec<[u8; 32]> = (1..=N).map(|n| s.release_epoch_key(n).unwrap().seed).collect();
    let mut chain = vec![CHAIN_SEED];
    for _ in 0..=N {
        let next = spec_h(&[b"chain", chain.last().unwrap()]);
        chain.push(next);
    }
    for (i, a) in released.iter().enumerate() {
        assert!(!chain.contains(a), "ξ_{} is not a chain state", i + 1);
        for b in &released[i + 1..] {
            assert_ne!(a, b);
        }
    }
}

// ── the export for a verifier outside Rust ──────────────────────────────────

#[test]
fn export_public_cases_for_an_outside_verifier() {
    let (mut s, pks) = alice(3);
    let ctx = |n: u64| context(&pks[(n - 1) as usize].group_hash, n);
    let real = sign(s.signing_key(1).unwrap(), b"said by alice");
    let e2 = sign(s.signing_key(2).unwrap(), b"said in 2");
    let mut board = ReleaseBoard::default();
    board.publish(s.release_epoch_key(1).unwrap());
    let forged = board.forge_with_released_key(ALICE, 1, b"never said by alice").unwrap();
    let hs = handshake_transcript(ALICE, BOB, &[2; 56], &[0xFD; 56], &[2; 32]);
    let fhs = board.forge_with_released_key(ALICE, 1, &hs).unwrap();
    let across = board.forge_across(ALICE, 1, 2, b"posing as 2").unwrap();
    let case = |label: &str, n: u64, ctx_epoch: u64, msg: &[u8], sig: &[u8], expected: bool| {
        serde_json::json!({
            "label": label, "pk": hex::encode(pks[(n - 1) as usize].vk.encode()),
            "context": hex::encode(ctx(ctx_epoch)), "message": hex::encode(msg),
            "signature": hex::encode(sig), "expected": expected,
        })
    };
    let cases = vec![
        case("holder, epoch 1", 1, 1, b"said by alice", &real.bytes, true),
        case("holder, epoch 2", 2, 2, b"said in 2", &e2.bytes, true),
        case("forger with the release of 1, epoch 1", 1, 1, b"never said by alice", &forged.bytes, true),
        case("forged handshake with Bob, epoch 1", 1, 1, &hs, &fhs.bytes, true),
        case("release of 1 forging epoch 2, under pk_2", 2, 2, b"posing as 2", &across.bytes, false),
        case("epoch-1 signature under pk_2", 2, 2, b"said by alice", &real.bytes, false),
        case("epoch-1 signature, epoch-2 context, pk_1", 1, 2, b"said by alice", &real.bytes, false),
        case("forgery, another message", 1, 1, b"altered", &forged.bytes, false),
    ];
    for c in &cases {
        let pk = &pks[if c["pk"] == hex::encode(pks[0].vk.encode()) { 0 } else { 1 }];
        let got = pqclean_verifies(pk, &hex::decode(c["context"].as_str().unwrap()).unwrap(),
                                   &hex::decode(c["message"].as_str().unwrap()).unwrap(),
                                   &hex::decode(c["signature"].as_str().unwrap()).unwrap());
        assert_eq!(got, c["expected"].as_bool().unwrap(), "PQClean: {}", c["label"]);
    }
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/target/evidence");
    std::fs::create_dir_all(dir).unwrap();
    let doc = serde_json::json!({
        "note": "public data only: verification keys, contexts, messages, signatures",
        "cases": cases,
    });
    std::fs::write(format!("{dir}/public-cases.json"), serde_json::to_string_pretty(&doc).unwrap())
        .unwrap();
}
