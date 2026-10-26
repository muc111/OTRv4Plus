// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
//! C1-C3 and the binding as properties over generated cases, not single
//! examples: any chain seed, any number of epochs, any set of releases, any
//! message. Reproducible: the generator seed is fixed (override with
//! EPOCHAL_PROPTEST_SEED) and the case count is EPOCHAL_PROPTEST_CASES
//! (default 256 per property).

use epochal_mldsa::*;
use proptest::prelude::*;
use proptest::test_runner::{Config, RngSeed};

const ALICE: &[u8] = b"alice@example.test";

fn config() -> Config {
    let env = |k: &str, d: u64| std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d);
    Config {
        cases: env("EPOCHAL_PROPTEST_CASES", 256) as u32,
        rng_seed: RngSeed::Fixed(env("EPOCHAL_PROPTEST_SEED", 0x0E70_C4A1)),
        failure_persistence: None,
        ..Config::default()
    }
}

fn epoch(group: &[u8], n: u64, salt: u8) -> GroupEpoch {
    let mut auth = [salt; 32];
    auth[..8].copy_from_slice(&n.to_be_bytes());
    GroupEpoch { group_id: group.to_vec(), epoch_id: n, authenticator: auth }
}

struct World {
    signer: EpochSigner,
    pks: Vec<PublicKey>,
    groups: Vec<GroupEpoch>,
    board: ReleaseBoard,
}

/// Keys for epochs first..first+k (k+1 of them, so epochs up to first+k-1
/// are closed), and the given closed epochs released.
fn world(seed: [u8; 32], first: u64, k: u64, released: &[bool], salt: u8) -> World {
    let group = b"room@conference.example.test";
    let mut signer = EpochSigner::new(ALICE, seed, first);
    let groups: Vec<_> = (first..=first + k).map(|n| epoch(group, n, salt)).collect();
    let pks = groups.iter().map(|g| signer.epoch_keygen(g.epoch_id, g).unwrap()).collect();
    let mut board = ReleaseBoard::default();
    for (i, r) in released.iter().enumerate().take(k as usize) {
        if *r {
            board.publish(signer.release_epoch_key(first + i as u64).unwrap());
        }
    }
    World { signer, pks, groups, board }
}

proptest! {
    #![proptest_config(config())]

    /// C2 + C3: a release forges its own epoch and no other. For every pair
    /// (released epoch r, target epoch t), the forgery verifies under pk_t
    /// exactly when r == t.
    #[test]
    fn a_release_forges_exactly_its_own_epoch(
        seed in any::<[u8; 32]>(), first in 1u64..1_000_000, k in 2u64..7,
        released in proptest::collection::vec(any::<bool>(), 6), salt in any::<u8>(),
        msg in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        let w = world(seed, first, k, &released, salt);
        for r in first..first + k {
            if !w.board.is_released(ALICE, r) {
                prop_assert!(w.board.forge_with_released_key(ALICE, r, &msg).is_none());
                continue;
            }
            for t in first..=first + k {
                let i = (t - first) as usize;
                let forged = w.board.forge_across(ALICE, r, t, &msg).unwrap();
                prop_assert_eq!(verify_bound(&w.pks[i], &w.groups[i], &msg, &forged), r == t,
                                "release {} forging {}", r, t);
            }
        }
    }

    /// C1: an unreleased epoch's key still authenticates the holder, and
    /// the receiver rule refuses exactly the released epochs.
    #[test]
    fn unreleased_epochs_stay_authentic_released_ones_are_refused(
        seed in any::<[u8; 32]>(), k in 2u64..7,
        released in proptest::collection::vec(any::<bool>(), 6),
        msg in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        let mut w = world(seed, 1, k, &[false; 6], 0xA7);
        let sigs: Vec<_> = (1..=k + 1).map(|n| sign(w.signer.signing_key(n).unwrap(), &msg)).collect();
        for (i, r) in released.iter().enumerate().take(k as usize) {
            if *r {
                w.board.publish(w.signer.release_epoch_key(i as u64 + 1).unwrap());
            }
        }
        for n in 1..=k + 1 {
            let i = (n - 1) as usize;
            prop_assert!(verify_bound(&w.pks[i], &w.groups[i], &msg, &sigs[i]));
            prop_assert_eq!(verify_unreleased(&w.board, &w.pks[i], &w.groups[i], &msg, &sigs[i]),
                            !w.board.is_released(ALICE, n));
            prop_assert_eq!(w.signer.signing_key(n).is_none(), w.board.is_released(ALICE, n),
                            "erased exactly when released");
        }
    }

    /// Only a closed epoch can be released: the current and every later one
    /// are refused, whatever the history.
    #[test]
    fn only_closed_epochs_are_releasable(first in 1u64..1_000_000, k in 1u64..7, ask in 0u64..10) {
        let mut w = world([1; 32], first, k, &[false; 6], 0);
        let target = first + ask;
        let res = w.signer.release_epoch_key(target);
        if ask < k {
            prop_assert!(res.is_ok());
        } else {
            prop_assert_eq!(res.err(), Some(ReleaseError::NotClosed));
        }
    }

    /// Any change to any bound field breaks the binding.
    #[test]
    fn any_tampered_binding_field_fails(
        seed in any::<[u8; 32]>(), field in 0usize..6, pos in 0usize..32, bit in 0u8..8,
    ) {
        let w = world(seed, 1, 2, &[false; 6], 0x33);
        let (mut pk, mut g) = (w.pks[0].clone(), w.groups[0].clone());
        prop_assert!(verify_group_binding(&pk, &g));
        match field {
            0 => g.authenticator[pos] ^= 1 << bit,
            1 => pk.binding[pos] ^= 1 << bit,
            2 => pk.group_hash[pos] ^= 1 << bit,
            3 => { pk.member = b"bob@example.test".to_vec(); }
            4 => { pk.vk = w.pks[1].vk.clone(); }
            _ => { g.group_id.push(b'x'); }
        }
        prop_assert!(!verify_group_binding(&pk, &g));
    }

    /// Any single bit flipped anywhere in a signature, and any truncation or
    /// extension, is rejected without a panic.
    #[test]
    fn mangled_signatures_are_rejected(
        seed in any::<[u8; 32]>(), pos in any::<prop::sample::Index>(), bit in 0u8..8,
        cut in any::<prop::sample::Index>(), extra in proptest::collection::vec(any::<u8>(), 1..64),
        msg in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        let w = world(seed, 1, 1, &[false; 6], 0x44);
        let sig = sign(w.signer.signing_key(1).unwrap(), &msg);
        prop_assert!(verify(&w.pks[0], &msg, &sig));
        let mut flipped = sig.clone();
        let i = pos.index(flipped.bytes.len());
        flipped.bytes[i] ^= 1 << bit;
        prop_assert!(!verify(&w.pks[0], &msg, &flipped), "bit {} of byte {}", bit, i);
        let mut short = sig.clone();
        short.bytes.truncate(cut.index(sig.bytes.len()));
        prop_assert!(!verify(&w.pks[0], &msg, &short));
        let mut long = sig.clone();
        long.bytes.extend_from_slice(&extra);
        prop_assert!(!verify(&w.pks[0], &msg, &long));
    }

    /// Two chain seeds, or two groups, never yield the same key.
    #[test]
    fn keys_are_unlinkable_across_chains_and_groups(a in any::<[u8; 32]>(), b in any::<[u8; 32]>()) {
        prop_assume!(a != b);
        let g1 = epoch(b"one@conference.example.test", 1, 0);
        let g2 = epoch(b"two@conference.example.test", 1, 0);
        let k = |s: [u8; 32], g: &GroupEpoch| {
            EpochSigner::new(ALICE, s, 1).epoch_keygen(1, g).unwrap().vk.encode().to_vec()
        };
        prop_assert_ne!(k(a, &g1), k(b, &g1));
        prop_assert_ne!(k(a, &g1), k(a, &g2));
    }
}
