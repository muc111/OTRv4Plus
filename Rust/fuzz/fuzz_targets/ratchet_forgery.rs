// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
//! The ratchet's commit discipline under attack.
//!
//! An attacker-built message (header, ciphertext, nonce, tag all fuzzed) is
//! offered to both receive paths. Whatever happens to it, the genuine
//! message sent afterwards must still decrypt: no unauthenticated input may
//! advance, desynchronise or poison the receive state.
#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use otrv4_core::ratchet::DoubleRatchet;

#[derive(Arbitrary, Debug)]
struct Forgery {
    header: Vec<u8>,
    ciphertext: Vec<u8>,
    nonce: [u8; 12],
    tag: [u8; 16],
    new_dh: bool,
    replay_genuine_first: bool,
}

fn pair() -> (DoubleRatchet, DoubleRatchet) {
    let a = DoubleRatchet::new(&[0x11; 32], &[0x22; 32], &[0x33; 32], &[0x44; 32], &[0xAA; 56], true)
        .expect("alice");
    let b = DoubleRatchet::new(&[0x11; 32], &[0x22; 32], &[0x33; 32], &[0x44; 32], &[0xBB; 56], false)
        .expect("bob");
    (a, b)
}

fuzz_target!(|f: Forgery| {
    if f.header.len() > 4096 || f.ciphertext.len() > 4096 { return; }
    let (mut alice, mut bob) = pair();
    let first = alice.encrypt(b"first").expect("encrypt");
    if f.replay_genuine_first {
        bob.decrypt_same_dh(&first.header, &first.ciphertext, &first.nonce, &first.tag)
            .expect("genuine first message");
    }
    let forged = if f.new_dh {
        bob.decrypt_new_dh(&f.header, &f.ciphertext, &f.nonce, &f.tag,
                           &[0x55; 56], &[0x66; 56], &[0xCC; 56])
    } else {
        bob.decrypt_same_dh(&f.header, &f.ciphertext, &f.nonce, &f.tag)
    };
    // A forgery cannot authenticate without the key; a hit here is a bug.
    if let Ok(r) = forged {
        assert!(f.header == first.header && f.ciphertext == first.ciphertext
                && f.nonce == first.nonce && f.tag == first.tag && !f.replay_genuine_first,
                "unauthenticated input decrypted: {:?}", r.plaintext);
        return;
    }
    if !f.replay_genuine_first {
        bob.decrypt_same_dh(&first.header, &first.ciphertext, &first.nonce, &first.tag)
            .expect("forgery poisoned the first genuine message");
    }
    let second = alice.encrypt(b"second").expect("encrypt");
    let pt = bob.decrypt_same_dh(&second.header, &second.ciphertext, &second.nonce, &second.tag)
        .expect("forgery desynchronised the receive chain");
    assert_eq!(pt.plaintext, b"second");
});
