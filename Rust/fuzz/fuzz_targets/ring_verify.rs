// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
//! ring_verify_bytes on arbitrary keys, message and signature: never panics,
//! and with honest keys only the genuine signature verifies.
#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use otrv4_core::ring_sig::{ring_sign_bytes, ring_verify_bytes};

#[derive(Arbitrary, Debug)]
struct In { a1: Vec<u8>, a2: Vec<u8>, msg: Vec<u8>, sig: Vec<u8>, flip: Vec<(u8, u8)> }

fuzz_target!(|x: In| {
    let _ = ring_verify_bytes(&x.a1, &x.a2, &x.msg, &x.sig);
    let _ = ring_sign_bytes(&[0x11; 57], &x.a1, &x.a2, &x.msg);
    // Honest ring: public keys from the verify_dake3 fixture would do, but
    // any sign/verify pair works. Flip bytes of a genuine signature.
    use std::sync::OnceLock;
    static KEYS: OnceLock<([u8; 57], [u8; 57])> = OnceLock::new();
    let (a1, a2) = KEYS.get_or_init(|| {
        let pk = |seed: [u8; 57]| {
            use otrv4_core::ring_sig::public_key_from_seed;
            public_key_from_seed(&seed)
        };
        (pk([0x11; 57]), pk([0x22; 57]))
    });
    let sig = ring_sign_bytes(&[0x11; 57], a1, a2, &x.msg).expect("honest ring");
    assert!(ring_verify_bytes(a1, a2, &x.msg, &sig));
    let mut bad = sig;
    let mut changed = false;
    for (pos, v) in x.flip.iter().take(8) {
        let p = *pos as usize * 228 / 256;
        if *v != 0 { bad[p] ^= v; changed = true; }
    }
    if changed && bad != sig {
        assert!(!ring_verify_bytes(a1, a2, &x.msg, &bad), "a modified signature verified");
    }
});
