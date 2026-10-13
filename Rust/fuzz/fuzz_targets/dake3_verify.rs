// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
//! verify_dake3 against a recorded genuine handshake: never panics, and no
//! DAKE3 other than the recorded one verifies over that transcript.
#![no_main]
use libfuzzer_sys::fuzz_target;
use otrv4_core::dake::verify_dake3;
use std::sync::OnceLock;

struct Fixture { t: Vec<u8>, d3: Vec<u8>, i: [u8; 57], r: [u8; 57], m: Vec<u8> }

fn field(src: &str, name: &str) -> Vec<u8> {
    let key = format!("\"{}\": \"", name);
    let start = src.find(&key).expect("field") + key.len();
    let end = start + src[start..].find('"').expect("end");
    (0..(end - start) / 2)
        .map(|k| u8::from_str_radix(&src[start + 2 * k..start + 2 * k + 2], 16).expect("hex"))
        .collect()
}

fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        let src = include_str!("../../../tests/fixtures/dake_recorded_v1.json");
        let mut t = field(src, "dake1");
        t.extend_from_slice(&field(src, "dake2"));
        Fixture {
            t,
            d3: field(src, "dake3"),
            i: field(src, "initiator_identity_pub").try_into().expect("57"),
            r: field(src, "responder_identity_pub").try_into().expect("57"),
            m: field(src, "initiator_mldsa_pub"),
        }
    })
}

fuzz_target!(|data: &[u8]| {
    let f = fixture();
    // Mutate the genuine DAKE3 by XOR, so the fuzzer explores near-misses
    // as well as garbage.
    let mut d3 = f.d3.clone();
    if data.len() > d3.len() { d3 = data.to_vec(); }
    else { for (k, b) in data.iter().enumerate() { d3[k] ^= b; } }
    if let Ok(true) = verify_dake3(&f.t, &d3, &f.i, &f.r, Some(&f.m)) {
        assert_eq!(d3, f.d3, "a DAKE3 other than the recorded one verified");
    }
});
