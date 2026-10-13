// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
//! SMP messages from the network, at every step.
//!
//! Step 1 (responder): fuzzed SMP1. Steps 2-4: a genuine run is driven up
//! to the step under test and the fuzzed bytes replace the peer's message.
//! Never panics; a fuzzed message never produces "verified".
//! The secret is set with the fuzz-only helper (no Argon2id per run).
#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use otrv4_core::smp::SmpState;

#[derive(Arbitrary, Debug)]
struct In { step: u8, classical: bool, msg: Vec<u8> }

fn state(init: bool, v: u8) -> SmpState {
    let mut s = SmpState::new(init);
    s.fuzz_set_secret_scalar(v);
    s
}

fuzz_target!(|x: In| {
    if x.msg.len() > 64 * 1024 { return; }
    // 0x01 classical keeps runs fast; 0x03 exercises the ML-DSA/ML-KEM layer.
    let v = if x.classical { 0x01 } else { 0x03 };
    let mut a = state(true, v);
    let mut b = state(false, v);
    match x.step % 4 {
        0 => { let _ = b.process_smp1_generate_smp2(&x.msg); }
        1 => {
            let Ok(_m1) = a.generate_smp1(None) else { return };
            let _ = a.process_smp2_generate_smp3(&x.msg);
            assert!(!a.is_verified());
        }
        2 => {
            let Ok(m1) = a.generate_smp1(None) else { return };
            let Ok(_m2) = b.process_smp1_generate_smp2(&m1) else { return };
            let _ = b.process_smp3_generate_smp4(&x.msg);
            assert!(!b.is_verified(), "fuzzed SMP3 verified");
        }
        _ => {
            let Ok(m1) = a.generate_smp1(None) else { return };
            let Ok(m2) = b.process_smp1_generate_smp2(&m1) else { return };
            let Ok(_m3) = a.process_smp2_generate_smp3(&m2) else { return };
            if let Ok(true) = a.process_smp4(&x.msg) { panic!("fuzzed SMP4 verified"); }
        }
    }
});
