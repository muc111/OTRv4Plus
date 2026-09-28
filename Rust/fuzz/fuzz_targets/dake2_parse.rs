// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
//! DAKE2 reaches the initiator from the network after its DAKE1. It must
//! never panic, and an arbitrary DAKE2 must never yield session keys: the
//! MAC is keyed from secrets the fuzzer cannot know.
#![no_main]
use libfuzzer_sys::fuzz_target;
use otrv4_core::dake::DakeState;

fuzz_target!(|data: &[u8]| {
    if data.len() > 16 * 1024 { return; }
    let mut s = match DakeState::new(&[7u8; 57], &[8u8; 57], &[9u8; 56], &[10u8; 56], None, None, 1) {
        Ok(s) => s,
        Err(_) => return,
    };
    if s.generate_dake1(&[0u8; 8], None).is_err() { return; }
    assert!(s.process_dake2(data, None).is_err(), "an arbitrary DAKE2 established a session");
});
