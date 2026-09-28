// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
//! DAKE1 is unauthenticated: anyone can send one. process_dake1 must never
//! panic, and must refuse anything whose profile does not verify.
#![no_main]
use libfuzzer_sys::fuzz_target;
use otrv4_core::dake::DakeState;

fuzz_target!(|data: &[u8]| {
    if data.len() > 16 * 1024 { return; }
    let mut s = match DakeState::new(&[7u8; 57], &[8u8; 57], &[9u8; 56], &[10u8; 56], None, None, 1) {
        Ok(s) => s,
        Err(_) => return,
    };
    let _ = s.process_dake1(data);
});
