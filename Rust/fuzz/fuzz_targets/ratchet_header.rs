// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
//! RatchetHeader::decode on arbitrary bytes: never panics, and anything it
//! accepts re-encodes to the same first 64 bytes.
#![no_main]
use libfuzzer_sys::fuzz_target;
use otrv4_core::header::RatchetHeader;

fuzz_target!(|data: &[u8]| {
    if let Ok(h) = RatchetHeader::decode(data) {
        let enc = h.encode();
        assert_eq!(&enc[..], &data[..enc.len()], "decode/encode disagree");
    }
    let _ = RatchetHeader::peek_dh_pub(data);
});
