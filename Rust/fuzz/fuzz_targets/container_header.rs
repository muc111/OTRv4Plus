// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
//! .otrv containers from outside (imports, synced files): `info` and
//! `open_bytes` on arbitrary files never panic, never allocate from the
//! unauthenticated length, and never open without the key.
#![no_main]
use libfuzzer_sys::fuzz_target;
use otrv4_core::container::{info, open_bytes, KeySource};

fuzz_target!(|data: &[u8]| {
    let dir = std::env::temp_dir().join(format!("otrv-fuzz-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let p = dir.join("in.otrv");
    if std::fs::write(&p, data).is_err() { return; }
    let _ = info(&p);
    let r = open_bytes(&p, &KeySource::Device(&[0x5a; 32]), 1 << 20);
    assert!(r.is_err() || data.len() >= 56 + 16, "opened a container shorter than header+tag");
});
