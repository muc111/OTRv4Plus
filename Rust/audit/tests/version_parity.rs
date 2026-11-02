// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
//! The ACVP tests (acvp_mlkem.rs, acvp_mldsa.rs) are only evidence about the
//! shipped code if they run against the version that ships. This crate has
//! its own lockfile, so a bump of the core's or MLS's `ml-kem` / `ml-dsa`
//! that skips this one would leave the vectors silently testing the old
//! version. Each lockfile must hold exactly one version of each, and all
//! three must agree.

use std::path::Path;

/// Every version of `name` locked in `lock`.
fn locked(lock: &str, name: &str) -> Vec<String> {
    let text = std::fs::read_to_string(lock).unwrap_or_else(|e| panic!("{lock}: {e}"));
    let mut out = Vec::new();
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        if line.trim() == format!("name = \"{name}\"") {
            let v = lines.next().expect("version line").trim();
            let v = v.strip_prefix("version = \"").and_then(|v| v.strip_suffix('"'));
            out.push(v.unwrap_or_else(|| panic!("{lock}: no version after {name}")).to_string());
        }
    }
    out
}

#[test]
fn audit_tests_the_ml_kem_and_ml_dsa_that_ship() {
    let audit = env!("CARGO_MANIFEST_DIR");
    let locks = [
        ("core (shipped)", Path::new(audit).join("../Cargo.lock")),
        ("mls (shipped)", Path::new(audit).join("../mls/Cargo.lock")),
        ("audit (tests)", Path::new(audit).join("Cargo.lock")),
    ];
    for name in ["ml-kem", "ml-dsa"] {
        let found: Vec<(&str, Vec<String>)> = locks
            .iter()
            .map(|(who, p)| (*who, locked(p.to_str().unwrap(), name)))
            .collect();
        for (who, vs) in &found {
            assert_eq!(vs.len(), 1, "{who} locks {name} {vs:?}: expected exactly one version");
        }
        let first = &found[0].1[0];
        assert!(
            found.iter().all(|(_, vs)| &vs[0] == first),
            "{name} versions differ across lockfiles: {found:?}"
        );
    }
}
