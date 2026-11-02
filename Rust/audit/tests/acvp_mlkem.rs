// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
//! FIPS 203 conformance of the SHIPPING ML-KEM-1024 (the `ml-kem` crate at the
//! version Rust/Cargo.lock pins; tests/version_parity.rs holds the versions
//! together) against NIST's ACVP vectors: vectors/acvp-mlkem1024.json,
//! regenerated and compared with vectors/extract_acvp.py, which pins the
//! ACVP-Server commit and the SHA-256 of each source file.
//!
//! Each test makes the same crate calls the shipping wrappers make
//! (src/mlkem.rs, mls/src/mlkem.rs):
//! * keyGen:   `DecapsulationKey::from_seed(d || z)`, then the 1568-byte
//!   `encapsulation_key().to_bytes()` and the 3168-byte expanded
//!   `to_expanded_bytes()` -- the encoding shipping stores and sends.
//! * encaps:   `EncapsulationKey::new(ek)` (FIPS 203 s7.2 modulus check),
//!   then `encapsulate_deterministic(m)`.
//! * decaps:   `from_expanded_bytes(dk)` (s7.3 hash check), then
//!   `decapsulate(c)`, including NIST's modified ciphertexts (implicit
//!   rejection).
//! * key checks: the two constructors accept exactly NIST's valid keys.

#![allow(deprecated)] // the expanded dk form is deprecated upstream; shipping uses it.

use ml_kem::array::Array;
use ml_kem::{
    Ciphertext, Decapsulate, DecapsulationKey, EncapsulationKey, ExpandedKeyEncoding, KeyExport,
    MlKem1024,
};
use serde_json::Value;
use sha3::{Digest, Sha3_256};

fn vectors() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/vectors/acvp-mlkem1024.json");
    serde_json::from_str(&std::fs::read_to_string(path).expect("vectors")).expect("json")
}

fn bytes(t: &Value, k: &str) -> Vec<u8> {
    hex::decode(t[k].as_str().unwrap_or_else(|| panic!("{k}"))).expect("hex")
}

fn sha3_hex(b: &[u8]) -> String {
    hex::encode(Sha3_256::digest(b))
}

fn tests<'a>(v: &'a Value, kind: &str) -> &'a Vec<Value> {
    v[kind]["tests"].as_array().unwrap()
}

fn tc(t: &Value) -> u64 {
    t["tcId"].as_u64().unwrap()
}

/// Every case is checked; the failures are reported together by tcId.
fn check_all(v: &Value, kind: &str, f: impl Fn(&Value) -> bool) -> usize {
    let cases = tests(v, kind);
    let failed: Vec<u64> = cases.iter().filter(|t| !f(t)).map(tc).collect();
    assert!(failed.is_empty(), "ACVP ML-KEM-1024 {kind}: failing tcIds {failed:?}");
    cases.len()
}

fn ek_of(b: &[u8]) -> Option<EncapsulationKey<MlKem1024>> {
    EncapsulationKey::<MlKem1024>::new(&Array::try_from(b).ok()?).ok()
}

fn dk_of(b: &[u8]) -> Option<DecapsulationKey<MlKem1024>> {
    DecapsulationKey::<MlKem1024>::from_expanded_bytes(&Array::try_from(b).ok()?).ok()
}

#[test]
fn the_vectors_are_the_pinned_nist_ones() {
    let v = vectors();
    assert_eq!(v["source"]["repository"], "https://github.com/usnistgov/ACVP-Server");
    assert_eq!(v["source"]["commit"], "975de31eb83d87039ec88934fdc47d8c312b892d");
    let files = v["source"]["files"].as_object().unwrap();
    assert_eq!(
        files["ML-KEM-keyGen-FIPS203/internalProjection.json"],
        "d7a62a2c3476957f56dd8d24f9004ea6776ccfe995ffe71a65bb9506dc9c7b1b"
    );
    assert_eq!(
        files["ML-KEM-encapDecap-FIPS203/internalProjection.json"],
        "a556952ce869bb89c3a3196a701dad89647c193a34c86eafb61a9d710d5b810f"
    );
    for (kind, n) in [
        ("keyGen", 25),
        ("encapsulation", 25),
        ("decapsulation", 10),
        ("encapsulationKeyCheck", 10),
        ("decapsulationKeyCheck", 10),
    ] {
        assert_eq!(tests(&v, kind).len(), n, "{kind}");
    }
}

#[test]
fn acvp_keygen_the_seed_rebuilds_the_fips_203_keys() {
    let v = vectors();
    let n = check_all(&v, "keyGen", |t| {
        let mut seed = bytes(t, "d");
        seed.extend_from_slice(&bytes(t, "z"));
        let dk = DecapsulationKey::<MlKem1024>::from_seed(Array::try_from(&seed[..]).unwrap());
        sha3_hex(dk.encapsulation_key().to_bytes().as_slice()) == t["ek_sha3"]
            && sha3_hex(dk.to_expanded_bytes().as_slice()) == t["dk_sha3"]
    });
    assert_eq!(n, 25);
}

#[test]
fn acvp_encapsulation_with_nists_m_gives_nists_c_and_k() {
    let v = vectors();
    let n = check_all(&v, "encapsulation", |t| {
        let Some(ek) = ek_of(&bytes(t, "ek")) else { return false };
        let m: [u8; 32] = bytes(t, "m").try_into().unwrap();
        let (c, k) = ek.encapsulate_deterministic(&Array::from(m));
        sha3_hex(c.as_slice()) == t["c_sha3"] && k.as_slice() == bytes(t, "k")
    });
    assert_eq!(n, 25);
}

#[test]
fn acvp_decapsulation_recovers_k_and_implicitly_rejects() {
    let v = vectors();
    let n = check_all(&v, "decapsulation", |t| {
        let Some(dk) = dk_of(&bytes(t, "dk")) else { return false };
        let c = Ciphertext::<MlKem1024>::try_from(&bytes(t, "c")[..]).unwrap();
        dk.decapsulate(&c).as_slice() == bytes(t, "k")
    });
    assert_eq!(n, 10);
    // Both kinds are present: genuine ciphertexts and ones NIST modified.
    let reasons: Vec<&str> =
        tests(&v, "decapsulation").iter().map(|t| t["reason"].as_str().unwrap()).collect();
    assert_eq!(reasons.iter().filter(|r| **r == "valid decapsulation").count(), 5, "{reasons:?}");
    assert_eq!(reasons.iter().filter(|r| **r == "modified ciphertext").count(), 5, "{reasons:?}");
}

#[test]
fn acvp_encapsulation_key_check_accepts_exactly_the_valid_keys() {
    let v = vectors();
    let n = check_all(&v, "encapsulationKeyCheck", |t| {
        ek_of(&bytes(t, "ek")).is_some() == t["testPassed"].as_bool().unwrap()
    });
    assert_eq!(n, 10);
    let c = tests(&v, "encapsulationKeyCheck");
    assert!(c.iter().any(|t| t["testPassed"] == true) && c.iter().any(|t| t["testPassed"] == false));
}

#[test]
fn acvp_decapsulation_key_check_accepts_exactly_the_valid_keys() {
    let v = vectors();
    let n = check_all(&v, "decapsulationKeyCheck", |t| {
        dk_of(&bytes(t, "dk")).is_some() == t["testPassed"].as_bool().unwrap()
    });
    assert_eq!(n, 10);
    let c = tests(&v, "decapsulationKeyCheck");
    assert!(c.iter().any(|t| t["testPassed"] == true) && c.iter().any(|t| t["testPassed"] == false));
}
