// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
//! FIPS 204 conformance of the prototype's three primitive paths, against
//! NIST's ACVP vectors (vectors/acvp-mldsa87.json; regenerate and compare
//! with vectors/extract_acvp.py, which pins the ACVP-Server commit and the
//! SHA-256 of each source file).
//!
//! * `key_from_release_seed` is ML-DSA-87 KeyGen_internal: a release, 32
//!   bytes, rebuilds exactly the key any conforming implementation would.
//! * `fips204_sign` is ML-DSA-87 Sign, hedged, pure, with a context: the
//!   path every holder's and every forger's signature goes through.
//! * `fips204_verify` accepts NIST's valid signatures and rejects each of
//!   its modified ones.
//!
//! The same vectors also run through PQClean (an implementation that shares
//! no code with RustCrypto's), so the independent verifier used in
//! tests/proofs.rs is itself shown to agree with NIST.

#![allow(deprecated)] // ACVP sigGen gives expanded secret keys, not seeds.

use epochal_mldsa::*;
use ml_dsa::{ExpandedSigningKey, MlDsa87, VerifyingKey};
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};
use serde_json::Value;
use sha3::{Digest, Sha3_256};

fn vectors() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/vectors/acvp-mldsa87.json");
    serde_json::from_str(&std::fs::read_to_string(path).expect("vectors")).expect("json")
}

fn bytes(t: &Value, k: &str) -> Vec<u8> {
    hex::decode(t[k].as_str().unwrap_or_else(|| panic!("{k}"))).expect("hex")
}

fn sha3_hex(b: &[u8]) -> String {
    hex::encode(Sha3_256::digest(b)).to_uppercase()
}

fn tests<'a>(v: &'a Value, kind: &str) -> &'a Vec<Value> {
    v[kind]["tests"].as_array().unwrap()
}

fn vk(pk: &[u8]) -> VerifyingKey<MlDsa87> {
    VerifyingKey::<MlDsa87>::decode(pk.try_into().expect("ML-DSA-87 pk is 2592 bytes"))
}

#[test]
fn the_vectors_are_the_pinned_nist_ones() {
    let v = vectors();
    assert_eq!(v["source"]["repository"], "https://github.com/usnistgov/ACVP-Server");
    assert_eq!(v["source"]["commit"], "975de31eb83d87039ec88934fdc47d8c312b892d");
    assert_eq!(tests(&v, "keyGen").len(), 25);
    assert_eq!(tests(&v, "sigGen").len(), 15);
    assert_eq!(tests(&v, "sigVer").len(), 15);
}

#[test]
fn acvp_keygen_a_release_seed_rebuilds_the_fips_204_key() {
    let v = vectors();
    for t in tests(&v, "keyGen") {
        let seed: [u8; 32] = bytes(t, "seed").try_into().unwrap();
        let sk = key_from_release_seed(&seed);
        let tc = &t["tcId"];
        assert_eq!(sha3_hex(&sk.verifying_key().encode()), t["pk_sha3"].as_str().unwrap().to_uppercase(),
                   "keyGen tcId {tc}: public key");
        assert_eq!(sha3_hex(&sk.to_expanded()), t["sk_sha3"].as_str().unwrap().to_uppercase(),
                   "keyGen tcId {tc}: secret key");
    }
}

#[test]
fn acvp_siggen_the_signing_path_is_fips_204_hedged_with_context() {
    let v = vectors();
    for t in tests(&v, "sigGen") {
        let skb = bytes(t, "sk");
        let sk = ExpandedSigningKey::<MlDsa87>::from_expanded(skb.as_slice().try_into().unwrap());
        let rnd: [u8; 32] = bytes(t, "rnd").try_into().unwrap();
        let sig = fips204_sign(&sk, &bytes(t, "context"), &bytes(t, "message"), &rnd);
        assert_eq!(sha3_hex(&sig), t["signature_sha3"].as_str().unwrap().to_uppercase(),
                   "sigGen tcId {}", t["tcId"]);
    }
}

#[test]
fn acvp_sigver_the_verification_path_accepts_and_rejects_as_nist_says() {
    let v = vectors();
    let (mut valid, mut invalid) = (0, 0);
    for t in tests(&v, "sigVer") {
        let expected = t["testPassed"].as_bool().unwrap();
        let got = fips204_verify(&vk(&bytes(t, "pk")), &bytes(t, "context"), &bytes(t, "message"),
                                 &bytes(t, "signature"));
        assert_eq!(got, expected, "sigVer tcId {} ({})", t["tcId"], t["reason"]);
        if expected { valid += 1 } else { invalid += 1 }
    }
    assert!(valid >= 3 && invalid >= 9, "both outcomes covered: {valid} valid, {invalid} modified");
}

#[test]
fn acvp_sigver_pqclean_the_independent_verifier_agrees_with_nist() {
    use pqcrypto_mldsa::mldsa87;
    let v = vectors();
    for t in tests(&v, "sigVer") {
        let pk = mldsa87::PublicKey::from_bytes(&bytes(t, "pk")).unwrap();
        let got = match mldsa87::DetachedSignature::from_bytes(&bytes(t, "signature")) {
            Ok(sig) => mldsa87::verify_detached_signature_ctx(&sig, &bytes(t, "message"),
                                                              &bytes(t, "context"), &pk).is_ok(),
            Err(_) => false,
        };
        assert_eq!(got, t["testPassed"].as_bool().unwrap(), "PQClean, sigVer tcId {}", t["tcId"]);
    }
}
