// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
//! FIPS 204 conformance of the SHIPPING ML-DSA-87 (the `ml-dsa` crate at the
//! version Rust/Cargo.lock pins; tests/version_parity.rs holds the versions
//! together) against NIST's ACVP vectors: vectors/acvp-mldsa87.json,
//! regenerated and compared with vectors/extract_acvp.py.
//!
//! Each test makes the same crate calls the shipping wrappers make
//! (src/mldsa.rs, mls/src/provider.rs):
//! * keyGen: `ExpandedSigningKey::from_seed(xi)`, then the 2592-byte
//!   `verifying_key().encode()` and the 4896-byte expanded `to_expanded()`.
//! * sigGen: `from_expanded(sk)`, then `sign_deterministic(M, ctx)` -- the
//!   DETERMINISTIC, external, pure group, which is how shipping signs.
//!   Shipping always passes an empty FIPS 204 context; NIST's group has two
//!   empty-context cases among contexts up to 255 bytes, and both are run.
//! * sigVer: `VerifyingKey::decode(pk)`, `Signature::try_from(sig)`, then
//!   `verify_with_context(M, ctx, sig)`: NIST's valid signatures verify and
//!   each of its modified ones (message, commitment, hint, z) is refused.

#![allow(deprecated)] // the expanded sk form is deprecated upstream; shipping uses it.

use ml_dsa::{EncodedVerifyingKey, ExpandedSigningKey, MlDsa87, Signature, VerifyingKey, B32};
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
    assert!(failed.is_empty(), "ACVP ML-DSA-87 {kind}: failing tcIds {failed:?}");
    cases.len()
}

#[test]
fn the_vectors_are_the_pinned_nist_ones() {
    let v = vectors();
    assert_eq!(v["source"]["repository"], "https://github.com/usnistgov/ACVP-Server");
    assert_eq!(v["source"]["commit"], "975de31eb83d87039ec88934fdc47d8c312b892d");
    let files = v["source"]["files"].as_object().unwrap();
    for (f, h) in [
        ("ML-DSA-keyGen-FIPS204", "e67ee6540d40e11506c3c4e3b1f79fc1cefcd49820db99fc61f87cc8ba463baf"),
        ("ML-DSA-sigGen-FIPS204", "72dcaf5f69853ca267ccd16af9cb40949786aca0fcfbf05d1ebeba132b93af22"),
        ("ML-DSA-sigVer-FIPS204", "47cdd6314c7f746d02421ffcba89d4dbc7bb875ac49e07a029fdfc26fba55437"),
    ] {
        assert_eq!(files[&format!("{f}/internalProjection.json")], h, "{f}");
    }
    assert_eq!(tests(&v, "keyGen").len(), 25);
    assert_eq!(tests(&v, "sigGen").len(), 15);
    assert_eq!(tests(&v, "sigVer").len(), 15);
}

#[test]
fn acvp_keygen_the_seed_rebuilds_the_fips_204_keys() {
    let v = vectors();
    let n = check_all(&v, "keyGen", |t| {
        let xi: [u8; 32] = bytes(t, "seed").try_into().unwrap();
        let seed: B32 = xi.into();
        let esk = ExpandedSigningKey::<MlDsa87>::from_seed(&seed);
        sha3_hex(esk.verifying_key().encode().as_slice()) == t["pk_sha3"]
            && sha3_hex(esk.to_expanded().as_slice()) == t["sk_sha3"]
    });
    assert_eq!(n, 25);
}

#[test]
fn acvp_siggen_deterministic_signing_gives_nists_signature() {
    let v = vectors();
    let n = check_all(&v, "sigGen", |t| {
        let sk = bytes(t, "sk");
        let esk = ExpandedSigningKey::<MlDsa87>::from_expanded(&sk[..].try_into().unwrap());
        match esk.sign_deterministic(&bytes(t, "message"), &bytes(t, "context")) {
            Ok(sig) => sha3_hex(sig.encode().as_slice()) == t["signature_sha3"],
            Err(_) => false,
        }
    });
    assert_eq!(n, 15);
    // The empty context, which is the only one shipping uses, is among them.
    let empty = tests(&v, "sigGen").iter().filter(|t| t["context"] == "").count();
    assert!(empty >= 1, "no empty-context sigGen case");
}

#[test]
fn acvp_sigver_accepts_nists_valid_signatures_and_refuses_each_modified_one() {
    let v = vectors();
    let n = check_all(&v, "sigVer", |t| {
        let enc: EncodedVerifyingKey<MlDsa87> = bytes(t, "pk")[..].try_into().unwrap();
        let vk = VerifyingKey::<MlDsa87>::decode(&enc);
        let ok = match Signature::<MlDsa87>::try_from(&bytes(t, "signature")[..]) {
            Ok(sig) => vk.verify_with_context(&bytes(t, "message"), &bytes(t, "context"), &sig),
            Err(_) => false,
        };
        ok == t["testPassed"].as_bool().unwrap()
    });
    assert_eq!(n, 15);
    let c = tests(&v, "sigVer");
    assert_eq!(c.iter().filter(|t| t["testPassed"] == true).count(), 3);
    assert_eq!(c.iter().filter(|t| t["testPassed"] == false).count(), 12);
}
