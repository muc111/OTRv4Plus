// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
//! dudect-style timing checks (Reparaz, Balasch, Verbauwhede 2017).
//!
//! Two input classes -- one fixed, one random -- are timed interleaved in a
//! random order, the upper tail is cropped, and Welch's t is computed. |t|
//! above ~4.5 suggests a data-dependent timing difference; above 10 it is
//! near certain. The harness proves its own sensitivity first with a
//! comparison that exits early (it must show a leak), so a quiet result on
//! the real primitives means something.
//!
//! Statistical, and noisy on a shared machine, so every test is #[ignore]:
//!
//!   cd Rust/audit && cargo test --release --test timing_dudect -- --ignored --nocapture --test-threads=1
//!
//! A clean run is evidence, not proof, of constant time; see the report.
use rand::{Rng, RngCore};
use std::hint::black_box;
use std::time::Instant;

const N: usize = 200_000;

fn welch_t(a: &[f64], b: &[f64]) -> f64 {
    let m = |v: &[f64]| v.iter().sum::<f64>() / v.len() as f64;
    let var = |v: &[f64], mu: f64| v.iter().map(|x| (x - mu).powi(2)).sum::<f64>() / (v.len() - 1) as f64;
    let (ma, mb) = (m(a), m(b));
    (ma - mb) / (var(a, ma) / a.len() as f64 + var(b, mb) / b.len() as f64).sqrt()
}

/// Time `op` on inputs from `class(c)` for random classes; return max |t|
/// over a few crop percentiles, as dudect does.
fn measure<I, P: FnMut(bool) -> I, O: FnMut(&I)>(mut prepare: P, mut op: O, n: usize) -> f64 {
    let mut rng = rand::thread_rng();
    let classes: Vec<bool> = (0..n).map(|_| rng.gen()).collect();
    let inputs: Vec<I> = classes.iter().map(|c| prepare(*c)).collect();
    let mut t = vec![0f64; n];
    for i in 0..n {
        let s = Instant::now();
        op(&inputs[i]);
        t[i] = s.elapsed().as_nanos() as f64;
    }
    let mut sorted = t.clone();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mut worst = 0f64;
    for pct in [0.5, 0.75, 0.9, 0.99] {
        let cut = sorted[((n as f64) * pct) as usize];
        let (mut a, mut b) = (Vec::new(), Vec::new());
        for i in 0..n {
            if t[i] <= cut { if classes[i] { a.push(t[i]) } else { b.push(t[i]) } }
        }
        worst = worst.max(welch_t(&a, &b).abs());
    }
    worst
}

fn leaky_eq(a: &[u8], b: &[u8]) -> bool {
    for i in 0..a.len() { if a[i] != b[i] { return false; } }
    true
}

#[test]
#[ignore]
fn control_an_early_exit_comparison_is_detected() {
    let secret = [0x5au8; 4096];
    let t = measure(
        |c| { let mut v = secret; if !c { v[0] ^= 1 } v },
        |v| { black_box(leaky_eq(black_box(v), black_box(&secret))); },
        N);
    println!("control (leaky compare, 4 KiB): max|t| = {t:.1}");
    assert!(t > 10.0, "the harness cannot see an obvious leak here (|t|={t:.1}); results below are meaningless");
}

#[test]
#[ignore]
fn ct_eq_of_a_mac_tag() {
    let secret = [0x5au8; 64];
    let t = measure(
        |c| { let mut v = secret; if !c { v[0] ^= 1 } v },
        |v| { black_box(otrv4_core::secure_mem::ct_eq(black_box(v), black_box(&secret))); },
        N);
    println!("secure_mem::ct_eq (64 B, equal vs first-byte-differs): max|t| = {t:.1}");
    assert!(t < 10.0);
}

#[test]
#[ignore]
fn verify_mac_where_a_forged_tag_differs() {
    // Accept vs reject is public (the caller acts on it); what must not
    // leak is HOW CLOSE a forgery was. Both classes are rejections: the
    // first byte wrong vs only the last byte wrong.
    let key = [7u8; 64];
    let data = [9u8; 256];
    let good = otrv4_core::kdf::hmac_sha3_512(&key, &data);
    let t = measure(
        |c| { let mut v = good; if c { v[0] ^= 1 } else { v[63] ^= 1 } v },
        |v| { black_box(otrv4_core::kdf::verify_mac(&key, &data, black_box(v)).is_ok()); },
        N);
    println!("kdf::verify_mac (reject at byte 0 vs byte 63): max|t| = {t:.1}");
    assert!(t < 10.0);
}

#[test]
#[ignore]
fn ring_sign_fixed_vs_random_secret() {
    // The signer's scalar multiplications use the secret; fixed-vs-random
    // secret is dudect's standard test for that.
    let a2 = otrv4_core::ring_sig::public_key_from_seed(&[0x22; 57]);
    let fixed = [0u8; 57];
    let t = measure(
        |c| {
            let mut s = [0u8; 57];
            if c { s = fixed } else { rand::thread_rng().fill_bytes(&mut s) }
            let a1 = otrv4_core::ring_sig::public_key_from_seed(&s);
            (s, a1)
        },
        |(s, a1)| { black_box(otrv4_core::ring_sig::ring_sign_bytes(s, a1, &a2, b"m").unwrap()); },
        4_000);
    println!("ring_sign_bytes (fixed vs random secret seed): max|t| = {t:.1}");
    assert!(t < 10.0);
}
