//! OTRv4 Schnorr ring signature in Rust (Phase 5.3c, v10.6.9).
//!
//! Direct port of `otr4_crypto_ext.c`'s `py_ring_sign` / `py_ring_verify` /
//! `ring_challenge` (lines 1472–1733).  Output is bit-exact compatible with
//! the C reference - Rust signatures verify with C, C signatures verify
//! with Rust.  This compatibility is enforced by the Python adapter's
//! startup self-check (`_verify_ring_sig_rust_compat`) before the Rust
//! path is enabled in production.
//!
//! Algorithm (OTRv4 spec §4.3.3, signer knows a1 such that A1 = a1·G):
//!
//! ```text
//!     a1   = SHAKE256(seed, 114)[:57], clamped per RFC 8032 §5.2.5
//!     t1   = per-signature ephemeral, bound to (seed-prefix ‖ random ‖ msg)
//!            and reduced mod Q (audit C1 fix; was seed-only, which leaked
//!            the identity key on the second signature)
//!     T1   = t1·G
//!     c2, r2  ← uniform random in [0, Q-1]
//!     T2   = r2·G + c2·A2                       (simulated responder)
//!     c    = SHAKE256(0x1C ‖ msg ‖ A1 ‖ A2 ‖ T1 ‖ T2, 57) mod Q
//!     c1   = (c - c2) mod Q
//!     r1   = (t1 - c1·a1) mod Q
//!     sig  = c1 ‖ r1 ‖ c2 ‖ r2          (each 57 bytes LE, total 228)
//! ```
//!
//! Verify:
//!
//! ```text
//!     parse (c1, r1, c2, r2) from sig
//!     T1'  = r1·G + c1·A1
//!     T2'  = r2·G + c2·A2
//!     c'   = SHAKE256(0x1C ‖ msg ‖ A1 ‖ A2 ‖ T1' ‖ T2', 57) mod Q
//!     accept iff c' == (c1 + c2) mod Q
//! ```
//!
//! Wire format mirrors the C implementation exactly: all scalars are
//! 57-byte little-endian (the high byte is 0x00 for canonical scalars
//! reduced mod Q, which is 446 bits).  Compressed point encoding follows
//! RFC 8032 (57 bytes, low 56 bytes = y-coordinate LE, high byte's bit
//! 7 = x-parity).
//!
//! ── Note on deprecation warnings ──
//! `ed448-goldilocks-plus 0.16` re-exports `generic_array 0.x`, which
//! the `sha3` crate now deprecates in favour of `generic_array 1.x`.
//! Several call sites in this module necessarily traffic through
//! `GenericArray<u8, U57>` and `GenericArray<u8, U114>` because that
//! is the only type `Scalar::from_bytes_mod_order_wide` accepts in
//! this crate version, and `Scalar::to_bytes_rfc_8032()` returns
//! `ScalarBytes = GenericArray<u8, U57>`.  The deprecation will go
//! away once `ed448-goldilocks-plus` upgrades to `generic-array 1.x`;
//! until then the warnings are unavoidable from our side, so we
//! suppress them at module scope with full disclosure here.
#![allow(deprecated)]

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::exceptions::PyValueError;

use ed448_goldilocks_plus::{
    Scalar, EdwardsPoint, CompressedEdwardsY,
    elliptic_curve::generic_array::GenericArray,
    elliptic_curve::ops::MulByGenerator,
    rand_core::{RngCore, OsRng},
};

use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};
use subtle::ConstantTimeEq;

use zeroize::Zeroize;

// ── Constants ───────────────────────────────────────────────────────────────

const ED448_SCALAR_BYTES: usize = 57;
const ED448_POINT_BYTES:  usize = 57;
const RING_SIG_BYTES:     usize = 4 * ED448_SCALAR_BYTES; // 228
const SIGMA_USAGE:        u8    = 0x1C;

// ── Helpers ─────────────────────────────────────────────────────────────────

/// SHAKE-256 over a sequence of byte-slice parts, output `out_len` bytes.
/// Mirrors `shake256_multi` in `otr4_crypto_ext.c`.
fn shake256_multi(parts: &[&[u8]], out: &mut [u8]) {
    let mut hasher = Shake256::default();
    for p in parts {
        hasher.update(p);
    }
    let mut xof = hasher.finalize_xof();
    xof.read(out);
}

/// Reduce a 57-byte little-endian value mod Q and return a Scalar.
/// Mirrors `BN_lebin2bn(in, 57) → BN_mod(., Q)` in the C code.
///
/// `Scalar::from_bytes_mod_order_wide` accepts up to 114 bytes; we
/// zero-extend our 57 bytes to 114.  This produces the same arithmetic
/// reduction as the C implementation's `BN_mod` call.
fn scalar_from_le57_mod_q(le57: &[u8]) -> Scalar {
    debug_assert_eq!(le57.len(), ED448_SCALAR_BYTES);
    let mut wide = [0u8; 114];
    wide[..ED448_SCALAR_BYTES].copy_from_slice(le57);
    let arr = GenericArray::clone_from_slice(&wide);
    Scalar::from_bytes_mod_order_wide(&arr)
}

/// Encode a Scalar as 57-byte little-endian (high byte is always 0 for
/// canonical scalars since Q < 2^446 < 2^448 = 2^(8·56) < 2^(8·57)).
/// Mirrors `BN_bn2lebinpad(., out, 57)` in the C code.
fn scalar_to_le57(s: &Scalar) -> [u8; ED448_SCALAR_BYTES] {
    let bytes = s.to_bytes_rfc_8032();
    // to_bytes_rfc_8032 returns 57-byte LE (RFC 8032 §2 Ed448 scalar encoding).
    let mut out = [0u8; ED448_SCALAR_BYTES];
    out.copy_from_slice(bytes.as_slice());
    out
}

/// Decode a 57-byte compressed Edwards point.  Returns None on invalid encoding
/// or non-canonical point (e.g. y >= p, or x derivation fails).
fn decode_point(p57: &[u8]) -> Option<EdwardsPoint> {
    debug_assert_eq!(p57.len(), ED448_POINT_BYTES);
    let mut arr = [0u8; ED448_POINT_BYTES];
    arr.copy_from_slice(p57);
    let compressed = CompressedEdwardsY(arr);
    compressed.decompress().into()
}

/// Decode a public key and refuse the degenerate ones.
///
/// A key whose point has small order (the identity or a pure torsion point)
/// has discrete log 0 modulo the group order, so anyone can "know" it: a
/// ring containing such a key is signable by anyone, and a pure Ed448
/// signature under it is forgeable. A key with a torsion component is not
/// [s]B for any s, so no honest implementation produces it. Both are refused
/// wherever a key enters from the wire. Honest keys ([s]B, prime order) are
/// unaffected, so this changes no valid transcript.
pub(crate) fn decode_public_key(p57: &[u8]) -> Option<EdwardsPoint> {
    if p57.len() != ED448_POINT_BYTES { return None; }
    let p = decode_point(p57)?;
    let small_order: bool = p.double().double().ct_eq(&EdwardsPoint::IDENTITY).into();
    let torsion_free: bool = p.is_torsion_free().into();
    if small_order || !torsion_free { return None; }
    Some(p)
}

/// Whether `p57` is a public key the protocol accepts. See `decode_public_key`.
pub(crate) fn is_acceptable_public_key(p57: &[u8]) -> bool {
    decode_public_key(p57).is_some()
}

/// The ring public key for a 57-byte seed (the point the signer occupies).
/// Public output only; used by tests and the fuzz harnesses.
pub fn public_key_from_seed(seed: &[u8; 57]) -> [u8; ED448_POINT_BYTES] {
    encode_point(&EdwardsPoint::mul_by_generator(&derive_signing_scalar(seed)))
}

/// Encode an Edwards point as 57-byte compressed.
fn encode_point(p: &EdwardsPoint) -> [u8; ED448_POINT_BYTES] {
    let compressed = p.compress();
    compressed.0
}

/// Compute the ring challenge scalar:
///   c = SHAKE256(0x1C ‖ msg ‖ A1 ‖ A2 ‖ T1 ‖ T2, 57) mod Q
/// Mirrors `ring_challenge` in the C code.
fn ring_challenge(
    msg: &[u8],
    a1:  &[u8],
    a2:  &[u8],
    t1:  &[u8],
    t2:  &[u8],
) -> Scalar {
    let usage = [SIGMA_USAGE];
    let mut h = [0u8; ED448_SCALAR_BYTES];
    shake256_multi(&[&usage, msg, a1, a2, t1, t2], &mut h);
    let s = scalar_from_le57_mod_q(&h);
    h.zeroize();
    s
}

/// Derive the Ed448 signing scalar `a1` from the 57-byte seed.
/// RFC 8032 §5.2.5: h = SHAKE-256(seed, 114); clamp h[0..56]:
///   h[0]  &= 0xFC      (clear bits 0,1)
///   h[55] |= 0x80      (set bit 447)
///   h[56]  = 0x00      (clear byte 56; Ed448 scalars are 447-bit)
/// Returns the clamped 57-byte LE encoding reduced mod Q.
fn derive_signing_scalar(seed: &[u8]) -> Scalar {
    debug_assert_eq!(seed.len(), 57);
    let mut h = [0u8; 114];
    shake256_multi(&[seed], &mut h);
    h[0]  &= 0xFC;
    h[55] |= 0x80;
    h[56]  = 0x00;
    // h[0..57] is the clamped scalar in LE.  Reduce mod Q.
    let s = scalar_from_le57_mod_q(&h[..57]);
    h.zeroize();
    s
}

/// Derive the per-signature Schnorr ephemeral scalar `t1`.
///
/// SECURITY (audit C1 fix): the ephemeral MUST be unique per signature.
/// The previous version derived `t1 = SHAKE256(seed ‖ 0x01)` from the
/// long-term seed ONLY, so every ring signature an identity produced
/// reused the same nonce point T1 = t1·G.  Two signatures over different
/// transcripts then leaked the long-term secret scalar via
/// `a1 = (r1_A - r1_B)·(c1_B - c1_A)^{-1} mod Q`.
///
/// This version binds the nonce to BOTH a secret prefix derived from the
/// seed AND the message, and hedges with 32 fresh random bytes (RFC 8032 /
/// RFC 6979 style plus hedging).  A repeated `(seed, msg)` still yields a
/// fresh nonce; a faulty RNG degrades to deterministic-but-message-bound
/// (still safe against the reuse attack as long as messages differ).
///
/// Verification is unchanged and never inspects how `t1` was produced, so
/// signatures remain wire-compatible: a peer running the old or the new
/// signer is verified identically.
fn derive_ephemeral_scalar(seed: &[u8], msg: &[u8]) -> Scalar {
    debug_assert_eq!(seed.len(), 57);

    // Secret prefix from the seed, domain-separated from a1's own hash.
    let mut prefix = [0u8; 57];
    shake256_multi(&[b"OTRv4-ringsig-nonce-prefix-v1", seed], &mut prefix);

    // Fresh hedging randomness.
    let mut rnd = [0u8; 32];
    OsRng.fill_bytes(&mut rnd);

    // t1 = wide-reduce SHAKE256(domain ‖ prefix ‖ rnd ‖ msg) mod Q.
    // Reduce the full 114-byte (912-bit) output so the scalar is uniform
    // (bias < 2^-460), matching random_scalar rather than the old 57-byte
    // reduction which carried a ~2^-10 bias.
    let mut wide = [0u8; 114];
    shake256_multi(&[b"OTRv4-ringsig-nonce-v1", &prefix, &rnd, msg], &mut wide);
    let arr = GenericArray::clone_from_slice(&wide);
    let s = Scalar::from_bytes_mod_order_wide(&arr);

    prefix.zeroize();
    rnd.zeroize();
    wide.zeroize();
    s
}

// ── Core sign / verify ──────────────────────────────────────────────────────

/// Compute an OTRv4 Schnorr ring signature.
///
/// Inputs:
///   - seed: 57-byte raw Ed448 private key (the seed before SHAKE expansion)
///   - a1:   57-byte compressed initiator public key (signer's pubkey)
///   - a2:   57-byte compressed responder public key (other party's pubkey)
///   - msg:  arbitrary-length transcript binding bytes
///
/// Output: 228-byte signature (c1 ‖ r1 ‖ c2 ‖ r2, each 57 bytes LE).
///
/// Errors:
///   - Input length mismatch
///   - Point decoding failure for `a2` (a1 is not decoded - its compressed
/// ```text
///     form is hashed directly; only a2 is used in scalar multiplication)
/// ```
// The `0*57..1*57` below reads as an erasing_op / identity_op to clippy, and
// arithmetically it is right: `0*57` is 0 and `1*57` is 57. It is written that
// way on purpose. The signature is four 57-byte scalars in a fixed order, and
// `n*57..(n+1)*57` on every line makes the layout checkable against the spec at
// a glance. Collapsing the first to `..57` and the second to `57..114` breaks
// the symmetry that makes a field-order mistake visible, which for a signature
// encoding is the property worth protecting.
#[allow(clippy::erasing_op, clippy::identity_op)]
pub fn ring_sign_bytes(
    seed: &[u8],
    a1:   &[u8],
    a2:   &[u8],
    msg:  &[u8],
) -> Result<[u8; RING_SIG_BYTES], &'static str> {
    if seed.len() != 57 { return Err("seed must be 57 bytes"); }
    if a1.len()   != 57 { return Err("a1 must be 57 bytes"); }
    if a2.len()   != 57 { return Err("a2 must be 57 bytes"); }

    // ── Step 1: signing scalar a1_scalar (signer's secret) ─────────────────
    let a1_scalar = derive_signing_scalar(seed);

    // ── Step 2: ephemeral scalar t1 (per-signature, message-bound; audit C1) ─
    let t1 = derive_ephemeral_scalar(seed, msg);

    // ── Step 3: T1 = t1·G ──────────────────────────────────────────────────
    let t1_point = EdwardsPoint::mul_by_generator(&t1);
    let t1_enc   = encode_point(&t1_point);

    // ── Step 4: simulate responder (c2, r2 random; T2 = r2·G + c2·A2) ──────
    let a2_point = decode_public_key(a2).ok_or("a2 is not an acceptable Ed448 public key")?;

    let c2 = random_scalar();
    let r2 = random_scalar();

    let r2_g  = EdwardsPoint::mul_by_generator(&r2);
    let c2_a2 = a2_point * c2;
    let t2_point = r2_g + c2_a2;
    let t2_enc = encode_point(&t2_point);

    // ── Step 5: c = challenge(msg, A1, A2, T1, T2) ─────────────────────────
    let c = ring_challenge(msg, a1, a2, &t1_enc, &t2_enc);

    // ── Step 6: c1 = (c - c2) mod Q ────────────────────────────────────────
    let c1 = c - c2;

    // ── Step 7: r1 = (t1 - c1·a1_scalar) mod Q ─────────────────────────────
    let r1 = t1 - (c1 * a1_scalar);

    // ── Encode output ──────────────────────────────────────────────────────
    let c1_bytes = scalar_to_le57(&c1);
    let r1_bytes = scalar_to_le57(&r1);
    let c2_bytes = scalar_to_le57(&c2);
    let r2_bytes = scalar_to_le57(&r2);

    let mut sig = [0u8; RING_SIG_BYTES];
    sig[0  *57..1*57].copy_from_slice(&c1_bytes);
    sig[1  *57..2*57].copy_from_slice(&r1_bytes);
    sig[2  *57..3*57].copy_from_slice(&c2_bytes);
    sig[3  *57..4*57].copy_from_slice(&r2_bytes);

    Ok(sig)
}

/// Verify an OTRv4 Schnorr ring signature.
///
/// Inputs:
///   - a1:   57-byte compressed initiator public key
///   - a2:   57-byte compressed responder public key
///   - msg:  transcript bytes (same as during sign)
///   - sig:  228-byte signature blob
///
/// Returns `true` iff the signature is valid.  Constant-time-ish:
/// scalar comparisons use the crate's `ct_eq`; point arithmetic is
/// constant-time in `ed448-goldilocks-plus`.  Note: not all branches
/// can be made constant-time (e.g. point decoding failures), and OTRv4
/// ring signature verification is not security-sensitive to timing
/// against an attacker who controls the signature (they already know
/// the signature bytes).
// The `0*57..1*57` below reads as an erasing_op / identity_op to clippy, and
// arithmetically it is right: `0*57` is 0 and `1*57` is 57. It is written that
// way on purpose. The signature is four 57-byte scalars in a fixed order, and
// `n*57..(n+1)*57` on every line makes the layout checkable against the spec at
// a glance. Collapsing the first to `..57` and the second to `57..114` breaks
// the symmetry that makes a field-order mistake visible, which for a signature
// encoding is the property worth protecting.
#[allow(clippy::erasing_op, clippy::identity_op)]
pub fn ring_verify_bytes(
    a1:  &[u8],
    a2:  &[u8],
    msg: &[u8],
    sig: &[u8],
) -> bool {
    if a1.len()  != 57 { return false; }
    if a2.len()  != 57 { return false; }
    if sig.len() != RING_SIG_BYTES { return false; }

    // Audit 2026-09: degenerate keys refused -- see decode_public_key.
    let a1_point = match decode_public_key(a1) { Some(p) => p, None => return false };
    let a2_point = match decode_public_key(a2) { Some(p) => p, None => return false };

    let c1 = scalar_from_le57_mod_q(&sig[0*57..1*57]);
    let r1 = scalar_from_le57_mod_q(&sig[1*57..2*57]);
    let c2 = scalar_from_le57_mod_q(&sig[2*57..3*57]);
    let r2 = scalar_from_le57_mod_q(&sig[3*57..4*57]);

    // Audit 2026-09: only canonical scalars (< Q). Reducing silently let
    // every signature be re-encoded as a different valid one (s + Q); the
    // signer only ever emits canonical scalars, so honest signatures are
    // unaffected. Non-malleability is cheap and removes a class of
    // "distinct bytes, same meaning" surprises from replay caches and logs.
    for (n, s) in [&c1, &r1, &c2, &r2].into_iter().enumerate() {
        if scalar_to_le57(s)[..] != sig[n*57..(n+1)*57] { return false; }
    }

    // T1' = r1·G + c1·A1
    let t1p = EdwardsPoint::mul_by_generator(&r1) + (a1_point * c1);
    // T2' = r2·G + c2·A2
    let t2p = EdwardsPoint::mul_by_generator(&r2) + (a2_point * c2);

    let t1p_enc = encode_point(&t1p);
    let t2p_enc = encode_point(&t2p);

    let c_chk = ring_challenge(msg, a1, a2, &t1p_enc, &t2p_enc);
    let c_sum = c1 + c2;

    c_chk == c_sum
}

/// Sample a uniformly-random scalar in [0, Q-1] using OsRng.
/// Mirrors `BN_rand_range(., Q)` in the C code.
fn random_scalar() -> Scalar {
    // Generate 114 random bytes and reduce mod Q.  This is a slight
    // statistical bias for scalars near Q, but it's exactly what
    // BN_rand_range does after rejection sampling converges, and the
    // bias is negligible (Q is 446 bits in a 448-bit field; the bias
    // is at most ~2^-446).
    let mut wide = [0u8; 114];
    OsRng.fill_bytes(&mut wide);
    let arr = GenericArray::clone_from_slice(&wide);
    let s = Scalar::from_bytes_mod_order_wide(&arr);
    wide.zeroize();
    s
}

// ── PyO3 surface ────────────────────────────────────────────────────────────

/// Python-callable: ring_sign(seed, A1, A2, msg) -> bytes(228).
#[pyfunction]
pub fn py_ring_sign<'py>(
    py:   Python<'py>,
    seed: &[u8],
    a1:   &[u8],
    a2:   &[u8],
    msg:  &[u8],
) -> PyResult<Py<PyBytes>> {
    match ring_sign_bytes(seed, a1, a2, msg) {
        Ok(sig) => Ok(PyBytes::new(py, &sig).unbind()),
        Err(e)  => Err(PyValueError::new_err(e)),
    }
}

/// Python-callable: ring_verify(A1, A2, msg, sig) -> bool.
#[pyfunction]
pub fn py_ring_verify(
    a1:  &[u8],
    a2:  &[u8],
    msg: &[u8],
    sig: &[u8],
) -> PyResult<bool> {
    Ok(ring_verify_bytes(a1, a2, msg, sig))
}

// ── Tests ───────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    /// Self-consistency: Rust signs, Rust verifies.
    #[test]
    fn rust_sign_rust_verify() {
        // Random seed (deterministic for test reproducibility).
        let seed = [0x42u8; 57];

        // Derive A1 from seed.
        let a1_scalar = derive_signing_scalar(&seed);
        let a1 = encode_point(&EdwardsPoint::mul_by_generator(&a1_scalar));

        // Random A2 (just another public point - we don't need its discrete log).
        let a2_seed = [0x37u8; 57];
        let a2_scalar = derive_signing_scalar(&a2_seed);
        let a2 = encode_point(&EdwardsPoint::mul_by_generator(&a2_scalar));

        let msg = b"OTRv4 ring sig test message";

        let sig = ring_sign_bytes(&seed, &a1, &a2, msg).expect("sign ok");
        assert!(ring_verify_bytes(&a1, &a2, msg, &sig), "self-verify failed");
    }

    /// Tampered signature must fail verify.
    #[test]
    fn tampered_sig_fails() {
        let seed = [0x42u8; 57];
        let a1_scalar = derive_signing_scalar(&seed);
        let a1 = encode_point(&EdwardsPoint::mul_by_generator(&a1_scalar));
        let a2_seed = [0x37u8; 57];
        let a2_scalar = derive_signing_scalar(&a2_seed);
        let a2 = encode_point(&EdwardsPoint::mul_by_generator(&a2_scalar));
        let msg = b"test";

        let mut sig = ring_sign_bytes(&seed, &a1, &a2, msg).unwrap();
        sig[0] ^= 0x01;  // flip a bit in c1
        assert!(!ring_verify_bytes(&a1, &a2, msg, &sig), "tampered sig accepted");
    }

    /// Wrong message must fail verify.
    #[test]
    fn wrong_msg_fails() {
        let seed = [0x42u8; 57];
        let a1_scalar = derive_signing_scalar(&seed);
        let a1 = encode_point(&EdwardsPoint::mul_by_generator(&a1_scalar));
        let a2_seed = [0x37u8; 57];
        let a2_scalar = derive_signing_scalar(&a2_seed);
        let a2 = encode_point(&EdwardsPoint::mul_by_generator(&a2_scalar));

        let sig = ring_sign_bytes(&seed, &a1, &a2, b"original").unwrap();
        assert!(!ring_verify_bytes(&a1, &a2, b"different", &sig));
    }

    /// Sig length and structure.
    #[test]
    // `1*57` is not a typo clippy should collapse to `57`: the four asserts
    // below read off the c1/r1/c2/r2 slots of the 4x57-byte signature, and the
    // multiplier is which slot.  Writing the first as a bare 57 would break the
    // column the other three line up in and lose that.
    #[allow(clippy::identity_op)]
    fn sig_is_228_bytes() {
        let seed = [0x42u8; 57];
        let a1_scalar = derive_signing_scalar(&seed);
        let a1 = encode_point(&EdwardsPoint::mul_by_generator(&a1_scalar));
        let a2_seed = [0x37u8; 57];
        let a2_scalar = derive_signing_scalar(&a2_seed);
        let a2 = encode_point(&EdwardsPoint::mul_by_generator(&a2_scalar));

        let sig = ring_sign_bytes(&seed, &a1, &a2, b"m").unwrap();
        assert_eq!(sig.len(), 228);
        // High byte of each scalar is 0x00 (Q < 2^447).
        assert_eq!(sig[1*57 - 1], 0x00, "c1 high byte not 0");
        assert_eq!(sig[2*57 - 1], 0x00, "r1 high byte not 0");
        assert_eq!(sig[3*57 - 1], 0x00, "c2 high byte not 0");
        assert_eq!(sig[4*57 - 1], 0x00, "r2 high byte not 0");
    }

    /// Audit C1 regression: the ephemeral MUST NOT be reused across
    /// signatures.  Two signatures by the same identity over different
    /// messages must use different nonce points T1, which shows up as
    /// different c1 values, so the reused-nonce key-recovery equation
    /// `a1 = (r1_A - r1_B)/(c1_B - c1_A)` cannot be solved.  We also
    /// require that signing the SAME (seed, msg) twice yields different
    /// signatures (hedged randomness).
    #[test]
    fn t1_is_not_reused_across_signatures() {
        let seed = [0x99u8; 57];
        let a1 = encode_point(&EdwardsPoint::mul_by_generator(&derive_signing_scalar(&seed)));
        let a2 = encode_point(&EdwardsPoint::mul_by_generator(&derive_signing_scalar(&[0x37u8; 57])));

        // Different messages -> different c1 (first 57 bytes).
        let sig_a = ring_sign_bytes(&seed, &a1, &a2, b"message A").expect("sign A");
        let sig_b = ring_sign_bytes(&seed, &a1, &a2, b"message B").expect("sign B");
        assert_ne!(&sig_a[0..57], &sig_b[0..57], "c1 repeated across messages: nonce reuse");

        // Same (seed, msg) twice -> different signatures (hedging).
        let sig_c = ring_sign_bytes(&seed, &a1, &a2, b"same").expect("sign C");
        let sig_d = ring_sign_bytes(&seed, &a1, &a2, b"same").expect("sign D");
        assert_ne!(sig_c, sig_d, "identical signatures for same (seed,msg): no hedging");

        // Both still verify (wire compatibility / correctness).
        assert!(ring_verify_bytes(&a1, &a2, b"message A", &sig_a));
        assert!(ring_verify_bytes(&a1, &a2, b"same", &sig_c));
    }
}

#[cfg(test)]
mod audit_identity_point {
    //! Audit 2026-09: degenerate public keys.
    //!
    //! A key of small order has discrete log 0 mod the group order, so the
    //! ring equation T2 = r2*G + c2*A2 can be satisfied by anyone. Before the
    //! fix, `ring_verify_bytes` accepted a signature over (victim, identity)
    //! forged without the victim's secret. These tests pin that the forgery is
    //! still arithmetically valid (so the check is load-bearing) and that the
    //! verifier and signer both refuse the key.
    use super::*;

    fn identity_enc() -> [u8; 57] { encode_point(&EdwardsPoint::IDENTITY) }

    fn victim() -> [u8; 57] {
        encode_point(&EdwardsPoint::mul_by_generator(&derive_signing_scalar(&[0x11u8; 57])))
    }

    /// A signature over (victim, degenerate) produced with no secret at all.
    fn forge(victim: &[u8; 57], degenerate: &[u8; 57], msg: &[u8]) -> ([u8; RING_SIG_BYTES], bool) {
        let c1 = random_scalar();
        let r1 = random_scalar();
        let a1p = decode_point(victim).unwrap();
        let t1 = EdwardsPoint::mul_by_generator(&r1) + a1p * c1;
        let t2_nonce = random_scalar();
        let t2 = EdwardsPoint::mul_by_generator(&t2_nonce);
        let c = ring_challenge(msg, victim, degenerate, &encode_point(&t1), &encode_point(&t2));
        let c2 = c - c1;
        let r2 = t2_nonce;
        let mut sig = [0u8; RING_SIG_BYTES];
        sig[0..57].copy_from_slice(&scalar_to_le57(&c1));
        sig[57..114].copy_from_slice(&scalar_to_le57(&r1));
        sig[114..171].copy_from_slice(&scalar_to_le57(&c2));
        sig[171..228].copy_from_slice(&scalar_to_le57(&r2));
        // The raw equation, without the key check: does the forgery satisfy it?
        let a2p = decode_point(degenerate).unwrap();
        let t1c = EdwardsPoint::mul_by_generator(&r1) + a1p * c1;
        let t2c = EdwardsPoint::mul_by_generator(&r2) + a2p * c2;
        let eq = ring_challenge(msg, victim, degenerate, &encode_point(&t1c), &encode_point(&t2c)) == c1 + c2;
        (sig, eq)
    }

    #[test]
    fn a_forgery_with_the_identity_key_satisfies_the_equation_but_is_refused() {
        let (v, o) = (victim(), identity_enc());
        let (sig, equation_holds) = forge(&v, &o, b"transcript");
        assert!(equation_holds, "the check below would be untested");
        assert!(!ring_verify_bytes(&v, &o, b"transcript", &sig));
        assert!(!ring_verify_bytes(&o, &v, b"transcript", &sig));
    }

    #[test]
    fn small_order_and_torsion_keys_are_not_acceptable() {
        assert!(!is_acceptable_public_key(&identity_enc()));
        // (0, -1): the point of order 2.
        let mut order2 = [0u8; 57];
        order2[0] = 0xfe;
        for b in order2.iter_mut().take(56).skip(1) { *b = 0xff; }
        order2[28] = 0xfe;
        // The library's decompress already refuses any point with a torsion
        // component, so the identity is the only degenerate key that decodes.
        // Both layers are pinned: a library change must not reopen this.
        let t: EdwardsPoint = Option::from(CompressedEdwardsY(order2).decompress_unchecked())
            .expect("(0,-1) is the y-coordinate of a curve point");
        assert!(bool::from(t.double().ct_eq(&EdwardsPoint::IDENTITY)), "order 2");
        assert!(decode_point(&order2).is_none());
        assert!(!is_acceptable_public_key(&order2));
        let honest = decode_point(&victim()).unwrap();
        let mixed = encode_point(&(honest + t));
        assert!(!is_acceptable_public_key(&mixed));
        assert!(decode_point(&identity_enc()).is_some(), "identity decodes; our check is what refuses it");
        assert!(is_acceptable_public_key(&victim()));
    }

    #[test]
    fn the_signer_refuses_a_degenerate_ring_member() {
        assert!(ring_sign_bytes(&[0x11u8; 57], &victim(), &identity_enc(), b"m").is_err());
    }

    /// Q as 57 little-endian bytes: (Q - 1) + 1.
    fn q_le57() -> [u8; 57] {
        let mut q = scalar_to_le57(&(Scalar::ZERO - Scalar::ONE));
        for b in q.iter_mut() {
            let (v, carry) = b.overflowing_add(1);
            *b = v;
            if !carry { break; }
        }
        q
    }

    fn add_le(a: &[u8], b: &[u8; 57]) -> [u8; 57] {
        let mut out = [0u8; 57];
        let mut carry = 0u16;
        for i in 0..57 {
            let v = a[i] as u16 + b[i] as u16 + carry;
            out[i] = v as u8;
            carry = v >> 8;
        }
        assert_eq!(carry, 0, "fits in 57 bytes");
        out
    }

    #[test]
    fn a_non_canonical_scalar_is_refused() {
        let a2 = encode_point(&EdwardsPoint::mul_by_generator(&derive_signing_scalar(&[0x22u8; 57])));
        let sig = ring_sign_bytes(&[0x11u8; 57], &victim(), &a2, b"m").unwrap();
        assert!(ring_verify_bytes(&victim(), &a2, b"m", &sig));
        for field in 0..4 {
            let mut bad = sig;
            let bumped = add_le(&sig[field * 57..(field + 1) * 57], &q_le57());
            bad[field * 57..(field + 1) * 57].copy_from_slice(&bumped);
            assert_ne!(bad, sig);
            // Same scalars mod Q, so the old reduce-and-accept verifier took it.
            assert!(!ring_verify_bytes(&victim(), &a2, b"m", &bad), "field {field}");
        }
    }

    #[test]
    fn honest_rings_still_verify() {
        let a2 = encode_point(&EdwardsPoint::mul_by_generator(&derive_signing_scalar(&[0x22u8; 57])));
        let sig = ring_sign_bytes(&[0x11u8; 57], &victim(), &a2, b"m").unwrap();
        assert!(ring_verify_bytes(&victim(), &a2, b"m", &sig));
    }
}
