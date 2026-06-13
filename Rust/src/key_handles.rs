//! Phase 5.3e (v10.6.12): Rust-owned long-term identity key handles.
//!
//! Eliminates the Python `cryptography` library `Ed448PrivateKey` and
//! `X448PrivateKey` objects from the OTRv4+ session lifetime.  Identity
//! keys are generated inside Rust, held in `SecretBytes<N>` (ZeroizeOnDrop),
//! and exposed to Python only as opaque handles.  Python receives ONLY
//! the public bytes.  All private operations (Ed448 sign, X448 DH) are
//! performed inside Rust against the stored SecretBytes.
//!
//! ── Handles ──
//!   - `Ed448KeyHandle` — wraps SecretBytes<57>; exposes `public_bytes()`
//!     (57-byte compressed Edwards Y) and `sign(msg) -> bytes(114)`.
//!   - `X448KeyHandle`  — wraps SecretBytes<56>; exposes `public_bytes()`
//!     (56-byte Curve448 u-coordinate) and `dh(peer_pub) -> bytes(56)`.
//!
//! ── Factories ──
//!   - `generate_ed448_keypair() -> Ed448KeyHandle`
//!   - `generate_x448_keypair()  -> X448KeyHandle`
//!
//! ── Lifetime ──
//! When the Python handle object is dropped (GC), Rust's Drop runs and
//! the SecretBytes is zeroized via the `ZeroizeOnDrop` derive on the
//! wrapper type.  Python sees the handle as an ordinary PyO3 class
//! instance; it cannot inspect, copy, or serialize the private bytes
//! by any public method.

#![allow(deprecated)] // upstream generic-array 0.x deprecation in ed448-goldilocks-plus 0.16

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::exceptions::PyValueError;

use ed448_goldilocks_plus::{
    SigningKey,
    VerifyingKey,
    Signature,
    rand_core::{RngCore, OsRng},
};

use zeroize::Zeroize;
use std::convert::TryFrom;

use crate::secure_mem::SecretBytes;

// ── Ed448 ────────────────────────────────────────────────────────────────────

/// Opaque handle to an Ed448 long-term private key held inside Rust.
///
/// Wraps SecretBytes<57> (the RFC 8032 §5.2 Ed448 seed).  The
/// `SecretBytes` type derives `ZeroizeOnDrop`, so when the Python
/// object holding this handle is garbage-collected, the underlying
/// private bytes are zeroized in memory before the heap slot is
/// reclaimed.
///
/// Python cannot read the private bytes through any public method;
/// only `public_bytes()` and `sign(msg)` are exposed.
#[pyclass(name = "Ed448KeyHandle")]
pub struct Ed448KeyHandle {
    seed: SecretBytes<57>,
    pub_bytes: [u8; 57],
}

#[pymethods]
impl Ed448KeyHandle {
    /// Construct from raw 57 bytes (test/internal use; production calls
    /// `generate_ed448_keypair` instead so the seed is never observed
    /// from Python at all).
    #[staticmethod]
    fn from_seed_bytes<'py>(seed: &[u8]) -> PyResult<Self> {
        if seed.len() != 57 {
            return Err(PyValueError::new_err(format!(
                "Ed448 seed must be 57 bytes, got {}", seed.len()
            )));
        }
        let signing_key = SigningKey::try_from(seed)
            .map_err(|e| PyValueError::new_err(format!(
                "Ed448 SigningKey construction failed: {:?}", e
            )))?;
        let vk = signing_key.verifying_key();
        let pub_bytes: [u8; 57] = vk.to_bytes();

        let mut seed_arr = [0u8; 57];
        seed_arr.copy_from_slice(seed);
        let secret = SecretBytes::new(seed_arr);
        seed_arr.zeroize();

        Ok(Self { seed: secret, pub_bytes })
    }

    /// 57-byte compressed Ed448 public key.
    fn public_bytes<'py>(&self, py: Python<'py>) -> Py<PyBytes> {
        PyBytes::new(py, &self.pub_bytes).unbind()
    }

    /// Sign `msg` with pure Ed448 (RFC 8032 §5.2, empty context).
    /// Returns the 114-byte signature.
    fn sign<'py>(&self, py: Python<'py>, msg: &[u8]) -> PyResult<Py<PyBytes>> {
        let signing_key = SigningKey::try_from(self.seed.expose_slice())
            .map_err(|e| PyValueError::new_err(format!(
                "Ed448 SigningKey reconstruction failed: {:?}", e
            )))?;
        let signature = signing_key.sign_raw(msg);
        let sig_bytes: [u8; 114] = signature.to_bytes();
        Ok(PyBytes::new(py, &sig_bytes).unbind())
    }

    /// OTRv4 Schnorr ring signature using this handle as the signing key.
    /// Calls `ring_sig::ring_sign_bytes` internally with the stored seed;
    /// Python never sees the seed.  Returns the 228-byte signature
    /// `c1 ‖ r1 ‖ c2 ‖ r2`.
    fn ring_sign<'py>(
        &self,
        py: Python<'py>,
        a1: &[u8],
        a2: &[u8],
        msg: &[u8],
    ) -> PyResult<Py<PyBytes>> {
        let sig = crate::ring_sig::ring_sign_bytes(
            self.seed.expose_slice(), a1, a2, msg
        ).map_err(|e| PyValueError::new_err(e))?;
        Ok(PyBytes::new(py, &sig).unbind())
    }

    fn __repr__(&self) -> String {
        // Never expose the private bytes in repr.
        format!("Ed448KeyHandle(pub={})", hex_short(&self.pub_bytes))
    }
}

impl Ed448KeyHandle {
    /// Crate-internal accessor for the seed slice.  Used by `dake.rs`'s
    /// `sign_profile_body_and_construct_with_handles` to construct
    /// `DakeState` without going through Python.  NOT a PyO3 method —
    /// not visible from Python.
    pub(crate) fn expose_seed_slice(&self) -> &[u8] {
        self.seed.expose_slice()
    }
}

/// Generate a fresh Ed448 keypair inside Rust.  Returns a handle
/// whose private bytes never appear in Python.
#[pyfunction]
pub fn generate_ed448_keypair() -> PyResult<Ed448KeyHandle> {
    let mut seed = [0u8; 57];
    OsRng.fill_bytes(&mut seed);

    let signing_key = SigningKey::try_from(&seed[..])
        .map_err(|e| PyValueError::new_err(format!(
            "Ed448 SigningKey construction failed: {:?}", e
        )))?;
    let vk = signing_key.verifying_key();
    let pub_bytes: [u8; 57] = vk.to_bytes();

    let secret = SecretBytes::new(seed);
    seed.zeroize();

    Ok(Ed448KeyHandle { seed: secret, pub_bytes })
}

/// Verify a pure-Ed448 signature against a 57-byte public key.
///
/// v10.6.20 (Phase 5.3h-D, stage 1): replaces the Python
/// `cryptography` library `Ed448PublicKey.from_public_bytes(pub).verify(
/// sig, msg)` call in `ClientProfile.decode()`.
///
/// This MUST stay the exact counterpart of `Ed448KeyHandle::sign`,
/// which calls `SigningKey::sign_raw` (pure Ed448, RFC 8032 §5.2,
/// empty context).  The verification side therefore uses
/// `VerifyingKey::verify_raw` — the inherent pure-Ed448 verifier — so
/// that any signature produced by `Ed448KeyHandle::sign` verifies here
/// and vice versa.  Do NOT switch this to a context-prefixed verify or
/// to the `signature::Verifier` trait: the framing would differ from
/// the signing side and previously-valid profiles would be rejected.
///
/// Arguments:
///   - `pub_bytes`: 57-byte compressed Ed448 public key
///   - `msg`:       the signed message (ClientProfile body, the bytes
///                  up to but not including the signature field)
///   - `sig_bytes`: 114-byte Ed448 signature
///
/// Returns `Ok(true)` on a valid signature, `Ok(false)` on any
/// verification failure (bad signature, point not on curve, wrong
/// length).  Never raises for a merely-invalid signature — only raises
/// `ValueError` if the public key or signature length is structurally
/// wrong, so the Python caller can distinguish "forged/tampered" from
/// "malformed input".
#[pyfunction]
pub fn verify_ed448_sig(pub_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> PyResult<bool> {
    if pub_bytes.len() != 57 {
        return Err(PyValueError::new_err(format!(
            "Ed448 public key must be 57 bytes, got {}", pub_bytes.len()
        )));
    }
    if sig_bytes.len() != 114 {
        return Err(PyValueError::new_err(format!(
            "Ed448 signature must be 114 bytes, got {}", sig_bytes.len()
        )));
    }

    let pk_arr: [u8; 57] = match <[u8; 57]>::try_from(pub_bytes) {
        Ok(a)  => a,
        Err(_) => return Err(PyValueError::new_err("Ed448 public key slice error")),
    };
    // VerifyingKey::from_bytes(&[u8; 57]) -> Result.  This is the real
    // constructor (verifying_key.rs); the TryFrom<PublicKeyBytes> impl
    // the compiler suggested is just a pkcs8 wrapper around it.
    let vk = match VerifyingKey::from_bytes(&pk_arr) {
        Ok(v)  => v,
        // A public key that does not decode to a valid curve point is
        // not a panic condition — it is a failed verification.
        Err(_) => return Ok(false),
    };

    // Signature: TryFrom<&[u8]> exists, checks length == SIGNATURE_LENGTH
    // (114) internally and returns SigningError on a bad encoding.
    let signature = match Signature::try_from(sig_bytes) {
        Ok(s)  => s,
        Err(_) => return Ok(false),
    };

    Ok(vk.verify_raw(&signature, msg).is_ok())
}

// ── X448 ─────────────────────────────────────────────────────────────────────

/// Opaque handle to an X448 long-term private key held inside Rust.
#[pyclass(name = "X448KeyHandle")]
pub struct X448KeyHandle {
    priv_bytes: SecretBytes<56>,
    pub_bytes: [u8; 56],
}

#[pymethods]
impl X448KeyHandle {
    /// Construct from raw 56 bytes.  Same intent as Ed448: production
    /// uses `generate_x448_keypair` so the seed never appears in Python.
    #[staticmethod]
    fn from_priv_bytes<'py>(priv_bytes: &[u8]) -> PyResult<Self> {
        if priv_bytes.len() != 56 {
            return Err(PyValueError::new_err(format!(
                "X448 private bytes must be 56 bytes, got {}", priv_bytes.len()
            )));
        }
        let mut priv_arr = [0u8; 56];
        priv_arr.copy_from_slice(priv_bytes);

        // Derive public via x448 crate (matches what dake.rs already uses).
        let sk = x448::Secret::from(priv_arr);
        let pk = x448::PublicKey::from(&sk);
        let pub_arr: [u8; 56] = *pk.as_bytes();

        let secret = SecretBytes::new(priv_arr);
        priv_arr.zeroize();

        Ok(Self { priv_bytes: secret, pub_bytes: pub_arr })
    }

    /// 56-byte X448 public key.
    fn public_bytes<'py>(&self, py: Python<'py>) -> Py<PyBytes> {
        PyBytes::new(py, &self.pub_bytes).unbind()
    }

    /// X448 Diffie-Hellman with a peer's 56-byte public key.
    /// Returns the 56-byte shared secret.
    fn dh<'py>(&self, py: Python<'py>, peer_pub: &[u8]) -> PyResult<Py<PyBytes>> {
        if peer_pub.len() != 56 {
            return Err(PyValueError::new_err(format!(
                "peer X448 public key must be 56 bytes, got {}", peer_pub.len()
            )));
        }
        let priv_arr: [u8; 56] = self.priv_bytes.expose_slice().try_into()
            .map_err(|_| PyValueError::new_err("internal: priv_bytes wrong length"))?;
        let sk = x448::Secret::from(priv_arr);
        let pk_arr: [u8; 56] = peer_pub.try_into()
            .map_err(|_| PyValueError::new_err("peer_pub wrong length"))?;
        let pk = x448::PublicKey::from_bytes(&pk_arr)
            .ok_or_else(|| PyValueError::new_err("invalid X448 public key"))?;
        let ss = sk.as_diffie_hellman(&pk)
            .ok_or_else(|| PyValueError::new_err("X448 DH produced all-zero shared secret"))?;
        let ss_bytes: [u8; 56] = *ss.as_bytes();
        Ok(PyBytes::new(py, &ss_bytes).unbind())
    }

    fn __repr__(&self) -> String {
        format!("X448KeyHandle(pub={})", hex_short(&self.pub_bytes))
    }
}

impl X448KeyHandle {
    /// Crate-internal accessor for the private bytes slice.  Used by
    /// `dake.rs`'s `sign_profile_body_and_construct_with_handles`.
    /// NOT a PyO3 method.
    pub(crate) fn expose_priv_slice(&self) -> &[u8] {
        self.priv_bytes.expose_slice()
    }
}

/// Generate a fresh X448 keypair inside Rust.
#[pyfunction]
pub fn generate_x448_keypair() -> PyResult<X448KeyHandle> {
    let mut priv_arr = [0u8; 56];
    OsRng.fill_bytes(&mut priv_arr);

    let sk = x448::Secret::from(priv_arr);
    let pk = x448::PublicKey::from(&sk);
    let pub_arr: [u8; 56] = *pk.as_bytes();

    let secret = SecretBytes::new(priv_arr);
    priv_arr.zeroize();

    Ok(X448KeyHandle { priv_bytes: secret, pub_bytes: pub_arr })
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn hex_short(bytes: &[u8]) -> String {
    // First 8 bytes hex-encoded, for use in __repr__ only.
    let n = bytes.len().min(8);
    let mut s = String::with_capacity(2 * n + 2);
    for b in &bytes[..n] {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    if bytes.len() > 8 { s.push_str("…"); }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// v10.6.20: a signature produced by Ed448KeyHandle::sign (sign_raw)
    /// must verify under verify_ed448_sig (verify_raw).  This is the
    /// guarantee that the Phase 5.3h-D stage-1 swap of ClientProfile
    /// verification preserves behaviour: same key, same message, the
    /// Rust verifier accepts what the Rust signer produced.
    #[test]
    fn ed448_sign_then_verify_roundtrip() {
        let mut seed = [7u8; 57];
        seed[56] = 0;
        let handle = Ed448KeyHandle::from_seed_bytes(&seed)
            .expect("seed -> handle");

        let signing_key = SigningKey::try_from(&seed[..]).expect("signing key");
        let msg = b"OTRv4+ v10.6.20 ClientProfile body bytes";
        let sig = signing_key.sign_raw(msg);
        let sig_bytes: [u8; 114] = sig.to_bytes();

        let pub_bytes = handle.pub_bytes;

        let ok = verify_ed448_sig(&pub_bytes, msg, &sig_bytes)
            .expect("verify call");
        assert!(ok, "valid Ed448 signature must verify");
    }

    /// Tampered message must NOT verify.
    #[test]
    fn ed448_verify_rejects_tampered_msg() {
        let seed = [9u8; 57];
        let signing_key = SigningKey::try_from(&seed[..]).expect("signing key");
        let vk = signing_key.verifying_key();
        let pub_bytes: [u8; 57] = vk.to_bytes();

        let sig = signing_key.sign_raw(b"original message");
        let sig_bytes: [u8; 114] = sig.to_bytes();

        let ok = verify_ed448_sig(&pub_bytes, b"tampered message", &sig_bytes)
            .expect("verify call");
        assert!(!ok, "tampered message must not verify");
    }

    /// Wrong-length inputs raise ValueError (structural error, not a
    /// silent false) so the Python caller can tell malformed input
    /// apart from a forged signature.
    #[test]
    fn ed448_verify_rejects_bad_lengths() {
        assert!(verify_ed448_sig(&[0u8; 10], b"x", &[0u8; 114]).is_err());
        assert!(verify_ed448_sig(&[0u8; 57], b"x", &[0u8; 10]).is_err());
    }

    // ── X448 ratchet DH (Phase 5.3h-D stage 2, v10.6.21) ─────────────────────

    /// RFC 7748 §5.2 X448 known-answer vector.
    ///
    /// This is the build-time guard against an X448 desync after the
    /// ratchet DH moves from the Python cryptography library to the Rust
    /// `x448` crate.  RFC 7748 X448 is fully deterministic: a given
    /// (clamped scalar, u-coordinate) pair has exactly one correct
    /// output.  If the `x448` crate reproduces the RFC's published
    /// result here, and OpenSSL (what the cryptography library wraps)
    /// also implements RFC 7748, the two agree byte-for-byte — so a
    /// v10.6.21 Rust-ratchet peer and any older cryptography-library
    /// peer derive identical DH secrets and the ratchet stays in sync.
    ///
    /// Vector (RFC 7748 §5.2, first X448 test):
    ///   input scalar  = 3d262fddf9ec8e88495266fea19a34d2...
    ///   input u-coord = 06fce640fa3487bfda5f6cf2d5263f8a...
    ///   output        = ce3e4ff95a60dc6697da1db1d85e6afb...
    #[test]
    fn x448_rfc7748_known_answer() {
        // RFC 7748 §5.2 — X448 test vector 1.
        let scalar: [u8; 56] = [
            0x3d, 0x26, 0x2f, 0xdd, 0xf9, 0xec, 0x8e, 0x88, 0x49, 0x52, 0x66,
            0xfe, 0xa1, 0x9a, 0x34, 0xd2, 0x88, 0x82, 0xac, 0xef, 0x04, 0x51,
            0x04, 0xd0, 0xd1, 0xaa, 0xe1, 0x21, 0x70, 0x0a, 0x77, 0x9c, 0x98,
            0x4c, 0x24, 0xf8, 0xcd, 0xd7, 0x8f, 0xbf, 0xf4, 0x49, 0x43, 0xeb,
            0xa3, 0x68, 0xf5, 0x4b, 0x29, 0x25, 0x9a, 0x4f, 0x1c, 0x60, 0x0a,
            0xd3,
        ];
        let u_coord: [u8; 56] = [
            0x06, 0xfc, 0xe6, 0x40, 0xfa, 0x34, 0x87, 0xbf, 0xda, 0x5f, 0x6c,
            0xf2, 0xd5, 0x26, 0x3f, 0x8a, 0xad, 0x88, 0x33, 0x4c, 0xbd, 0x07,
            0x43, 0x7f, 0x02, 0x0f, 0x08, 0xf9, 0x81, 0x4d, 0xc0, 0x31, 0xdd,
            0xbd, 0xc3, 0x8c, 0x19, 0xc6, 0xda, 0x25, 0x83, 0xfa, 0x54, 0x29,
            0xdb, 0x94, 0xad, 0xa1, 0x8a, 0xa7, 0xa7, 0xfb, 0x4e, 0xf8, 0xa0,
            0x86,
        ];
        let expected: [u8; 56] = [
            0xce, 0x3e, 0x4f, 0xf9, 0x5a, 0x60, 0xdc, 0x66, 0x97, 0xda, 0x1d,
            0xb1, 0xd8, 0x5e, 0x6a, 0xfb, 0xdf, 0x79, 0xb5, 0x0a, 0x24, 0x12,
            0xd7, 0x54, 0x6d, 0x5f, 0x23, 0x9f, 0xe1, 0x4f, 0xba, 0xad, 0xeb,
            0x44, 0x5f, 0xc6, 0x6a, 0x01, 0xb0, 0x77, 0x9d, 0x98, 0x22, 0x39,
            0x61, 0x11, 0x1e, 0x21, 0x76, 0x62, 0x82, 0xf7, 0x3d, 0xd9, 0x6b,
            0x6f,
        ];

        // x448::Secret::from clamps internally (RFC 7748).  The RFC's
        // worked example feeds the *raw* scalar through the same clamp,
        // so Secret::from(scalar) reproduces the RFC's clamped scalar.
        let sk = x448::Secret::from(scalar);
        let pk = x448::PublicKey::from_bytes(&u_coord)
            .expect("RFC 7748 u-coordinate is a valid point");
        let ss = sk.as_diffie_hellman(&pk)
            .expect("RFC 7748 vector must not be low-order");
        assert_eq!(
            ss.as_bytes()[..], expected[..],
            "x448 crate diverged from RFC 7748 X448 vector — ratchet would desync"
        );
    }

    /// X448KeyHandle.dh symmetry: two independently generated handles
    /// must derive the same shared secret from each other's public key.
    /// This is the property the double ratchet relies on every DH step.
    #[test]
    fn x448_handle_dh_is_symmetric() {
        let alice = generate_x448_keypair().expect("alice keygen");
        let bob   = generate_x448_keypair().expect("bob keygen");

        let alice_priv: [u8; 56] =
            alice.expose_priv_slice().try_into().expect("alice priv 56");
        let bob_priv: [u8; 56] =
            bob.expose_priv_slice().try_into().expect("bob priv 56");

        let alice_sk = x448::Secret::from(alice_priv);
        let bob_sk   = x448::Secret::from(bob_priv);

        let alice_pk = x448::PublicKey::from_bytes(&alice.pub_bytes)
            .expect("alice pub valid");
        let bob_pk   = x448::PublicKey::from_bytes(&bob.pub_bytes)
            .expect("bob pub valid");

        let ss_a = alice_sk.as_diffie_hellman(&bob_pk).expect("a dh");
        let ss_b = bob_sk.as_diffie_hellman(&alice_pk).expect("b dh");

        assert_eq!(
            ss_a.as_bytes()[..], ss_b.as_bytes()[..],
            "X448 DH must be symmetric — ratchet send/recv secrets would not match"
        );
    }
}
