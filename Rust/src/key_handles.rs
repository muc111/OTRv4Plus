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
    elliptic_curve::generic_array::GenericArray,
    rand_core::{RngCore, OsRng},
};

use zeroize::{Zeroize, ZeroizeOnDrop};
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
        PyBytes::new_bound(py, &self.pub_bytes).unbind()
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
        Ok(PyBytes::new_bound(py, &sig_bytes).unbind())
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
        Ok(PyBytes::new_bound(py, &sig).unbind())
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
        PyBytes::new_bound(py, &self.pub_bytes).unbind()
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
        Ok(PyBytes::new_bound(py, &ss_bytes).unbind())
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
