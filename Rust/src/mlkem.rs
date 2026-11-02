//! ML-KEM-1024 (FIPS 203) PyO3 bindings.
//!
//! These three functions back the Python `MLKEM1024BraceKEM` class, which
//! drives the double ratchet's post-quantum brace-key rotation.  The same
//! ML-KEM-1024 implementation powers the DAKE (`dake.rs`) and SMP (`smp.rs`);
//! this module exposes the identical operations to Python so the brace KEM
//! runs on the same audited code path.
//!
//! Exposed to Python:
//!
//! - `mlkem1024_keygen() -> (bytes, bytearray)`
//!   Generates a fresh ML-KEM-1024 keypair.  Returns
//!   `(encap_key_bytes, decap_key_bytearray)`.  The encapsulation key
//!   (public) is immutable `bytes`; the decapsulation key (private) is
//!   a mutable `bytearray` so the caller can wipe it via `_secure_wipe`
//!   on `MLKEM1024BraceKEM.zeroize()`.
//!
//! - `mlkem1024_encaps(ek: bytes) -> (bytes, bytes)`
//!   Encapsulates to a peer's encapsulation key.  Returns
//!   `(ciphertext, shared_secret)` — CIPHERTEXT FIRST, matching the Python
//!   caller `ct, ss = MLKEM1024BraceKEM.encapsulate(ek)`.
//!   Raises `ValueError` on a malformed encapsulation key.
//!
//! - `mlkem1024_decaps(ct: bytes, dk: bytes) -> bytes`
//!   Decapsulates a ciphertext with our decapsulation (secret) key.
//!   Returns the 32-byte shared secret.  Raises `ValueError` on a
//!   malformed ciphertext or decapsulation key.
//!
//! Byte sizes (FIPS 203 — ML-KEM-1024 parameter set):
//!   Encapsulation key (public):  1568 bytes
//!   Decapsulation key (secret):  3168 bytes (the legacy "expanded" form)
//!   Ciphertext:                  1568 bytes
//!   Shared secret:                 32 bytes
//!
//! Implementation note (v10.32): the implementation is the pure-Rust
//! RustCrypto `ml-kem` crate.  It replaced the unmaintained PQClean C
//! bindings (`pqcrypto-mlkem`); the byte encodings are identical (the
//! decapsulation key is the 3168-byte expanded form, cross-checked against
//! PQClean in `Rust/audit`).  A fresh ML-KEM keypair is produced from a
//! 64-byte FIPS 203 seed (`d || z`) and encapsulation draws a 32-byte `m`
//! from the OS CSPRNG, so the result is a uniformly random keypair /
//! ciphertext exactly as the randomized API gave.  No FFI: the crate keeps
//! `#![forbid(unsafe_code)]`.

use pyo3::prelude::*;
use pyo3::types::{PyByteArray, PyBytes};
use pyo3::exceptions::PyValueError;

use ml_kem::{MlKem1024, EncapsulationKey, DecapsulationKey, Ciphertext, Decapsulate, KeyExport,
             ExpandedDecapsulationKey, B32};
use zeroize::Zeroizing;
use ml_kem::array::Array;
#[allow(deprecated)]
use ml_kem::ExpandedKeyEncoding;

/// ML-KEM-1024 encapsulation-key (public) length, FIPS 203.
pub(crate) const MLKEM_EK_SIZE: usize = 1568;
/// ML-KEM-1024 ciphertext length, FIPS 203.
const MLKEM_CT_SIZE: usize = 1568;
/// ML-KEM-1024 expanded decapsulation-key (secret) length, FIPS 203.
#[cfg(test)]
const MLKEM_DK_SIZE: usize = 3168;

// ─── raw byte helpers (one implementation, shared by DAKE / SMP / ratchet) ────

/// A fresh keypair as `(ek 1568, expanded dk 3168)`, the former PQClean
/// encoding.  Driven by a 64-byte FIPS 203 seed from the OS CSPRNG.
/// The decapsulation key is returned in a wiped buffer, and every
/// intermediate copy (seed, encoded key) is wiped too.
pub(crate) fn raw_keypair() -> (Vec<u8>, Zeroizing<Vec<u8>>) {
    let mut seed = Zeroizing::new([0u8; 64]);
    getrandom::getrandom(&mut seed[..]).expect("OS CSPRNG for ML-KEM key generation");
    let dk = DecapsulationKey::<MlKem1024>::from_seed(Array::from(*seed));
    let ek = dk.encapsulation_key().to_bytes().as_slice().to_vec();
    #[allow(deprecated)]
    let expanded = Zeroizing::new(dk.to_expanded_bytes());
    (ek, Zeroizing::new(expanded.as_slice().to_vec()))
}

/// Encapsulate to `ek` (1568).  Returns `(ciphertext 1568, shared secret 32)`.
/// `None` if `ek` is not a valid encapsulation key.
/// The shared secret, and the randomness `m` that alone determines it, are
/// held in wiped buffers.
pub(crate) fn raw_encapsulate(ek: &[u8]) -> Option<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    let key = EncapsulationKey::<MlKem1024>::new(&Array::try_from(ek).ok()?).ok()?;
    let mut m = Zeroizing::new(B32::default());
    getrandom::getrandom(m.as_mut_slice()).ok()?;
    let (ct, ss) = key.encapsulate_deterministic(&m);
    let ss = Zeroizing::new(ss);
    Some((ct.as_slice().to_vec(), Zeroizing::new(ss.as_slice().to_vec())))
}

/// Decapsulate `ct` (1568) with the expanded decapsulation key `dk` (3168).
/// Returns the 32-byte shared secret, or `None` on a malformed input.
/// FIPS 203 implicit rejection: a tampered ciphertext yields an unrelated
/// secret rather than an error.
pub(crate) fn raw_decapsulate(dk: &[u8], ct: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let dk: Zeroizing<ExpandedDecapsulationKey<MlKem1024>> =
        Zeroizing::new(Array::try_from(dk).ok()?);
    #[allow(deprecated)]
    let key = DecapsulationKey::<MlKem1024>::from_expanded_bytes(&dk).ok()?;
    let ct = Ciphertext::<MlKem1024>::try_from(ct).ok()?;
    let ss = Zeroizing::new(key.decapsulate(&ct));
    Some(Zeroizing::new(ss.as_slice().to_vec()))
}

/// Generate a fresh ML-KEM-1024 keypair.
///
/// Returns `(encap_key_bytes, decap_key_bytearray)`.  The decapsulation
/// (private) key is a `bytearray` so the caller can wipe it in place on
/// key destruction.
#[pyfunction]
pub fn mlkem1024_keygen<'py>(
    py: Python<'py>,
) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyByteArray>)> {
    let (ek, sk) = raw_keypair();
    let ek_bytes = PyBytes::new(py, &ek);
    let dk_array = PyByteArray::new(py, &sk);
    Ok((ek_bytes, dk_array))
}

/// Encapsulate to a peer's ML-KEM-1024 encapsulation key.
///
/// Returns `(ciphertext, shared_secret)` — ciphertext first, matching the
/// Python caller's destructuring.  Raises `ValueError` if `ek` is not a
/// valid encapsulation key.
#[pyfunction]
pub fn mlkem1024_encaps<'py>(
    py: Python<'py>,
    ek: &[u8],
) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    if ek.len() != MLKEM_EK_SIZE {
        return Err(PyValueError::new_err(format!(
            "mlkem1024_encaps: encapsulation key must be {} bytes, got {}",
            MLKEM_EK_SIZE,
            ek.len()
        )));
    }
    let (ct, ss) = raw_encapsulate(ek).ok_or_else(|| {
        PyValueError::new_err("mlkem1024_encaps: malformed ML-KEM-1024 encapsulation key")
    })?;
    let ct_bytes = PyBytes::new(py, &ct);
    let ss_bytes = PyBytes::new(py, &ss);
    Ok((ct_bytes, ss_bytes))
}

/// Decapsulate an ML-KEM-1024 ciphertext with our decapsulation key.
///
/// Returns the 32-byte shared secret.  Raises `ValueError` if the
/// ciphertext or decapsulation key is malformed.
#[pyfunction]
pub fn mlkem1024_decaps<'py>(
    py: Python<'py>,
    ct: &[u8],
    dk: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    if ct.len() != MLKEM_CT_SIZE {
        return Err(PyValueError::new_err(format!(
            "mlkem1024_decaps: ciphertext must be {} bytes, got {}",
            MLKEM_CT_SIZE,
            ct.len()
        )));
    }
    let ss = raw_decapsulate(dk, ct).ok_or_else(|| {
        PyValueError::new_err("mlkem1024_decaps: malformed ML-KEM-1024 decapsulation key or ciphertext")
    })?;
    Ok(PyBytes::new(py, &ss))
}

// ─── Rust-owned keypair ──────────────────────────────────────────────────────

/// An ML-KEM-1024 keypair whose decapsulation key never leaves Rust.
///
/// `mlkem1024_keygen` hands the decapsulation key to Python as a
/// `bytearray` "so the caller can wipe it". That is the wrong shape for a
/// session secret: the wipe is only as good as every intermediate copy
/// (`bytes(dk)` at each decapsulation made another, unwipeable one), and the
/// shared secret came back as immutable `bytes`. The double ratchet's brace
/// rotation and the voice key exchange now use this type instead: Python
/// holds a handle and the public encapsulation key; decapsulation, and
/// whatever the shared secret feeds, happen inside Rust.
///
/// Single use. Decapsulating consumes the decapsulation key whatever the
/// outcome, because an ephemeral KEM key offered to a peer is spent.
#[pyclass(name = "MlKem1024Keypair")]
pub struct MlKemKeypair {
    ek: Vec<u8>,
    dk: Option<crate::secure_mem::SecretVec>,
}

#[pymethods]
impl MlKemKeypair {
    #[new]
    fn py_new() -> Self { Self::generate() }

    /// The encapsulation key. Public by definition.
    #[getter]
    fn encap_key<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.ek)
    }

    /// True once the decapsulation key has been used or destroyed.
    #[getter]
    fn spent(&self) -> bool { self.dk.is_none() }

    /// Destroy the decapsulation key without using it.
    fn zeroize(&mut self) { self.dk = None; }

    fn __repr__(&self) -> String {
        format!("<MlKem1024Keypair spent={}>", self.dk.is_none())
    }
}

impl MlKemKeypair {
    pub(crate) fn ek_bytes(&self) -> &[u8] { &self.ek }
    pub(crate) fn zeroize_key(&mut self) { self.dk = None; }

    pub(crate) fn generate() -> Self {
        let (ek, sk) = raw_keypair();
        Self {
            ek,
            dk: Some(crate::secure_mem::SecretVec::from_slice(&sk)),
        }
    }

    /// Decapsulate `ct`, consuming the decapsulation key. Crate-internal:
    /// the shared secret is returned only to Rust callers.
    pub(crate) fn decapsulate_consume(&mut self, ct: &[u8])
        -> PyResult<crate::secure_mem::SecretBytes<32>>
    {
        let ss = self.decapsulate_keep(ct);
        // Spent whether or not `ct` was well formed (a_bad_ciphertext_spends_the_key).
        self.dk = None;
        ss
    }

    /// Decapsulate `ct` and KEEP the decapsulation key. For a caller that
    /// commits only after the message carrying `ct` authenticates (the v2
    /// ratchet, SPEC §5.2): a forged ciphertext must not destroy the key the
    /// genuine one needs. ML-KEM's implicit rejection makes a forged `ct`
    /// yield an unrelated secret, so the forgery then fails its AEAD.
    pub(crate) fn decapsulate_keep(&self, ct: &[u8])
        -> PyResult<crate::secure_mem::SecretBytes<32>>
    {
        let dk = self.dk.as_ref().ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err(
                "this ML-KEM keypair has already been used")
        })?;
        if ct.len() != MLKEM_CT_SIZE {
            return Err(PyValueError::new_err(format!(
                "ML-KEM-1024 ciphertext must be {} bytes, got {}",
                MLKEM_CT_SIZE, ct.len())));
        }
        let ss = raw_decapsulate(dk.expose(), ct).ok_or_else(|| {
            PyValueError::new_err("malformed ML-KEM-1024 decapsulation key or ciphertext")
        })?;
        crate::secure_mem::SecretBytes::<32>::from_slice(&ss)
            .ok_or_else(|| PyValueError::new_err("ML-KEM shared secret has the wrong length"))
    }
}

/// Encapsulate to `ek`, returning `(ciphertext, shared_secret)` with the
/// shared secret kept as a Rust `SecretBytes`. Crate-internal.
pub(crate) fn encapsulate_internal(ek: &[u8])
    -> PyResult<(Vec<u8>, crate::secure_mem::SecretBytes<32>)>
{
    if ek.len() != MLKEM_EK_SIZE {
        return Err(PyValueError::new_err(format!(
            "ML-KEM-1024 encapsulation key must be {} bytes, got {}",
            MLKEM_EK_SIZE, ek.len())));
    }
    let (ct, ss) = raw_encapsulate(ek).ok_or_else(|| {
        PyValueError::new_err("malformed ML-KEM-1024 encapsulation key")
    })?;
    let held = crate::secure_mem::SecretBytes::<32>::from_slice(&ss)
        .ok_or_else(|| PyValueError::new_err("ML-KEM shared secret has the wrong length"))?;
    Ok((ct, held))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip: keygen, encapsulate, decapsulate — both sides must
    /// derive the same shared secret.
    #[test]
    fn mlkem1024_roundtrip_shared_secret_matches() {
        let (ek, dk) = raw_keypair();
        let (ct, ss_enc) = raw_encapsulate(&ek).unwrap();
        let ss_dec = raw_decapsulate(&dk, &ct).unwrap();
        assert_eq!(
            ss_enc, ss_dec,
            "encapsulator and decapsulator must agree on the shared secret"
        );
    }

    /// FIPS 203 ML-KEM-1024 byte sizes.
    #[test]
    fn mlkem1024_byte_sizes_match_spec() {
        let (ek, dk) = raw_keypair();
        assert_eq!(ek.len(), MLKEM_EK_SIZE, "ML-KEM-1024 encapsulation key must be 1568 bytes");
        assert_eq!(dk.len(), MLKEM_DK_SIZE, "ML-KEM-1024 decapsulation key must be 3168 bytes");
        let (ct, ss) = raw_encapsulate(&ek).unwrap();
        assert_eq!(ct.len(), MLKEM_CT_SIZE, "ML-KEM-1024 ciphertext must be 1568 bytes");
        assert_eq!(ss.len(), 32, "ML-KEM-1024 shared secret must be 32 bytes");
    }

    /// A ciphertext decapsulated under the wrong secret key must NOT
    /// yield the encapsulator's shared secret.  (ML-KEM's FO transform
    /// returns an implicit-rejection secret rather than failing, so we
    /// assert inequality, not an error.)
    #[test]
    fn mlkem1024_wrong_key_does_not_match() {
        let (ek_a, _dk_a) = raw_keypair();
        let (_ek_b, dk_b) = raw_keypair();
        let (ct, ss_enc) = raw_encapsulate(&ek_a).unwrap();
        let ss_wrong = raw_decapsulate(&dk_b, &ct).unwrap();
        assert_ne!(
            ss_enc, ss_wrong,
            "decapsulating under the wrong key must not reproduce the secret",
        );
    }

    /// The Rust-owned keypair agrees with the internal encapsulation, and is
    /// single-use: a second decapsulation is refused, not repeated.
    #[test]
    fn owned_keypair_agrees_and_is_single_use() {
        let mut kp = MlKemKeypair::generate();
        let (ct, ss_sender) = encapsulate_internal(&kp.ek).expect("encapsulate");
        let ss_receiver = kp.decapsulate_consume(&ct).expect("decapsulate");
        assert_eq!(ss_sender.expose(), ss_receiver.expose());
        assert!(kp.dk.is_none(), "decapsulation must consume the key");
        assert!(kp.decapsulate_consume(&ct).is_err(), "a spent key was reused");
    }

    /// A short ciphertext still consumes the key: a probe gets one try.
    #[test]
    fn a_bad_ciphertext_spends_the_key() {
        let mut kp = MlKemKeypair::generate();
        assert!(kp.decapsulate_consume(&[0u8; 10]).is_err());
        assert!(kp.dk.is_none());
    }
}
