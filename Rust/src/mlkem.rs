//! ML-KEM-1024 (FIPS 203) PyO3 bindings.
//!
//! v10.7.3 (Phase 5.3i-C): replaces the `otr4_crypto_ext` C extension's
//! `mlkem1024_keygen` / `mlkem1024_encaps` / `mlkem1024_decaps` entry
//! points.  After this migration `otr4_crypto_ext` has no remaining
//! callers and is deleted in Phase 5.3k.
//!
//! These three functions back the Python `MLKEM1024BraceKEM` class, which
//! drives the double ratchet's post-quantum brace-key rotation.  The same
//! `pqcrypto-mlkem` crate already powers the DAKE's ML-KEM in `dake.rs`
//! (`generate_mlkem_keypair` / `mlkem_encapsulate` / `mlkem_decapsulate`);
//! this module exposes the identical operations to Python so the brace
//! KEM runs on the same audited code path as the DAKE KEM.
//!
//! Exposed to Python:
//!
//! - `mlkem1024_keygen() -> (bytes, bytearray)`
//!     Generates a fresh ML-KEM-1024 keypair.  Returns
//!     `(encap_key_bytes, decap_key_bytearray)`.  The encapsulation key
//!     (public) is immutable `bytes`; the decapsulation key (private) is
//!     a mutable `bytearray` so the caller can wipe it via `_secure_wipe`
//!     on `MLKEM1024BraceKEM.zeroize()`.  Same shape as the C extension's
//!     `mlkem1024_keygen()`.
//!
//! - `mlkem1024_encaps(ek: bytes) -> (bytes, bytes)`
//!     Encapsulates to a peer's encapsulation key.  Returns
//!     `(ciphertext, shared_secret)` — CIPHERTEXT FIRST.
//!     IMPORTANT: `pqcrypto_mlkem::mlkem1024::encapsulate` returns
//!     `(SharedSecret, Ciphertext)` — the opposite order.  This wrapper
//!     inverts it to `(ct, ss)` to match both the C extension's contract
//!     and the Python caller `ct, ss = MLKEM1024BraceKEM.encapsulate(ek)`.
//!     Getting this order wrong silently desyncs the brace key.
//!     Raises `ValueError` on a malformed encapsulation key.
//!
//! - `mlkem1024_decaps(ct: bytes, dk: bytes) -> bytes`
//!     Decapsulates a ciphertext with our decapsulation (secret) key.
//!     Returns the 32-byte shared secret.  Raises `ValueError` on a
//!     malformed ciphertext or decapsulation key.
//!
//! Byte sizes (FIPS 203 — ML-KEM-1024 parameter set):
//!   Encapsulation key (public):  1568 bytes
//!   Decapsulation key (secret):  3168 bytes
//!   Ciphertext:                  1568 bytes
//!   Shared secret:                 32 bytes
//!
//! Implementation note: `pqcrypto-mlkem` is pinned to
//! `default-features = false, features = ["std"]` in Cargo.toml to disable
//! the AVX2 and NEON code paths, which caused SIGILL on Termux/aarch64
//! (v10.6.16).  The portable PQClean C reference implementation is used.

use pyo3::prelude::*;
use pyo3::types::{PyByteArray, PyBytes};
use pyo3::exceptions::PyValueError;

use pqcrypto_mlkem::mlkem1024;
use pqcrypto_traits::kem::{
    PublicKey    as _PqPubKey,
    SecretKey    as _PqSecKey,
    Ciphertext   as _PqCiphertext,
    SharedSecret as _PqSharedSecret,
};

/// ML-KEM-1024 encapsulation-key (public) length, FIPS 203.
const MLKEM_EK_SIZE: usize = 1568;
/// ML-KEM-1024 ciphertext length, FIPS 203.
const MLKEM_CT_SIZE: usize = 1568;

/// Generate a fresh ML-KEM-1024 keypair.
///
/// Returns `(encap_key_bytes, decap_key_bytearray)`.  The decapsulation
/// (private) key is a `bytearray` so the caller can wipe it in place on
/// key destruction.
#[pyfunction]
pub fn mlkem1024_keygen<'py>(
    py: Python<'py>,
) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyByteArray>)> {
    let (pk, sk) = mlkem1024::keypair();
    let ek_bytes = PyBytes::new(py, pk.as_bytes());
    let dk_array = PyByteArray::new(py, sk.as_bytes());
    Ok((ek_bytes, dk_array))
}

/// Encapsulate to a peer's ML-KEM-1024 encapsulation key.
///
/// Returns `(ciphertext, shared_secret)` — ciphertext first, matching the
/// `otr4_crypto_ext` contract and the Python caller's destructuring.
/// Raises `ValueError` if `ek` is not a valid encapsulation key.
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
    let pk = mlkem1024::PublicKey::from_bytes(ek)
        .map_err(|_| PyValueError::new_err(
            "mlkem1024_encaps: malformed ML-KEM-1024 encapsulation key",
        ))?;
    // pqcrypto returns (SharedSecret, Ciphertext) — invert to (ct, ss).
    let (ss, ct) = mlkem1024::encapsulate(&pk);
    let ct_bytes = PyBytes::new(py, ct.as_bytes());
    let ss_bytes = PyBytes::new(py, ss.as_bytes());
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
    let sk = mlkem1024::SecretKey::from_bytes(dk)
        .map_err(|_| PyValueError::new_err(
            "mlkem1024_decaps: malformed ML-KEM-1024 decapsulation key",
        ))?;
    let ciphertext = mlkem1024::Ciphertext::from_bytes(ct)
        .map_err(|_| PyValueError::new_err(
            "mlkem1024_decaps: malformed ML-KEM-1024 ciphertext",
        ))?;
    let ss = mlkem1024::decapsulate(&ciphertext, &sk);
    Ok(PyBytes::new(py, ss.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip: keygen, encapsulate, decapsulate — both sides must
    /// derive the same shared secret.
    #[test]
    fn mlkem1024_roundtrip_shared_secret_matches() {
        let (pk, sk) = mlkem1024::keypair();
        // encapsulate returns (ss, ct)
        let (ss_enc, ct) = mlkem1024::encapsulate(&pk);
        let ss_dec = mlkem1024::decapsulate(&ct, &sk);
        assert_eq!(
            ss_enc.as_bytes(),
            ss_dec.as_bytes(),
            "encapsulator and decapsulator must agree on the shared secret"
        );
    }

    /// FIPS 203 ML-KEM-1024 byte sizes — guards against pqcrypto-mlkem
    /// shifting constants between releases.
    #[test]
    fn mlkem1024_byte_sizes_match_spec() {
        let (pk, sk) = mlkem1024::keypair();
        assert_eq!(
            pk.as_bytes().len(),
            MLKEM_EK_SIZE,
            "ML-KEM-1024 encapsulation key must be 1568 bytes",
        );
        assert_eq!(
            sk.as_bytes().len(),
            3168,
            "ML-KEM-1024 decapsulation key must be 3168 bytes",
        );
        let (ss, ct) = mlkem1024::encapsulate(&pk);
        assert_eq!(
            ct.as_bytes().len(),
            MLKEM_CT_SIZE,
            "ML-KEM-1024 ciphertext must be 1568 bytes",
        );
        assert_eq!(
            ss.as_bytes().len(),
            32,
            "ML-KEM-1024 shared secret must be 32 bytes",
        );
    }

    /// A ciphertext decapsulated under the wrong secret key must NOT
    /// yield the encapsulator's shared secret.  (ML-KEM's FO transform
    /// returns an implicit-rejection secret rather than failing, so we
    /// assert inequality, not an error.)
    #[test]
    fn mlkem1024_wrong_key_does_not_match() {
        let (pk_a, _sk_a) = mlkem1024::keypair();
        let (_pk_b, sk_b) = mlkem1024::keypair();
        let (ss_enc, ct) = mlkem1024::encapsulate(&pk_a);
        let ss_wrong = mlkem1024::decapsulate(&ct, &sk_b);
        assert_ne!(
            ss_enc.as_bytes(),
            ss_wrong.as_bytes(),
            "decapsulating under the wrong key must not reproduce the secret",
        );
    }
}
