//! ML-DSA-87 (FIPS 204) PyO3 bindings.
//!
//! v10.6.18 (Phase 5.3j): replaces the `otr4_mldsa_ext` C extension.
//!
//! Exposes three functions to Python with byte-identical wire output to
//! the prior C extension (same FIPS 204 ML-KEM-1024 parameter set, same
//! PQClean reference implementation underneath):
//!
//! - `mldsa87_keygen() -> (bytes, bytearray)`
//!     Generates a fresh ML-DSA-87 keypair.  Returns `(pub_bytes, priv_bytearray)`.
//!     Public bytes as immutable `bytes`; private bytes as mutable `bytearray`
//!     so the caller can `_ossl.cleanse(priv)` it.  Same shape as the C
//!     extension's `mldsa87_keygen()`.
//!
//! - `mldsa87_sign(priv: bytes, msg: bytes) -> bytes`
//!     Signs `msg` with the ML-DSA-87 secret key.  Returns the 4627-byte
//!     detached signature (FIPS 204 §5.4).  Wire-identical to the C
//!     extension output.  Raises `ValueError` on invalid private key bytes.
//!
//! - `mldsa87_verify(pub: bytes, msg: bytes, sig: bytes) -> bool`
//!     Verifies a detached signature.  Returns `True` on success, `False`
//!     on any failure (parse error, signature mismatch).  Never raises;
//!     matches the C extension's tolerant verify behaviour so the
//!     Python `MLDSA87Auth.verify()` classmethod logic stays unchanged.
//!
//! Byte sizes (FIPS 204 §4 — ML-DSA-87 parameter set):
//!   Public key: 2592 bytes  (PQCLEAN_MLDSA87_CLEAN_CRYPTO_PUBLICKEYBYTES)
//!   Secret key: 4896 bytes  (PQCLEAN_MLDSA87_CLEAN_CRYPTO_SECRETKEYBYTES)
//!   Signature:  4627 bytes  (PQCLEAN_MLDSA87_CLEAN_CRYPTO_BYTES)
//!
//! Implementation note: `pqcrypto-mldsa` is pinned to
//! `default-features = false, features = ["std"]` in Cargo.toml to disable
//! the AVX2 and NEON code paths, which caused SIGILL on Termux/aarch64
//! the same way `pqcrypto-mlkem` did before its hardening.  The portable
//! C reference implementation is used.

use pyo3::prelude::*;
use pyo3::types::{PyByteArray, PyBytes};
use pyo3::exceptions::PyValueError;

use pqcrypto_mldsa::mldsa87;
use pqcrypto_traits::sign::{
    PublicKey       as _PqPubKey,
    SecretKey       as _PqSecKey,
    DetachedSignature as _PqSig,
};

/// Generate a fresh ML-DSA-87 keypair.
///
/// Returns `(pub_bytes, priv_bytearray)`.  Private bytes are a `bytearray`
/// (mutable) so the caller can `_ossl.cleanse` them on key destruction.
#[pyfunction]
pub fn mldsa87_keygen<'py>(py: Python<'py>) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyByteArray>)> {
    let (pk, sk) = mldsa87::keypair();
    let pub_bytes  = PyBytes::new(py, pk.as_bytes());
    let priv_array = PyByteArray::new(py, sk.as_bytes());
    Ok((pub_bytes, priv_array))
}

/// Sign a message with the ML-DSA-87 secret key.
///
/// Returns a 4627-byte detached signature.  Raises `ValueError` if the
/// private key bytes are the wrong length or otherwise invalid.
#[pyfunction]
pub fn mldsa87_sign<'py>(py: Python<'py>, priv_bytes: &[u8], msg: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    let sk = mldsa87::SecretKey::from_bytes(priv_bytes)
        .map_err(|_| PyValueError::new_err(
            "mldsa87_sign: invalid secret key bytes (expected 4896 bytes)"
        ))?;
    let sig = mldsa87::detached_sign(msg, &sk);
    Ok(PyBytes::new(py, sig.as_bytes()))
}

/// Verify an ML-DSA-87 detached signature.
///
/// Returns `True` on successful verification, `False` on any failure
/// (parse error in pub/sig, length mismatch, signature invalid).
/// Never raises — same tolerant behaviour as the C extension it replaces.
#[pyfunction]
pub fn mldsa87_verify(pub_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> PyResult<bool> {
    let pk = match mldsa87::PublicKey::from_bytes(pub_bytes) {
        Ok(k)  => k,
        Err(_) => return Ok(false),
    };
    let sig = match mldsa87::DetachedSignature::from_bytes(sig_bytes) {
        Ok(s)  => s,
        Err(_) => return Ok(false),
    };
    Ok(mldsa87::verify_detached_signature(&sig, msg, &pk).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip: keygen, sign, verify — known-good input.
    #[test]
    fn mldsa87_roundtrip_succeeds() {
        let (pk, sk) = mldsa87::keypair();
        let msg = b"OTRv4+ v10.6.18 mldsa87 round-trip";
        let sig = mldsa87::detached_sign(msg, &sk);
        assert!(
            mldsa87::verify_detached_signature(&sig, msg, &pk).is_ok(),
            "fresh keypair should sign and verify cleanly"
        );
    }

    /// Tampered message must fail to verify.
    #[test]
    fn mldsa87_tampered_msg_rejected() {
        let (pk, sk) = mldsa87::keypair();
        let msg     = b"original";
        let tampered = b"original!";
        let sig = mldsa87::detached_sign(msg, &sk);
        assert!(
            mldsa87::verify_detached_signature(&sig, tampered, &pk).is_err(),
            "tampered message must not verify"
        );
    }

    /// FIPS 204 ML-DSA-87 byte sizes (sanity check that
    /// pqcrypto-mldsa hasn't shifted constants between releases).
    #[test]
    fn mldsa87_byte_sizes_match_spec() {
        let (pk, sk) = mldsa87::keypair();
        assert_eq!(pk.as_bytes().len(), 2592, "ML-DSA-87 pubkey must be 2592 bytes");
        assert_eq!(sk.as_bytes().len(), 4896, "ML-DSA-87 seckey must be 4896 bytes");
        let sig = mldsa87::detached_sign(b"x", &sk);
        assert_eq!(sig.as_bytes().len(), 4627, "ML-DSA-87 signature must be 4627 bytes");
    }
}
