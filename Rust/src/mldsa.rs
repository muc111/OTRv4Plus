//! ML-DSA-87 (FIPS 204) PyO3 bindings.
//!
//! v10.6.18 (Phase 5.3j): replaces the `otr4_mldsa_ext` C extension.
//!
//! Exposes three functions to Python with byte-identical wire output to
//! the prior C extension (same FIPS 204 ML-DSA-87 parameter set, same
//! PQClean reference implementation underneath):
//!
//! - `mldsa87_keygen() -> (bytes, bytearray)`
//!   Generates a fresh ML-DSA-87 keypair.  Returns `(pub_bytes, priv_bytearray)`.
//!   Public bytes as immutable `bytes`; private bytes as mutable `bytearray`
//!   so the caller can `_ossl.cleanse(priv)` it.  Same shape as the C
//!   extension's `mldsa87_keygen()`.
//!
//! - `mldsa87_sign(priv: bytes, msg: bytes) -> bytes`
//!   Signs `msg` with the ML-DSA-87 secret key.  Returns the 4627-byte
//!   detached signature (FIPS 204 §5.4).  Wire-identical to the C
//!   extension output.  Raises `ValueError` on invalid private key bytes.
//!
//! - `mldsa87_verify(pub: bytes, msg: bytes, sig: bytes) -> bool`
//!   Verifies a detached signature.  Returns `True` on success, `False`
//!   on any failure (parse error, signature mismatch).  Never raises;
//!   matches the C extension's tolerant verify behaviour so the
//!   Python `MLDSA87Auth.verify()` classmethod logic stays unchanged.
//!
//! Byte sizes (FIPS 204 §4 - ML-DSA-87 parameter set):
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
/// Never raises - same tolerant behaviour as the C extension it replaces.
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

/// An ML-DSA-87 signing key that never leaves Rust.
///
/// `mldsa87_keygen` returns the 4896-byte secret key to Python, and the DAKE
/// held it in a `bytearray` for the life of every session -- then passed
/// `bytes(priv)` to `mldsa87_sign`, making a fresh, unwipeable copy on each
/// signature. This handle replaces that: Python can read the public key and
/// ask for a signature, and nothing else.
#[pyclass(name = "MlDsa87KeyHandle")]
pub struct MlDsa87KeyHandle {
    public: Vec<u8>,
    secret: Option<crate::secure_mem::SecretVec>,
}

#[pymethods]
impl MlDsa87KeyHandle {
    #[new]
    fn new() -> Self {
        let (pk, sk) = mldsa87::keypair();
        Self {
            public: pk.as_bytes().to_vec(),
            secret: Some(crate::secure_mem::SecretVec::from_slice(sk.as_bytes())),
        }
    }

    /// The 2592-byte public key.
    #[getter]
    fn public_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.public)
    }

    /// A 4627-byte detached signature over `msg`.
    fn sign<'py>(&self, py: Python<'py>, msg: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let secret = self.secret.as_ref().ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err(
                "ML-DSA-87 signing key has been destroyed")
        })?;
        let sk = mldsa87::SecretKey::from_bytes(secret.expose())
            .map_err(|_| PyValueError::new_err("internal: invalid ML-DSA-87 secret key"))?;
        let sig = mldsa87::detached_sign(msg, &sk);
        Ok(PyBytes::new(py, sig.as_bytes()))
    }

    /// Destroy the signing key. Idempotent.
    fn zeroize(&mut self) { self.secret = None; }

    #[getter]
    fn destroyed(&self) -> bool { self.secret.is_none() }

    fn __repr__(&self) -> String {
        format!("<MlDsa87KeyHandle destroyed={}>", self.secret.is_none())
    }
}

impl MlDsa87KeyHandle {
    /// A fresh keypair, for Rust callers and tests.
    #[cfg(test)]
    pub(crate) fn generate() -> Self { Self::new() }

    /// The public key, for Rust callers.
    #[cfg(test)]
    pub(crate) fn public_key(&self) -> &[u8] { &self.public }

    /// A detached signature, for Rust callers (the DAKE3 signer). The
    /// secret never becomes a Python object.
    pub(crate) fn sign_internal(&self, msg: &[u8]) -> Result<Vec<u8>, &'static str> {
        let secret = self.secret.as_ref().ok_or("ML-DSA-87 signing key has been destroyed")?;
        let sk = mldsa87::SecretKey::from_bytes(secret.expose())
            .map_err(|_| "invalid ML-DSA-87 secret key")?;
        Ok(mldsa87::detached_sign(msg, &sk).as_bytes().to_vec())
    }
}

// ── A persistent ML-DSA-87 identity (audit A2) ─────────────────────────────
//
// A fresh ML-DSA key per handshake authenticates nothing: anyone can make one.
// The long-term key is created once, sealed here under the identity DEK, and
// reloaded on every start, so a peer can pin it. Same construction as
// identity.rs; only ciphertext crosses into Python.
//
//   record    = version(1) || nonce(12) || AES-256-GCM(sk(4896) || pk(2592)) || tag(16)
//   AAD       = "otrv4plus.mldsa-identity" || 0x00 || version || key_id(4, BE)

const MLDSA_RECORD_VERSION: u8 = 1;
const MLDSA_AAD_DOMAIN: &[u8] = b"otrv4plus.mldsa-identity";
const MLDSA_SK_LEN: usize = 4896;
const MLDSA_PK_LEN: usize = 2592;

fn mldsa_aad(version: u8, key_id: u32) -> Vec<u8> {
    let mut aad = MLDSA_AAD_DOMAIN.to_vec();
    aad.push(0x00);
    aad.push(version);
    aad.extend_from_slice(&key_id.to_be_bytes());
    aad
}

impl MlDsa87KeyHandle {
    pub(crate) fn seal(&self, dek: &[u8], key_id: u32) -> Result<Vec<u8>, &'static str> {
        use aes_gcm::aead::{Aead, KeyInit, Payload};
        use rand_core::{OsRng, RngCore};
        let secret = self.secret.as_ref().ok_or("ML-DSA-87 signing key has been destroyed")?;
        let cipher = aes_gcm::Aes256Gcm::new_from_slice(dek).map_err(|_| "bad key")?;
        let mut plain = zeroize::Zeroizing::new(Vec::with_capacity(MLDSA_SK_LEN + MLDSA_PK_LEN));
        plain.extend_from_slice(secret.expose());
        plain.extend_from_slice(&self.public);
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let aad = mldsa_aad(MLDSA_RECORD_VERSION, key_id);
        let ct = cipher
            .encrypt(&aes_gcm::Nonce::from(nonce), Payload { msg: &plain, aad: &aad })
            .map_err(|_| "seal failed")?;
        let mut out = vec![MLDSA_RECORD_VERSION];
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    pub(crate) fn unseal(blob: &[u8], dek: &[u8], key_id: u32) -> Result<Self, &'static str> {
        use aes_gcm::aead::{Aead, KeyInit, Payload};
        if blob.len() != 1 + 12 + MLDSA_SK_LEN + MLDSA_PK_LEN + 16 || blob[0] != MLDSA_RECORD_VERSION {
            return Err("not an ML-DSA identity record");
        }
        let cipher = aes_gcm::Aes256Gcm::new_from_slice(dek).map_err(|_| "bad key")?;
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&blob[1..13]);
        let aad = mldsa_aad(blob[0], key_id);
        let plain = zeroize::Zeroizing::new(
            cipher.decrypt(&aes_gcm::Nonce::from(nonce), Payload { msg: &blob[13..], aad: &aad })
                  .map_err(|_| "record failed authentication")?);
        let (sk, pk) = plain.split_at(MLDSA_SK_LEN);
        let h = Self { public: pk.to_vec(), secret: Some(crate::secure_mem::SecretVec::from_slice(sk)) };
        // The pair must be a pair: a record whose halves disagree would sign
        // under a key nobody can verify.
        let probe = h.sign_internal(b"otrv4plus.mldsa-identity.check")?;
        let ok = mldsa87::PublicKey::from_bytes(pk).ok()
            .zip(mldsa87::DetachedSignature::from_bytes(&probe).ok())
            .is_some_and(|(pk, sig)| mldsa87::verify_detached_signature(
                &sig, b"otrv4plus.mldsa-identity.check", &pk).is_ok());
        if !ok { return Err("record holds a mismatched key pair"); }
        Ok(h)
    }
}

/// Seal a long-term ML-DSA-87 identity key under a Rust-held DEK.
#[pyfunction]
pub fn seal_mldsa_identity_under<'py>(
    py: Python<'py>,
    handle: PyRef<'py, MlDsa87KeyHandle>,
    dek: PyRef<'py, crate::at_rest::FileDek>,
    key_id: u32,
) -> PyResult<Bound<'py, PyBytes>> {
    let sealed = handle.seal(dek.expose()?, key_id).map_err(PyValueError::new_err)?;
    Ok(PyBytes::new(py, &sealed))
}

/// Reopen a sealed ML-DSA-87 identity. Raises on any failure, undifferentiated.
#[pyfunction]
pub fn unseal_mldsa_identity_under(
    blob: &[u8],
    dek: PyRef<'_, crate::at_rest::FileDek>,
    key_id: u32,
) -> PyResult<MlDsa87KeyHandle> {
    MlDsa87KeyHandle::unseal(blob, dek.expose()?, key_id)
        .map_err(|_| PyValueError::new_err("ML-DSA identity record could not be opened"))
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_sealed_identity_reopens_as_the_same_key_and_nothing_else_opens_it() {
        let h = MlDsa87KeyHandle::new();
        let blob = h.seal(&[7u8; 32], 1).expect("seal");
        let back = MlDsa87KeyHandle::unseal(&blob, &[7u8; 32], 1).expect("unseal");
        assert_eq!(back.public, h.public);
        assert!(MlDsa87KeyHandle::unseal(&blob, &[8u8; 32], 1).is_err(), "wrong key");
        assert!(MlDsa87KeyHandle::unseal(&blob, &[7u8; 32], 2).is_err(), "wrong key id");
        let mut bad = blob.clone();
        bad[40] ^= 1;
        assert!(MlDsa87KeyHandle::unseal(&bad, &[7u8; 32], 1).is_err(), "tampered");
        assert_ne!(h.seal(&[7u8; 32], 1).unwrap(), blob, "a fresh nonce per seal");
    }

    use super::*;

    /// Round-trip: keygen, sign, verify - known-good input.
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
