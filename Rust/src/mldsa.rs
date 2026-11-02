//! ML-DSA-87 (FIPS 204) PyO3 bindings.
//!
//! Exposes three functions to Python with byte-identical wire output to
//! the prior PQClean implementation (same FIPS 204 ML-DSA-87 parameter set,
//! same key/signature encodings):
//!
//! - `mldsa87_keygen() -> (bytes, bytearray)`
//!   Generates a fresh ML-DSA-87 keypair.  Returns `(pub_bytes, priv_bytearray)`.
//!   Public bytes as immutable `bytes`; private bytes as mutable `bytearray`
//!   so the caller can `_ossl.cleanse(priv)` it.
//!
//! - `mldsa87_sign(priv: bytes, msg: bytes) -> bytes`
//!   Signs `msg` with the ML-DSA-87 secret key.  Returns the 4627-byte
//!   detached signature (FIPS 204 §5.4).  Raises `ValueError` on invalid
//!   private key bytes.
//!
//! - `mldsa87_verify(pub: bytes, msg: bytes, sig: bytes) -> bool`
//!   Verifies a detached signature.  Returns `True` on success, `False`
//!   on any failure (parse error, signature mismatch).  Never raises.
//!
//! Byte sizes (FIPS 204 §4 - ML-DSA-87 parameter set):
//!   Public key: 2592 bytes
//!   Secret key: 4896 bytes  (the expanded signing key)
//!   Signature:  4627 bytes
//!
//! Implementation note (v10.32): the implementation is the pure-Rust
//! RustCrypto `ml-dsa` crate, replacing the unmaintained PQClean C bindings
//! (`pqcrypto-mldsa`). The byte encodings are identical (the secret key is
//! the 4896-byte expanded form, the public key 2592, the detached signature
//! 4627), cross-checked against PQClean in `Rust/audit`. Signing uses the
//! FIPS 204 DETERMINISTIC variant (`sign_deterministic`, empty context), so
//! no randomness is drawn at sign time; the signatures are standard and
//! verify identically. No FFI: the crate keeps `#![forbid(unsafe_code)]`.

use pyo3::prelude::*;
use pyo3::types::{PyByteArray, PyBytes};
use pyo3::exceptions::PyValueError;

use ml_dsa::{MlDsa87, VerifyingKey, Signature, EncodedVerifyingKey, ExpandedSigningKey, B32};

const MLDSA_SK_LEN: usize = 4896;
const MLDSA_PK_LEN: usize = 2592;

// ─── raw byte helpers (one implementation, shared by DAKE / SMP / identity) ───

/// A fresh keypair as `(pk 2592, expanded sk 4896)`, the former PQClean
/// encoding.  Driven by a 32-byte FIPS 204 seed from the OS CSPRNG.
#[allow(deprecated)] // `to_expanded` gives the 4896-byte PQClean-compatible form
pub(crate) fn raw_keypair() -> (Vec<u8>, Vec<u8>) {
    let mut xi = [0u8; 32];
    getrandom::getrandom(&mut xi).expect("OS CSPRNG for ML-DSA key generation");
    let seed: B32 = xi.into();
    xi.iter_mut().for_each(|b| *b = 0);
    let esk = ExpandedSigningKey::<MlDsa87>::from_seed(&seed);
    let pk = esk.verifying_key().encode().as_slice().to_vec();
    let sk = esk.to_expanded().as_slice().to_vec();
    (pk, sk)
}

/// A 4627-byte detached signature over `msg` under the expanded secret key
/// `sk` (4896), empty FIPS 204 context, deterministic.  `None` on a
/// malformed secret key.
#[allow(deprecated)] // `from_expanded` consumes the 4896-byte PQClean-compatible form
pub(crate) fn raw_sign(sk: &[u8], msg: &[u8]) -> Option<Vec<u8>> {
    let esk = ExpandedSigningKey::<MlDsa87>::from_expanded(&sk.try_into().ok()?);
    let sig = esk.sign_deterministic(msg, b"").ok()?;
    Some(sig.encode().as_slice().to_vec())
}

/// Verify a detached signature.  `false` on any failure (bad key, bad
/// signature, or an invalid signature).  Empty FIPS 204 context.
pub(crate) fn raw_verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let vk_enc: EncodedVerifyingKey<MlDsa87> = match pk.try_into() {
        Ok(v) => v,
        Err(_) => return false,
    };
    let vk = VerifyingKey::<MlDsa87>::decode(&vk_enc);
    let signature = match Signature::<MlDsa87>::try_from(sig) {
        Ok(s) => s,
        Err(_) => return false,
    };
    vk.verify_with_context(msg, b"", &signature)
}

/// Generate a fresh ML-DSA-87 keypair.
///
/// Returns `(pub_bytes, priv_bytearray)`.  Private bytes are a `bytearray`
/// (mutable) so the caller can `_ossl.cleanse` them on key destruction.
#[pyfunction]
pub fn mldsa87_keygen<'py>(py: Python<'py>) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyByteArray>)> {
    let (pk, sk) = raw_keypair();
    let pub_bytes  = PyBytes::new(py, &pk);
    let priv_array = PyByteArray::new(py, &sk);
    Ok((pub_bytes, priv_array))
}

/// Sign a message with the ML-DSA-87 secret key.
///
/// Returns a 4627-byte detached signature.  Raises `ValueError` if the
/// private key bytes are the wrong length or otherwise invalid.
#[pyfunction]
pub fn mldsa87_sign<'py>(py: Python<'py>, priv_bytes: &[u8], msg: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    let sig = raw_sign(priv_bytes, msg).ok_or_else(|| {
        PyValueError::new_err("mldsa87_sign: invalid secret key bytes (expected 4896 bytes)")
    })?;
    Ok(PyBytes::new(py, &sig))
}

/// Verify an ML-DSA-87 detached signature.
///
/// Returns `True` on successful verification, `False` on any failure
/// (parse error in pub/sig, length mismatch, signature invalid).
/// Never raises.
#[pyfunction]
pub fn mldsa87_verify(pub_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> PyResult<bool> {
    Ok(raw_verify(pub_bytes, msg, sig_bytes))
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
        let (pk, sk) = raw_keypair();
        Self {
            public: pk,
            secret: Some(crate::secure_mem::SecretVec::from_slice(&sk)),
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
        let sig = raw_sign(secret.expose(), msg)
            .ok_or_else(|| PyValueError::new_err("internal: invalid ML-DSA-87 secret key"))?;
        Ok(PyBytes::new(py, &sig))
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
        raw_sign(secret.expose(), msg).ok_or("invalid ML-DSA-87 secret key")
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
        let ok = raw_verify(pk, b"otrv4plus.mldsa-identity.check", &probe);
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
    use super::*;

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

    /// Round-trip: keygen, sign, verify - known-good input.
    #[test]
    fn mldsa87_roundtrip_succeeds() {
        let (pk, sk) = raw_keypair();
        let msg = b"OTRv4+ mldsa87 round-trip";
        let sig = raw_sign(&sk, msg).expect("sign");
        assert!(raw_verify(&pk, msg, &sig), "fresh keypair should sign and verify cleanly");
    }

    /// Tampered message must fail to verify.
    #[test]
    fn mldsa87_tampered_msg_rejected() {
        let (pk, sk) = raw_keypair();
        let sig = raw_sign(&sk, b"original").expect("sign");
        assert!(!raw_verify(&pk, b"original!", &sig), "tampered message must not verify");
    }

    /// FIPS 204 ML-DSA-87 byte sizes.
    #[test]
    fn mldsa87_byte_sizes_match_spec() {
        let (pk, sk) = raw_keypair();
        assert_eq!(pk.len(), MLDSA_PK_LEN, "ML-DSA-87 pubkey must be 2592 bytes");
        assert_eq!(sk.len(), MLDSA_SK_LEN, "ML-DSA-87 seckey must be 4896 bytes");
        let sig = raw_sign(&sk, b"x").expect("sign");
        assert_eq!(sig.len(), 4627, "ML-DSA-87 signature must be 4627 bytes");
    }
}
