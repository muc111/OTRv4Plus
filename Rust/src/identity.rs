//! Rust-owned identity persistence (decision B1, option B).
//!
//! The problem this solves
//! ----------------------
//! `generate_ed448_keypair()` creates the Ed448 seed inside Rust and there is no
//! PyO3 accessor that returns it: `Ed448KeyHandle::expose_seed_slice` is
//! `pub(crate)`.  That is the property the design depends on -- Python cannot
//! read a long-term private key -- but it also means an identity generated the
//! production way could not be persisted at all.
//!
//! The rejected fix was to generate the seed in Python and rebuild the handle
//! with `from_seed_bytes`.  That works, and costs exactly the property above:
//! the seed becomes a Python object at creation and again at every load, and
//! CPython offers no reliable way to erase it.
//!
//! This module is the accepted fix.  Sealing and unsealing happen INSIDE Rust,
//! using the crate-internal accessors, so only ciphertext ever crosses the
//! boundary.  There is deliberately **no** `get_seed()`, and none may be added:
//! `tests/test_rust_identity_sealing.py` enumerates the module's Python-visible
//! surface and fails if anything seed-shaped appears.
//!
//! What crosses the boundary
//! -------------------------
//! ```text
//!   Python -> Rust : a 32-byte data-encryption key, and an opaque blob
//!   Rust -> Python : an opaque blob, and key HANDLES (never key bytes)
//! ```
//!
//! The data-encryption key is supplied by the caller and is expected to have
//! been unwrapped from an Android Keystore key.  This module does not manage key
//! custody; it is the sealing layer only.
//!
//! Record format
//! -------------
//! ```text
//!   version(1) || nonce(12) || ciphertext || tag(16)
//!
//!   plaintext = ed448_seed(57) || x448_priv(56)          = 113 bytes
//!   AAD       = "otrv4plus.identity" || 0x00 || version || key_id(4, BE)
//! ```
//!
//! A fresh 96-bit nonce is drawn from the OS CSPRNG for every seal, matching the
//! storage design used elsewhere in the application.  `key_id` is bound into the
//! AAD so a record cannot be silently attributed to a different key generation,
//! and the version byte is bound so the framing cannot be reinterpreted.
//!
//! Zeroization
//! -----------
//! The assembled plaintext buffer is a `Zeroizing<Vec<u8>>`, so it is wiped when
//! it drops -- on the success path and on every error path alike.  The handles
//! themselves already hold `SecretBytes<N>`, which is `ZeroizeOnDrop`.
//!
//! This is memory *hygiene*, not a guarantee.  A `Zeroizing` buffer overwrites
//! the allocation it owns; it cannot reach copies the allocator, the kernel, or
//! a `Vec` reallocation may have left elsewhere, and it says nothing about swap
//! or hibernation.  The goal is to minimise how long secrets persist, not to
//! claim memory can be perfectly erased.

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::exceptions::PyValueError;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::key_handles::{Ed448KeyHandle, X448KeyHandle};

/// Record version. Bump only for a framing change, and keep readers for
/// older versions so an existing identity is never orphaned.
const IDENTITY_RECORD_VERSION: u8 = 1;

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const ED448_SEED_LEN: usize = 57;
const X448_PRIV_LEN: usize = 56;
const PLAINTEXT_LEN: usize = ED448_SEED_LEN + X448_PRIV_LEN;
const DEK_LEN: usize = 32;

/// Domain separator. Distinct from every other AAD in the application so an
/// identity record cannot be swapped in for a message or trust record.
const AAD_DOMAIN: &[u8] = b"otrv4plus.identity";

fn build_aad(version: u8, key_id: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_DOMAIN.len() + 6);
    aad.extend_from_slice(AAD_DOMAIN);
    aad.push(0x00);
    aad.push(version);
    aad.extend_from_slice(&key_id.to_be_bytes());
    aad
}

fn cipher_for(dek: &[u8]) -> PyResult<Aes256Gcm> {
    if dek.len() != DEK_LEN {
        return Err(PyValueError::new_err(format!(
            "data-encryption key must be {} bytes, got {}", DEK_LEN, dek.len()
        )));
    }
    Aes256Gcm::new_from_slice(dek)
        .map_err(|_| PyValueError::new_err("invalid data-encryption key"))
}

/// Seal an identity into an opaque, authenticated record.
///
/// The seed and private scalar are read through the crate-internal accessors and
/// never become Python objects. The returned bytes are ciphertext.
#[pyfunction]
pub fn seal_identity<'py>(
    py: Python<'py>,
    ed448: PyRef<'py, Ed448KeyHandle>,
    x448: PyRef<'py, X448KeyHandle>,
    dek: &[u8],
    key_id: u32,
) -> PyResult<Bound<'py, PyBytes>> {
    let cipher = cipher_for(dek)?;

    let seed = ed448.expose_seed_slice();
    let priv_bytes = x448.expose_priv_slice();
    if seed.len() != ED448_SEED_LEN || priv_bytes.len() != X448_PRIV_LEN {
        return Err(PyValueError::new_err("internal: key handle has wrong length"));
    }

    // Zeroizing: wiped on drop, including on the error paths below.
    let mut plaintext = Zeroizing::new(Vec::with_capacity(PLAINTEXT_LEN));
    plaintext.extend_from_slice(seed);
    plaintext.extend_from_slice(priv_bytes);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let aad = build_aad(IDENTITY_RECORD_VERSION, key_id);
    let ciphertext = cipher
        .encrypt(nonce, Payload { msg: plaintext.as_slice(), aad: &aad })
        .map_err(|_| PyValueError::new_err("identity sealing failed"))?;

    let mut record = Vec::with_capacity(1 + NONCE_LEN + ciphertext.len());
    record.push(IDENTITY_RECORD_VERSION);
    record.extend_from_slice(&nonce_bytes);
    record.extend_from_slice(&ciphertext);

    Ok(PyBytes::new(py, &record))
}

/// Open a sealed identity, returning reconstructed handles.
///
/// Returns `(Ed448KeyHandle, X448KeyHandle)`. The recovered secrets go straight
/// into the handles' `SecretBytes` and are never exposed to Python.
///
/// Every failure -- wrong key, tampered record, truncation, unknown version --
/// raises the same undifferentiated error, so a caller cannot learn *why* a
/// record failed to open.
#[pyfunction]
pub fn unseal_identity(
    blob: &[u8],
    dek: &[u8],
    key_id: u32,
) -> PyResult<(Ed448KeyHandle, X448KeyHandle)> {
    let cipher = cipher_for(dek)?;

    // Undifferentiated failure for anything about the record itself.
    let reject = || PyValueError::new_err("identity record could not be opened");

    if blob.len() < 1 + NONCE_LEN + TAG_LEN {
        return Err(reject());
    }
    let version = blob[0];
    if version != IDENTITY_RECORD_VERSION {
        // Refuse rather than guess at a framing this build does not know.
        return Err(reject());
    }

    let nonce = Nonce::from_slice(&blob[1..1 + NONCE_LEN]);
    let ciphertext = &blob[1 + NONCE_LEN..];
    let aad = build_aad(version, key_id);

    let plaintext = Zeroizing::new(
        cipher
            .decrypt(nonce, Payload { msg: ciphertext, aad: &aad })
            .map_err(|_| reject())?,
    );

    if plaintext.len() != PLAINTEXT_LEN {
        return Err(reject());
    }

    // from_seed_bytes / from_priv_bytes take &[u8] and copy into SecretBytes.
    // The slices below borrow the Zeroizing buffer, which is wiped on drop.
    let ed448 = Ed448KeyHandle::from_seed_internal(&plaintext[..ED448_SEED_LEN])?;
    let x448 = X448KeyHandle::from_priv_internal(&plaintext[ED448_SEED_LEN..])?;

    Ok((ed448, x448))
}

/// Generate a fresh identity and seal it in one call.
///
/// Preferred over generate-then-seal from Python: the handles are created and
/// sealed without the caller ever holding an unsealed identity it might
/// mishandle. Returns `(ed448_handle, x448_handle, sealed_record)`.
#[pyfunction]
pub fn create_sealed_identity<'py>(
    py: Python<'py>,
    dek: &[u8],
    key_id: u32,
) -> PyResult<(Ed448KeyHandle, X448KeyHandle, Bound<'py, PyBytes>)> {
    let cipher = cipher_for(dek)?;

    let ed448 = crate::key_handles::generate_ed448_keypair()?;
    let x448 = crate::key_handles::generate_x448_keypair()?;

    let mut plaintext = Zeroizing::new(Vec::with_capacity(PLAINTEXT_LEN));
    plaintext.extend_from_slice(ed448.expose_seed_slice());
    plaintext.extend_from_slice(x448.expose_priv_slice());

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let aad = build_aad(IDENTITY_RECORD_VERSION, key_id);
    let ciphertext = cipher
        .encrypt(nonce, Payload { msg: plaintext.as_slice(), aad: &aad })
        .map_err(|_| PyValueError::new_err("identity sealing failed"))?;

    let mut record = Vec::with_capacity(1 + NONCE_LEN + ciphertext.len());
    record.push(IDENTITY_RECORD_VERSION);
    record.extend_from_slice(&nonce_bytes);
    record.extend_from_slice(&ciphertext);

    Ok((ed448, x448, PyBytes::new(py, &record)))
}

/// Version of the identity record framing this build writes.
#[pyfunction]
pub fn identity_record_version() -> u8 {
    IDENTITY_RECORD_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dek() -> [u8; 32] { [0x2a; 32] }

    #[test]
    fn aad_binds_version_and_key_id() {
        assert_ne!(build_aad(1, 1), build_aad(1, 2));
        assert_ne!(build_aad(1, 1), build_aad(2, 1));
    }

    #[test]
    fn aad_domain_is_separated_from_other_records() {
        let aad = build_aad(1, 1);
        assert!(aad.starts_with(AAD_DOMAIN));
        assert_eq!(aad[AAD_DOMAIN.len()], 0x00);
    }

    #[test]
    fn record_layout_is_the_documented_length() {
        // 1 version + 12 nonce + 113 plaintext + 16 tag
        assert_eq!(1 + NONCE_LEN + PLAINTEXT_LEN + TAG_LEN, 142);
    }

    #[test]
    fn rejects_a_wrong_length_key() {
        assert!(cipher_for(&[0u8; 16]).is_err());
        assert!(cipher_for(&[0u8; 31]).is_err());
        assert!(cipher_for(&dek()).is_ok());
    }
}
