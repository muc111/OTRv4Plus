//! AES-256-GCM PyO3 bindings.
//!
//! v10.6.19 (Phase 5.3h, part B): replaces the
//! `cryptography.hazmat.primitives.ciphers.aead.AESGCM` Python uses in the
//! `SMPAutoRespondStorage` and `SecureKeyStorage` classes.
//!
//! Wraps the `aes-gcm` crate (already a Rust dependency for the ratchet
//! message-key path).  Exposes a stateless API that exactly matches the
//! cryptography library's call shape so the Python edits are one-line
//! swaps:
//!
//!     # before
//!     AESGCM(key).encrypt(nonce, plaintext, aad)
//!     AESGCM(key).decrypt(nonce, ct_and_tag, aad)
//!
//!     # after
//!     otrv4_core.aes256gcm_encrypt(key, nonce, plaintext, aad)
//!     otrv4_core.aes256gcm_decrypt(key, nonce, ct_and_tag, aad)
//!
//! Wire format (output of encrypt / input to decrypt) is `ciphertext || tag`,
//! with the 16-byte tag at the end.  This matches the cryptography library's
//! behaviour byte-for-byte — files written by the previous AESGCM code can
//! still be decrypted after the Python swap.
//!
//! Constraints:
//!   - key MUST be 32 bytes (AES-256).  ValueError on any other length.
//!   - nonce MUST be 12 bytes (96-bit, GCM-standard).  ValueError on any
//!     other length.
//!   - aad MAY be empty.  Both peers must agree on the AAD or decrypt fails.
//!
//! Decrypt returns ValueError on any failure (length mismatch, tag
//! verification failure, malformed ciphertext) — never raises an opaque
//! Rust panic.  Matches the cryptography library's `InvalidTag` behaviour
//! generically enough that callers wrapping in `try / except Exception`
//! continue to work unchanged.

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::exceptions::PyValueError;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};

/// Encrypt with AES-256-GCM.
///
/// Returns `ciphertext || 16-byte tag`.  Wire-identical to
/// `cryptography.hazmat.primitives.ciphers.aead.AESGCM(key).encrypt(
///     nonce, plaintext, aad)`.
#[pyfunction]
pub fn aes256gcm_encrypt<'py>(
    py: Python<'py>,
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    if key.len() != 32 {
        return Err(PyValueError::new_err(
            "aes256gcm_encrypt: key must be exactly 32 bytes (AES-256)"
        ));
    }
    if nonce.len() != 12 {
        return Err(PyValueError::new_err(
            "aes256gcm_encrypt: nonce must be exactly 12 bytes (GCM 96-bit)"
        ));
    }

    // v10.7.4 (Phase 5.3i-D): non-deprecated key/nonce construction.
    // Aes256Gcm::new_from_slice (KeyInit trait) takes &[u8] and length-checks.
    // For the nonce, GenericArray has no TryFrom<&[u8]>; the non-deprecated
    // path is &[u8] -> &[u8; 12] (slice TryInto) then Nonce::from(&array).
    // Key and nonce lengths are already validated above, so both conversions
    // are infallible here; mapped to ValueError defensively.
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| PyValueError::new_err(
            "aes256gcm_encrypt: invalid key length"
        ))?;
    let nonce_arr: &[u8; 12] = nonce.try_into()
        .map_err(|_| PyValueError::new_err(
            "aes256gcm_encrypt: invalid nonce length"
        ))?;
    let n = Nonce::from(*nonce_arr);

    let ct_with_tag = cipher
        .encrypt(&n, Payload { msg: plaintext, aad })
        .map_err(|_| PyValueError::new_err(
            "aes256gcm_encrypt: internal encryption failure"
        ))?;

    Ok(PyBytes::new(py, &ct_with_tag))
}

/// Decrypt with AES-256-GCM.
///
/// Accepts `ciphertext || 16-byte tag`.  Wire-identical to the cryptography
/// library `decrypt`.  Returns plaintext on success; raises `ValueError` on
/// any authentication or input-format failure.
#[pyfunction]
pub fn aes256gcm_decrypt<'py>(
    py: Python<'py>,
    key: &[u8],
    nonce: &[u8],
    ct_and_tag: &[u8],
    aad: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    if key.len() != 32 {
        return Err(PyValueError::new_err(
            "aes256gcm_decrypt: key must be exactly 32 bytes (AES-256)"
        ));
    }
    if nonce.len() != 12 {
        return Err(PyValueError::new_err(
            "aes256gcm_decrypt: nonce must be exactly 12 bytes (GCM 96-bit)"
        ));
    }
    if ct_and_tag.len() < 16 {
        return Err(PyValueError::new_err(
            "aes256gcm_decrypt: ciphertext-with-tag must be at least 16 bytes"
        ));
    }

    // v10.7.4 (Phase 5.3i-D): non-deprecated key/nonce construction.
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| PyValueError::new_err(
            "aes256gcm_decrypt: invalid key length"
        ))?;
    let nonce_arr: &[u8; 12] = nonce.try_into()
        .map_err(|_| PyValueError::new_err(
            "aes256gcm_decrypt: invalid nonce length"
        ))?;
    let n = Nonce::from(*nonce_arr);

    let plaintext = cipher
        .decrypt(&n, Payload { msg: ct_and_tag, aad })
        .map_err(|_| PyValueError::new_err(
            "aes256gcm_decrypt: authentication failed (wrong key, nonce, aad, or tampered ciphertext)"
        ))?;

    Ok(PyBytes::new(py, &plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip: encrypt then decrypt with the same key/nonce/aad.
    #[test]
    fn aead_roundtrip_succeeds() {
        let key  = [0x11u8; 32];
        let n    = [0x22u8; 12];
        let pt   = b"OTRv4+ v10.6.19 aead round-trip";
        let aad  = b"smp_secrets_v1";

        let cipher = Aes256Gcm::new_from_slice(&key).expect("test key is 32 bytes");
        let ct = cipher.encrypt(&Nonce::from(n),
            Payload { msg: pt, aad }).expect("encrypt");
        let recovered = cipher.decrypt(&Nonce::from(n),
            Payload { msg: &ct, aad }).expect("decrypt");
        assert_eq!(&recovered[..], &pt[..]);
    }

    /// Wrong AAD must fail.
    #[test]
    fn aead_wrong_aad_rejected() {
        let key  = [0x33u8; 32];
        let n    = [0x44u8; 12];
        let pt   = b"hello";
        let cipher = Aes256Gcm::new_from_slice(&key).expect("test key is 32 bytes");
        let ct = cipher.encrypt(&Nonce::from(n),
            Payload { msg: pt, aad: b"aad1" }).expect("encrypt");
        let result = cipher.decrypt(&Nonce::from(n),
            Payload { msg: &ct, aad: b"aad2" });
        assert!(result.is_err(), "wrong aad must reject");
    }

    /// Tampered ciphertext must fail.
    #[test]
    fn aead_tampered_ct_rejected() {
        let key  = [0x55u8; 32];
        let n    = [0x66u8; 12];
        let pt   = b"original";
        let aad  = b"";
        let cipher = Aes256Gcm::new_from_slice(&key).expect("test key is 32 bytes");
        let mut ct = cipher.encrypt(&Nonce::from(n),
            Payload { msg: pt, aad }).expect("encrypt");
        // flip a byte in the ciphertext
        ct[0] ^= 0x01;
        let result = cipher.decrypt(&Nonce::from(n),
            Payload { msg: &ct, aad });
        assert!(result.is_err(), "tampered ct must reject");
    }
}
