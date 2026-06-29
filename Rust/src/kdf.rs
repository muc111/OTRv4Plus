//! OTRv4 Key Derivation Functions.
//!
//! All KDF calls go through this module.  Every usage_id is domain-separated
//! per OTRv4 spec §3.2:
//!     KDF(usage_id || value, size) = SHAKE-256("OTRv4" || usage_id || value, size)
//!
//! Hardening:
//!   * `kdf_1_py` PyO3 export is gated behind `test-only-kdf` feature.
//!     Production builds (`--features pq-rust` only) do not expose the KDF.
//!   * No `expect()` on attacker-controlled inputs.  Internal invariants
//!     (HMAC-SHA3-512 always accepts any key length) use `expect()` guarded
//!     by the type system.

use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};
use crate::secure_mem::SecretBytes;
use crate::error::{OtrError, Result};
use zeroize::Zeroize;

const KDF_DOMAIN: &[u8] = b"OTRv4";

#[allow(dead_code)]
pub mod usage {
    pub const SSID:             u8 = 0x01;
    pub const BRACE_KEY:        u8 = 0x02;
    pub const SHARED_SECRET:    u8 = 0x03;
    pub const AUTH_R_MAC:       u8 = 0x04;
    pub const AUTH_I_MSG:       u8 = 0x05;
    pub const ROOT_KEY:         u8 = 0x11;
    pub const CHAIN_KEY:        u8 = 0x12;
    pub const MESSAGE_KEY:      u8 = 0x13;
    pub const MAC_KEY:          u8 = 0x14;
    pub const DAKE_MAC_KEY:     u8 = 0x15;
    pub const BRACE_KEY_ROTATE: u8 = 0x16;
    pub const EXTRA_SYM_KEY:    u8 = 0x1F;
    pub const PQ_BRACE_KEY:     u8 = 0x20;
    pub const NONCE_DERIVE:     u8 = 0x21;
}

// ── Core KDF ─────────────────────────────────────────────────────────────────

pub fn kdf_1(usage_id: u8, value: &[u8], output_len: usize) -> Vec<u8> {
    let mut h = Shake256::default();
    Update::update(&mut h, KDF_DOMAIN);
    Update::update(&mut h, &[usage_id]);
    Update::update(&mut h, value);
    let mut out = vec![0u8; output_len];
    h.finalize_xof().read(&mut out);
    out
}

pub fn kdf_secret<const N: usize>(usage_id: u8, value: &[u8]) -> SecretBytes<N> {
    let mut raw = kdf_1(usage_id, value, N);
    let mut arr = [0u8; N];
    // Length is N by construction of kdf_1; copy_from_slice is safe.
    arr.copy_from_slice(&raw);
    raw.zeroize();   // audit M2: wipe the heap copy of the secret
    SecretBytes::new(arr)
}

// ── PyO3 bridge - TEST ONLY ──────────────────────────────────────────────────
#[cfg(feature = "test-only-kdf")]
#[pyo3::pyfunction]
#[pyo3(name = "kdf_1")]
pub fn kdf_1_py(usage_id: u8, value: &[u8], output_len: usize) -> pyo3::PyResult<Vec<u8>> {
    if output_len == 0 {
        return Err(pyo3::exceptions::PyValueError::new_err("output_len must be > 0"));
    }
    if output_len > (1 << 20) {
        return Err(pyo3::exceptions::PyValueError::new_err("output_len too large"));
    }
    Ok(kdf_1(usage_id, value, output_len))
}

// ── Ratchet KDF ──────────────────────────────────────────────────────────────

/// Advance a chain key one step. Returns (next_ck, message_key, zeros).
pub fn kdf_chain(chain_key: &[u8; 32]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let mut new_ck = kdf_1(usage::CHAIN_KEY, chain_key, 32);
    let mut mk     = kdf_1(usage::MESSAGE_KEY, chain_key, 32);

    let mut ck_arr = [0u8; 32];
    let mut mk_arr = [0u8; 32];
    ck_arr.copy_from_slice(&new_ck);
    mk_arr.copy_from_slice(&mk);
    // Audit M2: wipe the heap copies of the derived key material.
    new_ck.zeroize();
    mk.zeroize();
    (ck_arr, mk_arr, [0u8; 32])
}

pub fn kdf_root(root_key: &[u8; 32], dh_output: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut input = Vec::with_capacity(32 + dh_output.len());
    input.extend_from_slice(root_key);
    input.extend_from_slice(dh_output);
    let mut raw = kdf_1(usage::ROOT_KEY, &input, 64);
    input.zeroize();
    let mut new_root  = [0u8; 32];
    let mut new_chain = [0u8; 32];
    new_root.copy_from_slice(&raw[..32]);
    new_chain.copy_from_slice(&raw[32..]);
    raw.zeroize();   // audit M2
    (new_root, new_chain)
}

pub fn kdf_brace_rotate(brace_key: &[u8; 32], mlkem_ss: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(32 + mlkem_ss.len());
    input.extend_from_slice(brace_key);
    input.extend_from_slice(mlkem_ss);
    let mut raw = kdf_1(usage::BRACE_KEY_ROTATE, &input, 32);
    input.zeroize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    raw.zeroize();   // audit M2
    out
}

// ── 64-byte variants ─────────────────────────────────────────────────────────

pub fn derive_ratchet_keys(
    root_key: &[u8; 64],
    shared_secret: &[u8],
) -> (SecretBytes<64>, SecretBytes<64>) {
    let mut input = Vec::with_capacity(64 + shared_secret.len());
    input.extend_from_slice(root_key);
    input.extend_from_slice(shared_secret);
    let mut raw = kdf_1(usage::ROOT_KEY, &input, 128);
    input.zeroize();
    let mut new_root  = [0u8; 64];
    let mut new_chain = [0u8; 64];
    new_root.copy_from_slice(&raw[..64]);
    new_chain.copy_from_slice(&raw[64..]);
    raw.zeroize();   // audit M2
    (SecretBytes::new(new_root), SecretBytes::new(new_chain))
}

pub fn derive_brace_key(old_brace: &[u8; 32], mlkem_ss: &[u8]) -> SecretBytes<32> {
    let mut input = Vec::with_capacity(32 + mlkem_ss.len());
    input.extend_from_slice(old_brace);
    input.extend_from_slice(mlkem_ss);
    let r = kdf_secret::<32>(usage::BRACE_KEY, &input);
    input.zeroize();
    r
}

pub fn derive_ssid(shared_secret: &[u8]) -> [u8; 8] {
    let mut raw = kdf_1(usage::SSID, shared_secret, 8);
    let mut out = [0u8; 8];
    out.copy_from_slice(&raw);
    raw.zeroize();   // audit M2 (ssid is public, but keep the path uniform)
    out
}

// ── MAC / fingerprint ────────────────────────────────────────────────────────

pub fn hmac_sha3_512(key: &[u8], data: &[u8]) -> [u8; 64] {
    use hmac::{Hmac, Mac};
    use sha3::Sha3_512;
    // HMAC accepts any key length; this expect cannot fire.
    let mut mac = <Hmac<Sha3_512> as Mac>::new_from_slice(key)
        .expect("HMAC-SHA3-512 NewFromSlice is infallible by construction");
    Mac::update(&mut mac, data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 64];
    out.copy_from_slice(&result);
    out
}

pub fn fingerprint_sha3_512(public_key_bytes: &[u8]) -> [u8; 64] {
    use sha3::{Sha3_512, Digest};
    let mut h = Sha3_512::new();
    Digest::update(&mut h, public_key_bytes);
    let r = h.finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(&r);
    out
}

pub fn verify_mac(key: &[u8], data: &[u8], expected: &[u8; 64]) -> Result<()> {
    let computed = hmac_sha3_512(key, data);
    if crate::secure_mem::ct_eq(&computed, expected) {
        Ok(())
    } else {
        Err(OtrError::AeadDecrypt)
    }
}
