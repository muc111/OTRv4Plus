// src/kdf.rs — OTRv4 Key Derivation Functions
//
// All KDF calls go through this module.  Every usage_id is domain-separated
// per OTRv4 spec §3.2:
//   KDF(usage_id || value, size) = SHAKE-256("OTRv4" || usage_id || value, size)

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
    let raw = kdf_1(usage_id, value, N);
    let mut arr = [0u8; N];
    arr.copy_from_slice(&raw);
    SecretBytes::new(arr)
}

// ── Ratchet KDF functions (32-byte keys used by DoubleRatchet) ────────────────

/// Advance a chain key one step.
/// Returns (next_chain_key, enc_key, mac_key) — all 32 bytes.
/// KDF("OTRv4" || 0x12 || chain_key, 96) split into 3 × 32.
pub fn kdf_chain(chain_key: &[u8; 32]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let raw = kdf_1(usage::CHAIN_KEY, chain_key, 96);
    let mut next_ck  = [0u8; 32];
    let mut enc_key  = [0u8; 32];
    let mut mac_key  = [0u8; 32];
    next_ck.copy_from_slice(&raw[  ..32]);
    enc_key.copy_from_slice(&raw[32..64]);
    mac_key.copy_from_slice(&raw[64..96]);
    (next_ck, enc_key, mac_key)
}

/// Derive new root + chain keys from old root key and DH shared secret.
/// KDF("OTRv4" || 0x11 || root_key || dh_output, 64) split into 2 × 32.
pub fn kdf_root(root_key: &[u8; 32], dh_output: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut input = Vec::with_capacity(32 + dh_output.len());
    input.extend_from_slice(root_key);
    input.extend_from_slice(dh_output);
    let raw = kdf_1(usage::ROOT_KEY, &input, 64);
    input.zeroize();
    let mut new_root  = [0u8; 32];
    let mut new_chain = [0u8; 32];
    new_root.copy_from_slice(&raw[..32]);
    new_chain.copy_from_slice(&raw[32..]);
    (new_root, new_chain)
}

/// Rotate the brace key using an ML-KEM shared secret.
/// KDF("OTRv4" || 0x16 || brace_key || mlkem_ss, 32)
pub fn kdf_brace_rotate(brace_key: &[u8; 32], mlkem_ss: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(32 + mlkem_ss.len());
    input.extend_from_slice(brace_key);
    input.extend_from_slice(mlkem_ss);
    let raw = kdf_1(usage::BRACE_KEY_ROTATE, &input, 32);
    input.zeroize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    out
}

// ── 64-byte key variants (used by DAKE / phase-2 modules) ────────────────────

pub fn derive_ratchet_keys(
    root_key: &[u8; 64],
    shared_secret: &[u8],
) -> (SecretBytes<64>, SecretBytes<64>) {
    let mut input = Vec::with_capacity(64 + shared_secret.len());
    input.extend_from_slice(root_key);
    input.extend_from_slice(shared_secret);
    let raw = kdf_1(usage::ROOT_KEY, &input, 128);
    input.zeroize();
    let mut new_root  = [0u8; 64];
    let mut new_chain = [0u8; 64];
    new_root.copy_from_slice(&raw[..64]);
    new_chain.copy_from_slice(&raw[64..]);
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
    let raw = kdf_1(usage::SSID, shared_secret, 8);
    let mut out = [0u8; 8];
    out.copy_from_slice(&raw);
    out
}

// ── MAC / fingerprint ─────────────────────────────────────────────────────────

pub fn hmac_sha3_512(key: &[u8], data: &[u8]) -> [u8; 64] {
    use hmac::{Hmac, Mac};
    use sha3::Sha3_512;
    let mut mac = <Hmac<Sha3_512> as Mac>::new_from_slice(key)
        .expect("HMAC-SHA3-512: key length invariant violated");
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
