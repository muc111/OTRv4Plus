/// KDF functions matching OTRv4 spec §3.2.
///
/// KDF_1(usage_id, value, length) = SHAKE-256("OTRv4" || usage_id || value, length)
///
/// All OTRv4 key derivation uses this single function with different
/// usage_id constants to domain-separate outputs.

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
use zeroize::Zeroize;

/// Domain separator required by OTRv4 spec §3.2.
const KDF_DOMAIN: &[u8] = b"OTRv4";

/// Usage IDs from OTRv4 spec §3.2.
#[allow(dead_code)]
pub mod usage {
    pub const BRACE_KEY: u8 = 0x02;
    pub const ROOT_KEY: u8 = 0x11;
    pub const CHAIN_KEY: u8 = 0x12;
    pub const MESSAGE_KEY: u8 = 0x13;
    pub const MAC_KEY: u8 = 0x14;
    pub const DAKE_MAC_KEY: u8 = 0x15;
    pub const BRACE_KEY_ROTATE: u8 = 0x16;
}

/// SHAKE-256 KDF matching Python's `kdf_1` exactly.
///
/// Produces `length` bytes of output.
pub fn kdf_1(usage_id: u8, value: &[u8], length: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(KDF_DOMAIN);
    hasher.update(&[usage_id]);
    hasher.update(value);
    let mut reader = hasher.finalize_xof();
    let mut out = vec![0u8; length];
    reader.read(&mut out);
    out
}

/// Derive next chain key, message encryption key, and MAC key.
///
/// Returns (next_ck[32], enc_key[32], mac_key[64]).
/// The input chain_key is NOT modified — caller must overwrite.
pub fn kdf_chain(chain_key: &[u8]) -> ([u8; 32], [u8; 32], [u8; 64]) {
    let next_ck_vec = kdf_1(usage::CHAIN_KEY, chain_key, 32);
    let enc_key_vec = kdf_1(usage::MESSAGE_KEY, chain_key, 32);
    let mac_key_vec = kdf_1(usage::MAC_KEY, chain_key, 64);

    let mut next_ck = [0u8; 32];
    let mut enc_key = [0u8; 32];
    let mut mac_key = [0u8; 64];

    next_ck.copy_from_slice(&next_ck_vec);
    enc_key.copy_from_slice(&enc_key_vec);
    mac_key.copy_from_slice(&mac_key_vec);

    (next_ck, enc_key, mac_key)
}

/// Root key ratchet KDF.
///
/// KDF_1(ROOT_KEY, root || dh_secret || brace_key, 64)
///   → (new_root[32], new_chain[32])
pub fn kdf_root(root_key: &[u8], dh_secret: &[u8], brace_key: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut input = Vec::with_capacity(root_key.len() + dh_secret.len() + brace_key.len());
    input.extend_from_slice(root_key);
    input.extend_from_slice(dh_secret);
    input.extend_from_slice(brace_key);

    let seed = kdf_1(usage::ROOT_KEY, &input, 64);
    input.zeroize();

    let mut new_root = [0u8; 32];
    let mut new_chain = [0u8; 32];
    new_root.copy_from_slice(&seed[..32]);
    new_chain.copy_from_slice(&seed[32..64]);

    (new_root, new_chain)
}

/// Brace key rotation KDF.
///
/// brace_key' = KDF_1(BRACE_KEY_ROTATE, old_brace || shared_secret, 32)
pub fn kdf_brace_rotate(old_brace: &[u8], shared_secret: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(old_brace.len() + shared_secret.len());
    input.extend_from_slice(old_brace);
    input.extend_from_slice(shared_secret);

    let result_vec = kdf_1(usage::BRACE_KEY_ROTATE, &input, 32);
    input.zeroize();

    let mut result = [0u8; 32];
    result.copy_from_slice(&result_vec);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kdf_1_deterministic() {
        let a = kdf_1(usage::ROOT_KEY, b"test", 32);
        let b = kdf_1(usage::ROOT_KEY, b"test", 32);
        assert_eq!(a, b);
    }

    #[test]
    fn test_kdf_1_different_usage() {
        let a = kdf_1(usage::ROOT_KEY, b"test", 32);
        let b = kdf_1(usage::CHAIN_KEY, b"test", 32);
        assert_ne!(a, b);
    }

    #[test]
    fn test_kdf_chain_sizes() {
        let ck = [0x42u8; 32];
        let (next, enc, mac) = kdf_chain(&ck);
        assert_eq!(next.len(), 32);
        assert_eq!(enc.len(), 32);
        assert_eq!(mac.len(), 64);
        // All outputs should be non-zero
        assert!(next.iter().any(|&b| b != 0));
        assert!(enc.iter().any(|&b| b != 0));
        assert!(mac.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_kdf_root_sizes() {
        let rk = [0x01u8; 32];
        let dh = [0x02u8; 56];
        let bk = [0x03u8; 32];
        let (new_root, new_chain) = kdf_root(&rk, &dh, &bk);
        assert_eq!(new_root.len(), 32);
        assert_eq!(new_chain.len(), 32);
        assert_ne!(new_root, new_chain);
    }
}
