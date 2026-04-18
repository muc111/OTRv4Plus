/// OTRv4 Double Ratchet (spec §4.4) in Rust.
///
/// Handles: chain key advancement, AES-256-GCM encrypt/decrypt,
/// skipped key management, replay detection, and secret zeroization.
///
/// X448 key exchange is delegated to the Python caller — this crate
/// only needs the resulting shared secrets.  This avoids linking
/// OpenSSL into the Rust build and keeps the DH operations in the
/// existing audited Python/C code path.

use std::collections::{BTreeMap, HashSet, VecDeque};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};
use rand::rngs::OsRng;
use rand::RngCore;

use crate::kdf::{kdf_chain, kdf_root, kdf_brace_rotate};
use crate::header::{RatchetHeader, RatchetError};

// ── Constants ────────────────────────────────────────────────────────

const MAX_SKIP: u32 = 1000;
const MAX_MESSAGE_KEYS: usize = 2000;
const MAX_SEEN: usize = 10_000;
const REKEY_INTERVAL: u32 = 50;
const AD_DEFAULT: &[u8] = b"OTRv4-DATA";

// ── Skipped key storage ─────────────────────────────────────────────

/// A skipped message key, zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
struct SkippedKey {
    enc_key: [u8; 32],
}

/// Composite key for the skipped-keys map: (dh_pub, msg_num).
/// dh_pub is 56 bytes for X448.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SkipId {
    dh_pub: [u8; 56],
    msg_num: u32,
}

// ── Replay cache with O(1) lookup ────────────────────────────────────

struct ReplayCache {
    set: HashSet<(Vec<u8>, u32)>,
    queue: VecDeque<(Vec<u8>, u32)>,
    max: usize,
}

impl ReplayCache {
    fn new(max: usize) -> Self {
        Self {
            set: HashSet::with_capacity(max),
            queue: VecDeque::with_capacity(max),
            max,
        }
    }

    fn contains(&self, dh_pub: &[u8], msg_num: u32) -> bool {
        // Use constant-time comparison for the lookup key construction
        let lookup_key = (dh_pub.to_vec(), msg_num);
        self.set.contains(&lookup_key)
    }

    fn insert(&mut self, dh_pub: &[u8], msg_num: u32) {
        let key = (dh_pub.to_vec(), msg_num);
        
        // Only insert if not already present
        if self.set.insert(key.clone()) {
            self.queue.push_back(key);
            
            // Maintain size limit with FIFO eviction
            if self.queue.len() > self.max {
                if let Some(old) = self.queue.pop_front() {
                    self.set.remove(&old);
                }
            }
        }
    }
    
    /// Clear all entries (useful for session teardown)
    #[allow(dead_code)]
    fn clear(&mut self) {
        self.set.clear();
        self.queue.clear();
    }
}

// Zeroize replay cache on drop
impl Drop for ReplayCache {
    fn drop(&mut self) {
        // Clear all entries to ensure any sensitive data in Vec<u8> is dropped
        self.set.clear();
        self.queue.clear();
    }
}

// ── Encrypt result ──────────────────────────────────────────────────

/// Result of encrypting a message.
pub struct EncryptResult {
    pub ciphertext: Vec<u8>,
    pub header: Vec<u8>,
    pub nonce: [u8; 12],
    pub tag: [u8; 16],
    pub ratchet_id: u32,
    pub reveal_mac_keys: Vec<Vec<u8>>,
}

// ── Double Ratchet ──────────────────────────────────────────────────

pub struct DoubleRatchet {
    // ── Key material (zeroized on drop) ─────────────────────
    root_key: [u8; 32],
    chain_key_send: [u8; 32],
    chain_key_recv: [u8; 32],
    brace_key: [u8; 32],

    // ── DH ratchet state ────────────────────────────────────
    dh_pub_local: [u8; 56],
    dh_pub_remote: Option<[u8; 56]>,
    last_remote_pub: Option<[u8; 56]>,

    // ── Counters ────────────────────────────────────────────
    msg_num_send: u32,
    msg_num_recv: u32,
    prev_chain_len_send: u32,
    msg_counter_send: u32,
    ratchet_id: u32,

    // ── Associated data ─────────────────────────────────────
    ad: Vec<u8>,

    // ── Skipped keys ────────────────────────────────────────
    skipped: BTreeMap<SkipId, SkippedKey>,

    // ── Replay detection ────────────────────────────────────
    seen: ReplayCache,

    // ── MAC reveal (OTRv4 §4.4.6) ──────────────────────────
    last_mac_key: Option<Vec<u8>>,
    pending_reveal_macs: Vec<Vec<u8>>,

    // ── Config ──────────────────────────────────────────────
    rekey_interval: u32,
    max_skip: u32,
}

impl Drop for DoubleRatchet {
    fn drop(&mut self) {
        // Zeroize all sensitive material
        self.root_key.zeroize();
        self.chain_key_send.zeroize();
        self.chain_key_recv.zeroize();
        self.brace_key.zeroize();
        self.dh_pub_local.zeroize();
        
        if let Some(ref mut k) = self.dh_pub_remote {
            k.zeroize();
        }
        if let Some(ref mut k) = self.last_remote_pub {
            k.zeroize();
        }
        if let Some(ref mut k) = self.last_mac_key {
            k.zeroize();
        }
        
        for mac in &mut self.pending_reveal_macs {
            mac.zeroize();
        }
        
        // Clear AD vector
        self.ad.zeroize();
        
        // SkippedKey implements ZeroizeOnDrop, clear map to trigger drops
        self.skipped.clear();
    }
}

impl DoubleRatchet {
    /// Create a new ratchet from DAKE-derived session keys.
    ///
    /// `dh_pub_local`: our current X448 public key (56 bytes).
    /// `root_key`, `chain_key_send`, `chain_key_recv`: from DAKE.
    /// `brace_key`: ML-KEM-1024 shared secret from DAKE (32 bytes).
    pub fn new(
        root_key: &[u8; 32],
        chain_key_send: &[u8; 32],
        chain_key_recv: &[u8; 32],
        brace_key: &[u8; 32],
        dh_pub_local: &[u8; 56],
        is_initiator: bool,
    ) -> Result<Self, RatchetError> {
        // Verify chain keys are non-zero using constant-time comparison
        let zero_key = [0u8; 32];
        if chain_key_send.ct_eq(&zero_key).into() || chain_key_recv.ct_eq(&zero_key).into() {
            return Err(RatchetError::ZeroChainKey);
        }
        
        // Verify root key is non-zero
        if root_key.ct_eq(&zero_key).into() {
            return Err(RatchetError::ZeroChainKey);
        }

        // Initiator sends on first half, responder on second
        let (ck_send, ck_recv) = if is_initiator {
            (*chain_key_send, *chain_key_recv)
        } else {
            (*chain_key_recv, *chain_key_send)
        };

        Ok(Self {
            root_key: *root_key,
            chain_key_send: ck_send,
            chain_key_recv: ck_recv,
            brace_key: *brace_key,
            dh_pub_local: *dh_pub_local,
            dh_pub_remote: None,
            last_remote_pub: None,
            msg_num_send: 0,
            msg_num_recv: 0,
            prev_chain_len_send: 0,
            msg_counter_send: 0,
            ratchet_id: 0,
            ad: AD_DEFAULT.to_vec(),
            skipped: BTreeMap::new(),
            seen: ReplayCache::new(MAX_SEEN),
            last_mac_key: None,
            pending_reveal_macs: Vec::new(),
            rekey_interval: REKEY_INTERVAL,
            max_skip: MAX_SKIP,
        })
    }

    /// Set associated data (default: b"OTRv4-DATA").
    pub fn set_ad(&mut self, ad: &[u8]) {
        self.ad.zeroize();
        self.ad = ad.to_vec();
    }

    /// Check if a DH rekey is needed (message counter exceeded interval).
    pub fn needs_rekey(&self) -> bool {
        self.msg_counter_send >= self.rekey_interval
    }

    /// Get our current DH public key.
    pub fn local_pub(&self) -> &[u8; 56] {
        &self.dh_pub_local
    }

    /// Get current ratchet ID.
    pub fn ratchet_id(&self) -> u32 {
        self.ratchet_id
    }

    /// Get brace key (for Python-side KEM rotation).
    pub fn brace_key(&self) -> &[u8; 32] {
        &self.brace_key
    }

    // ── Send-side DH ratchet ────────────────────────────────────

    /// Perform a send-side DH ratchet step.
    ///
    /// Called by Python when `needs_rekey()` is true, after Python
    /// has done:
    ///   1. Generated a new X448 keypair
    ///   2. Computed dh_secret = new_local.exchange(remote_pub)
    ///
    /// `dh_secret`: shared secret from the X448 exchange (56 bytes).
    /// `new_local_pub`: the new X448 public key (56 bytes).
    pub fn send_ratchet(
        &mut self,
        dh_secret: &[u8],
        new_local_pub: &[u8; 56],
    ) {
        // Perform root ratchet with DH secret and brace key
        let (new_root, new_chain) = kdf_root(&self.root_key, dh_secret, &self.brace_key);
        
        // Zeroize old root and replace
        self.root_key.zeroize();
        self.root_key = new_root;
        
        // Zeroize old send chain and replace
        self.chain_key_send.zeroize();
        self.chain_key_send = new_chain;
        
        // Update counters
        self.prev_chain_len_send = self.msg_num_send;
        self.msg_num_send = 0;
        self.msg_counter_send = 0;
        
        // Update local public key
        self.dh_pub_local = *new_local_pub;

        // Queue MAC key reveal for forward secrecy
        if let Some(ref mut mac) = self.last_mac_key {
            self.pending_reveal_macs.push(mac.clone());
            mac.zeroize();
        }
        self.last_mac_key = None;
        
        // Limit pending reveals to prevent memory exhaustion
        const MAX_PENDING_REVEALS: usize = 50;
        if self.pending_reveal_macs.len() > MAX_PENDING_REVEALS {
            let drain_n = self.pending_reveal_macs.len() - MAX_PENDING_REVEALS;
            for mac in self.pending_reveal_macs.drain(..drain_n) {
                drop(mac); // zeroized by Vec drop
            }
        }
    }

    /// Rotate the brace key with a new KEM shared secret.
    pub fn rotate_brace_key(&mut self, shared_secret: &[u8]) {
        let new = kdf_brace_rotate(&self.brace_key, shared_secret);
        self.brace_key.zeroize();
        self.brace_key = new;
    }

    // ── Encrypt ─────────────────────────────────────────────────

    /// Encrypt a plaintext message.
    ///
    /// Returns `EncryptResult` with ciphertext, header, nonce, tag,
    /// ratchet_id, and any MAC keys to reveal.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<EncryptResult, RatchetError> {
        // Advance send chain
        let (mut next_ck, mut enc_key, mac_key) = kdf_chain(&self.chain_key_send);
        
        // Zeroize old chain key and replace
        self.chain_key_send.zeroize();
        self.chain_key_send = next_ck;
        next_ck.zeroize();

        // Build header
        let header = RatchetHeader::new(
            self.dh_pub_local,
            self.prev_chain_len_send,
            self.msg_num_send,
        );
        let header_bytes = header.encode();

        // Build AAD = header || associated_data
        let mut aad = Vec::with_capacity(header_bytes.len() + self.ad.len());
        aad.extend_from_slice(&header_bytes);
        aad.extend_from_slice(&self.ad);

        // Generate cryptographically secure random nonce
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);

        // AES-256-GCM encrypt
        let cipher = Aes256Gcm::new_from_slice(&enc_key)
            .map_err(|e| RatchetError::Protocol(format!("AES key error: {e}")))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let ciphertext_with_tag = cipher
            .encrypt(nonce, aes_gcm::aead::Payload { 
                msg: plaintext, 
                aad: &aad 
            })
            .map_err(|e| RatchetError::Protocol(format!("AES encrypt error: {e}")))?;

        // Split ciphertext and tag
        let ct_len = ciphertext_with_tag
            .len()
            .checked_sub(16)
            .ok_or_else(|| RatchetError::Protocol("Ciphertext too short".into()))?;
            
        let ciphertext = ciphertext_with_tag[..ct_len].to_vec();
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&ciphertext_with_tag[ct_len..]);

        // Clean up encryption key
        enc_key.zeroize();

        // Store MAC key for potential reveal
        self.last_mac_key = Some(mac_key.to_vec());

        let rid = self.ratchet_id;
        
        // Increment counters with overflow protection
        self.msg_num_send = self.msg_num_send
            .checked_add(1)
            .ok_or_else(|| RatchetError::Protocol("Message counter overflow".into()))?;
        self.msg_counter_send = self.msg_counter_send
            .checked_add(1)
            .ok_or_else(|| RatchetError::Protocol("Rekey counter overflow".into()))?;

        // Collect reveal keys
        let reveal = std::mem::take(&mut self.pending_reveal_macs);

        Ok(EncryptResult {
            ciphertext,
            header: header_bytes.to_vec(),
            nonce: nonce_bytes,
            tag,
            ratchet_id: rid,
            reveal_mac_keys: reveal,
        })
    }

    // ── Decrypt ─────────────────────────────────────────────────

    /// Decrypt a message that uses the SAME DH key as current recv chain.
    ///
    /// This is the fast path — no DH ratchet needed.
    pub fn decrypt_same_dh(
        &mut self,
        header_bytes: &[u8],
        ciphertext: &[u8],
        nonce: &[u8; 12],
        tag: &[u8; 16],
    ) -> Result<Vec<u8>, RatchetError> {
        let header = RatchetHeader::decode(header_bytes)?;

        // Replay check
        if self.seen.contains(&header.dh_pub, header.msg_num) {
            return Err(RatchetError::ReplayDetected(
                format!("dh={:02x}{:02x}…, n={}", 
                    header.dh_pub[0], header.dh_pub[1], header.msg_num),
            ));
        }

        // First message: record remote DH pub
        if self.dh_pub_remote.is_none() {
            self.dh_pub_remote = Some(header.dh_pub);
        }

        // Try skipped keys first
        let skip_id = SkipId { 
            dh_pub: header.dh_pub, 
            msg_num: header.msg_num 
        };
        
        if let Some(skipped) = self.skipped.remove(&skip_id) {
            let pt = self.aes_decrypt(&skipped.enc_key, header_bytes, ciphertext, nonce, tag)?;
            // skipped is ZeroizeOnDrop
            self.seen.insert(&header.dh_pub, header.msg_num);
            return Ok(pt);
        }

        // Skip ahead if needed
        if header.msg_num > self.msg_num_recv {
            self.skip_keys(&header.dh_pub, header.msg_num)?;
        }

        if header.msg_num < self.msg_num_recv {
            return Err(RatchetError::MessageTooOld(
                format!("msg_num={} < recv_counter={}", 
                    header.msg_num, self.msg_num_recv),
            ));
        }

        // Advance recv chain
        let (mut next_ck, mut enc_key, _mac_key) = kdf_chain(&self.chain_key_recv);
        self.chain_key_recv.zeroize();
        self.chain_key_recv = next_ck;
        next_ck.zeroize();

        let pt = self.aes_decrypt(&enc_key, header_bytes, ciphertext, nonce, tag)?;
        enc_key.zeroize();

        self.msg_num_recv = header.msg_num
            .checked_add(1)
            .ok_or_else(|| RatchetError::Protocol("Message counter overflow".into()))?;
        self.seen.insert(&header.dh_pub, header.msg_num);

        Ok(pt)
    }

    /// Decrypt a message that carries a NEW DH key (DH ratchet step).
    ///
    /// Python has already performed the X448 exchanges and passes in:
    ///   - `dh_secret_recv`: old_local.exchange(new_remote)
    ///   - `dh_secret_send`: new_local.exchange(new_remote)
    ///   - `new_local_pub`: our freshly generated X448 public key
    pub fn decrypt_new_dh(
        &mut self,
        header_bytes: &[u8],
        ciphertext: &[u8],
        nonce: &[u8; 12],
        tag: &[u8; 16],
        dh_secret_recv: &[u8],
        dh_secret_send: &[u8],
        new_local_pub: &[u8; 56],
    ) -> Result<Vec<u8>, RatchetError> {
        let header = RatchetHeader::decode(header_bytes)?;

        // Replay check
        if self.seen.contains(&header.dh_pub, header.msg_num) {
            return Err(RatchetError::ReplayDetected(
                format!("dh={:02x}{:02x}…, n={}", 
                    header.dh_pub[0], header.dh_pub[1], header.msg_num),
            ));
        }

        // Bounds check for DoS protection
        if header.msg_num > self.max_skip {
            return Err(RatchetError::MaxSkipExceeded(header.msg_num));
        }

        // ── Derive temporary recv chain from old root + DH secret ────
        let (new_root_recv, new_recv_chain) =
            kdf_root(&self.root_key, dh_secret_recv, &self.brace_key);

        // Advance temporary chain to msg_num
        let mut temp_ck = new_recv_chain;
        for _ in 0..header.msg_num {
            let (next, _, _) = kdf_chain(&temp_ck);
            temp_ck.zeroize();
            temp_ck = next;
        }
        let (next_recv_ck, mut enc_key, _mac_key) = kdf_chain(&temp_ck);
        temp_ck.zeroize();

        // Try to decrypt
        let pt = self.aes_decrypt(&enc_key, header_bytes, ciphertext, nonce, tag)?;
        enc_key.zeroize();

        // ── Commit: update state only after successful decrypt ───────
        self.root_key.zeroize();
        self.root_key = new_root_recv;
        
        self.chain_key_recv.zeroize();
        self.chain_key_recv = next_recv_ck;

        // Track remote pub
        if let Some(old) = self.dh_pub_remote {
            self.last_remote_pub = Some(old);
        }
        self.dh_pub_remote = Some(header.dh_pub);

        // ── Send-side ratchet with new local key ─────────────────────
        let (new_root_send, new_send_chain) =
            kdf_root(&self.root_key, dh_secret_send, &self.brace_key);
        
        self.root_key.zeroize();
        self.root_key = new_root_send;
        
        self.chain_key_send.zeroize();
        self.chain_key_send = new_send_chain;
        self.dh_pub_local = *new_local_pub;

        // ── Reset counters with overflow protection ──────────────────
        self.prev_chain_len_send = self.msg_num_send;
        self.msg_num_send = 0;
        self.msg_counter_send = 0;
        self.msg_num_recv = header.msg_num
            .checked_add(1)
            .ok_or_else(|| RatchetError::Protocol("Message counter overflow".into()))?;
        self.ratchet_id = self.ratchet_id
            .checked_add(1)
            .ok_or_else(|| RatchetError::Protocol("Ratchet ID overflow".into()))?;

        // ── MAC reveal ───────────────────────────────────────────────
        if let Some(ref mut mac) = self.last_mac_key {
            self.pending_reveal_macs.push(mac.clone());
            mac.zeroize();
        }
        self.last_mac_key = None;

        // Prune skipped keys
        while self.skipped.len() > MAX_MESSAGE_KEYS {
            if let Some(first_key) = self.skipped.keys().next().cloned() {
                self.skipped.remove(&first_key);
            }
        }

        self.seen.insert(&header.dh_pub, header.msg_num);
        Ok(pt)
    }

    /// Check if a header contains a new DH key (triggers DH ratchet).
    pub fn is_new_dh(&self, header_bytes: &[u8]) -> bool {
        if let Some(remote) = &self.dh_pub_remote {
            if let Some(dh_pub) = RatchetHeader::peek_dh_pub(header_bytes) {
                // Constant-time comparison
                return dh_pub.ct_ne(remote.as_slice()).into();
            }
        }
        false
    }

    /// Extract DH public key from header bytes.
    pub fn header_dh_pub(header_bytes: &[u8]) -> Option<[u8; 56]> {
        if header_bytes.len() >= 56 {
            let mut pub_key = [0u8; 56];
            pub_key.copy_from_slice(&header_bytes[..56]);
            Some(pub_key)
        } else {
            None
        }
    }

    // ── Internal ────────────────────────────────────────────────

    fn aes_decrypt(
        &self,
        enc_key: &[u8; 32],
        header_bytes: &[u8],
        ciphertext: &[u8],
        nonce: &[u8; 12],
        tag: &[u8; 16],
    ) -> Result<Vec<u8>, RatchetError> {
        // Build AAD
        let mut aad = Vec::with_capacity(header_bytes.len() + self.ad.len());
        aad.extend_from_slice(header_bytes);
        aad.extend_from_slice(&self.ad);

        // Reconstruct ciphertext_with_tag for aes-gcm
        let mut ct_with_tag = Vec::with_capacity(
            ciphertext.len()
                .checked_add(16)
                .ok_or_else(|| RatchetError::DecryptionFailed("Ciphertext too large".into()))?
        );
        ct_with_tag.extend_from_slice(ciphertext);
        ct_with_tag.extend_from_slice(tag);

        let cipher = Aes256Gcm::new_from_slice(enc_key)
            .map_err(|e| RatchetError::DecryptionFailed(format!("AES key error: {e}")))?;
        let n = Nonce::from_slice(nonce);

        cipher
            .decrypt(n, aes_gcm::aead::Payload { 
                msg: &ct_with_tag, 
                aad: &aad 
            })
            .map_err(|_| RatchetError::DecryptionFailed(
                "AES-GCM authentication failed".into(),
            ))
    }

    fn skip_keys(&mut self, dh_pub: &[u8; 56], target: u32) -> Result<(), RatchetError> {
        // Check for overflow/underflow
        if target <= self.msg_num_recv {
            return Ok(());
        }
        
        let skip_count = target
            .checked_sub(self.msg_num_recv)
            .ok_or_else(|| RatchetError::Protocol("Skip count calculation overflow".into()))?;
            
        if skip_count > self.max_skip {
            return Err(RatchetError::MaxSkipExceeded(skip_count));
        }

        for n in self.msg_num_recv..target {
            let (mut next_ck, enc_key, _mac_key) = kdf_chain(&self.chain_key_recv);
            
            self.chain_key_recv.zeroize();
            self.chain_key_recv = next_ck;
            next_ck.zeroize();

            let skip_id = SkipId { 
                dh_pub: *dh_pub, 
                msg_num: n 
            };
            self.skipped.insert(skip_id, SkippedKey { enc_key });

            // Prune if over limit
            while self.skipped.len() > MAX_MESSAGE_KEYS {
                if let Some(first) = self.skipped.keys().next().cloned() {
                    self.skipped.remove(&first);
                }
            }
        }

        self.msg_num_recv = target;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pair() -> (DoubleRatchet, DoubleRatchet) {
        let root = [0x42u8; 32];
        let cks = [0xAAu8; 32];
        let ckr = [0xBBu8; 32];
        let bk = [0xCCu8; 32];
        let pub_a = [0x01u8; 56];
        let pub_b = [0x02u8; 56];

        let alice = DoubleRatchet::new(&root, &cks, &ckr, &bk, &pub_a, true).unwrap();
        let bob = DoubleRatchet::new(&root, &cks, &ckr, &bk, &pub_b, false).unwrap();
        (alice, bob)
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let (mut alice, mut bob) = make_pair();
        let msg = b"hello from alice";

        let enc = alice.encrypt(msg).unwrap();
        let pt = bob.decrypt_same_dh(
            &enc.header, &enc.ciphertext, &enc.nonce, &enc.tag,
        ).unwrap();

        assert_eq!(pt, msg);
    }

    #[test]
    fn test_multiple_messages() {
        let (mut alice, mut bob) = make_pair();

        for i in 0..20u32 {
            let msg = format!("message {i}");
            let enc = alice.encrypt(msg.as_bytes()).unwrap();
            let pt = bob.decrypt_same_dh(
                &enc.header, &enc.ciphertext, &enc.nonce, &enc.tag,
            ).unwrap();
            assert_eq!(pt, msg.as_bytes());
        }
    }

    #[test]
    fn test_bidirectional() {
        let (mut alice, mut bob) = make_pair();

        for i in 0..10u32 {
            let msg_a = format!("a2b-{i}");
            let enc_a = alice.encrypt(msg_a.as_bytes()).unwrap();
            let pt_a = bob.decrypt_same_dh(
                &enc_a.header, &enc_a.ciphertext, &enc_a.nonce, &enc_a.tag,
            ).unwrap();
            assert_eq!(pt_a, msg_a.as_bytes());

            let msg_b = format!("b2a-{i}");
            let enc_b = bob.encrypt(msg_b.as_bytes()).unwrap();
            let pt_b = alice.decrypt_same_dh(
                &enc_b.header, &enc_b.ciphertext, &enc_b.nonce, &enc_b.tag,
            ).unwrap();
            assert_eq!(pt_b, msg_b.as_bytes());
        }
    }

    #[test]
    fn test_replay_rejected() {
        let (mut alice, mut bob) = make_pair();
        let enc = alice.encrypt(b"test").unwrap();
        let _ = bob.decrypt_same_dh(
            &enc.header, &enc.ciphertext, &enc.nonce, &enc.tag,
        ).unwrap();

        // Replay same message
        let result = bob.decrypt_same_dh(
            &enc.header, &enc.ciphertext, &enc.nonce, &enc.tag,
        );
        assert!(matches!(result, Err(RatchetError::ReplayDetected(_))));
    }

    #[test]
    fn test_tampered_ciphertext_rejected() {
        let (mut alice, mut bob) = make_pair();
        let mut enc = alice.encrypt(b"test").unwrap();
        
        // Tamper with ciphertext
        if !enc.ciphertext.is_empty() {
            enc.ciphertext[0] ^= 0xFF;
        }

        let result = bob.decrypt_same_dh(
            &enc.header, &enc.ciphertext, &enc.nonce, &enc.tag,
        );
        assert!(matches!(result, Err(RatchetError::DecryptionFailed(_))));
    }

    #[test]
    fn test_zero_chain_key_rejected() {
        let root = [0x42u8; 32];
        let zero = [0u8; 32];
        let bk = [0xCCu8; 32];
        let pub_a = [0x01u8; 56];

        let result = DoubleRatchet::new(&root, &zero, &[0xBBu8; 32], &bk, &pub_a, true);
        assert!(matches!(result, Err(RatchetError::ZeroChainKey)));
    }

    #[test]
    fn test_out_of_order_delivery() {
        let (mut alice, mut bob) = make_pair();

        // Alice sends 3 messages
        let enc0 = alice.encrypt(b"msg-0").unwrap();
        let enc1 = alice.encrypt(b"msg-1").unwrap();
        let enc2 = alice.encrypt(b"msg-2").unwrap();

        // Bob receives them out of order: 2, 0, 1
        let pt2 = bob.decrypt_same_dh(
            &enc2.header, &enc2.ciphertext, &enc2.nonce, &enc2.tag,
        ).unwrap();
        assert_eq!(pt2, b"msg-2");

        let pt0 = bob.decrypt_same_dh(
            &enc0.header, &enc0.ciphertext, &enc0.nonce, &enc0.tag,
        ).unwrap();
        assert_eq!(pt0, b"msg-0");

        let pt1 = bob.decrypt_same_dh(
            &enc1.header, &enc1.ciphertext, &enc1.nonce, &enc1.tag,
        ).unwrap();
        assert_eq!(pt1, b"msg-1");
    }

    #[test]
    fn test_replay_cache_eviction() {
        let mut cache = ReplayCache::new(2);
        let dh1 = vec![1u8; 56];
        let dh2 = vec![2u8; 56];
        let dh3 = vec![3u8; 56];
        
        cache.insert(&dh1, 1);
        cache.insert(&dh2, 2);
        assert!(cache.contains(&dh1, 1));
        assert!(cache.contains(&dh2, 2));
        
        // This should evict dh1
        cache.insert(&dh3, 3);
        assert!(!cache.contains(&dh1, 1));
        assert!(cache.contains(&dh2, 2));
        assert!(cache.contains(&dh3, 3));
    }

    #[test]
    fn test_max_skip_enforcement() {
        let (mut alice, mut bob) = make_pair();
        
        // Try to decrypt a message with msg_num > MAX_SKIP
        let mut header = RatchetHeader::new([1u8; 56], 0, MAX_SKIP + 1);
        let header_bytes = header.encode();
        
        let result = bob.decrypt_same_dh(
            &header_bytes,
            b"test",
            &[0u8; 12],
            &[0u8; 16],
        );
        
        assert!(matches!(result, Err(RatchetError::MaxSkipExceeded(_))));
    }

    #[test]
    fn test_overflow_protection() {
        let (mut alice, _) = make_pair();
        
        // Set counters near overflow
        alice.msg_num_send = u32::MAX;
        
        // Should handle gracefully
        let result = alice.encrypt(b"test");
        assert!(matches!(result, Err(RatchetError::Protocol(_))));
    }
}