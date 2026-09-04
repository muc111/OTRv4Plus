/// OTRv4 Double Ratchet (spec §4.4) in Rust.
///
/// Handles: chain key advancement, AES‑256‑GCM encrypt/decrypt,
/// skipped key management, replay detection, and secret zeroization.
///
/// X448 key exchange is delegated to the Python caller - this crate
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

use crate::kdf::{kdf_chain, kdf_root, kdf_brace_rotate, kdf_mkmac, mkmac_fingerprint};
use crate::header::{RatchetHeader, RatchetError};

const MAX_SKIP: u32 = 1000;
const MAX_MESSAGE_KEYS: usize = 2000;
const MAX_SEEN: usize = 10_000;
const REKEY_INTERVAL: u32 = 50;
const AD_DEFAULT: &[u8] = b"OTRv4-DATA";

/// Audit C2: how many MKmac fingerprints to retain for the revealed-key
/// cross-check. A peer reveals at most MAX_PENDING_REVEALS (50) keys per
/// message and reveals them within a message or two of using them, so this is
/// two orders of magnitude more history than the check ever needs. Each entry
/// is 32 bytes and is a hash, not key material.
const MAX_MAC_FINGERPRINTS: usize = 4096;

// ── Skipped key storage ─────────────────────────────────────────────
#[derive(Zeroize, ZeroizeOnDrop)]
struct SkippedKey {
    enc_key: [u8; 32],
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SkipId {
    dh_pub: [u8; 56],
    msg_num: u32,
}

// ── Replay cache ────────────────────────────────────────────────────
struct ReplayCache {
    set: HashSet<(Vec<u8>, u32)>,
    queue: VecDeque<(Vec<u8>, u32)>,
    max: usize,
}

impl ReplayCache {
    fn new(max: usize) -> Self {
        Self { set: HashSet::with_capacity(max), queue: VecDeque::with_capacity(max), max }
    }
    fn contains(&self, dh_pub: &[u8], msg_num: u32) -> bool {
        self.set.contains(&(dh_pub.to_vec(), msg_num))
    }
    fn insert(&mut self, dh_pub: &[u8], msg_num: u32) {
        let key = (dh_pub.to_vec(), msg_num);
        if self.set.insert(key.clone()) {
            self.queue.push_back(key);
            if self.queue.len() > self.max {
                if let Some(old) = self.queue.pop_front() {
                    self.set.remove(&old);
                }
            }
        }
    }
    fn clear(&mut self) {
        self.set.clear();
        self.queue.clear();
    }
}

impl Drop for ReplayCache {
    fn drop(&mut self) { self.clear(); }
}

// ── Encrypt result ──────────────────────────────────────────────────
#[derive(Clone)]   // tests clone a message to build a forgery
pub struct EncryptResult {
    pub ciphertext: Vec<u8>,
    pub header: Vec<u8>,
    pub nonce: [u8; 12],
    pub tag: [u8; 16],
    pub ratchet_id: u32,
    pub reveal_mac_keys: Vec<Vec<u8>>,
    /// MKmac for THIS message (64 B, OTRv4 §4.4.2). The caller authenticates
    /// the assembled data message with it, then drops it; this ratchet keeps
    /// its own copy in `last_mac_key` for later revelation. MKmac is designed
    /// to become public, so handing it across the FFI boundary costs nothing
    /// that revelation would not publish anyway.
    pub mac_key: Vec<u8>,
}

/// Result of decrypting one message.
///
/// L1: the receive path previously queued nothing for revelation —
/// `last_mac_key` was assigned only in `encrypt_message`. Deniability turns on
/// revealing the keys that authenticated messages you RECEIVED, since those
/// are the ones a third party could then forge. The receive-side MKmac is now
/// queued after successful authentication.
pub struct DecryptResult {
    pub plaintext: Vec<u8>,
    /// MKmac for this message (64 B), so the caller can verify the outer MAC.
    pub mac_key: Vec<u8>,
}

// ── Double Ratchet ──────────────────────────────────────────────────
pub struct DoubleRatchet {
    root_key: [u8; 32],
    chain_key_send: [u8; 32],
    chain_key_recv: [u8; 32],
    brace_key: [u8; 32],

    dh_pub_local: [u8; 56],
    dh_pub_remote: Option<[u8; 56]>,
    last_remote_pub: Option<[u8; 56]>,

    msg_num_send: u32,
    msg_num_recv: u32,
    prev_chain_len_send: u32,
    msg_counter_send: u32,
    ratchet_id: u32,

    ad: Vec<u8>,
    skipped: BTreeMap<SkipId, SkippedKey>,
    seen: ReplayCache,
    last_mac_key: Option<Vec<u8>>,
    pending_reveal_macs: Vec<Vec<u8>>,
    /// Audit C2: fingerprints of every MKmac this endpoint has derived, in
    /// either direction, including the ones derived for skipped messages that
    /// never arrived. A key the peer reveals is checked against this set.
    /// Hashes only -- see kdf::mkmac_fingerprint.
    derived_mac_fps: HashSet<[u8; 32]>,
    derived_mac_fp_order: VecDeque<[u8; 32]>,
    rekey_interval: u32,
    max_skip: u32,
}

impl Drop for DoubleRatchet {
    fn drop(&mut self) {
        self.root_key.zeroize();
        self.chain_key_send.zeroize();
        self.chain_key_recv.zeroize();
        self.brace_key.zeroize();
        self.dh_pub_local.zeroize();
        if let Some(ref mut k) = self.dh_pub_remote { k.zeroize(); }
        if let Some(ref mut k) = self.last_remote_pub { k.zeroize(); }
        if let Some(ref mut k) = self.last_mac_key { k.zeroize(); }
        for mac in &mut self.pending_reveal_macs { mac.zeroize(); }
        self.derived_mac_fps.clear();
        self.derived_mac_fp_order.clear();
        self.ad.zeroize();
        self.skipped.clear();
    }
}

impl DoubleRatchet {
    pub fn new(
        root_key: &[u8; 32], chain_key_send: &[u8; 32], chain_key_recv: &[u8; 32],
        brace_key: &[u8; 32], dh_pub_local: &[u8; 56], is_initiator: bool,
    ) -> Result<Self, RatchetError> {
        let zero_key = [0u8; 32];
        if chain_key_send.ct_eq(&zero_key).into() || chain_key_recv.ct_eq(&zero_key).into() {
            return Err(RatchetError::ZeroChainKey);
        }
        if root_key.ct_eq(&zero_key).into() {
            return Err(RatchetError::ZeroChainKey);
        }

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
            derived_mac_fps: HashSet::new(),
            derived_mac_fp_order: VecDeque::new(),
            rekey_interval: REKEY_INTERVAL,
            max_skip: MAX_SKIP,
        })
    }

    pub fn set_ad(&mut self, ad: &[u8]) {
        self.ad.zeroize();
        self.ad = ad.to_vec();
    }

    pub fn needs_rekey(&self) -> bool {
        self.msg_counter_send >= self.rekey_interval
    }

    pub fn local_pub(&self) -> &[u8; 56] { &self.dh_pub_local }
    pub fn ratchet_id(&self) -> u32 { self.ratchet_id }
    pub fn brace_key(&self) -> &[u8; 32] { &self.brace_key }

    // ── Send‑side DH ratchet ────────────────────────────────────
    pub fn send_ratchet(&mut self, dh_secret: &[u8], new_local_pub: &[u8; 56]) {
        let (new_root, new_chain) = kdf_root(&self.root_key, dh_secret);
        self.root_key.zeroize();
        self.root_key = new_root;
        self.chain_key_send.zeroize();
        self.chain_key_send = new_chain;

        self.prev_chain_len_send = self.msg_num_send;
        self.msg_num_send = 0;
        self.msg_counter_send = 0;
        self.dh_pub_local = *new_local_pub;

        if let Some(ref mut mac) = self.last_mac_key {
            self.pending_reveal_macs.push(mac.clone());
            mac.zeroize();
        }
        self.last_mac_key = None;

        const MAX_PENDING_REVEALS: usize = 50;
        if self.pending_reveal_macs.len() > MAX_PENDING_REVEALS {
            let drain_n = self.pending_reveal_macs.len() - MAX_PENDING_REVEALS;
            for mut mac in self.pending_reveal_macs.drain(..drain_n) {
                mac.zeroize();
            }
        }
    }

    pub fn rotate_brace_key(&mut self, shared_secret: &[u8]) {
        let new = kdf_brace_rotate(&self.brace_key, shared_secret);
        self.brace_key.zeroize();
        self.brace_key = new;
    }

    // ── Encrypt ─────────────────────────────────────────────────
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<EncryptResult, RatchetError> {
        let (mut next_ck, mut enc_key, mkmac) = kdf_chain(&self.chain_key_send);
        self.chain_key_send.zeroize();
        self.chain_key_send = next_ck;
        next_ck.zeroize();

        let header = RatchetHeader::new(self.dh_pub_local, self.prev_chain_len_send, self.msg_num_send);
        let header_bytes = header.encode();

        let mut aad = Vec::with_capacity(header_bytes.len() + self.ad.len());
        aad.extend_from_slice(&header_bytes);
        aad.extend_from_slice(&self.ad);

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);

        let cipher = Aes256Gcm::new_from_slice(&enc_key)
            .map_err(|e| RatchetError::Protocol(format!("AES key error: {e}")))?;
        let nonce = Nonce::from(nonce_bytes);

        let ciphertext_with_tag = cipher
            .encrypt(&nonce, aes_gcm::aead::Payload { msg: plaintext, aad: &aad })
            .map_err(|e| RatchetError::Protocol(format!("AES encrypt error: {e}")))?;

        let ct_len = ciphertext_with_tag.len().checked_sub(16)
            .ok_or_else(|| RatchetError::Protocol("Ciphertext too short".into()))?;
        let ciphertext = ciphertext_with_tag[..ct_len].to_vec();
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&ciphertext_with_tag[ct_len..]);

        enc_key.zeroize();
        // Audit C2: the peer reveals the MKmac of every message it receives
        // from us, so our own send-side keys belong in the cross-check set.
        self.note_derived_mac(&mkmac);
        self.last_mac_key = Some(mkmac.to_vec());

        let rid = self.ratchet_id;
        self.msg_num_send = self.msg_num_send.checked_add(1)
            .ok_or_else(|| RatchetError::Protocol("Message counter overflow".into()))?;
        self.msg_counter_send = self.msg_counter_send.checked_add(1)
            .ok_or_else(|| RatchetError::Protocol("Rekey counter overflow".into()))?;

        let reveal = std::mem::take(&mut self.pending_reveal_macs);

        Ok(EncryptResult {
            ciphertext,
            header: header_bytes.to_vec(),
            nonce: nonce_bytes,
            tag,
            ratchet_id: rid,
            reveal_mac_keys: reveal,
            mac_key: mkmac.to_vec(),
        })
    }

    // ── Decrypt same DH ────────────────────────────────────────
    pub fn decrypt_same_dh(
        &mut self, header_bytes: &[u8], ciphertext: &[u8],
        nonce: &[u8; 12], tag: &[u8; 16],
    ) -> Result<DecryptResult, RatchetError> {
        let header = RatchetHeader::decode(header_bytes)?;

        if self.seen.contains(&header.dh_pub, header.msg_num) {
            return Err(RatchetError::ReplayDetected(format!(
                "dh={:02x}{:02x}…, n={}", header.dh_pub[0], header.dh_pub[1], header.msg_num
            )));
        }

        if self.dh_pub_remote.is_none() {
            self.dh_pub_remote = Some(header.dh_pub);
        }

        // Skipped-key path: peek, authenticate, and only then consume. The
        // previous code removed the key before decrypting, so a forged
        // message aimed at a skipped msg_num destroyed the key the genuine
        // message needed.
        let skip_id = SkipId { dh_pub: header.dh_pub, msg_num: header.msg_num };
        if let Some(skipped) = self.skipped.get(&skip_id) {
            let key = skipped.enc_key;
            let pt = self.aes_decrypt(&key, header_bytes, ciphertext, nonce, tag)?;
            self.skipped.remove(&skip_id);
            self.seen.insert(&header.dh_pub, header.msg_num);
            // Skipped path: MKmac is re-derived from the stored MKenc rather
            // than kept alongside it, so the store stays 32 bytes per entry.
            let mkmac = kdf_mkmac(&key);
            self.queue_reveal(&mkmac);
            return Ok(DecryptResult { plaintext: pt, mac_key: mkmac.to_vec() });
        }

        if header.msg_num < self.msg_num_recv {
            return Err(RatchetError::MessageTooOld(format!(
                "msg_num={} < recv_counter={}", header.msg_num, self.msg_num_recv
            )));
        }

        // ── Authenticate BEFORE mutating any ratchet state ──────────────
        //
        // This is the whole point of the rewrite. Previously skip_keys() and
        // the chain advance both ran before aes_decrypt, so ONE forged
        // message — and the header is visible on the wire, so anyone who can
        // observe and inject can build one — permanently advanced
        // chain_key_recv. Every genuine message after it then derived from
        // the wrong chain key, failed, and advanced it again. A single
        // unauthenticated packet killed the session for good.
        //
        // Everything below derives into scratch state. Nothing on `self`
        // changes until the AEAD tag has verified.
        let skip_count = header.msg_num.checked_sub(self.msg_num_recv)
            .ok_or_else(|| RatchetError::Protocol("Skip count overflow".into()))?;
        if skip_count > self.max_skip {
            return Err(RatchetError::MaxSkipExceeded(skip_count));
        }

        let mut scratch_ck = self.chain_key_recv;
        let mut pending_skipped: Vec<(u32, [u8; 32])> = Vec::new();
        for n in self.msg_num_recv..header.msg_num {
            let (mut next_ck, enc_key, _) = kdf_chain(&scratch_ck);
            scratch_ck.zeroize();
            scratch_ck = next_ck;
            next_ck.zeroize();
            pending_skipped.push((n, enc_key));
        }

        let (mut next_ck, mut enc_key, _) = kdf_chain(&scratch_ck);
        scratch_ck.zeroize();

        let recv_enc_key = enc_key;
        let pt = match self.aes_decrypt(&enc_key, header_bytes, ciphertext, nonce, tag) {
            Ok(pt) => pt,
            Err(e) => {
                // Forged or corrupt: discard every derived key and leave the
                // ratchet exactly as it was.
                enc_key.zeroize();
                next_ck.zeroize();
                for (_, mut k) in pending_skipped { k.zeroize(); }
                let mut dead = recv_enc_key; dead.zeroize();
                return Err(e);
            }
        };
        enc_key.zeroize();
        let mut recv_enc_key = recv_enc_key;

        // ── Authenticated: commit ───────────────────────────────────────
        for (n, enc_key) in pending_skipped {
            // Audit C2: the peer will reveal the MKmac of the message this
            // key belongs to whether or not that message ever reaches us, so
            // fingerprint it now while MKenc is in hand.
            self.note_derived_mac(&kdf_mkmac(&enc_key));
            let skip_id = SkipId { dh_pub: header.dh_pub, msg_num: n };
            self.skipped.insert(skip_id, SkippedKey { enc_key });
        }
        self.prune_skipped();

        self.chain_key_recv.zeroize();
        self.chain_key_recv = next_ck;
        next_ck.zeroize();

        self.msg_num_recv = header.msg_num.checked_add(1)
            .ok_or_else(|| RatchetError::Protocol("Message counter overflow".into()))?;
        self.seen.insert(&header.dh_pub, header.msg_num);

        let mkmac = kdf_mkmac(&recv_enc_key);
        recv_enc_key.zeroize();
        self.queue_reveal(&mkmac);
        Ok(DecryptResult { plaintext: pt, mac_key: mkmac.to_vec() })
    }

    /// Audit C2: remember that this endpoint derived `mkmac`.
    ///
    /// Called at every point an MKmac comes into existence -- send, receive,
    /// and the skipped-message path -- so that the set covers every key the
    /// peer could legitimately reveal, including keys for messages that were
    /// lost in transit and whose MKenc only ever existed in the skipped store.
    fn note_derived_mac(&mut self, mkmac: &[u8]) {
        let fp = mkmac_fingerprint(mkmac);
        if self.derived_mac_fps.insert(fp) {
            self.derived_mac_fp_order.push_back(fp);
        }
        while self.derived_mac_fp_order.len() > MAX_MAC_FINGERPRINTS {
            if let Some(old) = self.derived_mac_fp_order.pop_front() {
                self.derived_mac_fps.remove(&old);
            } else {
                break;
            }
        }
    }

    /// Audit C2: did this endpoint independently derive `key`?
    ///
    /// True means the peer revealed a MAC key that really did key a message
    /// on a chain both sides share -- the revelation is genuine. False means
    /// only that this endpoint cannot account for the key; it is NOT proof of
    /// misbehaviour, because eviction and messages skipped past an old chain
    /// both produce keys the peer holds and this side never derived.
    pub fn knows_derived_mac(&self, key: &[u8]) -> bool {
        self.derived_mac_fps.contains(&mkmac_fingerprint(key))
    }

    /// Queue a MAC key for later revelation, bounded.
    fn queue_reveal(&mut self, mkmac: &[u8; 64]) {
        self.note_derived_mac(mkmac);
        self.pending_reveal_macs.push(mkmac.to_vec());
        const MAX_PENDING_REVEALS: usize = 50;
        if self.pending_reveal_macs.len() > MAX_PENDING_REVEALS {
            let drain_n = self.pending_reveal_macs.len() - MAX_PENDING_REVEALS;
            for mut mac in self.pending_reveal_macs.drain(..drain_n) {
                mac.zeroize();
            }
        }
    }

    /// Bound the skipped-key store. Evicts the lowest SkipId, which is
    /// deterministic but arbitrary with respect to age; acceptable because
    /// the store is only reachable after authentication.
    fn prune_skipped(&mut self) {
        while self.skipped.len() > MAX_MESSAGE_KEYS {
            if let Some(first) = self.skipped.keys().next().cloned() {
                self.skipped.remove(&first);
            } else {
                break;
            }
        }
    }

    // ── Decrypt with DH ratchet ─────────────────────────────────
    pub fn decrypt_new_dh(
        &mut self, header_bytes: &[u8], ciphertext: &[u8],
        nonce: &[u8; 12], tag: &[u8; 16],
        dh_secret_recv: &[u8], dh_secret_send: &[u8], new_local_pub: &[u8; 56],
    ) -> Result<DecryptResult, RatchetError> {
        let header = RatchetHeader::decode(header_bytes)?;

        if self.seen.contains(&header.dh_pub, header.msg_num) {
            return Err(RatchetError::ReplayDetected(format!(
                "dh={:02x}{:02x}…, n={}", header.dh_pub[0], header.dh_pub[1], header.msg_num
            )));
        }
        if header.msg_num > self.max_skip {
            return Err(RatchetError::MaxSkipExceeded(header.msg_num));
        }

        // Same discipline as decrypt_same_dh: a DH ratchet step is a much
        // larger commitment — new root, both chains, both counters — and the
        // old code performed all of it, plus up to max_skip key derivations,
        // before authenticating. A forged header with a random dh_pub and a
        // high msg_num therefore burned the CPU, flooded the skipped-key
        // store (evicting genuine keys), and rotated the root, all on
        // unauthenticated input.
        let (new_root_recv, new_recv_chain) = kdf_root(&self.root_key, dh_secret_recv);

        let mut scratch_ck = new_recv_chain;
        let mut pending_skipped: Vec<(u32, [u8; 32])> = Vec::new();
        for n in 0..header.msg_num {
            let (mut next, mk, _) = kdf_chain(&scratch_ck);
            scratch_ck.zeroize();
            scratch_ck = next;
            next.zeroize();
            pending_skipped.push((n, mk));
        }
        let (mut next_recv_ck, mut enc_key, _) = kdf_chain(&scratch_ck);
        scratch_ck.zeroize();
        let mut recv_enc_key = enc_key;

        let pt = match self.aes_decrypt(&enc_key, header_bytes, ciphertext, nonce, tag) {
            Ok(pt) => pt,
            Err(e) => {
                enc_key.zeroize();
                recv_enc_key.zeroize();
                next_recv_ck.zeroize();
                let mut r = new_root_recv;  r.zeroize();
                for (_, mut k) in pending_skipped { k.zeroize(); }
                return Err(e);
            }
        };
        enc_key.zeroize();

        // ── Authenticated: commit the ratchet step ──────────────────────
        for (n, mk) in pending_skipped {
            // Audit L2: retain the skipped keys of the NEW receiving chain so
            // out-of-order messages arriving after this step still decrypt.
            // Audit C2: fingerprint the matching MKmac at the same time.
            self.note_derived_mac(&kdf_mkmac(&mk));
            let skip_id = SkipId { dh_pub: header.dh_pub, msg_num: n };
            self.skipped.insert(skip_id, SkippedKey { enc_key: mk });
        }
        self.prune_skipped();

        self.root_key.zeroize();
        self.root_key = new_root_recv;
        self.chain_key_recv.zeroize();
        self.chain_key_recv = next_recv_ck;
        next_recv_ck.zeroize();

        if let Some(old) = self.dh_pub_remote {
            self.last_remote_pub = Some(old);
        }
        self.dh_pub_remote = Some(header.dh_pub);

        let (new_root_send, new_send_chain) = kdf_root(&self.root_key, dh_secret_send);
        self.root_key.zeroize();
        self.root_key = new_root_send;
        self.chain_key_send.zeroize();
        self.chain_key_send = new_send_chain;
        self.dh_pub_local = *new_local_pub;

        self.prev_chain_len_send = self.msg_num_send;
        self.msg_num_send = 0;
        self.msg_counter_send = 0;
        self.msg_num_recv = header.msg_num.checked_add(1)
            .ok_or_else(|| RatchetError::Protocol("Message counter overflow".into()))?;
        self.ratchet_id = self.ratchet_id.checked_add(1)
            .ok_or_else(|| RatchetError::Protocol("Ratchet ID overflow".into()))?;

        if let Some(ref mut mac) = self.last_mac_key {
            self.pending_reveal_macs.push(mac.clone());
            mac.zeroize();
        }
        self.last_mac_key = None;

        self.seen.insert(&header.dh_pub, header.msg_num);

        let mkmac = kdf_mkmac(&recv_enc_key);
        recv_enc_key.zeroize();
        self.queue_reveal(&mkmac);
        Ok(DecryptResult { plaintext: pt, mac_key: mkmac.to_vec() })
    }

    // ── Check if a new DH public key was used ──────────────────
    pub fn is_new_dh(&self, header_bytes: &[u8]) -> bool {
        if let Some(remote) = &self.dh_pub_remote {
            if let Some(dh_pub) = RatchetHeader::peek_dh_pub(header_bytes) {
                return bool::from(!dh_pub.ct_eq(remote.as_slice()));
            }
        }
        true  // if no remote, then any key is new
    }

    // ── Utility to extract DH public key from header (static) ───
    pub fn header_dh_pub(header_bytes: &[u8]) -> Option<[u8; 56]> {
        if header_bytes.len() >= 56 {
            let mut pk = [0u8; 56];
            pk.copy_from_slice(&header_bytes[..56]);
            Some(pk)
        } else {
            None
        }
    }

    // ── Internal helper ────────────────────────────────────────
    fn aes_decrypt(&self, enc_key: &[u8; 32],
                   header_bytes: &[u8], ciphertext: &[u8],
                   nonce: &[u8; 12], tag: &[u8; 16]) -> Result<Vec<u8>, RatchetError> {
        let mut aad = Vec::with_capacity(header_bytes.len() + self.ad.len());
        aad.extend_from_slice(header_bytes);
        aad.extend_from_slice(&self.ad);

        let mut ct_with_tag = ciphertext.to_vec();
        ct_with_tag.extend_from_slice(tag);

        let cipher = Aes256Gcm::new_from_slice(enc_key)
            .map_err(|e| RatchetError::DecryptionFailed(format!("AES key error: {e}")))?;
        cipher.decrypt(&Nonce::from(*nonce), aes_gcm::aead::Payload { msg: &ct_with_tag, aad: &aad })
            .map_err(|_| RatchetError::DecryptionFailed("AES‑GCM authentication failed".into()))
    }

    // skip_keys() removed: it advanced chain_key_recv and msg_num_recv
    // BEFORE the message authenticated, so one forged packet
    // permanently desynchronised the receive chain. decrypt_same_dh
    // and decrypt_new_dh now derive into scratch and commit only
    // after the AEAD tag verifies. See tests::forged_frame_does_not
    // _desync_the_receive_chain.
}

// ── PyO3 wrapper with ALL required methods ──────────────────────────
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};

#[pyclass(name = "RustDoubleRatchet")]
pub struct RustDoubleRatchet {
    inner: DoubleRatchet,
    /// v10.14.0: the DAKE extra symmetric key (usage 0x1F), retained so a
    /// file transfer can derive a wrapping key from it.
    ///
    /// It used to be zeroized inside `from_dake_keys` along with the rest of
    /// DakeSessionKeys, which is why nothing could reach it.  It is kept here
    /// rather than on the inner DoubleRatchet deliberately: the inner struct
    /// is the ratchet proper and nothing about its derivations changes.
    ///
    /// WHY THIS KEY AND NOT A CHAIN KEY.  Chain and root keys advance, so a
    /// transfer keyed from one would break the moment the session ratcheted --
    /// which the transfer must survive (see the file-transfer lifetime rule).
    /// The extra symmetric key is fixed for the session, is what OTRv4
    /// reserves for exactly this kind of out-of-band use, and both peers
    /// derive the identical value from the DAKE.
    ///
    /// `None` for a ratchet built by `new()` -- the test and legacy path,
    /// which has no DAKE behind it and therefore no such key.
    extra_sym_key: Option<crate::secure_mem::SecretBytes<32>>,
}

#[pymethods]
impl RustDoubleRatchet {
    #[new]
    #[pyo3(signature = (root_key, chain_key_send, chain_key_recv, brace_key, dh_pub_local, is_initiator))]
    fn new(
        root_key: &[u8], chain_key_send: &[u8], chain_key_recv: &[u8],
        brace_key: &[u8], dh_pub_local: &[u8], is_initiator: bool,
    ) -> PyResult<Self> {
        let rk: &[u8; 32] = root_key.try_into()
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("root_key must be 32 bytes"))?;
        let cks: &[u8; 32] = chain_key_send.try_into()
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("chain_key_send must be 32 bytes"))?;
        let ckr: &[u8; 32] = chain_key_recv.try_into()
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("chain_key_recv must be 32 bytes"))?;
        let bk: &[u8; 32] = brace_key.try_into()
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("brace_key must be 32 bytes"))?;
        let pub_local: &[u8; 56] = dh_pub_local.try_into()
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("dh_pub_local must be 56 bytes"))?;
        let inner = DoubleRatchet::new(rk, cks, ckr, bk, pub_local, is_initiator)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        // No DAKE behind this constructor, so no extra symmetric key: a file
        // transfer over such a session fails closed rather than keying from
        // something weaker.
        Ok(Self { inner, extra_sym_key: None })
    }

    /// SECURITY (audit C2 partial - Patch-1, hardened in Patch-2): consume a
    /// `Dakeresult` directly into a ratchet.
    ///
    /// Patch-2 hardening:
    ///   §2  - Aggressive zeroization: every secret Vec<u8> has its contents
    ///         overwritten, then `clear()` + `shrink_to_fit()` to drop backing
    ///         capacity so the allocator may immediately reuse the memory.
    ///   §3  - Sets `result.consumed = true` BEFORE returning, so any
    ///         subsequent attempt to read `result.root_key` etc. raises
    ///         `Dakeresult has been consumed` from Python.
    ///   §4  - One flag covers the whole object: no partial reuse.
    ///   §7  - Defensive precondition assertion: refuses to consume a
    ///         Dakeresult that is already consumed (returns PyValueError;
    ///         no panic).
    ///
    /// Python adapter pattern:
    ///   ratchet = RustDoubleRatchet.from_dakeresult(dake_result, dh_pub_local, is_initiator)
    ///   # dake_result.consumed == True; reading any secret field raises.
    #[staticmethod]
    fn from_dakeresult(
        result:       &Bound<'_, pyo3::PyAny>,
        dh_pub_local: &[u8],
        is_initiator: bool,
    ) -> PyResult<Self> {
        use pyo3::exceptions::PyValueError;
        use crate::dake::Dakeresult;

        // §7 - defensive precondition: refuse already-consumed.
        // PyO3 0.21+ idiom: downcast directly to `Bound<Dakeresult>`, then
        // `borrow_mut()` returns a `PyRefMut<Dakeresult>` (PyCell is deprecated).
        let cell: &pyo3::Bound<'_, Dakeresult> = result.downcast::<Dakeresult>()
            .map_err(|_| PyValueError::new_err(
                "from_dakeresult: argument must be a Dakeresult instance",
            ))?;
        let mut bound: pyo3::PyRefMut<'_, Dakeresult> = cell.borrow_mut();

        if bound.consumed {
            return Err(PyValueError::new_err(
                "Dakeresult has been consumed - cannot consume twice",
            ));
        }

        // Helper closure: take Vec<u8> out of an Option, validate length,
        // copy into [u8; 32], zero the original Vec aggressively
        // (overwrite + clear + shrink_to_fit), then set the slot to None.
        // Patch-2 §2 implementation.
        fn take_aggressive(
            slot: &mut Option<Vec<u8>>,
            field_name: &'static str,
            need: usize,
        ) -> PyResult<[u8; 32]> {
            let mut v = slot.take().ok_or_else(|| PyValueError::new_err(
                format!("Dakeresult.{field_name} is None - DAKE failed or already consumed"),
            ))?;
            if v.len() != need {
                // Wipe before drop even on the error path.
                for b in v.iter_mut() { *b = 0u8; }
                v.clear();
                v.shrink_to_fit();
                return Err(PyValueError::new_err(format!(
                    "Dakeresult.{field_name}: expected {need} bytes, got {}", v.len(),
                )));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&v);

            // §2 - aggressive zero: overwrite contents, clear length, free capacity.
            for b in v.iter_mut() { *b = 0u8; }
            v.clear();
            v.shrink_to_fit();
            drop(v);

            Ok(arr)
        }

        // Get a single &mut Dakeresult from the PyRefMut so all field
        // accesses below go through one well-typed borrow.
        let dr: &mut Dakeresult = &mut *bound;

        let root_key    = take_aggressive(&mut dr.root_key,    "root_key",    32)?;
        let chain_key_a = take_aggressive(&mut dr.chain_key_a, "chain_key_a", 32)?;
        let chain_key_b = take_aggressive(&mut dr.chain_key_b, "chain_key_b", 32)?;
        let brace_key   = take_aggressive(&mut dr.brace_key,   "brace_key",   32)?;

        // mac_key - secret, but not consumed by the ratchet constructor itself.
        // Aggressively zero it anyway so it does not linger after this call.
        // Explicit type annotation on the binding so PyRefMut's deref doesn't
        // confuse the compiler about the closure body's iter_mut element type.
        let mac_key_taken: Option<Vec<u8>> = dr.mac_key.take();
        if let Some(mut v) = mac_key_taken {
            for b in v.iter_mut() { *b = 0u8; }
            v.clear();
            v.shrink_to_fit();
            drop(v);
        }

        // §3 + §4 - mark whole object consumed.  Idempotent guard: even though
        // we already drained the Vecs above, calling mark_consumed_and_zero
        // ensures consumed=true and any residual fields (mac_key was already
        // taken; this catches future-added secret fields automatically).
        dr.mark_consumed_and_zero();

        // Drop the borrow before constructing the ratchet so PyO3 doesn't
        // hold the Dakeresult locked.
        drop(bound);

        let pub_local: &[u8; 56] = dh_pub_local.try_into()
            .map_err(|_| PyValueError::new_err("dh_pub_local must be 56 bytes"))?;

        let inner = DoubleRatchet::new(
            &root_key, &chain_key_a, &chain_key_b, &brace_key, pub_local, is_initiator,
        ).map_err(|e| PyValueError::new_err(e.to_string()))?;

        // §8 (optional) - Force drop of temporary key arrays.  These are
        // [u8; 32] on the stack; once they go out of scope at the end of
        // this function they cannot be accessed.  We do not zero them here
        // because `DoubleRatchet::new` has already copied them into its own
        // ZeroizeOnDrop-managed fields, and these stack arrays are about
        // to be popped.  An attacker with stack-read primitive between this
        // line and function return would see them, but at that level of
        // capability the attacker can also read the ratchet itself.
        let _ = (root_key, chain_key_a, chain_key_b, brace_key);

        // Legacy Dakeresult path: the extra symmetric key was never carried
        // on that object, so it is not available here.  File transfer refuses
        // rather than substituting a different secret.
        Ok(Self { inner, extra_sym_key: None })
    }

    /// Begin sending a file over this session.  v10.14.0.
    ///
    /// Returns a sender that owns a fresh FileKey.  The wrapping key is
    /// derived here, inside Rust, from the session's DAKE extra symmetric key
    /// and the transfer id, and is never materialised anywhere Python can see.
    /// Python receives a handle and an opaque envelope.
    ///
    /// Fails closed on a session with no extra symmetric key -- a ratchet
    /// built by the legacy or test constructors -- rather than falling back
    /// to some other secret.
    fn file_sender(&self, transfer_id: &[u8])
        -> PyResult<crate::filetransfer::PyFileSender>
    {
        let key = self.extra_sym_key.as_ref().ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err(
                "this session has no extra symmetric key, so a file transfer \
                 cannot be keyed from it")
        })?;
        let id = crate::filetransfer::transfer_id_from(transfer_id)?;
        crate::filetransfer::PyFileSender::create(key, id)
    }

    /// Accept a file offered on this session.  v10.14.0.
    ///
    /// The envelope only opens if it was sealed by the peer this session was
    /// established with, for this transfer id.  Both are authenticated, so a
    /// replayed or redirected offer fails here rather than later.
    fn file_receiver(&self, transfer_id: &[u8], envelope: &[u8])
        -> PyResult<crate::filetransfer::PyFileReceiver>
    {
        let key = self.extra_sym_key.as_ref().ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err(
                "this session has no extra symmetric key, so a file transfer \
                 cannot be keyed from it")
        })?;
        let id = crate::filetransfer::transfer_id_from(transfer_id)?;
        crate::filetransfer::PyFileReceiver::create(key, id, envelope)
    }

    /// Whether this session can key a file transfer at all.
    #[getter]
    fn supports_file_transfer(&self) -> bool { self.extra_sym_key.is_some() }

    fn set_ad(&mut self, ad: &[u8]) { self.inner.set_ad(ad); }
    fn needs_rekey(&self) -> bool { self.inner.needs_rekey() }
    fn local_pub<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.inner.local_pub())
    }
    fn ratchet_id(&self) -> u32 { self.inner.ratchet_id() }
    // SECURITY (audit C4): brace_key getter REMOVED.
    // The brace key is a session secret and was previously exposed to Python
    // as PyBytes.  No production caller needs this - all rotation happens
    // inside Rust via rotate_brace_key().  Internal Rust accessor preserved
    // (DoubleRatchet::brace_key) for use by Rust code only.

    fn encrypt<'py>(&mut self, py: Python<'py>, plaintext: &[u8]) -> PyResult<Bound<'py, PyDict>> {
        let result = self.inner.encrypt(plaintext)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        let d = PyDict::new(py);
        d.set_item("ciphertext", PyBytes::new(py, &result.ciphertext))?;
        d.set_item("header", PyBytes::new(py, &result.header))?;
        d.set_item("nonce", PyBytes::new(py, &result.nonce))?;
        d.set_item("tag", PyBytes::new(py, &result.tag))?;
        d.set_item("ratchet_id", result.ratchet_id)?;
        let mac_list: Vec<Bound<'_, PyBytes>> = result.reveal_mac_keys.iter()
            .map(|k| PyBytes::new(py, k)).collect();
        d.set_item("reveal_mac_keys", mac_list)?;
        d.set_item("mac_key", PyBytes::new(py, &result.mac_key))?;
        Ok(d)
    }

    fn decrypt_same_dh<'py>(&mut self, py: Python<'py>,
        header: &[u8], ciphertext: &[u8], nonce: &[u8], tag: &[u8]) -> PyResult<Bound<'py, PyDict>> {
        let nonce_arr: &[u8; 12] = nonce.try_into()
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("nonce must be 12 bytes"))?;
        let tag_arr: &[u8; 16] = tag.try_into()
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("tag must be 16 bytes"))?;
        let r = self.inner.decrypt_same_dh(header, ciphertext, nonce_arr, tag_arr)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        let d = PyDict::new(py);
        d.set_item("plaintext", PyBytes::new(py, &r.plaintext))?;
        d.set_item("mac_key", PyBytes::new(py, &r.mac_key))?;
        Ok(d)
    }

    fn decrypt_new_dh<'py>(&mut self, py: Python<'py>,
        header: &[u8], ciphertext: &[u8], nonce: &[u8], tag: &[u8],
        dh_secret_recv: &[u8], dh_secret_send: &[u8], new_local_pub: &[u8],
    ) -> PyResult<Bound<'py, PyDict>> {
        let nonce_arr: &[u8; 12] = nonce.try_into()
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("nonce must be 12 bytes"))?;
        let tag_arr: &[u8; 16] = tag.try_into()
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("tag must be 16 bytes"))?;
        let new_local_pub: &[u8; 56] = new_local_pub.try_into()
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("new_local_pub must be 56 bytes"))?;
        let r = self.inner.decrypt_new_dh(header, ciphertext, nonce_arr, tag_arr,
            dh_secret_recv, dh_secret_send, new_local_pub)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        let d = PyDict::new(py);
        d.set_item("plaintext", PyBytes::new(py, &r.plaintext))?;
        d.set_item("mac_key", PyBytes::new(py, &r.mac_key))?;
        Ok(d)
    }

    fn send_ratchet(&mut self, dh_secret: &[u8], new_local_pub: &[u8]) -> PyResult<()> {
        let new_local_pub: &[u8; 56] = new_local_pub.try_into()
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("new_local_pub must be 56 bytes"))?;
        self.inner.send_ratchet(dh_secret, new_local_pub);
        Ok(())
    }

    fn rotate_brace_key(&mut self, shared_secret: &[u8]) {
        self.inner.rotate_brace_key(shared_secret);
    }

    fn is_new_dh(&self, header_bytes: &[u8]) -> bool {
        self.inner.is_new_dh(header_bytes)
    }

    /// Audit C2: has this endpoint independently derived the MAC key the peer
    /// just revealed?
    ///
    /// Takes a revealed key -- a value that is public by construction -- and
    /// returns a boolean. Nothing secret crosses the boundary in either
    /// direction: the ratchet stores fingerprints, not keys, and returns one
    /// bit. See DoubleRatchet::knows_derived_mac for what False does and does
    /// not prove.
    fn knows_revealed_mac_key(&self, key: &[u8]) -> bool {
        self.inner.knows_derived_mac(key)
    }

    // ── Corrected: returns Python bytes object ────────────────
    fn header_dh_pub<'py>(&self, py: Python<'py>, header_bytes: &[u8]) -> Option<Bound<'py, PyBytes>> {
        DoubleRatchet::header_dh_pub(header_bytes).map(|pk: [u8; 56]| PyBytes::new(py, &pk))
    }

    fn zeroize(&mut self) {
        // Audit I1: infallible (fixed non-zero keys never trip the zero-key
        // guard); use expect to satisfy #![deny(clippy::unwrap_used)].
        let dummy = DoubleRatchet::new(
            &[1u8; 32], &[2u8; 32], &[3u8; 32], &[4u8; 32], &[5u8; 56], false
        ).expect("dummy ratchet uses fixed non-zero keys");
        let old = std::mem::replace(&mut self.inner, dummy);
        drop(old);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 4 - non-PyO3 constructor for DakeOutput.consume_into_ratchet
//
// This impl block is intentionally OUTSIDE the #[pymethods] block because
// PyO3 cannot expose a method that takes a non-PyO3 Rust type
// (DakeSessionKeys here).  The method is callable from Rust code only -
// specifically from dake::DakeOutput::consume_into_ratchet - and accepts
// the secret session keys by-move, never crossing the FFI boundary.
//
// Closes audit findings C2 and C3 (Critical Exposure Window) for the
// Phase 4 path: the keys move from DakeState's local Vec/SecretBytes
// (inside generate_dake2 / process_dake2) → into DakeSessionKeys
// (private Rust type) → into DakeOutput's RefCell<Option<...>> (private
// to Rust; no PyO3 getter) → into this from_dake_keys constructor →
// into DoubleRatchet's owned SecretBytes fields (ZeroizeOnDrop).  At no
// point are they marshalled into PyBytes.
// ─────────────────────────────────────────────────────────────────────────────
impl RustDoubleRatchet {
    /// Construct a RustDoubleRatchet by consuming a DakeSessionKeys bundle
    /// directly.  The keys are moved into the ratchet's owned SecretBytes
    /// fields via DoubleRatchet::new().  After this call, the input
    /// DakeSessionKeys has been moved (Rust ownership) and dropped; its
    /// ZeroizeOnDrop impl wipes the original storage automatically.
    ///
    /// `ad` is the associated-data bytes used for AES-256-GCM in the
    /// ratchet (e.g. b"OTRv4-DATA").  `is_initiator` matches the role
    /// from DAKE; DoubleRatchet::new swaps chain_key_send/recv based on
    /// this flag.
    ///
    /// Returns RatchetError::ZeroChainKey if any of root_key,
    /// chain_key_send, chain_key_recv contained all zero bytes (KDF
    /// failure indicator).  Otherwise infallible.
    pub fn from_dake_keys(
        keys:         crate::secure_mem::DakeSessionKeys,
        ad:           &[u8],
        dh_pub_local: &[u8; 56],
        is_initiator: bool,
    ) -> Result<Self, RatchetError> {
        // Move keys into local stack arrays.  DoubleRatchet::new copies
        // them into its own SecretBytes fields, so the temporary arrays
        // on this stack frame are short-lived.
        let root_key       = *keys.root_key.expose();
        let chain_key_send = *keys.chain_key_send.expose();
        let chain_key_recv = *keys.chain_key_recv.expose();
        let brace_key      = *keys.brace_key.expose();
        // Copied before `drop(keys)` below wipes the original.  This is the
        // only place the extra symmetric key survives DAKE consumption.
        let extra_sym_key  = crate::secure_mem::SecretBytes::<32>::new(
            *keys.extra_sym_key.expose());

        let mut inner = DoubleRatchet::new(
            &root_key, &chain_key_send, &chain_key_recv, &brace_key,
            dh_pub_local, is_initiator,
        )?;
        inner.set_ad(ad);

        // Drop the keys explicitly.  ZeroizeOnDrop on DakeSessionKeys
        // wipes root_key / chain_key_send / chain_key_recv / brace_key /
        // ssid / extra_sym_key in their original locations.  The copies
        // we made for DoubleRatchet::new are now inside `inner` and
        // managed by its own ZeroizeOnDrop.  The temporary arrays on
        // this stack frame are about to be popped; we explicitly bind
        // them to `_` to signal end-of-life.
        drop(keys);
        let _ = (root_key, chain_key_send, chain_key_recv, brace_key);

        Ok(Self { inner, extra_sym_key: Some(extra_sym_key) })
    }
}
// ── Tests ───────────────────────────────────────────────────────────
//
// These exist because RT-1 shipped. The ratchet advanced chain_key_recv
// before authenticating, so one forged packet desynchronised a session
// permanently — and nothing in this crate would have noticed, because
// dake.rs and ratchet.rs between them had zero tests.
//
// Requires `cargo test` to link, which means extension-module must not be
// in `default`. See Cargo.toml.

#[cfg(test)]
mod tests {
    use super::*;

    const RK: [u8; 32] = [0x11; 32];
    const CKA: [u8; 32] = [0x22; 32];
    const CKB: [u8; 32] = [0x33; 32];
    const BK: [u8; 32] = [0x44; 32];

    /// A connected pair. Alice's send chain is Bob's receive chain: `new()`
    /// swaps them for the responder, so both are built from the same inputs.
    fn pair() -> (DoubleRatchet, DoubleRatchet) {
        let alice = DoubleRatchet::new(&RK, &CKA, &CKB, &BK, &[0xAA; 56], true)
            .expect("alice");
        let bob = DoubleRatchet::new(&RK, &CKA, &CKB, &BK, &[0xBB; 56], false)
            .expect("bob");
        (alice, bob)
    }

    fn deliver(rx: &mut DoubleRatchet, m: &EncryptResult)
        -> Result<Vec<u8>, RatchetError> {
        rx.decrypt_same_dh(&m.header, &m.ciphertext, &m.nonce, &m.tag)
          .map(|r| r.plaintext)
    }

    /// Deliver and keep the receive-side MKmac.
    fn deliver_full(rx: &mut DoubleRatchet, m: &EncryptResult)
        -> Result<DecryptResult, RatchetError> {
        rx.decrypt_same_dh(&m.header, &m.ciphertext, &m.nonce, &m.tag)
    }

    // ── Audit C2: revealed-key cross-check ──────────────────────────────

    #[test]
    fn own_send_key_is_accountable() {
        // The peer reveals the MKmac of every message it receives from us.
        let (mut a, _b) = pair();
        let m = a.encrypt(b"hello").unwrap();
        assert!(a.knows_derived_mac(&m.mac_key));
    }

    #[test]
    fn received_key_is_accountable() {
        let (mut a, mut b) = pair();
        let m = a.encrypt(b"hello").unwrap();
        let r = deliver_full(&mut b, &m).unwrap();
        assert!(b.knows_derived_mac(&r.mac_key));
        assert!(b.knows_derived_mac(&m.mac_key));
    }

    #[test]
    fn an_invented_key_is_not_accountable() {
        let (mut a, _b) = pair();
        let _ = a.encrypt(b"hello").unwrap();
        assert!(!a.knows_derived_mac(&[0x5A; 64]));
        assert!(!a.knows_derived_mac(&[0u8; 64]));
    }

    #[test]
    fn a_single_flipped_bit_is_not_accountable() {
        let (mut a, _b) = pair();
        let m = a.encrypt(b"hello").unwrap();
        let mut near = m.mac_key.clone();
        near[0] ^= 0x01;
        assert!(!a.knows_derived_mac(&near));
    }

    #[test]
    fn a_lost_messages_key_is_still_accountable() {
        // The case that would make a naive cross-check fire on honest peers:
        // Alice's first message never arrives, but she reveals its MKmac. Bob
        // holds the skipped MKenc and fingerprints the matching MKmac when he
        // stores it, so he can still account for the key.
        let (mut a, mut b) = pair();
        let lost = a.encrypt(b"never arrives").unwrap();
        let arrived = a.encrypt(b"arrives").unwrap();
        deliver(&mut b, &arrived).unwrap();
        assert!(b.knows_derived_mac(&lost.mac_key));
    }

    #[test]
    fn a_forgery_contributes_nothing_to_the_set() {
        let (mut a, mut b) = pair();
        let m = a.encrypt(b"real").unwrap();
        let mut forged_ct = m.ciphertext.clone();
        forged_ct[0] ^= 0x01;
        assert!(b.decrypt_same_dh(&m.header, &forged_ct, &m.nonce, &m.tag).is_err());
        // The genuine key is still unknown to Bob: he never authenticated it.
        assert!(!b.knows_derived_mac(&m.mac_key));
    }

    #[test]
    fn the_fingerprint_set_is_bounded() {
        let (mut a, _b) = pair();
        for _ in 0..(MAX_MAC_FINGERPRINTS + 200) {
            let _ = a.encrypt(b"x").unwrap();
        }
        assert!(a.derived_mac_fps.len() <= MAX_MAC_FINGERPRINTS);
        assert_eq!(a.derived_mac_fps.len(), a.derived_mac_fp_order.len());
    }

    #[test]
    fn a_message_never_reveals_its_own_key() {
        // encrypt() takes the pending queue before installing the current
        // message's key, so the two can never coincide.
        let (mut a, mut b) = pair();
        for _ in 0..5 {
            let m = a.encrypt(b"x").unwrap();
            assert!(!m.reveal_mac_keys.iter().any(|k| *k == m.mac_key));
            deliver(&mut b, &m).unwrap();
            let r = b.encrypt(b"y").unwrap();
            assert!(!r.reveal_mac_keys.iter().any(|k| *k == r.mac_key));
        }
    }

    #[test]
    fn round_trip() {
        let (mut a, mut b) = pair();
        let m = a.encrypt(b"hello").unwrap();
        assert_eq!(deliver(&mut b, &m).unwrap(), b"hello");
    }

    /// RT-1. The regression that motivated all of this.
    ///
    /// Corrupt one ciphertext byte, deliver it, then deliver a genuine
    /// message. Before the fix the forgery advanced chain_key_recv, so the
    /// genuine message derived from the wrong key and the session was dead
    /// from that point on — every subsequent message failing and advancing
    /// the chain again.
    #[test]
    fn forged_frame_does_not_desync_the_receive_chain() {
        let (mut a, mut b) = pair();

        let good = a.encrypt(b"first").unwrap();
        let mut forged = a.encrypt(b"second").unwrap();
        forged.ciphertext[0] ^= 0x01;

        assert!(deliver(&mut b, &forged).is_err(), "forgery must be rejected");
        assert_eq!(deliver(&mut b, &good).unwrap(), b"first",
                   "a rejected forgery must leave the ratchet untouched");

        // And the session keeps working afterwards.
        let third = a.encrypt(b"third").unwrap();
        assert_eq!(deliver(&mut b, &third).unwrap(), b"third");
    }

    /// RT-1, the skip_keys variant: a forged message claiming a distant
    /// msg_num used to advance the chain by that many steps and move
    /// msg_num_recv forward, after which every genuine message was rejected
    /// as MessageTooOld.
    #[test]
    fn forged_frame_with_a_large_msg_num_does_not_advance_the_counter() {
        let (mut a, mut b) = pair();
        let good = a.encrypt(b"payload").unwrap();

        let mut forged = good.clone();
        // Re-encode the header with a far-future msg_num.
        let hdr = RatchetHeader::decode(&good.header).unwrap();
        let far = RatchetHeader::new(hdr.dh_pub, hdr.prev_chain_len, 900);
        forged.header = far.encode().to_vec();

        assert!(deliver(&mut b, &forged).is_err());
        assert_eq!(b.msg_num_recv, 0, "counter must not move on a forgery");
        assert!(b.skipped.is_empty(), "no keys may be stored for a forgery");
        assert_eq!(deliver(&mut b, &good).unwrap(), b"payload");
    }

    /// RT-2. A forged message must not be able to fill the skipped-key store
    /// and evict the keys a legitimate out-of-order message needs.
    #[test]
    fn forgery_does_not_populate_the_skipped_store() {
        let (mut a, mut b) = pair();
        let m0 = a.encrypt(b"zero").unwrap();
        let _m1 = a.encrypt(b"one").unwrap();
        let m2 = a.encrypt(b"two").unwrap();

        // Genuine out-of-order delivery: m2 first stores a key for m1.
        assert_eq!(deliver(&mut b, &m0).unwrap(), b"zero");
        assert_eq!(deliver(&mut b, &m2).unwrap(), b"two");
        let stored = b.skipped.len();
        assert_eq!(stored, 1, "m1's key should be held");

        let mut forged = a.encrypt(b"forged").unwrap();
        forged.ciphertext[0] ^= 0xFF;
        assert!(deliver(&mut b, &forged).is_err());
        assert_eq!(b.skipped.len(), stored,
                   "a forgery must not add or evict skipped keys");
    }

    /// RT-3. A forgery aimed at a skipped msg_num used to consume the key
    /// before decrypting, destroying it for the genuine message.
    #[test]
    fn failed_decrypt_does_not_consume_a_skipped_key() {
        let (mut a, mut b) = pair();
        let m0 = a.encrypt(b"zero").unwrap();
        let m1 = a.encrypt(b"one").unwrap();
        let m2 = a.encrypt(b"two").unwrap();

        deliver(&mut b, &m0).unwrap();
        deliver(&mut b, &m2).unwrap();          // stores m1's key

        let mut forged = m1.clone();
        forged.ciphertext[0] ^= 0x01;
        assert!(deliver(&mut b, &forged).is_err());

        assert_eq!(deliver(&mut b, &m1).unwrap(), b"one",
                   "the real m1 must still decrypt after a forgery hit it");
    }

    // ── L1: MAC-key revelation ───────────────────────────────────────

    /// The bug: kdf_chain returned [0u8; 32] as MKmac, so every key queued
    /// for revelation was 32 zero bytes and revealing them proved nothing.
    #[test]
    fn mkmac_is_64_bytes_and_not_zero() {
        let (_, _, mkmac) = kdf_chain(&CKA);
        assert_eq!(mkmac.len(), 64, "OTRv4 §4.4.2 requires a 64-byte MKmac");
        assert!(mkmac.iter().any(|&b| b != 0), "MKmac must not be all-zero");
    }

    /// MKmac must derive from MKenc, not from the chain key, so that
    /// revealing it exposes nothing about the chain's future.
    #[test]
    fn mkmac_derives_from_the_message_key() {
        let (_, mkenc, mkmac) = kdf_chain(&CKA);
        assert_eq!(kdf_mkmac(&mkenc), mkmac);
        let (_, other_enc, _) = kdf_chain(&CKB);
        assert_ne!(kdf_mkmac(&other_enc), mkmac);
    }

    /// The sender's MKmac and the receiver's MKmac for the same message must
    /// be equal — otherwise the revealed key cannot forge that message.
    #[test]
    fn sender_and_receiver_agree_on_mkmac() {
        let (mut a, mut b) = pair();
        let m = a.encrypt(b"authentic").unwrap();
        let r = deliver_full(&mut b, &m).unwrap();
        assert_eq!(r.plaintext, b"authentic");
        assert_eq!(m.mac_key.len(), 64);
        assert_eq!(r.mac_key, m.mac_key,
                   "the key that authenticated the message must be the key \
                    both sides derive");
        assert!(r.mac_key.iter().any(|&x| x != 0));
    }

    /// The receive path queued nothing before this fix: last_mac_key was
    /// assigned only in encrypt_message. Deniability turns on revealing the
    /// keys that authenticated messages you RECEIVED.
    #[test]
    fn receive_side_mkmac_is_queued_for_revelation() {
        let (mut a, mut b) = pair();
        let m = a.encrypt(b"received").unwrap();
        let r = deliver_full(&mut b, &m).unwrap();

        let next = b.encrypt(b"reply").unwrap();
        assert!(next.reveal_mac_keys.iter().any(|k| k == &r.mac_key),
                "the MKmac that authenticated an inbound message must be \
                 revealed");
        for k in &next.reveal_mac_keys {
            assert_eq!(k.len(), 64);
            assert!(k.iter().any(|&x| x != 0), "no all-zero key may be revealed");
        }
    }

    /// Skipped messages take a different code path and must behave the same.
    #[test]
    fn skipped_message_mkmac_is_queued() {
        let (mut a, mut b) = pair();
        let m0 = a.encrypt(b"zero").unwrap();
        let m1 = a.encrypt(b"one").unwrap();
        let m2 = a.encrypt(b"two").unwrap();

        deliver_full(&mut b, &m0).unwrap();
        deliver_full(&mut b, &m2).unwrap();          // m1's key is skipped
        let r1 = deliver_full(&mut b, &m1).unwrap(); // arrives late
        assert_eq!(r1.mac_key, m1.mac_key,
                   "the skipped path must derive the same MKmac");

        let reply = b.encrypt(b"reply").unwrap();
        assert!(reply.reveal_mac_keys.iter().any(|k| k == &r1.mac_key));
    }

    /// A forgery must not leak a MAC key: nothing is queued if the message
    /// never authenticated.
    #[test]
    fn forgery_reveals_nothing() {
        let (mut a, mut b) = pair();
        let mut forged = a.encrypt(b"x").unwrap();
        forged.ciphertext[0] ^= 0x01;
        assert!(deliver_full(&mut b, &forged).is_err());
        let reply = b.encrypt(b"reply").unwrap();
        assert!(reply.reveal_mac_keys.is_empty(),
                "an unauthenticated message must not queue a MAC key");
    }

    /// An empty queue must stay empty — never a placeholder zero key.
    #[test]
    fn empty_reveal_queue_is_empty_not_zero_padded() {
        let (mut a, _b) = pair();
        let m = a.encrypt(b"first").unwrap();
        assert!(m.reveal_mac_keys.is_empty());
    }

    #[test]
    fn reveal_queue_is_bounded() {
        let (mut a, mut b) = pair();
        for i in 0..200 {
            let m = a.encrypt(format!("m{i}").as_bytes()).unwrap();
            deliver_full(&mut b, &m).unwrap();
        }
        let reply = b.encrypt(b"reply").unwrap();
        assert!(reply.reveal_mac_keys.len() <= 50,
                "got {}", reply.reveal_mac_keys.len());
    }

    #[test]
    fn out_of_order_delivery_works() {
        let (mut a, mut b) = pair();
        let msgs: Vec<_> = (0..5)
            .map(|i| a.encrypt(format!("m{i}").as_bytes()).unwrap())
            .collect();
        for i in [4usize, 0, 3, 1, 2] {
            assert_eq!(deliver(&mut b, &msgs[i]).unwrap(),
                       format!("m{i}").as_bytes());
        }
    }

    #[test]
    fn replay_is_rejected() {
        let (mut a, mut b) = pair();
        let m = a.encrypt(b"once").unwrap();
        assert_eq!(deliver(&mut b, &m).unwrap(), b"once");
        assert!(matches!(deliver(&mut b, &m),
                         Err(RatchetError::ReplayDetected(_))));
    }

    #[test]
    fn skip_beyond_max_is_refused() {
        let (mut a, mut b) = pair();
        let good = a.encrypt(b"x").unwrap();
        let hdr = RatchetHeader::decode(&good.header).unwrap();
        let far = RatchetHeader::new(hdr.dh_pub, hdr.prev_chain_len,
                                     MAX_SKIP + 1);
        let mut forged = good.clone();
        forged.header = far.encode().to_vec();
        assert!(matches!(deliver(&mut b, &forged),
                         Err(RatchetError::MaxSkipExceeded(_))));
        assert!(b.skipped.is_empty());
    }

    #[test]
    fn zero_chain_key_is_refused() {
        assert!(DoubleRatchet::new(&RK, &[0u8; 32], &CKB, &BK, &[0xAA; 56], true)
                .is_err());
        assert!(DoubleRatchet::new(&[0u8; 32], &CKA, &CKB, &BK, &[0xAA; 56], true)
                .is_err());
    }

    #[test]
    fn a_long_conversation_stays_in_sync() {
        let (mut a, mut b) = pair();
        for i in 0..200 {
            let m = a.encrypt(format!("msg {i}").as_bytes()).unwrap();
            assert_eq!(deliver(&mut b, &m).unwrap(),
                       format!("msg {i}").as_bytes(),
                       "desync at message {i}");
        }
        assert!(b.skipped.len() <= MAX_MESSAGE_KEYS);
    }
}
