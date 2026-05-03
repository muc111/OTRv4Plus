/// OTRv4 Double Ratchet (spec §4.4) in Rust.
///
/// Handles: chain key advancement, AES‑256‑GCM encrypt/decrypt,
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

const MAX_SKIP: u32 = 1000;
const MAX_MESSAGE_KEYS: usize = 2000;
const MAX_SEEN: usize = 10_000;
const REKEY_INTERVAL: u32 = 50;
const AD_DEFAULT: &[u8] = b"OTRv4-DATA";

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
            for mac in self.pending_reveal_macs.drain(..drain_n) {
                drop(mac);
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
        let (mut next_ck, mut enc_key, mac_key) = kdf_chain(&self.chain_key_send);
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
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext_with_tag = cipher
            .encrypt(nonce, aes_gcm::aead::Payload { msg: plaintext, aad: &aad })
            .map_err(|e| RatchetError::Protocol(format!("AES encrypt error: {e}")))?;

        let ct_len = ciphertext_with_tag.len().checked_sub(16)
            .ok_or_else(|| RatchetError::Protocol("Ciphertext too short".into()))?;
        let ciphertext = ciphertext_with_tag[..ct_len].to_vec();
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&ciphertext_with_tag[ct_len..]);

        enc_key.zeroize();
        self.last_mac_key = Some(mac_key.to_vec());

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
        })
    }

    // ── Decrypt same DH ────────────────────────────────────────
    pub fn decrypt_same_dh(
        &mut self, header_bytes: &[u8], ciphertext: &[u8],
        nonce: &[u8; 12], tag: &[u8; 16],
    ) -> Result<Vec<u8>, RatchetError> {
        let header = RatchetHeader::decode(header_bytes)?;

        if self.seen.contains(&header.dh_pub, header.msg_num) {
            return Err(RatchetError::ReplayDetected(format!(
                "dh={:02x}{:02x}…, n={}", header.dh_pub[0], header.dh_pub[1], header.msg_num
            )));
        }

        if self.dh_pub_remote.is_none() {
            self.dh_pub_remote = Some(header.dh_pub);
        }

        let skip_id = SkipId { dh_pub: header.dh_pub, msg_num: header.msg_num };
        if let Some(skipped) = self.skipped.remove(&skip_id) {
            let pt = self.aes_decrypt(&skipped.enc_key, header_bytes, ciphertext, nonce, tag)?;
            self.seen.insert(&header.dh_pub, header.msg_num);
            return Ok(pt);
        }

        if header.msg_num > self.msg_num_recv {
            self.skip_keys(&header.dh_pub, header.msg_num)?;
        }

        if header.msg_num < self.msg_num_recv {
            return Err(RatchetError::MessageTooOld(format!(
                "msg_num={} < recv_counter={}", header.msg_num, self.msg_num_recv
            )));
        }

        let (mut next_ck, mut enc_key, _) = kdf_chain(&self.chain_key_recv);
        self.chain_key_recv.zeroize();
        self.chain_key_recv = next_ck;
        next_ck.zeroize();

        let pt = self.aes_decrypt(&enc_key, header_bytes, ciphertext, nonce, tag)?;
        enc_key.zeroize();

        self.msg_num_recv = header.msg_num.checked_add(1)
            .ok_or_else(|| RatchetError::Protocol("Message counter overflow".into()))?;
        self.seen.insert(&header.dh_pub, header.msg_num);
        Ok(pt)
    }

    // ── Decrypt with DH ratchet ─────────────────────────────────
    pub fn decrypt_new_dh(
        &mut self, header_bytes: &[u8], ciphertext: &[u8],
        nonce: &[u8; 12], tag: &[u8; 16],
        dh_secret_recv: &[u8], dh_secret_send: &[u8], new_local_pub: &[u8; 56],
    ) -> Result<Vec<u8>, RatchetError> {
        let header = RatchetHeader::decode(header_bytes)?;

        if self.seen.contains(&header.dh_pub, header.msg_num) {
            return Err(RatchetError::ReplayDetected(format!(
                "dh={:02x}{:02x}…, n={}", header.dh_pub[0], header.dh_pub[1], header.msg_num
            )));
        }
        if header.msg_num > self.max_skip {
            return Err(RatchetError::MaxSkipExceeded(header.msg_num));
        }

        let (new_root_recv, new_recv_chain) = kdf_root(&self.root_key, dh_secret_recv);

        let mut temp_ck = new_recv_chain;
        for _ in 0..header.msg_num {
            let (next, _, _) = kdf_chain(&temp_ck);
            temp_ck.zeroize();
            temp_ck = next;
        }
        let (next_recv_ck, mut enc_key, _) = kdf_chain(&temp_ck);
        temp_ck.zeroize();

        let pt = self.aes_decrypt(&enc_key, header_bytes, ciphertext, nonce, tag)?;
        enc_key.zeroize();

        self.root_key.zeroize();
        self.root_key = new_root_recv;
        self.chain_key_recv.zeroize();
        self.chain_key_recv = next_recv_ck;

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

        while self.skipped.len() > MAX_MESSAGE_KEYS {
            if let Some(first_key) = self.skipped.keys().next().cloned() {
                self.skipped.remove(&first_key);
            }
        }

        self.seen.insert(&header.dh_pub, header.msg_num);
        Ok(pt)
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
        cipher.decrypt(Nonce::from_slice(nonce), aes_gcm::aead::Payload { msg: &ct_with_tag, aad: &aad })
            .map_err(|_| RatchetError::DecryptionFailed("AES‑GCM authentication failed".into()))
    }

    fn skip_keys(&mut self, dh_pub: &[u8; 56], target: u32) -> Result<(), RatchetError> {
        if target <= self.msg_num_recv { return Ok(()); }
        let skip_count = target.checked_sub(self.msg_num_recv)
            .ok_or_else(|| RatchetError::Protocol("Skip count overflow".into()))?;
        if skip_count > self.max_skip {
            return Err(RatchetError::MaxSkipExceeded(skip_count));
        }
        for n in self.msg_num_recv..target {
            let (mut next_ck, enc_key, _) = kdf_chain(&self.chain_key_recv);
            self.chain_key_recv.zeroize();
            self.chain_key_recv = next_ck;
            next_ck.zeroize();
            let skip_id = SkipId { dh_pub: *dh_pub, msg_num: n };
            self.skipped.insert(skip_id, SkippedKey { enc_key });
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

// ── PyO3 wrapper with ALL required methods ──────────────────────────
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};

#[pyclass(name = "RustDoubleRatchet")]
pub struct RustDoubleRatchet {
    inner: DoubleRatchet,
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
        Ok(Self { inner })
    }

    fn set_ad(&mut self, ad: &[u8]) { self.inner.set_ad(ad); }
    fn needs_rekey(&self) -> bool { self.inner.needs_rekey() }
    fn local_pub<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, self.inner.local_pub())
    }
    fn ratchet_id(&self) -> u32 { self.inner.ratchet_id() }
    fn brace_key<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, self.inner.brace_key())
    }

    fn encrypt<'py>(&mut self, py: Python<'py>, plaintext: &[u8]) -> PyResult<Bound<'py, PyDict>> {
        let result = self.inner.encrypt(plaintext)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        let d = PyDict::new_bound(py);
        d.set_item("ciphertext", PyBytes::new_bound(py, &result.ciphertext))?;
        d.set_item("header", PyBytes::new_bound(py, &result.header))?;
        d.set_item("nonce", PyBytes::new_bound(py, &result.nonce))?;
        d.set_item("tag", PyBytes::new_bound(py, &result.tag))?;
        d.set_item("ratchet_id", result.ratchet_id)?;
        let mac_list: Vec<Bound<'_, PyBytes>> = result.reveal_mac_keys.iter()
            .map(|k| PyBytes::new_bound(py, k)).collect();
        d.set_item("reveal_mac_keys", mac_list)?;
        Ok(d)
    }

    fn decrypt_same_dh<'py>(&mut self, py: Python<'py>,
        header: &[u8], ciphertext: &[u8], nonce: &[u8], tag: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let nonce_arr: &[u8; 12] = nonce.try_into()
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("nonce must be 12 bytes"))?;
        let tag_arr: &[u8; 16] = tag.try_into()
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("tag must be 16 bytes"))?;
        let plaintext = self.inner.decrypt_same_dh(header, ciphertext, nonce_arr, tag_arr)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        Ok(PyBytes::new_bound(py, &plaintext))
    }

    fn decrypt_new_dh<'py>(&mut self, py: Python<'py>,
        header: &[u8], ciphertext: &[u8], nonce: &[u8], tag: &[u8],
        dh_secret_recv: &[u8], dh_secret_send: &[u8], new_local_pub: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let nonce_arr: &[u8; 12] = nonce.try_into()
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("nonce must be 12 bytes"))?;
        let tag_arr: &[u8; 16] = tag.try_into()
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("tag must be 16 bytes"))?;
        let new_local_pub: &[u8; 56] = new_local_pub.try_into()
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("new_local_pub must be 56 bytes"))?;
        let plaintext = self.inner.decrypt_new_dh(header, ciphertext, nonce_arr, tag_arr,
            dh_secret_recv, dh_secret_send, new_local_pub)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        Ok(PyBytes::new_bound(py, &plaintext))
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

    // ── Corrected: returns Python bytes object ────────────────
    fn header_dh_pub<'py>(&self, py: Python<'py>, header_bytes: &[u8]) -> Option<Bound<'py, PyBytes>> {
        DoubleRatchet::header_dh_pub(header_bytes).map(|pk: [u8; 56]| PyBytes::new_bound(py, &pk))
    }

    fn zeroize(&mut self) {
        let dummy = DoubleRatchet::new(
            &[1u8; 32], &[2u8; 32], &[3u8; 32], &[4u8; 32], &[5u8; 56], false
        ).unwrap();
        let old = std::mem::replace(&mut self.inner, dummy);
        drop(old);
    }
}