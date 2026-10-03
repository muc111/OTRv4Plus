// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
//! Group voice media keys: AES-256-GCM frames under keys from the MLS
//! exporter (MLS_SECURITY_HARDENING.md §5, commit M5).
//!
//! THE KEY SCHEDULE
//! ================
//!   root        = MLS-Exporter("OTRv4+GroupVoice/v1", call_id, 64)
//!                 -- the group's epoch secret, so it is hybrid
//!                 (X448+ML-KEM-1024) since M4, and new with every epoch
//!   sender key  = HKDF-SHA512(ikm = root, salt = call_id,
//!                             info = "OTRv4+GroupVoice/Sender/v1" || LP(call_id)
//!                                    || u64(epoch) || u32(sender leaf index))
//!   ratchet     = HKDF-SHA512(ikm = key, salt = "", info = "OTRv4+GroupVoice/Ratchet/v1"),
//!                 once every RATCHET_INTERVAL frames (sub-epoch = counter / interval);
//!                 the previous key is dropped, so a later compromise does not
//!                 open earlier frames of the same epoch
//!   nonce       = u32(epoch) || u64(counter) -- derived, never sent as such;
//!                 unique because each sender has its own key and counter
//!   frame       = header (16) || AES-256-GCM(ciphertext || tag)
//!   header      = "G" || 0x01 || u16(sender) || u32(epoch) || u64(counter)
//!   AAD         = header || LP(call_id)
//!
//! The same AEAD, nonce rule and ratchet as 1:1 voice (`Rust/src/voice.rs`),
//! with the 1:1 direction byte replaced by the sender's leaf index.
//!
//! A new MLS epoch (any commit, and the call's 120 s self-update) gives a new
//! root. The previous epoch is kept only to finish frames already in flight
//! (`drop_previous`), then zeroized.
//!
//! LIMIT (stated in the hardening document): every member of the epoch can
//! derive every sender's key, so a member could forge another member's audio
//! -- as in SRTP or SFrame with group keys. Outsiders, the server and
//! anyone removed from the group cannot. Media frames are not signed: a
//! per-frame ML-DSA signature (4.6 KB) on a 60 ms Opus frame is not viable.

use std::collections::HashMap;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::Zeroizing;

pub const EXPORT_LABEL: &str = "OTRv4+GroupVoice/v1";
const LABEL_SENDER: &[u8] = b"OTRv4+GroupVoice/Sender/v1";
const LABEL_RATCHET: &[u8] = b"OTRv4+GroupVoice/Ratchet/v1";
pub const ROOT_LEN: usize = 64;
const KEY_LEN: usize = 32;
pub const HEADER_LEN: usize = 16;
const MAGIC: u8 = b'G';
const VERSION: u8 = 1;
/// Frames per sub-epoch: 500 x 60 ms = 30 s, as 1:1 voice.
pub const RATCHET_INTERVAL: u64 = 500;
/// How far ahead a receiver will ratchet for one frame.
const MAX_SUB_JUMP: u64 = 16;
/// Out-of-order tolerance per sender, in frames.
const REPLAY_WINDOW: u64 = 256;
/// Senders tracked per epoch: a full mesh is for small groups.
pub const MAX_SENDERS: usize = 16;
/// Largest frame accepted (an Opus frame is a few hundred bytes).
pub const MAX_FRAME: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoiceError {
    BadRoot,
    Malformed,
    WrongEpoch,
    OwnFrame,
    TooManySenders,
    TooFarAhead,
    Replayed,
    Auth,
    Exhausted,
    Zeroized,
}

fn lp(value: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}

fn sender_key(root: &[u8], call_id: &[u8], epoch: u64, sender: u32)
    -> Zeroizing<[u8; KEY_LEN]>
{
    let mut info = Vec::with_capacity(LABEL_SENDER.len() + 4 + call_id.len() + 12);
    info.extend_from_slice(LABEL_SENDER);
    lp(call_id, &mut info);
    info.extend_from_slice(&epoch.to_be_bytes());
    info.extend_from_slice(&sender.to_be_bytes());
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    Hkdf::<Sha512>::new(Some(call_id), root)
        .expand(&info, &mut key[..])
        .expect("32 bytes is a valid HKDF-SHA512 length");
    key
}

fn ratchet(key: &[u8; KEY_LEN]) -> Zeroizing<[u8; KEY_LEN]> {
    let mut next = Zeroizing::new([0u8; KEY_LEN]);
    Hkdf::<Sha512>::new(Some(b""), key)
        .expand(LABEL_RATCHET, &mut next[..])
        .expect("32 bytes is a valid HKDF-SHA512 length");
    next
}

fn nonce(epoch: u64, counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..4].copy_from_slice(&((epoch & 0xFFFF_FFFF) as u32).to_be_bytes());
    n[4..].copy_from_slice(&counter.to_be_bytes());
    n
}

fn header(sender: u32, epoch: u64, counter: u64) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[0] = MAGIC;
    h[1] = VERSION;
    h[2..4].copy_from_slice(&(sender as u16).to_be_bytes());
    h[4..8].copy_from_slice(&((epoch & 0xFFFF_FFFF) as u32).to_be_bytes());
    h[8..16].copy_from_slice(&counter.to_be_bytes());
    h
}

/// A frame's header, read without any key: (sender, epoch low 32 bits, counter).
pub fn parse_header(packet: &[u8]) -> Result<(u32, u32, u64), VoiceError> {
    if packet.len() < HEADER_LEN + 16 || packet[0] != MAGIC || packet[1] != VERSION {
        return Err(VoiceError::Malformed);
    }
    let sender = u16::from_be_bytes([packet[2], packet[3]]) as u32;
    let epoch = u32::from_be_bytes(packet[4..8].try_into().expect("4 bytes"));
    let counter = u64::from_be_bytes(packet[8..16].try_into().expect("8 bytes"));
    Ok((sender, epoch, counter))
}

fn aad(head: &[u8], call_id: &[u8]) -> Vec<u8> {
    let mut a = Vec::with_capacity(head.len() + 4 + call_id.len());
    a.extend_from_slice(head);
    lp(call_id, &mut a);
    a
}

/// One sender's chain in one epoch.
struct Chain {
    key: Zeroizing<[u8; KEY_LEN]>,
    sub: u64,
}

impl Chain {
    fn advance_to(&mut self, target: u64) -> Result<(), VoiceError> {
        if target < self.sub {
            return Err(VoiceError::Replayed);   // that sub-epoch's key is gone
        }
        if target - self.sub > MAX_SUB_JUMP {
            return Err(VoiceError::TooFarAhead);
        }
        while self.sub < target {
            self.key = ratchet(&self.key);      // the old key drops, zeroized
            self.sub += 1;
        }
        Ok(())
    }

    fn cipher(&self) -> Aes256Gcm {
        Aes256Gcm::new_from_slice(&self.key[..]).expect("32-byte key")
    }
}

struct Receiver {
    chain: Chain,
    highest: Option<u64>,
    /// Bit i set: counter `highest - i` was seen.
    window: u128,
    window_hi: u128,
}

impl Receiver {
    fn seen(&self, counter: u64) -> bool {
        let Some(hi) = self.highest else { return false };
        if counter > hi {
            return false;
        }
        let back = hi - counter;
        if back >= REPLAY_WINDOW {
            return true;                        // too old: treat as replayed
        }
        if back < 128 {
            self.window >> back & 1 == 1
        } else {
            self.window_hi >> (back - 128) & 1 == 1
        }
    }

    fn mark(&mut self, counter: u64) {
        match self.highest {
            None => {
                self.highest = Some(counter);
                self.window = 1;
            }
            Some(hi) if counter > hi => {
                let shift = counter - hi;
                // Shift the 256-bit window (window_hi:window) left by `shift`.
                if shift >= 256 {
                    self.window = 0;
                    self.window_hi = 0;
                } else if shift >= 128 {
                    self.window_hi = self.window << (shift - 128);
                    self.window = 0;
                } else {
                    self.window_hi = (self.window_hi << shift) | (self.window >> (128 - shift));
                    self.window <<= shift;
                }
                self.window |= 1;
                self.highest = Some(counter);
            }
            Some(hi) => {
                let back = hi - counter;
                if back < 128 {
                    self.window |= 1 << back;
                } else if back < 256 {
                    self.window_hi |= 1 << (back - 128);
                }
            }
        }
    }
}

/// The keys of one MLS epoch of one call.
struct EpochKeys {
    epoch: u64,
    /// Our leaf index in this epoch.
    own: u32,
    root: Zeroizing<[u8; ROOT_LEN]>,
    send: Chain,
    receivers: HashMap<u32, Receiver>,
}

impl EpochKeys {
    fn new(root: &[u8], call_id: &[u8], epoch: u64, own: u32) -> Result<Self, VoiceError> {
        if root.len() != ROOT_LEN {
            return Err(VoiceError::BadRoot);
        }
        let mut r = Zeroizing::new([0u8; ROOT_LEN]);
        r.copy_from_slice(root);
        let send = Chain { key: sender_key(&r[..], call_id, epoch, own), sub: 0 };
        Ok(Self { epoch, own, root: r, send, receivers: HashMap::new() })
    }
}

/// A member's view of one group call: seals its own frames, opens the
/// others'. No key has a getter; everything zeroizes on drop.
pub struct GroupVoice {
    call_id: Vec<u8>,
    own: u32,
    send_counter: u64,
    current: Option<EpochKeys>,
    previous: Option<EpochKeys>,
}

impl GroupVoice {
    /// `root` is the MLS exporter output for `epoch` (see
    /// `MlsClient::group_voice`); `own` is our leaf index in that epoch.
    pub fn new(root: &[u8], call_id: &[u8], epoch: u64, own: u32) -> Result<Self, VoiceError> {
        if own > u16::MAX as u32 || call_id.is_empty() || call_id.len() > 64 {
            return Err(VoiceError::Malformed);
        }
        Ok(Self {
            call_id: call_id.to_vec(),
            own,
            send_counter: 0,
            current: Some(EpochKeys::new(root, call_id, epoch, own)?),
            previous: None,
        })
    }

    pub fn epoch(&self) -> Option<u64> { self.current.as_ref().map(|k| k.epoch) }
    pub fn own_index(&self) -> u32 { self.own }
    pub fn send_counter(&self) -> u64 { self.send_counter }
    pub fn has_previous(&self) -> bool { self.previous.is_some() }

    /// A new MLS epoch: new root, new keys, counters from zero. The old
    /// epoch stays only for frames in flight, until `drop_previous`.
    pub fn rekey(&mut self, root: &[u8], epoch: u64, own: u32) -> Result<(), VoiceError> {
        let cur = self.current.as_ref().ok_or(VoiceError::Zeroized)?;
        if epoch <= cur.epoch || own > u16::MAX as u32 {
            return Err(VoiceError::WrongEpoch);
        }
        let next = EpochKeys::new(root, &self.call_id, epoch, own)?;
        self.previous = self.current.replace(next);   // the one before drops
        self.own = own;
        self.send_counter = 0;
        Ok(())
    }

    pub fn drop_previous(&mut self) {
        self.previous = None;
    }

    pub fn seal(&mut self, frame: &[u8]) -> Result<Vec<u8>, VoiceError> {
        if frame.len() > MAX_FRAME {
            return Err(VoiceError::Malformed);
        }
        let counter = self.send_counter;
        if counter == u64::MAX {
            return Err(VoiceError::Exhausted);
        }
        let own = self.own;
        let keys = self.current.as_mut().ok_or(VoiceError::Zeroized)?;
        keys.send.advance_to(counter / RATCHET_INTERVAL)?;
        let head = header(own, keys.epoch, counter);
        let ad = aad(&head, &self.call_id);
        let ct = keys.send.cipher()
            .encrypt(<&Nonce<_>>::from(&nonce(keys.epoch, counter)[..]), Payload { msg: frame, aad: &ad })
            .map_err(|_| VoiceError::Auth)?;
        self.send_counter += 1;
        let mut out = Vec::with_capacity(HEADER_LEN + ct.len());
        out.extend_from_slice(&head);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// (sender leaf index, frame). Refuses our own frames, other epochs,
    /// replays, forgeries, and more than MAX_SENDERS senders.
    pub fn open(&mut self, packet: &[u8]) -> Result<(u32, Zeroizing<Vec<u8>>), VoiceError> {
        if packet.len() > HEADER_LEN + MAX_FRAME + 16 {
            return Err(VoiceError::Malformed);
        }
        let (sender, epoch32, counter) = parse_header(packet)?;
        let call_id = self.call_id.clone();
        let keys = match (&mut self.current, &mut self.previous) {
            (Some(c), _) if (c.epoch & 0xFFFF_FFFF) as u32 == epoch32 => c,
            (_, Some(p)) if (p.epoch & 0xFFFF_FFFF) as u32 == epoch32 => p,
            (None, _) => return Err(VoiceError::Zeroized),
            _ => return Err(VoiceError::WrongEpoch),
        };
        if sender == keys.own {
            return Err(VoiceError::OwnFrame);
        }
        if !keys.receivers.contains_key(&sender) {
            if keys.receivers.len() >= MAX_SENDERS {
                return Err(VoiceError::TooManySenders);
            }
            let chain = Chain { key: sender_key(&keys.root[..], &call_id, keys.epoch, sender), sub: 0 };
            keys.receivers.insert(sender, Receiver { chain, highest: None, window: 0, window_hi: 0 });
        }
        let epoch = keys.epoch;
        let rx = keys.receivers.get_mut(&sender).expect("inserted above");
        if rx.seen(counter) {
            return Err(VoiceError::Replayed);
        }
        // Ratchet a COPY first: a forged frame must not move the chain.
        let target = counter / RATCHET_INTERVAL;
        let mut trial = Chain { key: Zeroizing::new(*rx.chain.key), sub: rx.chain.sub };
        trial.advance_to(target)?;
        let head = &packet[..HEADER_LEN];
        let ad = aad(head, &call_id);
        let pt = trial.cipher()
            .decrypt(<&Nonce<_>>::from(&nonce(epoch, counter)[..]),
                     Payload { msg: &packet[HEADER_LEN..], aad: &ad })
            .map_err(|_| VoiceError::Auth)?;
        rx.chain = trial;
        rx.mark(counter);
        Ok((sender, Zeroizing::new(pt)))
    }

    /// Hang up: every key gone. Further use refuses.
    pub fn zeroize(&mut self) {
        self.current = None;
        self.previous = None;
    }

    pub fn is_zeroized(&self) -> bool { self.current.is_none() }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CALL: &[u8] = b"call-1";

    fn pair() -> (GroupVoice, GroupVoice) {
        let root = [7u8; ROOT_LEN];
        (GroupVoice::new(&root, CALL, 5, 0).unwrap(), GroupVoice::new(&root, CALL, 5, 1).unwrap())
    }

    #[test]
    fn frames_round_trip_and_name_their_sender() {
        let (mut a, mut b) = pair();
        let p = a.seal(b"opus frame").unwrap();
        let (sender, frame) = b.open(&p).unwrap();
        assert_eq!((sender, &frame[..]), (0, &b"opus frame"[..]));
        assert_eq!(a.open(&p).unwrap_err(), VoiceError::OwnFrame);
    }

    #[test]
    fn replay_tamper_and_header_changes_are_refused() {
        let (mut a, mut b) = pair();
        let p = a.seal(b"x").unwrap();
        b.open(&p).unwrap();
        assert_eq!(b.open(&p).unwrap_err(), VoiceError::Replayed);
        let q = a.seal(b"y").unwrap();
        for i in [2usize, 5, 9, HEADER_LEN, q.len() - 1] {
            let mut bad = q.clone();
            bad[i] ^= 1;
            assert!(b.open(&bad).is_err(), "byte {i}");
        }
        // The genuine one still opens: a forgery did not move the chain.
        b.open(&q).unwrap();
    }

    #[test]
    fn senders_have_different_keys_and_nonces_never_collide() {
        let root = [9u8; ROOT_LEN];
        let k0 = sender_key(&root, CALL, 1, 0);
        let k1 = sender_key(&root, CALL, 1, 1);
        assert_ne!(*k0, *k1);
        assert_ne!(*sender_key(&root, CALL, 2, 0), *k0);
        assert_ne!(*sender_key(&root, b"call-2", 1, 0), *k0);
    }

    #[test]
    fn out_of_order_within_the_window_and_ratchet_boundaries() {
        let (mut a, mut b) = pair();
        let frames: Vec<_> = (0..RATCHET_INTERVAL + 5).map(|i| a.seal(&i.to_be_bytes()).unwrap()).collect();
        // Late frames inside the window open; then the next sub-epoch.
        b.open(&frames[3]).unwrap();
        b.open(&frames[1]).unwrap();
        b.open(&frames[2]).unwrap();
        b.open(&frames[RATCHET_INTERVAL as usize + 1]).unwrap();
        // A frame from the dropped sub-epoch can no longer be opened.
        assert!(b.open(&frames[10]).is_err());
        b.open(&frames[RATCHET_INTERVAL as usize]).unwrap();
    }

    #[test]
    fn a_new_epoch_replaces_the_keys_and_the_old_one_can_be_dropped() {
        let (mut a, mut b) = pair();
        let old = a.seal(b"in flight").unwrap();
        a.rekey(&[8u8; ROOT_LEN], 6, 0).unwrap();
        b.rekey(&[8u8; ROOT_LEN], 6, 1).unwrap();
        let new = a.seal(b"after").unwrap();
        assert_eq!(&b.open(&new).unwrap().1[..], b"after");
        assert_eq!(&b.open(&old).unwrap().1[..], b"in flight");
        let old2 = {
            let mut c = GroupVoice::new(&[7u8; ROOT_LEN], CALL, 5, 0).unwrap();
            c.send_counter = 1;
            c.seal(b"late").unwrap()
        };
        b.drop_previous();
        assert_eq!(b.open(&old2).unwrap_err(), VoiceError::WrongEpoch);
        assert_eq!(a.rekey(&[1u8; ROOT_LEN], 6, 0).unwrap_err(), VoiceError::WrongEpoch);
    }

    #[test]
    fn a_different_root_or_call_opens_nothing() {
        let (mut a, _) = pair();
        let p = a.seal(b"x").unwrap();
        let mut other = GroupVoice::new(&[6u8; ROOT_LEN], CALL, 5, 2).unwrap();
        assert_eq!(other.open(&p).unwrap_err(), VoiceError::Auth);
        let mut other = GroupVoice::new(&[7u8; ROOT_LEN], b"call-2", 5, 2).unwrap();
        assert_eq!(other.open(&p).unwrap_err(), VoiceError::Auth);
    }

    #[test]
    fn senders_are_capped_and_hangup_zeroizes() {
        let root = [3u8; ROOT_LEN];
        let mut me = GroupVoice::new(&root, CALL, 1, 0).unwrap();
        for s in 1..=(MAX_SENDERS as u32) {
            let p = GroupVoice::new(&root, CALL, 1, s).unwrap().seal(b"x").unwrap();
            me.open(&p).unwrap();
        }
        let p = GroupVoice::new(&root, CALL, 1, 99).unwrap().seal(b"x").unwrap();
        assert_eq!(me.open(&p).unwrap_err(), VoiceError::TooManySenders);
        me.zeroize();
        assert!(me.is_zeroized());
        assert_eq!(me.seal(b"x").unwrap_err(), VoiceError::Zeroized);
        assert!(GroupVoice::new(&[0u8; 10], CALL, 1, 0).is_err());
    }

    #[test]
    fn the_replay_window_tracks_256_frames() {
        let mut rx = Receiver {
            chain: Chain { key: Zeroizing::new([0u8; KEY_LEN]), sub: 0 },
            highest: None, window: 0, window_hi: 0,
        };
        for c in [0u64, 5, 200, 130, 3] {
            assert!(!rx.seen(c));
            rx.mark(c);
            assert!(rx.seen(c));
        }
        assert!(!rx.seen(4) && !rx.seen(199));
        rx.mark(600);                          // 600 - 256 = 344: older is gone
        assert!(rx.seen(300) && rx.seen(600) && !rx.seen(599));
    }
}
