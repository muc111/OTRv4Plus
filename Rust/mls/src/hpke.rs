// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
//! HPKE (RFC 9180), base mode, for the one suite MLS uses here:
//! KEM ML-KEM-1024 (0x0042), KDF HKDF-SHA384 (0x0002), AEAD AES-256-GCM
//! (0x0002) or export-only (0xFFFF).
//!
//! WHY THIS REPLACES hpke-rs
//! =========================
//! hpke-rs is MPL-2.0: a file-level copyleft component in a product that is
//! offered under AGPL-3.0 OR a commercial licence. It also brought a second
//! SHA-3 implementation (libcrux-sha3, for one SHAKE256 call) and, through
//! it, an unmaintained proc-macro (RUSTSEC-2026-0173). What MLS needs from
//! HPKE is small -- single-shot seal/open, a sender/receiver export, and
//! DeriveKeyPair -- and every primitive is one the core already ships.
//!
//! hpke-rs remains a DEV-dependency only: `tests/hpke_cross.rs` checks this
//! module against it byte for byte (derived keys, exports, and each side
//! opening the other's ciphertext). Nothing from it is compiled into what
//! ships.
//!
//! THE CONSTRUCTION (RFC 9180 §5.1, mode_base; ML-KEM per
//! draft-ietf-hpke-pq, as hpke-rs 0.7.0 implements it)
//!   suite_id      = "HPKE" || kem_id || kdf_id || aead_id
//!   LabeledExtract(salt, label, ikm) = HKDF-Extract(salt, "HPKE-v1"||suite_id||label||ikm)
//!   LabeledExpand(prk, label, info, L) = HKDF-Expand(prk, I2OSP(L,2)||"HPKE-v1"||suite_id||label||info, L)
//!   (shared_secret, enc) = ML-KEM-1024.Encaps(pk_r)       -- used directly
//!   context       = 0x00 || LabeledExtract("", "psk_id_hash", "")
//!                        || LabeledExtract("", "info_hash", info)
//!   secret        = LabeledExtract(shared_secret, "secret", "")
//!   key           = LabeledExpand(secret, "key", context, Nk)
//!   base_nonce    = LabeledExpand(secret, "base_nonce", context, Nn)
//!   exporter      = LabeledExpand(secret, "exp", context, 48)
//!   Export(ctx,L) = LabeledExpand(exporter, "sec", ctx, L)
//!   DeriveKeyPair(ikm) = ML-KEM-1024.KeyGen_internal(d || z = SHAKE256(ikm, 64))
//!
//! Every secret intermediate is `Zeroizing`.

use aes_gcm::{
    aead::{Aead as _, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha384;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use zeroize::Zeroizing;

use crate::mlkem;

const KEM_ID: u16 = 0x0042;
const KDF_ID: u16 = 0x0002;
const NH: usize = 48;
const HPKE_VERSION: &[u8] = b"HPKE-v1";
const MODE_BASE: u8 = 0x00;

/// The AEAD half of the suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Aead {
    Aes256Gcm,
    ExportOnly,
}

impl Aead {
    fn id(self) -> u16 {
        match self {
            Aead::Aes256Gcm => 0x0002,
            Aead::ExportOnly => 0xFFFF,
        }
    }
    fn nk(self) -> usize {
        match self {
            Aead::Aes256Gcm => 32,
            Aead::ExportOnly => 0,
        }
    }
    fn nn(self) -> usize {
        match self {
            Aead::Aes256Gcm => 12,
            Aead::ExportOnly => 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HpkeError {
    InvalidInput,
    Decaps,
    Open,
    Seal,
    Export,
}

fn suite_id(aead: Aead) -> [u8; 10] {
    let mut s = [0u8; 10];
    s[..4].copy_from_slice(b"HPKE");
    s[4..6].copy_from_slice(&KEM_ID.to_be_bytes());
    s[6..8].copy_from_slice(&KDF_ID.to_be_bytes());
    s[8..10].copy_from_slice(&aead.id().to_be_bytes());
    s
}

fn labeled_extract(salt: &[u8], suite: &[u8], label: &[u8], ikm: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut labeled = Zeroizing::new(Vec::with_capacity(
        HPKE_VERSION.len() + suite.len() + label.len() + ikm.len()));
    labeled.extend_from_slice(HPKE_VERSION);
    labeled.extend_from_slice(suite);
    labeled.extend_from_slice(label);
    labeled.extend_from_slice(ikm);
    let (prk, _) = Hkdf::<Sha384>::extract(Some(salt), &labeled);
    Zeroizing::new(prk.to_vec())
}

fn labeled_expand(prk: &[u8], suite: &[u8], label: &[u8], info: &[u8], len: usize)
    -> Result<Zeroizing<Vec<u8>>, HpkeError>
{
    if len > u16::MAX as usize {
        return Err(HpkeError::InvalidInput);
    }
    let mut labeled = Vec::with_capacity(2 + HPKE_VERSION.len() + suite.len() + label.len() + info.len());
    labeled.extend_from_slice(&(len as u16).to_be_bytes());
    labeled.extend_from_slice(HPKE_VERSION);
    labeled.extend_from_slice(suite);
    labeled.extend_from_slice(label);
    labeled.extend_from_slice(info);
    let hk = Hkdf::<Sha384>::from_prk(prk).map_err(|_| HpkeError::InvalidInput)?;
    let mut out = Zeroizing::new(vec![0u8; len]);
    hk.expand(&labeled, &mut out).map_err(|_| HpkeError::InvalidInput)?;
    Ok(out)
}

struct Context {
    aead: Aead,
    suite: [u8; 10],
    key: Zeroizing<Vec<u8>>,
    base_nonce: Zeroizing<Vec<u8>>,
    exporter: Zeroizing<Vec<u8>>,
}

fn key_schedule(shared_secret: &[u8], info: &[u8], aead: Aead) -> Result<Context, HpkeError> {
    let suite = suite_id(aead);
    let psk_id_hash = labeled_extract(&[], &suite, b"psk_id_hash", &[]);
    let info_hash = labeled_extract(&[], &suite, b"info_hash", info);
    let mut ctx = Vec::with_capacity(1 + 2 * NH);
    ctx.push(MODE_BASE);
    ctx.extend_from_slice(&psk_id_hash);
    ctx.extend_from_slice(&info_hash);
    let secret = labeled_extract(shared_secret, &suite, b"secret", &[]);
    Ok(Context {
        aead,
        suite,
        key: labeled_expand(&secret, &suite, b"key", &ctx, aead.nk())?,
        base_nonce: labeled_expand(&secret, &suite, b"base_nonce", &ctx, aead.nn())?,
        exporter: labeled_expand(&secret, &suite, b"exp", &ctx, NH)?,
    })
}

impl Context {
    fn export(&self, exporter_context: &[u8], len: usize) -> Result<Zeroizing<Vec<u8>>, HpkeError> {
        if len > 255 * NH {
            return Err(HpkeError::Export);
        }
        labeled_expand(&self.exporter, &self.suite, b"sec", exporter_context, len)
            .map_err(|_| HpkeError::Export)
    }

    /// Single-shot: sequence number 0, so the nonce is the base nonce.
    fn cipher(&self) -> Result<Aes256Gcm, HpkeError> {
        if self.aead != Aead::Aes256Gcm {
            return Err(HpkeError::InvalidInput);
        }
        Aes256Gcm::new_from_slice(&self.key).map_err(|_| HpkeError::InvalidInput)
    }
}

fn encap(pk_r: &[u8]) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), HpkeError> {
    if pk_r.len() != mlkem::PUBLIC_KEY_BYTES {
        return Err(HpkeError::InvalidInput);
    }
    let (ss, enc) = mlkem::encapsulate(pk_r).ok_or(HpkeError::InvalidInput)?;
    Ok((Zeroizing::new(ss), enc))
}

fn decap(enc: &[u8], sk_r: &[u8]) -> Result<Zeroizing<Vec<u8>>, HpkeError> {
    if enc.len() != mlkem::CIPHERTEXT_BYTES || sk_r.len() != mlkem::SECRET_KEY_BYTES {
        return Err(HpkeError::InvalidInput);
    }
    mlkem::decapsulate(enc, sk_r).map(Zeroizing::new).ok_or(HpkeError::Decaps)
}

/// SealBase: returns (enc, ciphertext || tag).
pub fn seal(pk_r: &[u8], info: &[u8], aad: &[u8], pt: &[u8]) -> Result<(Vec<u8>, Vec<u8>), HpkeError> {
    let (ss, enc) = encap(pk_r)?;
    let ctx = key_schedule(&ss, info, Aead::Aes256Gcm)?;
    let ct = ctx.cipher()?
        .encrypt(Nonce::from_slice(&ctx.base_nonce), Payload { msg: pt, aad })
        .map_err(|_| HpkeError::Seal)?;
    Ok((enc, ct))
}

/// OpenBase. Plaintext in a zeroizing buffer.
pub fn open(enc: &[u8], sk_r: &[u8], info: &[u8], aad: &[u8], ct: &[u8])
    -> Result<Zeroizing<Vec<u8>>, HpkeError>
{
    let ss = decap(enc, sk_r)?;
    let ctx = key_schedule(&ss, info, Aead::Aes256Gcm)?;
    ctx.cipher()?
        .decrypt(Nonce::from_slice(&ctx.base_nonce), Payload { msg: ct, aad })
        .map(Zeroizing::new)
        .map_err(|_| HpkeError::Open)
}

/// SetupBaseS then Export: (enc, exported secret).
pub fn sender_export(pk_r: &[u8], info: &[u8], aead: Aead, exporter_context: &[u8], len: usize)
    -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), HpkeError>
{
    let (ss, enc) = encap(pk_r)?;
    let ctx = key_schedule(&ss, info, aead)?;
    Ok((enc, ctx.export(exporter_context, len)?))
}

/// SetupBaseR then Export.
pub fn receiver_export(enc: &[u8], sk_r: &[u8], info: &[u8], aead: Aead,
                       exporter_context: &[u8], len: usize)
    -> Result<Zeroizing<Vec<u8>>, HpkeError>
{
    let ss = decap(enc, sk_r)?;
    let ctx = key_schedule(&ss, info, aead)?;
    ctx.export(exporter_context, len)
}

/// DeriveKeyPair: (private, public).
pub fn derive_key_pair(ikm: &[u8]) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), HpkeError> {
    let mut seed = Zeroizing::new([0u8; mlkem::SEED_BYTES]);
    let mut xof = sha3::Shake256::default();
    xof.update(ikm);
    xof.finalize_xof().read(&mut seed[..]);
    let (pk, sk) = mlkem::keypair_from_seed(&seed[..]).ok_or(HpkeError::InvalidInput)?;
    Ok((Zeroizing::new(sk), pk))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_refusals() {
        let (sk, pk) = derive_key_pair(b"ikm").unwrap();
        let (enc, ct) = seal(&pk, b"info", b"aad", b"hello").unwrap();
        assert_eq!(open(&enc, &sk, b"info", b"aad", &ct).unwrap().as_slice(), b"hello");
        assert_eq!(open(&enc, &sk, b"other", b"aad", &ct), Err(HpkeError::Open));
        assert_eq!(open(&enc, &sk, b"info", b"other", &ct), Err(HpkeError::Open));
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert_eq!(open(&enc, &sk, b"info", b"aad", &bad), Err(HpkeError::Open));
        assert_eq!(seal(&pk[..10], b"", b"", b"").unwrap_err(), HpkeError::InvalidInput);
        let (enc2, s1) = sender_export(&pk, b"i", Aead::ExportOnly, b"c", 48).unwrap();
        let s2 = receiver_export(&enc2, &sk, b"i", Aead::ExportOnly, b"c", 48).unwrap();
        assert_eq!(s1, s2);
        let (_, pk2) = derive_key_pair(b"ikm").unwrap();
        assert_eq!(pk, pk2, "DeriveKeyPair must be deterministic");
    }
}
