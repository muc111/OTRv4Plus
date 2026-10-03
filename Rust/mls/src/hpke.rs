// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
//! HPKE (RFC 9180), base mode, for the suites MLS uses here:
//! KDF HKDF-SHA384 (0x0002), AEAD AES-256-GCM (0x0002) or export-only
//! (0xFFFF), and KEM either
//!   * X448 + ML-KEM-1024 with a binding combiner (0xF0A1, private; the
//!     hybrid suite, MLS_SECURITY_HARDENING.md §2), or
//!   * ML-KEM-1024 alone (0x0042; the earlier PQ-only suite, kept so
//!     groups made with it keep working).
//!
//! THE HYBRID KEM (0xF0A1)
//! =======================
//!   pk  = pk_x448 (56) || pk_mlkem (1568)
//!   sk  = sk_x448 (56) || sk_mlkem (3168)      (pk_mlkem is inside sk_mlkem,
//!                                               FIPS 203 dk; pk_x448 is derived)
//!   enc = ct_x448 (56, an ephemeral X448 public key) || ct_mlkem (1568)
//!   ss  = SHA3-256("OTRv4+MLS/HybridKEM/v1" || ss_mlkem || ss_x448
//!                  || ct_x448 || pk_x448 || ct_mlkem || pk_mlkem)
//! Both halves are always computed and both enter `ss`: an attacker must
//! break X448 AND ML-KEM-1024. The combiner binds both ciphertexts and both
//! public keys (as X-Wing binds the classical ones), so a ciphertext cannot
//! be re-targeted at another key or have one half swapped. An X448 result
//! that is all zero (a low-order point) is refused.
//!   DeriveKeyPair(ikm): sk_x448 = SHAKE256("OTRv4+MLS/HybridKEM/v1/x448" || ikm, 56)
//!                       ML-KEM seed = SHAKE256("OTRv4+MLS/HybridKEM/v1/mlkem" || ikm, 64)
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

const KDF_ID: u16 = 0x0002;
const NH: usize = 48;
const HPKE_VERSION: &[u8] = b"HPKE-v1";
const MODE_BASE: u8 = 0x00;

/// The KEM half of the suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kem {
    /// ML-KEM-1024 alone (0x0042).
    MlKem1024,
    /// X448 + ML-KEM-1024, binding combiner (0xF0A1, private).
    X448MlKem1024,
}

const X448_BYTES: usize = 56;
const HYBRID_LABEL: &[u8] = b"OTRv4+MLS/HybridKEM/v1";

impl Kem {
    fn id(self) -> u16 {
        match self {
            Kem::MlKem1024 => 0x0042,
            Kem::X448MlKem1024 => 0xF0A1,
        }
    }
    pub fn public_key_bytes(self) -> usize {
        match self {
            Kem::MlKem1024 => mlkem::PUBLIC_KEY_BYTES,
            Kem::X448MlKem1024 => X448_BYTES + mlkem::PUBLIC_KEY_BYTES,
        }
    }
    pub fn secret_key_bytes(self) -> usize {
        match self {
            Kem::MlKem1024 => mlkem::SECRET_KEY_BYTES,
            Kem::X448MlKem1024 => X448_BYTES + mlkem::SECRET_KEY_BYTES,
        }
    }
    pub fn enc_bytes(self) -> usize {
        match self {
            Kem::MlKem1024 => mlkem::CIPHERTEXT_BYTES,
            Kem::X448MlKem1024 => X448_BYTES + mlkem::CIPHERTEXT_BYTES,
        }
    }
}

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

fn suite_id(kem: Kem, aead: Aead) -> [u8; 10] {
    let mut s = [0u8; 10];
    s[..4].copy_from_slice(b"HPKE");
    s[4..6].copy_from_slice(&kem.id().to_be_bytes());
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

fn key_schedule(kem: Kem, shared_secret: &[u8], info: &[u8], aead: Aead)
    -> Result<Context, HpkeError>
{
    let suite = suite_id(kem, aead);
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

fn mlkem_encap(pk_r: &[u8]) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), HpkeError> {
    if pk_r.len() != mlkem::PUBLIC_KEY_BYTES {
        return Err(HpkeError::InvalidInput);
    }
    let (ss, enc) = mlkem::encapsulate(pk_r).ok_or(HpkeError::InvalidInput)?;
    Ok((Zeroizing::new(ss), enc))
}

fn mlkem_decap(enc: &[u8], sk_r: &[u8]) -> Result<Zeroizing<Vec<u8>>, HpkeError> {
    if enc.len() != mlkem::CIPHERTEXT_BYTES || sk_r.len() != mlkem::SECRET_KEY_BYTES {
        return Err(HpkeError::InvalidInput);
    }
    mlkem::decapsulate(enc, sk_r).map(Zeroizing::new).ok_or(HpkeError::Decaps)
}

/// The ML-KEM-1024 public key inside a FIPS 203 decapsulation key
/// (dk = dk_pke (1536) || ek (1568) || H(ek) || z).
fn mlkem_pk_of(sk: &[u8]) -> &[u8] {
    &sk[1536..1536 + mlkem::PUBLIC_KEY_BYTES]
}

fn x448_public(sk: &[u8]) -> Result<[u8; X448_BYTES], HpkeError> {
    let arr: [u8; X448_BYTES] = sk.try_into().map_err(|_| HpkeError::InvalidInput)?;
    let secret = Zeroizing::new(arr);
    let sk = x448::Secret::from(*secret);
    Ok(*x448::PublicKey::from(&sk).as_bytes())
}

/// X448(sk, pk); refuses a low-order point (an all-zero result).
fn x448_dh(sk: &[u8], pk: &[u8]) -> Result<Zeroizing<Vec<u8>>, HpkeError> {
    let arr: [u8; X448_BYTES] = sk.try_into().map_err(|_| HpkeError::InvalidInput)?;
    let secret = Zeroizing::new(arr);
    let sk = x448::Secret::from(*secret);
    let pk = x448::PublicKey::from_bytes(pk).ok_or(HpkeError::InvalidInput)?;
    let shared = sk.as_diffie_hellman(&pk).ok_or(HpkeError::Decaps)?;
    let out = Zeroizing::new(shared.as_bytes().to_vec());
    if out.iter().all(|&b| b == 0) {
        return Err(HpkeError::Decaps);
    }
    Ok(out)
}

fn combine(ss_mlkem: &[u8], ss_x448: &[u8], ct_x448: &[u8], pk_x448: &[u8],
           ct_mlkem: &[u8], pk_mlkem: &[u8]) -> Zeroizing<Vec<u8>>
{
    use sha3::Digest as _;
    let mut h = sha3::Sha3_256::new();
    sha3::Digest::update(&mut h, HYBRID_LABEL);
    sha3::Digest::update(&mut h, ss_mlkem);
    sha3::Digest::update(&mut h, ss_x448);
    sha3::Digest::update(&mut h, ct_x448);
    sha3::Digest::update(&mut h, pk_x448);
    sha3::Digest::update(&mut h, ct_mlkem);
    sha3::Digest::update(&mut h, pk_mlkem);
    Zeroizing::new(h.finalize().to_vec())
}

fn encap(kem: Kem, pk_r: &[u8]) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), HpkeError> {
    match kem {
        Kem::MlKem1024 => mlkem_encap(pk_r),
        Kem::X448MlKem1024 => {
            if pk_r.len() != kem.public_key_bytes() {
                return Err(HpkeError::InvalidInput);
            }
            let (pk_x448, pk_mlkem) = pk_r.split_at(X448_BYTES);
            let mut eph = Zeroizing::new([0u8; X448_BYTES]);
            getrandom::getrandom(&mut eph[..]).map_err(|_| HpkeError::InvalidInput)?;
            let ct_x448 = x448_public(&eph[..])?;
            let ss_x448 = x448_dh(&eph[..], pk_x448)?;
            let (ss_mlkem, ct_mlkem) = mlkem_encap(pk_mlkem)?;
            let ss = combine(&ss_mlkem, &ss_x448, &ct_x448, pk_x448, &ct_mlkem, pk_mlkem);
            let mut enc = Vec::with_capacity(kem.enc_bytes());
            enc.extend_from_slice(&ct_x448);
            enc.extend_from_slice(&ct_mlkem);
            Ok((ss, enc))
        }
    }
}

fn decap(kem: Kem, enc: &[u8], sk_r: &[u8]) -> Result<Zeroizing<Vec<u8>>, HpkeError> {
    match kem {
        Kem::MlKem1024 => mlkem_decap(enc, sk_r),
        Kem::X448MlKem1024 => {
            if enc.len() != kem.enc_bytes() || sk_r.len() != kem.secret_key_bytes() {
                return Err(HpkeError::InvalidInput);
            }
            let (ct_x448, ct_mlkem) = enc.split_at(X448_BYTES);
            let (sk_x448, sk_mlkem) = sk_r.split_at(X448_BYTES);
            let pk_x448 = x448_public(sk_x448)?;
            // Both halves are always computed before either result is used.
            let ss_x448 = x448_dh(sk_x448, ct_x448);
            let ss_mlkem = mlkem_decap(ct_mlkem, sk_mlkem);
            let (ss_x448, ss_mlkem) = (ss_x448?, ss_mlkem?);
            Ok(combine(&ss_mlkem, &ss_x448, ct_x448, &pk_x448, ct_mlkem, mlkem_pk_of(sk_mlkem)))
        }
    }
}

/// SealBase: returns (enc, ciphertext || tag). ML-KEM-1024 alone.
pub fn seal(pk_r: &[u8], info: &[u8], aad: &[u8], pt: &[u8]) -> Result<(Vec<u8>, Vec<u8>), HpkeError> {
    seal_with(Kem::MlKem1024, pk_r, info, aad, pt)
}

/// SealBase with the given KEM: returns (enc, ciphertext || tag).
pub fn seal_with(kem: Kem, pk_r: &[u8], info: &[u8], aad: &[u8], pt: &[u8])
    -> Result<(Vec<u8>, Vec<u8>), HpkeError>
{
    let (ss, enc) = encap(kem, pk_r)?;
    let ctx = key_schedule(kem, &ss, info, Aead::Aes256Gcm)?;
    let ct = ctx.cipher()?
        .encrypt(<&Nonce<_>>::from(&ctx.base_nonce[..]), Payload { msg: pt, aad })
        .map_err(|_| HpkeError::Seal)?;
    Ok((enc, ct))
}

/// OpenBase. Plaintext in a zeroizing buffer. ML-KEM-1024 alone.
pub fn open(enc: &[u8], sk_r: &[u8], info: &[u8], aad: &[u8], ct: &[u8])
    -> Result<Zeroizing<Vec<u8>>, HpkeError>
{
    open_with(Kem::MlKem1024, enc, sk_r, info, aad, ct)
}

pub fn open_with(kem: Kem, enc: &[u8], sk_r: &[u8], info: &[u8], aad: &[u8], ct: &[u8])
    -> Result<Zeroizing<Vec<u8>>, HpkeError>
{
    let ss = decap(kem, enc, sk_r)?;
    let ctx = key_schedule(kem, &ss, info, Aead::Aes256Gcm)?;
    ctx.cipher()?
        .decrypt(<&Nonce<_>>::from(&ctx.base_nonce[..]), Payload { msg: ct, aad })
        .map(Zeroizing::new)
        .map_err(|_| HpkeError::Open)
}

/// SetupBaseS then Export: (enc, exported secret). ML-KEM-1024 alone.
pub fn sender_export(pk_r: &[u8], info: &[u8], aead: Aead, exporter_context: &[u8], len: usize)
    -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), HpkeError>
{
    sender_export_with(Kem::MlKem1024, pk_r, info, aead, exporter_context, len)
}

pub fn sender_export_with(kem: Kem, pk_r: &[u8], info: &[u8], aead: Aead,
                          exporter_context: &[u8], len: usize)
    -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), HpkeError>
{
    let (ss, enc) = encap(kem, pk_r)?;
    let ctx = key_schedule(kem, &ss, info, aead)?;
    Ok((enc, ctx.export(exporter_context, len)?))
}

/// SetupBaseR then Export. ML-KEM-1024 alone.
pub fn receiver_export(enc: &[u8], sk_r: &[u8], info: &[u8], aead: Aead,
                       exporter_context: &[u8], len: usize)
    -> Result<Zeroizing<Vec<u8>>, HpkeError>
{
    receiver_export_with(Kem::MlKem1024, enc, sk_r, info, aead, exporter_context, len)
}

pub fn receiver_export_with(kem: Kem, enc: &[u8], sk_r: &[u8], info: &[u8], aead: Aead,
                            exporter_context: &[u8], len: usize)
    -> Result<Zeroizing<Vec<u8>>, HpkeError>
{
    let ss = decap(kem, enc, sk_r)?;
    let ctx = key_schedule(kem, &ss, info, aead)?;
    ctx.export(exporter_context, len)
}

fn shake(parts: &[&[u8]], out: &mut [u8]) {
    let mut xof = sha3::Shake256::default();
    for p in parts {
        xof.update(p);
    }
    xof.finalize_xof().read(out);
}

/// DeriveKeyPair: (private, public). ML-KEM-1024 alone.
pub fn derive_key_pair(ikm: &[u8]) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), HpkeError> {
    derive_key_pair_with(Kem::MlKem1024, ikm)
}

pub fn derive_key_pair_with(kem: Kem, ikm: &[u8]) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), HpkeError> {
    match kem {
        Kem::MlKem1024 => {
            let mut seed = Zeroizing::new([0u8; mlkem::SEED_BYTES]);
            shake(&[ikm], &mut seed[..]);
            let (pk, sk) = mlkem::keypair_from_seed(&seed[..]).ok_or(HpkeError::InvalidInput)?;
            Ok((Zeroizing::new(sk), pk))
        }
        Kem::X448MlKem1024 => {
            let mut sk_x448 = Zeroizing::new([0u8; X448_BYTES]);
            shake(&[HYBRID_LABEL, b"/x448", ikm], &mut sk_x448[..]);
            let mut seed = Zeroizing::new([0u8; mlkem::SEED_BYTES]);
            shake(&[HYBRID_LABEL, b"/mlkem", ikm], &mut seed[..]);
            let (pk_mlkem, sk_mlkem) =
                mlkem::keypair_from_seed(&seed[..]).ok_or(HpkeError::InvalidInput)?;
            let sk_mlkem = Zeroizing::new(sk_mlkem);
            let mut sk = Zeroizing::new(Vec::with_capacity(kem.secret_key_bytes()));
            sk.extend_from_slice(&sk_x448[..]);
            sk.extend_from_slice(&sk_mlkem);
            let mut pk = Vec::with_capacity(kem.public_key_bytes());
            pk.extend_from_slice(&x448_public(&sk_x448[..])?);
            pk.extend_from_slice(&pk_mlkem);
            Ok((sk, pk))
        }
    }
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

    const H: Kem = Kem::X448MlKem1024;

    #[test]
    fn hybrid_round_trip_sizes_and_determinism() {
        let (sk, pk) = derive_key_pair_with(H, b"ikm").unwrap();
        assert_eq!((pk.len(), sk.len()), (56 + 1568, 56 + 3168));
        let (sk2, pk2) = derive_key_pair_with(H, b"ikm").unwrap();
        assert_eq!((&pk, &sk[..]), (&pk2, &sk2[..]));
        assert_ne!(pk, derive_key_pair_with(H, b"other").unwrap().1);
        // Not the ML-KEM-only key from the same ikm (domain-separated).
        assert_ne!(&pk[56..], &derive_key_pair(b"ikm").unwrap().1[..]);
        let (enc, ct) = seal_with(H, &pk, b"info", b"aad", b"hello").unwrap();
        assert_eq!(enc.len(), 56 + 1568);
        assert_eq!(open_with(H, &enc, &sk, b"info", b"aad", &ct).unwrap().as_slice(), b"hello");
        let (enc, s1) = sender_export_with(H, &pk, b"i", Aead::ExportOnly, b"c", 48).unwrap();
        let s2 = receiver_export_with(H, &enc, &sk, b"i", Aead::ExportOnly, b"c", 48).unwrap();
        assert_eq!(s1, s2);
    }

    #[test]
    fn hybrid_binds_both_halves() {
        let (sk, pk) = derive_key_pair_with(H, b"recipient").unwrap();
        let (enc, ct) = seal_with(H, &pk, b"", b"", b"secret").unwrap();
        // Either half of the ciphertext changed: refused.
        for i in [0usize, 30, 55, 56, 900, enc.len() - 1] {
            let mut bad = enc.clone();
            bad[i] ^= 0x01;
            assert!(open_with(H, &bad, &sk, b"", b"", &ct).is_err(), "byte {i}");
        }
        // One half spliced from another encapsulation to the same key.
        let (enc2, _) = seal_with(H, &pk, b"", b"", b"other").unwrap();
        let mut mixed = enc[..56].to_vec();
        mixed.extend_from_slice(&enc2[56..]);
        assert!(open_with(H, &mixed, &sk, b"", b"", &ct).is_err());
        let mut mixed = enc2[..56].to_vec();
        mixed.extend_from_slice(&enc[56..]);
        assert!(open_with(H, &mixed, &sk, b"", b"", &ct).is_err());
        // The other KEM's suite id: refused (the key schedule differs).
        assert!(open_with(Kem::MlKem1024, &enc[56..], &sk[56..], b"", b"", &ct).is_err());
    }

    #[test]
    fn hybrid_refuses_low_order_and_bad_lengths() {
        let (sk, pk) = derive_key_pair_with(H, b"r").unwrap();
        let (enc, ct) = seal_with(H, &pk, b"", b"", b"x").unwrap();
        // A zero (low-order) X448 point in place of the ephemeral key.
        let mut zero = vec![0u8; 56];
        zero.extend_from_slice(&enc[56..]);
        assert!(open_with(H, &zero, &sk, b"", b"", &ct).is_err());
        // A public key whose X448 half is a low-order point.
        let mut weak = vec![0u8; 56];
        weak.extend_from_slice(&pk[56..]);
        assert!(seal_with(H, &weak, b"", b"", b"x").is_err());
        assert_eq!(seal_with(H, &pk[..100], b"", b"", b"x").unwrap_err(), HpkeError::InvalidInput);
        assert_eq!(open_with(H, &enc[..100], &sk, b"", b"", &ct).unwrap_err(),
                   HpkeError::InvalidInput);
    }
}
