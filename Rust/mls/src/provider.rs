// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
//! The OpenMLS provider: OpenMLS's crypto trait on the core's primitives.
//!
//! Two ciphersuites, and nothing else:
//!
//!   * **MLS_256_X448MLKEM1024_AES256GCM_SHA384_ED448MLDSA87** (0xF0A1,
//!     private; every new group). KEM X448 + ML-KEM-1024 with a binding
//!     combiner (`crate::hpke`), signature Ed448 + ML-DSA-87 composite
//!     (below). Breaking one half of either does not break the group.
//!   * MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87 (0x0907; the PQ-only
//!     suite of earlier versions), kept so groups made with it keep
//!     working. No new group uses it.
//!
//! Anything outside them (another hash, AEAD, signature scheme or KEM) is
//! refused with an error, never quietly served by something else.
//!
//! THE COMPOSITE SIGNATURE (0xFEA1)
//! ================================
//!   m'  = "OTRv4+MLS/CompositeSig/v1" || m
//!   sig = Ed448(sk_ed, m') (114) || ML-DSA-87(sk_ml, m') (4627)
//!   pk  = pk_ed (57) || pk_ml (2592);  sk = seed_ed (57) || sk_ml (4896)
//! Verification requires BOTH to pass; a length that is not exact is
//! refused. Pure Ed448 (RFC 8032, empty context), as the core's identity
//! keys; ML-DSA-87 as below. The prefix keeps a composite signature from
//! being taken apart and either half used as a plain signature on `m`.
//!
//! | MLS needs            | from                                        |
//! |----------------------|---------------------------------------------|
//! | SHA-384, HKDF, HMAC  | sha2 / hkdf / hmac (the core's versions)    |
//! | AES-256-GCM          | aes-gcm (the core's version)                |
//! | ML-DSA-87            | pqcrypto-mldsa, PQClean (as the core's DAKE)|
//! | HPKE, ML-KEM-1024    | `crate::hpke` (RFC 9180) on PQClean ML-KEM  |
//! | randomness           | the operating system (getrandom)            |
//!
//! ML-DSA-87 private keys are PQClean's 4896-byte expanded form. They are
//! local to this client -- MLS never sends a private key -- so the form only
//! has to agree with itself; public keys and signatures are FIPS 204 and are
//! checked against an independent implementation in the tests.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use crate::storage::SecureStorage;
use openmls_traits::{
    crypto::OpenMlsCrypto,
    random::OpenMlsRand,
    signatures::{Signer, SignerError},
    types::{
        AeadType, Ciphersuite, CryptoError, ExporterSecret, HashType, HpkeAeadType,
        HpkeCiphertext, HpkeConfig, HpkeKdfType, HpkeKemType, HpkeKeyPair, SignatureScheme,
    },
    OpenMlsProvider,
};
use pqcrypto_mldsa::mldsa87;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};
use sha2::{Digest, Sha384};
use tls_codec::SecretVLBytes;
use zeroize::{Zeroize, Zeroizing};

use crate::hpke::{self, Aead as HpkeAead, Kem};

/// The ciphersuite of every new group: hybrid KEM, composite signature.
pub const CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_256_X448MLKEM1024_AES256GCM_SHA384_ED448MLDSA87;
/// The PQ-only suite of earlier versions: existing groups only.
pub const LEGACY_CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87;
/// The composite signature scheme of `CIPHERSUITE`.
pub const COMPOSITE: SignatureScheme = SignatureScheme::ED448_MLDSA87;

pub const MLDSA87_PUBLIC_KEY_BYTES: usize = 2592;
pub const MLDSA87_SECRET_KEY_BYTES: usize = 4896;
pub const MLDSA87_SIGNATURE_BYTES: usize = 4627;
pub const ED448_PUBLIC_KEY_BYTES: usize = 57;
pub const ED448_SEED_BYTES: usize = 57;
pub const ED448_SIGNATURE_BYTES: usize = 114;
pub const COMPOSITE_PUBLIC_KEY_BYTES: usize = ED448_PUBLIC_KEY_BYTES + MLDSA87_PUBLIC_KEY_BYTES;
pub const COMPOSITE_SECRET_KEY_BYTES: usize = ED448_SEED_BYTES + MLDSA87_SECRET_KEY_BYTES;
pub const COMPOSITE_SIGNATURE_BYTES: usize = ED448_SIGNATURE_BYTES + MLDSA87_SIGNATURE_BYTES;
const COMPOSITE_LABEL: &[u8] = b"OTRv4+MLS/CompositeSig/v1";

/// Stateless: every primitive is a pure function of its inputs, randomness
/// comes from the OS per call.
#[derive(Debug, Default, Clone, Copy)]
pub struct CoreCrypto;

fn sha384_only(hash_type: HashType) -> Result<(), CryptoError> {
    match hash_type {
        HashType::Sha2_384 => Ok(()),
        _ => Err(CryptoError::UnsupportedHashAlgorithm),
    }
}

/// The HPKE configurations the two suites use; anything else is refused.
fn hpke_suite(config: &HpkeConfig) -> Result<(Kem, HpkeAead), CryptoError> {
    let kem = match config.0 {
        HpkeKemType::X448MlKem1024 => Kem::X448MlKem1024,
        HpkeKemType::MlKem1024 => Kem::MlKem1024,
        _ => return Err(CryptoError::UnsupportedCiphersuite),
    };
    if config.1 != HpkeKdfType::HkdfSha384 {
        return Err(CryptoError::UnsupportedKdf);
    }
    match config.2 {
        HpkeAeadType::AesGcm256 => Ok((kem, HpkeAead::Aes256Gcm)),
        HpkeAeadType::Export => Ok((kem, HpkeAead::ExportOnly)),
        _ => Err(CryptoError::UnsupportedAeadAlgorithm),
    }
}

fn aes256(alg: AeadType, key: &[u8], nonce: &[u8]) -> Result<Aes256Gcm, CryptoError> {
    if alg != AeadType::Aes256Gcm {
        return Err(CryptoError::UnsupportedAeadAlgorithm);
    }
    if nonce.len() != 12 {
        return Err(CryptoError::InvalidLength);
    }
    Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::InvalidLength)
}

/// ML-DSA-87 detached signature (FIPS 204, empty context).
pub(crate) fn mldsa87_sign(secret: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let sk = mldsa87::SecretKey::from_bytes(secret).map_err(|_| CryptoError::InvalidLength)?;
    Ok(mldsa87::detached_sign(data, &sk).as_bytes().to_vec())
}

fn mldsa87_verify(pk: &[u8], data: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
    let pk = mldsa87::PublicKey::from_bytes(pk).map_err(|_| CryptoError::InvalidLength)?;
    let sig = mldsa87::DetachedSignature::from_bytes(signature)
        .map_err(|_| CryptoError::InvalidLength)?;
    mldsa87::verify_detached_signature(&sig, data, &pk)
        .map_err(|_| CryptoError::InvalidSignature)
}

fn composite_message(data: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(COMPOSITE_LABEL.len() + data.len());
    m.extend_from_slice(COMPOSITE_LABEL);
    m.extend_from_slice(data);
    m
}

fn ed448_key(seed: &[u8]) -> Result<ed448_goldilocks_plus::SigningKey, CryptoError> {
    ed448_goldilocks_plus::SigningKey::try_from(seed).map_err(|_| CryptoError::InvalidLength)
}

/// Ed448 || ML-DSA-87 over the labelled message; `secret` is seed || sk.
pub(crate) fn composite_sign(secret: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if secret.len() != COMPOSITE_SECRET_KEY_BYTES {
        return Err(CryptoError::InvalidLength);
    }
    let (seed, ml_sk) = secret.split_at(ED448_SEED_BYTES);
    let m = composite_message(data);
    let ed = ed448_key(seed)?.sign_raw(&m).to_bytes();
    let ml = mldsa87_sign(ml_sk, &m)?;
    let mut sig = Vec::with_capacity(COMPOSITE_SIGNATURE_BYTES);
    sig.extend_from_slice(&ed);
    sig.extend_from_slice(&ml);
    Ok(sig)
}

/// Both halves must verify. Both are always checked.
pub(crate) fn composite_verify(pk: &[u8], data: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
    if pk.len() != COMPOSITE_PUBLIC_KEY_BYTES || signature.len() != COMPOSITE_SIGNATURE_BYTES {
        return Err(CryptoError::InvalidLength);
    }
    let (ed_pk, ml_pk) = pk.split_at(ED448_PUBLIC_KEY_BYTES);
    let (ed_sig, ml_sig) = signature.split_at(ED448_SIGNATURE_BYTES);
    let m = composite_message(data);
    let ed_ok = (|| {
        let pk: &[u8; 57] = ed_pk.try_into().ok()?;
        let vk = ed448_goldilocks_plus::VerifyingKey::from_bytes(pk).ok()?;
        let sig: &[u8; 114] = ed_sig.try_into().ok()?;
        let sig = ed448_goldilocks_plus::Signature::from_bytes(sig).ok()?;
        vk.verify_raw(&sig, &m).ok()
    })().is_some();
    let ml_ok = mldsa87_verify(ml_pk, &m, ml_sig).is_ok();
    if ed_ok && ml_ok { Ok(()) } else { Err(CryptoError::InvalidSignature) }
}

impl OpenMlsCrypto for CoreCrypto {
    fn supports(&self, ciphersuite: Ciphersuite) -> Result<(), CryptoError> {
        if ciphersuite == CIPHERSUITE || ciphersuite == LEGACY_CIPHERSUITE {
            Ok(())
        } else {
            Err(CryptoError::UnsupportedCiphersuite)
        }
    }

    fn supported_ciphersuites(&self) -> Vec<Ciphersuite> {
        vec![CIPHERSUITE, LEGACY_CIPHERSUITE]
    }

    fn hkdf_extract(
        &self,
        hash_type: HashType,
        salt: &[u8],
        ikm: &[u8],
    ) -> Result<SecretVLBytes, CryptoError> {
        sha384_only(hash_type)?;
        let (mut prk, _) = Hkdf::<Sha384>::extract(Some(salt), ikm);
        let out = prk[..].into();
        prk[..].zeroize();
        Ok(out)
    }

    fn hmac(
        &self,
        hash_type: HashType,
        key: &[u8],
        message: &[u8],
    ) -> Result<SecretVLBytes, CryptoError> {
        sha384_only(hash_type)?;
        let mut mac =
            <Hmac<Sha384> as Mac>::new_from_slice(key).map_err(|_| CryptoError::InvalidLength)?;
        mac.update(message);
        let mut tag = mac.finalize().into_bytes();
        let out = tag[..].into();
        tag[..].zeroize();
        Ok(out)
    }

    fn hkdf_expand(
        &self,
        hash_type: HashType,
        prk: &[u8],
        info: &[u8],
        okm_len: usize,
    ) -> Result<SecretVLBytes, CryptoError> {
        sha384_only(hash_type)?;
        let hkdf = Hkdf::<Sha384>::from_prk(prk).map_err(|_| CryptoError::HkdfOutputLengthInvalid)?;
        let mut okm = Zeroizing::new(vec![0u8; okm_len]);
        hkdf.expand(info, &mut okm)
            .map_err(|_| CryptoError::HkdfOutputLengthInvalid)?;
        Ok(okm.as_slice().into())
    }

    fn hash(&self, hash_type: HashType, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        sha384_only(hash_type)?;
        Ok(Sha384::digest(data).to_vec())
    }

    fn aead_encrypt(
        &self,
        alg: AeadType,
        key: &[u8],
        data: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        aes256(alg, key, nonce)?
            .encrypt(nonce.into(), Payload { msg: data, aad })
            .map_err(|_| CryptoError::CryptoLibraryError)
    }

    fn aead_decrypt(
        &self,
        alg: AeadType,
        key: &[u8],
        ct_tag: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        aes256(alg, key, nonce)?
            .decrypt(nonce.into(), Payload { msg: ct_tag, aad })
            .map_err(|_| CryptoError::AeadDecryptionError)
    }

    /// (private, public). Prefer `SignatureKeyPair::generate`, which keeps
    /// the private key in a wiped buffer; this exists because the trait
    /// requires it.
    fn signature_key_gen(&self, alg: SignatureScheme) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let pair = SignatureKeyPair::generate_for(alg)?;
        Ok((pair.secret().to_vec(), pair.public().to_vec()))
    }

    fn verify_signature(
        &self,
        alg: SignatureScheme,
        data: &[u8],
        pk: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        match alg {
            COMPOSITE => composite_verify(pk, data, signature),
            SignatureScheme::MLDSA87 => mldsa87_verify(pk, data, signature),
            _ => Err(CryptoError::UnsupportedSignatureScheme),
        }
    }

    fn sign(&self, alg: SignatureScheme, data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        match alg {
            COMPOSITE => composite_sign(key, data),
            SignatureScheme::MLDSA87 => mldsa87_sign(key, data),
            _ => Err(CryptoError::UnsupportedSignatureScheme),
        }
    }

    fn hpke_seal(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        aad: &[u8],
        ptxt: &[u8],
    ) -> Result<HpkeCiphertext, CryptoError> {
        let (kem, aead) = hpke_suite(&config)?;
        if aead != HpkeAead::Aes256Gcm {
            return Err(CryptoError::UnsupportedAeadAlgorithm);
        }
        let (kem_output, ciphertext) = hpke::seal_with(kem, pk_r, info, aad, ptxt).map_err(|e| match e {
            hpke::HpkeError::InvalidInput => CryptoError::InvalidLength,
            _ => CryptoError::HpkeEncryptionError,
        })?;
        Ok(HpkeCiphertext {
            kem_output: kem_output.into(),
            ciphertext: ciphertext.into(),
        })
    }

    fn hpke_open(
        &self,
        config: HpkeConfig,
        input: &HpkeCiphertext,
        sk_r: &[u8],
        info: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let (kem, aead) = hpke_suite(&config)?;
        if aead != HpkeAead::Aes256Gcm {
            return Err(CryptoError::UnsupportedAeadAlgorithm);
        }
        hpke::open_with(kem, input.kem_output.as_slice(), sk_r, info, aad, input.ciphertext.as_slice())
            // OpenMLS takes ownership of the plaintext as a plain Vec.
            .map(|pt| pt.to_vec())
            .map_err(|_| CryptoError::HpkeDecryptionError)
    }

    fn hpke_setup_sender_and_export(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<(Vec<u8>, ExporterSecret), CryptoError> {
        let (kem, aead) = hpke_suite(&config)?;
        let (kem_output, secret) =
            hpke::sender_export_with(kem, pk_r, info, aead, exporter_context, exporter_length)
                .map_err(|e| match e {
                    hpke::HpkeError::Export => CryptoError::ExporterError,
                    _ => CryptoError::SenderSetupError,
                })?;
        Ok((kem_output, secret.to_vec().into()))
    }

    fn hpke_setup_receiver_and_export(
        &self,
        config: HpkeConfig,
        enc: &[u8],
        sk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<ExporterSecret, CryptoError> {
        let (kem, aead) = hpke_suite(&config)?;
        let secret = hpke::receiver_export_with(kem, enc, sk_r, info, aead, exporter_context,
                                                exporter_length)
            .map_err(|e| match e {
                hpke::HpkeError::Export => CryptoError::ExporterError,
                _ => CryptoError::ReceiverSetupError,
            })?;
        Ok(secret.to_vec().into())
    }

    fn derive_hpke_keypair(
        &self,
        config: HpkeConfig,
        ikm: &[u8],
    ) -> Result<HpkeKeyPair, CryptoError> {
        let (kem, _) = hpke_suite(&config)?;
        let (private, public) = hpke::derive_key_pair_with(kem, ikm).map_err(|e| match e {
            hpke::HpkeError::InvalidInput => CryptoError::InvalidLength,
            _ => CryptoError::CryptoLibraryError,
        })?;
        Ok(HpkeKeyPair {
            private: private.to_vec().into(),
            public,
        })
    }
}

/// OS randomness failure. getrandom only fails when the platform has no
/// usable source, which is fatal for key generation.
#[derive(Debug, thiserror::Error)]
#[error("the operating system supplied no randomness")]
pub struct RandomnessError;

impl OpenMlsRand for CoreCrypto {
    type Error = RandomnessError;

    fn random_array<const N: usize>(&self) -> Result<[u8; N], Self::Error> {
        let mut out = [0u8; N];
        getrandom::getrandom(&mut out).map_err(|_| RandomnessError)?;
        Ok(out)
    }

    fn random_vec(&self, len: usize) -> Result<Vec<u8>, Self::Error> {
        let mut out = vec![0u8; len];
        getrandom::getrandom(&mut out).map_err(|_| RandomnessError)?;
        Ok(out)
    }
}

/// The provider OpenMLS runs on. Storage is `SecureStorage`: Rust-owned,
/// zeroized on wipe and on drop, sealed by `MlsClient` when persisted.
#[derive(Default)]
pub struct CoreProvider {
    crypto: CoreCrypto,
    storage: SecureStorage,
}

impl CoreProvider {
    /// Destroy every group secret this provider's storage holds.
    pub fn wipe(&self) {
        self.storage.wipe();
    }

    #[cfg(test)]
    pub(crate) fn storage_values_for_test(&self) -> Vec<Vec<u8>> {
        self.storage.values_for_test()
    }

    /// Entries in storage (no contents).
    pub fn stored_entries(&self) -> usize {
        self.storage.len()
    }

    pub(crate) fn secure_storage(&self) -> &SecureStorage {
        &self.storage
    }
}

impl OpenMlsProvider for CoreProvider {
    type CryptoProvider = CoreCrypto;
    type RandProvider = CoreCrypto;
    type StorageProvider = SecureStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

/// A member's signing key: composite Ed448 + ML-DSA-87 (every new group),
/// or ML-DSA-87 alone (groups of the earlier suite). The private half never
/// leaves this struct and is wiped when it is dropped.
pub struct SignatureKeyPair {
    scheme: SignatureScheme,
    public: Vec<u8>,
    secret: Zeroizing<Vec<u8>>,
}

impl SignatureKeyPair {
    /// A composite key, for the hybrid suite.
    pub fn generate() -> Self {
        Self::generate_for(COMPOSITE).expect("the composite scheme is supported")
    }

    /// A key for `scheme`: COMPOSITE or MLDSA87.
    pub fn generate_for(scheme: SignatureScheme) -> Result<Self, CryptoError> {
        let (ml_pk, ml_sk) = mldsa87::keypair();
        match scheme {
            SignatureScheme::MLDSA87 => Ok(Self {
                scheme,
                public: ml_pk.as_bytes().to_vec(),
                secret: Zeroizing::new(ml_sk.as_bytes().to_vec()),
            }),
            COMPOSITE => {
                let mut seed = Zeroizing::new([0u8; ED448_SEED_BYTES]);
                getrandom::getrandom(&mut seed[..])
                    .map_err(|_| CryptoError::InsufficientRandomness)?;
                let ed_pk = ed448_key(&seed[..])?.verifying_key().to_bytes();
                let mut public = Vec::with_capacity(COMPOSITE_PUBLIC_KEY_BYTES);
                public.extend_from_slice(&ed_pk[..]);
                public.extend_from_slice(ml_pk.as_bytes());
                let mut secret = Zeroizing::new(Vec::with_capacity(COMPOSITE_SECRET_KEY_BYTES));
                secret.extend_from_slice(&seed[..]);
                secret.extend_from_slice(ml_sk.as_bytes());
                Ok(Self { scheme, public, secret })
            }
            _ => Err(CryptoError::UnsupportedSignatureScheme),
        }
    }

    pub fn public(&self) -> &[u8] {
        &self.public
    }

    pub fn scheme(&self) -> SignatureScheme {
        self.scheme
    }

    /// The private half, for sealing inside `MlsClient` only.
    pub(crate) fn secret(&self) -> &[u8] {
        &self.secret
    }

    /// Rebuild from sealed state; the scheme follows from the lengths. A
    /// composite key's Ed448 half must match its seed.
    pub(crate) fn from_parts(public: Vec<u8>, secret: Zeroizing<Vec<u8>>) -> Option<Self> {
        if public.len() == mldsa87::public_key_bytes()
            && secret.len() == mldsa87::secret_key_bytes()
        {
            return Some(Self { scheme: SignatureScheme::MLDSA87, public, secret });
        }
        if public.len() == COMPOSITE_PUBLIC_KEY_BYTES
            && secret.len() == COMPOSITE_SECRET_KEY_BYTES
        {
            let ed_pk = ed448_key(&secret[..ED448_SEED_BYTES]).ok()?.verifying_key().to_bytes();
            if ed_pk[..] != public[..ED448_PUBLIC_KEY_BYTES] {
                return None;
            }
            return Some(Self { scheme: COMPOSITE, public, secret });
        }
        None
    }
}

impl core::fmt::Debug for SignatureKeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SignatureKeyPair").finish_non_exhaustive()
    }
}

impl Signer for SignatureKeyPair {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        match self.scheme {
            COMPOSITE => composite_sign(&self.secret, payload),
            _ => mldsa87_sign(&self.secret, payload),
        }
        .map_err(SignerError::CryptoError)
    }

    fn signature_scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

#[cfg(test)]
mod composite_tests {
    use super::*;

    #[test]
    fn both_halves_must_verify() {
        let k = SignatureKeyPair::generate();
        assert_eq!(k.public().len(), COMPOSITE_PUBLIC_KEY_BYTES);
        let sig = k.sign(b"commit").unwrap();
        assert_eq!(sig.len(), COMPOSITE_SIGNATURE_BYTES);
        let c = CoreCrypto;
        assert!(c.verify_signature(COMPOSITE, b"commit", k.public(), &sig).is_ok());
        assert!(c.verify_signature(COMPOSITE, b"commiT", k.public(), &sig).is_err());
        // Either half damaged: refused.
        for i in [0usize, 60, 113, 114, 2000, sig.len() - 1] {
            let mut bad = sig.clone();
            bad[i] ^= 1;
            assert!(c.verify_signature(COMPOSITE, b"commit", k.public(), &bad).is_err(), "{i}");
        }
        // A half from another key's signature on the same message.
        let other = SignatureKeyPair::generate().sign(b"commit").unwrap();
        let mut spliced = sig[..ED448_SIGNATURE_BYTES].to_vec();
        spliced.extend_from_slice(&other[ED448_SIGNATURE_BYTES..]);
        assert!(c.verify_signature(COMPOSITE, b"commit", k.public(), &spliced).is_err());
        // The ML-DSA half alone is no ML-DSA signature on the message.
        let ml_pk = &k.public()[ED448_PUBLIC_KEY_BYTES..];
        assert!(c.verify_signature(SignatureScheme::MLDSA87, b"commit", ml_pk,
                                   &sig[ED448_SIGNATURE_BYTES..]).is_err());
        assert!(c.verify_signature(COMPOSITE, b"commit", k.public(), &sig[1..]).is_err());
    }

    #[test]
    fn sealed_parts_round_trip_and_are_checked() {
        let k = SignatureKeyPair::generate();
        let back = SignatureKeyPair::from_parts(k.public().to_vec(),
                                                Zeroizing::new(k.secret().to_vec())).unwrap();
        assert_eq!(back.scheme(), COMPOSITE);
        let mut wrong = k.public().to_vec();
        wrong[0] ^= 1;
        assert!(SignatureKeyPair::from_parts(wrong, Zeroizing::new(k.secret().to_vec())).is_none());
        let legacy = SignatureKeyPair::generate_for(SignatureScheme::MLDSA87).unwrap();
        let back = SignatureKeyPair::from_parts(legacy.public().to_vec(),
                                                Zeroizing::new(legacy.secret().to_vec())).unwrap();
        assert_eq!(back.scheme(), SignatureScheme::MLDSA87);
        assert!(SignatureKeyPair::generate_for(SignatureScheme::ED25519).is_err());
    }
}
