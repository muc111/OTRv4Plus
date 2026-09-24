// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
//! The OpenMLS provider: OpenMLS's crypto trait on the core's primitives.
//!
//! Exactly one ciphersuite, MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87.
//! Anything outside it (another hash, AEAD, signature scheme or KEM) is
//! refused with an error, never quietly served by something else.
//!
//! | MLS needs            | from                                        |
//! |----------------------|---------------------------------------------|
//! | SHA-384, HKDF, HMAC  | sha2 / hkdf / hmac (the core's versions)    |
//! | AES-256-GCM          | aes-gcm (the core's version)                |
//! | ML-DSA-87            | pqcrypto-mldsa, PQClean (as the core's DAKE)|
//! | HPKE, ML-KEM-1024    | hpke-rs over `CoreHpke` (PQClean ML-KEM)    |
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
use hpke_rs::{Hpke, Mode};
use hpke_rs_crypto::types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};
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

use crate::hpke_backend::CoreHpke;

/// The one ciphersuite this provider serves.
pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87;

pub const MLDSA87_PUBLIC_KEY_BYTES: usize = 2592;
pub const MLDSA87_SECRET_KEY_BYTES: usize = 4896;
pub const MLDSA87_SIGNATURE_BYTES: usize = 4627;

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

fn hpke_for(config: &HpkeConfig) -> Result<Hpke<CoreHpke>, CryptoError> {
    let kem = match config.0 {
        HpkeKemType::MlKem1024 => KemAlgorithm::MlKem1024,
        _ => return Err(CryptoError::UnsupportedCiphersuite),
    };
    let kdf = match config.1 {
        HpkeKdfType::HkdfSha384 => KdfAlgorithm::HkdfSha384,
        _ => return Err(CryptoError::UnsupportedKdf),
    };
    let aead = match config.2 {
        HpkeAeadType::AesGcm256 => AeadAlgorithm::Aes256Gcm,
        HpkeAeadType::Export => AeadAlgorithm::HpkeExport,
        _ => return Err(CryptoError::UnsupportedAeadAlgorithm),
    };
    Ok(Hpke::new(Mode::Base, kem, kdf, aead))
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

impl OpenMlsCrypto for CoreCrypto {
    fn supports(&self, ciphersuite: Ciphersuite) -> Result<(), CryptoError> {
        if ciphersuite == CIPHERSUITE {
            Ok(())
        } else {
            Err(CryptoError::UnsupportedCiphersuite)
        }
    }

    fn supported_ciphersuites(&self) -> Vec<Ciphersuite> {
        vec![CIPHERSUITE]
    }

    fn hkdf_extract(
        &self,
        hash_type: HashType,
        salt: &[u8],
        ikm: &[u8],
    ) -> Result<SecretVLBytes, CryptoError> {
        sha384_only(hash_type)?;
        let (mut prk, _) = Hkdf::<Sha384>::extract(Some(salt), ikm);
        let out = prk.as_slice().into();
        prk.as_mut_slice().zeroize();
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
        let out = tag.as_slice().into();
        tag.as_mut_slice().zeroize();
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
        if alg != SignatureScheme::MLDSA87 {
            return Err(CryptoError::UnsupportedSignatureScheme);
        }
        let (pk, sk) = mldsa87::keypair();
        Ok((sk.as_bytes().to_vec(), pk.as_bytes().to_vec()))
    }

    fn verify_signature(
        &self,
        alg: SignatureScheme,
        data: &[u8],
        pk: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        if alg != SignatureScheme::MLDSA87 {
            return Err(CryptoError::UnsupportedSignatureScheme);
        }
        let pk = mldsa87::PublicKey::from_bytes(pk).map_err(|_| CryptoError::InvalidLength)?;
        let sig = mldsa87::DetachedSignature::from_bytes(signature)
            .map_err(|_| CryptoError::InvalidLength)?;
        mldsa87::verify_detached_signature(&sig, data, &pk)
            .map_err(|_| CryptoError::InvalidSignature)
    }

    fn sign(&self, alg: SignatureScheme, data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if alg != SignatureScheme::MLDSA87 {
            return Err(CryptoError::UnsupportedSignatureScheme);
        }
        mldsa87_sign(key, data)
    }

    fn hpke_seal(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        aad: &[u8],
        ptxt: &[u8],
    ) -> Result<HpkeCiphertext, CryptoError> {
        let (kem_output, ciphertext) = hpke_for(&config)?
            .seal(&pk_r.into(), info, aad, ptxt, None, None, None)
            .map_err(|e| match e {
                hpke_rs::HpkeError::InvalidInput => CryptoError::InvalidLength,
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
        hpke_for(&config)?
            .open(
                input.kem_output.as_slice(),
                &sk_r.into(),
                info,
                aad,
                input.ciphertext.as_slice(),
                None,
                None,
                None,
            )
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
        let (kem_output, context) = hpke_for(&config)?
            .setup_sender(&pk_r.into(), info, None, None, None)
            .map_err(|_| CryptoError::SenderSetupError)?;
        let secret = context
            .export(exporter_context, exporter_length)
            .map_err(|_| CryptoError::ExporterError)?;
        Ok((kem_output, secret.into()))
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
        let context = hpke_for(&config)?
            .setup_receiver(enc, &sk_r.into(), info, None, None, None)
            .map_err(|_| CryptoError::ReceiverSetupError)?;
        let secret = context
            .export(exporter_context, exporter_length)
            .map_err(|_| CryptoError::ExporterError)?;
        Ok(secret.into())
    }

    fn derive_hpke_keypair(
        &self,
        config: HpkeConfig,
        ikm: &[u8],
    ) -> Result<HpkeKeyPair, CryptoError> {
        let (private, public) = hpke_for(&config)?
            .derive_key_pair(ikm)
            .map_err(|e| match e {
                hpke_rs::HpkeError::InvalidInput => CryptoError::InvalidLength,
                _ => CryptoError::CryptoLibraryError,
            })?
            .into_keys();
        Ok(HpkeKeyPair {
            private: private.as_slice().to_vec().into(),
            public: public.as_slice().to_vec(),
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
/// zeroized on wipe and on drop. Encrypted persistence is a later stage.
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

/// A member's ML-DSA-87 signing key. The private half never leaves this
/// struct and is wiped when it is dropped.
pub struct SignatureKeyPair {
    public: Vec<u8>,
    secret: Zeroizing<Vec<u8>>,
}

impl SignatureKeyPair {
    pub fn generate() -> Self {
        let (pk, sk) = mldsa87::keypair();
        Self {
            public: pk.as_bytes().to_vec(),
            secret: Zeroizing::new(sk.as_bytes().to_vec()),
        }
    }

    pub fn public(&self) -> &[u8] {
        &self.public
    }
}

impl core::fmt::Debug for SignatureKeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SignatureKeyPair").finish_non_exhaustive()
    }
}

impl Signer for SignatureKeyPair {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        mldsa87_sign(&self.secret, payload).map_err(SignerError::CryptoError)
    }

    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::MLDSA87
    }
}
