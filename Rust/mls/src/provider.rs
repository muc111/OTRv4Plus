// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
//! The OpenMLS provider: OpenMLS's crypto trait on the core's primitives.
//!
//! Two ciphersuites, and nothing else. Both hash and HKDF with SHA-512.
//!
//!   * **MLS_256_X448MLKEM1024_AES256GCM_SHA384_ED448MLDSA87** (0xF0A1,
//!     private; every new group). KEM X448 + ML-KEM-1024 with a binding
//!     combiner (`crate::hpke`), signature Ed448 + ML-DSA-87 composite
//!     (below). Breaking one half of either does not break the group. The
//!     code point's name keeps the historical `SHA384` token, but this
//!     private suite is bound to SHA-512 in the vendored ciphersuite table.
//!   * MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87 (0x0906; ML-KEM-1024
//!     alone, no X448 combiner). A standard code point, so it is what the
//!     reference OpenMLS provider cross-checks against (tests/interop.rs);
//!     also hash/HKDF SHA-512.
//!
//! Anything outside them (another hash, AEAD, signature scheme or KEM) is
//! refused with an error, never quietly served by something else.
//!
//! THE COMPOSITE SIGNATURE (0xFEA1)
//! ================================
//!   m'  = "OTRv4+MLS/CompositeSig/v2" || SHA-512(pk) || m
//!   sig = Ed448(sk_ed, m') (114) || ML-DSA-87(sk_ml, m') (4627)
//!   pk  = pk_ed (57) || pk_ml (2592);  sk = seed_ed (57) || sk_ml (4896)
//! Verification requires BOTH to pass; a length that is not exact is
//! refused. Pure Ed448 (RFC 8032, empty context), as the core's identity
//! keys; ML-DSA-87 as below. The label keeps a composite signature from
//! being taken apart and either half used as a plain signature on `m`, and
//! SHA-512(pk) binds BOTH component public keys into what each half signs,
//! so neither half verifies when paired with another key's half (label v2;
//! v1 bound neither).
//!
//! | MLS needs            | from                                        |
//! |----------------------|---------------------------------------------|
//! | SHA-512, HKDF, HMAC  | sha2 / hkdf / hmac (the core's versions)    |
//! | AES-256-GCM          | aes-gcm (the core's version)                |
//! | ML-DSA-87            | the `ml-dsa` crate (as the core's DAKE)     |
//! | HPKE, ML-KEM-1024    | `crate::hpke` (RFC 9180) on `ml-kem`        |
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
use ml_dsa::{MlDsa87, VerifyingKey, Signature, EncodedVerifyingKey, ExpandedSigningKey,
             ExpandedSigningKeyBytes, B32};
use sha2::{Digest, Sha512};
use tls_codec::SecretVLBytes;
use zeroize::{Zeroize, Zeroizing};

use crate::hpke::{self, Aead as HpkeAead, Kem};

/// The ciphersuite of every new group: hybrid KEM, composite signature.
pub const CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_256_X448MLKEM1024_AES256GCM_SHA384_ED448MLDSA87;
/// The non-hybrid PQ suite: ML-KEM-1024 alone, no X448 combiner. TEST ONLY:
/// served only with the `reference-interop` feature, because the reference
/// OpenMLS provider (tests/interop.rs) has no private hybrid code point and
/// this standard suite is what the independent cross-check runs on. The
/// shipped build serves `CIPHERSUITE` alone.
pub const LEGACY_CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87;
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
const COMPOSITE_LABEL: &[u8] = b"OTRv4+MLS/CompositeSig/v2";

/// Stateless: every primitive is a pure function of its inputs, randomness
/// comes from the OS per call.
#[derive(Debug, Default, Clone, Copy)]
pub struct CoreCrypto;

fn sha512_only(hash_type: HashType) -> Result<(), CryptoError> {
    match hash_type {
        HashType::Sha2_512 => Ok(()),
        _ => Err(CryptoError::UnsupportedHashAlgorithm),
    }
}

/// Whether a suite is served: the hybrid one, plus the test-only non-hybrid
/// one when built for the reference cross-check.
fn served(ciphersuite: Ciphersuite) -> bool {
    ciphersuite == CIPHERSUITE
        || (cfg!(feature = "reference-interop") && ciphersuite == LEGACY_CIPHERSUITE)
}

/// The HPKE configurations the served suites use; anything else is refused.
fn hpke_suite(config: &HpkeConfig) -> Result<(Kem, HpkeAead), CryptoError> {
    let kem = match config.0 {
        HpkeKemType::X448MlKem1024 => Kem::X448MlKem1024,
        HpkeKemType::MlKem1024 if cfg!(feature = "reference-interop") => Kem::MlKem1024,
        _ => return Err(CryptoError::UnsupportedCiphersuite),
    };
    if config.1 != HpkeKdfType::HkdfSha512 {
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

/// A fresh ML-DSA-87 keypair as `(pk 2592, expanded sk 4896)`.
#[allow(deprecated)] // `to_expanded` gives the 4896-byte PQClean-compatible form
fn mldsa87_keypair() -> (Vec<u8>, Zeroizing<Vec<u8>>) {
    let mut seed = Zeroizing::new(B32::default());
    getrandom::getrandom(seed.as_mut_slice()).expect("OS CSPRNG for ML-DSA key generation");
    let esk = ExpandedSigningKey::<MlDsa87>::from_seed(&seed);
    let pk = esk.verifying_key().encode().as_slice().to_vec();
    let expanded = Zeroizing::new(esk.to_expanded());
    (pk, Zeroizing::new(expanded.as_slice().to_vec()))
}

/// ML-DSA-87 detached signature: FIPS 204 ML-DSA.Sign (Algorithm 2),
/// hedged, pure, empty context, i.e. Sign_internal over `M' = 0 || 0 || M`
/// with 32 fresh bytes of OS randomness. (`sign_internal` takes M' as given.)
/// `secret` is the 4896-byte expanded signing key.
#[allow(deprecated)] // `from_expanded` consumes the 4896-byte PQClean-compatible sk
pub(crate) fn mldsa87_sign(secret: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let enc: Zeroizing<ExpandedSigningKeyBytes<MlDsa87>> =
        Zeroizing::new(secret.try_into().map_err(|_| CryptoError::InvalidLength)?);
    let esk = ExpandedSigningKey::<MlDsa87>::from_expanded(&enc);
    let mut rnd = Zeroizing::new(B32::default());
    getrandom::getrandom(rnd.as_mut_slice()).map_err(|_| CryptoError::InsufficientRandomness)?;
    let sig = esk.sign_internal(&[&[0u8], &[0u8], data], &rnd);
    Ok(sig.encode().as_slice().to_vec())
}

fn mldsa87_verify(pk: &[u8], data: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
    let vk_enc: EncodedVerifyingKey<MlDsa87> =
        pk.try_into().map_err(|_| CryptoError::InvalidLength)?;
    let vk = VerifyingKey::<MlDsa87>::decode(&vk_enc);
    let sig = Signature::<MlDsa87>::try_from(signature).map_err(|_| CryptoError::InvalidLength)?;
    if vk.verify_with_context(data, b"", &sig) {
        Ok(())
    } else {
        Err(CryptoError::InvalidSignature)
    }
}

/// m' = label || SHA-512(pk_composite) || m. The hash of the whole
/// composite public key (pk_ed || pk_ml) binds both halves: a signature
/// made for one (Ed448, ML-DSA-87) pair verifies under no other.
fn composite_message(pk_composite: &[u8], data: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(COMPOSITE_LABEL.len() + 64 + data.len());
    m.extend_from_slice(COMPOSITE_LABEL);
    m.extend_from_slice(&Sha512::digest(pk_composite));
    m.extend_from_slice(data);
    m
}

/// The composite public key `pk_ed (57) || pk_ml (2592)` that `secret`
/// (seed_ed || expanded ml sk) signs for. Decoding our own signing key, so
/// `from_expanded` cannot be driven by an attacker here.
#[allow(deprecated)]
fn composite_public_from_secret(seed: &[u8], ml_sk: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let ed_pub = ed448_key(seed)?.verifying_key().to_bytes();
    let enc: ExpandedSigningKeyBytes<MlDsa87> =
        ml_sk.try_into().map_err(|_| CryptoError::InvalidLength)?;
    let ml_vk = ExpandedSigningKey::<MlDsa87>::from_expanded(&enc).verifying_key().encode();
    let mut pk = Vec::with_capacity(COMPOSITE_PUBLIC_KEY_BYTES);
    pk.extend_from_slice(&ed_pub[..]);
    pk.extend_from_slice(ml_vk.as_slice());
    Ok(pk)
}

/// Whether a 4896-byte expanded ML-DSA-87 signing key can be decoded by
/// `ExpandedSigningKey::from_expanded` WITHOUT panicking.
///
/// Layout: rho 32 | K 32 | tr 64 | s1 672 | s2 768 | t0 3328. `ml-dsa`'s
/// BitUnpack asserts every s1/s2 coefficient (eta = 2, packed in 3 bits) is
/// <= 2*eta = 4 and panics otherwise; t0 (13-bit) cannot exceed its bound
/// and rho/K/tr are raw bytes, so s1||s2 is the entire panic surface. The
/// build is panic=abort and F4 key-reveal publications carry an
/// attacker-chosen expanded key (client::revealed_fingerprints), so an
/// undecodable one would abort the process: `from_parts` refuses it here,
/// before it can reach `from_expanded`. The 1440 bytes of s1||s2 hold
/// 3840 three-bit fields, LSB-first with no padding (256*(7+8)*3 bits =
/// 1440*8), so the check is independent of the coefficient order.
fn mldsa_expanded_decodable(sk: &[u8]) -> bool {
    if sk.len() != MLDSA87_SECRET_KEY_BYTES {
        return false;
    }
    const S1_S2: core::ops::Range<usize> = 128..128 + 672 + 768;
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in &sk[S1_S2] {
        acc |= (byte as u32) << bits;
        bits += 8;
        while bits >= 3 {
            if acc & 0b111 > 4 {
                return false;
            }
            acc >>= 3;
            bits -= 3;
        }
    }
    true
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
    let pk = composite_public_from_secret(seed, ml_sk)?;
    let m = composite_message(&pk, data);
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
    let m = composite_message(pk, data);
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
        if served(ciphersuite) {
            Ok(())
        } else {
            Err(CryptoError::UnsupportedCiphersuite)
        }
    }

    fn supported_ciphersuites(&self) -> Vec<Ciphersuite> {
        [CIPHERSUITE, LEGACY_CIPHERSUITE].into_iter().filter(|c| served(*c)).collect()
    }

    fn hkdf_extract(
        &self,
        hash_type: HashType,
        salt: &[u8],
        ikm: &[u8],
    ) -> Result<SecretVLBytes, CryptoError> {
        sha512_only(hash_type)?;
        let (mut prk, _) = Hkdf::<Sha512>::extract(Some(salt), ikm);
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
        sha512_only(hash_type)?;
        let mut mac =
            <Hmac<Sha512> as hmac::KeyInit>::new_from_slice(key).map_err(|_| CryptoError::InvalidLength)?;
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
        sha512_only(hash_type)?;
        let hkdf = Hkdf::<Sha512>::from_prk(prk).map_err(|_| CryptoError::HkdfOutputLengthInvalid)?;
        let mut okm = Zeroizing::new(vec![0u8; okm_len]);
        hkdf.expand(info, &mut okm)
            .map_err(|_| CryptoError::HkdfOutputLengthInvalid)?;
        Ok(okm.as_slice().into())
    }

    fn hash(&self, hash_type: HashType, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        sha512_only(hash_type)?;
        Ok(Sha512::digest(data).to_vec())
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
            .encrypt(nonce.try_into().map_err(|_| CryptoError::InvalidLength)?, Payload { msg: data, aad })
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
            .decrypt(nonce.try_into().map_err(|_| CryptoError::InvalidLength)?, Payload { msg: ct_tag, aad })
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
        let (ml_pk, ml_sk) = mldsa87_keypair();
        match scheme {
            SignatureScheme::MLDSA87 => Ok(Self {
                scheme,
                public: ml_pk,
                secret: ml_sk,
            }),
            COMPOSITE => {
                let mut seed = Zeroizing::new([0u8; ED448_SEED_BYTES]);
                getrandom::getrandom(&mut seed[..])
                    .map_err(|_| CryptoError::InsufficientRandomness)?;
                let ed_pk = ed448_key(&seed[..])?.verifying_key().to_bytes();
                let mut public = Vec::with_capacity(COMPOSITE_PUBLIC_KEY_BYTES);
                public.extend_from_slice(&ed_pk[..]);
                public.extend_from_slice(&ml_pk);
                let mut secret = Zeroizing::new(Vec::with_capacity(COMPOSITE_SECRET_KEY_BYTES));
                secret.extend_from_slice(&seed[..]);
                secret.extend_from_slice(&ml_sk);
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
        if public.len() == MLDSA87_PUBLIC_KEY_BYTES
            && secret.len() == MLDSA87_SECRET_KEY_BYTES
        {
            // A key reaching here may be attacker-supplied (F4 reveal); refuse
            // an ML-DSA half that from_expanded would abort on.
            if !mldsa_expanded_decodable(&secret) {
                return None;
            }
            return Some(Self { scheme: SignatureScheme::MLDSA87, public, secret });
        }
        if public.len() == COMPOSITE_PUBLIC_KEY_BYTES
            && secret.len() == COMPOSITE_SECRET_KEY_BYTES
        {
            let ed_pk = ed448_key(&secret[..ED448_SEED_BYTES]).ok()?.verifying_key().to_bytes();
            if ed_pk[..] != public[..ED448_PUBLIC_KEY_BYTES] {
                return None;
            }
            if !mldsa_expanded_decodable(&secret[ED448_SEED_BYTES..]) {
                return None;
            }
            return Some(Self { scheme: COMPOSITE, public, secret });
        }
        None
    }
}

impl SignatureKeyPair {
    /// Whether the private half really signs for the public half: a probe is
    /// signed and verified. For a key a member says they published (F4).
    pub(crate) fn is_consistent(&self) -> bool {
        const PROBE: &[u8] = b"OTRv4+ MLS published signing key probe";
        let Ok(signature) = Signer::sign(self, PROBE) else { return false };
        match self.scheme {
            COMPOSITE => composite_verify(&self.public, PROBE, &signature).is_ok(),
            _ => mldsa87_verify(&self.public, PROBE, &signature).is_ok(),
        }
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

    /// ML-DSA signing is hedged: one key, one message, two different
    /// signatures, both valid (for the composite and for plain ML-DSA-87).
    #[test]
    fn signing_is_hedged_not_deterministic() {
        let k = SignatureKeyPair::generate();
        let (a, b) = (k.sign(b"same").unwrap(), k.sign(b"same").unwrap());
        assert_ne!(a, b);
        let c = CoreCrypto;
        assert!(c.verify_signature(COMPOSITE, b"same", k.public(), &a).is_ok());
        assert!(c.verify_signature(COMPOSITE, b"same", k.public(), &b).is_ok());
        let m = SignatureKeyPair::generate_for(SignatureScheme::MLDSA87).unwrap();
        assert_ne!(m.sign(b"same").unwrap(), m.sign(b"same").unwrap());
    }

    /// Each half is bound to the whole composite public key: neither
    /// verifies when spliced onto a different key's matching half.
    #[test]
    fn a_half_cannot_be_recombined_with_another_keys_half() {
        let (a, b) = (SignatureKeyPair::generate(), SignatureKeyPair::generate());
        let (sa, sb) = (a.sign(b"m").unwrap(), b.sign(b"m").unwrap());
        let ed = ED448_SIGNATURE_BYTES;
        let edp = ED448_PUBLIC_KEY_BYTES;
        let c = CoreCrypto;
        // A's Ed448 half + B's ML-DSA half, under the mixed public key
        // (A's Ed448 pk + B's ML-DSA pk). Both halves are individually
        // valid signatures for their own key, yet the composite is refused.
        let mut mixed_sig = sa[..ed].to_vec();
        mixed_sig.extend_from_slice(&sb[ed..]);
        let mut mixed_pk = a.public()[..edp].to_vec();
        mixed_pk.extend_from_slice(&b.public()[edp..]);
        assert!(c.verify_signature(COMPOSITE, b"m", &mixed_pk, &mixed_sig).is_err());
        // And each real signature is refused under the mixed key.
        assert!(c.verify_signature(COMPOSITE, b"m", &mixed_pk, &sa).is_err());
        assert!(c.verify_signature(COMPOSITE, b"m", &mixed_pk, &sb).is_err());
    }

    /// A published "retired key" (F4) carries an attacker-chosen expanded
    /// ML-DSA half. from_parts must refuse one that `from_expanded` would
    /// abort on (panic=abort), before is_consistent/sign can reach it.
    #[test]
    fn from_parts_refuses_an_undecodable_mldsa_half() {
        // Every freshly generated key is decodable.
        for _ in 0..64 {
            let k = SignatureKeyPair::generate();
            assert!(mldsa_expanded_decodable(&k.secret()[ED448_SEED_BYTES..]));
            let m = SignatureKeyPair::generate_for(SignatureScheme::MLDSA87).unwrap();
            assert!(mldsa_expanded_decodable(m.secret()));
        }
        // A real composite key with its ML-DSA half overwritten: the Ed448
        // half still matches its seed, so only the ML-DSA check can catch it.
        let k = SignatureKeyPair::generate();
        let mut bad = Zeroizing::new(k.secret().to_vec());
        for b in &mut bad[ED448_SEED_BYTES..] { *b = 0xff; }
        assert!(!mldsa_expanded_decodable(&bad[ED448_SEED_BYTES..]));
        assert!(SignatureKeyPair::from_parts(k.public().to_vec(), bad).is_none(),
                "an undecodable ML-DSA half must be refused");
        // The genuine key still round-trips through from_parts.
        assert!(SignatureKeyPair::from_parts(
            k.public().to_vec(), Zeroizing::new(k.secret().to_vec())).is_some());
        // Same for the plain MLDSA87 scheme.
        let m = SignatureKeyPair::generate_for(SignatureScheme::MLDSA87).unwrap();
        let mut bad = Zeroizing::new(m.secret().to_vec());
        for b in bad.iter_mut() { *b = 0xff; }
        assert!(SignatureKeyPair::from_parts(m.public().to_vec(), bad).is_none());
    }

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
