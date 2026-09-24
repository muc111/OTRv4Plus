// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
//! hpke-rs's crypto backend, on the core's primitives.
//!
//! hpke-rs does the RFC 9180 composition (key schedule, labelled KDF,
//! nonces, export); this supplies the primitives it asks for, for the one
//! configuration the MLS suite uses: KEM ML-KEM-1024, KDF HKDF-SHA384, AEAD
//! AES-256-GCM (plus export-only). Everything else is refused.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm,
};
use hkdf::Hkdf;
use hpke_rs_crypto::{
    error::Error,
    types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm},
    HpkeCrypto, HpkeTestRng,
};
use sha2::Sha384;
use zeroize::Zeroize;

use crate::mlkem;

#[derive(Debug, Default, Clone, Copy)]
pub struct CoreHpke;

/// Operating-system randomness, per call. Holds no state, so there is
/// nothing to zeroize; it cannot report failure (rand_core's CryptoRng is
/// infallible), so an OS that cannot supply randomness is a panic rather
/// than weak keys.
#[derive(Debug, Default)]
pub struct OsPrng;

impl Zeroize for OsPrng {
    fn zeroize(&mut self) {}
}

fn os_fill(dst: &mut [u8]) {
    getrandom::getrandom(dst).expect("the operating system supplied no randomness");
}

impl rand_core_hpke::TryRng for OsPrng {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        os_fill(&mut b);
        Ok(u32::from_le_bytes(b))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        os_fill(&mut b);
        Ok(u64::from_le_bytes(b))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        os_fill(dst);
        Ok(())
    }
}

impl rand_core_hpke::TryCryptoRng for OsPrng {}

#[derive(Debug)]
pub struct NoTestRng;
impl core::fmt::Display for NoTestRng {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("no test randomness")
    }
}

impl HpkeTestRng for OsPrng {
    type Error = NoTestRng;
    /// Not a test PRNG: real randomness, always.
    fn try_fill_test_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        os_fill(dest);
        Ok(())
    }
    fn seed(&mut self, _: &[u8]) {}
}

impl HpkeCrypto for CoreHpke {
    type HpkePrng = OsPrng;

    fn name() -> String {
        "otrv4plus-core".into()
    }

    fn supports_kdf(alg: KdfAlgorithm) -> Result<(), Error> {
        match alg {
            KdfAlgorithm::HkdfSha384 => Ok(()),
            _ => Err(Error::UnknownKdfAlgorithm),
        }
    }

    fn supports_kem(alg: KemAlgorithm) -> Result<(), Error> {
        match alg {
            KemAlgorithm::MlKem1024 => Ok(()),
            _ => Err(Error::UnknownKemAlgorithm),
        }
    }

    fn supports_aead(alg: AeadAlgorithm) -> Result<(), Error> {
        match alg {
            AeadAlgorithm::Aes256Gcm | AeadAlgorithm::HpkeExport => Ok(()),
            _ => Err(Error::UnknownAeadAlgorithm),
        }
    }

    fn prng() -> Self::HpkePrng {
        OsPrng
    }

    fn kdf_extract(alg: KdfAlgorithm, salt: &[u8], ikm: &[u8]) -> Result<Vec<u8>, Error> {
        Self::supports_kdf(alg)?;
        Ok(Hkdf::<Sha384>::extract(Some(salt), ikm).0.to_vec())
    }

    fn kdf_expand(
        alg: KdfAlgorithm,
        prk: &[u8],
        info: &[u8],
        output_size: usize,
    ) -> Result<Vec<u8>, Error> {
        Self::supports_kdf(alg)?;
        let hkdf = Hkdf::<Sha384>::from_prk(prk).map_err(|_| Error::HpkeInvalidOutputLength)?;
        let mut okm = vec![0u8; output_size];
        hkdf.expand(info, &mut okm)
            .map_err(|_| Error::HpkeInvalidOutputLength)?;
        Ok(okm)
    }

    fn dh(_alg: KemAlgorithm, _pk: &[u8], _sk: &[u8]) -> Result<Vec<u8>, Error> {
        Err(Error::UnknownKemAlgorithm)
    }

    fn secret_to_public(_alg: KemAlgorithm, _sk: &[u8]) -> Result<Vec<u8>, Error> {
        Err(Error::UnknownKemAlgorithm)
    }

    fn kem_key_gen(alg: KemAlgorithm, prng: &mut Self::HpkePrng) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let mut seed = vec![0u8; mlkem::SEED_BYTES];
        HpkeTestRng::try_fill_test_bytes(prng, &mut seed).map_err(|_| Error::InsufficientRandomness)?;
        let out = Self::kem_key_gen_derand(alg, &seed);
        seed.zeroize();
        out
    }

    /// (encapsulation key, decapsulation key) from the FIPS 203 seed.
    fn kem_key_gen_derand(alg: KemAlgorithm, seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
        Self::supports_kem(alg)?;
        mlkem::keypair_from_seed(seed).ok_or(Error::KemInvalidSecretKey)
    }

    /// (shared secret, encapsulation) -- the order hpke-rs expects.
    fn kem_encaps(
        alg: KemAlgorithm,
        pk_r: &[u8],
        _prng: &mut Self::HpkePrng,
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        Self::supports_kem(alg)?;
        mlkem::encapsulate(pk_r).ok_or(Error::KemInvalidPublicKey)
    }

    fn kem_decaps(alg: KemAlgorithm, ct: &[u8], sk_r: &[u8]) -> Result<Vec<u8>, Error> {
        Self::supports_kem(alg)?;
        mlkem::decapsulate(ct, sk_r).ok_or(Error::KemInvalidCiphertext)
    }

    fn dh_validate_sk(_alg: KemAlgorithm, _sk: &[u8]) -> Result<Vec<u8>, Error> {
        Err(Error::UnknownKemAlgorithm)
    }

    fn aead_seal(
        alg: AeadAlgorithm,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        msg: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if alg != AeadAlgorithm::Aes256Gcm {
            return Err(Error::UnknownAeadAlgorithm);
        }
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::AeadInvalidNonce)?;
        if nonce.len() != 12 {
            return Err(Error::AeadInvalidNonce);
        }
        cipher
            .encrypt(nonce.into(), Payload { msg, aad })
            .map_err(|_| Error::CryptoLibraryError("aes-gcm seal".into()))
    }

    fn aead_open(
        alg: AeadAlgorithm,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        msg: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if alg != AeadAlgorithm::Aes256Gcm {
            return Err(Error::UnknownAeadAlgorithm);
        }
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::AeadInvalidNonce)?;
        if nonce.len() != 12 {
            return Err(Error::AeadInvalidNonce);
        }
        cipher
            .decrypt(nonce.into(), Payload { msg, aad })
            .map_err(|_| Error::AeadOpenError)
    }
}
