// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
//! ML-KEM-1024 from PQClean -- the implementation otrv4_core already uses.
//!
//! `pqcrypto-mlkem` compiles PQClean's `kem.c`, which defines FIPS 203's
//! deterministic key generation `crypto_kem_keypair_derand(pk, sk, coins)`
//! with `coins = d || z` (64 bytes), but the Rust crate does not export it.
//! MLS needs exactly that: every member re-derives a tree node's HPKE key
//! pair from a shared secret and checks it against the public key in the
//! tree, so derivation must be deterministic and identical everywhere.
//!
//! The portable "clean" build of ML-KEM-1024 is compiled on every target
//! (pqcrypto-mlkem's build.rs), so the symbol below is always present.
//! This is the ONLY `unsafe` in the crate.

use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _};
use zeroize::Zeroize;

pub const PUBLIC_KEY_BYTES: usize = 1568;
pub const SECRET_KEY_BYTES: usize = 3168;
pub const CIPHERTEXT_BYTES: usize = 1568;
pub const SEED_BYTES: usize = 64;

#[allow(unsafe_code)]
mod ffi {
    extern "C" {
        pub fn PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair_derand(
            pk: *mut u8,
            sk: *mut u8,
            coins: *const u8,
        ) -> core::ffi::c_int;
    }
}

/// (public, secret) from a 64-byte FIPS 203 seed `d || z`.
#[allow(unsafe_code)]
pub fn keypair_from_seed(seed: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    if seed.len() != SEED_BYTES {
        return None;
    }
    // Make sure pqcrypto-mlkem (and so the PQClean object holding the
    // symbol) is linked in.
    let _ = pqcrypto_mlkem::mlkem1024::public_key_bytes();
    let mut pk = vec![0u8; PUBLIC_KEY_BYTES];
    let mut sk = vec![0u8; SECRET_KEY_BYTES];
    // SAFETY: the buffers have exactly the sizes PQClean's api.h declares
    // for ML-KEM-1024, and `seed` is exactly 64 bytes, checked above.
    let rc = unsafe {
        ffi::PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair_derand(
            pk.as_mut_ptr(),
            sk.as_mut_ptr(),
            seed.as_ptr(),
        )
    };
    if rc != 0 {
        sk.zeroize();
        return None;
    }
    Some((pk, sk))
}

/// (shared secret, ciphertext) to `pk`.
pub fn encapsulate(pk: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let pk = pqcrypto_mlkem::mlkem1024::PublicKey::from_bytes(pk).ok()?;
    let (ss, ct) = pqcrypto_mlkem::mlkem1024::encapsulate(&pk);
    Some((ss.as_bytes().to_vec(), ct.as_bytes().to_vec()))
}

/// The shared secret in `ct`, for secret key `sk`.
pub fn decapsulate(ct: &[u8], sk: &[u8]) -> Option<Vec<u8>> {
    let ct = pqcrypto_mlkem::mlkem1024::Ciphertext::from_bytes(ct).ok()?;
    let sk = pqcrypto_mlkem::mlkem1024::SecretKey::from_bytes(sk).ok()?;
    Some(pqcrypto_mlkem::mlkem1024::decapsulate(&ct, &sk).as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeded_keygen_is_deterministic_and_works() {
        let seed = [0x42u8; SEED_BYTES];
        let (pk1, sk1) = keypair_from_seed(&seed).unwrap();
        let (pk2, sk2) = keypair_from_seed(&seed).unwrap();
        assert_eq!(pk1, pk2);
        assert_eq!(sk1, sk2);
        assert_eq!((pk1.len(), sk1.len()), (PUBLIC_KEY_BYTES, SECRET_KEY_BYTES));
        let (pk3, _) = keypair_from_seed(&[0x43u8; SEED_BYTES]).unwrap();
        assert_ne!(pk1, pk3);

        let (ss, ct) = encapsulate(&pk1).unwrap();
        assert_eq!(ct.len(), CIPHERTEXT_BYTES);
        assert_eq!(decapsulate(&ct, &sk1).unwrap(), ss);
    }

    #[test]
    fn wrong_lengths_are_refused() {
        assert!(keypair_from_seed(&[0u8; 32]).is_none());
        assert!(keypair_from_seed(&[0u8; 65]).is_none());
        assert!(encapsulate(&[0u8; 100]).is_none());
        assert!(decapsulate(&[0u8; 100], &[0u8; SECRET_KEY_BYTES]).is_none());
    }
}
