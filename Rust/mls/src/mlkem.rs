// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
//! ML-KEM-1024 -- the pure-Rust `ml-kem` crate (the implementation
//! otrv4_core uses).
//!
//! MLS needs FIPS 203 deterministic key generation: every member re-derives
//! a tree node's HPKE key pair from a shared secret and checks it against the
//! public key in the tree, so derivation must be deterministic and identical
//! everywhere. `ml-kem` provides this as `DecapsulationKey::from_seed(d || z)`
//! in pure Rust, so this crate needs no FFI and keeps #![forbid(unsafe_code)].
//!
//! Byte encodings are the FIPS 203 forms (ek 1568, expanded dk 3168, ct 1568),
//! identical to the former PQClean bindings and cross-checked in Rust/audit.

use ml_kem::{MlKem1024, EncapsulationKey, DecapsulationKey, Ciphertext, Decapsulate, KeyExport,
             ExpandedDecapsulationKey, Seed, B32};
use zeroize::Zeroizing;
use ml_kem::array::Array;
#[allow(deprecated)]
use ml_kem::ExpandedKeyEncoding;

pub const PUBLIC_KEY_BYTES: usize = 1568;
pub const SECRET_KEY_BYTES: usize = 3168;
pub const CIPHERTEXT_BYTES: usize = 1568;
pub const SEED_BYTES: usize = 64;

/// (public, secret) from a 64-byte FIPS 203 seed `d || z`. The secret is the
/// 3168-byte expanded decapsulation key, in a wiped buffer; the seed copy and
/// the encoded key are wiped too.
pub fn keypair_from_seed(seed: &[u8]) -> Option<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    if seed.len() != SEED_BYTES {
        return None;
    }
    let seed: Zeroizing<Seed> = Zeroizing::new(Array::try_from(seed).ok()?);
    let dk = DecapsulationKey::<MlKem1024>::from_seed(*seed);
    let pk = dk.encapsulation_key().to_bytes().as_slice().to_vec();
    #[allow(deprecated)]
    let expanded = Zeroizing::new(dk.to_expanded_bytes());
    Some((pk, Zeroizing::new(expanded.as_slice().to_vec())))
}

/// (shared secret, ciphertext) to `pk`. The shared secret, and the
/// randomness `m` that alone determines it, are held in wiped buffers.
pub fn encapsulate(pk: &[u8]) -> Option<(Zeroizing<Vec<u8>>, Vec<u8>)> {
    let key = EncapsulationKey::<MlKem1024>::new(&Array::try_from(pk).ok()?).ok()?;
    let mut m = Zeroizing::new(B32::default());
    getrandom::getrandom(m.as_mut_slice()).ok()?;
    let (ct, ss) = key.encapsulate_deterministic(&m);
    let ss = Zeroizing::new(ss);
    Some((Zeroizing::new(ss.as_slice().to_vec()), ct.as_slice().to_vec()))
}

/// The shared secret in `ct`, for expanded secret key `sk` (3168).
pub fn decapsulate(ct: &[u8], sk: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let sk: Zeroizing<ExpandedDecapsulationKey<MlKem1024>> =
        Zeroizing::new(Array::try_from(sk).ok()?);
    #[allow(deprecated)]
    let key = DecapsulationKey::<MlKem1024>::from_expanded_bytes(&sk).ok()?;
    let ct = Ciphertext::<MlKem1024>::try_from(ct).ok()?;
    let ss = Zeroizing::new(key.decapsulate(&ct));
    Some(Zeroizing::new(ss.as_slice().to_vec()))
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
