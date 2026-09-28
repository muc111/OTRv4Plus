// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
//! PQClean (shipped) vs RustCrypto (independent) for ML-KEM-1024 and
//! ML-DSA-87. Every check runs in both directions.
#![allow(deprecated)] // ml-kem's expanded-key encoding: the format PQClean uses

use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _};
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};
use rand::RngCore;

const ROUNDS: usize = 64;

mod kem {
    use super::*;
    use ml_kem::{array::Array, Decapsulate, EncapsulationKey, DecapsulationKey, MlKem1024, Ciphertext};
    use pqcrypto_mlkem::mlkem1024 as pq;

    fn rc_dk(sk: &[u8]) -> DecapsulationKey<MlKem1024> {
        let arr = Array::try_from(sk).expect("expanded dk size");
        DecapsulationKey::<MlKem1024>::from_expanded(&arr).expect("valid expanded dk")
    }

    #[test]
    fn keys_agree() {
        for _ in 0..ROUNDS {
            let (pk, sk) = pq::keypair();
            let dk = rc_dk(sk.as_bytes());
            use ml_kem::KeyExport;
            assert_eq!(dk.encapsulation_key().to_bytes().as_slice(), pk.as_bytes());
        }
    }

    #[test]
    fn pqclean_encapsulates_rustcrypto_decapsulates() {
        for _ in 0..ROUNDS {
            let (pk, sk) = pq::keypair();
            let (ss, ct) = pq::encapsulate(&pk);
            let rc_ct: Ciphertext<MlKem1024> = Array::try_from(ct.as_bytes()).expect("ct size");
            assert_eq!(rc_dk(sk.as_bytes()).decapsulate(&rc_ct).as_slice(), ss.as_bytes());
        }
    }

    #[test]
    fn rustcrypto_encapsulates_pqclean_decapsulates() {
        for _ in 0..ROUNDS {
            let (pk, sk) = pq::keypair();
            let ek = EncapsulationKey::<MlKem1024>::new(&Array::try_from(pk.as_bytes()).unwrap())
                .expect("valid ek");
            let mut m = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut m);
            let (ct, ss) = ek.encapsulate_deterministic(&Array::from(m));
            let pq_ct = pq::Ciphertext::from_bytes(ct.as_slice()).expect("ct");
            assert_eq!(pq::decapsulate(&pq_ct, &sk).as_bytes(), ss.as_slice());
        }
    }

    /// FIPS 203 implicit rejection: a tampered ciphertext yields
    /// J(z || c), not an error. Both must compute the same pseudo-random
    /// key, or one of them is not implementing the standard.
    #[test]
    fn implicit_rejection_agrees() {
        let mut rng = rand::thread_rng();
        for _ in 0..ROUNDS {
            let (pk, sk) = pq::keypair();
            let (ss, ct) = pq::encapsulate(&pk);
            let mut bad = ct.as_bytes().to_vec();
            let i = (rng.next_u32() as usize) % bad.len();
            bad[i] ^= 1 << (rng.next_u32() % 8);
            let pq_ss = pq::decapsulate(&pq::Ciphertext::from_bytes(&bad).unwrap(), &sk);
            let rc_ss = rc_dk(sk.as_bytes()).decapsulate(&Array::try_from(&bad[..]).unwrap());
            assert_ne!(pq_ss.as_bytes(), ss.as_bytes(), "tamper undetected");
            assert_eq!(pq_ss.as_bytes(), rc_ss.as_slice(), "implicit rejection differs");
        }
    }

    #[test]
    fn a_non_canonical_encapsulation_key_is_refused_by_rustcrypto() {
        // FIPS 203 §7.2 modulus check: coefficients >= q are invalid. PQClean's
        // encapsulate does not check (it reduces); the core must not rely on
        // the KEM to validate a peer key. Recorded, not asserted, for PQClean.
        let (pk, _) = pq::keypair();
        let mut bad = pk.as_bytes().to_vec();
        bad[0] = 0xff; bad[1] |= 0x0f;   // first 12-bit coefficient = 0xfff >= q
        let rc = EncapsulationKey::<MlKem1024>::new(&Array::try_from(&bad[..]).unwrap());
        assert!(rc.is_err(), "RustCrypto should refuse a coefficient >= q");
        let pq_accepts = pq::PublicKey::from_bytes(&bad).is_ok();
        eprintln!("PQClean from_bytes accepts non-canonical ek: {pq_accepts}");
    }
}

mod sig {
    use super::*;
    use ml_dsa::{EncodedVerifyingKey, ExpandedSigningKey, MlDsa87, VerifyingKey};
    use ml_dsa::signature::SignatureEncoding;
    use pqcrypto_mldsa::mldsa87 as pq;

    fn rc_vk(pk: &[u8]) -> VerifyingKey<MlDsa87> {
        let enc = EncodedVerifyingKey::<MlDsa87>::try_from(pk).expect("vk size");
        VerifyingKey::<MlDsa87>::decode(&enc)
    }

    fn rc_sig(sig: &[u8]) -> Option<ml_dsa::Signature<MlDsa87>> {
        ml_dsa::Signature::<MlDsa87>::try_from(sig).ok()
    }

    #[test]
    fn pqclean_signs_rustcrypto_verifies() {
        let mut rng = rand::thread_rng();
        for n in 0..ROUNDS {
            let (pk, sk) = pq::keypair();
            let mut msg = vec![0u8; n * 7];
            rng.fill_bytes(&mut msg);
            let sig = pq::detached_sign(&msg, &sk);
            let s = rc_sig(sig.as_bytes()).expect("decodes");
            assert!(rc_vk(pk.as_bytes()).verify_with_context(&msg, b"", &s));
            // and a different message does not
            msg.push(1);
            assert!(!rc_vk(pk.as_bytes()).verify_with_context(&msg, b"", &s));
        }
    }

    #[test]
    fn rustcrypto_signs_pqclean_verifies() {
        let mut rng = rand::thread_rng();
        for n in 0..ROUNDS {
            let (pk, sk) = pq::keypair();
            let esk = ExpandedSigningKey::<MlDsa87>::from_expanded(
                &sk.as_bytes().try_into().expect("expanded sk size"));
            let mut msg = vec![0u8; n * 5 + 1];
            rng.fill_bytes(&mut msg);
            let s = esk.sign_deterministic(&msg, b"").expect("sign");
            let bytes = s.to_bytes();
            let sig = pq::DetachedSignature::from_bytes(bytes.as_ref()).expect("sig");
            assert!(pq::verify_detached_signature(&sig, &msg, &pk).is_ok());
        }
    }

    #[test]
    fn tampered_signatures_are_refused_by_both() {
        let mut rng = rand::thread_rng();
        let (pk, sk) = pq::keypair();
        let msg = b"OTRv4Plus audit";
        let sig = pq::detached_sign(msg, &sk);
        for _ in 0..ROUNDS * 4 {
            let mut bad = sig.as_bytes().to_vec();
            let i = (rng.next_u32() as usize) % bad.len();
            bad[i] ^= 1 << (rng.next_u32() % 8);
            let pq_ok = pq::DetachedSignature::from_bytes(&bad)
                .map(|s| pq::verify_detached_signature(&s, msg, &pk).is_ok())
                .unwrap_or(false);
            let rc_ok = rc_sig(&bad)
                .map(|s| rc_vk(pk.as_bytes()).verify_with_context(msg, b"", &s))
                .unwrap_or(false);
            assert_eq!(pq_ok, rc_ok, "implementations disagree at byte {i}");
            assert!(!pq_ok, "tampered signature accepted at byte {i}");
        }
    }
}
