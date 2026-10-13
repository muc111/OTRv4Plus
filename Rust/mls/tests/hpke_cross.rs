// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
//! src/hpke.rs against hpke-rs 0.7.0 (the implementation it replaced in the
//! build), byte for byte. hpke-rs is a dev-dependency only.

#[path = "support/hpke_backend.rs"]
#[allow(dead_code)]
mod backend;

use backend::CoreHpke;
use hpke_rs::{Hpke, Mode};
use hpke_rs_crypto::types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};
use otrv4_mls::hpke::{self, Aead};

fn reference(aead: AeadAlgorithm) -> Hpke<CoreHpke> {
    Hpke::new(Mode::Base, KemAlgorithm::MlKem1024, KdfAlgorithm::HkdfSha384, aead)
}

#[test]
fn derive_key_pair_matches_for_many_inputs() {
    for i in 0u8..16 {
        let ikm: Vec<u8> = (0..(i as usize * 7 + 1)).map(|j| (j as u8) ^ i).collect();
        let (sk, pk) = hpke::derive_key_pair(&ikm).unwrap();
        let kp = reference(AeadAlgorithm::Aes256Gcm).derive_key_pair(&ikm).unwrap();
        let (rsk, rpk) = kp.into_keys();
        assert_eq!(pk, rpk.as_slice(), "public key differs for ikm #{i}");
        assert_eq!(sk.as_slice(), rsk.as_slice(), "private key differs for ikm #{i}");
    }
}

#[test]
fn each_side_opens_the_other() {
    let (sk, pk) = hpke::derive_key_pair(b"recipient").unwrap();
    for (info, aad, pt) in [(&b""[..], &b""[..], &b""[..]),
                            (b"info", b"aad", b"hello"),
                            (b"i", b"", &[7u8; 5000][..])] {
        // Ours seals, hpke-rs opens.
        let (enc, ct) = hpke::seal(&pk, info, aad, pt).unwrap();
        let got = reference(AeadAlgorithm::Aes256Gcm)
            .open(&enc, &sk.to_vec().into(), info, aad, &ct, None, None, None)
            .unwrap();
        assert_eq!(got, pt);
        // hpke-rs seals, ours opens.
        let (enc, ct) = reference(AeadAlgorithm::Aes256Gcm)
            .seal(&pk.clone().into(), info, aad, pt, None, None, None)
            .unwrap();
        assert_eq!(hpke::open(&enc, &sk, info, aad, &ct).unwrap().as_slice(), pt);
    }
}

#[test]
fn exports_match_in_both_directions_and_both_aeads() {
    let (sk, pk) = hpke::derive_key_pair(b"exporter").unwrap();
    for (aead, raead) in [(Aead::ExportOnly, AeadAlgorithm::HpkeExport),
                          (Aead::Aes256Gcm, AeadAlgorithm::Aes256Gcm)] {
        for len in [1usize, 32, 48, 64, 255] {
            let (enc, ours) = hpke::sender_export(&pk, b"info", aead, b"ctx", len).unwrap();
            let theirs = reference(raead)
                .setup_receiver(&enc, &sk.to_vec().into(), b"info", None, None, None)
                .unwrap()
                .export(b"ctx", len)
                .unwrap();
            assert_eq!(ours.as_slice(), theirs.as_slice(), "{aead:?} len {len}");

            let (enc, ctx) = reference(raead)
                .setup_sender(&pk.clone().into(), b"info", None, None, None)
                .unwrap();
            let theirs = ctx.export(b"ctx", len).unwrap();
            let ours = hpke::receiver_export(&enc, &sk, b"info", aead, b"ctx", len).unwrap();
            assert_eq!(ours.as_slice(), theirs.as_slice());
        }
    }
}

#[test]
fn wrong_key_info_or_aad_do_not_open() {
    let (sk, pk) = hpke::derive_key_pair(b"a").unwrap();
    let (sk2, _) = hpke::derive_key_pair(b"b").unwrap();
    let (enc, ct) = hpke::seal(&pk, b"info", b"aad", b"x").unwrap();
    assert!(hpke::open(&enc, &sk2, b"info", b"aad", &ct).is_err());
    assert!(hpke::open(&enc, &sk, b"info2", b"aad", &ct).is_err());
    assert!(hpke::open(&enc, &sk, b"info", b"aad2", &ct).is_err());
    assert!(hpke::open(&enc[..100], &sk, b"info", b"aad", &ct).is_err());
}
