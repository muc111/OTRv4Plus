// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
//! Our provider against OpenMLS's reference provider (openmls_rust_crypto:
//! RustCrypto ml-dsa, and hpke-rs-rust-crypto's ML-KEM), an independent
//! implementation of the same suite. Test-only; never shipped.
//!
//! If these agree, the PQClean-backed provider computes the same MLS as
//! everyone else's: deterministic HPKE key derivation, HPKE, and ML-DSA-87.

use openmls::prelude::{tls_codec::*, *};
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{
    crypto::OpenMlsCrypto,
    signatures::{Signer, SignerError},
    OpenMlsProvider,
};
use otrv4_mls::{CoreCrypto, CoreProvider, SignatureKeyPair, CIPHERSUITE};

/// A signer for the reference provider (its own key format).
struct RefSigner {
    private: Vec<u8>,
    public: Vec<u8>,
    provider: OpenMlsRustCrypto,
}

impl RefSigner {
    fn new() -> Self {
        let provider = OpenMlsRustCrypto::default();
        let (private, public) = provider.crypto().signature_key_gen(SignatureScheme::MLDSA87).unwrap();
        Self { private, public, provider }
    }
}

impl Signer for RefSigner {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        self.provider
            .crypto()
            .sign(SignatureScheme::MLDSA87, payload, &self.private)
            .map_err(SignerError::CryptoError)
    }
    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::MLDSA87
    }
}

fn ours() -> CoreCrypto {
    CoreCrypto
}

fn reference() -> OpenMlsRustCrypto {
    OpenMlsRustCrypto::default()
}

#[test]
fn derived_hpke_public_keys_match() {
    // Every member re-derives tree keys from path secrets and checks them
    // against the tree: derivation must match bit for bit.
    let r = reference();
    for i in 0u8..8 {
        let ikm = [i.wrapping_mul(37); 48];
        let a = ours().derive_hpke_keypair(CIPHERSUITE.hpke_config(), &ikm).unwrap();
        let b = r.crypto().derive_hpke_keypair(CIPHERSUITE.hpke_config(), &ikm).unwrap();
        assert_eq!(a.public, b.public, "ikm #{i}");
        assert_eq!(a.public.len(), 1568);
    }
}

#[test]
fn hpke_both_directions() {
    let r = reference();
    let ikm = [7u8; 48];
    let mine = ours().derive_hpke_keypair(CIPHERSUITE.hpke_config(), &ikm).unwrap();
    let theirs = r.crypto().derive_hpke_keypair(CIPHERSUITE.hpke_config(), &ikm).unwrap();

    let ct = ours()
        .hpke_seal(CIPHERSUITE.hpke_config(), &theirs.public, b"info", b"aad", b"to reference")
        .unwrap();
    let pt = r.crypto()
        .hpke_open(CIPHERSUITE.hpke_config(), &ct, &theirs.private, b"info", b"aad")
        .unwrap();
    assert_eq!(pt, b"to reference");

    let ct = r.crypto()
        .hpke_seal(CIPHERSUITE.hpke_config(), &mine.public, b"info", b"aad", b"to core")
        .unwrap();
    let pt = ours()
        .hpke_open(CIPHERSUITE.hpke_config(), &ct, &mine.private, b"info", b"aad")
        .unwrap();
    assert_eq!(pt, b"to core");

    // Exporter (used for external init / PSK paths) agrees too.
    let (enc, s1) = ours()
        .hpke_setup_sender_and_export(CIPHERSUITE.hpke_config(), &theirs.public, b"i", b"ctx", 32)
        .unwrap();
    let s2 = r.crypto()
        .hpke_setup_receiver_and_export(CIPHERSUITE.hpke_config(), &enc, &theirs.private, b"i", b"ctx", 32)
        .unwrap();
    assert_eq!(s1.len(), 32);
    assert_eq!(*s1, *s2);
}

#[test]
fn ml_dsa_87_signatures_both_directions() {
    let r = reference();
    let msg = b"MLS leaf node to be signed";

    let mine = SignatureKeyPair::generate();
    let sig = mine.sign(msg).unwrap();
    r.crypto().verify_signature(SignatureScheme::MLDSA87, msg, mine.public(), &sig).unwrap();

    let theirs = RefSigner::new();
    let sig = theirs.sign(msg).unwrap();
    ours().verify_signature(SignatureScheme::MLDSA87, msg, &theirs.public, &sig).unwrap();
    assert!(ours().verify_signature(SignatureScheme::MLDSA87, b"other", &theirs.public, &sig).is_err());
}

fn wire(msg: &MlsMessageOut) -> MlsMessageIn {
    MlsMessageIn::tls_deserialize_exact(msg.to_bytes().unwrap()).unwrap()
}

fn app<P: OpenMlsProvider>(group: &mut MlsGroup, provider: &P, msg: &MlsMessageOut) -> Vec<u8> {
    let p = wire(msg).try_into_protocol_message().unwrap();
    match group.process_message(provider, p).unwrap().into_content() {
        ProcessedMessageContent::ApplicationMessage(m) => m.into_bytes(),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn mixed_group_core_and_reference() {
    // Alice on our provider creates the group; Bob, on the reference
    // provider, joins from her Welcome; both talk; Bob rotates his key and
    // Alice follows the commit.
    let alice_p = CoreProvider::default();
    let alice_s = SignatureKeyPair::generate();
    let alice_c = CredentialWithKey {
        credential: BasicCredential::new(b"alice".to_vec()).into(),
        signature_key: alice_s.public().to_vec().into(),
    };
    let bob_s = RefSigner::new();
    let bob_p = &bob_s.provider;
    let bob_c = CredentialWithKey {
        credential: BasicCredential::new(b"bob".to_vec()).into(),
        signature_key: bob_s.public.clone().into(),
    };
    let bob_kp = KeyPackage::builder()
        .build(CIPHERSUITE, bob_p, &bob_s, bob_c)
        .unwrap()
        .key_package()
        .clone();

    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .build();
    let mut a = MlsGroup::new(&alice_p, &alice_s, &config, alice_c).unwrap();
    let (_, welcome, _) = a.add_members(&alice_p, &alice_s, &[bob_kp]).unwrap();
    a.merge_pending_commit(&alice_p).unwrap();

    let MlsMessageBodyIn::Welcome(welcome) = wire(&welcome).extract() else {
        panic!("not a welcome")
    };
    let join = MlsGroupJoinConfig::builder().use_ratchet_tree_extension(true).build();
    let mut b = StagedWelcome::new_from_welcome(bob_p, &join, welcome, None)
        .unwrap()
        .into_group(bob_p)
        .unwrap();

    let m = a.create_message(&alice_p, &alice_s, b"core to reference").unwrap();
    assert_eq!(app(&mut b, bob_p, &m), b"core to reference");
    let m = b.create_message(bob_p, &bob_s, b"reference to core").unwrap();
    assert_eq!(app(&mut a, &alice_p, &m), b"reference to core");

    let (commit, _, _) = b
        .self_update(bob_p, &bob_s, LeafNodeParameters::default())
        .unwrap()
        .into_contents();
    b.merge_pending_commit(bob_p).unwrap();
    let p = wire(&commit).try_into_protocol_message().unwrap();
    match a.process_message(&alice_p, p).unwrap().into_content() {
        ProcessedMessageContent::StagedCommitMessage(c) => a.merge_staged_commit(&alice_p, *c).unwrap(),
        other => panic!("unexpected {other:?}"),
    }
    assert_eq!(
        a.export_secret(alice_p.crypto(), "x", b"", 32).unwrap(),
        b.export_secret(bob_p.crypto(), "x", b"", 32).unwrap()
    );
    let m = a.create_message(&alice_p, &alice_s, b"after update").unwrap();
    assert_eq!(app(&mut b, bob_p, &m), b"after update");
}
