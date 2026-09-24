// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
//! MLS groups on the core's crypto, members in one process. Every message
//! goes through its wire bytes, as it would over a transport.

use openmls::prelude::{tls_codec::*, *};
use openmls_traits::{crypto::OpenMlsCrypto, signatures::Signer, OpenMlsProvider};
use otrv4_mls::{CoreProvider, SignatureKeyPair, CIPHERSUITE};

struct Member {
    provider: CoreProvider,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
}

impl Member {
    fn new(name: &'static str) -> Self {
        let signer = SignatureKeyPair::generate();
        let credential = CredentialWithKey {
            credential: BasicCredential::new(name.as_bytes().to_vec()).into(),
            signature_key: signer.public().to_vec().into(),
        };
        Self { provider: CoreProvider::default(), signer, credential }
    }

    fn key_package(&self) -> KeyPackage {
        KeyPackage::builder()
            .build(CIPHERSUITE, &self.provider, &self.signer, self.credential.clone())
            .expect("key package")
            .key_package()
            .clone()
    }
}

fn create_config() -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .build()
}

fn join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder().use_ratchet_tree_extension(true).build()
}

/// Out through the wire format and back in.
fn wire(msg: &MlsMessageOut) -> MlsMessageIn {
    let bytes = msg.to_bytes().expect("serialise");
    MlsMessageIn::tls_deserialize_exact(bytes).expect("deserialise")
}

fn join(member: &Member, welcome: &MlsMessageOut) -> MlsGroup {
    let MlsMessageBodyIn::Welcome(welcome) = wire(welcome).extract() else {
        panic!("not a welcome");
    };
    StagedWelcome::new_from_welcome(&member.provider, &join_config(), welcome, None)
        .expect("staged welcome")
        .into_group(&member.provider)
        .expect("joined")
}

fn receive<P: OpenMlsProvider>(group: &mut MlsGroup, provider: &P, msg: &MlsMessageOut) -> Option<Vec<u8>> {
    let protocol = wire(msg).try_into_protocol_message().expect("protocol message");
    match group.process_message(provider, protocol).expect("processed").into_content() {
        ProcessedMessageContent::ApplicationMessage(m) => Some(m.into_bytes()),
        ProcessedMessageContent::StagedCommitMessage(c) => {
            group.merge_staged_commit(provider, *c).expect("merged");
            None
        }
        other => panic!("unexpected content {other:?}"),
    }
}

fn exporter(group: &MlsGroup, provider: &CoreProvider) -> Vec<u8> {
    group.export_secret(provider.crypto(), "otrv4plus test", b"", 32).expect("export")
}

#[test]
fn three_members_add_message_update_remove() {
    let alice = Member::new("alice");
    let bob = Member::new("bob");
    let carol = Member::new("carol");

    let mut a = MlsGroup::new(&alice.provider, &alice.signer, &create_config(), alice.credential.clone())
        .expect("group");
    assert_eq!(a.ciphersuite(), CIPHERSUITE);

    // Alice adds Bob and Carol in one commit.
    let (_commit, welcome, _) = a
        .add_members(&alice.provider, &alice.signer, &[bob.key_package(), carol.key_package()])
        .expect("add");
    a.merge_pending_commit(&alice.provider).expect("merge");
    let mut b = join(&bob, &welcome);
    let mut c = join(&carol, &welcome);
    assert_eq!(a.members().count(), 3);
    assert_eq!(a.epoch(), b.epoch());
    assert_eq!(exporter(&a, &alice.provider), exporter(&b, &bob.provider));
    assert_eq!(exporter(&a, &alice.provider), exporter(&c, &carol.provider));

    // Everyone can talk to everyone.
    let m = a.create_message(&alice.provider, &alice.signer, b"hello from alice").unwrap();
    assert_eq!(receive(&mut b, &bob.provider, &m).unwrap(), b"hello from alice");
    assert_eq!(receive(&mut c, &carol.provider, &m).unwrap(), b"hello from alice");
    let m = c.create_message(&carol.provider, &carol.signer, b"carol here").unwrap();
    assert_eq!(receive(&mut a, &alice.provider, &m).unwrap(), b"carol here");
    assert_eq!(receive(&mut b, &bob.provider, &m).unwrap(), b"carol here");

    // Bob rotates his leaf key (post-compromise security): new epoch, new
    // secrets, still in agreement.
    let before = exporter(&a, &alice.provider);
    let (commit, _, _) = b
        .self_update(&bob.provider, &bob.signer, LeafNodeParameters::default())
        .expect("self update")
        .into_contents();
    b.merge_pending_commit(&bob.provider).unwrap();
    receive(&mut a, &alice.provider, &commit);
    receive(&mut c, &carol.provider, &commit);
    let after = exporter(&a, &alice.provider);
    assert_ne!(before, after);
    assert_eq!(after, exporter(&b, &bob.provider));
    assert_eq!(after, exporter(&c, &carol.provider));

    // Alice removes Carol. Carol learns she is out; the others move on to an
    // epoch whose secrets she does not have.
    let carol_leaf = c.own_leaf_index();
    let (commit, _, _) = a.remove_members(&alice.provider, &alice.signer, &[carol_leaf]).unwrap();
    a.merge_pending_commit(&alice.provider).unwrap();
    receive(&mut b, &bob.provider, &commit);
    receive(&mut c, &carol.provider, &commit);
    assert!(!c.is_active(), "a removed member's group is inactive");
    assert_eq!(a.members().count(), 2);
    assert!(c.export_secret(carol.provider.crypto(), "otrv4plus test", b"", 32).is_err(),
            "an evicted member has no group secrets to export");

    let m = a.create_message(&alice.provider, &alice.signer, b"after carol").unwrap();
    assert_eq!(receive(&mut b, &bob.provider, &m).unwrap(), b"after carol");
    let protocol = wire(&m).try_into_protocol_message().unwrap();
    assert!(c.process_message(&carol.provider, protocol).is_err(),
            "the removed member must not read the next epoch");
}

#[test]
fn a_tampered_message_is_rejected() {
    let alice = Member::new("alice");
    let bob = Member::new("bob");
    let mut a = MlsGroup::new(&alice.provider, &alice.signer, &create_config(), alice.credential.clone()).unwrap();
    let (_, welcome, _) = a.add_members(&alice.provider, &alice.signer, &[bob.key_package()]).unwrap();
    a.merge_pending_commit(&alice.provider).unwrap();
    let mut b = join(&bob, &welcome);

    let m = a.create_message(&alice.provider, &alice.signer, b"integrity").unwrap();
    let mut bytes = m.to_bytes().unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01; // inside the AEAD tag
    let protocol = MlsMessageIn::tls_deserialize_exact(bytes).unwrap()
        .try_into_protocol_message().unwrap();
    assert!(b.process_message(&bob.provider, protocol).is_err());
}

#[test]
fn only_the_pq_suite_is_served() {
    let p = CoreProvider::default();
    assert_eq!(p.crypto().supported_ciphersuites(), vec![CIPHERSUITE]);
    assert!(p.crypto().supports(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519).is_err());
    assert!(p.crypto().supports(Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87).is_err());
    assert!(p.crypto().hash(HashType::Sha2_256, b"x").is_err());
    assert!(p.crypto().signature_key_gen(SignatureScheme::ED25519).is_err());

    // A group cannot even be created on another suite.
    let alice = Member::new("alice");
    let other = MlsGroupCreateConfig::builder()
        .ciphersuite(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519)
        .build();
    assert!(MlsGroup::new(&alice.provider, &alice.signer, &other, alice.credential.clone()).is_err());
}

#[test]
fn signer_uses_ml_dsa_87() {
    let s = SignatureKeyPair::generate();
    assert_eq!(s.signature_scheme(), SignatureScheme::MLDSA87);
    assert_eq!(s.public().len(), otrv4_mls::provider::MLDSA87_PUBLIC_KEY_BYTES);
    let sig = s.sign(b"payload").unwrap();
    assert_eq!(sig.len(), otrv4_mls::provider::MLDSA87_SIGNATURE_BYTES);
    let crypto = otrv4_mls::CoreCrypto;
    crypto.verify_signature(SignatureScheme::MLDSA87, b"payload", s.public(), &sig).unwrap();
    assert!(crypto.verify_signature(SignatureScheme::MLDSA87, b"payloaD", s.public(), &sig).is_err());
    assert_eq!(format!("{s:?}"), "SignatureKeyPair { .. }", "Debug never prints key bytes");
}
