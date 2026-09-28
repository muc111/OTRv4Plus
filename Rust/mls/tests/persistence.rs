// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
//! Sealed MLS state: survives a restart, opens only under the right key and
//! account, refuses every alteration, and never carries readable secrets.

use otrv4_mls::{client::fingerprint, Event, MlsClient, MlsError};

const GROUP: &[u8] = b"secure-room@conference.example.i2p";
const DEK: [u8; 32] = [7u8; 32];
const CTX: &[u8] = b"alice@example.i2p";

fn relay(members: &mut [&mut MlsClient], msg: &[u8]) -> Vec<Result<Event, MlsError>> {
    members.iter_mut().map(|m| m.process(GROUP, msg)).collect()
}

fn text(ev: &Result<Event, MlsError>) -> Vec<u8> {
    match ev {
        Ok(Event::Application { plaintext, .. }) => plaintext.to_vec(),
        other => panic!("expected an application message, got {other:?}"),
    }
}

fn three() -> (MlsClient, MlsClient, MlsClient) {
    let mut alice = MlsClient::new(b"alice@example.i2p");
    let mut bob = MlsClient::new(b"bob@example.i2p");
    let mut carol = MlsClient::new(b"carol@example.i2p");
    alice.create_group(GROUP).unwrap();
    let kps = vec![bob.key_package().unwrap(), carol.key_package().unwrap()];
    let commit = alice.add_members(GROUP, &kps).unwrap();
    let welcome = match alice.process(GROUP, &commit).unwrap() {
        Event::Commit { ours: true, welcome: Some(w), .. } => w,
        other => panic!("{other:?}"),
    };
    bob.join(&welcome).unwrap();
    carol.join(&welcome).unwrap();
    (alice, bob, carol)
}

fn reload(c: &MlsClient) -> MlsClient {
    let blob = c.export_sealed(&DEK, CTX).unwrap();
    MlsClient::import_sealed(&DEK, CTX, &blob).unwrap()
}

#[test]
fn a_reloaded_member_keeps_talking_both_ways() {
    let (a, mut b, mut c) = three();
    let m0 = a.export_sealed(&DEK, CTX).unwrap();
    drop(a);                                   // the process exits
    let mut a = MlsClient::import_sealed(&DEK, CTX, &m0).unwrap();
    assert_eq!(a.members(GROUP).unwrap().len(), 3);
    assert_eq!(a.epoch(GROUP).unwrap(), b.epoch(GROUP).unwrap());

    let m = a.encrypt(GROUP, b"back after restart").unwrap();
    let evs = relay(&mut [&mut b, &mut c], &m);
    assert_eq!(text(&evs[0]), b"back after restart");
    let m = b.encrypt(GROUP, b"welcome back").unwrap();
    assert_eq!(text(&a.process(GROUP, &m)), b"welcome back");

    // Epochs keep moving after the reload.
    let commit = c.self_update(GROUP).unwrap();
    relay(&mut [&mut a, &mut b, &mut c], &commit);
    let m = a.encrypt(GROUP, b"next epoch").unwrap();
    assert_eq!(text(&c.process(GROUP, &m)), b"next epoch");
}

#[test]
fn a_commit_pending_at_restart_still_resolves_when_the_room_echoes_it() {
    let (mut a, mut b, mut c) = three();
    let commit = a.self_update(GROUP).unwrap();
    let mut a = reload(&a);
    assert!(a.has_pending_commit(GROUP));
    let evs = relay(&mut [&mut a, &mut b, &mut c], &commit);
    assert!(matches!(evs[0], Ok(Event::Commit { ours: true, .. })), "{:?}", evs[0]);
    assert_eq!(a.epoch(GROUP).unwrap(), b.epoch(GROUP).unwrap());
    let m = a.encrypt(GROUP, b"after").unwrap();
    assert_eq!(text(&b.process(GROUP, &m)), b"after");
}

#[test]
fn the_blob_opens_only_under_its_key_and_account() {
    let (a, _b, _c) = three();
    let blob = a.export_sealed(&DEK, CTX).unwrap();
    assert!(MlsClient::import_sealed(&[8u8; 32], CTX, &blob).is_err(), "wrong key opened it");
    assert!(MlsClient::import_sealed(&DEK, b"mallory@example.i2p", &blob).is_err(),
            "another account's context opened it");
    assert!(MlsClient::import_sealed(&[7u8; 16], CTX, &blob).is_err());
}

#[test]
fn every_alteration_is_refused() {
    let (a, _b, _c) = three();
    let blob = a.export_sealed(&DEK, CTX).unwrap();
    // Every region: magic, version, nonce, body, tag.
    for i in [0usize, 4, 5, 16, 17, blob.len() / 2, blob.len() - 1] {
        let mut bad = blob.clone();
        bad[i] ^= 0x01;
        assert!(MlsClient::import_sealed(&DEK, CTX, &bad).is_err(), "flip at {i} accepted");
    }
    for cut in [0usize, 4, 17, 32, blob.len() - 1] {
        assert!(MlsClient::import_sealed(&DEK, CTX, &blob[..cut]).is_err(), "truncated to {cut}");
    }
    let mut longer = blob.clone();
    longer.push(0);
    assert!(MlsClient::import_sealed(&DEK, CTX, &longer).is_err());
}

#[test]
fn nothing_readable_is_in_the_blob() {
    let (a, _b, _c) = three();
    let blob = a.export_sealed(&DEK, CTX).unwrap();
    for needle in [&b"alice@example.i2p"[..], b"secure-room", b"GroupState", b"EpochSecrets",
                   b"MessageSecrets", b"SignatureKeyPair"] {
        assert!(!blob.windows(needle.len()).any(|w| w == needle),
                "{:?} readable in the sealed blob", String::from_utf8_lossy(needle));
    }
    // Two seals of the same state differ (fresh nonce).
    assert_ne!(blob, a.export_sealed(&DEK, CTX).unwrap());
}

#[test]
fn a_wiped_client_cannot_be_sealed() {
    let (mut a, _b, _c) = three();
    a.wipe();
    assert_eq!(a.export_sealed(&DEK, CTX), Err(MlsError::Wiped));
}

#[test]
fn a_removed_member_holding_an_old_copy_cannot_read_what_follows() {
    let (mut a, mut b, mut c) = three();
    // Carol keeps a sealed copy of her state from before her removal.
    let carol_copy = c.export_sealed(&DEK, b"carol").unwrap();
    let commit = a.remove_members(GROUP, &[b"carol@example.i2p".to_vec()]).unwrap();
    relay(&mut [&mut a, &mut b, &mut c], &commit);
    let secret = a.encrypt(GROUP, b"after carol left").unwrap();
    let mut old = MlsClient::import_sealed(&DEK, b"carol", &carol_copy).unwrap();
    assert!(old.process(GROUP, &secret).is_err(), "a removed member decrypted a later message");
    assert_eq!(text(&b.process(GROUP, &secret)), b"after carol left");
}

#[test]
fn restoring_a_stale_snapshot_does_not_decrypt_later_epochs() {
    let (mut a, mut b, mut c) = three();
    let stale = b.export_sealed(&DEK, b"bob").unwrap();
    let commit = c.self_update(GROUP).unwrap();
    relay(&mut [&mut a, &mut b, &mut c], &commit);
    let m = a.encrypt(GROUP, b"epoch two").unwrap();
    let mut rolled_back = MlsClient::import_sealed(&DEK, b"bob", &stale).unwrap();
    assert!(rolled_back.process(GROUP, &m).is_err(), "a rolled-back member read a newer epoch");
}

#[test]
fn fingerprints_bind_a_member_to_the_key_they_hold() {
    let (mut a, b, c) = three();
    assert_eq!(a.member_fingerprint(GROUP, b"bob@example.i2p").unwrap(), b.own_fingerprint());
    assert_eq!(a.member_fingerprint(GROUP, b"carol@example.i2p").unwrap(), c.own_fingerprint());
    assert_ne!(b.own_fingerprint(), c.own_fingerprint());
    assert_eq!(a.own_fingerprint().len(), 48);
    assert_eq!(a.member_fingerprint(GROUP, b"nobody"), Err(MlsError::NoSuchMember));
    // A reload keeps the same signing identity.
    let r = reload(&a);
    assert_eq!(r.own_fingerprint(), a.own_fingerprint());
    // A fresh client with the same name is a different key: a name alone
    // proves nothing, which is why the fingerprint is what gets verified.
    let impostor = MlsClient::new(b"bob@example.i2p");
    assert_ne!(impostor.own_fingerprint(), b.own_fingerprint());
    assert_eq!(fingerprint(b"x").len(), 48);
}
