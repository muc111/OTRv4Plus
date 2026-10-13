// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
//! Signing keys (MLS_SECURITY_HARDENING.md §1, commit M2): one per group,
//! replaced by every self-update, reported to the other members as a
//! rotation they can carry a binding across, and gone with the group.

use otrv4_mls::{client::fingerprint, Event, MlsClient, MlsError};

const G1: &[u8] = b"one@conference.example.i2p";
const G2: &[u8] = b"two@conference.example.i2p";

fn welcome_of(ev: Result<Event, MlsError>) -> Vec<u8> {
    match ev {
        Ok(Event::Commit { ours: true, welcome: Some(w), .. }) => w,
        other => panic!("expected our add to land, got {other:?}"),
    }
}

/// Alice and Bob in group `g`, Alice its creator.
fn pair_in(a: &mut MlsClient, b: &mut MlsClient, g: &[u8]) {
    a.create_group(g).unwrap();
    let commit = a.add_members(g, &[b.key_package().unwrap()]).unwrap();
    let w = welcome_of(a.process(g, &commit));
    assert_eq!(b.join(&w).unwrap(), g);
}

#[test]
fn every_group_has_its_own_key() {
    let mut a = MlsClient::new(b"alice");
    let mut b = MlsClient::new(b"bob");
    pair_in(&mut a, &mut b, G1);
    pair_in(&mut a, &mut b, G2);
    assert_ne!(a.own_fingerprint(G1).unwrap(), a.own_fingerprint(G2).unwrap());
    assert_ne!(b.own_fingerprint(G1).unwrap(), b.own_fingerprint(G2).unwrap());
    // What the other member holds is that group's key, not another's.
    assert_eq!(a.member_fingerprint(G1, b"bob").unwrap(), b.own_fingerprint(G1).unwrap());
    assert_eq!(a.member_fingerprint(G2, b"bob").unwrap(), b.own_fingerprint(G2).unwrap());
}

#[test]
fn a_self_update_rotates_the_key_and_says_so() {
    let mut a = MlsClient::new(b"alice");
    let mut b = MlsClient::new(b"bob");
    pair_in(&mut a, &mut b, G1);
    let old = a.own_fingerprint(G1).unwrap();
    let commit = a.self_update(G1).unwrap();
    // Until the room shows it landed, the old key is still ours.
    assert_eq!(a.own_fingerprint(G1).unwrap(), old);
    let new = match a.process(G1, &commit).unwrap() {
        Event::Commit { ours: true, committer, rekeyed, .. } => {
            assert_eq!(committer, b"alice");
            assert_eq!(rekeyed.len(), 1);
            rekeyed[0].2.clone()
        }
        other => panic!("{other:?}"),
    };
    assert_ne!(new, old);
    assert_eq!(a.own_fingerprint(G1).unwrap(), new);
    match b.process(G1, &commit).unwrap() {
        Event::Commit { ours: false, committer, rekeyed, .. } => {
            assert_eq!(committer, b"alice");
            assert_eq!(rekeyed, vec![(b"alice".to_vec(), old.clone(), new.clone())]);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(b.member_fingerprint(G1, b"alice").unwrap(), new);
    // Messages are signed (and verified) with the new key from now on.
    let m = a.encrypt(G1, b"after rotation").unwrap();
    assert!(matches!(b.process(G1, &m).unwrap(), Event::Application { .. }));
}

#[test]
fn a_lost_self_update_keeps_the_old_key() {
    let mut a = MlsClient::new(b"alice");
    let mut b = MlsClient::new(b"bob");
    pair_in(&mut a, &mut b, G1);
    let old = a.own_fingerprint(G1).unwrap();
    let mine = a.self_update(G1).unwrap();
    let theirs = b.self_update(G1).unwrap();
    // The room put Bob's first: Alice's can never apply.
    match a.process(G1, &theirs).unwrap() {
        Event::Commit { dropped_ours: true, committer, rekeyed, .. } => {
            assert_eq!(committer, b"bob");
            assert_eq!(rekeyed.len(), 1);
            assert_eq!(rekeyed[0].0, b"bob");
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(b.process(G1, &theirs).unwrap(), Event::Commit { ours: true, .. }));
    assert!(a.process(G1, &mine).is_err());
    assert_eq!(a.own_fingerprint(G1).unwrap(), old);
    assert_eq!(b.member_fingerprint(G1, b"alice").unwrap(), old);
    let m = a.encrypt(G1, b"still the old key").unwrap();
    assert!(matches!(b.process(G1, &m).unwrap(), Event::Application { .. }));
}

#[test]
fn an_add_or_remove_is_not_a_rotation() {
    let mut a = MlsClient::new(b"alice");
    let mut b = MlsClient::new(b"bob");
    let mut c = MlsClient::new(b"carol");
    pair_in(&mut a, &mut b, G1);
    let add = a.add_members(G1, &[c.key_package().unwrap()]).unwrap();
    let w = welcome_of(a.process(G1, &add));
    // Alice's add-commit refreshes her HPKE path but not her signing key.
    match b.process(G1, &add).unwrap() {
        Event::Commit { committer, rekeyed, .. } => {
            assert_eq!(committer, b"alice");
            assert!(rekeyed.is_empty(), "{rekeyed:?}");
        }
        other => panic!("{other:?}"),
    }
    c.join(&w).unwrap();
    // Bob removes Carol, then a NEW "carol" (another key) is added: a new
    // member under an old name, never reported as Carol's rotation.
    let rm = b.remove_members(G1, &[b"carol".to_vec()]).unwrap();
    assert!(matches!(b.process(G1, &rm).unwrap(), Event::Commit { ours: true, .. }));
    match a.process(G1, &rm).unwrap() {
        Event::Commit { committer, rekeyed, .. } => {
            assert_eq!(committer, b"bob");
            assert!(rekeyed.is_empty());
        }
        other => panic!("{other:?}"),
    }
    let mut impostor = MlsClient::new(b"carol");
    let add = b.add_members(G1, &[impostor.key_package().unwrap()]).unwrap();
    let w = welcome_of(b.process(G1, &add));
    match a.process(G1, &add).unwrap() {
        Event::Commit { rekeyed, .. } => assert!(rekeyed.is_empty()),
        other => panic!("{other:?}"),
    }
    impostor.join(&w).unwrap();
    assert_ne!(a.member_fingerprint(G1, b"carol").unwrap(), c.own_fingerprint(G1).unwrap_or_default());
}

#[test]
fn forgetting_a_group_forgets_its_key() {
    let mut a = MlsClient::new(b"alice");
    let mut b = MlsClient::new(b"bob");
    pair_in(&mut a, &mut b, G1);
    a.forget_group(G1);
    assert_eq!(a.own_fingerprint(G1), Err(MlsError::NoSuchGroup));
    // A Welcome made from a KeyPackage we no longer hold the key for is refused.
    let mut c = MlsClient::new(b"carol");
    c.create_group(G2).unwrap();
    let kp = b.key_package().unwrap();
    for _ in 0..20 {
        b.key_package().unwrap();          // the first is pushed out (16 kept)
    }
    let add = c.add_members(G2, &[kp]).unwrap();
    let w = welcome_of(c.process(G2, &add));
    assert!(matches!(b.join(&w), Err(MlsError::Refused(_))));
    assert!(!b.has_group(G2));
    assert_eq!(fingerprint(b"").len(), 48);
}

#[test]
fn group_voice_keys_come_from_the_epoch_and_follow_it() {
    use otrv4_mls::group_voice::VoiceError;
    let mut a = MlsClient::new(b"alice");
    let mut b = MlsClient::new(b"bob");
    pair_in(&mut a, &mut b, G1);
    let mut va = a.group_voice(G1, b"call").unwrap();
    let mut vb = b.group_voice(G1, b"call").unwrap();
    let p = va.seal(b"hello").unwrap();
    let (sender, frame) = vb.open(&p).unwrap();
    assert_eq!(&frame[..], b"hello");
    assert_eq!(b.member_at(G1, sender).unwrap(), b"alice");
    // An outsider with the same call id has no key.
    let mut c = MlsClient::new(b"carol");
    c.create_group(G1).unwrap();
    let mut vc = c.group_voice(G1, b"call").unwrap();
    assert!(vc.open(&p).is_err());
    // A commit (here a rekey) moves the call to the new epoch's keys.
    let commit = a.self_update(G1).unwrap();
    a.process(G1, &commit).unwrap();
    b.process(G1, &commit).unwrap();
    assert!(a.group_voice_rekey(G1, b"call", &mut va).unwrap());
    assert!(b.group_voice_rekey(G1, b"call", &mut vb).unwrap());
    assert!(!b.group_voice_rekey(G1, b"call", &mut vb).unwrap());
    let q = va.seal(b"new epoch").unwrap();
    assert_eq!(&vb.open(&q).unwrap().1[..], b"new epoch");
    vb.drop_previous();
    assert_eq!(vb.open(&p).unwrap_err(), VoiceError::WrongEpoch);
}

#[test]
fn a_member_who_lost_their_state_is_replaced_not_duplicated() {
    // Alice, Bob and Carol; Alice wipes her device and is invited again.
    let mut a = MlsClient::new(b"alice");
    let mut b = MlsClient::new(b"bob");
    let mut c = MlsClient::new(b"carol");
    pair_in(&mut b, &mut c, G1);
    let commit = b.add_members(G1, &[a.key_package().unwrap()]).unwrap();
    let w = welcome_of(b.process(G1, &commit));
    c.process(G1, &commit).unwrap();
    a.join(&w).unwrap();
    let old = b.member_fingerprint(G1, b"alice").unwrap();

    let mut a2 = MlsClient::new(b"alice");             // after the wipe
    let commit = b.add_members(G1, &[a2.key_package().unwrap()]).unwrap();
    let w = welcome_of(b.process(G1, &commit));
    assert!(matches!(c.process(G1, &commit).unwrap(), Event::Commit { .. }));
    a2.join(&w).unwrap();

    for m in [&mut b, &mut c, &mut a2] {
        let alices = m.members(G1).unwrap().iter().filter(|x| x.as_slice() == b"alice").count();
        assert_eq!(alices, 1, "exactly one leaf for alice");
        assert_eq!(m.members(G1).unwrap().len(), 3);
    }
    assert_ne!(b.member_fingerprint(G1, b"alice").unwrap(), old);
    // The new Alice reads and is read; the old leaf's holder is out.
    let m = a2.encrypt(G1, b"back again").unwrap();
    assert!(matches!(c.process(G1, &m).unwrap(), Event::Application { .. }));
    let m = c.encrypt(G1, b"welcome back").unwrap();
    assert!(matches!(a2.process(G1, &m).unwrap(), Event::Application { .. }));
    assert!(a.process(G1, &m).is_err(), "the wiped leaf cannot read the new epoch");
}

#[test]
fn our_own_identity_is_never_added() {
    let mut a = MlsClient::new(b"alice");
    let mut a2 = MlsClient::new(b"alice");
    a.create_group(G1).unwrap();
    assert!(a.add_members(G1, &[a2.key_package().unwrap()]).is_err());
}
