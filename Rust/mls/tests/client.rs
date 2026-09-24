// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
//! The MLS client over a simulated XMPP room: every message is relayed to
//! every member, the sender included, in one order -- which is what a MUC
//! does and what the commit-order rule relies on.

use otrv4_mls::{Event, MlsClient, MlsError};

const GROUP: &[u8] = b"secure-room@conference.example.i2p";

/// Relay one room message to every member in order; collect events.
fn relay(members: &mut [&mut MlsClient], msg: &[u8]) -> Vec<Result<Event, MlsError>> {
    members.iter_mut().map(|m| m.process(GROUP, msg)).collect()
}

fn text(ev: &Result<Event, MlsError>) -> (Vec<u8>, Vec<u8>) {
    match ev {
        Ok(Event::Application { sender, plaintext }) => (sender.clone(), plaintext.to_vec()),
        other => panic!("expected an application message, got {other:?}"),
    }
}

/// Alice creates the room's group and adds Bob and Carol through the room.
fn three() -> (MlsClient, MlsClient, MlsClient) {
    let mut alice = MlsClient::new(b"alice@example.i2p");
    let mut bob = MlsClient::new(b"bob@example.i2p");
    let mut carol = MlsClient::new(b"carol@example.i2p");
    alice.create_group(GROUP).unwrap();
    let kps = vec![bob.key_package().unwrap(), carol.key_package().unwrap()];
    let commit = alice.add_members(GROUP, &kps).unwrap();
    assert!(alice.has_pending_commit(GROUP));
    // The room relays the commit back to Alice: hers won, Welcome released.
    let welcome = match alice.process(GROUP, &commit).unwrap() {
        Event::Commit { ours: true, welcome: Some(w), .. } => w,
        other => panic!("{other:?}"),
    };
    assert_eq!(bob.join(&welcome).unwrap(), GROUP);
    assert_eq!(carol.join(&welcome).unwrap(), GROUP);
    (alice, bob, carol)
}

#[test]
fn three_members_talk_through_the_room() {
    let (mut a, mut b, mut c) = three();
    assert_eq!(a.members(GROUP).unwrap().len(), 3);
    assert_eq!(a.epoch(GROUP).unwrap(), b.epoch(GROUP).unwrap());
    let m = a.encrypt(GROUP, b"hello room").unwrap();
    assert!(!m.windows(10).any(|w| w == b"hello room"), "plaintext on the wire");
    let evs = relay(&mut [&mut b, &mut c], &m);
    assert_eq!(text(&evs[0]), (b"alice@example.i2p".to_vec(), b"hello room".to_vec()));
    assert_eq!(text(&evs[1]).1, b"hello room");
    let m = c.encrypt(GROUP, b"carol here").unwrap();
    let evs = relay(&mut [&mut a, &mut b], &m);
    assert_eq!(text(&evs[0]).0, b"carol@example.i2p");
    assert_eq!(text(&evs[1]).1, b"carol here");
}

#[test]
fn a_fourth_member_is_added_and_one_removed() {
    let (mut a, mut b, mut c) = three();
    let mut d = MlsClient::new(b"dave@example.i2p");
    let commit = b.add_members(GROUP, &[d.key_package().unwrap()]).unwrap();
    let evs = relay(&mut [&mut a, &mut b, &mut c], &commit);
    let welcome = match &evs[1] { Ok(Event::Commit { ours: true, welcome: Some(w), .. }) => w.clone(),
                                  other => panic!("{other:?}") };
    d.join(&welcome).unwrap();
    assert_eq!(d.members(GROUP).unwrap().len(), 4);

    // Alice removes Carol.
    let commit = a.remove_members(GROUP, &[b"carol@example.i2p".to_vec()]).unwrap();
    let evs = relay(&mut [&mut a, &mut b, &mut c, &mut d], &commit);
    assert!(matches!(evs[2], Ok(Event::Commit { removed_us: true, .. })));
    assert!(!c.has_group(GROUP), "the removed member forgets the group");
    let m = a.encrypt(GROUP, b"without carol").unwrap();
    assert!(c.process(GROUP, &m).is_err());
    let evs = relay(&mut [&mut b, &mut d], &m);
    assert_eq!(text(&evs[0]).1, b"without carol");
    assert_eq!(text(&evs[1]).1, b"without carol");
    assert_eq!(a.members(GROUP).unwrap(),
               vec![b"alice@example.i2p".to_vec(), b"bob@example.i2p".to_vec(),
                    b"dave@example.i2p".to_vec()]);
}

#[test]
fn replayed_tampered_and_stale_messages_are_refused() {
    let (mut a, mut b, mut c) = three();
    let m = a.encrypt(GROUP, b"once").unwrap();
    assert_eq!(text(&b.process(GROUP, &m)).1, b"once");
    assert!(b.process(GROUP, &m).is_err(), "replay accepted");

    let mut bad = a.encrypt(GROUP, b"tamper").unwrap();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    assert!(b.process(GROUP, &bad).is_err(), "tampered message accepted");

    // A message from the epoch before a commit is unreadable after it.
    let stale = a.encrypt(GROUP, b"old epoch").unwrap();
    let commit = c.self_update(GROUP).unwrap();
    relay(&mut [&mut a, &mut b, &mut c], &commit);
    assert!(b.process(GROUP, &stale).is_err(), "stale-epoch message accepted");
}

#[test]
fn concurrent_commits_resolve_by_room_order() {
    let (mut a, mut b, mut c) = three();
    // Alice and Bob both commit in the same epoch; the room carries Bob's first.
    let from_a = a.self_update(GROUP).unwrap();
    let from_b = b.self_update(GROUP).unwrap();
    let first = relay(&mut [&mut a, &mut b, &mut c], &from_b);
    assert!(matches!(first[0], Ok(Event::Commit { ours: false, dropped_ours: true, .. })));
    assert!(matches!(first[1], Ok(Event::Commit { ours: true, .. })));
    // Alice's commit arrives second, for a closed epoch: refused everywhere.
    for r in relay(&mut [&mut b, &mut c], &from_a) {
        assert!(r.is_err());
    }
    let epoch = a.epoch(GROUP).unwrap();
    assert_eq!(epoch, b.epoch(GROUP).unwrap());
    assert_eq!(epoch, c.epoch(GROUP).unwrap());
    // And the group still works.
    let m = a.encrypt(GROUP, b"converged").unwrap();
    assert_eq!(text(&c.process(GROUP, &m)).1, b"converged");
}

#[test]
fn sending_waits_for_a_pending_commit() {
    let (mut a, _b, _c) = three();
    a.self_update(GROUP).unwrap();
    assert_eq!(a.encrypt(GROUP, b"x"), Err(MlsError::CommitPending));
    assert_eq!(a.self_update(GROUP), Err(MlsError::CommitPending));
}

#[test]
fn a_welcome_for_someone_else_is_refused() {
    let mut a = MlsClient::new(b"alice@example.i2p");
    let mut b = MlsClient::new(b"bob@example.i2p");
    let mut eve = MlsClient::new(b"eve@example.i2p");
    a.create_group(GROUP).unwrap();
    let commit = a.add_members(GROUP, &[b.key_package().unwrap()]).unwrap();
    let welcome = match a.process(GROUP, &commit).unwrap() {
        Event::Commit { welcome: Some(w), .. } => w, other => panic!("{other:?}") };
    assert!(eve.join(&welcome).is_err());
    assert!(b.join(&welcome).is_ok());
}

#[test]
fn wipe_destroys_every_group_and_refuses_use() {
    let (mut a, mut b, _c) = three();
    let m = a.encrypt(GROUP, b"before").unwrap();
    assert!(a.stored_entries() > 0);
    a.wipe();
    assert!(a.is_wiped());
    assert_eq!(a.stored_entries(), 0, "storage survived the wipe");
    assert!(!a.has_group(GROUP));
    assert!(a.group_ids().is_empty());
    assert_eq!(a.encrypt(GROUP, b"after"), Err(MlsError::Wiped));
    assert_eq!(a.key_package(), Err(MlsError::Wiped));
    assert_eq!(a.create_group(b"new"), Err(MlsError::Wiped));
    // The others are unaffected.
    assert_eq!(text(&b.process(GROUP, &m)).1, b"before");
}

#[test]
fn messages_for_another_group_or_garbage_are_refused() {
    let (mut a, mut b, _c) = three();
    b.create_group(b"other-room").unwrap();
    let m = a.encrypt(GROUP, b"x").unwrap();
    assert!(b.process(b"other-room", &m).is_err());
    assert!(matches!(b.process(GROUP, b"not mls"), Err(MlsError::Malformed)));
    assert!(matches!(b.process(b"unknown", &m), Err(MlsError::NoSuchGroup)));
}
