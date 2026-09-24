// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
//! One user's MLS state: identity, signing key, groups, storage.
//!
//! This is the whole security surface of OTRv4Plus group chat. Callers --
//! the Python transport, via `otrv4_core` -- hand in wire bytes and a group
//! id and get back wire bytes, plaintext and public facts (members, epoch).
//! No key, secret, tree or storage entry leaves this struct.
//!
//! COMMIT ORDER: THE ROOM DECIDES
//! ==============================
//! Two members may commit in the same epoch; if each merged its own at once
//! the group would fork. So a commit is never merged when it is made. It is
//! held as pending and sent to the room; the XMPP room relays messages to
//! every occupant, the sender included, in one order. When a commit for our
//! epoch arrives:
//!   * if it is byte-for-byte our pending commit, ours came first: merge it;
//!   * otherwise someone else's came first: drop ours and apply theirs.
//! Every member sees the same first commit, so every member ends in the same
//! epoch. A dropped commit is reported so the caller can retry.
//!
//! What this does NOT decide: application messages sent in an epoch that a
//! commit then closes are unreadable after it (OpenMLS keeps no past-epoch
//! secrets), and messages are only as available as the room delivers them.

use std::collections::HashMap;

use openmls::prelude::{tls_codec::*, *};
use zeroize::Zeroizing;

use crate::provider::{CoreProvider, SignatureKeyPair, CIPHERSUITE};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MlsError {
    #[error("this MLS state was wiped")]
    Wiped,
    #[error("no such group")]
    NoSuchGroup,
    #[error("a group with that id already exists")]
    GroupExists,
    #[error("a commit is already pending in this group")]
    CommitPending,
    #[error("no member with that identity")]
    NoSuchMember,
    #[error("malformed message")]
    Malformed,
    #[error("message refused: {0}")]
    Refused(&'static str),
    #[error("MLS operation failed: {0}")]
    Failed(&'static str),
}

pub type Result<T> = std::result::Result<T, MlsError>;

/// What a processed message was.
#[derive(Debug)]
pub enum Event {
    /// A group message: the sender's identity (their credential) and text.
    Application { sender: Vec<u8>, plaintext: Zeroizing<Vec<u8>> },
    /// A commit moved the group to `epoch`. `welcome` is set when it was our
    /// own add-commit that won: the caller now delivers it to the invitees.
    Commit { epoch: u64, ours: bool, welcome: Option<Vec<u8>>, removed_us: bool,
             dropped_ours: bool },
    /// A standalone proposal was queued (not used by this client, accepted).
    Proposal,
}

struct Pending {
    commit: Vec<u8>,
    welcome: Option<Vec<u8>>,
}

pub struct MlsClient {
    identity: Vec<u8>,
    provider: CoreProvider,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
    groups: HashMap<Vec<u8>, MlsGroup>,
    pending: HashMap<Vec<u8>, Pending>,
    wiped: bool,
}

fn create_config() -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        // Handshake messages are encrypted too: the room sees ciphertext only.
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .build()
}

fn join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .build()
}

fn out_bytes(msg: &MlsMessageOut) -> Result<Vec<u8>> {
    msg.to_bytes().map_err(|_| MlsError::Failed("serialise"))
}

fn identity_of(credential: &Credential) -> Vec<u8> {
    BasicCredential::try_from(credential.clone())
        .map(|c| c.identity().to_vec())
        .unwrap_or_default()
}

impl MlsClient {
    /// A fresh MLS identity: `identity` is what other members see (the bare
    /// JID). The ML-DSA-87 signing key is generated here and never leaves.
    pub fn new(identity: &[u8]) -> Self {
        let signer = SignatureKeyPair::generate();
        let credential = CredentialWithKey {
            credential: BasicCredential::new(identity.to_vec()).into(),
            signature_key: signer.public().to_vec().into(),
        };
        Self {
            identity: identity.to_vec(),
            provider: CoreProvider::default(),
            signer,
            credential,
            groups: HashMap::new(),
            pending: HashMap::new(),
            wiped: false,
        }
    }

    fn live(&self) -> Result<()> {
        if self.wiped { Err(MlsError::Wiped) } else { Ok(()) }
    }

    fn group(&mut self, id: &[u8]) -> Result<&mut MlsGroup> {
        self.live()?;
        self.groups.get_mut(id).ok_or(MlsError::NoSuchGroup)
    }

    pub fn identity(&self) -> &[u8] { &self.identity }

    /// A KeyPackage (public: lets someone add us to a group), as MLS wire
    /// bytes. Its private half stays in this client's storage.
    pub fn key_package(&mut self) -> Result<Vec<u8>> {
        self.live()?;
        let bundle = KeyPackage::builder()
            .build(CIPHERSUITE, &self.provider, &self.signer, self.credential.clone())
            .map_err(|_| MlsError::Failed("key package"))?;
        let msg: MlsMessageOut = bundle.key_package().clone().into();
        out_bytes(&msg)
    }

    pub fn create_group(&mut self, group_id: &[u8]) -> Result<()> {
        self.live()?;
        if self.groups.contains_key(group_id) {
            return Err(MlsError::GroupExists);
        }
        let group = MlsGroup::new_with_group_id(
            &self.provider, &self.signer, &create_config(),
            GroupId::from_slice(group_id), self.credential.clone(),
        ).map_err(|_| MlsError::Failed("create group"))?;
        self.groups.insert(group_id.to_vec(), group);
        Ok(())
    }

    pub fn has_group(&self, group_id: &[u8]) -> bool {
        !self.wiped && self.groups.contains_key(group_id)
    }

    pub fn group_ids(&self) -> Vec<Vec<u8>> {
        if self.wiped { return vec![]; }
        let mut ids: Vec<_> = self.groups.keys().cloned().collect();
        ids.sort();
        ids
    }

    pub fn epoch(&mut self, group_id: &[u8]) -> Result<u64> {
        Ok(self.group(group_id)?.epoch().as_u64())
    }

    /// Members' identities, sorted.
    pub fn members(&mut self, group_id: &[u8]) -> Result<Vec<Vec<u8>>> {
        let mut out: Vec<_> = self.group(group_id)?.members()
            .map(|m| identity_of(&m.credential)).collect();
        out.sort();
        Ok(out)
    }

    pub fn has_pending_commit(&self, group_id: &[u8]) -> bool {
        self.pending.contains_key(group_id)
    }

    fn hold(&mut self, group_id: &[u8], commit: Vec<u8>, welcome: Option<Vec<u8>>)
        -> Result<Vec<u8>>
    {
        self.pending.insert(group_id.to_vec(), Pending { commit: commit.clone(), welcome });
        Ok(commit)
    }

    fn refuse_if_pending(&self, group_id: &[u8]) -> Result<()> {
        if self.pending.contains_key(group_id) { Err(MlsError::CommitPending) } else { Ok(()) }
    }

    /// Commit adding the members whose KeyPackages (MLS wire bytes) are
    /// given. Returns the commit to send to the room; the Welcome is released
    /// by `process` once the room shows our commit won.
    pub fn add_members(&mut self, group_id: &[u8], key_packages: &[Vec<u8>]) -> Result<Vec<u8>> {
        self.live()?;
        self.refuse_if_pending(group_id)?;
        let mut kps = Vec::with_capacity(key_packages.len());
        for bytes in key_packages {
            let msg = MlsMessageIn::tls_deserialize_exact(bytes.as_slice())
                .map_err(|_| MlsError::Malformed)?;
            let kp_in = match msg.extract() {
                MlsMessageBodyIn::KeyPackage(kp) => kp,
                _ => return Err(MlsError::Malformed),
            };
            let kp = kp_in.validate(self.provider.crypto(), ProtocolVersion::Mls10)
                .map_err(|_| MlsError::Refused("invalid key package"))?;
            if kp.ciphersuite() != CIPHERSUITE {
                return Err(MlsError::Refused("key package for another ciphersuite"));
            }
            kps.push(kp);
        }
        let (provider, signer) = (&self.provider, &self.signer);
        let group = self.groups.get_mut(group_id).ok_or(MlsError::NoSuchGroup)?;
        let (commit, welcome, _) = group.add_members(provider, signer, &kps)
            .map_err(|_| MlsError::Failed("add members"))?;
        let (c, w) = (out_bytes(&commit)?, out_bytes(&welcome)?);
        self.hold(group_id, c, Some(w))
    }

    /// Commit removing the members with these identities.
    pub fn remove_members(&mut self, group_id: &[u8], identities: &[Vec<u8>]) -> Result<Vec<u8>> {
        self.live()?;
        self.refuse_if_pending(group_id)?;
        let (provider, signer) = (&self.provider, &self.signer);
        let group = self.groups.get_mut(group_id).ok_or(MlsError::NoSuchGroup)?;
        let mut leaves = Vec::new();
        for id in identities {
            let leaf = group.members()
                .find(|m| &identity_of(&m.credential) == id)
                .ok_or(MlsError::NoSuchMember)?.index;
            leaves.push(leaf);
        }
        let (commit, _, _) = group.remove_members(provider, signer, &leaves)
            .map_err(|_| MlsError::Failed("remove members"))?;
        let c = out_bytes(&commit)?;
        self.hold(group_id, c, None)
    }

    /// Commit a fresh leaf key for ourselves (post-compromise security).
    pub fn self_update(&mut self, group_id: &[u8]) -> Result<Vec<u8>> {
        self.live()?;
        self.refuse_if_pending(group_id)?;
        let (provider, signer) = (&self.provider, &self.signer);
        let group = self.groups.get_mut(group_id).ok_or(MlsError::NoSuchGroup)?;
        let (commit, _, _) = group.self_update(provider, signer, LeafNodeParameters::default())
            .map_err(|_| MlsError::Failed("self update"))?
            .into_contents();
        let c = out_bytes(&commit)?;
        self.hold(group_id, c, None)
    }

    /// Join from a Welcome (MLS wire bytes). Returns the group id.
    pub fn join(&mut self, welcome: &[u8]) -> Result<Vec<u8>> {
        self.live()?;
        let msg = MlsMessageIn::tls_deserialize_exact(welcome).map_err(|_| MlsError::Malformed)?;
        let welcome = match msg.extract() {
            MlsMessageBodyIn::Welcome(w) => w,
            _ => return Err(MlsError::Malformed),
        };
        let group = StagedWelcome::new_from_welcome(&self.provider, &join_config(), welcome, None)
            .map_err(|_| MlsError::Refused("welcome not for us or invalid"))?
            .into_group(&self.provider)
            .map_err(|_| MlsError::Failed("join"))?;
        if group.ciphersuite() != CIPHERSUITE {
            return Err(MlsError::Refused("group uses another ciphersuite"));
        }
        let id = group.group_id().as_slice().to_vec();
        if self.groups.contains_key(&id) {
            return Err(MlsError::GroupExists);
        }
        self.groups.insert(id.clone(), group);
        Ok(id)
    }

    /// Encrypt a group message. Refused while one of our commits is pending:
    /// if it wins, the message would be in a closed epoch.
    pub fn encrypt(&mut self, group_id: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        self.live()?;
        self.refuse_if_pending(group_id)?;
        let (provider, signer) = (&self.provider, &self.signer);
        let group = self.groups.get_mut(group_id).ok_or(MlsError::NoSuchGroup)?;
        let msg = group.create_message(provider, signer, plaintext)
            .map_err(|_| MlsError::Failed("encrypt"))?;
        out_bytes(&msg)
    }

    /// Process one message received from the room, in room order.
    pub fn process(&mut self, group_id: &[u8], message: &[u8]) -> Result<Event> {
        self.live()?;
        if !self.groups.contains_key(group_id) {
            return Err(MlsError::NoSuchGroup);
        }
        // Our own commit, relayed back first: it won the epoch.
        if let Some(p) = self.pending.get(group_id) {
            if p.commit.as_slice() == message {
                let p = self.pending.remove(group_id).expect("present");
                let provider = &self.provider;
                let group = self.groups.get_mut(group_id).expect("present");
                group.merge_pending_commit(provider)
                    .map_err(|_| MlsError::Failed("merge own commit"))?;
                return Ok(Event::Commit { epoch: group.epoch().as_u64(), ours: true,
                                          welcome: p.welcome, removed_us: false,
                                          dropped_ours: false });
            }
        }

        let msg = MlsMessageIn::tls_deserialize_exact(message).map_err(|_| MlsError::Malformed)?;
        let protocol = msg.try_into_protocol_message().map_err(|_| MlsError::Malformed)?;
        if protocol.group_id().as_slice() != group_id {
            return Err(MlsError::Refused("message for another group"));
        }
        let provider = &self.provider;
        let group = self.groups.get_mut(group_id).expect("present");
        let processed = group.process_message(provider, protocol)
            .map_err(|_| MlsError::Refused("did not authenticate, replayed, or wrong epoch"))?;
        let sender = identity_of(processed.credential());
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(m) => {
                Ok(Event::Application { sender, plaintext: Zeroizing::new(m.into_bytes()) })
            }
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                let removed_us = staged.self_removed();
                // Someone else's commit came first: ours can never apply.
                let dropped_ours = self.pending.remove(group_id).is_some();
                if dropped_ours {
                    group.clear_pending_commit(provider.storage())
                        .map_err(|_| MlsError::Failed("clear pending commit"))?;
                }
                group.merge_staged_commit(provider, *staged)
                    .map_err(|_| MlsError::Failed("merge commit"))?;
                let epoch = group.epoch().as_u64();
                if removed_us {
                    self.forget_group(group_id);
                }
                Ok(Event::Commit { epoch, ours: false, welcome: None, removed_us, dropped_ours })
            }
            ProcessedMessageContent::ProposalMessage(p) => {
                group.store_pending_proposal(provider.storage(), *p)
                    .map_err(|_| MlsError::Failed("store proposal"))?;
                Ok(Event::Proposal)
            }
            _ => Err(MlsError::Refused("unsupported message")),
        }
    }

    /// Drop a group and every secret it holds (we left, or were removed).
    pub fn forget_group(&mut self, group_id: &[u8]) {
        self.pending.remove(group_id);
        if let Some(mut group) = self.groups.remove(group_id) {
            let _ = group.delete(self.provider.storage());
        }
    }

    /// Wipe & Exit: destroy every group, pending commit, secret and the
    /// signing key. The client refuses all further use.
    pub fn wipe(&mut self) {
        self.pending.clear();
        self.groups.clear();          // OpenMLS secrets zeroize on drop
        self.provider.wipe();         // every stored entry, zeroized
        self.signer = SignatureKeyPair::generate(); // the old key is dropped (wiped)
        self.wiped = true;
    }

    pub fn is_wiped(&self) -> bool { self.wiped }

    /// Entries in storage (tests: proves the wipe emptied it).
    pub fn stored_entries(&self) -> usize { self.provider.stored_entries() }
}

impl Drop for MlsClient {
    fn drop(&mut self) { self.wipe(); }
}

#[cfg(test)]
mod storage_tests {
    use super::*;

    /// The store OpenMLS writes group secrets into holds CBOR, never JSON,
    /// and the wipe leaves nothing.
    #[test]
    fn stored_state_is_binary_and_wiped() {
        let mut a = MlsClient::new(b"alice");
        let mut b = MlsClient::new(b"bob");
        a.create_group(b"g").unwrap();
        let c = a.add_members(b"g", &[b.key_package().unwrap()]).unwrap();
        a.process(b"g", &c).unwrap();
        let _ = a.encrypt(b"g", b"x").unwrap();
        let values = a.provider.storage_values_for_test();
        assert!(values.len() > 5, "expected group state in storage");
        for v in &values {
            let first = v.first().copied().unwrap_or(0);
            assert!(!matches!(first, b'{' | b'[' | b'"'), "JSON-looking value in storage");
            assert!(std::str::from_utf8(v).map(|t| !t.contains("\"secret\"")).unwrap_or(true));
        }
        a.wipe();
        assert!(a.provider.storage_values_for_test().is_empty());
    }
}
