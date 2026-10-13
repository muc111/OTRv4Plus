// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
//! One user's MLS state: identity, signing keys, groups, storage.
//!
//! SIGNING KEYS: ONE PER GROUP, ROTATED
//! ====================================
//! MLS signs every message with the sender leaf's signature key, and a
//! signature is evidence anyone can check (MLS_SECURITY_HARDENING.md §1). To
//! keep that evidence as narrow as RFC 9420 allows:
//!   * every group gets its own ML-DSA-87 key -- made for the KeyPackage that
//!     brought us in, or when we created the group -- so a member cannot be
//!     linked across groups by key;
//!   * every self-update replaces it (`self_update_with_new_signer`), so a
//!     key signs only until our next rekey; the old private key is dropped
//!     (zeroized) once the new one is in the group;
//!   * forgetting a group drops its key.
//!
//! A rotation is authenticated by the OLD key (the commit is signed with it),
//! so a member that had bound our old key over OTRv4+ carries the binding to
//! the new one: `Event::Commit::rekeyed`.
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
//!
//! Every member sees the same first commit, so every member ends in the same
//! epoch. A dropped commit is reported so the caller can retry.
//!
//! What this does NOT decide: application messages sent in an epoch that a
//! commit then closes are unreadable after it (OpenMLS keeps no past-epoch
//! secrets), and messages are only as available as the room delivers them.

use std::collections::HashMap;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use openmls::prelude::{tls_codec::*, *};

use sha2::{Digest, Sha384};
use zeroize::Zeroizing;

use crate::provider::{CoreProvider, SignatureKeyPair, CIPHERSUITE, LEGACY_CIPHERSUITE};

/// Sealed-state header: magic, then format version.
const STATE_MAGIC: &[u8; 4] = b"OMLS";
const STATE_VERSION: u8 = 2;
/// The format before per-group signing keys; still opened (and migrated).
const STATE_VERSION_1: u8 = 1;
/// KeyPackages we made and nobody has used yet: each holds its own key.
/// Older ones are forgotten (an invitation that old has expired anyway).
const MAX_KP_SIGNERS: usize = 16;
/// The caller's own state sealed alongside ours (bindings, pending work).
pub const MAX_APP_DATA: usize = 1 << 20;
const STATE_KDF_INFO: &[u8] = b"OTRv4Plus MLS sealed state v1";
/// Upper bound on a sealed blob we will try to open (64 MiB).
const STATE_MAX: usize = 64 << 20;

type SignerOut<'a> = (&'a serde_bytes::Bytes, &'a serde_bytes::Bytes);
type SignerIn = (serde_bytes::ByteBuf, serde_bytes::ByteBuf);

#[derive(serde::Serialize)]
struct StateOut<'a> {
    identity: &'a serde_bytes::Bytes,
    groups: Vec<&'a serde_bytes::Bytes>,
    /// (group, its signing key public, private)
    signers: Vec<(&'a serde_bytes::Bytes, &'a serde_bytes::Bytes, &'a serde_bytes::Bytes)>,
    kp_signers: Vec<SignerOut<'a>>,
    /// (group, commit, welcome, the key that commit rotates to)
    #[allow(clippy::type_complexity)]
    pending: Vec<(&'a serde_bytes::Bytes, &'a serde_bytes::Bytes,
                  Option<&'a serde_bytes::Bytes>, Option<SignerOut<'a>>)>,
    storage: &'a serde_bytes::Bytes,
    app_data: &'a serde_bytes::Bytes,
}

#[derive(serde::Deserialize)]
struct StateIn {
    identity: serde_bytes::ByteBuf,
    groups: Vec<serde_bytes::ByteBuf>,
    signers: Vec<(serde_bytes::ByteBuf, serde_bytes::ByteBuf, serde_bytes::ByteBuf)>,
    kp_signers: Vec<SignerIn>,
    #[allow(clippy::type_complexity)]
    pending: Vec<(serde_bytes::ByteBuf, serde_bytes::ByteBuf, Option<serde_bytes::ByteBuf>,
                  Option<SignerIn>)>,
    storage: serde_bytes::ByteBuf,
    app_data: serde_bytes::ByteBuf,
}

/// Version 1: one signing key for the whole client.
#[derive(serde::Deserialize)]
struct StateInV1 {
    identity: serde_bytes::ByteBuf,
    sig_pub: serde_bytes::ByteBuf,
    sig_sk: serde_bytes::ByteBuf,
    groups: Vec<serde_bytes::ByteBuf>,
    pending: Vec<(serde_bytes::ByteBuf, serde_bytes::ByteBuf, Option<serde_bytes::ByteBuf>)>,
    storage: serde_bytes::ByteBuf,
}

fn signer_out(s: &SignatureKeyPair) -> SignerOut<'_> {
    (serde_bytes::Bytes::new(s.public()), serde_bytes::Bytes::new(s.secret()))
}

fn signer_from(public: serde_bytes::ByteBuf, secret: serde_bytes::ByteBuf)
    -> Result<SignatureKeyPair>
{
    let secret = Zeroizing::new(secret.into_vec());
    SignatureKeyPair::from_parts(public.into_vec(), secret)
        .ok_or(MlsError::Refused("sealed MLS state has a bad signing key"))
}

/// The sealing key for MLS state, derived from the caller's data-encryption
/// key so that key is never used directly for two purposes.
fn state_key(dek: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    if dek.len() != 32 {
        return Err(MlsError::Failed("sealing key must be 32 bytes"));
    }
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, dek);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(STATE_KDF_INFO, &mut out[..]).map_err(|_| MlsError::Failed("kdf"))?;
    Ok(out)
}

fn state_aad(context: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(5 + context.len());
    aad.extend_from_slice(STATE_MAGIC);
    aad.push(STATE_VERSION);
    aad.extend_from_slice(context);
    aad
}

/// SHA-384 of an ML-DSA-87 signature public key: what a member's MLS
/// identity is compared by. Public, so it may be shown and sent.
pub fn fingerprint(signature_public_key: &[u8]) -> Vec<u8> {
    Sha384::digest(signature_public_key).to_vec()
}

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
    ///
    /// `committer` is the identity of the member whose commit it was (ours
    /// when `ours`). `rekeyed` lists members whose signature key this commit
    /// replaced by their own update -- authenticated by their old key -- as
    /// (identity, old fingerprint, new fingerprint). A leaf replaced any
    /// other way (removed, then someone added under the same name) is never
    /// listed: that is a new member, not a rotation.
    Commit { epoch: u64, ours: bool, welcome: Option<Vec<u8>>, removed_us: bool,
             dropped_ours: bool, committer: Vec<u8>,
             rekeyed: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> },
    /// A standalone proposal was queued (not used by this client, accepted).
    Proposal,
}

struct Pending {
    commit: Vec<u8>,
    welcome: Option<Vec<u8>>,
    /// A self-update's new signing key: ours once the commit lands.
    new_signer: Option<SignatureKeyPair>,
}

pub struct MlsClient {
    identity: Vec<u8>,
    provider: CoreProvider,
    /// group -> our leaf's signing key in it.
    signers: HashMap<Vec<u8>, SignatureKeyPair>,
    /// Keys of KeyPackages not yet used, oldest first.
    kp_signers: Vec<SignatureKeyPair>,
    groups: HashMap<Vec<u8>, MlsGroup>,
    pending: HashMap<Vec<u8>, Pending>,
    app_data: Zeroizing<Vec<u8>>,
    wiped: bool,
}

/// What our leaves say they support: the hybrid suite (every new group)
/// and the earlier PQ-only one (existing groups). The hybrid suite is a
/// private code point, so it is not in OpenMLS's default list and must be
/// declared, or OpenMLS refuses a leaf that does not list its own group's
/// suite.
fn capabilities() -> Capabilities {
    Capabilities::new(None, Some(&[CIPHERSUITE, LEGACY_CIPHERSUITE]), None, None, None)
}

fn create_config() -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .capabilities(capabilities())
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

fn credential_for(identity: &[u8], signer: &SignatureKeyPair) -> CredentialWithKey {
    CredentialWithKey {
        credential: BasicCredential::new(identity.to_vec()).into(),
        signature_key: signer.public().to_vec().into(),
    }
}

fn identity_of(credential: &Credential) -> Vec<u8> {
    BasicCredential::try_from(credential.clone())
        .map(|c| c.identity().to_vec())
        .unwrap_or_default()
}

impl MlsClient {
    /// A fresh MLS identity: `identity` is what other members see (the bare
    /// JID). Signing keys (ML-DSA-87, one per group) are generated here and
    /// never leave.
    pub fn new(identity: &[u8]) -> Self {
        Self {
            identity: identity.to_vec(),
            provider: CoreProvider::default(),
            signers: HashMap::new(),
            kp_signers: Vec::new(),
            groups: HashMap::new(),
            pending: HashMap::new(),
            app_data: Zeroizing::new(Vec::new()),
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

    /// Our group and our signing key in it, together (disjoint borrows).
    fn group_and_signer(&mut self, group_id: &[u8])
        -> Result<(&CoreProvider, &SignatureKeyPair, &mut MlsGroup)>
    {
        self.live()?;
        let group = self.groups.get_mut(group_id).ok_or(MlsError::NoSuchGroup)?;
        let signer = self.signers.get(group_id).ok_or(MlsError::Failed("no signing key"))?;
        Ok((&self.provider, signer, group))
    }

    /// A KeyPackage (public: lets someone add us to a group), as MLS wire
    /// bytes. It carries a signing key of its own, which becomes our key in
    /// the group it brings us into. Private halves stay in this client.
    pub fn key_package(&mut self) -> Result<Vec<u8>> {
        self.live()?;
        let signer = SignatureKeyPair::generate();
        let bundle = KeyPackage::builder()
            .leaf_node_capabilities(capabilities())
            .build(CIPHERSUITE, &self.provider, &signer,
                   credential_for(&self.identity, &signer))
            .map_err(|_| MlsError::Failed("key package"))?;
        let msg: MlsMessageOut = bundle.key_package().clone().into();
        let out = out_bytes(&msg)?;
        self.kp_signers.push(signer);
        if self.kp_signers.len() > MAX_KP_SIGNERS {
            let excess = self.kp_signers.len() - MAX_KP_SIGNERS;
            self.kp_signers.drain(..excess);       // dropped: zeroized
        }
        Ok(out)
    }

    pub fn create_group(&mut self, group_id: &[u8]) -> Result<()> {
        self.live()?;
        if self.groups.contains_key(group_id) {
            return Err(MlsError::GroupExists);
        }
        let signer = SignatureKeyPair::generate();
        let group = MlsGroup::new_with_group_id(
            &self.provider, &signer, &create_config(),
            GroupId::from_slice(group_id), credential_for(&self.identity, &signer),
        ).map_err(|_| MlsError::Failed("create group"))?;
        self.groups.insert(group_id.to_vec(), group);
        self.signers.insert(group_id.to_vec(), signer);
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

    /// The group's ciphersuite code point: 0xF0A1 (hybrid) or 0x0907
    /// (the earlier PQ-only suite).
    pub fn ciphersuite(&mut self, group_id: &[u8]) -> Result<u16> {
        Ok(u16::from(self.group(group_id)?.ciphersuite()))
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

    fn hold(&mut self, group_id: &[u8], commit: Vec<u8>, welcome: Option<Vec<u8>>,
            new_signer: Option<SignatureKeyPair>) -> Result<Vec<u8>>
    {
        self.pending.insert(group_id.to_vec(),
                            Pending { commit: commit.clone(), welcome, new_signer });
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
        let suite = self.groups.get(group_id).ok_or(MlsError::NoSuchGroup)?.ciphersuite();
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
            if kp.ciphersuite() != suite {
                // A group of the earlier PQ-only suite cannot take members
                // whose clients now make hybrid KeyPackages: re-create it.
                return Err(MlsError::Refused("key package for another ciphersuite"));
            }
            kps.push(kp);
        }
        let own = self.identity.clone();
        let (provider, signer, group) = self.group_and_signer(group_id)?;
        // A member who lost their state (a wipe, a new device) comes back
        // with a new KeyPackage under the same identity. Their old leaf can
        // never read again: it is removed in the same commit (RFC 9420
        // allows Remove and Add together), so the group never holds two
        // leaves for one person.
        let mut stale = Vec::new();
        for kp in &kps {
            let who = identity_of(kp.leaf_node().credential());
            if who == own {
                return Err(MlsError::Refused("key package with our own identity"));
            }
            stale.extend(group.members()
                .filter(|m| identity_of(&m.credential) == who)
                .map(|m| m.index));
        }
        let (c, w) = if stale.is_empty() {
            let (commit, welcome, _) = group.add_members(provider, signer, &kps)
                .map_err(|_| MlsError::Failed("add members"))?;
            (out_bytes(&commit)?, out_bytes(&welcome)?)
        } else {
            let bundle = group.commit_builder()
                .propose_removals(stale)
                .propose_adds(kps)
                .load_psks(provider.storage())
                .map_err(|_| MlsError::Failed("re-add members"))?
                .build(provider.rand(), provider.crypto(), signer, |_| true)
                .map_err(|_| MlsError::Failed("re-add members"))?
                .stage_commit(provider)
                .map_err(|_| MlsError::Failed("re-add members"))?;
            let (commit, welcome, _) = bundle.into_messages();
            let welcome = welcome.ok_or(MlsError::Failed("re-add members"))?;
            (out_bytes(&commit)?, out_bytes(&welcome)?)
        };
        self.hold(group_id, c, Some(w), None)
    }

    /// Commit removing the members with these identities.
    pub fn remove_members(&mut self, group_id: &[u8], identities: &[Vec<u8>]) -> Result<Vec<u8>> {
        self.live()?;
        self.refuse_if_pending(group_id)?;
        let (provider, signer, group) = self.group_and_signer(group_id)?;
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
        self.hold(group_id, c, None, None)
    }

    /// Commit a fresh leaf for ourselves (post-compromise security): new
    /// encryption keys along the path AND a new signing key. The commit is
    /// signed with the old key, which authenticates the new one to every
    /// member; the old key is dropped when the commit lands.
    pub fn self_update(&mut self, group_id: &[u8]) -> Result<Vec<u8>> {
        self.live()?;
        self.refuse_if_pending(group_id)?;
        let identity = self.identity.clone();
        let scheme = self.groups.get(group_id).ok_or(MlsError::NoSuchGroup)?
            .ciphersuite().signature_algorithm();
        let new_signer = SignatureKeyPair::generate_for(scheme)
            .map_err(|_| MlsError::Failed("signing key"))?;
        let (provider, signer, group) = self.group_and_signer(group_id)?;
        let bundle = NewSignerBundle {
            signer: &new_signer,
            credential_with_key: credential_for(&identity, &new_signer),
        };
        let (commit, _, _) = group
            .self_update_with_new_signer(provider, signer, bundle,
                                         LeafNodeParameters::default())
            .map_err(|_| MlsError::Failed("self update"))?
            .into_contents();
        let c = out_bytes(&commit)?;
        self.hold(group_id, c, None, Some(new_signer))
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
        if group.ciphersuite() != CIPHERSUITE && group.ciphersuite() != LEGACY_CIPHERSUITE {
            return Err(MlsError::Refused("group uses another ciphersuite"));
        }
        let id = group.group_id().as_slice().to_vec();
        if self.groups.contains_key(&id) {
            return Err(MlsError::GroupExists);
        }
        // Our leaf carries the key of the KeyPackage it was made from.
        let ours = group.own_leaf_node().map(|l| l.signature_key().as_slice().to_vec());
        let at = ours.and_then(|pk| self.kp_signers.iter().position(|s| s.public() == pk));
        let Some(at) = at else {
            let mut group = group;
            let _ = group.delete(self.provider.storage());
            return Err(MlsError::Refused("welcome for a key package we no longer hold"));
        };
        let signer = self.kp_signers.remove(at);
        self.groups.insert(id.clone(), group);
        self.signers.insert(id.clone(), signer);
        Ok(id)
    }

    /// Encrypt a group message. Refused while one of our commits is pending:
    /// if it wins, the message would be in a closed epoch.
    pub fn encrypt(&mut self, group_id: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        self.live()?;
        self.refuse_if_pending(group_id)?;
        let (provider, signer, group) = self.group_and_signer(group_id)?;
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
                let epoch = group.epoch().as_u64();
                let mut rekeyed = Vec::new();
                if let Some(new_signer) = p.new_signer {
                    // The new key is in the group: the old one goes (zeroized).
                    let old = self.signers.insert(group_id.to_vec(), new_signer);
                    if let (Some(old), Some(new)) = (old, self.signers.get(group_id)) {
                        rekeyed.push((self.identity.clone(), fingerprint(old.public()),
                                      fingerprint(new.public())));
                    }
                }
                return Ok(Event::Commit { epoch, ours: true, welcome: p.welcome,
                                          removed_us: false, dropped_ours: false,
                                          committer: self.identity.clone(), rekeyed });
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
        let sender_leaf = match processed.sender() {
            Sender::Member(index) => Some(*index),
            _ => None,
        };
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(m) => {
                Ok(Event::Application { sender, plaintext: Zeroizing::new(m.into_bytes()) })
            }
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                let removed_us = staged.self_removed();
                // Signature keys replaced by their owner's own update: the
                // committer's update path, and Update proposals it carries.
                let mut updates: Vec<(LeafNodeIndex, Vec<u8>, Vec<u8>)> = Vec::new();
                if let (Some(leaf), Some(index)) = (staged.update_path_leaf_node(), sender_leaf) {
                    updates.push((index, identity_of(leaf.credential()),
                                  leaf.signature_key().as_slice().to_vec()));
                }
                for queued in staged.update_proposals() {
                    if let Sender::Member(index) = queued.sender() {
                        let leaf = queued.update_proposal().leaf_node();
                        updates.push((*index, identity_of(leaf.credential()),
                                      leaf.signature_key().as_slice().to_vec()));
                    }
                }
                let removed: Vec<LeafNodeIndex> =
                    staged.remove_proposals().map(|r| r.remove_proposal().removed()).collect();
                let mut rekeyed = Vec::new();
                for (index, new_identity, new_key) in updates {
                    if removed.contains(&index) {
                        continue;
                    }
                    let Some(before) = group.member_at(index) else { continue };
                    if identity_of(&before.credential) == new_identity
                        && before.signature_key != new_key
                    {
                        rekeyed.push((new_identity, fingerprint(&before.signature_key),
                                      fingerprint(&new_key)));
                    }
                }
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
                Ok(Event::Commit { epoch, ours: false, welcome: None, removed_us, dropped_ours,
                                   committer: sender, rekeyed })
            }
            ProcessedMessageContent::ProposalMessage(p) => {
                group.store_pending_proposal(provider.storage(), *p)
                    .map_err(|_| MlsError::Failed("store proposal"))?;
                Ok(Event::Proposal)
            }
            _ => Err(MlsError::Refused("unsupported message")),
        }
    }

    /// Media keys for a call in this group, from the MLS exporter of the
    /// current epoch (`crate::group_voice`). Nothing secret leaves: the
    /// returned object seals and opens frames itself.
    pub fn group_voice(&mut self, group_id: &[u8], call_id: &[u8])
        -> Result<crate::group_voice::GroupVoice>
    {
        let (root, epoch, own) = self.voice_root(group_id, call_id)?;
        crate::group_voice::GroupVoice::new(&root[..], call_id, epoch, own)
            .map_err(|_| MlsError::Refused("bad call id"))
    }

    /// Move a call's keys to the group's current epoch (after a commit).
    /// A no-op if the call is already there.
    pub fn group_voice_rekey(&mut self, group_id: &[u8], call_id: &[u8],
                             voice: &mut crate::group_voice::GroupVoice) -> Result<bool>
    {
        let epoch = self.group(group_id)?.epoch().as_u64();
        if voice.epoch() == Some(epoch) {
            return Ok(false);
        }
        let (root, epoch, own) = self.voice_root(group_id, call_id)?;
        voice.rekey(&root[..], epoch, own).map_err(|_| MlsError::Refused("call epoch"))?;
        Ok(true)
    }

    fn voice_root(&mut self, group_id: &[u8], call_id: &[u8])
        -> Result<(Zeroizing<Vec<u8>>, u64, u32)>
    {
        self.live()?;
        let crypto_provider = &self.provider;
        let group = self.groups.get(group_id).ok_or(MlsError::NoSuchGroup)?;
        let root = group
            .export_secret(crypto_provider.crypto(), crate::group_voice::EXPORT_LABEL,
                           call_id, crate::group_voice::ROOT_LEN)
            .map_err(|_| MlsError::Failed("exporter"))?;
        Ok((Zeroizing::new(root), group.epoch().as_u64(), group.own_leaf_index().u32()))
    }

    /// The identity of the member at a leaf index (who a voice frame is from).
    pub fn member_at(&mut self, group_id: &[u8], leaf: u32) -> Result<Vec<u8>> {
        let group = self.group(group_id)?;
        group.member_at(LeafNodeIndex::new(leaf))
            .map(|m| identity_of(&m.credential))
            .ok_or(MlsError::NoSuchMember)
    }

    /// Drop a group and every secret it holds (we left, or were removed).
    pub fn forget_group(&mut self, group_id: &[u8]) {
        self.pending.remove(group_id);
        self.signers.remove(group_id);           // dropped: zeroized
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
        self.signers.clear();         // signing keys zeroize on drop
        self.kp_signers.clear();
        self.app_data = Zeroizing::new(Vec::new());
        self.wiped = true;
    }

    pub fn is_wiped(&self) -> bool { self.wiped }

    /// Our MLS fingerprint in a group (SHA-384 of our signature public key
    /// there). Different in every group, and new after each self-update.
    pub fn own_fingerprint(&self, group_id: &[u8]) -> Result<Vec<u8>> {
        self.live()?;
        self.signers.get(group_id).map(|s| fingerprint(s.public()))
            .ok_or(MlsError::NoSuchGroup)
    }

    /// The caller's own state, sealed with ours by `export_sealed` (it is
    /// opaque here). Bounded by MAX_APP_DATA.
    pub fn set_app_data(&mut self, data: &[u8]) -> Result<()> {
        self.live()?;
        if data.len() > MAX_APP_DATA {
            return Err(MlsError::Refused("app data too large"));
        }
        self.app_data = Zeroizing::new(data.to_vec());
        Ok(())
    }

    pub fn app_data(&self) -> &[u8] { &self.app_data }

    /// The fingerprint a group holds for the member with this identity.
    ///
    /// Identity binding is deliberately NOT membership: MLS says this key
    /// belongs to a leaf, not that the leaf is who its credential names. The
    /// caller compares this against a fingerprint it learned over a channel
    /// that authenticates the person -- an SMP-verified OTRv4+ session.
    pub fn member_fingerprint(&mut self, group_id: &[u8], identity: &[u8]) -> Result<Vec<u8>> {
        let group = self.group(group_id)?;
        let member = group.members()
            .find(|m| identity_of(&m.credential) == identity)
            .ok_or(MlsError::NoSuchMember)?;
        Ok(fingerprint(member.signature_key.as_slice()))
    }

    /// Seal the whole client -- identity, signing key, every group and its
    /// secrets, and any commit still waiting for the room -- under a key
    /// derived from `dek`. `context` is bound as associated data (the owning
    /// account), so a blob cannot be opened as another account's.
    ///
    /// AES-256-GCM, random 96-bit nonce. The plaintext exists only in
    /// zeroizing buffers inside this function.
    pub fn export_sealed(&self, dek: &[u8], context: &[u8]) -> Result<Vec<u8>> {
        self.live()?;
        let storage = self.provider.secure_storage().snapshot()
            .map_err(|_| MlsError::Failed("snapshot"))?;
        let group_ids: Vec<Vec<u8>> = self.group_ids();
        let b = serde_bytes::Bytes::new;
        let state = StateOut {
            identity: b(&self.identity),
            groups: group_ids.iter().map(|g| b(g)).collect(),
            signers: self.signers.iter()
                .map(|(g, s)| (b(g), b(s.public()), b(s.secret()))).collect(),
            kp_signers: self.kp_signers.iter().map(signer_out).collect(),
            pending: self.pending.iter().map(|(g, p)| (
                b(g),
                b(&p.commit),
                p.welcome.as_deref().map(b),
                p.new_signer.as_ref().map(signer_out),
            )).collect(),
            storage: b(&storage),
            app_data: b(&self.app_data),
        };
        let key_bytes = |s: &SignatureKeyPair| s.public().len() + s.secret().len() + 16;
        let need = storage.len() + self.identity.len() + self.app_data.len()
            + group_ids.iter().map(|g| g.len() + 16).sum::<usize>()
            + self.signers.iter().map(|(g, s)| g.len() + key_bytes(s)).sum::<usize>()
            + self.kp_signers.iter().map(key_bytes).sum::<usize>()
            + self.pending.values().map(|p| p.commit.len()
                + p.welcome.as_ref().map_or(0, |w| w.len())
                + p.new_signer.as_ref().map_or(0, key_bytes) + 32).sum::<usize>()
            + 256;
        let mut plain = Zeroizing::new(Vec::with_capacity(need));
        ciborium::ser::into_writer(&state, &mut *plain).map_err(|_| MlsError::Failed("encode"))?;

        let key = state_key(dek)?;
        let cipher = Aes256Gcm::new_from_slice(&key[..]).map_err(|_| MlsError::Failed("key"))?;
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce).map_err(|_| MlsError::Failed("randomness"))?;
        let aad = state_aad(context);
        let ct = cipher.encrypt(<&Nonce<_>>::from(&nonce[..]), Payload { msg: &plain, aad: &aad })
            .map_err(|_| MlsError::Failed("seal"))?;
        let mut out = Vec::with_capacity(5 + 12 + ct.len());
        out.extend_from_slice(STATE_MAGIC);
        out.push(STATE_VERSION);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Open a blob from `export_sealed` into a working client.
    ///
    /// Fails closed and undifferentiated: a wrong key, a wrong context, a
    /// truncated or altered blob and an unknown version all refuse, and
    /// nothing partial is returned.
    pub fn import_sealed(dek: &[u8], context: &[u8], blob: &[u8]) -> Result<Self> {
        if blob.len() > STATE_MAX || blob.len() < 5 + 12 + 16
            || &blob[..4] != STATE_MAGIC
            || !(blob[4] == STATE_VERSION || blob[4] == STATE_VERSION_1)
        {
            return Err(MlsError::Refused("not a sealed MLS state this build can open"));
        }
        let version = blob[4];
        let key = state_key(dek)?;
        let cipher = Aes256Gcm::new_from_slice(&key[..]).map_err(|_| MlsError::Failed("key"))?;
        let mut aad = state_aad(context);
        aad[4] = version;
        let plain = Zeroizing::new(
            cipher.decrypt(<&Nonce<_>>::from(&blob[5..17]), Payload { msg: &blob[17..], aad: &aad })
                .map_err(|_| MlsError::Refused("sealed MLS state did not open"))?,
        );
        let state: StateIn = if version == STATE_VERSION_1 {
            Self::migrate_v1(&plain)?
        } else {
            ciborium::de::from_reader(plain.as_slice())
                .map_err(|_| MlsError::Refused("sealed MLS state is malformed"))?
        };
        let storage_bytes = Zeroizing::new(state.storage.into_vec());
        if state.app_data.len() > MAX_APP_DATA {
            return Err(MlsError::Refused("sealed MLS state is malformed"));
        }
        let app_data = Zeroizing::new(state.app_data.into_vec());
        let identity = state.identity.into_vec();
        let provider = CoreProvider::default();
        provider.secure_storage().restore(&storage_bytes)
            .map_err(|_| MlsError::Refused("sealed MLS state has bad storage"))?;
        let mut groups = HashMap::new();
        for gid in state.groups {
            let gid = gid.into_vec();
            let group = MlsGroup::load(provider.storage(), &GroupId::from_slice(&gid))
                .map_err(|_| MlsError::Refused("sealed MLS group did not load"))?
                .ok_or(MlsError::Refused("sealed MLS group missing"))?;
            groups.insert(gid, group);
        }
        let mut signers = HashMap::new();
        for (gid, public, secret) in state.signers {
            let gid = gid.into_vec();
            if !groups.contains_key(&gid) {
                return Err(MlsError::Refused("signing key for an unknown group"));
            }
            signers.insert(gid, signer_from(public, secret)?);
        }
        if groups.keys().any(|g| !signers.contains_key(g)) {
            return Err(MlsError::Refused("sealed MLS group has no signing key"));
        }
        let mut kp_signers = Vec::new();
        for (public, secret) in state.kp_signers.into_iter().take(MAX_KP_SIGNERS) {
            kp_signers.push(signer_from(public, secret)?);
        }
        let mut pending = HashMap::new();
        for (gid, commit, welcome, new_signer) in state.pending {
            let gid = gid.into_vec();
            if !groups.contains_key(&gid) {
                return Err(MlsError::Refused("pending commit for an unknown group"));
            }
            let new_signer = match new_signer {
                Some((public, secret)) => Some(signer_from(public, secret)?),
                None => None,
            };
            pending.insert(gid, Pending { commit: commit.into_vec(),
                                          welcome: welcome.map(|w| w.into_vec()),
                                          new_signer });
        }
        Ok(Self { identity, provider, signers, kp_signers, groups, pending, app_data,
                  wiped: false })
    }

    /// A version-1 state (one signing key for everything) in today's shape:
    /// that key becomes every group's key -- the next self-update in each
    /// group replaces it -- and stays usable for a KeyPackage already sent.
    fn migrate_v1(plain: &[u8]) -> Result<StateIn> {
        let old: StateInV1 = ciborium::de::from_reader(plain)
            .map_err(|_| MlsError::Refused("sealed MLS state is malformed"))?;
        let key = (old.sig_pub, old.sig_sk);
        Ok(StateIn {
            identity: old.identity,
            signers: old.groups.iter()
                .map(|g| (g.clone(), key.0.clone(), key.1.clone())).collect(),
            groups: old.groups,
            kp_signers: vec![key],
            pending: old.pending.into_iter().map(|(g, c, w)| (g, c, w, None)).collect(),
            storage: old.storage,
            app_data: serde_bytes::ByteBuf::new(),
        })
    }

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

    /// A state sealed by the previous format (one signing key for the
    /// client) opens, and that key becomes the group's key.
    #[test]
    fn a_version_1_state_is_migrated() {
        #[derive(serde::Serialize)]
        struct V1<'a> {
            identity: &'a serde_bytes::Bytes,
            sig_pub: &'a serde_bytes::Bytes,
            sig_sk: &'a serde_bytes::Bytes,
            groups: Vec<&'a serde_bytes::Bytes>,
            pending: Vec<(&'a serde_bytes::Bytes, &'a serde_bytes::Bytes,
                          Option<&'a serde_bytes::Bytes>)>,
            storage: &'a serde_bytes::Bytes,
        }
        let mut a = MlsClient::new(b"alice");
        let mut b = MlsClient::new(b"bob");
        a.create_group(b"g").unwrap();
        let add = a.add_members(b"g", &[b.key_package().unwrap()]).unwrap();
        let w = match a.process(b"g", &add).unwrap() {
            Event::Commit { welcome: Some(w), .. } => w,
            other => panic!("{other:?}"),
        };
        b.join(&w).unwrap();
        let key = a.signers.get(b"g".as_slice()).unwrap();
        let storage = a.provider.secure_storage().snapshot().unwrap();
        let bb = serde_bytes::Bytes::new;
        let v1 = V1 { identity: bb(b"alice"), sig_pub: bb(key.public()),
                      sig_sk: bb(key.secret()), groups: vec![bb(b"g")], pending: vec![],
                      storage: bb(&storage) };
        let mut plain = Vec::new();
        ciborium::ser::into_writer(&v1, &mut plain).unwrap();
        let dek = [9u8; 32];
        let k = state_key(&dek).unwrap();
        let cipher = Aes256Gcm::new_from_slice(&k[..]).unwrap();
        let mut aad = state_aad(b"ctx");
        aad[4] = STATE_VERSION_1;
        let nonce = [1u8; 12];
        let ct = cipher.encrypt(<&Nonce<_>>::from(&nonce[..]),
                                Payload { msg: &plain, aad: &aad }).unwrap();
        let mut blob = STATE_MAGIC.to_vec();
        blob.push(STATE_VERSION_1);
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ct);

        let mut opened = MlsClient::import_sealed(&dek, b"ctx", &blob).unwrap();
        assert_eq!(opened.own_fingerprint(b"g").unwrap(), a.own_fingerprint(b"g").unwrap());
        let m = opened.encrypt(b"g", b"after migration").unwrap();
        assert!(matches!(b.process(b"g", &m).unwrap(), Event::Application { .. }));
        // Saved again, it is the current format.
        assert_eq!(opened.export_sealed(&dek, b"ctx").unwrap()[4], STATE_VERSION);
    }

    /// A STANDALONE proposal (RFC 9420 §12.1), which no OTRv4Plus client
    /// sends -- they commit their proposals inline -- but which a member may
    /// receive. It must authenticate, be queued rather than shown, refuse a
    /// tampered or replayed copy, and be folded in by the next commit without
    /// breaking the group.
    #[test]
    fn a_standalone_proposal_is_queued_then_committed() {
        let mut a = MlsClient::new(b"alice");
        let mut b = MlsClient::new(b"bob");
        a.create_group(b"g").unwrap();
        let add = a.add_members(b"g", &[b.key_package().unwrap()]).unwrap();
        let welcome = match a.process(b"g", &add).unwrap() {
            Event::Commit { welcome: Some(w), .. } => w,
            _ => panic!("expected our add to land with a Welcome"),
        };
        b.join(&welcome).unwrap();

        // Bob proposes a fresh leaf for himself, without committing it.
        let proposal = {
            let (provider, signer) = (&b.provider, b.signers.get(b"g".as_slice()).unwrap());
            let group = b.groups.get_mut(b"g".as_slice()).unwrap();
            let (out, _ref) = group
                .propose_self_update(provider, signer, LeafNodeParameters::default())
                .unwrap();
            out.to_bytes().unwrap()
        };

        assert!(matches!(a.process(b"g", &proposal).unwrap(), Event::Proposal));
        assert!(a.process(b"g", &proposal).is_err(), "a replayed proposal was accepted");
        let epoch = a.epoch(b"g").unwrap();

        // Alice's next commit folds the queued proposal in; both move on.
        let commit = a.self_update(b"g").unwrap();
        assert!(matches!(a.process(b"g", &commit).unwrap(), Event::Commit { ours: true, .. }));
        assert!(matches!(b.process(b"g", &commit).unwrap(), Event::Commit { .. }));
        assert_eq!(a.epoch(b"g").unwrap(), epoch + 1);
        assert_eq!(b.epoch(b"g").unwrap(), epoch + 1);

        let ct = b.encrypt(b"g", b"after the proposal").unwrap();
        match a.process(b"g", &ct).unwrap() {
            Event::Application { plaintext, .. } => assert_eq!(&plaintext[..], b"after the proposal"),
            _ => panic!("expected an application message"),
        }
    }

    /// A tampered copy is refused -- and, as OpenMLS's secret tree deletes a
    /// generation's key when it is first used, the GENUINE message arriving
    /// after it is refused too. Fail closed, never a wrong acceptance; the
    /// effect is that of the relay dropping the message, which a relay can
    /// do anyway. Recorded here so a change to it is deliberate.
    #[test]
    fn a_tampered_copy_is_refused_and_spends_the_generation() {
        let mut a = MlsClient::new(b"alice");
        let mut b = MlsClient::new(b"bob");
        a.create_group(b"g").unwrap();
        let add = a.add_members(b"g", &[b.key_package().unwrap()]).unwrap();
        let welcome = match a.process(b"g", &add).unwrap() {
            Event::Commit { welcome: Some(w), .. } => w,
            _ => panic!("expected a Welcome"),
        };
        b.join(&welcome).unwrap();

        let genuine = b.encrypt(b"g", b"first").unwrap();
        let mut tampered = genuine.clone();
        let i = tampered.len() - 10;
        tampered[i] ^= 0x01;
        assert!(a.process(b"g", &tampered).is_err(), "a tampered message was accepted");
        assert!(a.process(b"g", &genuine).is_err());

        // The group is unharmed: the next message decrypts.
        let next = b.encrypt(b"g", b"second").unwrap();
        match a.process(b"g", &next).unwrap() {
            Event::Application { plaintext, .. } => assert_eq!(&plaintext[..], b"second"),
            _ => panic!("expected an application message"),
        }
    }
}
