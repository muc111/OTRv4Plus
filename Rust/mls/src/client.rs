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

use crate::provider::{CoreProvider, SignatureKeyPair, CIPHERSUITE};

/// Sealed-state header: magic, then format version.
const STATE_MAGIC: &[u8; 4] = b"OMLS";
const STATE_VERSION: u8 = 1;
const STATE_KDF_INFO: &[u8] = b"OTRv4Plus MLS sealed state v1";
/// Upper bound on a sealed blob we will try to open (64 MiB).
const STATE_MAX: usize = 64 << 20;

#[derive(serde::Serialize)]
struct StateOut<'a> {
    identity: &'a serde_bytes::Bytes,
    sig_pub: &'a serde_bytes::Bytes,
    sig_sk: &'a serde_bytes::Bytes,
    groups: Vec<&'a serde_bytes::Bytes>,
    pending: Vec<(&'a serde_bytes::Bytes, &'a serde_bytes::Bytes, Option<&'a serde_bytes::Bytes>)>,
    storage: &'a serde_bytes::Bytes,
}

#[derive(serde::Deserialize)]
struct StateIn {
    identity: serde_bytes::ByteBuf,
    sig_pub: serde_bytes::ByteBuf,
    sig_sk: serde_bytes::ByteBuf,
    groups: Vec<serde_bytes::ByteBuf>,
    pending: Vec<(serde_bytes::ByteBuf, serde_bytes::ByteBuf, Option<serde_bytes::ByteBuf>)>,
    storage: serde_bytes::ByteBuf,
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

    /// Our own MLS fingerprint (SHA-384 of our signature public key).
    pub fn own_fingerprint(&self) -> Vec<u8> { fingerprint(self.signer.public()) }

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
        let pending: Vec<(&[u8], &Pending)> =
            self.pending.iter().map(|(k, v)| (k.as_slice(), v)).collect();
        let state = StateOut {
            identity: serde_bytes::Bytes::new(&self.identity),
            sig_pub: serde_bytes::Bytes::new(self.signer.public()),
            sig_sk: serde_bytes::Bytes::new(self.signer.secret()),
            groups: group_ids.iter().map(|g| serde_bytes::Bytes::new(g)).collect(),
            pending: pending.iter().map(|(g, p)| (
                serde_bytes::Bytes::new(g),
                serde_bytes::Bytes::new(&p.commit),
                p.welcome.as_deref().map(serde_bytes::Bytes::new),
            )).collect(),
            storage: serde_bytes::Bytes::new(&storage),
        };
        let need = storage.len() + self.signer.secret().len() + self.signer.public().len()
            + self.identity.len()
            + group_ids.iter().map(|g| g.len() + 16).sum::<usize>()
            + self.pending.values().map(|p| p.commit.len()
                + p.welcome.as_ref().map_or(0, |w| w.len()) + 32).sum::<usize>()
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
            || &blob[..4] != STATE_MAGIC || blob[4] != STATE_VERSION
        {
            return Err(MlsError::Refused("not a sealed MLS state this build can open"));
        }
        let key = state_key(dek)?;
        let cipher = Aes256Gcm::new_from_slice(&key[..]).map_err(|_| MlsError::Failed("key"))?;
        let aad = state_aad(context);
        let plain = Zeroizing::new(
            cipher.decrypt(<&Nonce<_>>::from(&blob[5..17]), Payload { msg: &blob[17..], aad: &aad })
                .map_err(|_| MlsError::Refused("sealed MLS state did not open"))?,
        );
        let state: StateIn = ciborium::de::from_reader(plain.as_slice())
            .map_err(|_| MlsError::Refused("sealed MLS state is malformed"))?;
        let sig_sk = Zeroizing::new(state.sig_sk.into_vec());
        let storage_bytes = Zeroizing::new(state.storage.into_vec());
        let signer = SignatureKeyPair::from_parts(state.sig_pub.into_vec(), sig_sk)
            .ok_or(MlsError::Refused("sealed MLS state has a bad signing key"))?;
        let identity = state.identity.into_vec();
        let credential = CredentialWithKey {
            credential: BasicCredential::new(identity.clone()).into(),
            signature_key: signer.public().to_vec().into(),
        };
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
        let mut pending = HashMap::new();
        for (gid, commit, welcome) in state.pending {
            let gid = gid.into_vec();
            if !groups.contains_key(&gid) {
                return Err(MlsError::Refused("pending commit for an unknown group"));
            }
            pending.insert(gid, Pending { commit: commit.into_vec(),
                                          welcome: welcome.map(|w| w.into_vec()) });
        }
        Ok(Self { identity, provider, signer, credential, groups, pending, wiped: false })
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
            let (provider, signer) = (&b.provider, &b.signer);
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
