// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
// Copyright (C) 2025-2026 muc111
//! Epochal ML-DSA-87: a research prototype. See ANALYSIS.md; the lifecycle
//! here is derived from its section 1 (claim C).
//!
//! * One ML-DSA-87 key per (member, group, epoch), from a one-way chain:
//!   `s_{N+1} = H("chain" | s_N)`, `xi_N = H("sign" | s_N | H(G) | N | auth_N)`,
//!   `sk_N = ML-DSA.KeyGen_internal(xi_N)`. `s_N` is erased once used.
//! * Every signature carries the FIPS 204 context `label | H(G) | N`.
//! * A key is bound to the group epoch by a tag only holders of the MLS
//!   epoch authenticator can make or check.
//! * Release publishes `xi_N` (32 B) once epoch N is closed; anyone can then
//!   rebuild `sk_N` and sign for epoch N -- and only epoch N.

use std::collections::BTreeMap;

use ml_dsa::{EncodedSignature, ExpandedSigningKey, MlDsa87, Signature, VerifyingKey, B32};
use sha3::{Digest, Sha3_256};
use zeroize::Zeroize;

/// The FIPS 204 context label of every epochal signature.
pub const CONTEXT_LABEL: &[u8] = b"OTRv4+ epochal v1";

fn h(parts: &[&[u8]]) -> [u8; 32] {
    let mut d = Sha3_256::new();
    for p in parts {
        d.update((p.len() as u32).to_be_bytes());
        d.update(p);
    }
    d.finalize().into()
}

/// One MLS group at one epoch, as a member knows it. `authenticator` is the
/// RFC 9420 epoch authenticator: known to that epoch's members only.
#[derive(Clone)]
pub struct GroupEpoch {
    pub group_id: Vec<u8>,
    pub epoch_id: u64,
    pub authenticator: [u8; 32],
}

impl GroupEpoch {
    pub fn group_hash(&self) -> [u8; 32] {
        h(&[b"group", &self.group_id])
    }
}

/// What is distributed during an epoch: the key, whose it says it is, and
/// the group-binding tag.
#[derive(Clone)]
pub struct PublicKey {
    pub group_hash: [u8; 32],
    pub epoch_id: u64,
    pub member: Vec<u8>,
    pub vk: VerifyingKey<MlDsa87>,
    pub binding: [u8; 32],
}

/// A member's signing key for one epoch. Never distributed; released only
/// as its seed, once the epoch is closed.
pub struct SecretKey {
    group_hash: [u8; 32],
    epoch_id: u64,
    seed: B32,
    sk: ExpandedSigningKey<MlDsa87>,
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

#[derive(Clone)]
pub struct EpochSignature {
    pub epoch_id: u64,
    pub bytes: Vec<u8>,
}

/// What a release publishes: the epoch's private key, in FIPS 204 seed form.
#[derive(Clone)]
pub struct Release {
    pub group_hash: [u8; 32],
    pub epoch_id: u64,
    pub member: Vec<u8>,
    pub seed: [u8; 32],
}

/// The FIPS 204 context string of every signature for (group, epoch).
pub fn context(group_hash: &[u8; 32], epoch_id: u64) -> Vec<u8> {
    let mut ctx = CONTEXT_LABEL.to_vec();
    ctx.extend_from_slice(group_hash);
    ctx.extend_from_slice(&epoch_id.to_be_bytes());
    ctx
}

fn binding_tag(authenticator: &[u8; 32], group_hash: &[u8; 32], epoch_id: u64,
               member: &[u8], vk: &VerifyingKey<MlDsa87>) -> [u8; 32] {
    let pk_hash = h(&[vk.encode().as_slice()]);
    h(&[b"bind", authenticator, group_hash, &epoch_id.to_be_bytes(), member, &pk_hash])
}

fn key_from_seed(seed: &B32) -> ExpandedSigningKey<MlDsa87> {
    ExpandedSigningKey::<MlDsa87>::from_seed(seed)
}

/// FIPS 204 ML-DSA.Sign (hedged): external message form
/// `M' = 0 | len(ctx) | ctx | M`, fresh 32-byte randomiser.
fn sign_with(sk: &ExpandedSigningKey<MlDsa87>, ctx: &[u8], message: &[u8]) -> Vec<u8> {
    let mut rnd = [0u8; 32];
    getrandom::getrandom(&mut rnd).expect("OS randomness");
    fips204_sign(sk, ctx, message, &rnd)
}

/// The one signing path, with the randomiser explicit: FIPS 204 Algorithm 2
/// (ML-DSA.Sign, pure, with context). Every signature here, the holder's
/// and a forger's, is made by this function, so it is what the NIST ACVP
/// sigGen vectors check (tests/conformance.rs). Exposed for those vectors
/// and for the byte-identity proof (tests/proofs.rs); production signing
/// must take `rnd` from the OS, as `sign` does.
pub fn fips204_sign(sk: &ExpandedSigningKey<MlDsa87>, ctx: &[u8], message: &[u8],
                    rnd: &[u8; 32]) -> Vec<u8> {
    assert!(ctx.len() <= 255, "FIPS 204: |ctx| <= 255");
    let rnd = B32::from(*rnd);
    let sig = sk.sign_internal(&[&[0u8], &[ctx.len() as u8], ctx, message], &rnd);
    sig.encode().to_vec()
}

/// FIPS 204 ML-DSA.KeyGen_internal from a 32-byte seed: what a release
/// lets anyone run. Checked against the ACVP keyGen vectors.
pub fn key_from_release_seed(seed: &[u8; 32]) -> ExpandedSigningKey<MlDsa87> {
    key_from_seed(&B32::from(*seed))
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReleaseError {
    /// The epoch is still open (or not reached): its key is live.
    NotClosed,
    /// No key for that epoch here (never made, or already released).
    Unknown,
}

/// A member's epochal signer for one group.
pub struct EpochSigner {
    member: Vec<u8>,
    chain: [u8; 32],
    next_epoch: u64,
    keys: BTreeMap<u64, SecretKey>,
}

impl EpochSigner {
    /// `chain_seed`: the member's secret starting point for this group.
    pub fn new(member: &[u8], chain_seed: [u8; 32], first_epoch: u64) -> Self {
        Self { member: member.to_vec(), chain: chain_seed, next_epoch: first_epoch,
               keys: BTreeMap::new() }
    }

    /// epoch_keygen(epoch_id, group_state) -> (pk, sk). Only forward: the
    /// chain steps to `epoch_id`, erasing each state it passes. The secret
    /// key stays in the signer (`signing_key`) until released.
    pub fn epoch_keygen(&mut self, epoch_id: u64, group: &GroupEpoch)
        -> Result<PublicKey, ReleaseError>
    {
        if epoch_id < self.next_epoch || group.epoch_id != epoch_id {
            return Err(ReleaseError::NotClosed);
        }
        while self.next_epoch < epoch_id {
            self.step();
        }
        let gh = group.group_hash();
        let mut xi = h(&[b"sign", &self.chain, &gh, &epoch_id.to_be_bytes(),
                         &group.authenticator]);
        self.step();
        let seed = B32::from(xi);
        xi.zeroize();
        let sk = key_from_seed(&seed);
        let vk = sk.verifying_key();
        let binding = binding_tag(&group.authenticator, &gh, epoch_id, &self.member, &vk);
        self.keys.insert(epoch_id, SecretKey { group_hash: gh, epoch_id, seed, sk });
        Ok(PublicKey { group_hash: gh, epoch_id, member: self.member.clone(), vk, binding })
    }

    fn step(&mut self) {
        let next = h(&[b"chain", &self.chain]);
        self.chain.zeroize();
        self.chain = next;
        self.next_epoch += 1;
    }

    pub fn signing_key(&self, epoch_id: u64) -> Option<&SecretKey> {
        self.keys.get(&epoch_id)
    }

    /// release_epoch_key(epoch_id) -> the published seed. Only a CLOSED
    /// epoch: one whose successor's key has been made. The key is erased
    /// here as it is released.
    pub fn release_epoch_key(&mut self, epoch_id: u64) -> Result<Release, ReleaseError> {
        if epoch_id + 1 >= self.next_epoch {
            return Err(ReleaseError::NotClosed);  // no later epoch's key yet: still open
        }
        let key = self.keys.remove(&epoch_id).ok_or(ReleaseError::Unknown)?;
        let mut seed = [0u8; 32];
        seed.copy_from_slice(key.seed.as_slice());
        Ok(Release { group_hash: key.group_hash, epoch_id, member: self.member.clone(), seed })
    }
}

/// sign(sk, message) -> signature, in the key's own group and epoch.
pub fn sign(sk: &SecretKey, message: &[u8]) -> EpochSignature {
    let ctx = context(&sk.group_hash, sk.epoch_id);
    EpochSignature { epoch_id: sk.epoch_id, bytes: sign_with(&sk.sk, &ctx, message) }
}

impl SecretKey {
    /// `sign`, with the randomiser given: for the byte-identity proof only.
    pub fn sign_with_rnd(&self, message: &[u8], rnd: &[u8; 32]) -> EpochSignature {
        let ctx = context(&self.group_hash, self.epoch_id);
        EpochSignature { epoch_id: self.epoch_id, bytes: fips204_sign(&self.sk, &ctx, message, rnd) }
    }

    /// The holder's expanded key, to compare with what a release rebuilds.
    pub fn expanded(&self) -> &ExpandedSigningKey<MlDsa87> {
        &self.sk
    }
}

/// verify(pk, message, signature) -> bool: the ML-DSA-87 signature under
/// `pk`, in `pk`'s group and epoch. Says nothing about group membership
/// (`verify_group_binding`) or release (`verify_unreleased`).
pub fn verify(pk: &PublicKey, message: &[u8], sig: &EpochSignature) -> bool {
    sig.epoch_id == pk.epoch_id
        && fips204_verify(&pk.vk, &context(&pk.group_hash, pk.epoch_id), message, &sig.bytes)
}

/// The one verification path: FIPS 204 Algorithm 3 (ML-DSA.Verify, pure,
/// with context) over the encoded signature. Checked against the NIST ACVP
/// sigVer vectors. Malformed input is a rejection, never a panic.
pub fn fips204_verify(vk: &VerifyingKey<MlDsa87>, ctx: &[u8], message: &[u8], sig: &[u8]) -> bool {
    if ctx.len() > 255 {
        return false;
    }
    let Ok(enc) = EncodedSignature::<MlDsa87>::try_from(sig) else { return false };
    let Some(sig) = Signature::<MlDsa87>::decode(&enc) else { return false };
    vk.verify_with_context(message, ctx, &sig)
}

/// Whether `pk` was registered by a holder of this group epoch's
/// authenticator: "a member of G at epoch N". Not which member (ANALYSIS §1).
pub fn verify_group_binding(pk: &PublicKey, group: &GroupEpoch) -> bool {
    group.epoch_id == pk.epoch_id
        && group.group_hash() == pk.group_hash
        && binding_tag(&group.authenticator, &pk.group_hash, pk.epoch_id, &pk.member, &pk.vk)
            == pk.binding
}

/// Group-bound verification: the signature, and the key's binding.
pub fn verify_bound(pk: &PublicKey, group: &GroupEpoch, message: &[u8],
                    sig: &EpochSignature) -> bool {
    verify_group_binding(pk, group) && verify(pk, message, sig)
}

/// The publisher: where releases appear (ANALYSIS §3, a trusted party).
#[derive(Default)]
pub struct ReleaseBoard {
    released: BTreeMap<(Vec<u8>, u64), Release>,
}

impl ReleaseBoard {
    pub fn publish(&mut self, release: Release) {
        self.released.insert((release.member.clone(), release.epoch_id), release);
    }

    pub fn is_released(&self, member: &[u8], epoch_id: u64) -> bool {
        self.released.contains_key(&(member.to_vec(), epoch_id))
    }

    /// forge_with_released_key(epoch_id, message): what any third party can
    /// do with a release -- rebuild the key and sign, for that epoch only.
    pub fn forge_with_released_key(&self, member: &[u8], epoch_id: u64, message: &[u8])
        -> Option<EpochSignature>
    {
        let r = self.released.get(&(member.to_vec(), epoch_id))?;
        let seed = B32::from(r.seed);
        let sk = key_from_seed(&seed);
        let ctx = context(&r.group_hash, epoch_id);
        Some(EpochSignature { epoch_id, bytes: sign_with(&sk, &ctx, message) })
    }

    /// `forge_with_released_key`, with the randomiser given: for the
    /// byte-identity proof only.
    pub fn forge_with_rnd(&self, member: &[u8], epoch_id: u64, message: &[u8], rnd: &[u8; 32])
        -> Option<EpochSignature>
    {
        let r = self.released.get(&(member.to_vec(), epoch_id))?;
        let sk = key_from_seed(&B32::from(r.seed));
        let ctx = context(&r.group_hash, epoch_id);
        Some(EpochSignature { epoch_id, bytes: fips204_sign(&sk, &ctx, message, rnd) })
    }

    /// The key a third party rebuilds from a release.
    pub fn rebuild(&self, member: &[u8], epoch_id: u64) -> Option<ExpandedSigningKey<MlDsa87>> {
        let r = self.released.get(&(member.to_vec(), epoch_id))?;
        Some(key_from_seed(&B32::from(r.seed)))
    }

    /// Like an attacker who holds the release of `released_epoch` and
    /// tries to sign as `target_epoch`: the released key, the target's
    /// context.
    pub fn forge_across(&self, member: &[u8], released_epoch: u64, target_epoch: u64,
                        message: &[u8]) -> Option<EpochSignature> {
        let r = self.released.get(&(member.to_vec(), released_epoch))?;
        let sk = key_from_seed(&B32::from(r.seed));
        let ctx = context(&r.group_hash, target_epoch);
        Some(EpochSignature { epoch_id: target_epoch, bytes: sign_with(&sk, &ctx, message) })
    }
}

/// The receiver rule at the epoch boundary (ANALYSIS §3): once a release of
/// (member, epoch) has been seen, that epoch's signatures are refused --
/// they may be forgeries.
pub fn verify_unreleased(board: &ReleaseBoard, pk: &PublicKey, group: &GroupEpoch,
                         message: &[u8], sig: &EpochSignature) -> bool {
    !board.is_released(&pk.member, pk.epoch_id) && verify_bound(pk, group, message, sig)
}

/// When epochs open: fixed duration, 24 h unless configured. Decides only
/// when a member makes its next epoch's key (and so may release the last);
/// verification never reads the clock (ANALYSIS §3, clock skew).
#[derive(Clone, Copy)]
pub struct EpochSchedule {
    pub start_unix: u64,
    pub duration_secs: u64,
}

impl Default for EpochSchedule {
    fn default() -> Self {
        Self { start_unix: 0, duration_secs: 24 * 3600 }
    }
}

impl EpochSchedule {
    /// The epoch in force at `unix_time` (1 is the first).
    pub fn epoch_at(&self, unix_time: u64) -> u64 {
        1 + unix_time.saturating_sub(self.start_unix) / self.duration_secs.max(1)
    }
}

/// A handshake transcript in the shape the v2 DAKE signs it (SPEC §4.3): who
/// initiated, to whom, both ephemeral public keys, the session id. A valid
/// signature on this under a member's key is what proves "that you talked"
/// (SPEC §10.1) -- the attribution MAC-key release does not touch.
pub fn handshake_transcript(initiator: &[u8], responder: &[u8], eph_initiator: &[u8],
                            eph_responder: &[u8], session_id: &[u8]) -> Vec<u8> {
    let mut out = b"OTRv4+ epochal handshake v1".to_vec();
    for part in [initiator, responder, eph_initiator, eph_responder, session_id] {
        out.extend_from_slice(&(part.len() as u32).to_be_bytes());
        out.extend_from_slice(part);
    }
    out
}
