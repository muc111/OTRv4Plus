#!/usr/bin/env python3
"""Generate the OTRv4+ group protocol test vectors from SPEC_GROUP.md.

READ THIS BEFORE CHANGING ANYTHING HERE
=======================================
This program is an **independent encoder**.  It was written from
SPEC_GROUP.md and it imports nothing from the client, from `otrv4_core`, or
from any future group implementation.  Its signatures come from
`ed448_rfc8032.py`, a transcription of the RFC 8032 reference algorithm that
shares no code with `ed448-goldilocks-plus`.

That independence is the entire value of the output.  SPEC_GROUP.md §15.2:

    A vector produced by the code it is meant to check proves only that the
    code agrees with itself.

So: when the group implementation lands and disagrees with a vector, the
answer is **not** to regenerate the vectors.  It is to work out which of the
two read the specification correctly.  Regenerating from the implementation
under test destroys the only thing these files are for.

If the specification itself changes, bump `VECTOR_SET_VERSION`, keep the old
file, and say in the commit message what changed and why.

THE KEYS IN THE OUTPUT ARE PUBLISHED PRIVATE KEYS
=================================================
Every seed here is derived from a fixed string and written into the JSON in
the clear.  They exist so a third party can reproduce the vectors without
running this program.  They are not secret, must never be used for anything,
and no code path outside `tests/` may read this file.

Usage:
    python3 tests/group_vectors/generate_group_vectors.py            # check
    python3 tests/group_vectors/generate_group_vectors.py --write    # emit
"""

import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ed448_rfc8032 as ed448     # noqa: E402  (path set above)

VECTOR_SET_VERSION = 1
SPEC = "SPEC_GROUP.md version 1 (draft)"
OUTPUT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                      "group_vectors_v1.json")

# --------------------------------------------------------------- §1.2 domain
GROUP_DOMAIN = b"OTRv4Plus_Group_v1" + b"\x00"
SPEC_VERSION = 0x01

TAG_MEMBER_ENTRY = 0x01
TAG_MEMBER_SET = 0x02
TAG_GROUP_STATE = 0x03
TAG_COMMIT = 0x04
TAG_PROPOSAL = 0x05
TAG_VOTE = 0x06
TAG_ENVELOPE = 0x07

ROLE_MEMBER = 0x01
ROLE_ADMIN = 0x02

T_GENESIS = 0x01
T_JOIN = 0x02
T_LEAVE = 0x03
T_REVOKE = 0x04
T_POLICY_CHANGE = 0x07

POLICY_ADMIN_ONLY = 0x01
POLICY_THRESHOLD = 0x02

VERDICT_FOR = 0x01

ZERO_STATE_HASH = b"\x00" * 64          # §4.1, epoch 0's previous_state_hash


# ------------------------------------------------------------- §1 primitives
def u8(value):
    return bytes([value])


def u32be(value):
    return value.to_bytes(4, "big")


def u64be(value):
    return value.to_bytes(8, "big")


def LEN(data):
    """§1: four bytes, big-endian.  Not eight.  See the note in the spec."""
    return u32be(len(data)) + data


def H(data):
    """§1: SHA3-512, 64 bytes."""
    return hashlib.sha3_512(data).digest()


def prefix(tag):
    return GROUP_DOMAIN + u8(SPEC_VERSION) + u8(tag)


# --------------------------------------------------------------- §3 identity
class Device:
    """A test participant.  A device, not an account (§3)."""

    def __init__(self, name, jid):
        self.name = name
        self.jid = jid
        # Fixed derivation so the seeds are reproducible without this file.
        self.seed = hashlib.shake_256(
            b"OTRv4Plus group test vector seed v1|" + name.encode()
        ).digest(57)
        self.identity_pub = ed448.public_key(self.seed)

    def sign(self, message):
        return ed448.sign(self.seed, message)


def member_entry(device, role, joined_epoch):
    """§3.  `jid` is display metadata; it is in the signed bytes but MUST NOT
    be used for ordering, comparison or authorisation."""
    return (prefix(TAG_MEMBER_ENTRY)
            + LEN(device.identity_pub)
            + LEN(device.jid.encode("utf-8"))
            + u8(role)
            + u64be(joined_epoch))


class Member:
    """An entry in a member set: a device with its role and joining epoch."""

    def __init__(self, device, role, joined_epoch):
        self.device = device
        self.role = role
        self.joined_epoch = joined_epoch

    @property
    def key(self):
        return self.device.identity_pub

    def encode(self):
        return member_entry(self.device, self.role, self.joined_epoch)


def sort_members(members):
    """§2: sort by the 57-byte identity public key as unsigned bytes.

    Never by JID (mutable, can collide) and never by the encoded entry -- the
    spec warns that those coincide today and says not to rely on it.
    """
    return sorted(members, key=lambda m: m.key)


def member_set_hash(members):
    """§4."""
    ordered = sort_members(members)
    body = prefix(TAG_MEMBER_SET) + u32be(len(ordered))
    for member in ordered:
        body += member.encode()
    return H(body)


# ------------------------------------------------------------ §4 group state
def group_state(group_id, epoch, previous_state_hash, set_hash,
                policy_id=POLICY_ADMIN_ONLY, policy_params=b""):
    return (prefix(TAG_GROUP_STATE)
            + LEN(group_id)
            + u64be(epoch)
            + LEN(previous_state_hash)
            + LEN(set_hash)
            + u8(policy_id)
            + LEN(policy_params))


def state_hash(encoded_state):
    return H(encoded_state)


def genesis_group_id(founder_pub, nonce):
    """§4.1.  Truncated to 32 bytes; the founder's key is bound in, so a
    group_id cannot be claimed by someone who did not create it."""
    assert len(nonce) == 32
    return H(prefix(TAG_GROUP_STATE) + LEN(founder_pub) + LEN(nonce))[:32]


class State:
    """A verified head: everything a member needs to check the next commit."""

    def __init__(self, group_id, epoch, previous_state_hash, members,
                 policy_id=POLICY_ADMIN_ONLY, policy_params=b""):
        self.group_id = group_id
        self.epoch = epoch
        self.previous_state_hash = previous_state_hash
        self.members = sort_members(list(members))
        self.policy_id = policy_id
        self.policy_params = policy_params
        self.member_set_hash = member_set_hash(self.members)
        self.encoded = group_state(group_id, epoch, previous_state_hash,
                                   self.member_set_hash, policy_id,
                                   policy_params)
        self.state_hash = state_hash(self.encoded)

    def with_members(self, members, policy_id=None, policy_params=None):
        """The child state produced by applying a transition (§6 condition 7:
        the receiver recomputes this; a commit does not get to assert it)."""
        return State(
            self.group_id, self.epoch + 1, self.state_hash, members,
            self.policy_id if policy_id is None else policy_id,
            self.policy_params if policy_params is None else policy_params)


# -------------------------------------------------------------- §6 transitions
def commit_body(group_id, new_epoch, previous_state_hash,
                new_member_set_hash, transition_type, transition_data,
                evidence, signer_pub):
    return (prefix(TAG_COMMIT)
            + LEN(group_id)
            + u64be(new_epoch)
            + LEN(previous_state_hash)
            + LEN(new_member_set_hash)
            + u8(transition_type)
            + LEN(transition_data)
            + LEN(evidence)
            + LEN(signer_pub))


class Commit:
    def __init__(self, parent, signer, transition_type, transition_data,
                 child, evidence=b""):
        self.parent = parent
        self.signer = signer
        self.transition_type = transition_type
        self.transition_data = transition_data
        self.child = child
        self.evidence = evidence
        self.body = commit_body(
            parent.group_id, parent.epoch + 1, parent.state_hash,
            child.member_set_hash, transition_type, transition_data,
            evidence, signer.identity_pub)
        self.signature = signer.sign(self.body)
        self.commit_id = H(self.body + self.signature)


# ----------------------------------------------------------- §7.1 proposals
def proposal_body(group_id, epoch, proposal_id, transition_type,
                  transition_data, proposer_pub):
    return (prefix(TAG_PROPOSAL)
            + LEN(group_id) + u64be(epoch)
            + LEN(proposal_id)
            + u8(transition_type)
            + LEN(transition_data)
            + LEN(proposer_pub))


def vote_body(group_id, epoch, proposal_id, proposal_hash, verdict,
              voter_pub):
    return (prefix(TAG_VOTE)
            + LEN(group_id) + u64be(epoch)
            + LEN(proposal_id)
            + LEN(proposal_hash)
            + u8(verdict)
            + LEN(voter_pub))


# ------------------------------------------------------------- §9 envelope
def envelope(group_id, epoch, message_id, payload):
    return (prefix(TAG_ENVELOPE)
            + LEN(group_id)
            + u64be(epoch)
            + LEN(message_id)
            + LEN(payload))


# ------------------------------------------------------------------ actors
ALICE = Device("alice", "alice@example.i2p")
BOB = Device("bob", "bob@example.i2p")
CAROL = Device("carol", "carol@example.i2p")
DAVE = Device("dave", "dave@example.i2p")
MALLORY = Device("mallory", "mallory@example.i2p")
# A second device claiming Bob's JID.  §3: two entries with the same JID and
# different identity keys are two members, and the JID proves nothing.
BOB_IMPOSTOR = Device("bob-impostor", "bob@example.i2p")
UNICODE = Device("unicode", "zoë@example.i2p")

ACTORS = [ALICE, BOB, CAROL, DAVE, MALLORY, BOB_IMPOSTOR, UNICODE]

GENESIS_NONCE = bytes(range(32))


def hexed(value):
    return value.hex()


def build():
    vectors = {}

    # ---- 1. canonical member serialisation -----------------------------
    entries = []
    for device, role, epoch, note in (
        (ALICE, ROLE_ADMIN, 0, "founder: ADMIN at epoch 0"),
        (BOB, ROLE_MEMBER, 1, "ordinary member"),
        (UNICODE, ROLE_MEMBER, 2, "non-ASCII JID, UTF-8 encoded"),
        (BOB_IMPOSTOR, ROLE_MEMBER, 3,
         "same JID as bob, different key: a different member (§3)"),
        (DAVE, ROLE_ADMIN, 0xFFFFFFFFFFFFFFFF, "joined_epoch at uint64 max"),
    ):
        encoded = member_entry(device, role, epoch)
        entries.append({
            "note": note,
            "identity_pub": hexed(device.identity_pub),
            "jid": device.jid,
            "jid_utf8": hexed(device.jid.encode("utf-8")),
            "role": role,
            "joined_epoch": epoch,
            "encoded": hexed(encoded),
            "encoded_len": len(encoded),
        })
    vectors["01_member_entry"] = {
        "spec": "§3",
        "note": ("The encoding is domain ‖ version ‖ 0x01 ‖ LEN(pub) ‖ "
                 "LEN(jid) ‖ u8(role) ‖ u64be(joined_epoch). Every entry is "
                 "the same length because both variable fields are "
                 "length-prefixed, not because either is fixed."),
        "cases": entries,
    }

    # ---- 2. member set ordering ----------------------------------------
    roster = [Member(ALICE, ROLE_ADMIN, 0),
              Member(BOB, ROLE_MEMBER, 1),
              Member(CAROL, ROLE_MEMBER, 1),
              Member(UNICODE, ROLE_MEMBER, 2)]
    ordered = sort_members(roster)
    by_jid = sorted(roster, key=lambda m: m.device.jid)
    vectors["02_member_set"] = {
        "spec": "§2, §4",
        "note": ("Sorted by the 57-byte identity key as unsigned bytes. The "
                 "JID order is given only to show it differs: an "
                 "implementation that sorts by JID produces a different hash "
                 "and every signature over it fails."),
        "members": [
            {"name": m.device.name, "identity_pub": hexed(m.key),
             "role": m.role, "joined_epoch": m.joined_epoch}
            for m in roster],
        "order_by_identity_key": [m.device.name for m in ordered],
        "order_by_jid_do_not_use": [m.device.jid for m in by_jid],
        "member_set_hash": hexed(member_set_hash(roster)),
        "member_set_hash_is_order_independent_input": hexed(
            member_set_hash(list(reversed(roster)))),
        "empty_set_hash": hexed(member_set_hash([])),
        "single_member_set_hash": hexed(
            member_set_hash([Member(ALICE, ROLE_ADMIN, 0)])),
    }

    # ---- 3. genesis -----------------------------------------------------
    group_id = genesis_group_id(ALICE.identity_pub, GENESIS_NONCE)
    genesis_members = [Member(ALICE, ROLE_ADMIN, 0)]
    genesis = State(group_id, 0, ZERO_STATE_HASH, genesis_members)
    # No genesis COMMIT vector is emitted, and that is deliberate. §6.1
    # verifies a commit against a parent state, and genesis has no parent:
    # conditions 2, 3, 4 and 6 have nothing to check against. A member joins
    # by being handed the genesis state itself and pinning it (§5: a second
    # genesis for one group_id is an error, not an alternative history).
    # Emitting a T_GENESIS commit here would invite an implementer to verify
    # it with the ordinary path, which cannot work.
    vectors["03_genesis"] = {
        "spec": "§4.1",
        "note": ("group_id binds the founder's identity key, so two groups "
                 "collide only if that key does. previous_state_hash at "
                 "epoch 0 is 64 zero bytes."),
        "founder": ALICE.name,
        "founder_identity_pub": hexed(ALICE.identity_pub),
        "nonce": hexed(GENESIS_NONCE),
        "group_id": hexed(group_id),
        "group_id_preimage": hexed(prefix(TAG_GROUP_STATE)
                                   + LEN(ALICE.identity_pub)
                                   + LEN(GENESIS_NONCE)),
        "epoch": 0,
        "previous_state_hash": hexed(ZERO_STATE_HASH),
        "member_set_hash": hexed(genesis.member_set_hash),
        "policy_id": POLICY_ADMIN_ONLY,
        "policy_params": "",
        "group_state_encoded": hexed(genesis.encoded),
        "state_hash": hexed(genesis.state_hash),
    }

    # ---- 4. JOIN --------------------------------------------------------
    after_bob_members = genesis.members + [Member(BOB, ROLE_MEMBER, 1)]
    after_bob = genesis.with_members(after_bob_members)
    join_bob = Commit(genesis, ALICE, T_JOIN,
                      member_entry(BOB, ROLE_MEMBER, 1), after_bob)
    vectors["04_join"] = {
        "spec": "§6",
        "note": ("transition_data is the joining member_entry. The receiver "
                 "applies it to the parent set and recomputes the hash "
                 "(condition 7); the commit does not get to assert it."),
        "parent_state_hash": hexed(genesis.state_hash),
        "parent_epoch": genesis.epoch,
        "signer": ALICE.name,
        "transition_type": T_JOIN,
        "transition_data": hexed(join_bob.transition_data),
        "evidence": "",
        "new_epoch": after_bob.epoch,
        "new_member_set_hash": hexed(after_bob.member_set_hash),
        "commit_encoded": hexed(join_bob.body),
        "commit_signature": hexed(join_bob.signature),
        "commit_id": hexed(join_bob.commit_id),
        "resulting_group_state": hexed(after_bob.encoded),
        "resulting_state_hash": hexed(after_bob.state_hash),
    }

    # Carol joins too -- the chain the later sections build on.
    after_carol_members = after_bob.members + [Member(CAROL, ROLE_MEMBER, 2)]
    after_carol = after_bob.with_members(after_carol_members)
    join_carol = Commit(after_bob, ALICE, T_JOIN,
                        member_entry(CAROL, ROLE_MEMBER, 2), after_carol)

    # ---- 5. LEAVE -------------------------------------------------------
    after_leave_members = [m for m in after_carol.members
                           if m.key != BOB.identity_pub]
    after_leave = after_carol.with_members(after_leave_members)
    leave_bob = Commit(after_carol, BOB, T_LEAVE, BOB.identity_pub,
                       after_leave)
    vectors["05_leave"] = {
        "spec": "§6, §7",
        "note": ("LEAVE is self-signed and needs no evidence under any "
                 "policy. transition_data is the leaving identity_pub, not a "
                 "member_entry."),
        "parent_state_hash": hexed(after_carol.state_hash),
        "parent_epoch": after_carol.epoch,
        "signer": BOB.name,
        "transition_type": T_LEAVE,
        "transition_data": hexed(BOB.identity_pub),
        "commit_encoded": hexed(leave_bob.body),
        "commit_signature": hexed(leave_bob.signature),
        "commit_id": hexed(leave_bob.commit_id),
        "resulting_member_set_hash": hexed(after_leave.member_set_hash),
        "resulting_state_hash": hexed(after_leave.state_hash),
    }

    # ---- 6. membership replacement --------------------------------------
    # Bob's device is revoked; a different device claiming the same JID joins.
    # The member set must not treat them as the same member.
    revoked_members = [m for m in after_carol.members
                       if m.key != BOB.identity_pub]
    after_revoke = after_carol.with_members(revoked_members)
    revoke_bob = Commit(after_carol, ALICE, T_REVOKE, BOB.identity_pub,
                        after_revoke)
    replaced_members = after_revoke.members + [
        Member(BOB_IMPOSTOR, ROLE_MEMBER, 4)]
    after_replace = after_revoke.with_members(replaced_members)
    join_impostor = Commit(after_revoke, ALICE, T_JOIN,
                           member_entry(BOB_IMPOSTOR, ROLE_MEMBER, 4),
                           after_replace)
    vectors["06_membership_replacement"] = {
        "spec": "§3, §6",
        "note": ("A REVOKE followed by a JOIN of a different device holding "
                 "the same JID. The two member sets differ, so the two state "
                 "hashes differ: an implementation that deduplicates by JID "
                 "produces the wrong hash for the second one."),
        "revoked_identity_pub": hexed(BOB.identity_pub),
        "replacement_identity_pub": hexed(BOB_IMPOSTOR.identity_pub),
        "shared_jid": BOB.jid,
        "revoke_commit_encoded": hexed(revoke_bob.body),
        "revoke_commit_signature": hexed(revoke_bob.signature),
        "revoke_commit_id": hexed(revoke_bob.commit_id),
        "state_after_revoke": hexed(after_revoke.state_hash),
        "join_commit_encoded": hexed(join_impostor.body),
        "join_commit_signature": hexed(join_impostor.signature),
        "join_commit_id": hexed(join_impostor.commit_id),
        "member_set_hash_after_replacement": hexed(
            after_replace.member_set_hash),
        "state_after_replacement": hexed(after_replace.state_hash),
    }

    # ---- 7. state hash chaining -----------------------------------------
    vectors["07_state_chain"] = {
        "spec": "§5",
        "note": ("Each epoch's previous_state_hash is the parent's "
                 "state_hash. A chain cannot be verified from a state alone: "
                 "it is the linkage that is checked."),
        "chain": [
            {"epoch": s.epoch,
             "previous_state_hash": hexed(s.previous_state_hash),
             "member_set_hash": hexed(s.member_set_hash),
             "group_state_encoded": hexed(s.encoded),
             "state_hash": hexed(s.state_hash),
             "members": [m.device.name for m in s.members]}
            for s in (genesis, after_bob, after_carol, after_revoke)],
    }

    # ---- 8/9. concurrency and equivocation ------------------------------
    # Two DIFFERENT signers, same parent: §8.1, converge on lowest commit_id.
    concurrent_a = Commit(after_carol, ALICE, T_JOIN,
                          member_entry(DAVE, ROLE_MEMBER, 3),
                          after_carol.with_members(
                              after_carol.members
                              + [Member(DAVE, ROLE_MEMBER, 3)]))
    concurrent_b = Commit(after_carol, CAROL, T_LEAVE, CAROL.identity_pub,
                          after_carol.with_members(
                              [m for m in after_carol.members
                               if m.key != CAROL.identity_pub]))
    winner = min((concurrent_a, concurrent_b), key=lambda c: c.commit_id)
    vectors["08_concurrent_commits"] = {
        "spec": "§8.1",
        "note": ("DIFFERENT signers off the same parent. Benign. Resolved by "
                 "the numerically lower commit_id, comparing 64 bytes "
                 "unsigned big-endian -- never by arrival order or "
                 "timestamp. Applying this rule to §8.2 is the mistake the "
                 "spec exists to prevent."),
        "parent_state_hash": hexed(after_carol.state_hash),
        "commit_a": {"signer": ALICE.name,
                     "encoded": hexed(concurrent_a.body),
                     "signature": hexed(concurrent_a.signature),
                     "commit_id": hexed(concurrent_a.commit_id)},
        "commit_b": {"signer": CAROL.name,
                     "encoded": hexed(concurrent_b.body),
                     "signature": hexed(concurrent_b.signature),
                     "commit_id": hexed(concurrent_b.commit_id)},
        "different_signers": True,
        "expected_resolution": "converge",
        "expected_winner": "commit_a" if winner is concurrent_a else "commit_b",
        "expected_winner_commit_id": hexed(winner.commit_id),
    }

    # Same signer, same parent, two different children: §8.2 EQUIVOCATION.
    equiv_a = Commit(after_carol, ALICE, T_JOIN,
                     member_entry(DAVE, ROLE_MEMBER, 3),
                     after_carol.with_members(
                         after_carol.members + [Member(DAVE, ROLE_MEMBER, 3)]))
    equiv_b = Commit(after_carol, ALICE, T_JOIN,
                     member_entry(MALLORY, ROLE_MEMBER, 3),
                     after_carol.with_members(
                         after_carol.members
                         + [Member(MALLORY, ROLE_MEMBER, 3)]))
    lower = min((equiv_a, equiv_b), key=lambda c: c.commit_id)
    vectors["09_equivocation"] = {
        "spec": "§8.2",
        "note": ("The SAME signer, two valid commits, one parent. This is an "
                 "attack, not concurrency. An implementation MUST branch on "
                 "who signed BEFORE it compares any commit_id."),
        "parent_state_hash": hexed(after_carol.state_hash),
        "signer": ALICE.name,
        "signer_identity_pub": hexed(ALICE.identity_pub),
        "commit_a": {"encoded": hexed(equiv_a.body),
                     "signature": hexed(equiv_a.signature),
                     "commit_id": hexed(equiv_a.commit_id)},
        "commit_b": {"encoded": hexed(equiv_b.body),
                     "signature": hexed(equiv_b.signature),
                     "commit_id": hexed(equiv_b.commit_id)},
        "same_signer": True,
        "both_signatures_valid": True,
        "expected_resolution": "equivocation_detected",
        "expected_epoch_advance": False,
        "expected_both_retained_as_evidence": True,
        "lowest_commit_id_do_not_use": hexed(lower.commit_id),
        "why_lowest_is_recorded": (
            "So a test can assert the implementation did NOT pick it. A "
            "conforming implementation reaches no winner here at all."),
    }

    # ---- 11. deterministic commit_id ------------------------------------
    repeat = Commit(genesis, ALICE, T_JOIN,
                    member_entry(BOB, ROLE_MEMBER, 1), after_bob)
    assert repeat.signature == join_bob.signature
    assert repeat.commit_id == join_bob.commit_id
    vectors["10_commit_id_determinism"] = {
        "spec": "§6",
        "note": ("Ed448 signing is deterministic, so the same commit body "
                 "signed by the same key twice yields byte-identical "
                 "signatures and one commit_id. A vector set could not exist "
                 "otherwise. This is a property of Ed448, NOT a security "
                 "requirement of the protocol: an implementation using a "
                 "randomised signature scheme would still be sound, and "
                 "would fail this vector."),
        "commit_encoded": hexed(join_bob.body),
        "signature_first": hexed(join_bob.signature),
        "signature_second": hexed(repeat.signature),
        "commit_id": hexed(join_bob.commit_id),
        "commit_id_preimage_len": len(join_bob.body) + len(join_bob.signature),
    }

    # ---- 12. Ed448 signature vectors ------------------------------------
    signature_cases = []
    for device in (ALICE, BOB, MALLORY):
        for message in (b"", b"\x00", b"OTRv4Plus", bytes(range(256))):
            signature = device.sign(message)
            signature_cases.append({
                "signer": device.name,
                "identity_pub": hexed(device.identity_pub),
                "message": hexed(message),
                "signature": hexed(signature),
                "valid": True,
            })
    vectors["11_ed448_signatures"] = {
        "spec": "§1, RFC 8032",
        "note": ("Produced by ed448_rfc8032.py, which reproduces the RFC "
                 "8032 §7.4 vectors exactly. These are raw Ed448 over the "
                 "given message with an empty context -- no group domain "
                 "separator is applied here; that belongs to the structures "
                 "being signed."),
        "seeds_are_public_test_material": True,
        "cases": signature_cases,
    }

    # ---- 13. rejection cases --------------------------------------------
    bad = []

    flipped = bytearray(join_bob.signature)
    flipped[0] ^= 0x01
    bad.append({
        "name": "signature bit flipped",
        "spec": "§6.1 condition 5",
        "commit_encoded": hexed(join_bob.body),
        "commit_signature": hexed(bytes(flipped)),
        "parent_state_hash": hexed(genesis.state_hash),
        "expected": "reject",
        "reason": "signature does not verify under signer_identity_pub",
    })

    wrong_key_sig = MALLORY.sign(join_bob.body)
    bad.append({
        "name": "signed by a key other than signer_identity_pub",
        "spec": "§6.1 condition 5",
        "commit_encoded": hexed(join_bob.body),
        "commit_signature": hexed(wrong_key_sig),
        "parent_state_hash": hexed(genesis.state_hash),
        "expected": "reject",
        "reason": ("the body names alice as signer; the signature verifies "
                   "only under mallory's key"),
    })

    truncated = join_bob.signature[:-1]
    bad.append({
        "name": "signature one byte short",
        "spec": "§1.1",
        "commit_encoded": hexed(join_bob.body),
        "commit_signature": hexed(truncated),
        "parent_state_hash": hexed(genesis.state_hash),
        "expected": "reject",
        "reason": "an Ed448 signature is 114 bytes",
    })
    vectors["12_invalid_signatures"] = {
        "spec": "§6.1",
        "note": "Every case here is a well-formed commit body.",
        "cases": bad,
    }

    # ---- 14. wrong parent -----------------------------------------------
    stale = Commit(genesis, ALICE, T_JOIN,
                   member_entry(DAVE, ROLE_MEMBER, 1),
                   genesis.with_members(
                       genesis.members + [Member(DAVE, ROLE_MEMBER, 1)]))
    skipping_body = commit_body(
        after_carol.group_id, after_carol.epoch + 2, after_carol.state_hash,
        after_carol.member_set_hash, T_JOIN,
        member_entry(DAVE, ROLE_MEMBER, 4), b"", ALICE.identity_pub)
    unknown_parent_body = commit_body(
        after_carol.group_id, after_carol.epoch + 1, H(b"not a real state"),
        after_carol.member_set_hash, T_JOIN,
        member_entry(DAVE, ROLE_MEMBER, 4), b"", ALICE.identity_pub)
    other_group_body = commit_body(
        genesis_group_id(MALLORY.identity_pub, GENESIS_NONCE),
        after_carol.epoch + 1, after_carol.state_hash,
        after_carol.member_set_hash, T_JOIN,
        member_entry(DAVE, ROLE_MEMBER, 4), b"", ALICE.identity_pub)
    vectors["13_wrong_parent"] = {
        "spec": "§6.1 conditions 1, 2, 3",
        "note": ("Each of these is correctly signed. They must be rejected "
                 "on the state check, before or regardless of the signature "
                 "-- and rejected, not queued as 'the future'."),
        "current_head_state_hash": hexed(after_carol.state_hash),
        "current_head_epoch": after_carol.epoch,
        "cases": [
            {"name": "applies to an older parent",
             "commit_encoded": hexed(stale.body),
             "commit_signature": hexed(stale.signature),
             "expected": "reject",
             "reason": "previous_state_hash is not the receiver's head "
                       "(condition 2)"},
            {"name": "epoch skips one",
             "commit_encoded": hexed(skipping_body),
             "commit_signature": hexed(ALICE.sign(skipping_body)),
             "expected": "reject",
             "reason": "new_epoch != parent epoch + 1 (condition 3)"},
            {"name": "parent hash never existed",
             "commit_encoded": hexed(unknown_parent_body),
             "commit_signature": hexed(ALICE.sign(unknown_parent_body)),
             "expected": "reject",
             "reason": "unlinkable parent: a fork (§8.3), surfaced not "
                       "resolved"},
            {"name": "correct shape, wrong group",
             "commit_encoded": hexed(other_group_body),
             "commit_signature": hexed(ALICE.sign(other_group_body)),
             "expected": "reject",
             "reason": "group_id does not match (condition 1)"},
        ],
    }

    # ---- 15. commits by a revoked member --------------------------------
    revoked_signer_body = commit_body(
        after_revoke.group_id, after_revoke.epoch + 1,
        after_revoke.state_hash, after_revoke.member_set_hash, T_JOIN,
        member_entry(DAVE, ROLE_MEMBER, 4), b"", BOB.identity_pub)
    outsider_body = commit_body(
        after_carol.group_id, after_carol.epoch + 1, after_carol.state_hash,
        after_carol.member_set_hash, T_JOIN,
        member_entry(MALLORY, ROLE_MEMBER, 3), b"", MALLORY.identity_pub)
    non_admin_body = commit_body(
        after_carol.group_id, after_carol.epoch + 1, after_carol.state_hash,
        after_carol.with_members(
            after_carol.members + [Member(DAVE, ROLE_MEMBER, 3)]
        ).member_set_hash,
        T_JOIN, member_entry(DAVE, ROLE_MEMBER, 3), b"", CAROL.identity_pub)
    vectors["14_unauthorised_signers"] = {
        "spec": "§6.1 conditions 4 and 6, §7",
        "note": ("Condition 4 is what makes revocation cryptographic rather "
                 "than advisory: the revoked key is absent from every "
                 "subsequent parent member set, so its commits fail forever "
                 "without any revocation list being consulted."),
        "cases": [
            {"name": "signed by a revoked device",
             "parent_state_hash": hexed(after_revoke.state_hash),
             "signer_identity_pub": hexed(BOB.identity_pub),
             "commit_encoded": hexed(revoked_signer_body),
             "commit_signature": hexed(BOB.sign(revoked_signer_body)),
             "expected": "reject",
             "reason": "signer is not in the parent member set (condition 4)"},
            {"name": "signed by a device that was never a member",
             "parent_state_hash": hexed(after_carol.state_hash),
             "signer_identity_pub": hexed(MALLORY.identity_pub),
             "commit_encoded": hexed(outsider_body),
             "commit_signature": hexed(MALLORY.sign(outsider_body)),
             "expected": "reject",
             "reason": "condition 4; note it is also a self-JOIN, which no "
                       "policy authorises"},
            {"name": "JOIN signed by a non-admin under ADMIN_ONLY",
             "parent_state_hash": hexed(after_carol.state_hash),
             "signer_identity_pub": hexed(CAROL.identity_pub),
             "commit_encoded": hexed(non_admin_body),
             "commit_signature": hexed(CAROL.sign(non_admin_body)),
             "expected": "reject",
             "reason": "policy 0x01 requires role = ADMIN for JOIN "
                       "(condition 6)"},
        ],
    }

    # ---- 16. malformed canonical encodings ------------------------------
    eight_byte_prefix = (prefix(TAG_MEMBER_ENTRY)
                         + len(ALICE.identity_pub).to_bytes(8, "big")
                         + ALICE.identity_pub
                         + len(ALICE.jid.encode()).to_bytes(8, "big")
                         + ALICE.jid.encode()
                         + u8(ROLE_ADMIN) + u64be(0))
    wrong_tag = (prefix(TAG_MEMBER_SET) + LEN(ALICE.identity_pub)
                 + LEN(ALICE.jid.encode()) + u8(ROLE_ADMIN) + u64be(0))
    trailing = member_entry(ALICE, ROLE_ADMIN, 0) + b"\x00"
    short_group_id = group_state(genesis.group_id[:31], 0, ZERO_STATE_HASH,
                                 genesis.member_set_hash)
    unsorted_body = (prefix(TAG_MEMBER_SET) + u32be(2))
    pair = sort_members([Member(ALICE, ROLE_ADMIN, 0),
                         Member(BOB, ROLE_MEMBER, 1)])
    unsorted_body += pair[1].encode() + pair[0].encode()
    count_lies = (prefix(TAG_MEMBER_SET) + u32be(3)
                  + pair[0].encode() + pair[1].encode())
    vectors["15_malformed_encodings"] = {
        "spec": "§2",
        "note": ("§2's re-encoding rule: reject a structure whose "
                 "re-encoding does not reproduce the bytes received. It MUST "
                 "be enforced on receipt, not on send -- a sender that "
                 "happens to be canonical proves nothing about a peer."),
        "cases": [
            {"name": "eight-byte length prefixes",
             "bytes": hexed(eight_byte_prefix),
             "expected": "reject",
             "reason": "LEN is four bytes big-endian (§1). An eight-byte "
                       "prefix in a Rust draft made every frame fail its tag "
                       "with no diagnostic."},
            {"name": "member entry carrying the member-set context tag",
             "bytes": hexed(wrong_tag),
             "expected": "reject",
             "reason": "context tags separate the structures (§1.2)"},
            {"name": "trailing byte after a complete member entry",
             "bytes": hexed(trailing),
             "expected": "reject",
             "reason": "re-encoding does not reproduce the input (§2)"},
            {"name": "group_id of 31 bytes",
             "bytes": hexed(short_group_id),
             "expected": "reject",
             "reason": "group_id is 32 bytes (§1.1); the length prefix "
                       "parses, the value is still wrong"},
            {"name": "member set in descending key order",
             "bytes": hexed(unsorted_body),
             "expected": "reject",
             "reason": "members are sorted ascending by identity key (§2)"},
            {"name": "count field larger than the entries present",
             "bytes": hexed(count_lies),
             "expected": "reject",
             "reason": "truncated input; must not be read past the end"},
        ],
    }

    # ---- 17. complete commit verification -------------------------------
    vectors["16_complete_verification"] = {
        "spec": "§6.1",
        "note": ("One fixture carrying everything the eight conditions need. "
                 "A verifier given the parent state and this commit must "
                 "accept; each mutation listed must be rejected for the "
                 "stated condition."),
        "parent": {
            "group_id": hexed(after_bob.group_id),
            "epoch": after_bob.epoch,
            "previous_state_hash": hexed(after_bob.previous_state_hash),
            "members": [
                {"identity_pub": hexed(m.key), "jid": m.device.jid,
                 "role": m.role, "joined_epoch": m.joined_epoch}
                for m in after_bob.members],
            "member_set_hash": hexed(after_bob.member_set_hash),
            "policy_id": after_bob.policy_id,
            "policy_params": hexed(after_bob.policy_params),
            "group_state_encoded": hexed(after_bob.encoded),
            "state_hash": hexed(after_bob.state_hash),
        },
        "commit": {
            "signer": ALICE.name,
            "signer_identity_pub": hexed(ALICE.identity_pub),
            "transition_type": T_JOIN,
            "transition_data": hexed(join_carol.transition_data),
            "evidence": "",
            "new_epoch": after_carol.epoch,
            "new_member_set_hash": hexed(after_carol.member_set_hash),
            "encoded": hexed(join_carol.body),
            "signature": hexed(join_carol.signature),
            "commit_id": hexed(join_carol.commit_id),
        },
        "expected": "accept",
        "resulting_state": {
            "epoch": after_carol.epoch,
            "member_set_hash": hexed(after_carol.member_set_hash),
            "group_state_encoded": hexed(after_carol.encoded),
            "state_hash": hexed(after_carol.state_hash),
            "members": [m.device.name for m in after_carol.members],
        },
        "conditions": {
            "1": "group_id matches",
            "2": "previous_state_hash equals the parent state_hash",
            "3": "new_epoch is parent epoch + 1",
            "4": "signer is in the parent member set and not revoked",
            "5": "signature verifies",
            "6": "ADMIN_ONLY: signer is ADMIN in the parent; evidence empty",
            "7": "applying transition_data to the parent set reproduces "
                 "new_member_set_hash",
            "8": "the commit re-encodes to the bytes received",
        },
    }

    # ---- 18. threshold votes (beyond the fifteen; §7.1 needs vectors too)
    threshold_params = (2).to_bytes(2, "big") + (3).to_bytes(2, "big")
    threshold_state = State(after_carol.group_id, after_carol.epoch,
                            after_carol.previous_state_hash,
                            after_carol.members,
                            POLICY_THRESHOLD, threshold_params)
    proposal_id = bytes(range(16))
    revoke_target = CAROL
    prop = proposal_body(threshold_state.group_id, threshold_state.epoch,
                         proposal_id, T_REVOKE, revoke_target.identity_pub,
                         ALICE.identity_pub)
    prop_sig = ALICE.sign(prop)
    prop_hash = H(prop + prop_sig)
    votes = []
    for voter in (ALICE, BOB):
        body = vote_body(threshold_state.group_id, threshold_state.epoch,
                         proposal_id, prop_hash, VERDICT_FOR,
                         voter.identity_pub)
        votes.append((voter, body, voter.sign(body)))
    # §2: evidence is the canonical sorted concatenation.  Sorted by the
    # voter's identity key, for the same reason member sets are.
    votes.sort(key=lambda item: item[0].identity_pub)
    evidence = b"".join(body + signature for _voter, body, signature in votes)
    revoke_members = [m for m in threshold_state.members
                      if m.key != revoke_target.identity_pub]
    threshold_child = threshold_state.with_members(revoke_members)
    threshold_commit = Commit(threshold_state, ALICE, T_REVOKE,
                              revoke_target.identity_pub, threshold_child,
                              evidence=evidence)
    members_count = len(threshold_state.members)
    required = -(-2 * members_count // 3)
    vectors["17_threshold_votes"] = {
        "spec": "§7, §7.1",
        "note": ("The tally is evidence, not a claim: the committer includes "
                 "the votes it counted and every other member re-tallies "
                 "them. The revocation target's own vote MUST NOT count, and "
                 "a vote binds the hash of the proposal, not only its id."),
        "policy_id": POLICY_THRESHOLD,
        "policy_params": hexed(threshold_params),
        "numerator": 2, "denominator": 3,
        "member_count": members_count,
        "votes_required": required,
        "revocation_target": revoke_target.name,
        "proposal_id": hexed(proposal_id),
        "proposal_encoded": hexed(prop),
        "proposal_signature": hexed(prop_sig),
        "proposal_hash": hexed(prop_hash),
        "votes": [
            {"voter": voter.name, "encoded": hexed(body),
             "signature": hexed(signature)}
            for voter, body, signature in votes],
        "evidence": hexed(evidence),
        "commit_encoded": hexed(threshold_commit.body),
        "commit_signature": hexed(threshold_commit.signature),
        "commit_id": hexed(threshold_commit.commit_id),
        "expected": "accept",
        "resulting_state_hash": hexed(threshold_child.state_hash),
    }

    # ---- 19. message envelope (§9) --------------------------------------
    message_id = bytes(range(16, 32))
    envelope_cases = []
    for payload, note in ((b"hello", "ordinary text"),
                          (b"", "empty payload"),
                          ("héllo".encode("utf-8"), "UTF-8 payload")):
        encoded = envelope(after_carol.group_id, after_carol.epoch,
                           message_id, payload)
        envelope_cases.append({
            "note": note,
            "group_id": hexed(after_carol.group_id),
            "epoch": after_carol.epoch,
            "message_id": hexed(message_id),
            "payload": hexed(payload),
            "encoded": hexed(encoded),
        })
    vectors["18_message_envelope"] = {
        "spec": "§9, §9.1",
        "note": ("The envelope is NOT signed, deliberately: the two-party "
                 "channel already authenticates the sender deniably, and a "
                 "signature would replace a deniable property with a "
                 "non-deniable one. There is no signature field to omit -- "
                 "an implementation that adds one is not implementing this "
                 "specification."),
        "signed": False,
        "cases": envelope_cases,
    }

    return {
        "vector_set_version": VECTOR_SET_VERSION,
        "spec": SPEC,
        "generated_by": ("tests/group_vectors/generate_group_vectors.py, an "
                         "encoder written from the specification. Signatures "
                         "from ed448_rfc8032.py (RFC 8032 reference "
                         "algorithm, verified against RFC 8032 §7.4). "
                         "Nothing here calls the implementation these "
                         "vectors test -- see SPEC_GROUP.md §15.2."),
        "warning": ("The seeds below are PUBLISHED PRIVATE KEYS for test use "
                    "only. They must never appear in anything but a test."),
        "constants": {
            "GROUP_DOMAIN": hexed(GROUP_DOMAIN),
            "GROUP_DOMAIN_ascii": GROUP_DOMAIN[:-1].decode(),
            "SPEC_VERSION": SPEC_VERSION,
            "context_tags": {
                "member_entry": TAG_MEMBER_ENTRY,
                "member_set": TAG_MEMBER_SET,
                "group_state": TAG_GROUP_STATE,
                "commit": TAG_COMMIT,
                "proposal": TAG_PROPOSAL,
                "vote": TAG_VOTE,
                "envelope": TAG_ENVELOPE,
            },
            "hash": "SHA3-512",
            "length_prefix_bytes": 4,
            "sizes": {"identity_pub": 57, "signature": 114, "digest": 64,
                      "group_id": 32, "message_id": 16, "proposal_id": 16},
        },
        "actors": {
            device.name: {
                "seed": hexed(device.seed),
                "seed_derivation": ("SHAKE256('OTRv4Plus group test vector "
                                    "seed v1|' + name, 57)"),
                "identity_pub": hexed(device.identity_pub),
                "jid": device.jid,
            } for device in ACTORS
        },
        "vectors": build_ordered(vectors),
    }


def build_ordered(vectors):
    return {key: vectors[key] for key in sorted(vectors)}


def main():
    ed448._self_check()
    skipped = ed448.cross_check_against_core()
    if skipped:
        print("note: no cross-check against otrv4_core (%s)" % skipped)
    else:
        print("Ed448 cross-checked against otrv4_core: ok")

    generated = build()
    rendered = json.dumps(generated, indent=2, ensure_ascii=False,
                          sort_keys=False) + "\n"

    if "--write" in sys.argv:
        with open(OUTPUT, "w", encoding="utf-8") as handle:
            handle.write(rendered)
        print("wrote %s (%d bytes, %d sections)"
              % (OUTPUT, len(rendered), len(generated["vectors"])))
        return 0

    if not os.path.exists(OUTPUT):
        print("%s does not exist; run with --write" % OUTPUT)
        return 1
    with open(OUTPUT, encoding="utf-8") as handle:
        existing = handle.read()
    if existing == rendered:
        print("%s is reproducible from this generator" % OUTPUT)
        return 0
    print("MISMATCH: the committed vectors differ from a fresh generation.\n"
          "Do not regenerate to make a failing implementation pass -- work "
          "out which side misread the spec first.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
