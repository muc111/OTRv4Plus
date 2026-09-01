# OTRv4+ Group Protocol Specification

**Version:** 1 (draft)
**Status:** specification only. No implementation exists.
**Companion to:** [SPEC.md](SPEC.md), which specifies the two-party protocol
this one is built on and does not replace.

---

## 0. Preface

### 0.1 What this is

An **authenticated group-state layer over independent hybrid OTRv4+ pairwise
channels.**

It is deliberately *not* "group OTR". There is no group cipher, no group key,
no group ratchet and no group key schedule. Two things are specified here and
nothing else:

1. an authenticated, append-only record of **who is in the group** and **what
   the current group state is**;
2. an envelope that binds a message to a group and an epoch.

The message contents are encrypted and authenticated entirely by the existing
two-party channel of SPEC.md. This document adds no confidentiality mechanism
of its own.

### 0.2 Why there is no group key

The audit in [GROUP_CRYPTO_AUDIT.md](GROUP_CRYPTO_AUDIT.md) established that
every pair of members already has a channel that is hybrid post-quantum
(X448 + ML-KEM-1024), DAKE-authenticated and transcript-bound. Sending a group
message independently to each member over those channels inherits all of it.

A shared group secret would replace `n−1` encryptions with one, and would cost
a group key agreement that has to be designed, specified and analysed. At the
group sizes this protocol targets that is a bad trade. The consequence — and
it is a real one — is in §13.1.

### 0.3 The line this specification must not cross

Implementations MUST NOT introduce, and this specification does not contain,
any of the following:

* a mechanism combining several ML-KEM shared secrets into a group secret;
* a group ratchet, group KDF, group combiner or group AEAD key schedule;
* sender-key distribution;
* ML-KEM retrofitted into an MLS key schedule;
* any construction whose security depends on a novel interaction between
  ML-KEM, Ed448, the two-party ratchet and group state.

The following are **not** new cryptography and are what this specification
uses: Ed448 signatures over canonically serialised structures, SHA3-512 over
those structures, a hash chain, epoch counters, membership-set hashes, and the
existing two-party channel used unchanged.

If a proposed change requires anything from the first list, it requires
cryptographic review before implementation, not after.

---

## 1. Notation

| | |
|---|---|
| `LEN(x)` | `uint32be(len(x)) ‖ x` — **four** bytes, big-endian |
| `uint8`, `uint32be`, `uint64be` | unsigned, big-endian |
| `H(x)` | SHA3-512, 64 bytes |
| `SIG(k, m)` | Ed448 signature under identity key `k`, 114 bytes |
| `‖` | concatenation |

The four-byte length prefix is not arbitrary: it is the convention used
throughout this project, and an eight-byte prefix in one Rust draft made every
frame fail its tag with no error and no diagnostic. Use four.

### 1.1 Fixed sizes

| Field | Bytes |
|---|---|
| Ed448 identity public key | 57 |
| Ed448 signature | 114 |
| SHA3-512 digest | 64 |
| GroupID | 32 |
| MessageID | 16 |
| ProposalID | 16 |

### 1.2 Domain separator

```
GROUP_DOMAIN = "OTRv4Plus_Group_v1" ‖ 0x00
SPEC_VERSION = 0x01
```

Every hash and every signature in this document is computed over a byte string
beginning with `GROUP_DOMAIN ‖ SPEC_VERSION ‖ <context tag>`. The context tags
are distinct per structure, so no byte string valid in one position can be
reinterpreted in another.

| Context | Tag |
|---|---|
| Member entry | `0x01` |
| Member set | `0x02` |
| Group state | `0x03` |
| Commit | `0x04` |
| Proposal | `0x05` |
| Vote | `0x06` |
| Message envelope | `0x07` |

---

## 2. Canonical encoding

Signatures are worthless if two implementations serialise the same state
differently. Every structure below has exactly one valid encoding.

An implementation MUST:

* emit fields in the order given, with no padding and no optional fields;
* length-prefix every variable-length field with `LEN`;
* sort the member set by the **57-byte identity public key**, compared as
  unsigned bytes, ascending — never by JID, which is mutable and can collide.
  Sorting the *encoded entries* happens to give the same order today, because
  every identity key is the same length and the key is the first
  variable-length field; do not rely on that. Sort by the key;
* reject a received structure whose re-encoding does not reproduce the bytes
  received, rather than accepting a second encoding of the same content.

That last rule is the one that prevents signature-stripping and
malleability games; it MUST be enforced on receipt, not on send.

---

## 3. Identity

A participant is a **device**, not an account.

```
member_entry =
      GROUP_DOMAIN ‖ SPEC_VERSION ‖ 0x01
    ‖ LEN(identity_pub)          // 57 bytes, Ed448
    ‖ LEN(jid)                   // UTF-8, informational
    ‖ uint8(role)
    ‖ uint64be(joined_epoch)
```

`identity_pub` is the device's long-term Ed448 identity key — the same key
`otrv4plus_identity.py` persists and TOFU-pins per JID. Nothing new is
generated for group membership.

`jid` is **display metadata only.** It MUST NOT be used for authorisation,
membership comparison, deduplication or ordering. Two entries with the same
JID and different identity keys are two members.

`role` is `0x01` MEMBER or `0x02` ADMIN. Its meaning is defined by the policy
in §7 and by nothing else.

> **Multi-device is out of scope for version 1.** The encoding above already
> supports one account holding several devices — each is its own entry — so no
> format change is needed later. What version 1 does not specify is how a
> device list is published and authenticated, which is a separate problem with
> its own attack surface.

---

## 4. Group state

```
member_set_hash =
    H( GROUP_DOMAIN ‖ SPEC_VERSION ‖ 0x02
     ‖ uint32be(count)
     ‖ member_entry[0] ‖ member_entry[1] ‖ … )      // sorted, §2

group_state =
      GROUP_DOMAIN ‖ SPEC_VERSION ‖ 0x03
    ‖ LEN(group_id)                 // 32
    ‖ uint64be(epoch)
    ‖ LEN(previous_state_hash)      // 64
    ‖ LEN(member_set_hash)          // 64
    ‖ uint8(policy_id)
    ‖ LEN(policy_params)

state_hash = H(group_state)
```

`state_hash` is what the next epoch's `previous_state_hash` refers to. The
member set itself is not carried in the state — only its hash — so a member
who has the set can verify it, and one who does not can still verify the
chain.

### 4.1 Genesis

```
group_id = H( GROUP_DOMAIN ‖ SPEC_VERSION ‖ 0x03
            ‖ LEN(founder_identity_pub)
            ‖ LEN(nonce) )[0:32]              // nonce: 32 random bytes
```

At epoch 0, `previous_state_hash` is 64 zero bytes. The genesis member set
contains exactly one entry: the founder, with `role = ADMIN` and
`joined_epoch = 0`.

Binding the founder's key into `group_id` means two groups cannot collide
except by the founder's own key colliding, and a `group_id` cannot be claimed
by someone who did not create it.

---

## 5. The state chain

```
epoch 0            epoch 1            epoch 2
state_hash S0  ──▶ prev = S0      ──▶ prev = S1
                   state_hash S1      state_hash S2
```

Every epoch after 0 is produced by exactly one **commit**. A member's view of
the group is the state at the head of the chain it has verified.

An implementation MUST NOT accept a state it cannot link to the genesis it
already holds. A group is identified by `group_id` **and** by its genesis
`state_hash`; a second genesis for the same `group_id` is an error, not an
alternative history.

---

## 6. Transitions

```
commit =
      GROUP_DOMAIN ‖ SPEC_VERSION ‖ 0x04
    ‖ LEN(group_id)
    ‖ uint64be(new_epoch)
    ‖ LEN(previous_state_hash)      // the parent this applies to
    ‖ LEN(new_member_set_hash)
    ‖ uint8(transition_type)
    ‖ LEN(transition_data)
    ‖ LEN(evidence)
    ‖ LEN(signer_identity_pub)

commit_signature = SIG(signer, commit)
commit_id        = H(commit ‖ commit_signature)
```

| Type | Value | `transition_data` |
|---|---|---|
| GENESIS | `0x01` | the founder's `member_entry` |
| JOIN | `0x02` | the joining `member_entry` |
| LEAVE | `0x03` | the leaving `identity_pub` |
| REVOKE | `0x04` | the revoked `identity_pub` |
| DEVICE_ADD | `0x05` | reserved, version 2 |
| DEVICE_REMOVE | `0x06` | reserved, version 2 |
| POLICY_CHANGE | `0x07` | new `policy_id ‖ LEN(policy_params)` |

`evidence` is the canonical, sorted concatenation of the authorisation objects
the policy requires (§7) — empty where the policy requires none.

### 6.1 Verifying a commit

A receiver MUST reject the commit unless **all** hold:

1. `group_id` matches the group it is being applied to;
2. `previous_state_hash` equals the receiver's current `state_hash`;
3. `new_epoch` equals the receiver's current epoch + 1;
4. `signer_identity_pub` is in the member set **of the parent state**, and is
   not revoked in it;
5. the signature verifies under `signer_identity_pub`;
6. the transition is authorised under the parent state's policy, and
   `evidence` proves it (§7);
7. applying `transition_data` to the parent member set yields exactly
   `new_member_set_hash`;
8. the re-encoding rule of §2 holds.

Condition 4 is the one that makes revocation cryptographic rather than
advisory: a revoked device is absent from every subsequent member set, so
every commit it signs fails at step 4 forever.

Condition 7 is what stops a signer claiming an arbitrary new member set. The
receiver recomputes it; the commit does not get to assert it.

---

## 7. Authorisation policy

The policy is a **field of the group state**, not a constant in the code, so
it is auditable and changeable by a POLICY_CHANGE transition rather than by a
release.

| `policy_id` | Name | `policy_params` |
|---|---|---|
| `0x01` | ADMIN_ONLY | empty |
| `0x02` | THRESHOLD | `uint16be(numerator) ‖ uint16be(denominator)` |

**`0x01` ADMIN_ONLY.** JOIN, REVOKE and POLICY_CHANGE require a signer with
`role = ADMIN` in the parent state. `evidence` is empty. LEAVE is always
self-signed and needs no authorisation.

**`0x02` THRESHOLD.** REVOKE requires votes from at least
`ceil(numerator × |members| / denominator)` distinct non-revoked members of
the parent state, excluding the revocation target. `evidence` is the sorted
concatenation of those votes. JOIN follows the same rule.

The default for version 1 is `0x01` ADMIN_ONLY, because it is simpler, its
failure mode is comprehensible, and §13.4 explains why a threshold is not
obviously safer.

### 7.1 Proposals and votes

```
proposal =
      GROUP_DOMAIN ‖ SPEC_VERSION ‖ 0x05
    ‖ LEN(group_id) ‖ uint64be(epoch)
    ‖ LEN(proposal_id)              // 16 random bytes
    ‖ uint8(transition_type)
    ‖ LEN(transition_data)
    ‖ LEN(proposer_identity_pub)
proposal_signature = SIG(proposer, proposal)

vote =
      GROUP_DOMAIN ‖ SPEC_VERSION ‖ 0x06
    ‖ LEN(group_id) ‖ uint64be(epoch)
    ‖ LEN(proposal_id)
    ‖ LEN(H(proposal ‖ proposal_signature))
    ‖ uint8(verdict)                // 0x01 for, 0x02 against
    ‖ LEN(voter_identity_pub)
vote_signature = SIG(voter, vote)
```

A vote binds the group, the epoch, the proposal identifier **and the hash of
the proposal itself**. Binding only the identifier would let a proposer alter
a proposal after votes were cast for it.

A counter MUST reject a vote that: is signed by a device outside the parent
member set; is signed by a revoked device; is signed by the revocation target;
duplicates a `(voter, proposal_id)` already counted; carries an epoch other
than the parent's; or whose `proposal` hash does not match the proposal the
commit carries.

**The tally is evidence, not a claim.** The committer includes the votes it
counted; every other member re-tallies them independently and rejects the
commit if the evidence does not meet the threshold. No member is trusted to
report a result.

### 7.2 Suspicion is not revocation

A SECURITY_CONCERN is a proposal, and nothing more. This protocol has no
mechanism to establish that a device is compromised, and MUST NOT be described
as having one. What a completed REVOKE establishes is narrower and real:

> the group no longer sends this device group messages, and no commit it signs
> will be accepted again.

---

## 8. Concurrency, forks and equivocation

Two members can commit against the same parent at the same time. That is
normal, not an attack, and must be distinguished from one that is.

### 8.1 Concurrent commits — benign

Two **different** signers, two valid commits, same `previous_state_hash`.

Resolution is deterministic: the commit with the numerically **lower
`commit_id`** wins. The loser's transition is discarded, and its proposer MAY
re-propose it against the new head. Every member reaches the same answer
without communicating, because `commit_id` is a hash of bytes they all have.

An implementation MUST NOT resolve this by arrival order, timestamp, or
sender preference.

### 8.2 Equivocation — an attack

The **same** signer producing two different valid commits from the same
parent. The two signatures are proof of misbehaviour attributable to one key.

This MUST be surfaced as a security event, MUST NOT be auto-resolved by the
tie-break of §8.1, and both commits MUST be retained as evidence. Whether the
group revokes the equivocating device is a policy decision made by §7, not by
the protocol.

### 8.3 Fork

A member holding a state whose `previous_state_hash` it cannot link to the
head it can verify. Surfaced, never silently resolved, never silently
discarded.

---

## 9. Message layer

A group message is sent **independently to each member** over that member's
existing two-party channel. There is no broadcast and no shared ciphertext.

```
envelope =
      GROUP_DOMAIN ‖ SPEC_VERSION ‖ 0x07
    ‖ LEN(group_id)
    ‖ uint64be(epoch)
    ‖ LEN(message_id)               // 16 random bytes
    ‖ LEN(payload)
```

The envelope travels as the plaintext of an ordinary two-party message. It is
**not signed.** See §9.1.

`group_id` and `epoch` are present so a recipient cannot be made to attribute
a message to the wrong group: without them, a message from one group could be
relayed into another group's view by a member of both.

`message_id` exists for deduplication, not for ordering.

### 9.1 Group messages are not signed, deliberately

Signing group messages would give each one a non-repudiable author. OTR exists
in large part to avoid that, and this project's DAKE uses a ring signature
specifically to keep the handshake deniable.

The two-party channel already authenticates the sender to each recipient, and
that authentication is deniable. Adding a signature would replace a deniable
property with a non-deniable one for no gain in the group's own guarantees.

Membership **transitions**, by contrast, must be signed: their whole purpose
is to be verifiable by a third member who did not witness them. §13.3 states
what that costs.

### 9.2 Sending

A sender MUST NOT send to a member absent from its current member set, and
MUST NOT send at an epoch it has not verified. A send to a member with no
established two-party channel fails for that member only.

### 9.3 Receiving

A receiver MUST reject an envelope whose `group_id` is unknown, or whose
sender is not in the member set at the stated epoch. An envelope at an epoch
ahead of the receiver's own indicates stale state (§11), not a forgery.

---

## 10. Replay

| Object | What prevents replay |
|---|---|
| Commit | `previous_state_hash` — applies to exactly one parent, once |
| Proposal | `(group_id, epoch, proposal_id)`, tracked until the epoch closes |
| Vote | `(group_id, epoch, proposal_id, voter)`, counted at most once |
| Message | `(group_id, epoch, message_id)` in a bounded per-group window |

The message window is bounded and therefore lossy: an implementation MUST
document its size and MUST NOT describe out-of-window deduplication as replay
protection. Message replay protection within the two-party channel is
specified by SPEC.md §5.5 and is unaffected by this document.

---

## 11. Offline members and stale state

Members go offline across epoch transitions. This is routine over I2P, not an
edge case.

A member at epoch `m` receiving evidence of epoch `n > m` MUST NOT act at
epoch `m`. It MUST obtain and verify commits `m+1 … n` in order, applying §6.1
to each. A member that cannot obtain the intervening commits MUST NOT skip to
`n`; a state chain verified only at its head is not verified.

A member returning to find itself **absent** from the current member set has
been removed. It MUST stop sending to the group and MUST NOT attempt to
rejoin automatically.

---

## 12. Security properties claimed

1. **Membership integrity.** No device outside the member set at epoch `n` can
   produce a state accepted as epoch `n+1`.
2. **Authenticated history.** The chain from genesis to head is verifiable by
   any member, and a modified past changes every subsequent `state_hash`.
3. **Post-revocation exclusion.** A revoked device receives no further group
   messages, because members stop encrypting to it, and can produce no further
   accepted commit, because it is absent from every subsequent member set.
4. **Confidentiality and integrity of message content**, per pairwise channel,
   exactly as SPEC.md specifies — including its hybrid post-quantum property
   and its forward secrecy.
5. **Compromise isolation.** Compromising one pairwise channel yields that
   channel. There is no group secret whose compromise yields all of them.
6. **Deniability of message content**, inherited from the pairwise channel.

---

## 13. Security properties NOT claimed

### 13.1 No transcript consistency — read this one

**A malicious sender can send different content to different members and the
protocol cannot detect it.**

This is the price of fan-out and it is not a small one. With a shared group
key everyone receives the same ciphertext, so equivocation is impossible.
Here, each recipient receives its own ciphertext, and nothing compares them.

A future version MAY add periodic transcript-hash comparison between members,
which would make equivocation *detectable after the fact*. It would not make
it preventable. Version 1 does neither and must not imply otherwise.

### 13.2 No group forward secrecy beyond the pairwise channels

Each channel has the forward secrecy of SPEC.md §5. There is no additional
group-level property, because there is no group-level secret. A revoked member
retains whatever it legitimately decrypted; this protocol makes no claim about
erasing the past.

### 13.3 Membership records are not deniable

Commits are signed by long-term identity keys. A commit is therefore
cryptographic evidence, verifiable by anyone holding it, that a particular
device approved a particular membership change.

Message content stays deniable (§9.1). **Membership does not.** A seized
device yields signed records of the group changes it authorised. That is
inherent: a membership record that could be denied could not be verified by
the members who need to verify it. It is stated here so it is a known trade
rather than a discovery.

### 13.4 Voting does not survive a compromised majority

Under THRESHOLD policy, an attacker controlling enough devices to meet the
threshold controls membership — including revoking honest members. No quorum
avoids this; the quorum *is* the security parameter.

Under duress, a threshold is also coercible in a way a single admin is not
necessarily: it is harder to coerce one person than to coerce a majority, and
also easier. Neither policy is safe against an adversary who controls the
people. ADMIN_ONLY is the default because its failure mode is at least legible.

### 13.5 No protection against a compromised endpoint

Plaintext exists on the device that displays it. This protocol changes nothing
about that, and revocation is containment *after* a compromise is suspected by
a human — never detection of one.

### 13.6 Metadata

The XMPP server sees one stanza per recipient per group message. Group
membership and activity are therefore inferable from traffic patterns even
though content is not readable. Fan-out makes this **more** visible than a
shared-ciphertext scheme would, because the recipient set is explicit in the
traffic. I2P hides the network location of the participants; it does not hide
this pattern from the server.

---

## 14. Constants and limits

| Constant | Value | Why |
|---|---|---|
| `GROUP_SPEC_VERSION` | 1 | this document |
| `MAX_MEMBERS` (client policy) | 30 | see below |
| `MAX_PAYLOAD` | 16384 | bounded so one message cannot exhaust a recipient |
| `MAX_EVIDENCE` | 65536 | bounds vote-set size |
| Message replay window | implementation-defined, documented | §10 |

**`MAX_MEMBERS` is client policy, not a protocol constant.** The encoding
supports more. Thirty is an I2P deployment limit: fan-out sends `n−1` stanzas
per message and I2P is the constraint on that, not the cryptography. A
deployment on a different transport has no reason to inherit the number, and a
future implementation MUST be able to raise it without a wire change.

This mirrors the rule in [TRANSPORT_POLICY.md](TRANSPORT_POLICY.md): a routing
constraint does not belong inside the cryptographic layer.

---

## 15. Test vectors

Not yet produced. This section records what generating them requires, because
one prerequisite is missing from the core today.

Everything except signatures is a deterministic function of its inputs, so
`member_entry`, `member_set_hash`, `group_state`, `state_hash` and `commit`
vectors can be produced from fixed byte strings with no key material at all.

**Signature vectors cannot.** Ed448 signing is deterministic given the seed,
but `otrv4_core` exposes only `generate_ed448_keypair()` — there is no way to
construct a key from a fixed seed, so no signature or `commit_id` vector can
be reproduced. Producing them needs either a seeded constructor or a
test-only entry point gated the way `test-only-kdf` is.

That is a decision to take deliberately: a seeded key constructor is exactly
the kind of API that must not exist in a release build.

### 15.1 What was checked instead

The encoding of §§3–6 was implemented as a throwaway reference and exercised
before this document was committed. It confirmed: the sizes are as stated
(`group_id` 32, `state_hash` 64, signature 114, `commit_id` 64); a genesis
state and a JOIN commit encode and verify; the §6.1 conditions that can be
checked without a network hold; a revoked device is absent from the next
parent member set, so its later commits fail condition 4; the §8.1 tie-break
is deterministic; and the context tags of §1.2 separate the structures — a
member entry, a member set hash and a state hash over the same material are
all distinct.

The reference encoder was not kept. It exists in the commit message for this
document and should be rewritten from the specification, not recovered from
history — an encoder derived from the spec is a check on the spec; one copied
forward is not.

---

## 16. What implementation must add that this document does not specify

Named so they are not mistaken for oversights:

* how a `member_entry` for a new member is obtained and verified out of band
  before a JOIN — the protocol authenticates the commit, not the introduction;
* how commits are distributed to members who were offline (§11 says they must
  be fetched and verified, not how);
* the persistence format for group state, which must satisfy the same at-rest
  rules as the rest of the project;
* the user-facing security events, and how a fork or equivocation is presented
  to a human who has to decide what to do about it.
