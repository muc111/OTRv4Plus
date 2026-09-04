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

**One distinction to carry through every discussion of this protocol:**

| Component | Role |
|---|---|
| **AES-256-GCM** | the symmetric cipher that encrypts payload bytes |
| **ML-KEM-1024** | post-quantum **key establishment**, in the two-party channel |
| **X448** | classical key establishment, alongside ML-KEM |
| **Ed448** | signatures over group state — never over message content |

ML-KEM is **not** a message cipher and never encrypts a payload. It
establishes key material inside the two-party handshake and ratchet; AES-256-GCM
is what a message is actually encrypted with. Describing this protocol as
"ML-KEM encrypted" would be wrong in a way that matters, because it implies a
PQ mechanism operating where there is none.

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

### 7.1.1 How `evidence` is encoded

Under-specified in the first draft of this document and pinned here because
`tests/group_vectors/group_vectors_v1.json` §18 now depends on it.

```
evidence = (vote ‖ vote_signature) ‖ (vote ‖ vote_signature) ‖ …
```

sorted ascending by `voter_identity_pub` as unsigned bytes — the same rule
and the same reason as the member set in §2, so two members counting the same
votes produce the same bytes and therefore the same `commit_id`.

There is no separator and no count field, and none is needed: every field of
a `vote` is fixed-length or length-prefixed, so a `vote` is exactly 215 bytes
and a record exactly 329. A parser MUST reject `evidence` whose length is not
a multiple of 329, and MUST reject a repeated `voter_identity_pub` rather than
counting it twice.

`evidence` is empty for every transition the policy does not require votes
for, including every transition under ADMIN_ONLY.

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

**The rule that must not be misread:**

> `lowest(commit_id)` is a **convergence** rule. It is not an **equivocation**
> rule. It resolves a disagreement between honest members. It must never be
> allowed to resolve, hide, or silently pick a winner from, two commits by the
> same signer.

Applying the tie-break to the §8.2 case would let an attacker equivocate and
have the protocol quietly clean up after them — the group would converge, and
nobody would learn that one member had signed two futures. An implementation
MUST therefore branch on **who signed**, before it compares any `commit_id`.

```
two valid commits, same previous_state_hash
                │
      ┌─────────┴─────────┐
 different signers    same signer
      │                   │
   §8.1 converge       §8.2 EQUIVOCATION
   lowest commit_id    never auto-resolved
```

### 8.1 Concurrent commits — benign

Two **different** signers, two valid commits, same `previous_state_hash`.

Resolution is deterministic: the commit with the numerically **lower
`commit_id`** wins, comparing the 64 bytes as unsigned big-endian. The loser's
transition is discarded, and its proposer MAY re-propose it against the new
head. Every member reaches the same answer without communicating, because
`commit_id` is a hash of bytes they all have.

An implementation MUST NOT resolve this by arrival order, timestamp, or
sender preference.

### 8.2 Equivocation — an attack

The **same** signer producing two different valid commits from the same
parent.

The two commits, with their signatures, are self-contained cryptographic proof
of misbehaviour attributable to one identity key. Anyone holding both can
verify it without trusting the reporter.

An implementation MUST:

* detect it — which requires retaining, per epoch, the set of
  `(signer, previous_state_hash)` pairs it has already seen a commit for;
* surface it as a security event naming the signer;
* retain **both** commits and both signatures as evidence;
* refuse to advance the epoch on either of them until a human or a policy
  decision resolves it.

An implementation MUST NOT apply §8.1 to this case, MUST NOT discard the
losing commit, and MUST NOT treat "the group converged" as a resolution.

Whether the group revokes the equivocating device is a §7 policy decision, not
something the protocol performs by itself.

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

The split is not an accident of implementation; it follows from what each
object has to accomplish:

| Object | Authentication | Why |
|---|---|---|
| OTR DAKE | **deniable** | ring signature, by design (SPEC.md §4.5) |
| Group message | **deniable** | inherited from the two-party channel |
| Membership commit | **non-deniable** | must be verifiable by members who did not witness it |
| Vote / proposal evidence | **non-deniable** | must be re-tallied independently (§7.1) |

An object that must convince a third party cannot also be deniable to that
third party. Anyone proposing to "add deniability" to commits is proposing to
remove the property that makes consensus verifiable.

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

**Produced.** `tests/group_vectors/group_vectors_v1.json`, eighteen sections,
covering §§2–9. `tests/test_group_vectors.py` checks them on every run.

They exist **before** any implementation, which is the point: when the group
state machine is written it is checked against these bytes, and a
disagreement is a question about which side misread this document — never a
reason to regenerate the file.

Everything except signatures is a deterministic function of its inputs, so
`member_entry`, `member_set_hash`, `group_state`, `state_hash` and the signed
body of a `commit` are produced from fixed byte strings with no key material
at all.

### 15.0 What is in the file

| Section | Covers |
|---|---|
| `01_member_entry` | §3 encoding, including a non-ASCII JID and `joined_epoch` at `uint64` max |
| `02_member_set` | §2 ordering by identity key, with the JID order shown to prove it differs |
| `03_genesis` | §4.1 `group_id` derivation and the epoch-0 state |
| `04_join`, `05_leave` | §6 commits and the states they produce |
| `06_membership_replacement` | a revoked device replaced by another holding the same JID |
| `07_state_chain` | §5 linkage across four epochs |
| `08_concurrent_commits` | §8.1, two signers, expected winner recorded |
| `09_equivocation` | §8.2, one signer, **no** winner recorded |
| `10_commit_id_determinism` | the same body signed twice |
| `11_ed448_signatures` | raw Ed448 over fixed messages |
| `12`–`15` | rejection cases: bad signatures, wrong parent, unauthorised signer, non-canonical encoding |
| `16_complete_verification` | one fixture exercising all eight §6.1 conditions |
| `17_threshold_votes` | §7.1 proposal, votes, evidence, re-tally |
| `18_message_envelope` | §9, with no signature field |

No genesis *commit* vector is emitted. §6.1 verifies a commit against a parent
state and genesis has no parent, so conditions 2, 3, 4 and 6 have nothing to
check. A joiner pins the genesis state itself (§5).

### 15.1 Signature and `commit_id` vectors

Ed448 signing in this project is **deterministic** — the same key over the
same message always produces the same 114 bytes — so signature and `commit_id`
vectors are reproducible provided the signing key itself can be fixed.

The committed signatures were **not** produced by this project's Ed448 —
they come from the RFC 8032 reference algorithm, for the reason in §15.2. The
core's own signing is what they were checked *against*, and that check needs a
fixed key, which exists only in a build that must never ship:

```rust
#[cfg(feature = "test-only-kdf")]
#[staticmethod]
pub(crate) fn from_seed_bytes<'py>(seed: &[u8]) -> PyResult<Self>
```

`Ed448KeyHandle.from_seed_bytes(seed)` takes a 57-byte seed and returns a
handle whose private key is still Rust-owned with no getter. It exists solely
so that protocol vectors are reproducible — and, as used here, so that two
implementations can be made to sign the same thing and compared.

**The rule it satisfies, stated so it cannot be diluted later:**

> A deterministic Ed448 seed-import primitive may exist solely for
> reproducible protocol test vectors and must not be reachable through the
> production API/build.

Three separate mechanisms enforce the second half:

1. **Compilation.** The `#[cfg(feature = "test-only-kdf")]` attribute means
   the function is not compiled at all without the feature — it is absent from
   the object file, not merely unexported.
2. **The build guard.** `Rust/build.rs` *panics at build time* when
   `test-only-kdf` is enabled unless `OTRV4PLUS_ALLOW_TEST_GATES=1` is set in
   the environment, so the feature cannot be turned on by an inherited Cargo
   flag or a careless `--all-features`.
3. **The release test.** `tests/test_release_guard.py` asserts against the
   installed wheel that `Ed448KeyHandle` has no `from_seed_bytes` attribute
   (`test_production_artifact_exposes_no_seed_injection`) and separately that
   the compiled object file contains no gated symbol
   (`test_production_object_file_contains_no_gated_symbols`). Both run in the
   ordinary suite.

Generating vectors therefore means building the gated wheel deliberately:

```bash
cd Rust
OTRV4PLUS_ALLOW_TEST_GATES=1 maturin build --release \
    --features pyo3/extension-module,test-only-kdf
python3.12 -m pip install --break-system-packages --force-reinstall \
    target/wheels/otrv4_core-*.whl
```

and then **restoring the production wheel** before anything else is run:

```bash
python3.12 -m pip install --break-system-packages --force-reinstall ./Rust
python3.12 -m pytest tests/test_release_guard.py -q
```

Verified on this repository: under the production wheel
`hasattr(otrv4_core.Ed448KeyHandle, "from_seed_bytes")` is `False`; under the
gated wheel it is `True`, and for `seed = bytes(range(57))` both the derived
public key and the signature over a fixed message reproduce exactly across
processes.

### 15.2 Vectors must not be generated by the implementation under test

A vector produced by the code it is meant to check proves only that the code
agrees with itself — the same defect the ML-KEM tests had before
[GROUP_CRYPTO_AUDIT.md](GROUP_CRYPTO_AUDIT.md) §2.

So the expected values MUST come from an independent encoder written from
**this document**. What was actually done:

* the encodings of §§2–9 are implemented in
  `tests/group_vectors/generate_group_vectors.py`, written from this
  specification, importing nothing from the client and nothing from
  `otrv4_core`. `test_the_generator_does_not_import_the_client` enforces that
  by reading its imports from the AST;
* the signatures come from `tests/group_vectors/ed448_rfc8032.py`, a
  transcription of the RFC 8032 reference algorithm sharing no code with
  `ed448-goldilocks-plus`. It reproduces the RFC 8032 §7.4 "Blank" vector
  exactly — key and signature — and derives the §7.4 "1 octet" public key;
* those signatures were then checked against the Rust implementation through
  the gated wheel: eight seeds, agreement on both the public key and the
  signature. Two independent implementations, one RFC anchor;
* and every signature in the committed file verifies under the **production**
  `verify_ed448_sig` on every test run, which needs no gate at all — verifying
  is a production API.

In consequence, so the file cannot be quietly turned into a mirror of the
implementation:

> If the group implementation disagrees with a vector, do not regenerate the
> vector. Establish which of the two read this document correctly, and fix
> that one. If the specification itself changes, bump the vector-set version
> and keep the old file.

The reference signer is variable-time arithmetic on secret scalars and must
never be reachable from client code. `test_nothing_outside_the_vector_directory_imports_it`
walks the tree to enforce it.

### 15.3 What the first reference encoder confirmed

Before the vectors existed, the encoding of §§3–6 was implemented as a
throwaway reference and exercised. It confirmed: the sizes are as stated
(`group_id` 32, `state_hash` 64, signature 114, `commit_id` 64); a genesis
state and a JOIN commit encode and verify; the §6.1 conditions that can be
checked without a network hold; a revoked device is absent from the next
parent member set, so its later commits fail condition 4; the §8.1 tie-break
is deterministic; and the context tags of §1.2 separate the structures — a
member entry, a member set hash and a state hash over the same material are
all distinct.

That encoder was not kept. The generator in `tests/group_vectors/` was
written from this document afresh rather than recovered from it — an encoder
derived from the spec is a check on the spec; one copied forward is not.

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
