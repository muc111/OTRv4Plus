# MLS + audio: hardening against the OTRv4+ security posture

Owner's specification of 2026-10-03, checked against the code as it stood
(rc.25, core 0.11.0), and updated as each step lands. **Status at rc.27
(core 0.12.0): M1, M2, M3 and M4 done; M5 (group calls) open.** Each requirement is marked **MET**, **PARTIAL** or
**NOT MET**, with where in the code it is decided, what is missing, and the
commit that closes it. "Flag" marks a place where a library forces something
weaker than the specification; those need an owner decision.

Documentation licence: CC BY-SA 4.0 (see LICENSING.md).

---

## 1. Deniability / non-provable sender identity — PARTIAL

**What MLS forces (Flag D1).** RFC 9420 §6.1 signs every handshake and every
application message (`FramedContent` signature) with the sender leaf's
signature key, and the signature travels inside the encrypted
`PrivateMessage`. No conforming configuration turns this off. So any group
member who receives a message holds a signature that a third party can
check against that leaf's key. This is a transferable proof that the holder
of key K wrote the message. OpenMLS 0.9 implements RFC 9420 faithfully, so
the property comes from the protocol, not from a library bug.

**What we do today** (`Rust/mls/src/client.rs`):

- The credential is a `BasicCredential` carrying the bare JID as a label.
  It is not signed by any long-term identity key, so it proves nothing: a
  leaf can claim any JID.
- The leaf signature key is an ML-DSA-87 key that the MLS client generates
  itself. It is **not** the OTRv4+ long-term identity key and is never
  certified by it.
- The only link between "leaf key K" and "this person" is the inviter's
  fingerprint, sent **inside the OTRv4+ session** (deniable DAKE, deniable
  MACs) when inviting, and checked against the group
  (`android_bridge/groups.py` `_on_welcome`, the binding check).
- **Gap (closed in M2, rc.27):** one signature key per client, reused
  across every group and never rotated. That made a member linkable across
  groups, and kept the proof valid for as long as the key lived.

**What gets the closest to OTRv4+ within RFC 9420** (commit M2):

1. **A fresh signature key per group**, never reused in another group.
2. **Rotation of the leaf signature key on every self-update**
   (`self_update_with_new_signer`). Each key signs only one epoch window.
3. **Optional key publication (owner decision).** After rotation, the old
   ML-DSA private key could be sent to the group inside an MLS message,
   the way OTRv4 reveals old MAC keys. From then on anyone in the group
   could have produced signatures under it, so old signatures stop being
   evidence. This is an extension outside RFC 9420. It only helps against
   a judge who believes the leaked key was published. It costs about 4.9 KB
   per rotation.

**Done in M2 (rc.27):** 1 and 2. Each KeyPackage carries its own key, which
becomes our key in the group it brings us into; creating a group makes a
fresh one; every self-update (manual, after 50 messages, or 30 minutes,
whichever first) replaces it, and the old private key is dropped when the
commit lands (`Rust/mls/src/client.rs`). The commit is signed with the old
key, so the core reports `rekeyed: (identity, old fp, new fp)` only for a
key replaced by its owner's own update -- never for a new leaf under an
old name -- and the bridge carries an SMP binding across exactly those.
The inviter's current fingerprint also travels with the Welcome over
OTRv4+, so a rotation between invite and Welcome does not fail the join.
3 (publication) remains deferred (decision D1).

Even with all three, a member who records traffic **before** rotation holds
signatures made by a key that was then private. Full OTRv4-style
deniability inside MLS (ring-signature or designated-verifier
authentication of leaves) is current research, for example the "deniable
MLS" constructions. It is not implementable in RFC 9420 or OpenMLS without
forking the protocol. **Recommendation:** do 1 and 2 now, and decide on 3.

## 2. Ciphersuite: AES-256-GCM + hybrid PQ — MET (M4, rc.27)

**Since rc.27 (M4):** every new group uses
`MLS_256_X448MLKEM1024_AES256GCM_SHA384_ED448MLDSA87` (private code point
0xF0A1), served by our own provider (`Rust/mls/src/provider.rs`, which
refuses everything else). Before rc.27 it was
`MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87` (0x0907, PQ-only); groups made
then keep working (the provider still serves that suite for them) but take
no new members: a hybrid KeyPackage cannot join a 0x0907 group, and the
app says to create a new group.

| requirement | since rc.27 | status |
|---|---|---|
| AEAD AES-256-GCM only | AES-256-GCM (HPKE and MLS) | **MET** |
| KEM X448 + ML-KEM-1024, binding combiner | `Rust/mls/src/hpke.rs`, KEM 0xF0A1 | **MET** |
| Signature Ed448 + ML-DSA-87 | composite, both must verify, 0xFEA1 | **MET** |
| Hash/KDF | SHA-384 / HKDF-SHA384 | fine |

Measured (4-member group): a KeyPackage is 15.4 KB, adding one member
31.0 KB (Welcome 26.5 KB), adding two 49.8 KB, a self-update 22.3 KB, a
two-letter message 4.8 KB (6.4 K characters in the room). The classical
halves add about 2-3 % to the PQ-only sizes.

As built, versus the design below: the signature code point is 0xFEA1 (the
TLS SignatureScheme private range is 0xFE00-0xFFFF, unlike MLS's), the
composite message is `"OTRv4+MLS/CompositeSig/v1" || m` (MLS already
labels and length-prefixes what it signs, so no separate context field),
and the HPKE secret key is `sk_x448 || sk_mlkem` (the ML-KEM public key is
inside the FIPS 203 decapsulation key, the X448 one is derived). Only
`openmls_traits` is patched (`Rust/vendor/VENDORED.md`); `openmls` takes
the suite through each leaf's declared capabilities.

**Flag C1: OpenMLS's ciphersuite list is a closed enum.** OpenMLS 0.9 /
openmls_traits 0.6 define `Ciphersuite`, `HpkeKemType` and
`SignatureScheme` as fixed enums. They contain X-Wing (X25519+ML-KEM-768)
but no X448+ML-KEM-1024 KEM and no composite signature. A new suite cannot
be added without patching both crates. Options:

- **(a) Vendor and patch** openmls_traits and openmls (`[patch.crates-io]`)
  to add private-use code points: ciphersuite `0xF0A1`
  `MLS_256_X448MLKEM1024_AES256GCM_SHA384_ED448MLDSA87`, KEM `0xF0A1`,
  signature `0xF0A1`. This is clean and honest on the wire, but we then
  maintain a fork. **Recommended.**
- (b) Put the hybrid inside the existing ML-KEM-1024 / ML-DSA-87 code points.
  OpenMLS treats keys and signatures as opaque bytes, so it would work, but
  the wire would claim an algorithm it does not use. Rejected.

**Design for (a)** (commit M4):

- **KEM (binding, X-Wing-style, at X448/ML-KEM-1024 strength):**
  `ss = SHA3-256("OTRv4+MLS/HybridKEM/v1" || ss_mlkem || ss_x448 || ct_x448 || pk_x448 || ct_mlkem || pk_mlkem)`,
  where `ct_x448` is the ephemeral X448 public key. The encapsulation key is
  `pk_x448 || pk_mlkem` (56 + 1568 bytes) and the ciphertext is
  `ct_x448 || ct_mlkem` (56 + 1568). HPKE `DeriveKeyPair` derives both halves
  from one seed with labels `"…/x448"` and `"…/mlkem"`.
- **Signature (composite):**
  `sig = Ed448(m') || ML-DSA-87(m')` with
  `m' = "OTRv4+MLS/CompositeSig/v1" || len(ctx) || ctx || m`. Verification
  requires **both** to pass, and the public key is `pk_ed448 || pk_mldsa`.
- Both halves come from crates the core already uses (`x448`,
  `ed448-goldilocks-plus`, PQClean), with no new primitive implementation.
- Existing groups cannot survive the change (a new suite means new groups).
  The core version bumps and Termux needs `build.sh`.

## 3. Strong entropy — MET (one improvement)

- Every MLS random value comes from `getrandom` (OS CSPRNG;
  `provider.rs` `random_array` / `random_vec`). A failure returns an error,
  so the operation fails closed and never falls back. On Linux/Android,
  `getrandom(2)` blocks until the kernel pool is initialised (≥ 256 bits).
- The voice and OTR paths use the core's OS-backed RNG likewise.
- Secrets: OpenMLS keeps group state in our `SecureStorage` (zeroizing,
  `Rust/mls/src/storage.rs`). Key material types are `Zeroizing` and
  sealed at rest with a DEK. Nothing secret crosses into Python or
  Kotlin: Python sees ciphertext, public keys and plaintext it is shown.
- *Done (M2):* per-group signing keys are `Zeroizing` and dropped when
  replaced, when the group is forgotten, and on Wipe & Exit. Unused
  KeyPackage keys are capped at 16.
- The bridge's own bookkeeping (SMP bindings, invitations in flight, an
  unconfirmed commit, key-refresh times) is sealed inside the same
  AES-256-GCM state blob, bound to the account (rc.27).

## 4. Rekeying, FS and PCS — PARTIAL → mostly MET with M1

| requirement | status |
|---|---|
| Automatic Update+Commit every N messages or T minutes | **MET in M1**: defaults 50 messages / 30 min, set by `OTRV4PLUS_MLS_REKEY_MESSAGES` / `OTRV4PLUS_MLS_REKEY_SECONDS` (`android_bridge/groups.py`). Never while one of our commits is pending; a lost commit is re-sent (rc.24) |
| Commit with path on every membership change | **MET**: OpenMLS add and remove commits always carry a path when the committer's leaf is updated |
| Delete previous-epoch secrets at once | **MET**: `max_past_epochs` is left at OpenMLS's default of 0, so no past epoch is kept for decryption |
| Single-use message keys, deleted after use | **MET**: OpenMLS secret tree, default sender-ratchet window (5 out of order, 1000 forward). Each key is deleted once used |
| Heal after compromise with one Update+Commit, or Remove | **MET**: `/group rekey` (Termux), automatic self-update, `/group remove` |
| Idle leaf (no Update/Commit for > 24 h) proposed for removal by the next honest member | **MET in M3 (rc.27)** with the owner's 72 h default (U1), `OTRV4PLUS_MLS_IDLE_REMOVE_HOURS` (0 = off). Every online member self-updates at least every 30 min even when silent (`SecureGroups.maintain`, every 5 min), so only a member away for 72 h is affected; nothing is judged for 10 min after a (re)connect |

**Idle-leaf removal: a usability flag (U1).** A phone that is off
overnight sends no Update for 24 h and would be removed every morning. It
would then need a re-invite over OTRv4+ before it could read the group
again. Proposed: implement it with the timeout configurable
(`OTRV4PLUS_MLS_IDLE_REMOVE_HOURS`) and a **default of 72 h**, the removal
announced in the group. Or keep 24 h if the stricter posture is worth the
friction.

## 5. Audio calls — 1:1 MET; group calls NOT MET

1:1 voice (`Rust/src/voice.rs`, `otrv4plus_voice.py`) already matches the
specification, on Android and Termux:

- media root from **X448 + ML-KEM-1024**, both mandatory (`take_shared`
  of both), HKDF with domain labels `OTRv4+Voice/*/v1`;
- **AES-256-GCM** frames; nonce `u32(epoch) || u64(counter)`, derived and
  never transmitted;
- **rekey every 120 s** (`VOICE_REKEY_SECONDS`), two-phase with
  confirmation tags (`LABEL_CONFIRM`), bounded catch-up;
- call set-up **gated on SMP verification** (`_smp_verified`, checked in
  `_on_invite` before a session exists);
- media over **I2P datagrams** (SAM); no PSTN, no phone numbers, no clearnet.

**Group (MLS) calls do not exist.** Design for commit M5:

- the media root comes from the MLS exporter
  (`exporter("OTRv4+GroupVoice/v1", call_id, 64)`), which is hybrid once
  M4 lands. There is one key per sender
  (`HKDF(root, "…/sender" || leaf_index)`), the same AES-256-GCM framing and
  nonce rule as 1:1, and the root rotates with every epoch plus a 120 s
  timer that forces a self-update;
- transport is I2P datagrams, a full mesh for up to ~5 members (each sends
  to each). A larger call needs a relay, which is a separate design;
- set-up is gated on every participant being a verified group member
  (bound over SMP-verified OTRv4+, as invitations are today).

This is the largest item: transport, mixing and UI on two clients.

## 6. Threat model notes

- **Forward secrecy:** OTRv4+ (double ratchet) and MLS (epoch deletion,
  single-use keys) both delete keys after use. Voice deletes the old root
  after a confirmed rekey.
- **Post-compromise security:** MLS heals at the next commit from the
  compromised member. M1 makes that automatic (≤ 50 messages / 30 min).
  OTRv4+ heals at the next DH ratchet step.
- **Deniability:** OTRv4+ is deniable (DAKE, ring signatures, published
  MAC keys). MLS can only approach it (§1): leaf keys are unlinked to
  identity except through deniable OTRv4+, rotated per group and epoch
  after M2, and optionally published.
- **PQ resistance:** hybrid everywhere since rc.27: OTRv4+, voice, and MLS
  (X448+ML-KEM-1024, Ed448+ML-DSA-87), so a break of either half alone does
  not break confidentiality or authentication. Groups made before rc.27
  remain PQ-only until re-created.
- **Metadata:** the room (server) sees member nicknames, timing and sizes.
  Content and the group roster in the tree are encrypted
  (`PURE_CIPHERTEXT` wire format). The server never sees a JID–key link.

## 7. Owner decisions (2026-10-03)

- **C1 → patch OpenMLS** (vendored openmls + openmls_traits, private-use
  code points for the hybrid KEM, composite signature and suite).
- **U1 → idle-leaf removal after 72 h**, configurable
  (`OTRV4PLUS_MLS_IDLE_REMOVE_HOURS`).
- **D1 → rotate only** (per-group leaf keys, rotated on every
  self-update); publishing old keys is deferred.

Found while planning M3: the core's commit event does not say **who**
committed, which idle tracking needs. M2 adds the committer's leaf identity
to the commit event (one core change for both).

## 8. Commit plan

| | commit | needs a core rebuild |
|---|---|---|
| M1 | rekey defaults 50 msgs / 30 min, env knobs; this document | no |
| M2 | per-group signature keys, rotated on self-update; zeroized on forget — **done, rc.27 / core 0.12.0** | yes |
| M3 | idle-leaf removal, 72 h default, needs M2's committer field — **done, rc.27** | no |
| M4 | hybrid ciphersuite via patched OpenMLS (decision C1) — **done, rc.27** | yes; new groups |
| M5 | group audio calls over MLS exporter keys and I2P | yes |
| M2b | optional: publish rotated signature keys (decision D1-3) | yes |
