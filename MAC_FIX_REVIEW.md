# MAC fix review

Independent review of commit `ded35ac` — *"fix(L1): derive MKmac per OTRv4
§4.4.2; add voice latency measurement"* — as merged into the Android branch.

This is a verification pass, not a restatement of the commit message or of
`MAC_KEY_REVELATION_AUDIT.md`. Every claim below was checked against the
post-merge source and, where it is a behavioural claim, against a test that
exercises the implementation rather than a reconstruction of it.

**Scope note.** The commit also adds voice latency measurement (PING/PONG RTT,
NTP-style offset correction). That is unrelated to the MAC work and is not
reviewed here; it is covered by `VOICE_SOAK_TEST.md`.

---

## 1. Original behaviour

Three separate defects, which the original L1 entry ("reveals all-zeros")
described only the first of.

**(a) The revealed key was 32 zero bytes.** `kdf.rs::kdf_chain()` returned
`[0u8; 32]` in the position OTRv4 §4.4.2 assigns to `MKmac`. Its own doc comment
named the value "zeros". `ratchet.rs::encrypt_message` bound that to `mac_key`
and stored it as `last_mac_key`, so every key queued for revelation was zero.
The Python mirror `_kdf_ck()` had the identical placeholder, documented as
`extra_zeros`.

**(b) `MKmac` was never derived at all.** `usage::MAC_KEY` (`0x14`) was defined
in both languages and referenced nowhere. The §4.4.2 construction did not exist
in the implementation.

**(c) The key that actually authenticated a data message was not a ratchet
key.** Both paths computed:

```python
mac_key = hashlib.sha3_512(
    session_id + ratchet_id.to_bytes(4,"big")
               + msg_num.to_bytes(4,"big") + b"OTRv4-MAC-KEY").digest()[:32]
```

So the value that authenticated a message and the value that got revealed were
two unrelated keys.

## 2. Root cause

The three are one root cause with two symptoms: **`MKmac` was never wired into
the ratchet.** Because it did not exist, the MAC layer needed *some* key and got
an ad-hoc one derived from session state (c); and the revelation slot, having
nothing real to carry, was filled with a placeholder (a) that was never revisited
(b).

Fixing only (a) — replacing the placeholder with a real derivation — would have
removed the zeros and changed nothing about the property, because the revealed
key still would not have been the authenticating key. The upstream audit
identified this and said so explicitly, which is the correct call.

## 3. Files changed

| File | Change |
|---|---|
| `Rust/src/kdf.rs` | `kdf_chain` third return `[u8;32]` → `[u8;64]`, now `kdf_1(usage::MAC_KEY, &mk, 64)`; new `kdf_mkmac(enc_key)` helper |
| `Rust/src/ratchet.rs` | receive-side MKmac derived and queued; `queue_reveal` bounded at 50 with zeroization on eviction; `DecryptResult.mac_key` added |
| `otrv4+.py` | `_kdf_ck` returns real MKmac; old `sha3_512(session_id‖…)` derivation removed; `REVEALED_MAC_KEY_LEN` 32 → 64; `_record_revealed_mac_keys`; truncation raises `ValueError` |
| `otrv4plus_voice.py` | voice latency measurement (unrelated to MAC) |
| `test_mac_key_revelation.py` | new, 28 tests |
| `test_voice_*.py` | updated for the new return shapes |
| `MAC_KEY_REVELATION_AUDIT.md` | new |

Added during this review: `tests/test_mac_revelation_end_to_end.py` (9 tests),
and repairs to `tests/` for the API change — see §7.

## 4. Code path affected

```
send:     chain_key ──kdf_chain──▶ (next_ck, MKenc, MKmac[64])
                                        │        └─ authenticates the data message
                                        │        └─ stored as last_mac_key
                                        └─ AES-256-GCM encrypt
          next encrypt ──▶ last_mac_key moved into pending_reveal_macs
                       ──▶ pending_reveal_macs drained into the wire field

receive:  AES-256-GCM decrypt + tag verify        ← authentication happens HERE
             │ (fails → return, no state mutated)
             ▼
          ── commit ratchet state ──
             │
          MKmac = kdf_mkmac(recv_enc_key) ──▶ queue_reveal
             │
             └──▶ returned to Python ──▶ dmsg.verify_mac(mac_key)
```

**Ordering check.** The receive-side MKmac is derived and queued *after* the GCM
tag verifies and after the commit point, so only genuinely authenticated messages
put a key in the reveal queue. This preserves the v10.11.1 "authenticate before
mutating ratchet state" property (RT-1). Verified by reading
`ratchet.rs::decrypt_same_dh` / `decrypt_new_dh`: the `aes_decrypt` result is
matched and returns early on failure, and the `// ── Authenticated: commit ──`
marker precedes the `kdf_mkmac` call.

## 5. Do both clients use the corrected behaviour?

**Yes, and `otrv4plus_xmpp.py` contains no MAC code of its own.** Verified by
search: `mac_key`, `MKmac`, `_kdf_ck`, `compute_mac` and `verify_mac` return no
hits in that file. The XMPP transport drives `EnhancedSessionManager` from
`otrv4+.py`, so it inherits the corrected path with no separate implementation
to drift. The IRC client in `otrv4+.py` shares the same session layer.

The old derivation is gone everywhere: `grep -n "OTRv4-MAC-KEY"` returns no hits
across `otrv4+.py`, `otrv4plus_xmpp.py` and `otrv4plus_voice.py`.

## 6. Rust/Python boundary

MKmac now crosses the boundary as `bytes`, in both directions:

- `encrypt_message` returns it as a 7th tuple element;
- `decrypt_message` returns `(plaintext, mac_key)`;
- `RustDoubleRatchet.decrypt_*_dh` return `{'plaintext', 'mac_key'}`.

**This is a deliberate and defensible exception to the "no secrets across the
boundary" rule**, and the source says so: MKmac is designed to become public, so
handing it to Python costs nothing that revelation would not publish anyway.
`MKenc` — the key that actually decrypts — is *not* exported, and a test asserts
publishing MKmac does not expose it or the ciphertext.

The relationship is one-way: `MKmac = KDF(0x14, MKenc, 64)`. Recovering MKenc
from MKmac means inverting SHAKE-256.

## 7. Tests proving the old behaviour is gone

`test_mac_key_revelation.py::TestRegressionGuards` greps the source for the zero
placeholder and the `session_id` derivation — useful, but source-level.

The behavioural proofs are in `tests/test_mac_revelation_end_to_end.py`, added
during this review because **the fix's own coverage did not close the loop**:

> `test_mac_key_revelation.py::TestForgeability` synthesises its own MKmac and
> MACs a message with it via `build_message`, which computes the MAC with
> whatever key it is handed. `assert original.verify_mac(mkmac)` is therefore a
> property of MACs in general — a MAC verifies under the key it was computed
> with — not evidence about this implementation. **No test in that file drives a
> real ratchet or reads the real reveal queue**, so it would pass against the
> pre-fix code, where the revealed key and the authenticating key were unrelated.

The new tests drive the actual ratchet and assert on the bytes the implementation
emits:

| Test | Proves |
|---|---|
| `test_mkmac_is_not_zero_and_not_the_message_key` | the 32-byte zero placeholder is gone |
| `test_mkmac_differs_per_message` | the key is chain-derived, not a function of wire fields |
| `test_sender_and_receiver_agree_on_mkmac` | both ends derive the same 64-byte value |
| `test_receiver_publishes_the_key_that_authenticated_what_it_received` | **the published key IS the authenticating key** |
| `test_a_published_key_can_re_mac_a_forgery_of_the_real_message` | the published key forges a real transcript entry |

These are non-vacuous by construction: the fourth compares the published bytes
against the sender's MKmac for a specific message, which pre-fix were a zero
buffer and an unrelated `sha3_512` digest respectively.

## 8. Tests proving legitimate handling still works

- `test_sender_and_receiver_agree_on_mkmac` — the MAC verifies on the happy path.
- `TestWrongKey` (upstream) — an unrelated key, an all-zero key and a truncated
  key all fail to verify.
- `TestWireEncoding` (upstream) — revealed keys round-trip byte-exact; an empty
  queue encodes as empty rather than as a zero key; a wrong-length key is refused
  rather than padded; a truncated reveal list is rejected.
- `TestRevelationHygiene` (new) — nothing is published before it has
  authenticated something; the queue drains rather than republishing; it stays
  bounded at 50 under sustained one-way traffic; publishing MKmac exposes neither
  MKenc nor the ciphertext.

Full suite state after repair: **415 passed, 42 skipped, 1 xfailed, 0 failed** in
`tests/`, with no `--ignore`; **238 passed** in the root voice/audio suites;
**57 passed** in Rust.

## 9. Wire compatibility

**Changed. This is a breaking change.**

1. **The MAC value differs.** Same field, same offset, different key — so a
   pre-fix peer and a post-fix peer fail each other's MAC check.
2. **The revealed-key field widened 32 → 64 bytes** per entry
   (`REVEALED_MAC_KEY_LEN`), changing the byte layout of any data message
   carrying revealed keys.
3. `otrv4plus_voice.py` also changed the frame plaintext layout for the latency
   timestamp, though the packet stays 199 bytes.

## 10. Peer compatibility

**Existing peers are NOT compatible. Both endpoints must upgrade together.**

**Original finding: there was no version guard for this break.** `PROTOCOL_VERSION`
remained `0x0004` and `OTRConstants.PROTOCOL_VERSION` remained `0x04`; neither was
bumped, and no negotiation or capability flag distinguished the two formats. A
mismatched pair failed with `"MAC verification failed - message may be forged or
replayed"` — a message pointing at forgery or replay when the actual cause was a
version mismatch.

**Resolved** in `36bf131`. See §13.

## 11. Test vectors

**Unchanged.** `Rust/src/test_vectors.rs` has no diff across the merge
(`git diff 15df236..HEAD -- Rust/src/test_vectors.rs` is empty). The RFC 8032
Ed448 vectors and the RFC 7748 X448 known-answer test in `key_handles.rs` are
untouched, as they should be: the fix changes how a key is derived from the
chain, not any primitive.

`kdf_chain`'s in-crate signature changed (`[u8;32]` → `[u8;64]` third element),
which is an API change within the crate, not a vector change.

## 12. Security concerns raised by this review

Recorded as they stood at review time. Current status in §13.

**C1 — no version guard for a breaking wire change (§10).** Medium. Not a
cryptographic weakness; a diagnosability and deployment problem that presents as
a forgery warning. → **RESOLVED**, §13.1.

**C2 — peer-revealed keys are recorded, not verified.**
`_record_revealed_mac_keys` validated length and rejected all-zero entries, then
appended to a bounded list. Nothing cross-checked that a published key
corresponded to a message actually received: a peer could publish well-formed
random 64-byte values indefinitely and nothing would notice. Low severity — the
keys are public by design and the store is bounded — but the property was weaker
than it appeared. → **RESOLVED**, §13.2.

**C3 — MKmac is queued before the outer MAC is verified.** The queue happens
after GCM authenticates and after the commit point, but before
`dmsg.verify_mac()` runs in Python. → **AUDITED, no change required**, §13.3.

**C4 — the outer MAC's role should be documented.** With MKmac now genuinely
chain-derived, the outer MAC is no longer the "adds nothing" layer the upstream
audit described. But GCM remains the primary authentication and runs first. The
outer MAC's purpose is now precisely to *be revealable*. That is worth stating so
a future reader does not treat it as redundant and remove it — which would remove
the deniability mechanism with it. → Stated here and at the call site in
`_enh_dec_v6`; also in the header of `tests/test_reveal_ordering.py`.

**C5 — L1's status. Re-scope, do not simply close.** → §13.4.

---

## 13. Resolution pass

Work done after the review above, on `claude/otrv4plus-android-spec-a3oq4d`.
Commits `36bf131` (C1) and `8d509bc` (C2/C3).

Evidence vocabulary used throughout:

| Label | Meaning |
|---|---|
| OBSERVED | Seen in one run or one reading of the source. Not generalised. |
| TEST-VERIFIED | An automated test asserts it and that test currently passes. |
| IMPLEMENTATION PROPERTY | Holds by construction in this codebase. Not a statement about the protocol. |
| DESIGN INTENT | What the code is meant to do. Not evidence that it does. |
| FORMAL SECURITY CLAIM | A cryptographic property with an argument or proof behind it. Used nowhere in this document. |

### 13.1 C1 — protocol versioning · RESOLVED

The two formats that changed incompatibly now carry different version numbers:

| Constant | Was | Is | Why |
|---|---|---|---|
| `OTRv4DataMessage.PROTOCOL_VERSION` | `0x0004` | `0x0005` | MAC value differs; `REVEALED_MAC_KEY_LEN` 32 → 64 |
| `VOICE_PROTOCOL_VERSION` | `3` | `4` | frame plaintext layout changed (8-byte timestamp inside the AEAD) |
| `OTRConstants.PROTOCOL_VERSION` | `0x04` | `0x04` | **deliberately unchanged** — see below |

The ClientProfile and DAKE formats did not change. Bumping their version would
falsely signal a handshake change and invalidate every existing profile, so it
stays at `0x04`; `TestProfileVersionUnchanged` pins it so a later edit cannot
bump it casually. That is the one version this work concluded must NOT change,
and this is the technical reason.

`ProtocolVersionError(ValueError)` was added. Subclassing `ValueError` keeps
every existing `except ValueError` handler around `decode()` working, while a
caller that needs to tell a version mismatch from a cryptographic failure can
catch it specifically. `decode()` re-raises it ahead of its generic wrapper —
the wrapper flattened it on the first attempt, which restored exactly the
ambiguity C1 exists to remove, so there is a regression test for that alone.

The gate is strict equality in **both** directions. No older revision is
accepted, so the old MAC construction is never evaluated and cannot be forced;
no newer revision is accepted either, since this build does not know its framing.

TEST-VERIFIED (`tests/test_protocol_version.py`, 34 tests): matching versions,
mismatched versions, old/new peer interaction, downgrade attempts across
`0x0000`–`0x0004`, forward versions, malformed and truncated version fields,
200 random-garbage inputs, and the voice frame revision.

Also fixed in the same commit: `BinaryReader.read_uint{8,16,32,64}` and
`read_mpi` converted `ensure()`'s `ValueError` into `RuntimeError` through a
bare `except Exception`. Truncation is an expected condition on untrusted
input, `decode()` does not catch `RuntimeError`, and no caller expects it — so
a short header escaped the parser as an "unexpected error" rather than a clean
parse failure. `read_bytes()` already re-raised; the integer readers now match.

**Documented break.** Builds at data-message revision `0x0004` and `0x0005`
cannot interoperate, in either direction, and neither can voice revisions `3`
and `4`. There is no compatibility mode and none should be added: accepting the
old revision would mean accepting the old MAC construction.

### 13.2 C2 — revealed MAC key cross-check · RESOLVED

Lifecycle traced end to end. What is revealed, by whom:

| Source | What it is | Where it is queued |
|---|---|---|
| `encrypt()` | MKmac of a message **we sent**, held in `last_mac_key` and queued on the *next* send | `ratchet.rs` `encrypt` / `send_ratchet` |
| `decrypt_same_dh` / `decrypt_new_dh` | MKmac of a message **we received**, after authentication | `queue_reveal` |
| skipped-key path | MKmac re-derived from a stored MKenc | `queue_reveal` |

So each side publishes keys the other side also derived — which is what makes
the check possible. IMPLEMENTATION PROPERTY: the engine now fingerprints every
MKmac it derives (`kdf::mkmac_fingerprint`, domain-separated SHA3-256), and
`knows_derived_mac()` answers whether a revealed key is one of them.

Fingerprints, not keys. The cross-check adds no new store of live key material,
and one bit crosses the PyO3 boundary in response to a value that is public by
construction. The set is bounded at 4096 entries with FIFO eviction.

Fingerprinting **at the skipped-key path** is what makes the check usable in
practice. When a message is lost in transit its MKenc only ever exists in the
skipped store, yet the peer still reveals the matching MKmac. Deriving the
fingerprint when that key is stored — rather than when the message arrives —
means an honest peer's revelation for a lost message is still accountable.
TEST-VERIFIED in both Rust and Python.

Fail closed (raises, tears the message down):

- wrong length
- all-zero
- **the key that authenticated the very message carrying the revelation.** New.
  Publishing the current message's MKmac would make that message forgeable at
  the instant it is accepted. `encrypt()` takes the pending queue before
  installing the current key, so the engine cannot do it; the receive-side
  guard and a Rust test hold that ordering in place.

Not fatal, and deliberately so: a key this endpoint cannot account for. An
unaccounted key is **not** evidence of misbehaviour. Eviction from the
fingerprint window, and messages skipped past the tail of an old chain before a
DH rotation, both leave an honest peer holding keys this side never derived.
Making it fatal would let anyone able to drop a single packet kill any session
on demand, and would buy nothing — a peer that wants to defeat the check can
simply reveal nothing at all. Verified and unaccounted counts are kept
(`revealed_mac_keys_verified`, `revealed_mac_keys_unaccounted`) so the condition
is visible rather than silent.

TEST-VERIFIED (`tests/test_revealed_mac_crosscheck.py`, 17 tests; `ratchet.rs`,
8 tests): keys derivable in both directions and through the real reveal queue;
a lost message's key still accountable; invented keys and one-bit-off keys
rejected; the three fatal cases; unaccounted keys counted not raised; both
stores bounded.

### 13.3 C3 — reveal ordering · AUDITED, NO CHANGE REQUIRED

Required invariant:

    unauthenticated input → parse/validate → AEAD → outer MAC
      → commit ratchet state → queue/reveal MAC key

Both Rust receive paths already hold it. Every key derivation runs into scratch
state (`scratch_ck`, `pending_skipped`); `aes_decrypt` gates the commit and
zeroizes everything on failure; `queue_reveal` sits after the
`// ── Authenticated: commit ──` marker. The skipped-key path peeks at the
stored key, authenticates, and only then consumes it. No ordering change was
needed, so none was made.

One deviation is deliberate and is now documented rather than "fixed": the
engine queues the reveal after the AEAD tag verifies but **before** the caller
checks the outer MAC. That is sound. `MKmac = KDF(0x14, MKenc, 64)`, so anyone
able to produce a valid GCM tag under MKenc can compute the outer MAC as well.
The outer MAC is a second, spec-mandated check whose key is later published —
it is not the thing standing between a forgery and the ratchet. AES-256-GCM is,
and it runs first.

TEST-VERIFIED (`tests/test_reveal_ordering.py`, 15 tests), asserting on emitted
values rather than source shape: a forged ciphertext, a forged tag, a wholly
invented message and a burst of 32 forgeries each publish nothing; the genuine
message still decrypts after a forgery and after 50 of them; a forged high
`msg_num` does not flood the skipped store; a replay publishes no second copy;
a valid message publishes exactly its authenticating key and nothing else;
earlier state and the pending queue survive a later forgery.

### 13.4 L1 — four separate claims

The single word "resolved" was doing too much work. Split:

**A. The mechanism is implemented.** TEST-VERIFIED. `MKmac = KDF(0x14, MKenc,
64)` per OTRv4 §4.4.2, 64 bytes, chain-derived, different for every message.

**B. It is correctly integrated into the ratchet.** TEST-VERIFIED. Sender and
receiver derive the same MKmac for the same message; the key that is published
is the key that authenticated it; the queue drains, does not republish, is
bounded at 50, and publishes nothing for a message that failed to authenticate.

**C. It is tested end to end.** TEST-VERIFIED, against the real ratchet and the
real reveal queue rather than a reconstruction — `tests/test_mac_revelation_end_to_end.py`,
`tests/test_reveal_ordering.py`, `tests/test_revealed_mac_crosscheck.py`. A
published key can re-MAC a forgery of the real message, using the bytes the
implementation itself emitted.

**D. The protocol provides formal deniability.** **NOT CLAIMED.** No
cryptographic argument or proof is offered here, and none of the tests above
constitutes one. Formal deniability is a statement about what an adversary or a
judge can distinguish given a transcript; it depends on the whole protocol — the
ring signature, the DAKE transcript, SMP, and whatever else binds a party to a
session — and cannot be established by a unit test.

L1's status is therefore: **mechanism implemented, integrated and tested;
formal deniability remains an unproven protocol-level property.** The mechanism
stays: it is a precondition for the property, and the absence of a proof is not
a reason to remove it. "Deniable" should not be used as a product claim until a
cryptographic review says otherwise. The ring signature independently provides
*participation* deniability for the handshake — a different and defensible
claim that should not be conflated with transcript deniability.

---

## Verdict

The fix is real, correctly derived per §4.4.2, correctly ordered with respect to
authentication, consistent across both clients, and it does not touch any
primitive or test vector. The invariant it establishes is:

> **The value that authenticates a data message is `MKmac = KDF(0x14, MKenc, 64)`,
> derived from that message's own chain-derived encryption key; and the value
> later published for that message is that same value.**

Before the fix neither half held: the authenticating value was a function of
session state and two cleartext wire fields, and the published value was a zero
buffer. Both halves are now enforced and both are covered by tests that exercise
the implementation rather than a reconstruction of it.

That is a genuine improvement and the analysis behind it was sound. It is not, on
its own, a demonstration of formal deniability — see §13.4, which separates the
four claims that were previously collapsed into one.

C1, C2 and C3 have since been addressed; §13 records what changed, what was
audited and left alone, and why. The remaining open item is not an
implementation defect: it is the formal property, which needs a cryptographic
review this document cannot substitute for.
