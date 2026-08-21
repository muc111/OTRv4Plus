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

**Finding: there is no version guard for this break.** `PROTOCOL_VERSION`
remains `0x0004` and `OTRConstants.PROTOCOL_VERSION` remains `0x04`; neither was
bumped, and no negotiation or capability flag distinguishes the two formats.

The practical consequence is that a mismatched pair fails with
`"MAC verification failed - message may be forged or replayed"` — a message that
points at forgery or replay when the actual cause is a version mismatch. That is
a misleading diagnostic on a security-relevant path, and on a consumer product it
would generate support reports about attacks that are not happening.

This does not weaken the cryptography. It is a deployment and diagnosability
concern, and it is worth fixing before any public release. See §12.

## 11. Test vectors

**Unchanged.** `Rust/src/test_vectors.rs` has no diff across the merge
(`git diff 15df236..HEAD -- Rust/src/test_vectors.rs` is empty). The RFC 8032
Ed448 vectors and the RFC 7748 X448 known-answer test in `key_handles.rs` are
untouched, as they should be: the fix changes how a key is derived from the
chain, not any primitive.

`kdf_chain`'s in-crate signature changed (`[u8;32]` → `[u8;64]` third element),
which is an API change within the crate, not a vector change.

## 12. Remaining security concerns

**C1 — no version guard for a breaking wire change (§10).** Medium. Not a
cryptographic weakness; a diagnosability and deployment problem that presents as
a forgery warning. Recommend a version bump or capability flag before release.

**C2 — peer-revealed keys are recorded, not verified.**
`_record_revealed_mac_keys` validates length and rejects all-zero entries, then
appends to a bounded list. Nothing cross-checks that a published key corresponds
to a message actually received. The docstring is honest that the store exists "so
the property is observable", but recording is not verification: a peer could
publish well-formed random 64-byte values indefinitely and nothing would notice.
Low severity — the keys are public by design and the store is bounded — but the
property is weaker than it may appear.

**C3 — MKmac is queued before the outer MAC is verified.** The queue happens
after GCM authenticates and after the commit point, but before
`dmsg.verify_mac()` runs in Python. A message whose GCM tag passes but whose
outer MAC fails would still have had its key queued. Low severity: passing GCM
means the peer held the correct chain keys, so the key is not being published for
a forgery. Worth recording because the ordering is not obvious from either side
alone.

**C4 — the outer MAC's role should be documented.** With MKmac now genuinely
chain-derived, the outer MAC is no longer the "adds nothing" layer the upstream
audit described. But GCM remains the primary authentication and runs first. The
outer MAC's purpose is now precisely to *be revealable*. That is worth stating so
a future reader does not treat it as redundant and remove it — which would remove
the deniability mechanism with it.

**C5 — L1's status. My recommendation: re-scope, do not simply close.**

`MAC_KEY_REVELATION_AUDIT.md` marks L1 **RESOLVED** on the strength of the
forgeability test. As §7 sets out, that particular test does not support the
conclusion. The end-to-end tests added here *do* support a narrower one:

- **Demonstrated:** the implementation publishes the key that authenticated a
  received message, and that published key can re-MAC a forgery of that message.
  The mechanism works.
- **Not demonstrated:** formal OTR deniability. That is a statement about what an
  adversary or judge can distinguish given a transcript, and it depends on the
  whole protocol — the ring signature, the DAKE transcript, SMP, and what other
  evidence binds a party to a session. It cannot be established by a unit test.

So the *implementation defect* is fixed and verified; the *formal property* is
not established. Recommend L1 be recorded as **mechanism implemented and
verified; formal property unverified**, and that "deniable" not be used as a
product claim until a cryptographic review says otherwise. Note that the ring
signature independently provides *participation* deniability for the handshake —
a different and defensible claim that should not be conflated with transcript
deniability.

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
its own, a demonstration of formal deniability, and C1 should be addressed before
release.
