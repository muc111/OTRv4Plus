# MAC_KEY_REVELATION_AUDIT.md

**Status: FIXED (Option A). Wire format changed — both endpoints must upgrade.**

L1 is **RESOLVED**: the forgeability test passes, which it could not have done
before, because the revealed key was not the key that authenticated anything.

---

## Root cause

> The zero MAC key was caused by **`kdf.rs::kdf_chain()` returning
> `[0u8; 32]` in the position where OTRv4 §4.4.2 requires `MKmac`** — its own
> doc comment called it "zeros". `ratchet.rs::encrypt_message` bound that to
> `mac_key` and stored it as `last_mac_key`, so **every key ever queued for
> revelation was 32 zero bytes**. The Python mirror `_kdf_ck()` had the
> identical placeholder.
>
> Underneath that, **`MKmac` was never derived anywhere**: `usage::MAC_KEY`
> (0x14) was defined in both languages and referenced nowhere. The value that
> authenticated a data message and the value that got revealed were two
> unrelated keys.

*Correction to the first draft of this document:* I initially attributed the
zeros to the Python `_kdf_ck` and reported the Rust side as correct. That was
wrong. `kdf_chain` in `kdf.rs` does the same thing and is the one on the live
path — the Python mirror's third return value is discarded by both callers.
Reading further before writing found it.

Fixing only the zeros would not restore the deniability property. The brief
warns against exactly that, so the analysis below separates the two.

---

## Evidence

### F1 — the literal zero (`otrv4_.py:3139-3148`)

```python
def _kdf_ck(self, ck: bytes, label: bytes = b"MESSAGE_KEY"):
    """Advance a chain key per OTRv4 spec §4.4.2.

    Returns (new_ck, message_key, extra_zeros).
    """
    new_ck = kdf_1(KDFUsage.CHAIN_KEY, ck, 32)
    mk     = kdf_1(KDFUsage.MESSAGE_KEY, ck, 32)
    return new_ck, mk, bytes(32)
```

A function whose docstring claims to implement §4.4.2 returns 32 zero bytes in
the third position. §4.4.2 puts `MKmac` there. The docstring names it
"extra_zeros", so this was deliberate at the time, not an accident.

Both call sites discard it — `new_ck_s, _, _ = self._kdf_ck(...)` at line 3169
and line 3238 — so it is inert on the current path. It is still the all-zero
MAC key the audit found, and any future caller reading position 2 as `MKmac`
gets zeros with no error.

### F2 — `MKmac` is never derived (`otrv4_.py:265`)

`KDFUsage.MAC_KEY = 0x14` is defined and **never referenced anywhere in either
file**. The spec construction

```
MKmac = KDF(usage_MAC_key ‖ MKenc, 64)
```

does not exist in this implementation.

### F3 — the authenticating key is not a ratchet key (`otrv4_.py:5842`, `5949`)

Both the send and receive paths compute:

```python
mac_key = hashlib.sha3_512(
    self.session_id
    + ratchet_id.to_bytes(4, "big")
    + msg_num.to_bytes(4, "big")
    + b"OTRv4-MAC-KEY"
).digest()[:32]
```

This is:

- **not derived from the chain key** — it has no relationship to the ratchet
- **not 64 bytes** — truncated to 32
- **not the value revealed** — see F4
- **a pure function of `session_id` and two cleartext wire fields.**
  `ratchet_id` and `message_id` are transmitted in the clear in every data
  message, so the only secret input is `session_id`. Anyone who learns
  `session_id` can compute the MAC key for every message in the session, past
  and future.

The message's real authenticity comes from AES-256-GCM; this SHA3-512 layer
adds nothing an attacker with `session_id` cannot reproduce.

### F4 — the revealed key never authenticated anything

The Rust side is correct in isolation. `ratchet.rs:249` stores
`last_mac_key = kdf_chain(chain_key_send).2` — a genuine 32-byte chain-derived
key — and both push sites clone before zeroizing, in the right order:

```rust
if let Some(ref mut mac) = self.last_mac_key {
    self.pending_reveal_macs.push(mac.clone());   // clone first
    mac.zeroize();                                // then wipe
}
```

So `reveal_mac_keys` carries real, non-zero key material. It is simply **not
the key `dmsg.mac` was computed with**. Revealing it lets a forger produce
nothing.

### F5 — the receiver discards revealed keys

`revealed_mac_keys` is written at `otrv4_.py:5866`, encoded at 1281, decoded at
1341 — and never read again. No code path consumes a peer's revealed keys.

### F6 — only send-side keys are ever queued

`last_mac_key` is assigned in `encrypt_message` only. The decrypt paths never
queue a MAC key. Phases 2D (skipped messages) and 2E (session expiration) of
the brief have no implementation to inspect: neither path can reveal anything
because nothing is ever stored to reveal.

---

## What this means for L1

L1 as written ("reveals all-zero bytes") understates it. Three independent
things must all be true for OTRv4 deniability, and none of them currently is:

| Requirement | Status |
|---|---|
| `MKmac = KDF(usage_MAC_key ‖ MKenc, 64)` | Not implemented |
| The revealed key is the key that authenticated the message | Two different keys |
| A peer can use a revealed key to forge a message | Receiver discards them |

Making `_kdf_ck` return a real key would remove the zeros and change nothing
about the property.

---

## Decision required

The brief asks for a minimal fix that preserves the wire format. **Those two
constraints cannot both hold.** Restoring the actual OTRv4 property requires:

1. Deriving `MKmac` per spec — **64 bytes**, from `MKenc`, in Rust alongside
   `enc_key`.
2. Computing `dmsg.mac` with that key instead of the `session_id`-derived one.
   Same field, same offset, different value — so a v10.11.1 peer and a patched
   peer will fail each other's MAC check.
3. Widening the revealed-key encoding from 32 to 64 bytes
   (`otrv4_.py:1281-1284`, `1341`), which changes the wire layout of every
   data message carrying revealed keys.
4. Queuing the *receive*-side MKmac after successful authentication, which is
   the direction that matters for deniability — the keys that authenticated
   messages **you received** are the ones whose revelation lets a third party
   forge them.
5. Consuming revealed keys on receipt, or at minimum validating length and
   count, so the property is observable rather than nominal.

That is a wire break of the same class as the v10.11.1 DAKE1 change: both ends
must upgrade together. It is not a redesign — the ratchet, DAKE, SMP and GCM
layer are untouched — but it is not minimal either, and it cannot be shipped
silently.

**Three options, in order of my preference:**

- **A. Implement it properly** (steps 1-5), version the change, and require
  both ends to upgrade. This is the only route that lets L1 be marked
  RESOLVED, because the forgeability test in Phase 5 can only pass if the
  revealed key is the authenticating key.
- **B. Fix F1 only** — replace the `bytes(32)` with a real derivation so no
  zero placeholder exists — and **explicitly re-scope L1 as NOT RESOLVED**,
  documenting that revelation is currently nominal. Honest, cheap, no wire
  break. The zeros disappear; the property does not arrive.
- **C. Remove the revelation machinery entirely** and document that OTRv4+
  does not implement MAC-key revelation. Currently the code advertises a
  security property it does not provide, which is worse than not claiming it.

I would not recommend a patch that removes the zeros and leaves L1 marked
resolved. That is the specific failure the brief calls out.

---

## What I could not do here

- **Phase 1 (reproduce)** and **Phases 6/9 (integration and full regression)**
  require a built `otrv4_core.so`. No toolchain in this environment reaches
  the 1.85 the dependency tree needs, so I could not execute the reproduction
  the brief asks for. The analysis above is from source, cross-checked between
  `otrv4_.py`, `otrv4plus_xmpp.py` and `ratchet.rs`, with line references so
  every claim is checkable.
- **Phase 7 (cross-implementation check)** against a known-good OTRv4
  implementation — I have no reference implementation to compare against here,
  only the specification text quoted in the brief.

---

## Separate finding, not part of L1

F3 stands on its own regardless of which option is chosen. A per-message MAC
key derived from `session_id ‖ ratchet_id ‖ message_id` — where the last two
are cleartext — means the MAC layer provides no authentication an attacker
holding `session_id` could not forge. GCM is doing the real work. If the MAC
layer is meant to be load-bearing, it needs a chain-derived key; if it is not,
it should be documented as redundant rather than left looking like a second
line of defence.
