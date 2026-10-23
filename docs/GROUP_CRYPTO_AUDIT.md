# Group work, steps 1–2: crypto audit and ML-KEM verification

Steps 1 and 2 of the eleven-step group plan. They gate steps 3 and 4, which
are decisions rather than code, so they are answered here.

Repository state `51c7ebb`, `otrv4_core 0.10.26`, client `10.14.0`.

**Nothing about groups has been built.** No group code exists and none is
proposed by this document.

---

## Step 1 — what the Rust core already has

### Primitives

| Primitive | Crate, resolved version | Where | Python sees |
|---|---|---|---|
| ML-KEM-1024 (FIPS 203) | `pqcrypto-mlkem` 0.1.1 (PQClean portable) | `mlkem.rs`, `dake.rs` | ek/ct/ss bytes |
| ML-DSA-87 (FIPS 204) | `pqcrypto-mldsa` 0.1.2 | `mldsa.rs` | sig bytes |
| Ed448 | `ed448-goldilocks-plus` 0.16.0 | `key_handles.rs`, `ring_sig.rs` | **handle only** |
| X448 | `x448` 0.6.0 | `key_handles.rs`, `voice.rs` | **handle only** |
| AES-256-GCM | `aes-gcm` 0.10.3 | `aead.rs`, `voice.rs`, `filetransfer.rs` | ciphertext |
| SHAKE-256 KDF | `sha3` 0.10.9 | `kdf.rs` | nothing |
| HKDF-SHA512 | `hkdf` 0.12.4 + `sha2` 0.10.9 | `voice.rs` | nothing |
| SHA-256 | `sha2` 0.10.9 | `filetransfer.rs` | digests |
| Argon2id | `argon2` 0.5.3 | `smp.rs` | nothing |
| Zeroization | `zeroize` 1.8.2 | `secure_mem.rs` | n/a |

The AVX2 and NEON paths are disabled (`default-features = false`) because they
caused SIGILL on Termux aarch64 at v10.6.16. The portable C reference
implementation is what runs.

### The finding that matters most for groups

**`Ed448KeyHandle.sign()` already exists**, alongside `verify_ed448_sig` and
`ring_sign`. The key is Rust-owned with no getter; Python passes a message and
receives a signature.

Every authenticated object the group design needs — a membership transition, a
roster commit, a vote, a security concern — is *a signed statement*. That means
**the group state machine needs no new cryptography at all.** It needs a
serialisation format, a hash chain, and signatures over both, all of which are
available today.

### Available KDF usage IDs

`kdf.rs` allocates `0x01`–`0x05`, `0x11`–`0x16`, `0x1C` (ring signature),
`0x1F` (extra symmetric key), `0x20`, `0x21`, `0x22` (file transfer). A group
layer would take the next free values; there is no shortage and the table is
one place.

### The existing hybrid, and whether it is bound

The DAKE combines three X448 outputs and one ML-KEM shared secret:

```
mixed_secret = KDF_1(0x03, dh1 || dh2 || dh3 || mlkem_ss, 64)
```

The ML-KEM ciphertext is not an input to that KDF. It is nonetheless bound:
SPEC §4.5 defines the DAKE transcript as the byte concatenation of every DAKE
wire message, the ciphertext travels inside those messages, and the Ed448 ring
signature in DAKE3 signs the transcript. So the hybrid is transcript-bound by
the surrounding protocol rather than by the combiner itself. That is a valid
construction and no change is proposed.

Recorded because it is the pattern someone would copy: **a new construction
that reuses this combiner shape without an equivalent transcript signature
would not inherit the binding.** If a group KEM is ever adopted, its combiner
should bind the ciphertext and the encapsulation key directly.

### What does not exist

Verified by search, not assumed:

* **No multi-device support.** No device lists, no device identifiers, one
  identity per install. `grep` for `device_list|devicelist|device_id` returns
  nothing.
* **No MUC or group-chat code** of any kind.
* **No fan-out.** Every send path is 1:1.
* **No roster, epoch or membership structure.**

The XMPP identity is a persistent Ed448 sealed in Rust and TOFU-pinned per JID
(`otrv4plus_identity.py`); IRC is deliberately ephemeral. The persistent half
is a reasonable base for a device identity. The *account → many devices*
relation is entirely absent and is its own project.

---

## Step 2 — ML-KEM-1024 verification

### What was wrong with the existing tests

`mlkem.rs` has three unit tests: round trip, byte sizes, wrong-key inequality.
All three compare the implementation **against itself**. A self-consistent
implementation of the wrong algorithm passes every one of them.

### Method

Cross-checked against **Go 1.25.1 `crypto/mlkem`** — a separate codebase, a
separate language, and FIPS 140 validated. Only public values cross the
boundary, which is sufficient: agreement on the shared secret is agreement on
the algorithm.

Both directions were run, because each exercises different halves:

```
Direction A   Go keygen → PQClean encapsulate → Go decapsulate
              checks PQClean's ENCAPSULATION

Direction B   PQClean keygen → Go encapsulate → PQClean decapsulate
              checks PQClean's KEY GENERATION and DECAPSULATION
```

### Result

**10 agreements, 0 mismatches**, five iterations of each direction with fresh
random keys every time.

Sizes confirmed at runtime against FIPS 203 ML-KEM-1024: encapsulation key
1568, decapsulation key 3168, ciphertext 1568, shared secret 32.

### Implicit rejection, confirmed

FIPS 203 decapsulation must not fail. On an invalid ciphertext it returns a
pseudorandom shared secret derived from the implicit-rejection key `z`, rather
than an error. Verified:

* a tampered ciphertext returns 32 bytes and **does not raise**;
* the value is **deterministic** — same ciphertext and key, same answer, so it
  is a function of `z` and not fresh randomness;
* it differs from the real shared secret;
* decapsulating under the wrong key likewise returns rather than raises;
* a wrong-*length* ciphertext is still refused, which is correct — implicit
  rejection is for a well-formed ciphertext that does not decrypt, not for a
  malformed input.

This matters beyond conformance: any caller written against a raising API
would break on a conforming implementation, and an implementation that raised
would leak through the error whether a ciphertext was well formed.

### Made repeatable

`tests/test_mlkem_cross_implementation.py`, 10 tests. It **skips** where no Go
toolchain is present, which includes Termux — it is a development-machine
verification, not a runtime dependency. Last actually executed 2026-09-01 with
Go 1.25.1; the skip reason says so, so a green run on a phone cannot be
mistaken for a green cross-check.

---

## Steps 3 and 4 — what the audit says about them

### Step 3, "define hybrid KEM construction"

**This step is unnecessary under pairwise fan-out, and is the strongest
argument for choosing it.**

Fan-out has no group key. Each message is encrypted separately to each member
under the existing 1:1 session, which is already hybrid, already
DAKE-authenticated, and already transcript-bound. The group inherits every
cryptographic property of the 1:1 channel without a new construction, a new
combiner, or a new transcript to get wrong.

A hybrid KEM is only needed if a *shared group secret* is adopted — sender
keys or TreeKEM. At 30 members that buys one encryption per message instead of
29, and costs a group key agreement that has to be designed, specified and
verified. For a 200-byte chat message the saving is ~6 KB per send.

If it is ever adopted, the combiner should bind the ML-KEM ciphertext and
encapsulation key directly, for the reason in step 1.

### Step 4, "MLS adoption vs compatible custom layer"

The audit produces a decisive technical answer.

RFC 9420 defines a ciphersuite that matches this project's classical
primitives exactly — X448 for key exchange, Ed448 for signatures, AES-256-GCM,
SHA-512. So MLS is not a poor fit on those grounds.

**But MLS has no standardised post-quantum ciphersuite.** ML-KEM in MLS is
draft work, not RFC 9420. Adopting MLS as specified means a group whose
confidentiality is X448-only while every 1:1 session in the same client is
hybrid — a group chat strictly weaker than the two-party chat beside it,
against precisely the store-now-decrypt-later adversary this project exists to
resist.

That is the answer to step 4, and it should be written into
`GROUP_SECURITY_ARCHITECTURE.md` rather than left implicit, because "why not
MLS?" is the first question any reviewer will ask.

It does **not** follow that the MLS *architecture* should be discarded. The
epoch, membership-set hash, previous-state hash and commit model are the right
shape and are worth following closely — borrowing the state machine while
keeping this project's hybrid cryptography underneath.

---

## What this audit does not establish

* Nothing here was run on a phone. The cross-implementation check cannot run
  on Termux at all, by design.
* The brace-key rotation's ciphertext binding was **not** traced. The DAKE's
  was, from SPEC §4.5. This only matters if a group KEM is later adopted.
* No side-channel, timing or fault analysis of the PQClean implementation was
  attempted. Agreement on outputs is not a statement about how they are
  computed.
* FIPS 140 validation belongs to Go's implementation. Agreeing with a
  validated implementation is strong evidence of algorithm conformance; it is
  not validation of this one.
