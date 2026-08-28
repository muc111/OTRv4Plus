# OTRv4+ Protocol Specification

**Version:** 10.13.1
**Status:** Draft / Research Prototype
**Repository:** github.com/muc111/OTRv4Plus

---

## 0. Preface

### 0.1 Scope

This document is the formal wire-level and cryptographic specification for OTRv4+, a
post-quantum hardened extension of the OTRv4 protocol. It is intended to be precise
enough that an independent implementation can be written from this document alone,
without reference to the source code.

OTRv4+ is **not** wire-compatible with stock OTRv4. The two protocols cannot
interoperate. A stock OTRv4 client and an OTRv4+ client cannot complete a handshake
with each other.

### 0.2 Relationship to OTRv4

OTRv4+ extends the OTRv4 Internet Draft (Goldbeck, de Moura, et al.). Where this
document does not explicitly override OTRv4, the OTRv4 specification applies. The
extensions defined here are:

1. ML-KEM-1024 (FIPS 203) encapsulation key transport in the DAKE.
2. ML-KEM-1024 brace-key contribution to session key derivation.
3. ML-KEM-1024 brace-key rotation in the Double Ratchet.
4. ML-DSA-87 (FIPS 204) hybrid signatures in DAKE3.
5. Hybrid post-quantum Socialist Millionaire Protocol (SMP) using ML-KEM-1024
   and ML-DSA-87 wrapping the classical Schnorr ZKP.
6. An encrypted voice protocol (§9), keyed by a hybrid X448 + ML-KEM-1024
   exchange negotiated inside the OTR channel and carried over I2P datagrams.

### 0.3 Terminology

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, MAY, and OPTIONAL are to be interpreted as described in RFC 2119.

### 0.4 Notation

- All multi-byte integers are **big-endian** (network byte order) unless stated otherwise.
- `||` denotes byte-string concatenation.
- `BYTE` is an 8-bit unsigned integer.
- `INT` is a 32-bit unsigned big-endian integer (4 bytes).
- `x[a..b]` denotes bytes from offset `a` (inclusive) to `b` (exclusive), zero-indexed.
- Lengths are in bytes.

---

## 1. Cryptographic Primitives

| Primitive | Algorithm | Parameters |
|-----------|-----------|------------|
| Identity signature | Ed448 | RFC 8032, 57-byte keys |
| Ephemeral key exchange | X448 | RFC 7748, 56-byte keys |
| Deniable authentication | Ed448 ring signature | OTRv4 §, 228-byte signature |
| Post-quantum KEM | ML-KEM-1024 | FIPS 203, Level 5 |
| Post-quantum signature | ML-DSA-87 | FIPS 204, Level 5 |
| Hash / XOF | SHAKE-256, SHA3-512 | FIPS 202 |
| MAC | HMAC-SHA3-512 | RFC 2104 + FIPS 202 |
| AEAD | AES-256-GCM | NIST SP 800-38D, 96-bit nonce, 128-bit tag |
| SMP group | 3072-bit MODP | RFC 3526 Group 15 |

### 1.1 Fixed Sizes

| Element | Size (bytes) |
|---------|-------------|
| Ed448 public key | 57 |
| Ed448 private seed | 57 |
| X448 public key | 56 |
| X448 private key | 56 |
| ML-KEM-1024 encapsulation key (ek) | 1568 |
| ML-KEM-1024 ciphertext (ct) | 1568 |
| ML-KEM-1024 decapsulation key (dk) | 3168 |
| ML-KEM-1024 shared secret | 32 |
| ML-DSA-87 public key | 2592 |
| ML-DSA-87 signature | 4627 |
| Ring signature (sigma) | 228 |
| HMAC-SHA3-512 MAC | 64 |
| SMP prime / group element | 384 |
| SSID | 8 |
| AES-256-GCM nonce | 12 |
| AES-256-GCM authentication tag | 16 |
| Ratchet (data-message) header | 64 |

---

## 2. Key Derivation Function

### 2.1 Core KDF

All key derivation uses `KDF_1`, defined as:

```
KDF_1(usage_id, value, output_len) =
    SHAKE-256( "OTRv4" || usage_id || value )  truncated/expanded to output_len bytes
```

Where:
- `"OTRv4"` is the 5-byte ASCII domain separator `0x4F 0x54 0x52 0x76 0x34`.
- `usage_id` is a single BYTE (see §2.2).
- `value` is the input keying material.
- The SHAKE-256 XOF output is read for exactly `output_len` bytes.

The domain separator is `"OTRv4"` (not `"OTRv4+"`) for compatibility with the
underlying OTRv4 KDF construction. The OTRv4+ extensions are distinguished by
**usage IDs**, not by the domain string.

### 2.2 Usage IDs

| Name | usage_id | Purpose |
|------|----------|---------|
| SSID | 0x01 | Session ID derivation |
| BRACE_KEY | 0x02 | Brace key derivation |
| SHARED_SECRET | 0x03 | Mixed shared secret |
| AUTH_R_MAC | 0x04 | DAKE2 Auth-R MAC |
| AUTH_I_MSG | 0x05 | DAKE3 Auth-I |
| ROOT_KEY | 0x11 | Ratchet root key |
| CHAIN_KEY | 0x12 | Ratchet chain key advance |
| MESSAGE_KEY | 0x13 | Per-message key |
| MAC_KEY | 0x14 | Per-message MAC key |
| DAKE_MAC_KEY | 0x15 | DAKE handshake MAC key |
| BRACE_KEY_ROTATE | 0x16 | Brace key rotation |
| EXTRA_SYM_KEY | 0x1F | Extra symmetric key (TLV 7) |
| PQ_BRACE_KEY | 0x20 | SMP post-quantum binding key |
| NONCE_DERIVE | 0x21 | Nonce derivation (reserved; see §5.4) |

Two usage IDs are defined for OTRv4 compatibility but are not load-bearing in the
data-message path of this implementation. `MAC_KEY` (0x14) is reserved: data
messages are authenticated by the AES-256-GCM tag (§5.4), not by a separate HMAC,
so no per-message MAC key is derived or transmitted. `NONCE_DERIVE` (0x21) is
reserved: the data-message AEAD draws a fresh random 96-bit nonce per message from
the system CSPRNG rather than deriving it (§5.4). Implementations targeting wire
compatibility with this specification MUST follow §5.4 and MUST NOT derive the
nonce from `NONCE_DERIVE`.

### 2.3 Derived KDF Functions

**Chain key advance** (per message):
```
new_chain_key = KDF_1(0x12, chain_key, 32)
message_key   = KDF_1(0x13, chain_key, 32)
```

**Root key step** (32-byte variant):
```
tmp           = KDF_1(0x11, root_key || dh_output, 64)
new_root_key  = tmp[0..32]
new_chain_key = tmp[32..64]
```

**Brace key rotation:**
```
new_brace_key = KDF_1(0x16, brace_key || mlkem_shared_secret, 32)
```

**Brace key derivation** (from ML-KEM only, zero seed in DAKE):
```
brace_key = KDF_1(0x02, [0x00 * 32] || mlkem_shared_secret, 32)
```

**SSID:**
```
ssid = KDF_1(0x01, shared_secret, 8)
```

**HMAC-SHA3-512:**
```
hmac_sha3_512(key, data) = HMAC-SHA3-512(key, data)   // 64-byte output
```

**Fingerprint:**
```
fingerprint(pubkey_bytes) = SHA3-512(pubkey_bytes)   // 64-byte output
```

---

## 3. ClientProfile

The ClientProfile carries the long-term Ed448 identity key and is exchanged
during the DAKE. Its structure (as parsed by the wire decoder):

```
Offset  Size           Field
------  -------------  --------------------------------------------
0       1              profile_type (BYTE)
1       1              num_versions (BYTE, value V, 1..8)
2       V              versions[] (V bytes, e.g. 0x04 for OTRv4)
2+V     57             Ed448 identity public key
...     56             X448 prekey public key
...     8              expiry timestamp (INT64, big-endian, unix seconds)
...     114            Ed448 signature over the profile body
```

**Total ClientProfile size** = `1 + 1 + V + 57 + 56 + 8 + 114 = 237 + V` bytes.

For the typical case of a single version (`V = 1`, value `0x04`), the
ClientProfile is **238 bytes**.

The Ed448 identity public key is located at offset `2 + V`. Implementations MUST
parse `num_versions` to locate it; the offset is not fixed.

`num_versions` MUST be in the range 1..8 inclusive. A value of 0 or > 8 MUST
cause the message to be rejected.

---

## 4. Deniable Authenticated Key Exchange (DAKE)

The DAKE is a three-message handshake: DAKE1 (initiator → responder),
DAKE2 (responder → initiator), DAKE3 (initiator → responder).

Message type bytes:

| Message | Type byte |
|---------|-----------|
| DAKE1 | 0x35 |
| DAKE2 | 0x36 |
| DAKE3 | 0x37 |

### 4.1 DAKE1 (Identity Message)

Sent by the initiator. Wire layout:

```
Offset    Size      Field
--------  --------  ------------------------------------------
0         1         message_type = 0x35
1         56        initiator X448 ephemeral public key
57        1568      initiator ML-KEM-1024 encapsulation key (ek)
1625      237+V     initiator ClientProfile
1625+P    2592      [OPTIONAL] initiator ML-DSA-87 public key
```

Where `P = 237 + V` is the ClientProfile size.

The ML-DSA-87 public key is OPTIONAL and is present if and only if the remaining
bytes after the ClientProfile equal exactly 2592. An implementation determines
presence by checking whether `(total_length - offset_after_profile) >= 2592`.

**Minimum DAKE1 size:** `1 + 56 + 1568 + 3 = 1628` bytes (the `+3` is the minimum
parseable profile header before length validation). A conforming DAKE1 with a
single-version profile and ML-DSA public key is
`1 + 56 + 1568 + 238 + 2592 = 4455` bytes.

### 4.2 DAKE2 (Auth-R Message)

Sent by the responder after processing DAKE1. Wire layout:

```
Offset    Size      Field
--------  --------  ------------------------------------------
0         1         message_type = 0x36
1         56        responder X448 ephemeral public key
57        1568      ML-KEM-1024 ciphertext (ct), encapsulated to
                    the initiator's ek from DAKE1
1625      237+V     responder ClientProfile
1625+P    2592      [OPTIONAL] responder ML-DSA-87 public key
...       64        MAC (HMAC-SHA3-512), see §4.2.1
```

#### 4.2.1 DAKE2 MAC

The MAC is computed over the **entire wire body** preceding the MAC field:

```
wire_body = message_type || responder_X448_pub || ct || ClientProfile
            [ || responder_ML-DSA-87_pub ]
mac_key   = KDF_1(0x15, mixed_secret, 64)       // DAKE_MAC_KEY
MAC       = HMAC-SHA3-512(mac_key, wire_body)
```

The MAC covers the message type byte and the optional ML-DSA public key if
present. The receiver MUST compute the MAC over `data[0..offset_of_mac]` and
compare using a constant-time equality function. A MAC mismatch MUST abort the
handshake.

### 4.3 DAKE3 (Auth-I Message)

Sent by the initiator after processing DAKE2. Wire layout:

```
Offset    Size      Field
--------  --------  ------------------------------------------
0         1         message_type = 0x37
1         228       Ed448 ring signature (sigma)
229       1         ML-DSA flag: 0x01 = present, 0x00 = absent
230       4627      [present iff flag==0x01] ML-DSA-87 signature
```

A DAKE3 with the ML-DSA signature present is
`1 + 228 + 1 + 4627 = 4857` bytes. Without it, `1 + 228 + 1 = 230` bytes.

When the flag is `0x01`, the receiver MUST verify **both** the Ed448 ring
signature and the ML-DSA-87 signature. Both MUST verify for the handshake to
succeed (hybrid authentication).

### 4.4 Session Key Derivation

After DAKE2 is generated (responder) or processed (initiator), both parties
compute three X448 Diffie-Hellman shared secrets and one ML-KEM shared secret.

**DH computations** (responder side; initiator is symmetric):
```
dh1 = X448(our_ephemeral_priv,  peer_ephemeral_pub)
dh2 = X448(our_ephemeral_priv,  peer_prekey_pub)
dh3 = X448(our_prekey_priv,     peer_ephemeral_pub)
```

**ML-KEM shared secret:**
- Responder: `(ct, mlkem_ss) = ML-KEM-1024.Encapsulate(initiator_ek)`
- Initiator: `mlkem_ss = ML-KEM-1024.Decapsulate(our_dk, ct)`

**Mixed secret** (order is normative):
```
combined      = dh1 || dh2 || dh3 || mlkem_ss
mixed_secret  = KDF_1(0x03, combined, 64)        // SHARED_SECRET
```

The classical DH secrets are concatenated **first**, in the order dh1, dh2, dh3,
followed by the ML-KEM shared secret. This ordering is normative and both parties
MUST use it identically.

**Derived keys:**
```
ssid       = KDF_1(0x01, mixed_secret, 8)
brace_key  = KDF_1(0x02, [0x00 * 32] || mlkem_ss, 32)
root_key, chain_key_send, chain_key_recv, extra_sym_key
           = (derived per OTRv4 §, using mixed_secret and brace_key)
```

A quantum adversary who recovers all three X448 DH secrets still cannot compute
`mixed_secret` without also recovering `mlkem_ss`, which requires breaking
ML-KEM-1024.

### 4.5 DAKE Transcript and Ring Signature

**Transcript.** Both parties maintain a running DAKE transcript `t`, the in-order
byte concatenation of every DAKE wire message as it is sent or received. After
DAKE2, `t = DAKE1_bytes || DAKE2_bytes`. The DAKE3 signatures are computed over `t`
as it stands at that point; `t` does NOT include DAKE3 itself at signing time.
After a DAKE3 is verified, its bytes are appended to `t` for any later binding.
Both peers MUST accumulate the transcript identically, byte for byte.

**Ring signature (sigma).** DAKE3 carries an Ed448 Schnorr ring signature that
proves the signer holds the private key for one of two long-term identity keys:
its own and the peer's. Because either identity-key holder could have produced it,
the signature authenticates the handshake while remaining deniable to any third
party. This is a 1-out-of-2 OR proof, encoded as four 57-byte scalars, total
**228 bytes**.

Let `G` be the Ed448 base point, `Q` the group order, `seed` the signer's identity
seed, and `usage = 0x1C`. The ring is the ordered pair of identity public keys
`(A1, A2)` and the signed message is the transcript `t`. The signer knows the
discrete log of one ring member; the construction below is written for a signer
who knows `a1` with `A1 = a1·G`, simulating the `A2` clause:

```
Sign:
  t1     = SHAKE-256(seed || 0x01, 57) mod Q          # ephemeral nonce
  T1     = t1 · G
  c2, r2 = uniform random scalars in [0, Q-1]         # simulated clause
  T2     = r2 · G + c2 · A2
  c      = SHAKE-256(0x1C || t || A1 || A2 || T1 || T2, 57) mod Q
  c1     = (c - c2) mod Q
  r1     = (t1 - c1 · a1) mod Q
  sigma  = c1 || r1 || c2 || r2                        # 4 x 57 = 228 bytes

Verify:
  parse (c1, r1, c2, r2) from sigma                    # each 57-byte LE scalar
  T1'    = r1 · G + c1 · A1
  T2'    = r2 · G + c2 · A2
  c'     = SHAKE-256(0x1C || t || A1 || A2 || T1' || T2', 57) mod Q
  ACCEPT iff c' == (c1 + c2) mod Q
```

Scalars are 57-byte little-endian (the high byte is `0x00` for canonical scalars
reduced mod `Q`, which is below 2^446). Points are 57-byte compressed Edwards
encodings per RFC 8032. Verification accepts regardless of which clause the signer
simulated, so the verifier need not know which party signed; both peers MUST,
however, place the two identity keys in the **same order** in the challenge hash.
The reference implementation fixes this order, and a conforming implementation MUST
match it.

**ML-DSA-87 over the transcript.** When the DAKE3 ML-DSA flag is `0x01`, the
ML-DSA-87 signature is computed over the same transcript `t` and MUST also verify
for the handshake to succeed. Unlike the ring signature, the ML-DSA-87 signature
is attributable and therefore not deniable (§10.1).

---

## 5. Double Ratchet

OTRv4+ uses the OTRv4 Double Ratchet (OTRv4 §) with one extension: an ML-KEM-1024
brace-key contribution folded in at every DH ratchet step.

The ratchet combines two mechanisms. The **symmetric-key ratchet** governs
individual messages: each direction has a 32-byte chain key, and sending or
receiving a message advances that chain key by one KDF step (§5.3), yielding a
single-use message key and overwriting the previous chain key. Because the KDF
runs only forward, a compromised chain key does not expose earlier messages
(forward secrecy). The **DH ratchet** governs the longer-term key material: every
data message header (§5.4) carries the sender's current X448 ratchet public key,
and when a receiver sees a public key it has not used before, it performs an X448
exchange against its own current ratchet secret, folds the result (together with
the brace key, §5.2) into the root key to derive a fresh receiving chain, then
generates a new X448 ratchet key pair of its own and folds again to derive a fresh
sending chain. Fresh DH contributions periodically inject entropy that no prior
state can predict, which is what gives the ratchet post-compromise (self-healing)
security. Each peer holds two chains at any time (`chain_key_send`,
`chain_key_recv`), a root key, a brace key, and the skipped-key and replay state of
§5.5.

State variables per direction: `prev_chain_len` (the number of messages sent under
the previous sending chain, transmitted as the header field `prev_chain_len`) and
`msg_num` (the index of the current message within its chain). Both are 32-bit and
are used by the receiver to bound skipped-key derivation across ratchet steps
(§5.5).

### 5.1 Brace Key Rotation

At each DH ratchet step:

1. The party performing the ratchet step generates a fresh ML-KEM-1024 keypair
   and includes the encapsulation key in the data message header.
2. The receiving party encapsulates to that key:
   ```
   (ct, mlkem_ss) = ML-KEM-1024.Encapsulate(ek)
   ```
   and includes `ct` in its next data message.
3. Both parties update the brace key:
   ```
   new_brace_key = KDF_1(0x16, old_brace_key || mlkem_ss, 32)   // BRACE_KEY_ROTATE
   ```

### 5.2 Root Key Folding

The brace key is folded into the root key derivation at every ratchet step:

```
root_key_input = dh_secret || brace_key
seed           = KDF_1(0x11, root_key || root_key_input, 64)    // ROOT_KEY
new_root_key   = seed[0..32]
new_chain_key  = seed[32..64]
```

### 5.3 Per-Message Keys

```
message_key   = KDF_1(0x13, chain_key, 32)        // MESSAGE_KEY
new_chain_key = KDF_1(0x12, chain_key, 32)        // CHAIN_KEY
```

The message key is consumed once, by the AEAD of §5.4, and the chain key is then
overwritten by `new_chain_key`. The third value some KDF call sites destructure
(a MAC key) is not used on the data path; see §2.2 and §5.4.

### 5.4 Data Message Format and AEAD

Each application message is encrypted under its single-use `message_key` with
AES-256-GCM (NIST SP 800-38D). GCM is the sole authenticator of a data message:
there is no separate HMAC on the data path.

**Header.** The ratchet header is 64 bytes, big-endian:

```
Offset  Size  Field
------  ----  ---------------------------------------------
0       56    dh_pub          (sender's current X448 ratchet public key)
56      4     prev_chain_len  (INT, messages in the previous sending chain)
60      4     msg_num         (INT, index of this message in its chain)
```

**Associated data (AAD).** The GCM associated data is the 64-byte ratchet header
followed by the 8-byte session identifier `ssid` derived during the DAKE (§4.4).
Both peers derive `ssid` symmetrically from `mixed_secret` and MUST use it
identically as the fixed `ad` component. The derivation and total AAD are:

```
ad  = ssid                           // 8 bytes; KDF_1(0x01, mixed_secret, 8) from §4.4
aad = header_bytes(64) || ad         // 72 bytes total
```

`ad` is fixed for the lifetime of the session (it does not change per message or per
ratchet step). An implementation MUST derive `ad` from the session SSID exactly as
above; any deviation causes decryption failure with no distinguishable error.

The header is authenticated but NOT encrypted: the receiver needs `dh_pub`,
`prev_chain_len`, and `msg_num` in the clear to select or derive the correct key
before decrypting. Binding them as AAD means any alteration of the header, or any
attempt to replay a message under a different ratchet position, causes the tag to
fail.

**Encryption.**

```
nonce       = 12 random bytes from the system CSPRNG     // 96-bit, fresh per message
ct_with_tag = AES-256-GCM-Encrypt(key = message_key, nonce, plaintext, aad)
ciphertext  = ct_with_tag[0 .. len-16]
tag         = ct_with_tag[len-16 .. len]                 // 128-bit
```

The message key is 32 bytes (AES-256). The nonce is fresh and random per message.
Because each message key is itself used exactly once, nonce uniqueness under a
given key holds regardless; the random nonce is defence in depth, not a uniqueness
requirement. The nonce MUST be transmitted with the message, since the receiver
cannot reconstruct it. The values placed in the data message are therefore the
64-byte header, the 12-byte nonce, the ciphertext, and the 16-byte tag, carried
inside the OTRv4 DATA message envelope (the outer envelope, instance tags, and
flags follow OTRv4 §).

**Decryption.** The receiver reconstructs `aad = received_header || ad`, appends
the tag to the ciphertext, and calls AES-256-GCM-Decrypt with the message key for
that header position. Any failure (wrong key, wrong nonce, AAD mismatch, or
tampered ciphertext) MUST return a single generic decryption error that does not
distinguish the cause.

The same AES-256-GCM construction (32-byte key, 12-byte nonce, `ciphertext || tag`
output, AAD label) is reused, non-normatively for interop, to seal secrets at rest:
the SMP secret vault and the on-device key store both encrypt their contents with
it under a separately derived key.

### 5.5 Out-of-Order, Skipped Keys, and Replay

Messages may arrive out of order or be lost. The receiver uses the header fields to
recover without compromising forward secrecy.

**Skipped keys.** When an arriving `msg_num` is ahead of the receiver's position in
the current receiving chain, the receiver advances the chain to catch up and stores
each intermediate message key, indexed by `(dh_pub, msg_num)`, so a later-arriving
message can still be decrypted. When a header presents a new `dh_pub` (a DH ratchet
step), the receiver first skips and stores up to `prev_chain_len` keys from the
previous receiving chain, then performs the DH ratchet (§5.2).

**Bounds (REQUIRED).**

| Constraint | Value | Behaviour on breach |
|------------|-------|---------------------|
| Max skip per chain advance (`MAX_SKIP`) | 1000 | reject message (MaxSkipExceeded) |
| Max stored skipped keys (`MAX_MESSAGE_KEYS`) | 2000 | evict oldest stored key |

A skip request exceeding `MAX_SKIP` MUST be rejected rather than serviced, to
prevent a peer from forcing unbounded KDF work with a single large `msg_num`. The
stored-key set is capped at `MAX_MESSAGE_KEYS`; on overflow the oldest entry is
evicted.

**Replay.** The receiver maintains a cache of recently accepted `(dh_pub, msg_num)`
pairs and MUST reject any message whose pair is already present. Every stored
skipped key, like every chain, root, and brace key, MUST be zeroized as soon as it
is consumed or evicted.

---

## 6. Socialist Millionaire Protocol (SMP): Hybrid Post-Quantum

SMP provides out-of-band identity verification by proving both parties hold the
same shared secret, without revealing it. OTRv4+ implements a hybrid construction:
the classical four-step Schnorr ZKP over the 3072-bit MODP group runs alongside an
ML-KEM-1024 and ML-DSA-87 binding layer.

### 6.1 Group Parameters

- **Prime `p`:** the 3072-bit MODP prime from RFC 3526, Group 15 (384 bytes).
- **Order `q`:** `(p - 1) / 2` (Sophie Germain / safe-prime subgroup order).
- **Generator `g`:** `2`.

Group elements are encoded as **384-byte big-endian** fixed-width integers.

### 6.2 Wire Encoding of Group Elements

Each SMP message is a sequence of length-prefixed fields:

```
field = length (INT, 4 bytes, big-endian) || value (length bytes)
message = field_1 || field_2 || ... || field_n
```

The number of fields per message is fixed (see §6.5). The decoder reads exactly
`n` fields. Each field's length prefix is a 32-bit big-endian integer.

### 6.3 Group Element Validation

Every received group element MUST be validated before use:

```
v = big-endian integer of the field bytes
REJECT if v < 2
REJECT if v >= p
```

A field failing validation MUST abort the SMP session and zeroize all state.

### 6.4 Secret Derivation

The SMP secret scalar is derived from the user's shared passphrase, the session
ID, and both fingerprints. This is purely classical and symmetric (it does NOT
incorporate ML-KEM material; see §6.7 for the rationale).

**Step 1 depends on the negotiated wire version** (§6.1). Wire version `0x03`
stretches with Argon2id; `0x01` and `0x02` use the iterated SHAKE-256
construction. The two produce different scalars from the same passphrase, which
is why this required a version byte rather than a silent upgrade: a peer pair
that disagrees MUST abort at the version check (§6.1) and MUST NOT proceed to
report a passphrase mismatch, because the passphrase may well be correct.

#### Step 1a: Argon2id stretch (wire version 0x03)

```
(first, second) = (our_fp, peer_fp) if our_fp <= peer_fp
                  else (peer_fp, our_fp)              // lexicographic ordering

salt = SHA3-512( "OTRv4+SMP-ARGON2-SALT-v3" || 0x00
               || LEN(session_id) || session_id
               || LEN(first)      || first
               || LEN(second)     || second )[0..32]  // LEN = 8-byte BE length

state = Argon2id( password = raw_secret,
                  salt     = salt,
                  m        = 65536 KiB,   // 64 MiB
                  t        = 3,
                  p        = 4,
                  outlen   = 64 )         // Argon2 version 0x13
```

Where `"OTRv4+SMP-ARGON2-SALT-v3"` is the 24-byte ASCII literal followed by a
`0x00` byte.

Every field entering the salt is length-prefixed. Without this, a
`(session_id, first, second)` triple could be re-split into a different triple
with the same concatenation and derive the same salt.

The Argon2 cost parameters are part of the wire format. Both peers MUST use
identical values; differing parameters yield different scalars and SMP fails
with an ordinary "no match", indistinguishable from a wrong passphrase.
Changing any of them requires a new wire version byte.

The salt is deterministic rather than random, and MUST be. Both peers have to
arrive at the same scalar, and SMP has no message in which to carry a salt. The
salt's role in Argon2 is domain separation between derivations, not secrecy;
`session_id` is per-DAKE, so even the same two peers re-running SMP derive
under a fresh salt.

Implementations MUST NOT fall back to Step 1b if Argon2id fails. Every length
involved is fixed by the constants above, so a failure is an implementation
bug; degrading to the weaker stretch would require both peers to make the same
mistake in order to still interoperate, and would silently undo the property
this version exists to provide.

#### Step 1b: SHAKE-256 iterated KDF, 50,000 rounds (wire versions 0x01, 0x02)

```
state = SHAKE-256( "OTRv4+SMP-v2" || 0x00 || raw_secret )   // 64-byte output
for i in 0 .. 49998:                                          // KDF_ROUNDS - 1
    state = SHAKE-256( INT(i) || state )                      // INT = 4-byte BE
```
Where `"OTRv4+SMP-v2"` is the 12-byte ASCII literal followed by a `0x00` byte.

This construction is retained verbatim for interoperability with peers that
have not been updated, and implementations MUST NOT alter it while they still
speak `0x02`.

Its weakness is not the round count. Nothing user-specific enters the expensive
part: the session ID and fingerprints are mixed in afterwards by Step 2, a
single HMAC. An attacker therefore computes `state` once per candidate
passphrase and reuses it against every user and every session, after which
testing a candidate against a captured SMP transcript costs one HMAC. The
iteration count buys far less than it appears to. Wire version `0x03` addresses
this by moving the session ID and fingerprints into the Argon2id salt, and adds
memory-hardness on top.

Note that SMP transcripts permit an offline dictionary attack on the shared
passphrase by any party who completes SMP with the user. A memory-hard,
per-session-salted KDF raises the cost of that attack; it does not remove it.
Passphrases SHOULD still be chosen accordingly.

**Step 2: HMAC-SHA3-512 session binding:**
```
hmac_key = SHA3-512(session_id)
(first, second) = (our_fp, peer_fp) if our_fp <= peer_fp
                  else (peer_fp, our_fp)              // lexicographic ordering
binding = HMAC-SHA3-512(hmac_key, first || second || state)
```

The fingerprints are ordered lexicographically so both parties derive the same
secret regardless of role. Implementations MUST NOT use role-dependent ordering.

Under `0x03` the session ID and fingerprints are already bound into the salt, so
Step 2 is redundant there. It is retained for all versions so that the path from
`state` to the scalar is identical regardless of which stretch produced it.

**Step 3: reduce mod order:**
```
secret_int = big-endian-integer(binding) mod q
if secret_int == 0: secret_int = 1
secret = 384-byte big-endian encoding of secret_int
```

### 6.5 Classical SMP Messages

The classical SMP four-step protocol fields (each a length-prefixed group element
or scalar per §6.2):

**SMP1 (initiator → responder), 6 fields:**
```
g2a, c2, d2, g3a, c3, d3
```
Where `g2a = g^a2`, `g3a = g^a3`, and `(c2,d2)`, `(c3,d3)` are Schnorr ZKPs of
knowledge of `a2`, `a3` respectively.

**SMP2 (responder → initiator), 11 fields:**
```
g2b, c2b, d2b, g3b, c3b, d3b, Pb, Qb, cP, d5, d6
```

**SMP3 (initiator → responder), 5 fields:** (decoder reads 5)
```
Pa, Qa, cP, d5, d6   (plus Ra and its ZKP per OTRv4 §)
```

**SMP4 (responder → initiator), 3 fields:**
```
Rb, cR, d7
```

The Schnorr ZKP for each statement uses a per-statement version byte in the
challenge hash (see §6.6).

### 6.6 Schnorr ZKP Construction

For a statement proving knowledge of exponent `x` such that `base^x = value`:

**Prove** (given random nonce `r`):
```
commitment = base^r mod p
c = SHA3-512( version_byte || commitment_bytes || base_val_bytes ) mod q
d = (r - c*x) mod q          // computed as (r + q - (c*x mod q)) mod q
output (c, d)
```

**Verify:**
```
gd = base^d mod p
gc = value^c mod p
commitment' = (gd * gc) mod p
c' = SHA3-512( version_byte || commitment'_bytes || base_val_bytes ) mod q
ACCEPT iff c' == c
```

The `version_byte` is a per-statement domain separator (1, 2, 3, 4, ... assigned
per ZKP within the protocol) preventing cross-protocol proof reuse.

All `base^exp mod p` operations on secret exponents MUST be constant-time
(Montgomery-form modular exponentiation is RECOMMENDED).

### 6.7 Post-Quantum Binding Layer

The hybrid PQ layer wraps the classical SMP with ML-KEM-1024 and ML-DSA-87.

**Wire version byte:** every hybrid-PQ SMP message is prefixed conceptually with
a version indicator:
- `0x01` = classical SMP only
- `0x02` = hybrid post-quantum, iterated SHAKE-256 secret derivation (§6.4 Step 1b)
- `0x03` = hybrid post-quantum, Argon2id secret derivation (§6.4 Step 1a)

`0x03` is the default for new sessions. Implementations MUST NOT select a lower
version automatically.

`0x02` and `0x03` have **identical message layouts**; both carry the ML-KEM and
ML-DSA payloads described below, and message sizes are unchanged between them.
They differ only in §6.4 Step 1, and therefore derive different secret scalars
from the same passphrase.

A version mismatch between peers MUST abort the session, at the version check
and before any comparison of secrets. No silent downgrade to classical mode, and
no silent downgrade from `0x03` to `0x02`, is permitted.

Because `0x02` and `0x03` derive different scalars, a mismatched pair that was
allowed to continue would complete the protocol and report that the passphrases
do not match, when they may be identical. Implementations MUST therefore
distinguish the two conditions in anything shown to the user: a version mismatch
means the peers are running different builds, not that the passphrase is wrong.

**SMP1 (hybrid):** the initiator additionally generates an ML-KEM-1024 keypair and
an ML-DSA-87 keypair. The encapsulation key (1568 bytes) and the ML-DSA-87 public
key (2592 bytes) are appended to the classical SMP1 payload.

**SMP2 (hybrid):** the responder:
```
(ct, kem_ss)   = ML-KEM-1024.Encapsulate(initiator_ek)
transcript_tag = HMAC-SHA3-512(SHA3-512(ssid), smp1_wire_bytes)   // §6.10; see below
pq_binding_key = KDF_1(0x20, domain || kem_ss || transcript_tag, 32)  // PQ_BRACE_KEY
```
generates its own ML-DSA-87 keypair, and signs the entire SMP2 wire body with
ML-DSA-87 using `pq_binding_key` as signing context. It appends `ct` (1568),
its ML-DSA-87 public key (2592), and the ML-DSA-87 signature (4627).

The terms in the `pq_binding_key` derivation are defined as follows:

- **`domain`** = the 12-byte ASCII literal `"OTRv4+SMP-PQ"` (no null terminator).
  This is a domain separator that distinguishes this key from all other
  `KDF_1(0x20, ...)` outputs. Its size and encoding are normative.

- **`kem_ss`** = the 32-byte ML-KEM-1024 shared secret produced by
  `ML-KEM-1024.Encapsulate(initiator_ek)` above. This is the quantum-hardening
  contribution; an attacker who cannot break ML-KEM-1024 cannot derive this key.

- **`transcript_tag`** = the 64-byte SMP transcript MAC per §6.10, computed as
  `HMAC-SHA3-512(SHA3-512(ssid), prior_smp_wire_bytes)` over all SMP wire messages
  received before the current step, in order. At SMP2 this covers only SMP1 wire
  bytes; at SMP3 it covers SMP1 || SMP2 wire bytes; at SMP4 SMP1 || SMP2 || SMP3.
  This binds `pq_binding_key` to the specific transcript, preventing cross-session
  key reuse. Implementations MUST update the running transcript before computing
  `transcript_tag` for each step.

The KDF input is therefore 12 + 32 + 64 = 108 bytes.

**SMP3 / SMP4 (hybrid):** each side verifies the previous step's ML-DSA-87
signature **before** processing the classical fields, then signs its own output
under `pq_binding_key`. SMP3 decapsulates to derive the same `pq_binding_key`:
```
kem_ss         = ML-KEM-1024.Decapsulate(initiator_dk, ct)
transcript_tag = HMAC-SHA3-512(SHA3-512(ssid), smp1_wire_bytes)   // same as SMP2
pq_binding_key = KDF_1(0x20, domain || kem_ss || transcript_tag, 32)
```
The initiator MUST use the same `transcript_tag` value (over SMP1 only) at SMP3
as the responder used at SMP2, so both derive the same `pq_binding_key`.

**Security argument:** breaking the equality proof requires breaking **all three**
of: the 3072-bit discrete logarithm (to forge the classical ZKPs), ML-KEM-1024 (to
recover `kem_ss` and derive `pq_binding_key`), and ML-DSA-87 (to forge any step's
signature). None alone is sufficient.

### 6.8 Equality Test

The final comparison determines whether the secrets match. Given the classical SMP
computation yielding `Pa/Pb` and `Rab`:

```
matched = constant_time_equal( fe_bytes(pa_over_pb), fe_bytes(rab) )
```

The comparison MUST be constant-time. The result is a single boolean: match
(secrets equal, identity verified) or no-match (secrets differ).

### 6.9 Lifecycle and Rate Limiting

| Parameter | Value |
|-----------|-------|
| Maximum attempts | 3 |
| Session timeout | 2700 seconds (45 minutes) |
| Retry cooldown | 30 seconds |
| KDF rounds | 50,000 |

The session timeout accommodates high-latency transports (I2P) with the large
hybrid-PQ wire overhead. On expiry or attempt-limit exhaustion, the SMP session
MUST abort and zeroize all secret state.

### 6.10 Transcript Binding

Each SMP message is fed into a running HMAC-SHA3-512 transcript keyed by the
session ID:
```
transcript_mac = HMAC-SHA3-512(SHA3-512(session_id)[truncated to 64], all_wire_bytes_in_order)
```
The transcript binds the sequence of messages to the session, preventing
message reordering or cross-session splicing.

---

## 7. Message Fragmentation

OTRv4+ messages frequently exceed the IRC line length limit and are fragmented
per OTRv4 §, using the pipe-delimited format:

```
?OTRv4|sender_tag|receiver_tag|fragment_index|fragment_total|fragment_data
```

Where:
- `sender_tag`, `receiver_tag` are 8-hex-digit instance tags.
- `fragment_index` is the 1-based index (5-digit zero-padded).
- `fragment_total` is the total count (5-digit zero-padded).
- `fragment_data` is the Base64-encoded chunk of the underlying message.

### 7.1 Reassembly Constraints

| Constraint | Value |
|------------|-------|
| Reassembly state key | (sender_nick, fragment_total) |
| Reassembly timeout | 120 seconds |
| Maximum in-flight fragments per sender | 50 |
| Maximum reassembled payload | 1 MiB |

A receiver MUST discard a fragment set exceeding the in-flight limit, and MUST
reject a reassembled payload exceeding 1 MiB, to prevent memory exhaustion.

### 7.2 Transport-Specific Fragment Sizing

| Transport | Fragment payload size | Send pacing |
|-----------|----------------------|-------------|
| TLS clearnet (IRC) | 450 bytes | Token bucket (4 tokens, 2/fragment, 1/sec refill) |
| I2P SAM (IRC) | 380 bytes | 2 fragments then 6-second pause |
| Tor (IRC) | 450 bytes | 200 ms fixed inter-fragment delay |
| XMPP (any) | fragment only above ~6 KiB | none |

Fragment sizing is a transport-layer concern and does not affect the
cryptographic payload. The IRC I2P sizing reflects the stricter line-length and
flood policies of `irc.postman.i2p`. XMPP carries multi-kilobyte stanzas directly,
so it fragments only payloads exceeding a conservative ~6 KiB threshold and applies
no send pacing; the underlying cryptographic messages (DAKE, SMP, data) are
byte-identical across all transports.

---

## 8. State Machines

### 8.1 DAKE State Machine

```
Initiator:                          Responder:
  Idle                                Idle
   │ generate_dake1()                  │ process_dake1()
   ▼                                   ▼
  SentDake1                          ReceivedDake1
   │ process_dake2()                   │ generate_dake2()
   ▼                                   ▼
  (assemble_dake3)                   SentDake2
   │ send DAKE3                        │ process_dake3()
   ▼                                   ▼
  Established                        Established
```

### 8.2 SMP Phase Machine

```
Idle
 │
 ├─ generate_smp1()              → AwaitingMsg2   (initiator)
 ├─ process_smp1_generate_smp2() → AwaitingMsg3   (responder)
 │
AwaitingMsg2
 │ process_smp2_generate_smp3()  → AwaitingMsg4
AwaitingMsg3
 │ process_smp3_generate_smp4()  → Verified | Failed
AwaitingMsg4
 │ process_smp4()                → Verified | Failed

Terminal states: Verified, Failed, Aborted
```

Any protocol error, validation failure, ZKP verification failure, ML-DSA
verification failure, or version mismatch transitions to **Failed** or **Aborted**
and zeroizes all SMP secret state.

---

## 9. Encrypted Voice

Voice is a separate protocol keyed from, and authenticated by, an established
OTR session. It has its own wire version, its own key schedule, and its own
transport. Nothing in this section changes anything in §1–§8.

### 9.1 Preconditions

A voice call MUST NOT be offered or accepted unless, in this order:

1. the transport is connected;
2. an OTR session is established (DAKE complete, §4);
3. SMP has completed and the engine's own verification predicate reports
   VERIFIED (§6).

The predicate MUST be the cryptographic state, never a UI string, a log line,
or any peer-supplied text. There is no shortcut and no downgrade: if the
predicate is false the call is refused.

### 9.2 Roles

Roles are fixed by who sent the INVITE and never change for the life of the
call. INITIATOR is the caller; RESPONDER is the callee. The initiator generates
the ephemeral ML-KEM-1024 keypair and decapsulates; the responder encapsulates.
That direction is chosen so the 1568-byte encapsulation key rides the INVITE and
the 1568-byte ciphertext rides the ACCEPT — neither side sends both.

### 9.3 Control Messages

Control messages travel **inside** the established OTR channel and are never
sent in the clear. If the OTR channel is unavailable the message is dropped, not
downgraded. Each is a text body:

```
"?OTRv4-CALL:" || VERB || ":" || field ("|" field)*
```

| Verb | Fields |
|---|---|
| `INVITE` | call_id, dest_b64, x448_pub, mlkem_ek |
| `ACCEPT` | call_id, x448_pub, mlkem_ct, confirm_responder |
| `CONFIRM` | call_id, confirm_initiator |
| `REJECT` | call_id, reason |
| `REKEY` | call_id, epoch, x448_pub, mlkem_ek |
| `REKEYACK` | call_id, epoch, x448_pub, mlkem_ct, confirm_responder |
| `REKEYCOMMIT` | call_id, epoch, confirm_initiator |
| `MEDIAPATH` | call_id, epoch, seq, destination, tag |
| `END` | call_id |

Every message carries the call_id and MUST be discarded if it does not match
the receiver's current call. Key confirmation is two-way and role-labelled: the
responder proves possession first (ACCEPT), the initiator second (CONFIRM).
Neither side starts audio before the exchange completes, so a key mismatch can
never cause a frame to be emitted under a key the peer does not hold.

### 9.4 Key Derivation

`LP(x)` is a 4-byte big-endian length prefix followed by `x`. `u64(n)` is an
8-byte big-endian integer. Every field is length-prefixed, so no two distinct
field sets serialise to the same byte string.

```
transcript = LP("OTRv4+Voice/v3")
          || LP(call_id)
          || LP(otr_binding)
          || LP(fp_low) || LP(fp_high)            # sorted — symmetric
          || LP(initiator_x448_pub)
          || LP(responder_x448_pub)
          || LP(mlkem_ek) || LP(mlkem_ct)
          || u64(epoch)

ikm  = LP(x448_shared) || LP(mlkem_shared)        # BOTH mandatory
salt = SHA-512("OTRv4+Voice/Salt/v3" || transcript)
root = HKDF-SHA512(ikm, salt, info = "OTRv4+Voice/Initial/v1" || transcript)
```

`root` is 64 bytes. The construction is a concatenation KDF: an adversary MUST
break X448 **and** ML-KEM-1024 to recover it, and it is not weakened if either
primitive is later broken. An implementation MUST NOT derive the root from
either input alone.

The fingerprints are sorted before hashing so both endpoints produce identical
bytes; the X448 publics are ordered by role rather than by local/remote for the
same reason.

Directional media keys:

```
K_dir = HKDF-SHA512(root, salt = call_id,
                    info = "OTRv4+Voice/Media/v1" || LP(call_id)
                           || u64(epoch) || dir_byte)

dir_byte = 0x01  initiator -> responder
           0x02  responder -> initiator
```

The two directions never share a key, so both counters may start at zero.

Confirmation tags use `"OTRv4+Voice/Confirm/v1" || LP(call_id) || u64(epoch)`,
producing 2 × 32 bytes, one per role. Rekey derives a new root from the old one
under `"OTRv4+Voice/Rekey/v1"`.

### 9.5 Media Frame

```
off  0  sync        u8      0xA7
off  1  version     u8      0x04
off  2  frame_type  u8      0x01 AUDIO | 0x02 PING | 0x03 PONG
off  3  epoch       u64 BE
off 11  counter     u64 BE
off 19  length      u16 BE  (sealed length; constant for the call)
off 21  ciphertext || GCM tag
```

Header length is 21 bytes. The AEAD is AES-256-GCM.

```
AAD   = "OTRv4+Voice/AAD/v3" || LP(call_id) || dir_byte || header[0..21]
nonce = u32BE(epoch mod 2^32) || u64BE(counter)
```

The nonce is **derived, not transmitted**: it costs no bytes and cannot be
tampered with independently of the header. `dir_byte` is **not** on the wire —
the receiver supplies the peer's direction locally, so a frame reflected back at
its own sender fails authentication.

Every security-relevant header field is inside the AAD. Flipping the epoch,
counter, length or frame type causes a tag failure.

A receiver MUST reject a frame whose version byte is not `0x04`. Version
mismatch MUST be reported as a version error, distinguishable from a
cryptographic failure.

**Wire geometry** is fixed for the call and MUST match on both endpoints. With
the defaults — Opus 16 kHz mono, 60 ms frames, 24 kbit/s CBR — the Opus slot is
232 bytes, the plaintext 242 bytes, the sealed body 258 bytes, and the packet
279 bytes, sent at 16.7 packets/s. The slot is derived from bitrate and frame
duration, not hand-set; peers configured differently establish a call, report it
healthy, and carry no audio.

Packet size and rate are **constant for the whole call**. Muting encodes digital
silence rather than suspending transmission. DTX and variable packet sizing MUST
NOT be enabled in the privacy profile: both make packet timing and size depend
on speech.

### 9.6 Replay, Ordering, and the Symmetric Ratchet

Each epoch runs a symmetric ratchet every 500 frames (30 s at the 60 ms
default), giving forward secrecy within an epoch. The ratchet cannot provide
post-compromise security; that comes only from a successful hybrid rekey.

A sliding replay window rejects a counter already accepted. A limited number of
sub-epochs is retained for reordering; the forward-hashing jump from a single
bad frame is bounded. A frame that fails authentication MUST NOT advance any
state.

### 9.7 Endpoint Announcement (`MEDIAPATH`)

An endpoint MAY move mid-call — an I2P SAM session can be lost while the OTR
channel survives. The new destination is announced with:

```
tag = HKDF-SHA512(root, salt = call_id,
                  info = "OTRv4+Voice/Endpoint/v1" || LP(call_id)
                         || u64(epoch) || u64(seq)
                         || LP(destination_ascii)
                         || u8(1 if from_initiator else 0))
```

32 bytes, from the **committed epoch root**. A receiver MUST, in this order:

1. reject unless the call is ACTIVE;
2. reject `seq` less than or equal to the highest already seen — this covers
   replay, control-channel reordering, and any attempt to reinstate a
   destination already moved past;
3. reject an unparseable destination;
4. verify the tag, and only then adopt the destination.

No state may move before the tag verifies, so a forged or replayed announcement
costs nothing and changes nothing. Announcements MUST be rate-limited.

**No media key derives from the destination.** The transcript in §9.4 covers the
call_id, the OTR binding, both fingerprints, the X448 and ML-KEM material and
the epoch, and nothing else. Moving the address therefore invalidates no key:
epoch, replay window, ratchet state and call identity all survive an endpoint
change, and a packet already accepted stays rejected afterwards. An
implementation MUST NOT tie an address change to a rekey.

### 9.8 Transport

Media is carried over I2P SAM v3 repliable datagrams under a transient
destination created for the call. Signalling is carried over the OTR channel on
whatever transport that session uses.

An implementation MUST NOT fall back from I2P to a less private transport for
media, silently or otherwise. Failure MUST be closed, not downgraded. Voice over
Tor is not specified: there is no Tor UDP transport here, and carrying media
over TCP is out of scope.

### 9.9 What This Protocol Claims

Claimed:

* Confidentiality and integrity of media against a classical adversary,
  contingent on X448.
* Confidentiality against a store-now-decrypt-later quantum adversary,
  contingent on ML-KEM-1024. Both are required; neither alone suffices.
* Forward secrecy within a call from the symmetric ratchet, and across rekeys
  from the ephemeral hybrid exchange.
* Post-compromise recovery at each successful hybrid rekey.
* Authentication of the media endpoint address against forgery, replay and
  rollback.

Not claimed:

* **Real-time authentication is only as post-quantum as the DAKE.** The
  ephemeral voice keys are authenticated by the surrounding OTR channel. A
  quantum adversary able to forge that authentication *live* could MITM a call
  in progress; recorded calls remain protected by ML-KEM-1024.
* **Metadata is reduced, not eliminated.** Constant-rate shaping removes
  speech-dependent size and timing. Call start, end, duration, loss, congestion
  and tunnel behaviour remain observable, and the signalling server still sees
  that two identities exchanged encrypted stanzas.
* Anything about latency. See §9.5 for the shape of the traffic, not its speed.

---

## 10. Security Requirements for Implementations

An implementation claiming conformance MUST:

1. Hold all private key material (Ed448 seed, X448 private keys, ML-KEM
   decapsulation keys, ML-DSA signing keys, SMP exponents, derived chain/root/brace
   keys) in memory that is zeroized on drop. Private key bytes MUST NOT be exposed
   across an FFI or scripting boundary.

2. Use a cryptographically secure RNG seeded from the operating system entropy
   source for all key generation, all SMP blinding scalars, and all ZKP nonces.

3. Perform all secret-dependent modular exponentiation in constant time.

4. Compare all secrets, MACs, and equality-test values using constant-time
   comparison.

5. Validate every received group element per §6.3 before use.

6. Verify both the Ed448 ring signature and (when present) the ML-DSA-87 signature
   in DAKE3.

7. Reject any SMP version mismatch without downgrade.

8. Enforce the fragment reassembly limits in §7.1.

9. Encrypt each data message under its single-use message key with AES-256-GCM,
   bind the 64-byte ratchet header as associated data, transmit the fresh per-message
   nonce, and return a single generic error on any decryption failure (§5.4).

10. Enforce the skipped-key bounds (`MAX_SKIP`, `MAX_MESSAGE_KEYS`) and reject
    replayed `(dh_pub, msg_num)` pairs (§5.5).

### 10.1 Known Limitations (Non-Normative)

- The SMP Schnorr ZKP scalar arithmetic (the `d = r - c*x` computation) uses
  variable-time big-integer arithmetic in the reference implementation. The
  exponentiation is constant-time but the surrounding scalar multiply is not. A
  fully constant-time ZKP is future work.
- Post-quantum deniability is NOT provided: the ML-DSA-87 signature in DAKE3 is
  attributable. Classical deniability (Ed448 ring signature) is preserved.
- ClientProfile signatures are Ed448 only, not hybrid.

---

## 11. Test Vectors

Conforming implementations SHOULD validate against:

- **RFC 8032** Ed448 test vectors (signature correctness).
- **RFC 7748** X448 test vectors (DH correctness).
- **FIPS 203** ML-KEM-1024 known-answer tests.
- **FIPS 204** ML-DSA-87 known-answer tests.
- **RFC 3526** Group 15 prime (the SMP prime MUST equal this value exactly).

The reference implementation includes a build-time assertion that the
`crypto-bigint` and `num-bigint` representations of the SMP prime are byte-for-byte
identical, and known-answer tests for the constant-time modular exponentiation
against a reference `modpow`.

---

## Appendix A: SMP Prime (RFC 3526 Group 15)

The 3072-bit MODP prime `p`, hexadecimal, big-endian:

```
FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64
ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7
ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B
F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31
43DB5BFC E0FD108E 4B82D120 A93AD2CA FFFFFFFF FFFFFFFF
```

Order `q = (p - 1) / 2`. Generator `g = 2`.

---

*End of specification. This document describes OTRv4+ v10.12.0 as implemented. It is
a research prototype specification and has not undergone formal cryptographic
review.*
