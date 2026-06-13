# OTRv4+ Protocol Specification

**Version:** 10.9.1
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
| ML-KEM-1024 shared secret | 32 |
| ML-DSA-87 public key | 2592 |
| ML-DSA-87 signature | 4627 |
| Ring signature (sigma) | 228 |
| HMAC-SHA3-512 MAC | 64 |
| SMP prime / group element | 384 |
| SSID | 8 |

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
| NONCE_DERIVE | 0x21 | Nonce derivation |

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

---

## 5. Double Ratchet

OTRv4+ uses the OTRv4 Double Ratchet (OTRv4 §) with one extension: ML-KEM-1024
brace key rotation at every DH ratchet step.

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

Messages are encrypted with AES-256-GCM. The 96-bit nonce MUST be unique per
`(message_key)`. Nonce reuse under the same key catastrophically breaks GCM
confidentiality and authenticity.

---

## 6. Socialist Millionaire Protocol (SMP) — Hybrid Post-Quantum

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
incorporate ML-KEM material — see §6.7 for the rationale).

**Step 1 — SHAKE-256 iterated KDF (50,000 rounds):**
```
state = SHAKE-256( "OTRv4+SMP-v2" || 0x00 || raw_secret )   // 64-byte output
for i in 0 .. 49998:                                          // KDF_ROUNDS - 1
    state = SHAKE-256( INT(i) || state )                      // INT = 4-byte BE
```
Where `"OTRv4+SMP-v2"` is the 12-byte ASCII literal followed by a `0x00` byte.

**Step 2 — HMAC-SHA3-512 session binding:**
```
hmac_key = SHA3-512(session_id)
(first, second) = (our_fp, peer_fp) if our_fp <= peer_fp
                  else (peer_fp, our_fp)              // lexicographic ordering
binding = HMAC-SHA3-512(hmac_key, first || second || state)
```

The fingerprints are ordered lexicographically so both parties derive the same
secret regardless of role. Implementations MUST NOT use role-dependent ordering.

**Step 3 — reduce mod order:**
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
- `0x02` = hybrid post-quantum

A version mismatch between peers MUST abort the session. No silent downgrade to
classical mode is permitted.

**SMP1 (hybrid):** the initiator additionally generates an ML-KEM-1024 keypair and
an ML-DSA-87 keypair. The encapsulation key (1568 bytes) and the ML-DSA-87 public
key (2592 bytes) are appended to the classical SMP1 payload.

**SMP2 (hybrid):** the responder:
```
(ct, kem_ss) = ML-KEM-1024.Encapsulate(initiator_ek)
pq_binding_key = KDF_1(0x20, domain || kem_ss || transcript_tag, 32)  // PQ_BRACE_KEY
```
generates its own ML-DSA-87 keypair, and signs the entire SMP2 wire body with
ML-DSA-87 using `pq_binding_key` as signing context. It appends `ct` (1568),
its ML-DSA-87 public key (2592), and the ML-DSA-87 signature (4627).

**SMP3 / SMP4 (hybrid):** each side verifies the previous step's ML-DSA-87
signature **before** processing the classical fields, then signs its own output
under `pq_binding_key`. SMP3 decapsulates to derive the same `pq_binding_key`.

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
| TLS clearnet | 450 bytes | Token bucket (4 tokens, 2/fragment, 1/sec refill) |
| I2P SAM | 380 bytes | 2 fragments then 6-second pause |
| Tor | 450 bytes | 200 ms fixed inter-fragment delay |

Fragment sizing is a transport-layer concern and does not affect the
cryptographic payload. The I2P sizing reflects the stricter line-length and flood
policies of `irc.postman.i2p`.

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

## 9. Security Requirements for Implementations

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

### 9.1 Known Limitations (Non-Normative)

- The SMP Schnorr ZKP scalar arithmetic (the `d = r - c*x` computation) uses
  variable-time big-integer arithmetic in the reference implementation. The
  exponentiation is constant-time but the surrounding scalar multiply is not. A
  fully constant-time ZKP is future work.
- Post-quantum deniability is NOT provided: the ML-DSA-87 signature in DAKE3 is
  attributable. Classical deniability (Ed448 ring signature) is preserved.
- ClientProfile signatures are Ed448 only, not hybrid.

---

## 10. Test Vectors

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

*End of specification. This document describes OTRv4+ v10.9.1 as implemented. It is
a research prototype specification and has not undergone formal cryptographic
review.*
