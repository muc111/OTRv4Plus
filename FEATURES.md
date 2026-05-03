# OTRv4+ Feature Reference

## 1. Core OTRv4 Protocol (Spec Compliant)

| Feature | Implementation |
|---|---|
| **DAKE** | DAKE1 (Identity), DAKE2 (Auth‑R), DAKE3 (Auth‑I) per OTRv4 §4.2–4.3. Initiator/responder roles. Over I2P SAM: ~2m 44s handshake time. |
| **Ed448 & X448** | Long‑term Ed448 identity keys (57‑byte public) + ephemeral X448 keys (56‑byte public). 224‑bit classical security. |
| **Double Ratchet** | Chain key advancement, message key derivation, AES‑256‑GCM encrypt/decrypt, skipped key management, and replay detection run inside the Rust `otrv4_core` crate. Keys are `ZeroizeOnDrop` — no Python memory exposure at any point. |
| **Message encryption** | AES‑256‑GCM with 12‑byte nonces. MAC key derived via SHA3‑512. |
| **Session ID & SSID** | 8‑byte SSID derived from KDF_1 (usage 0x01), used for SMP session binding. |
| **Client Profiles** | Encoded and signed Ed448+X448 keys with expiry timestamp. Strict verification — no unsigned or expired profiles accepted. |
| **Ring Signatures** | Auth‑I / Auth‑R Schnorr ring signatures (228 bytes) for deniable authentication. Implemented in C extension with constant-time arithmetic. |
| **Instance Tags** | Random 32‑bit tags (≥ 0x100) for multi‑session discrimination per peer. |
| **TLV Handling** | All OTRv4 TLVs: PADDING (0x00), DISCONNECTED (0x01), SMP messages (0x02–0x07), EXTRA_SYMMETRIC_KEY (0x09). |
| **Fragmentation** | IRC‑aware fragmenter using spec format `?OTRv4\|stag\|rtag\|k\|n\|data.` with reassembly buffer (timeout 120s, max 50 fragments, SMP elevated to 100). |
| **Rekeying** | Automatic DH ratchet after 100 messages or 86400 seconds (configurable). |
| **Disconnect notification** | Sends DISCONNECTED TLV before session termination. |

---

## 2. Post‑Quantum Cryptography (NIST Level 5)

| Component | Algorithm | NIST Level | Integration |
|---|---|---|---|
| **ML‑KEM‑1024** (FIPS 203) | Module‑Lattice Key Encapsulation | Level 5 (~256-bit PQ security) | Brace KEM — rotates brace key on every DH ratchet epoch. Used in DAKE (ek in DAKE1, ct in DAKE2) and the Double Ratchet for ongoing PQ protection. |
| **ML‑DSA‑87** (FIPS 204) | Module‑Lattice Digital Signature | Level 5 | Hybrid PQ authentication in DAKE3. Appended after Ed448 ring signature (flag byte). Provides post-quantum authentication. |

**Brace KEM rotation protocol:**

- Each DH ratchet step generates a fresh ML‑KEM‑1024 keypair
- Encapsulation key (`ek`) sent in one message, ciphertext (`ct`) returned in the next
- Brace key updated via `KDF_1(0x16, old_brace ‖ KEM_shared_secret, 32)`
- At most one KEM field per message (ek or ct, never both)

**PQ authentication:**

```
DAKE3 wire: 0x37 ‖ ring_sigma(228) ‖ flag(1) [‖ MLDSA_sig(4627)]
flag 0x00 = classical only
flag 0x01 = ML-DSA-87 signature appended
```

Peers without ML‑DSA fall back to classical ring signature — backward compatible.

---

## 3. Socialist Millionaire Protocol (SMP) — v10.5.10

SMP is how two parties prove to each other that they share a secret without sending it over the wire. This prevents a man-in-the-middle attacker who has intercepted your DAKE from impersonating your peer: even if they can fake a fingerprint, they cannot know your shared passphrase. Over I2P the full four-step exchange takes approximately **2 minutes**.

### Protocol properties

| Property | Detail |
|---|---|
| **Spec compliance** | OTRv4 §5 — 2048‑bit safe prime (RFC 3526 Group 14), SHA3‑512 for ZKP challenges |
| **State machine** | `IDLE → AWAITING_MSG2 → AWAITING_MSG3 → AWAITING_MSG4 → VERIFIED / FAILED / ABORTED` |
| **ZKP type** | Fiat‑Shamir Schnorr proofs with constant-time `num_bigint` arithmetic inside Rust |
| **Secret KDF** | 50,000-round SHAKE‑256 chain + HMAC‑SHA3‑512 bound to session_id + fingerprints |
| **Fingerprint binding** | Lexicographic ordering so initiator and responder derive identical secrets |
| **Wire layout** | SMP1: 6 elements · SMP2: 11 elements · SMP3: 5 elements · SMP4: 3 elements |
| **Rate limiting** | 3 failures → permanent `Aborted`; 30-second cooldown between retries |
| **Session expiry** | 10-minute hard timeout per `SmpState` |
| **Transcript MAC** | HMAC‑SHA3‑512 over all wire bytes, keyed to session_id — prevents cross-session replay |
| **Progress display** | `[███ ░░░ ░░░ ░░░] step 1/4` with step labels and colour transitions |
| **Verification result** | Both initiator and responder transition to 🔵 `SMP_VERIFIED` simultaneously |

### Rust architecture

All SMP logic runs in `otrv4_core`. Python is an orchestrator only.

```
Python                           Rust (otrv4_core)
  │                                     │
  │  set_secret_from_vault(vault, ...)  │
  │────────────────────────────────────>│  SHAKE-256 × 50k → HMAC-SHA3-512
  │                                     │  result stored in SmpState.secret: SecretVec
  │                                     │  (ZeroizeOnDrop — Python GC cannot reach this)
  │                                     │
  │  generate_smp1(question) → bytes    │
  │<────────────────────────────────────│  exponents a2,a3 generated via OsRng
  │                                     │  ZKPs computed with num_bigint
  │                                     │  wire bytes returned (public values only)
  │                                     │
  │  process_smp2_generate_smp3(data)   │
  │────────────────────────────────────>│  verifies Pb/Qb ZKP (combined soundness)
  │<────────────────────────────────────│  generates Pa/Qa/Ra — returns wire bytes
  │                                     │
  │  process_smp3_generate_smp4(data)   │
  │────────────────────────────────────>│  verifies Ra ZKP
  │<────────────────────────────────────│  computes Rb, equality check → phase=Verified
  │                                     │  (Bob transitions to VERIFIED here)
  │  rust_smp.is_verified() → True      │
  │<────────────────────────────────────│
  │  → security_level = SMP_VERIFIED    │
  │  → UI transitions to 🔵             │
  │                                     │
  │  process_smp4(data) → bool          │  (Alice's path)
  │────────────────────────────────────>│  verifies Rb ZKP, equality check
  │<────────────────────────────────────│  phase=Verified → returns true
  │  → security_level = SMP_VERIFIED    │
  │  → UI transitions to 🔵             │
```

### Secret isolation

```
Python                           Rust
  │                                │
  raw = bytearray(secret.encode()) │  ← mutable Python bytes
  vault.store("smp_secret", raw)   │──>│  Vec<u8> allocated in Rust heap
                                   │   │  ZeroizeOnDrop registered
  raw[i] = 0 for all i             │  ← overwritten immediately
  del raw                          │  ← Python ref dropped
                                   │
  smp.set_secret_from_vault(vault) │──>│  SHAKE-256 × 50k in Rust
                                   │   │  SecretVec stored in SmpState
                                   │   │  vault bytes never copied to Python
```

---

## 4. Built‑in IRC Client

| Feature | Description |
|---|---|
| **Network autodetection** | `.i2p` → I2P SOCKS5 (127.0.0.1:4447), `.onion` → Tor SOCKS5 (9050), else clearnet |
| **TLS support** | Clearnet uses TLS on port 6697 (auto‑detected). I2P/Tor skip TLS (tunnel already encrypted). |
| **I2P SAM bridge** | Fresh I2P destination (b32 address) per session — cross‑session correlation requires active I2P deanonymisation |
| **IRCv3 CAP** | Requests `multi-prefix`, `account-notify`, `away-notify` — negotiated at connect |
| **SASL PLAIN** | Full SASL authentication (replaces NickServ IDENTIFY) |
| **Auto‑join** | Joins configured channel after MOTD |
| **Fragmentation** | OTR messages fragmented to ≤ 300-byte IRC lines; reassembly buffer with timeout (120s) |
| **Ping watchdog** | Sends periodic PING; reconnects after 10 minutes of silence |
| **Auto‑reconnect** | Exponential backoff (up to 120s) on connection loss, up to 999 attempts |
| **Tabbed UI** | In-terminal panels: system, channels, private peers, debug. Tab bar with unread counters and security icons. |
| **Raw input mode** | Character-at-a-time input. Preserves typed text when incoming messages arrive. |
| **Pager** | Non-destructive inline pager for `/names`, `/list`, `/whois` |
| **Termux optimisations** | Smaller tab bar, vibration + notifications for OTR events |

---

## 5. Security Hardening & Side‑Channel Resistance

| Measure | Implementation |
|---|---|
| **Constant‑time crypto** | All modular exponentiation uses OpenSSL `BN_mod_exp_mont_consttime`. No Python `pow()` fallback. |
| **Rust secret isolation** | All secret key material in Rust `SecretBytes<N>` / `SecretVec` with `ZeroizeOnDrop`. Python holds opaque handles only. |
| **Constant-time equality** | `subtle::ConstantTimeEq` for all secret comparisons in Rust SMP |
| **mlock** | `SecureMemory` class attempts `mlock()` to prevent swapping of private keys (logs warning if unavailable on Termux) |
| **OPENSSL_cleanse** | Zeroisation of sensitive bytearrays via C extension (resists compiler dead-store elimination) |
| **Core dump disable** | `prctl(PR_SET_DUMPABLE, 0)` via `otr4_crypto_ext.disable_core_dumps()` |
| **TOFU** | Trust database pins first-seen fingerprint; mismatch raises exception (MITM detection) |
| **Fingerprint** | SHA3‑512 of Ed448 public key → 128 hex chars, grouped as 10×8 (OTRv4 spec §4.1) |
| **DAKE1 rate limiting** | Per-peer sliding window (5 attempts / 60 seconds) to prevent CPU exhaustion |
| **Replay protection** | Skipped message keys (max 1000 skip) and seen-message cache (10k entries) |
| **Fragment flood limit** | Max 50 fragments per reassembly buffer; SMP elevated to 100 |
| **SMP rate limiting** | 3 failures → permanent `Aborted`; 30-second cooldown between retries |
| **SMP session expiry** | 10-minute hard timeout per `SmpState` — prevents stale handshake attacks |

---

## 6. Additional Utilities

| Feature | Purpose |
|---|---|
| **RustSMPVault** | Rust-owned secret container. Python receives only a `u64` handle. Entries are individually `ZeroizeOnDrop`; bulk `clear()` drains the map entry-by-entry so each `SecretEntry` is zeroed before the HashMap is cleared. |
| **SecureKeyStorage** | AES‑256‑GCM encrypted keyring (Argon2id KDF) for Ed448/X448 private keys |
| **SMPAutoRespondStorage** | Encrypted JSON store for per-peer SMP secrets |
| **OTRLogger** | Structured logging to rotating files (security, network, UI, session logs separated) |
| **OTRTracer** | State transition tracing (DAKE, session, SMP) — feeds debug panel |
| **EventHandler** | Event bus for errors, SMP events, security events |
| **TwentySevenClubNick** | Nick generator with 12,000+ combinations and real-name mapping for `/whois` |
| **BinaryReader** | Safe, bounds-checked deserialisation for wire formats |
| **KDF_1** | SHAKE‑256 with "OTRv4" domain separator — all key derivations (usage IDs 0x01–0x1F) |

---

## 7. Test Coverage (313 tests)

313 tests (299 Python + 14 Rust):

| Category | What is tested |
|---|---|
| Double ratchet | 10k/50k/100k message sequences, state fork attacks, replay resistance, forward secrecy erasure, post-compromise recovery, out-of-order delivery |
| KEM roundtrips | ML‑KEM‑1024 encaps/decaps, brace key rotation, ek/ct exchange |
| ML-DSA hybrid | DAKE3 flag encoding, signature verification, fallback to classical |
| Ring signatures | Sign/verify, non-malleability, transcript binding |
| Wire format fuzzing | Malformed DAKE1/2/3, truncated messages, invalid TLVs |
| SMP | ZKP verification, state transitions, replay attacks, question support, vault isolation |
| DAKE state machine | All legal transitions, timeout handling, rate limiting |
| Rust vault | Zeroization correctness, handle registry isolation, clear-before-free |

```bash
pytest -v test_*.py fuzz_harnesses.py -k "not 300k"   # quick (~2h on Termux)
pytest -v test_*.py fuzz_harnesses.py                 # full (~8h)
```

---

## 8. Rust Migration Status (v10.5.10)

| Component | Secret storage | Zeroization | Status |
|---|---|---|---|
| **Double ratchet** | Rust `SecretBytes<N>` / `SecretVec` | `ZeroizeOnDrop` — no Python exposure | ✅ Complete (v10.5.8) |
| **SMP state machine** | Rust `SmpState` — all exponents are `SecretVec` | `ZeroizeOnDrop` + explicit `destroy()` | ✅ Complete (v10.5.10) |
| **SMP vault** | Rust `RustSMPVault` — `SecretEntry` per slot | `ZeroizeOnDrop` per entry; `clear()` drains individually | ✅ Complete (v10.5.10) |
| **DAKE DH secrets** | Python `bytes` during KDF | `OPENSSL_cleanse` after use | 🔜 Phase 3 |
| **Identity keys (Ed448/X448)** | Python OpenSSL objects | No deterministic zeroization | 🔜 Phase 4 |
