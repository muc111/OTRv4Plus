# OTRv4+ – Complete Feature List

This document lists every cryptographic, protocol, and client feature implemented in OTRv4+. For a high‑level overview, see the main [README](README.md).

---

## 1. Core OTRv4 Protocol (Spec Compliant)

| Feature | Implementation |
|---------|----------------|
| **DAKE (Deniable Authenticated Key Exchange)** | DAKE1 (Identity), DAKE2 (Auth‑R), DAKE3 (Auth‑I) per OTRv4 §4.2–4.3. Supports initiator/responder roles. |
| **Ed448 & X448** | Long‑term Ed448 identity keys (57‑byte public) + ephemeral X448 keys (56‑byte public) for DH ratchet. 224‑bit classical security. |
| **Double Ratchet** | OTRv4 §4.4 – root key ratchet, sending/receiving chain keys, message key derivation (KDF_1), skip‑ahead for out‑of‑order messages. |
| **Message encryption** | AES‑256‑GCM with 12‑byte nonces. MAC key derived via SHA3‑512. |
| **Session ID & SSID** | 8‑byte SSID derived from KDF_1 (usage 0x01), used for session binding. |
| **Client Profiles** | Encoded and signed Ed448+X448 keys with expiry timestamp. Strict verification – no unsigned/expired profiles accepted. |
| **Ring Signatures** | Auth‑I / Auth‑R Schnorr ring signatures (228 bytes) for deniable authentication. Implemented in C extension. |
| **Instance Tags** | Random 32‑bit tags (≥0x100) for multi‑session discrimination per peer. |
| **TLV Handling** | Supports all OTRv4 TLVs: PADDING (0x00), DISCONNECTED (0x01), SMP messages (0x02–0x07), EXTRA_SYMMETRIC_KEY (0x09). |
| **Fragmentation** | IRC‑aware fragmenter using spec format `?OTRv4\|stag\|rtag\|k\|n\|data.` with reassembly buffer (timeout 120s, max 50 fragments, SMP elevated to 100). |
| **Rekeying** | Automatic DH ratchet after 100 messages or 86400 seconds (configurable). |
| **Disconnect notification** | Sends DISCONNECTED TLV before session termination. |

---

## 2. Post‑Quantum Cryptography (NIST Level 5)

| Component | Algorithm | NIST Level | Integration |
|-----------|-----------|------------|--------------|
| **ML‑KEM‑1024** (FIPS 203) | Module‑Lattice Key Encapsulation Mechanism | **Level 5** (~256‑bit PQ security) | Brace KEM – rotates the brace key on every DH ratchet epoch. Used in DAKE (ek in DAKE1, ct in DAKE2) and in Double Ratchet for ongoing PQ protection. |
| **ML‑DSA‑87** (FIPS 204) | Module‑Lattice Digital Signature Algorithm | **Level 5** | Hybrid PQ authentication in DAKE3. Appended after Ed448 ring signature (flag byte). Provides post‑quantum authentication at the cost of PQ deniability. |

**Brace KEM rotation protocol**:
- Each DH ratchet step generates a fresh ML‑KEM‑1024 keypair.
- Encapsulation key (`ek`) sent in one message, ciphertext (`ct`) returned in the next.
- Brace key updated via `KDF_1(0x16, old_brace ‖ KEM_shared_secret, 32)`.
- At most one KEM field per message (ek or ct, never both).

**PQ authentication details**:
- DAKE3 wire: `0x37 ‖ ring_sigma(228) ‖ flag(1) [‖ MLDSA_sig(4627)]`
- Flag `0x00` = classical only, `0x01` = ML‑DSA‑87 signature appended.
- Peers without ML‑DSA fall back to classical ring signature – backward compatible.

All PQC operations use OpenSSL 3.5+ native providers (no liboqs). C extensions expose them to Python.

---

## 3. Socialist Millionaire Protocol (SMP)

| Feature | Details |
|---------|---------|
| **Spec compliance** | OTRv4 §5 – 3072‑bit safe prime (RFC 3526 Group 15), SHA3‑512 for ZKP challenges. |
| **Group** | `p = 2^3072 - 2^3008 - 1 + ...` (standard RFC 3526), generator 2. |
| **State machine** | NONE → EXPECT1/2/3/4 → SUCCEEDED / FAILED. Transitions enforced. |
| **Zero‑knowledge proofs** | Fiat‑Shamir with constant‑time modular exponentiation via OpenSSL `BN_mod_exp_mont_consttime`. No Python fallback. |
| **Question support** | SMP message 1Q – question embedded in first message (UTF‑8, max 65535 bytes). |
| **Retry & backoff** | Automatic retry up to 3 times with exponential backoff (5s, 15s, 45s). |
| **Auto‑respond storage** | Encrypted `smp_secrets.json` (AES‑256‑GCM + scrypt KDF) – stores pre‑shared secrets per peer. |
| **Progress notification** | Real‑time bar in terminal: `[███ ░░░ ░░░ ░░░] step 2/4` with ETA. |
| **Verification** | On success, security level upgrades to `SMP_VERIFIED` (🔵 icon). |
| **Replay protection** | Seen‑message cache (OrderedDict, max 10k entries) using SHA3‑256 of TLV. |

---

## 4. Built‑in IRC Client

| Feature | Description |
|---------|-------------|
| **Network autodetection** | `.i2p` → I2P SOCKS5 (127.0.0.1:4447), `.onion` → Tor SOCKS5 (9050), else clearnet. |
| **TLS support** | Clearnet uses TLS on port 6697 (auto‑detected). I2P/Tor skip TLS (tunnel already encrypted). |
| **IRCv3 CAP** | Requests `sasl`, `multi‑prefix`, `server‑time`, `message‑tags`, `account‑notify`, `away‑notify`, `cap‑notify`, `echo‑message`. |
| **SASL PLAIN** | Full SASL authentication (replaces NickServ IDENTIFY). |
| **NickServ login/register** | Optional `/msg NickServ IDENTIFY` or REGISTER with password. |
| **Auto‑join** | Joins configured channel after MOTD. |
| **Fragmentation** | OTR messages fragmented to ≤ 350‑byte IRC lines; reassembly buffer with timeout (120s). |
| **Ping watchdog** | Sends periodic PING; reconnects after 10 minutes of silence. |
| **Auto‑reconnect** | Exponential backoff (up to 120s) on connection loss, up to 999 attempts. |
| **Tabbed UI** | In‑terminal panels: system, channels, private peers, debug. Tab bar with unread counters and security icons. |
| **Raw input mode** | Character‑at‑a‑time input, no `Enter` required for navigation. Preserves typed text when incoming messages arrive. |
| **Pager** | Non‑destructive inline pager for `/names`, `/list`, `/whois`. |
| **Termux optimisations** | Smaller tab bar, vibration + notifications for OTR events. |
| **Secure memory wiping** | Overwrites keys and secrets on shutdown (mlock + OPENSSL_cleanse). |

---

## 5. Security Hardening & Side‑Channel Resistance

| Measure | Implementation |
|---------|----------------|
| **Constant‑time crypto** | All modular exponentiation uses OpenSSL `BN_mod_exp_mont_consttime`. No Python `pow()` fallback. |
| **mlock** | `SecureMemory` class uses `mlock()` to prevent swapping of private keys (logs warning if unavailable). |
| **OPENSSL_cleanse** | Zeroisation of sensitive bytearrays via C extension (resists compiler dead‑store elimination). |
| **Core dump disable** | `prctl(PR_SET_DUMPABLE, 0)` via `otr4_crypto_ext.disable_core_dumps()`. |
| **Trust on First Use (TOFU)** | Trust database pins first‑seen fingerprint; mismatch raises exception (MITM detection). |
| **Fingerprint** | SHA3‑512 of Ed448 public key → 128 hex chars, grouped as 10×8 (OTRv4 spec §4.1). |
| **DAKE1 rate limiting** | Per‑peer sliding window (5 attempts / 60 seconds) to prevent CPU exhaustion. |
| **Replay protection** | Skipped message keys (max 1000 skip) and seen‑message cache (10k entries). |
| **Fragment flood limit** | Max 50 fragments per reassembly buffer; SMP elevated to 100. |
| **MPI / varbytes limits** | Enforced maximum lengths (1 MB) to avoid OOM. |
| **Instance tag validation** | Rejects tags < 0x100 (reserved range). |

---

## 6. Additional Utilities

| Feature | Purpose |
|---------|---------|
| **SecureKeyStorage** | AES‑256‑GCM encrypted keyring (Argon2/scrypt KDF) for Ed448/X448 private keys. |
| **SMPAutoRespondStorage** | Encrypted JSON store for per‑peer SMP secrets (XOR‑obfuscated, AES‑256‑GCM on disk). |
| **OTRLogger** | Structured logging to rotating files (separate security, network, UI, session logs). |
| **OTRTracer** | State transition tracing (DAKE, session, SMP) – feeds debug panel. |
| **EventHandler** | Event bus for errors, SMP events, security events. |
| **TwentySevenClubNick** | Nick generator with 12,000+ combinations (adjectives + nouns) and real‑name mapping for `/whois`. |
| **BinaryReader** | Safe, bounds‑checked deserialisation for wire formats. |
| **KDF_1** | SHAKE‑256 with “OTRv4” domain separator – used for all key derivations (usage IDs 0x01–0x1F). |

---

## 7. Test Coverage (224 tests)

| Test category | What is tested |
|---------------|----------------|
| Double ratchet | 10k/50k/100k message sequences, state fork attacks, replay resistance, forward secrecy erasure, post‑compromise recovery, out‑of‑order delivery. |
| KEM roundtrips | ML‑KEM‑1024 encaps/decaps, brace key rotation, ek/ct exchange. |
| ML‑DSA hybrid | DAKE3 flag encoding, signature verification, fallback to classical. |
| Ring signatures | Sign/verify, non‑malleability, transcript binding. |
| Wire format fuzzing | Malformed DAKE1/2/3, truncated messages, invalid TLVs. |
| SMP | Zero‑knowledge proof verification, state transitions, replay attacks, question support. |
| DAKE state machine | All legal transitions, timeout handling, rate limiting. |

Run with:
```bash
pytest -v test_*.py fuzz_harnesses.py -k "not 300k"   # quick (~2h on Termux)
pytest -v test_*.py fuzz_harnesses.py                 # full (~8h)