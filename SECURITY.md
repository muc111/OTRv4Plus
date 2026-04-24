# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| v10.5.8+ | ✅ |
| older    | ❌ |

## Reporting a vulnerability

Use GitHub’s private vulnerability reporting (Security tab → Report a vulnerability).  
Do not open a public issue.

Include: description, steps to reproduce, potential impact, suggested fix (if any).  
Acknowledgment within 48 hours; fix for critical issues within 14 days.

## In‑scope
- Cryptographic weaknesses (DAKE, ratchet, SMP, ring signatures)
- Key material leaks (memory, disk, network)
- Authentication bypasses
- Plaintext recovery

## Out‑of‑scope
- Endpoint compromise (rooted device, malware)
- I2P/Tor network‑level attacks
- Social engineering

## Memory‑safety status (v10.5.8)

| Component       | Secret storage | Zeroization |
|-----------------|----------------|-------------|
| Double ratchet  | Rust `Zeroize` | Deterministic on drop/`zeroize()` |
| SMP exponents   | Python `int` during computation → Rust vault afterwards | Vault zeroized on session end |
| DAKE DH secrets | Python `bytes` during KDF | Cleansed by `_ossl.cleanse` |
| Identity keys   | Python OpenSSL objects | No zeroization (OpenSSL heap) |

See `ROADMAP.md` for the plan to move all secrets into Rust with `Zeroize`.