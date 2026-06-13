# Why I Built OTRv4+ in 2026

In 2025, the UK's Online Safety Act began requiring age verification for many platforms. The EU's Digital Services Act mandates "trusted flagger" systems that pressure platforms to scan private messages. Mainstream platforms now demand phone numbers, government ID, or facial scans just to participate in public discourse.

And in September 2026, Google will begin closing the Android Open Source Project, ending F-Droid as we know it on stock devices. Remote attestation and client-side scanning are coming to the mobile ecosystem.

**IRC never went away. It doesn't ask for your ID.**
Combined with I2P, it doesn't know your IP address.
Combined with OTRv4+, the server operator cannot read your messages.
Combined with post-quantum cryptography, even a future quantum computer cannot decrypt your past conversations.
Combined with SMP, a man-in-the-middle who intercepts your handshake cannot impersonate your peer.

## Why the wait is worth it

A fully verified OTRv4+ session over I2P takes about 15–16 minutes to establish from first contact to 🔵 with the hybrid post-quantum SMP. Over TLS clearnet it is under 6 minutes. That is not a bug. That is what NIST Level 5 post-quantum security over an anonymising network costs — the SMP2 message alone is 49 fragments of ML-KEM and ML-DSA key material.

What you get at the end of those minutes:

- **Quantum-safe forward secrecy**: ML-KEM-1024 rotated at every ratchet step. Someone who records your traffic today and builds a quantum computer in 2035 cannot decrypt it.
- **Post-quantum authentication**: ML-DSA-87 alongside Ed448 ring signatures. Your peer's identity is verified against a standard that survives Shor's algorithm.
- **Hybrid post-quantum identity proof**: SMP runs four Rust-computed steps over I2P, with the classical Schnorr zero-knowledge proof wrapped in an ML-KEM-1024 + ML-DSA-87 binding layer. Your shared passphrase is never sent over the wire and never leaves Rust-owned memory. To forge a false "verified" result an attacker would need to break the 3072-bit discrete log, ML-KEM-1024, and ML-DSA-87 simultaneously. The modular exponentiation is constant-time, so step timing does not leak your secret.
- **Network anonymity**: Your I2P destination is unique to this session. The server sees a b32.i2p address it has never seen before and will never see again.
- **Deniability**: Ed448 ring signatures mean neither party can prove to a third party who said what. The transcript is cryptographically repudiable.

No other widely deployable tool gives you all of this simultaneously. Signal is faster and better for async use. This is for the sessions where both parties are present, traces are unacceptable, and you need to know with cryptographic certainty that you are talking to exactly who you think you are.

## Where can you run this?

| Platform | Method |
|---|---|
| **Android (Termux)** | Build from source — see the README install guide |
| **GrapheneOS (Pixel)** | Termux in work profile — fully functional, no Google services required |
| **Linux phones** (PostmarketOS, Mobian) | Build the Rust core, run with Python |
| **Desktop Linux** | Native Python, or WeeChat plugin (drop-in, no compilation) |
| **OpenBSD** | Native Python — works out of the box |
| **Raspberry Pi / Steam Deck** | Same as desktop Linux |

The core cryptographic engine is written in **Rust**, with a thin Python wrapper. (Earlier versions used C extensions for some primitives; these were retired in 2026 and the entire crypto surface is now pure Rust.) If Python becomes unavailable on your platform of choice, the Rust core can be bound to any language with an FFI.

## Why this matters for the post-Android world

We are entering an era where **owning your hardware and software** is the only way to guarantee private communication. This project is designed to be:

- **Portable**: The core crypto compiles anywhere `cargo` runs
- **Auditable**: The security-critical code is in Rust, not a black-box app
- **Self-hostable**: No central servers — just IRC + I2P
- **Future-proof**: Post-quantum cryptography is baked in today, not bolted on later

This is the communication tool I wanted for myself. I'm sharing it because others may need it too.

---

## Getting started

Build and install instructions are in the [README](README.md#quick-start). The
core cryptographic engine builds from source with `cargo`; there are no prebuilt
binaries and no C extensions.
