# Why I Built OTRv4+ in 2026

In 2025, the UK's Online Safety Act began requiring age verification for many platforms. The EU's Digital Services Act mandates "trusted flagger" systems that pressure platforms to scan private messages. Mainstream platforms now demand phone numbers, government ID, or facial scans just to participate in public discourse.

And in September 2026, Google will begin closing the Android Open Source Project, ending F-Droid as we know it on stock devices. Remote attestation and client-side scanning are coming to the mobile ecosystem.

**IRC never went away. It doesn't ask for your ID.**
Combined with I2P, it doesn't know your IP address.
Combined with OTRv4+, the server operator cannot read your messages.
Combined with post-quantum cryptography, even a future quantum computer cannot decrypt your past conversations.
Combined with SMP, a man-in-the-middle who intercepts your handshake cannot impersonate your peer.

## Why the wait is worth it

A fully verified OTRv4+ session over I2P takes about 6–7 minutes to establish from first contact to 🔵. That is not a bug. That is what security over an anonymising network costs.

What you get at the end of those 7 minutes:

- **Quantum-safe forward secrecy**: ML-KEM-1024 rotated at every ratchet step. Someone who records your traffic today and builds a quantum computer in 2035 cannot decrypt it.
- **Post-quantum authentication**: ML-DSA-87 alongside Ed448 ring signatures. Your peer's identity is verified against a standard that survives Shor's algorithm.
- **Zero-knowledge identity proof**: SMP ran four Rust-computed steps over I2P. Your shared passphrase was never sent over the wire. It never left Rust-owned memory. Even if someone compromised the IRC server and captured every fragment, they cannot brute-force your passphrase from the transcript in any reasonable timeframe.
- **Network anonymity**: Your I2P destination is unique to this session. The server sees a b32.i2p address it has never seen before and will never see again.
- **Deniability**: Ed448 ring signatures mean neither party can prove to a third party who said what. The transcript is cryptographically repudiable.

No other widely deployable tool gives you all of this simultaneously. Signal is faster and better for async use. This is for the sessions where both parties are present, traces are unacceptable, and you need to know with cryptographic certainty that you are talking to exactly who you think you are.

## Where can you run this?

| Platform | Method |
|---|---|
| **Android (Termux)** | One-command install — `./termux_install.sh` |
| **GrapheneOS (Pixel)** | Termux in work profile — fully functional, no Google services required |
| **Linux phones** (PostmarketOS, Mobian) | Native Python — `python otrv4+.py` |
| **Desktop Linux** | Native Python, or WeeChat plugin (drop-in, no compilation) |
| **OpenBSD** | Native Python — works out of the box |
| **Raspberry Pi / Steam Deck** | Same as desktop Linux |

The core cryptographic engine is written in **Rust** and **C**, with a thin Python wrapper. If Python becomes unavailable on your platform of choice, the Rust core can be bound to any language with an FFI.

## Why this matters for the post-Android world

We are entering an era where **owning your hardware and software** is the only way to guarantee private communication. This project is designed to be:

- **Portable**: The core crypto compiles anywhere `cargo` runs
- **Auditable**: The security-critical code is in C/Rust, not a black-box app
- **Self-hostable**: No central servers — just IRC + I2P
- **Future-proof**: Post-quantum cryptography is baked in today, not bolted on later

This is the communication tool I wanted for myself. I'm sharing it because others may need it too.

---

## Quick Start

```bash
git clone https://github.com/muc111/OTRv4Plus
cd OTRv4Plus
./termux_install.sh   # Android/Termux
# or
python otrv4+.py      # Linux/macOS
```
