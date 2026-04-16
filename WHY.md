# Why I Built OTRv4+ in 2026

In 2025, the UK's Online Safety Act began requiring age verification for many platforms. The EU's Digital Services Act mandates "trusted flagger" systems that pressure platforms to scan private messages. Mainstream platforms now demand phone numbers, government ID, or facial scans just to participate in public discourse.

And in September 2026, Google will begin closing the Android Open Source Project, ending F-Droid as we know it on stock devices. Remote attestation and client-side scanning are coming to the mobile ecosystem.

**IRC never went away. It doesn't ask for your ID.**  
Combined with I2P, it doesn't know your IP address.  
Combined with OTRv4+, the server operator cannot read your messages.  
Combined with post-quantum cryptography, even a future quantum computer cannot decrypt your past conversations.

## Where Can You Run This?

This is not an Android-only tool. It works on:

| Platform | Method |
|----------|--------|
| **GrapheneOS (Pixel)** | Termux in work profile — still fully functional, no Google services required |
| **Linux phones** (PostmarketOS, Mobian) | Native Python — `python otrv4+.py` |
| **Desktop Linux** | Native Python, or **WeeChat plugin** (drop-in, no compilation) |
| **OpenBSD** | Native Python — works out of the box |
| **Raspberry Pi / Steam Deck** | Same as desktop Linux |

The core cryptographic engine is written in **Rust** and **C**, with a thin Python wrapper. If Python becomes unavailable on your platform of choice, the Rust core can be bound to any language with an FFI (Swift, Go, Node.js, even a Tauri desktop app).

## Why This Matters for the Post-Android World

We are entering an era where **owning your hardware and software** is the only way to guarantee private communication. This project is designed to be:

- **Portable**: The core crypto compiles anywhere `cargo` runs.
- **Auditable**: The security-critical code is in C/Rust, not a black-box app.
- **Self-hostable**: No central servers — just IRC + I2P.
- **Future-proof**: Post-quantum cryptography is baked in today.

This is the communication tool I wanted for myself. I'm sharing it because others may need it too, whether on a de-Googled Pixel, a Linux laptop, or a terminal on OpenBSD.

---

## Quick Start

```bash
git clone https://github.com/muc111/OTRv4Plus
cd OTRv4Plus
python otrv4+.py