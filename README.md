<p align="center">
  <img src="icon.png" width="200" alt="OTRv4+">
</p>

<h1 align="center">OTRv4+</h1>
<p align="center"><strong>Post‑quantum encrypted IRC. Runs on your phone over I2P, Tor, or clearnet. Leaves no trace.</strong></p>

<p align="center">
  <a href="#installation">Install</a> ·
  <a href="#quick-start">Quick start</a> ·
  <a href="#commands">Commands</a> ·
  <a href="#security-features">Security</a> ·
  <a href="#how-long-does-it-take">Timing</a> ·
  <a href="#license">License</a>
</p>

---

## One‑line install (Android / Termux)

```bash
git clone https://github.com/muc111/OTRv4Plus.git && cd OTRv4Plus && chmod +x termux_install.sh && ./termux_install.sh && PYTHONMALLOC=malloc python otrv4+.py
```

The installer builds the Rust SMP + ratchet core and all C extensions, or falls back to prebuilt binaries automatically – no manual compilation needed.

---

## What is this?

OTRv4+ is a complete implementation of the OTRv4 specification with post‑quantum cryptography at every layer.

- **Key exchange**: ML‑KEM‑1024 (Kyber1024) hybridised with X448
- **Authentication**: ML‑DSA‑87 (FIPS 204) added to Ed448 ring signatures
- **Ratchet**: Fresh ML‑KEM encapsulation at every DH ratchet step forward secrecy is quantum‑resistant throughout the session
- **SMP**: Full Socialist Millionaire Protocol state machine running entirely inside Rust the Python process is cryptographically blind to all secret material

It runs as a single terminal IRC client over I2P, Tor, or clearnet, and wipes all key material on exit.

The OTRv4 spec has existed for years with zero complete, maintained implementations. This fills that gap and adds PQC on top.

---

## v10.5.10 – Rust SMP Engine (current)

This release completes the migration of the Socialist Millionaire Protocol into Rust. The Python layer now acts only as an orchestrator it passes opaque handles and wire bytes; all secret values live exclusively in Rust‑owned, `ZeroizeOnDrop` memory.

**What changed from v10.5.8:**

- Full Rust SMP state machine (`SmpState`) with rate limiting, session expiry, and transcript MAC
- `RustSMPVault` Rust‑owned secret container; Python GC cannot reach any secret byte
- `set_secret_from_vault()` secrets flow directly from vault to SMP engine without crossing the Python interpreter
- Passphrase encoded into a `bytearray` and overwritten immediately after `vault.store()` returns
- Canonical fingerprint ordering in KDF so initiator and responder derive identical secrets from the same passphrase
- Bob's (responder's) SMP verified state now correctly transitions to 🔵 on `process_smp3_generate_smp4()`
- 50,000‑round SHAKE‑256 stretch + HMAC‑SHA3‑512 session binding brute‑force of any captured transcript is computationally infeasible

---

## How long does it take?

OTRv4+ over I2P is not fast. I2P routes traffic through multiple encrypted hops; latency is high by design. Here is what a real session looks like measured from live debug logs:

| Phase | What happens | Typical time over I2P |
|---|---|---|
| **I2P bootstrap** | i2pd builds enough tunnels to reach irc.postman.i2p | 2–5 minutes (one‑time on first run) |
| **DAKE** | Three‑message handshake: DAKE1 → DAKE2 → DAKE3 | **~2 minutes 44 seconds** |
| **Fingerprint trust** | You type `y` to trust the remote fingerprint | Instant (your decision) |
| **SMP verification** | Four‑message ZKP exchange | **~2 minutes** |
| **Total to 🔵** | From `/otr nick` to fully verified blue session | **~6 minutes 37 seconds** |

These figures come from a real session log (Termux on Android, irc.postman.i2p, SAM bridge). The DAKE fragments arrive one at a time because each 6 kB message must traverse separate I2P tunnels at ~4 second intervals.

**This is the cost of the security you get.** A man‑in‑the‑middle cannot inject themselves into any of those steps. SMP proves via zero‑knowledge proof, without sending the secret that you are talking to exactly who you think you are. Once the session is blue you have:

- Quantum‑safe forward secrecy (ML‑KEM‑1024 ratchet)
- Post‑quantum authentication (ML‑DSA‑87)
- Identity verification that cannot be replayed or forged (SMP ZKP)
- Network anonymity (I2P)
- Deniability (Ed448 ring signatures)

No other widely deployable tool gives you all of these simultaneously. The wait is worth it.

---

## Live demo – Termux on Android

DAKE handshake, fingerprint exchange, and 4‑step SMP identity verification over I2P SAM bridge:

<p align="center">
  <img src="git_screenshot.png" width="380" alt="OTRv4+ running in Termux – DAKE + SMP over I2P">
</p>

The screenshot shows a complete session: SAM bridge connection → DAKE3 completing with Ed448 ring‑sig + ML‑DSA‑87 → SHA3‑512 fingerprint trust → SMP ZKP running all four Rust steps → both sides turn 🔵.

---

## Quick start

1. Launch: `PYTHONMALLOC=malloc python otrv4+.py`
2. Join a channel: `/join #otr`
3. Start an encrypted session: `/otr bob`
4. Verify identity: `/smp mysecret` then `/smp start` (both users type the same passphrase nothing is sent over the wire)

The client defaults to `irc.postman.i2p` with auto‑network detection: `.i2p` → I2P, `.onion` → Tor, everything else → TLS.

To connect to a different server: `python otrv4+.py -s irc.libera.chat:6697`

---

## Security features

| | Feature | Detail |
|---|---|---|
| 🔐 | **Post‑quantum handshake** | ML‑KEM‑1024 + X448 hybrid → quantum‑safe session keys from the first message |
| 🔄 | **Post‑quantum ratchet** | Fresh ML‑KEM encapsulation every DH ratchet epoch compromise of one epoch doesn't open others |
| 🪪 | **Deniable authentication** | Ed448 + ML‑DSA‑87 ring signatures you know who you're talking to; no third party can prove it |
| 🧐 | **Zero‑knowledge identity** | SMP prove you both know a shared secret without sending it; all four steps run in Rust |
| 🔒 | **Rust secret isolation** | SMP secrets, ratchet keys, and vault entries live in Rust `ZeroizeOnDrop` memory. Python holds only opaque handles. The Python GC cannot access any secret value. |
| 🧅 | **Network agnostic** | Auto‑detects I2P / Tor / clearnet same client, same commands |
| 👤 | **No persistent identity** | Random nick every launch; fresh I2P destination every session via SAM |
| 🧹 | **Zero traces on exit** | Rust `Zeroize`, `OPENSSL_cleanse`, NIST SP 800‑88r1 file destruction nothing recoverable after `/quit` |
| 📱 | **Runs on a phone** | Termux on Android, one‑command install, no root required |

**Honest tradeoffs:** both parties must be online simultaneously. No async messaging, no push notifications. If you need async, use Signal. If you need synchronous, deniable, post‑quantum chat that leaves no trace, this is it.

---

## Installation

### Android – Termux

```bash
git clone https://github.com/muc111/OTRv4Plus.git && cd OTRv4Plus && chmod +x termux_install.sh && ./termux_install.sh && PYTHONMALLOC=malloc python otrv4+.py
```

<details>
<summary>What the installer does</summary>

| Stage | What happens |
|---|---|
| [1/5] System deps | `pkg install python rust openssl clang make binutils` |
| [2/5] Python tools | `pip install maturin setuptools` |
| [3/5] Clean | Removes stale build artefacts |
| [4/5] API level | Reads Android API level via `getprop` (defaults to 24) |
| [5/5] C extensions | Builds `otr4_crypto_ext`, `otr4_ed448_ct`, `otr4_mldsa_ext` with `setup_otr4.py` |
| [6/6] Rust core | `cargo build --release --features pq-rust` → copies `libotrv4_core.so` to project root |

Automatic prebuilt fallback: if any step fails, the script copies `.so` files from `prebuilt/` and continues.

</details>

**I2P:** The default server is `irc.postman.i2p`. You need i2pd running:

```bash
pkg install i2pd && i2pd --daemon
```

Wait ~3 minutes for I2P to bootstrap, then launch OTRv4+.

### Linux / macOS

<details>
<summary>Manual build instructions</summary>

Requirements: Python 3.9+, OpenSSL 3.5+, C compiler, Rust toolchain.

**Debian / Ubuntu (23.04+)**

```bash
sudo apt install python3 python3-dev python3-venv libssl-dev build-essential git
python3 -m venv ~/otr-env && source ~/otr-env/bin/activate
pip install cryptography pysocks argon2-cffi maturin
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh && source ~/.cargo/env

git clone https://github.com/muc111/OTRv4Plus.git && cd OTRv4Plus
python setup_otr4.py build_ext --inplace
bash build_ed448.sh

cd Rust && cargo build --release --features pq-rust
cp target/release/libotrv4_core.so .. && cd ..

PYTHONMALLOC=malloc python otrv4+.py -s irc.libera.chat:6697
```

</details>

---

## Commands

```
/otr <nick>          Start OTR session
/smp <secret>        Set SMP shared secret (stays in Rust memory never logged)
/smp start           Begin SMP verification (initiator)
/fingerprint         Show your fingerprint and the peer's
/trust <nick>        Trust a peer's fingerprint manually
/endotr              End the current encrypted session
/secure              Show current security level
/join <channel>      Join a channel
/part                Leave current channel
/switch <nick>       Switch to a peer's tab
/quit                Wipe all keys and exit
```

`/join`, `/switch`, `/part`, `/names` all accept the channel name with or without `#`.

---

## Technical details

<details>
<summary>🔐 Cryptographic design</summary>

### DAKE (Deniable Authenticated Key Exchange)

- **DAKE1**: X448 ephemeral + ML‑KEM‑1024 encapsulation key + client profile + optional ML‑DSA‑87 public key
- **DAKE2**: X448 ephemeral + ML‑KEM‑1024 ciphertext + client profile + optional ML‑DSA‑87 public key + MAC
- **DAKE3**: Ed448 ring signature + optional ML‑DSA‑87 signature

Both peers contribute to the session key via X448 + ML‑KEM. ML‑DSA fields use a flag byte (`0x01` present / `0x00` absent) peers without ML‑DSA fall back to classical ring signatures.

### Double ratchet

Pure Rust implementation (`otrv4_core`). Root key, chain keys, and message keys derived via SHAKE‑256 KDF with "OTRv4" domain separator per spec §3.2. Fresh ML‑KEM encapsulation at every DH ratchet epoch. Brace key rotated every `REKEY_INTERVAL` messages. `Zeroize` on drop; all `unsafe` blocks forbidden.

### Wire format

```
DAKE1: 0x35 ‖ X448_eph(56) ‖ MLKEM_ek(1568) ‖ profile(var) [‖ MLDSA_pub(2592)]
DAKE2: 0x36 ‖ X448_eph(56) ‖ MLKEM_ct(1568) ‖ profile(var) [‖ MLDSA_pub(2592)] ‖ MAC(64)
DAKE3: 0x37 ‖ ring_sigma(228) ‖ flag(1) [‖ MLDSA_sig(4627)]
DATA:  0x00 ‖ 0x04 ‖ 0x03 ‖ header(64) ‖ nonce(12) ‖ ct(var) ‖ tag(16)
```

Messages fragment at 300 bytes for IRC line limits using OTR §4.7 wire format.

### SMP (Socialist Millionaire Protocol) v10.5.10

All four SMP messages are processed entirely inside the Rust `otrv4_core` crate. No Python integer ever holds an SMP exponent.

| Property | Detail |
|---|---|
| Group | 2048-bit safe prime (RFC 3526 Group 14), generator 2 |
| ZKP hash | SHA3‑512 (Fiat‑Shamir) |
| Secret KDF | 50,000-round SHAKE‑256 chain + HMAC‑SHA3‑512 session binding |
| Fingerprint order | Lexicographic both sides always see the same input regardless of who initiated |
| Rate limiting | 3 failures → permanent `Aborted` state; 30-second cooldown between retries |
| Session expiry | 10-minute hard timeout per `SmpState` |
| Transcript MAC | HMAC‑SHA3‑512 over all wire messages prevents cross‑session replay |
| Secret storage | `RustSMPVault` Rust heap only; Python holds an opaque `u64` handle |
| Zeroization | `ZeroizeOnDrop` on every `SecretVec`; explicit `destroy()` on abort |

### KDF

All key derivation uses `SHAKE‑256("OTRv4" ‖ usage_ID ‖ value, size)` per spec §3.2. Usage IDs `0x00`–`0x1F` are domain‑separated to prevent key conflation.

</details>

<details>
<summary>🧠 Memory security</summary>

### How secrets are isolated from Python's garbage collector

The Python GC cannot zeroize memory. Any secret that enters a Python `str`, `bytes`, or `int` object is uncontrolled: the GC may copy it during compaction, leave it in freed blocks, or expose it in a crash dump. OTRv4+ eliminates this through strict Rust ownership of all secret material.

| Component | Where secrets live | Python sees | Zeroization |
|---|---|---|---|
| **SMP passphrase** | `RustSMPVault` (Rust `Vec<u8>`, `ZeroizeOnDrop`) | Opaque `u64` handle | On `vault.clear()` or session end |
| **SMP exponents** | `SmpState.SecretVec` fields | Nothing | `ZeroizeOnDrop` + explicit `destroy()` |
| **Ratchet keys** | `RustDoubleRatchet` (`SecretBytes<32>`) | Nothing | `ZeroizeOnDrop` on every key struct |
| **Brace key** | Rust `SecretBytes<32>` | Nothing | `ZeroizeOnDrop` |
| **Session KDF output** | Rust, consumed immediately | Nothing | Stack/local scope |
| **Passphrase in transit** | `bytearray` (Python, wiped) | Overwritten before GC | `for i in range(len(raw)): raw[i] = 0` |

The only window where secret bytes touch Python memory is the brief moment between `secret.encode('utf-8')` and `vault.store()`. This is a `bytearray` (mutable, not interned) that is overwritten byte-by-byte in a `finally` block before being deleted. The CPython allocator may retain the freed block until the next allocation this is an unavoidable language-level limitation but the exposure window is microseconds, not session-lifetime.

### Other hardening

- `OPENSSL_cleanse` on all C extension key buffers before deallocation
- `prctl(PR_SET_DUMPABLE, 0)` core dumps disabled
- Key storage: AES‑256‑GCM + Argon2id (64 MB, 3 passes) for the master key
- File destruction: NIST SP 800‑88r1 re‑encrypt with ephemeral key, overwrite with zeros and random, then unlink
- On `/quit`: all ratchets zeroized, all C buffers cleansed, `~/.otrv4plus/` deleted, terminal cleared

</details>

<details>
<summary>⚖️ Comparison with Signal</summary>

Signal's PQXDH adds ML‑KEM to the initial handshake but their own spec notes that "authentication in PQXDH is not quantum‑secure." After the handshake their ratchet is purely classical compromise one epoch key and you can decrypt forward.

OTRv4+ adds ML‑KEM encapsulation at every DH ratchet epoch, so forward secrecy is post‑quantum throughout the session, not just at setup. ML‑DSA‑87 provides post‑quantum authentication. SMP identity verification uses a zero‑knowledge proof with the secret stored only in Rust memory Signal has no equivalent.

The tradeoffs: no async support, no push notifications, no PQ deniability (an open research problem nobody has solved). This is for sessions where both parties are present and traces are unacceptable.

</details>

<details>
<summary>📋 Known issues and limitations</summary>

- **Passphrase briefly in Python memory**: the ~microsecond window between `encode()` and `vault.store()` see Memory security section
- **DAKE DH shared secrets pass through Python briefly** before the KDF (private keys stay in OpenSSL's C heap)
- **Fragment count leaks message type** to a local observer (DAKE = 20–25 fragments in a burst)
- **Random nick pool** (~11,000 names) reduces but doesn't eliminate cross‑session correlation
- **Clearnet exposes your IP** in WHOIS until cloaking kicks in use I2P or Tor
- **PQ deniability** doesn't exist as a standardised primitive anywhere open research problem
- **I2P latency** makes the handshake and SMP take several minutes this is a network property, not a bug

None of these are cryptographic breaks.

</details>

---

## Tests

313 tests (299 Python + 14 Rust) covering: double ratchet across 100k messages, replay and forgery resistance, ML‑KEM‑1024 known‑answer vectors, ML‑DSA‑87 smoke tests, ring signature non‑malleability, SMP full protocol flow, property‑based verification.

```bash
# Rust tests
cd Rust && cargo test --release && cd ..

# Python tests
pip install pytest hypothesis
PYTHONPATH=. pytest tests/ -v
```

---

## Why use this

<details>
<summary>Threat model and use cases</summary>

**The server sees nothing.** All messages are end‑to‑end encrypted with OTRv4. The IRC server admin gets ciphertext and metadata who's talking to who, when, and roughly how much. They cannot read a single word.

**Quantum computers won't break your old logs.** ML‑KEM‑1024 at the handshake plus fresh KEM material rotated with every DH ratchet means someone who records everything today and runs a quantum computer in 2030 cannot recover session keys.

**No persistent identity.** Random nick on every launch. Fresh I2P destination every session. No account, no email, no phone number. You show up, talk, and disappear.

**Deniable authentication.** Ed448 ring signatures mean neither party can prove to a third party that the other person said anything specific.

**SMP verification without revealing secrets.** The shared passphrase is never sent over the wire. The protocol proves you both know it via zero‑knowledge exchange running entirely inside Rust. Nothing to brute‑force after the fact.

**Everything wipes on exit.** `/quit` zeroizes every Rust ratchet, cleanses every C extension buffer, clears the terminal, and deletes `~/.otrv4plus/`.

Intended for journalists, researchers, activists, and anyone who needs synchronous, deniable, post‑quantum chat that leaves no trace.

</details>

---

## WeeChat plugin

Same crypto, different frontend. Drop the plugin files into `~/.local/share/weechat/python/` and run `/python load weechat_otrv4plus.py` inside WeeChat.

---

## Development

Built with AI‑assisted development (Claude). All cryptographic implementations verified through 313 automated tests, live DAKE and SMP exchanges between Termux instances over I2P, and a full security audit with all findings patched. The Rust ratchet and SMP cores contain zero `unsafe` blocks.

---

## License

GPL‑3.0 – see LICENSE. Commercial licensing available – see COMMERCIAL‑LICENSE.md.

---

*"Arguing that you don't care about the right to privacy because you have nothing to hide is no different than saying you don't care about free speech because you have nothing to say."* Edward Snowden
