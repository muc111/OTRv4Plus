# Off The Record v4 Plus PQC (OTRv4)

Post-quantum encrypted messaging over IRC. Built for I2P, works everywhere.

This is the only OTRv4 implementation with post-quantum cryptography. The key exchange, authentication, and ratchet all use NIST-standardised PQC alongside classical crypto. If a quantum computer breaks X448, your messages — past and future — stay protected.

The client defaults to `irc.postman.i2p` over I2P's SOCKS5 proxy. Point it at any IRC server and it auto-detects the network: `.i2p` routes through I2P, `.onion` through Tor, everything else goes clearnet with TLS. No manual proxy config needed.

One Python file (~12,000 lines), three C extensions, a Rust ratchet core, 224 tests. Runs on Termux on a phone.

---

## I2P quick start

If you're already running I2P, this connects out of the box:

```bash
git clone https://github.com/muc111/OTRv4Plus.git
cd OTRv4Plus

# On Debian/Ubuntu/Arch/macOS — create a venv first:
python3 -m venv ~/otr-env && source ~/otr-env/bin/activate
pip install cryptography pysocks

# On Termux — pip works directly:
# pip install cryptography pysocks

# Build C extensions (all platforms)
python setup_otr4.py build_ext --inplace
bash build_ed448.sh
gcc -shared -fPIC -O2 -o otr4_mldsa_ext.so otr4_mldsa_ext.c \
    $(python3-config --includes) $(python3-config --ldflags --embed) -lcrypto

# Run — connects to irc.postman.i2p by default
PYTHONMALLOC=malloc python otrv4+.py
```

The client connects to `irc.postman.i2p:6667` via I2P's SOCKS5 proxy on `127.0.0.1:4447`. Once you're in, `/join #otr` or any channel, then `/otr <nick>` to start an encrypted session with someone.

For clearnet or Tor:

```bash
# Libera.Chat with TLS
PYTHONMALLOC=malloc python otrv4+.py -s irc.libera.chat:6697

# Tor hidden service
PYTHONMALLOC=malloc python otrv4+.py -s palladium.libera.chat.onion:6667

# SASL login
PYTHONMALLOC=malloc python otrv4+.py -s irc.libera.chat --sasl -n YourNick

# Specific port, no TLS
PYTHONMALLOC=malloc python otrv4+.py -s irc.example.com -p 6667 --no-tls
```

`PYTHONMALLOC=malloc` lets the C extensions use `mlock()` for secure memory pages. You can omit it for a quick test but it should be used in practice.

---

## Platform setup

Every platform needs: Python 3.9+, OpenSSL 3.5+, a C compiler, and the `cryptography` and `pysocks` pip packages. On Debian/Ubuntu 23.04+, Arch, and macOS, pip requires a virtual environment — the platform sections below include the venv setup. Termux doesn't have this restriction. The Rust ratchet core is optional but recommended — without it, chain keys are cleaned by Python's garbage collector instead of being deterministically zeroed.

### Termux (Android)

Termux doesn't enforce the externally-managed-environment restriction so `pip install` works directly.

```bash
# Core dependencies
pkg install python openssl clang build-essential git

# Python packages
pip install cryptography pysocks

# I2P — install i2pd from the Termux repos or use the Java I2P Android app
# i2pd exposes SOCKS5 on 127.0.0.1:4447 by default
pkg install i2pd
# Start i2pd in the background:
i2pd --daemon

# Tor (optional)
pkg install tor
tor &   # SOCKS5 on 127.0.0.1:9050

# Rust ratchet core (optional, recommended)
pkg install rust
pip install maturin
cd Rust
cargo test --release
export ANDROID_API_LEVEL=24
maturin build --release
pip install target/wheels/otrv4_core-*.whl --break-system-packages
cd ..
```

### Debian / Ubuntu

Ubuntu 23.04+ and Debian 12+ block system-wide `pip install`. Use a virtual environment.

```bash
# Core dependencies
sudo apt update
sudo apt install python3 python3-dev python3-pip python3-venv \
                 libssl-dev build-essential git

# Create and activate virtual environment
python3 -m venv ~/otr-env
source ~/otr-env/bin/activate

# Python packages (inside venv — no --break-system-packages needed)
pip install cryptography pysocks

# I2P — i2pd from the official repo
sudo apt install apt-transport-https
wget -q -O - https://repo.i2pd.xyz/.help/add_repo | sudo bash -s -
sudo apt update
sudo apt install i2pd
# i2pd starts automatically; SOCKS5 on 127.0.0.1:4447

# Tor (optional)
sudo apt install tor
# Starts automatically; SOCKS5 on 127.0.0.1:9050

# Rust ratchet core (optional, recommended)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
pip install maturin
cd Rust
cargo test --release
maturin build --release
pip install target/wheels/otrv4_core-*.whl
cd ..

# IMPORTANT: always activate the venv before running the client
# source ~/otr-env/bin/activate
```

### Arch Linux

Arch also enforces externally-managed-environment on recent versions.

```bash
# Core dependencies
sudo pacman -S python python-pip openssl base-devel git

# Create and activate virtual environment
python3 -m venv ~/otr-env
source ~/otr-env/bin/activate

# Python packages
pip install cryptography pysocks

# I2P
sudo pacman -S i2pd
sudo systemctl enable --now i2pd

# Tor (optional)
sudo pacman -S tor
sudo systemctl enable --now tor

# Rust ratchet core (optional, recommended)
sudo pacman -S rust
pip install maturin
cd Rust && cargo test --release && maturin build --release
pip install target/wheels/otrv4_core-*.whl
cd ..
```

### macOS (Homebrew)

```bash
# Core dependencies
brew install python openssl@3 git

# Create and activate virtual environment
python3 -m venv ~/otr-env
source ~/otr-env/bin/activate

# Python packages — point at Homebrew's OpenSSL
LDFLAGS="-L$(brew --prefix openssl@3)/lib" \
CFLAGS="-I$(brew --prefix openssl@3)/include" \
pip install cryptography pysocks

# I2P — install i2pd via Homebrew
brew install i2pd
brew services start i2pd

# Tor (optional)
brew install tor
brew services start tor

# Rust ratchet core (optional, recommended)
brew install rust
pip install maturin
cd Rust && cargo test --release && maturin build --release
pip install target/wheels/otrv4_core-*.whl
cd ..
```

### Verify OpenSSL

ML-KEM-1024 and ML-DSA-87 need OpenSSL 3.5+. If your distro ships an older version, the C extensions will fail to build.

```bash
openssl version
# Must show: OpenSSL 3.5.0 or later

# If it shows 3.x older than 3.5, you need to build OpenSSL from source
# or use a backport. Termux ships 3.5+ by default.
```

---

## How it works

You launch the client. It connects to IRC (I2P by default). You join a channel, see who's there, and type `/otr SomeNick` to start an encrypted session.

Behind the scenes:

1. **DAKE handshake** — three messages (DAKE1/DAKE2/DAKE3) establish a shared secret using triple X448 Diffie-Hellman + ML-KEM-1024 post-quantum encapsulation. The third message carries an Ed448 ring signature (deniable authentication) and optionally an ML-DSA-87 signature (post-quantum authentication).

2. **Double ratchet** — every message derives a fresh encryption key from the chain. Every 50 messages (or 5 minutes), a DH ratchet step generates new ephemeral keys. Each DH ratchet also rotates the ML-KEM brace key, so post-quantum protection self-heals after compromise.

3. **SMP verification** — both sides type the same shared secret (`/smp mysecret`), then `/smp start`. The Socialist Millionaires' Protocol proves they know the same secret without revealing it. Uses 3072-bit DH with zero-knowledge proofs. The passphrase is stretched through 10,000 iterations of SHAKE-256.

4. **Shutdown** — on `/quit`, every ratchet is zeroized (Rust `Drop` trait overwrites all key bytes), the screen is cleared, and persistent data is securely wiped.

The session indicator shows security level: 🔴 plaintext, 🟡 encrypted (unverified), 🟢 fingerprint trusted, 🔵 SMP verified.

---

## Network auto-detection

The client inspects the server hostname you give it:

| Hostname pattern | Network | Proxy | Default port |
|---|---|---|---|
| `*.i2p` | I2P | `127.0.0.1:4447` (SOCKS5) | 6667 |
| `*.onion` | Tor | `127.0.0.1:9050` (SOCKS5) | 6667 |
| anything else | Clearnet | direct | 6697 (TLS) |

No flags needed. `irc.postman.i2p` routes through I2P. `palladium.libera.chat.onion` routes through Tor. `irc.libera.chat` goes direct with TLS auto-negotiated.

I2P users: make sure i2pd (or Java I2P) is running with the SOCKS5 proxy enabled on port 4447. The client will tell you if it can't reach the proxy.

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    otrv4+.py                        │
│         IRC client, UI, DAKE, SMP, config           │
│                   (~12,000 lines)                   │
├─────────────┬─────────────┬─────────────────────────┤
│  Rust core  │ C extensions│    Python cryptography   │
│ otrv4_core  │ 3 × .so     │    (OpenSSL bindings)    │
├─────────────┼─────────────┼─────────────────────────┤
│ AES-256-GCM │ ML-KEM-1024 │ X448 key exchange       │
│ SHAKE-256   │ Ed448 ring  │ Ed448 signatures        │
│ Chain KDF   │ signatures  │ ML-DSA-87 (via EVP)     │
│ Skip keys   │ BN ct arith │                         │
│ Replay det  │ Memory lock │                         │
│ Zeroize     │ OSSL cleanse│                         │
└─────────────┴─────────────┴─────────────────────────┘
                      OpenSSL 3.5+
```

The Rust core handles the double ratchet — where message keys live the longest and matter the most. All chain keys, root keys, brace keys, message keys, and skipped keys are deterministically zeroed on drop. If Rust isn't installed, the client falls back to equivalent Python code backed by the same C/OpenSSL crypto. The protocol and wire format are identical either way.

The startup banner tells you which backend is running:

```
OTRv4 IRC Client
==================================================
Version : OTRv4+ 10.0
Server  : irc.postman.i2p:6667
Network : 🧅 I2P (plaintext)
Auth    : anonymous
Channel : #otr
Debug   : OFF
Ratchet : 🦀 Rust (zeroize-on-drop)
==================================================
```

---

## Crypto stack

**Key exchange (DAKE):** Triple X448 Diffie-Hellman + ML-KEM-1024 encapsulation (FIPS 203). The KEM shared secret is mixed into root key derivation. Both classical and post-quantum key material must be compromised to break the session.

**Authentication (DAKE3):** Ed448 Schnorr ring signature for classical deniability + ML-DSA-87 (FIPS 204) for post-quantum authentication. The ring sig means neither party can prove the other participated. ML-DSA means a quantum adversary can't forge your identity. These coexist — deniability against classical adversaries, authentication against quantum ones.

**Ratchet:** OTRv4 double ratchet with ML-KEM-1024 brace key rotation every DH epoch. The brace key starts as the DAKE's KEM shared secret and rotates with fresh KEM material on each DH ratchet. Post-quantum protection self-heals after compromise.

**Per-message:** AES-256-GCM with 12-byte random nonce. Keys derived via SHAKE-256 (KDF_1, spec §3.2). MAC keys are SHA3-512. 128-bit post-quantum symmetric security via Grover's bound.

**SMP:** RFC 3526 Group 15 (3072-bit safe prime). Fiat-Shamir zero-knowledge proofs. All modular exponentiation via OpenSSL's `BN_mod_exp_mont_consttime`. Passphrase stretched through 10,000 rounds of SHAKE-256 with `OTRv4+SMP\x00` domain separator.

No liboqs. All PQC uses OpenSSL 3.5+ native FIPS 203/204 providers.

---

## C extensions

| File | Lines | What it does |
|---|---|---|
| `otr4_crypto_ext.c` | 1866 | BN constant-time arithmetic, ML-KEM-1024 (full NTT implementation), Ed448 ring signatures, `mlock()`/`OPENSSL_cleanse` memory hardening |
| `otr4_ed448_ct.c` | 867 | Constant-time Ed448 scalar multiplication using Montgomery ladder with XOR-based `cswap` — no branching on secret bits |
| `otr4_mldsa_ext.c` | 321 | ML-DSA-87 keygen/sign/verify via OpenSSL's EVP API |

These are mandatory. The client refuses to start without them.

### Build

```bash
python setup_otr4.py build_ext --inplace
bash build_ed448.sh
gcc -shared -fPIC -O2 -o otr4_mldsa_ext.so otr4_mldsa_ext.c \
    $(python3-config --includes) $(python3-config --ldflags --embed) -lcrypto
```

If any extension fails, check that `python3-dev` (or `python3-devel`) and `libssl-dev` (or `openssl-devel`) are installed and `openssl version` shows 3.5+.

---

## Rust ratchet core

The double ratchet runs in Rust via PyO3. Every secret byte is overwritten with zeros when the ratchet is dropped — guaranteed by Rust's `Zeroize` trait, not dependent on Python's garbage collector.

```bash
cd Rust
cargo test --release          # 11 tests in 0.01s
maturin build --release
pip install target/wheels/otrv4_core-*.whl --break-system-packages
```

On Termux, set `export ANDROID_API_LEVEL=24` before running `maturin build`.

Zero `unsafe` blocks. The Rust code handles: SHAKE-256 KDF, AES-256-GCM encrypt/decrypt, chain key advancement, skipped key storage (`BTreeMap` with `ZeroizeOnDrop` entries), replay detection, and brace key rotation.

X448/Ed448 key exchange stays in Python (OpenSSL via the `cryptography` library). ML-KEM and ML-DSA stay in the C extensions. Rust and Python interoperate on the same wire format.

If the Rust module isn't installed, the client falls back silently to the Python ratchet. Both backends pass the same 224 tests.

---

## Wire format

```
DAKE1:  0x35 ‖ X448_eph(56) ‖ MLKEM_ek(1568) ‖ profile(var) [‖ MLDSA_pub(2592)]
DAKE2:  0x36 ‖ X448_eph(56) ‖ MLKEM_ct(1568) ‖ profile(var) [‖ MLDSA_pub(2592)] ‖ MAC(64)
DAKE3:  0x37 ‖ ring_sigma(228) ‖ flag(1) [‖ MLDSA_sig(4627)]
DATA:   0x00 ‖ 0x04 ‖ 0x03 ‖ header(64) ‖ nonce(12) ‖ ciphertext(var) ‖ tag(16)
```

ML-DSA fields use flag-byte encoding — `0x01` means present, `0x00` means absent. Peers without ML-DSA fall back to classical ring signatures only. Fully backward compatible.

OTR messages are fragmented for IRC line limits (300 bytes per fragment) using the spec §4.7 wire format: `?OTRv4|sender_tag|receiver_tag|k|n|data.`

---

## Commands

**IRC:** `/join #channel` `/part` `/nick newnick` `/msg nick message` `/names` `/topic` `/list` `/whois nick` `/invite nick #channel` `/kick nick` `/mode` `/notice` `/away message` `/back` `/raw COMMAND` `/reconnect` `/quit`

**OTR:** `/otr nick` starts a session (sends DAKE1). `/endotr nick` ends it. `/fingerprint` shows yours and theirs. `/trust nick` marks a fingerprint trusted. `/smp secret` sets the verification passphrase. `/smp start` begins verification. `/smp abort` cancels. `/smp status` shows progress. `/secure` lists all active sessions.

**UI:** `/switch panelname` `/tabs` `/tab-next` `/tab-prev` `/tab-close` `/clear` `/ignore nick` `/unignore nick` `/ignored` `/status` `/debug` `/version`

---

## Tests

```bash
# Standard suite (~2 minutes on Termux)
pytest -v test_*.py fuzz_harnesses.py -k "not 300k"

# Full gauntlet including 300k message torture tests (~8 hours)
pytest -v test_*.py fuzz_harnesses.py
```

224 tests across 10 files: double ratchet correctness across 10k/50k/100k messages, state fork attacks, replay resistance, forward secrecy erasure, post-compromise recovery, out-of-order delivery, ML-KEM roundtrips, ML-DSA hybrid verification, ring signature non-malleability, wire format fuzzing, SMP zero-knowledge proofs, DAKE state machine transitions, and differential property testing.

---

## Security status

| Layer | Where it runs | Secret zeroization |
|---|---|---|
| Double ratchet (chain/root/brace/message keys) | Rust | Deterministic — `Zeroize` on drop |
| AES-256-GCM encrypt/decrypt | Rust | Deterministic |
| SHAKE-256 KDF | Rust | Deterministic |
| Skipped keys + replay cache | Rust | `ZeroizeOnDrop` on `BTreeMap` entries |
| ML-KEM-1024 | C extension | `OPENSSL_cleanse` |
| ML-DSA-87 | C extension (OpenSSL EVP) | `OPENSSL_cleanse` |
| Ed448 ring signatures | C extension (constant-time) | `OPENSSL_cleanse` |
| Ed448 scalar multiply | C extension (Montgomery cswap) | `OPENSSL_cleanse` |
| X448 key exchange | Python `cryptography` (OpenSSL) | OpenSSL-managed |
| SMP exponents (a2, b3, r5...) | Python (OpenSSL BN arithmetic) | GC-dependent (seconds) |
| DAKE ephemeral keys | Python | GC-dependent (milliseconds) |

The ratchet is where secrets live the longest — every message key, every chain advancement, every skipped key for out-of-order delivery. That's all Rust now with guaranteed zeroization. SMP exponents exist for seconds during the handshake. DAKE ephemerals are one-shot.

---

## Comparison with Signal PQXDH

Signal's PQXDH (revision 3, 2024) adds ML-KEM to the initial handshake but does not upgrade authentication. Their spec states explicitly: "Authentication in PQXDH is not quantum-secure" and "post-quantum secure deniable mutual authentication is an open research problem."

This client takes a different approach. ML-DSA-87 provides post-quantum authentication at the cost of PQ deniability — a quantum adversary could verify the signature and prove you participated. The ring signature still provides classical deniability. PQ deniable signatures don't exist in any standard, so this is the best available option.

| | Signal PQXDH | OTRv4+ |
|---|---|---|
| PQ key exchange | ML-KEM at handshake only | ML-KEM-1024 at DAKE + every ratchet epoch |
| PQ authentication | None | ML-DSA-87 hybrid |
| Classical deniability | Yes | Yes (ring signature) |
| PQ deniability | No | No (open problem) |
| Async support | Yes (prekey server) | No (both online, IRC) |
| Ratchet memory safety | GC-dependent | Rust zeroize-on-drop |

---

## Known limitations

Endpoint compromise beats everything. A rooted phone, a malicious Termux package, or screen capture malware bypasses all cryptography. This is true for every encrypted messenger, not just this one.

I2P traffic analysis can fingerprint OTR handshakes by fragment count — DAKE messages produce 20-25 IRC lines in a distinctive burst. Padding cannot be added at the fragment layer without a protocol-level change (a PADDING TLV inside the encrypted envelope). This is a known limitation documented in the codebase.

The nick generator produces ~11,000 unique nicks from a combinatorial pool. This reduces but doesn't eliminate cross-session correlation if an observer sees you reconnect with different nicks.

SMP security depends on passphrase entropy. The 10,000x SHAKE-256 stretching makes brute-force harder but short passphrases (under 6 characters) remain vulnerable. The client warns you.

Clearnet connections expose your IP in IRC WHOIS until nick cloaking activates. Use I2P or Tor to avoid this.

The one cryptographic gap is PQ deniability. No standardised primitive exists. When one does, the flag-byte mechanism in DAKE3 supports upgrading without breaking backward compatibility.

---

## Data

Everything persistent lives in `~/.otrv4plus/`:

- `trust.json` — fingerprint trust database (TOFU)
- `smp_secrets.json` — SMP secrets (XOR-obfuscated at rest)
- `keys/` — Ed448 identity key, X448 prekey (encrypted)
- `logs/otrv4plus.log` — rotating event log

On `/quit`, active sessions are zeroized (Rust deterministic wipe for ratchet keys, `OPENSSL_cleanse` for C extension secrets) and the screen is cleared.

---

## License

GPL-3.0 for open source use — see [LICENSE](LICENSE).

Commercial licensing available for proprietary integration — see [COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md).

---

## Development

This project was built with AI-assisted development (Claude).
All cryptographic code has been manually tested across 224 tests,
verified with live DAKE and SMP exchanges over I2P, and the
C extensions have been audited for constant-time correctness.
The Rust ratchet core contains zero unsafe blocks.

---

> *"Arguing that you don't care about the right to privacy because you have nothing to hide is no different than saying you don't care about free speech because you have nothing to say."* — Edward Snowden

> *"If privacy is outlawed, only outlaws will have privacy."* — Phil Zimmermann

> *"Privacy is necessary for an open society in the electronic age. Privacy is not secrecy."* — Cypherpunk Manifesto
