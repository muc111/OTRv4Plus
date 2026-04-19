<p align="center">
  <img src="icon.png" width="200" alt="OTRv4+">
</p>

# OTRv4+

Off The Record v4 + PQC

Post-quantum OTR for IRC. The whole thing runs on a phone over I2P/TOR/Clearnet

I built this because nobody else was going to. The OTRv4 spec has been sitting there for years with zero complete implementations, and meanwhile every messaging protocol is scrambling to bolt on post-quantum crypto before Q-day arrives. So I did both — implemented the full OTRv4 spec and added PQC to every layer while I was at it.

It defaults to `irc.postman.i2p`. Point it at any server and it figures out the network — `.i2p` goes through I2P, `.onion` through Tor, everything else gets TLS. No config files, no setup wizards.

---

## Why use this

If you're a journalist, researcher, or just someone who doesn't want their conversations stored forever on some company's server waiting for a quantum computer to decrypt them five years from now — this is for you.

Here's what it actually protects against:

**The server sees nothing.** All messages are end-to-end encrypted with OTRv4. The IRC server admin gets ciphertext and metadata — who's talking to who, when, and how much. They cannot read a single word you say.

**Quantum computers won't break your old logs.** ML-KEM-1024 at the handshake plus fresh KEM material rotated in with every DH ratchet means even if someone records everything today and throws a quantum computer at it in 2030, the session keys stay safe. Signal only does PQC at the initial handshake — compromise that and the whole session opens up. This one self-heals.

**No persistent identity.** Random nick on every launch. Fresh I2P destination every session when SAM is enabled. No account, no email, no phone number, no username that follows you around. You show up, talk, and disappear. Next time you connect you're a completely different person as far as the network can tell.

**Deniable authentication.** Ed448 ring signatures mean neither side can cryptographically prove to a third party that the other person said anything. You know who you're talking to. Nobody else can prove it was them. Standard in OTR, kept intact here.

**SMP verification without revealing secrets.** You can verify you're talking to the right person by typing a shared passphrase. The protocol proves you both know it without sending it over the wire. No attacker can brute-force it after the fact because the exchange is zero-knowledge.

**Everything wipes on exit.** `/quit` zeroizes every Rust ratchet, cleanses every C extension buffer, clears the terminal screen, and deletes `~/.otrv4plus/`. Nothing lingers in swap or temp files. If someone grabs your phone, there's nothing to recover.

**Runs on anything.** One Python file, three C extensions, one Rust library. Works on Linux, macOS, Android via Termux. No Docker, no systemd services, no cloud dependencies. You can audit the whole protocol in one sitting.

**Network agnostic.** Point it at `.i2p` and it routes through I2P. `.onion` goes through Tor. Clearnet IRC servers get TLS. Same client, same crypto, no config changes.

The tradeoff is both parties need to be online at the same time (it's IRC, not Signal) and there's no forward secrecy for stored identity keys (that's what the random nicks and transient I2P destinations are for). If you need async messaging, this isn't it. If you need synchronous, deniable, post-quantum chat that leaves no trace, this is exactly it.

---

## Live demo — Termux on Android

*DAKE handshake, fingerprint exchange, and 4-step SMP identity verification over I2P SAM bridge:*

<p align="center">
  <img src="git_screenshot.png" width="380" alt="OTRv4+ running in Termux — DAKE + SMP over I2P">
</p>

The screenshot shows a complete session: SAM bridge connection → DAKE3 completing with Ed448 ring signatures → SHA3-512 fingerprint trust → SMP zero-knowledge proof running all four steps → Rust double ratchet session live. Nick is randomised on every launch.

---

## 📱 Termux (Android) — One-Line Install

One command does everything — clone, build, and run:

```bash
git clone https://github.com/muc111/OTRv4Plus.git && cd OTRv4Plus && chmod +x termux_install.sh && ./termux_install.sh && PYTHONMALLOC=malloc python otrv4+.py
```

That's it. Paste it into Termux and walk away.

### What `termux_install.sh` does

The script runs five stages automatically:

| Stage | What happens |
|-------|-------------|
| **[1/5] System deps** | `pkg install python rust openssl clang make binutils` |
| **[2/5] Python tools** | `pip install maturin setuptools` |
| **[3/5] Clean** | Removes stale build artefacts so you start fresh |
| **[4/5] API level** | Reads your device's Android API level via `getprop` (defaults to 24) |
| **[5/5] C extensions** | Builds `otr4_crypto_ext`, `otr4_ed448_ct`, `otr4_mldsa_ext` with `setup_otr4.py` |
| **[6/6] Rust core** | `cargo build --release` → copies `libotrv4_core.so` into the project root |

**Automatic prebuilt fallback:** if any build step fails (no compiler, missing headers, old toolchain), the script copies the prebuilt `.so` files from the `prebuilt/` directory and continues. You get a working install either way.

At the end you'll see:

```
🎉 OTRv4+ is ready!

Run with:
  PYTHONMALLOC=malloc python otrv4+.py
```

### Step-by-step (if you prefer to run things manually)

```bash
# 1. Clone
git clone https://github.com/muc111/OTRv4Plus.git
cd OTRv4Plus

# 2. Run the installer
chmod +x termux_install.sh
./termux_install.sh

# 3. Launch
PYTHONMALLOC=malloc python otrv4+.py
```

> **I2P:** The default server is `irc.postman.i2p`. You need i2pd running:
> ```bash
> pkg install i2pd && i2pd --daemon
> ```
> Wait ~3 minutes for I2P to bootstrap, then launch OTRv4+. See [I2P setup](#i2p-setup) below.

---

## Get it running — other platforms

You need Python 3.9+, OpenSSL 3.5+ (for ML-KEM and ML-DSA), a C compiler, and the Rust ratchet core.

**If you can't or don't want to build from source:** prebuilt `.so` files for Termux on Android (aarch64) are in the `prebuilt/` directory. Just copy them into your OTRv4Plus folder and skip the C extension and Rust build steps. See [Prebuilt binaries](#prebuilt-binaries) below.

### Debian / Ubuntu (23.04+)

23.04+ blocks pip outside a venv, so use one:

```bash
sudo apt install python3 python3-dev python3-venv libssl-dev build-essential git
python3 -m venv ~/otr-env
source ~/otr-env/bin/activate
pip install cryptography pysocks argon2-cffi maturin
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

git clone https://github.com/muc111/OTRv4Plus.git
cd OTRv4Plus
python setup_otr4.py build_ext --inplace
bash build_ed448.sh
gcc -shared -fPIC -O2 -o otr4_mldsa_ext.so otr4_mldsa_ext.c \
    $(python3-config --includes) $(python3-config --ldflags --embed) -lcrypto

cd Rust
cargo test --release
maturin build --release
pip install target/wheels/otrv4_core-*.whl
cd ..

PYTHONMALLOC=malloc python otrv4+.py -s irc.libera.chat:6697
```

Always run `source ~/otr-env/bin/activate` before launching.

### Arch Linux

```bash
sudo pacman -S python python-pip openssl base-devel git rust
python3 -m venv ~/otr-env && source ~/otr-env/bin/activate
pip install cryptography pysocks argon2-cffi maturin
```

Then clone and follow the same build steps as Debian above.

### macOS

```bash
brew install python openssl@3 git rust
python3 -m venv ~/otr-env && source ~/otr-env/bin/activate
LDFLAGS="-L$(brew --prefix openssl@3)/lib" CFLAGS="-I$(brew --prefix openssl@3)/include" \
pip install cryptography pysocks argon2-cffi maturin
```

Then clone, build the C extensions and Rust core, and run. Same steps as above.

---

## Prebuilt binaries

If you're on Termux (Android, aarch64) and don't want to install a full build toolchain, the `prebuilt/` directory contains compiled `.so` files ready to use:

| File | Purpose |
|------|---------|
| `otr4_crypto_ext.so` | OpenSSL-backed AES-GCM, ChaCha20, HKDF, core dumps suppressed |
| `otr4_ed448_ct.so` | Constant-time Ed448 scalar multiplication |
| `otr4_mldsa_ext.so` | ML-DSA-87 (FIPS 204) post-quantum signing — requires OpenSSL ≥ 3.5 |
| `libotrv4_core.so` | Rust double-ratchet core with zeroize-on-drop key material |

Copy them into your OTRv4Plus directory and you're done:

```bash
cp prebuilt/*.so ~/OTRv4Plus/
```

No C compiler, no Rust toolchain, no maturin. Just Python and the dependencies from pip.

These are compiled for Termux on aarch64. If you're on a different platform (Debian x86_64, macOS arm64, etc.), you'll need to build from source using the instructions above.

---

## Rust ratchet core (required)

The double ratchet runs entirely in Rust. All per-message encryption, key derivation, chain advancement, skip keys, and replay detection happen in Rust with deterministic secret zeroization. The Python `DoubleRatchet` class has been removed — there is no fallback. If the Rust module isn't installed, the client refuses to start.

```bash
cd Rust
cargo test --release          # 11 tests, 0.01s
maturin build --release
pip install target/wheels/otrv4_core-*.whl
cd ..
```

On Termux add `export ANDROID_API_LEVEL=24` before `maturin build` (the installer does this for you automatically).

The startup banner confirms Rust is active:

```
Ratchet : 🦀 Rust (zeroize-on-drop)
```

If Rust is missing you'll see:

```
❌ FATAL: otrv4_core Rust module not installed.
```

Zero unsafe blocks in the Rust code.

---

## I2P setup

The client expects I2P's SOCKS5 proxy on `127.0.0.1:4447`.

| Platform | Command |
|----------|---------|
| Termux | `pkg install i2pd && i2pd --daemon` |
| Debian | `sudo apt install i2pd` (starts automatically) |
| Arch | `sudo pacman -S i2pd && sudo systemctl enable --now i2pd` |
| macOS | `brew install i2pd && brew services start i2pd` |

Tor works too — SOCKS5 on port 9050 or 9150. The client picks it up automatically from `.onion` hostnames.

### SAM vs SOCKS5

When connecting to I2P, the client tries the SAM bridge first and falls back to SOCKS5 if SAM isn't available.

**Why this matters:** with SOCKS5, every connection you make shares the same local I2P destination. The IRC server, and anyone watching it, sees the same `.b32.i2p` address every time you connect. If you disconnect and reconnect with a new nick, you're still the same destination. Cross-session tracking is trivial.

SAM creates a fresh transient destination for each session. Every time you launch the client, you get a new I2P identity. There's nothing to correlate between sessions. This is how Tor does it — one circuit per target — and it's the right way to do it on I2P too.

SAM v3.1 is used — just the basic stream connection features that both i2pd and Java I2P have supported for years.

The startup banner tells you which one is active:

```
I2P     : SAM bridge (unique destination per session)
```

or if SAM isn't running:

```
I2P     : SOCKS5 (shared destination — SAM not available)
```

To enable SAM on i2pd, add this to your `i2pd.conf`:

```ini
[sam]
enabled = true
address = 127.0.0.1
port = 7656
```

Then restart i2pd. Java I2P has SAM enabled by default on port 7656.

Tor connections still use SOCKS5 — Tor already creates separate circuits per destination, so the shared-destination problem doesn't apply. Clearnet connections go direct with TLS.

### Check your OpenSSL

```bash
openssl version
```

Needs to say `3.5.0` or later. ML-KEM-1024 and ML-DSA-87 don't exist in older versions and the C extensions won't compile without them. Termux ships 3.5+ already.

---

## What's actually in here

The crypto isn't one trick. Every layer got upgraded:

**Key exchange** — Triple X448 Diffie-Hellman plus ML-KEM-1024 (FIPS 203). The KEM shared secret mixes into the root key, so even if X448 falls to a quantum computer, the session keys are still safe. This happens during a three-message DAKE handshake.

**Authentication** — Ed448 ring signatures give you classical deniability (neither side can prove the other was there). On top of that, ML-DSA-87 (FIPS 204) gives post-quantum authentication — a quantum adversary can't forge your identity. Both run in DAKE3. Strict length validation on all ML-DSA public keys and signatures prevents truncation attacks.

**Ratchet** — Rust-only double ratchet with ML-KEM-1024 brace key rotation every DH epoch. Most PQC messaging protocols only do KEM at the handshake. This one self-heals — if an attacker compromises a session, the next DH ratchet restores PQC protection with fresh KEM material. The Python ratchet class has been removed entirely.

**Per-message** — AES-256-GCM, SHAKE-256 KDFs, random 12-byte nonces. All running in Rust. Nothing exotic at the symmetric level, just stuff that Grover's algorithm can't halve faster than 128-bit security.

**SMP** — Socialist Millionaires' Protocol for identity verification. Both sides type the same passphrase (minimum 8 characters, enforced), the protocol proves they match without revealing it. Uses 3072-bit DH (RFC 3526 Group 15) with zero-knowledge proofs. The passphrase gets stretched through 10,000 rounds of SHAKE-256. All secret exponents stored in a Rust vault with deterministic zeroization. Session-bound — secrets include session ID and both fingerprints to prevent cross-session brute-force.

**Secrets at rest** — Argon2id (64MB, 3 iterations, parallelism 4) for key derivation when storing SMP secrets and identity keys to disk. Falls back to scrypt if argon2-cffi is not installed.

No liboqs. All PQC goes through OpenSSL 3.5+ native providers.

---

## How it looks

Startup banner:

```
OTRv4 IRC Client
==================================================
Version : OTRv4+ 10.5.5
Server  : irc.postman.i2p:6667
Network : 🧅 I2P (plaintext)
Auth    : anonymous
Channel : #otr
Debug   : OFF
Ratchet : 🦀 Rust (zeroize-on-drop)
I2P     : SAM bridge (unique destination per session)
==================================================
```

See the live demo above for the full session flow in Termux.

Once connected, `/join #otr` and `/otr somenick` to start an encrypted session. The indicator shows security level:

🔴 plaintext  
🟡 encrypted, unverified  
🟢 fingerprint trusted  
🔵 SMP verified

Session established looks like:

```
🔒 OTR session with Bob established — Ed448/X448, AES-256-GCM (initiator) [🦀 Rust]
```

### Finding other OTRv4+ users

Type `/names` and it'll show you who else in the channel is running this client. It works by checking the gecos field (the "real name" in IRC) for "OTRv4+". Anyone who has it gets a blue 🔒 prefix in the list:

```
🔒 alice   🔒 bob    carol   dave
--- 🔒 = OTRv4+ client (2 user(s)) — use /otr <nick> to chat ---
```

Regular IRC clients don't show the prefix. It's a quick way to spot who you can actually start an OTR session with instead of guessing.

On `/quit`:

```
🦀 2 Rust ratchet(s) zeroized (deterministic memory wipe)
OTRv4+ terminated — 🦀 Rust memory zeroized — screen cleared
```

---

## The network thing

The client inspects the server hostname and does the right thing:

- `*.i2p` → routes through I2P SAM bridge (preferred) or SOCKS5 fallback
- `*.onion` → routes through Tor SOCKS5 on `127.0.0.1:9050`
- anything else → direct connection with TLS

No flags. `irc.postman.i2p` just works if i2pd is running. `irc.libera.chat:6697` just works over TLS. You can also force things with `-s server:port --no-tls` or `--sasl -n YourNick`.

On disconnect, the client auto-reconnects and rejoins all channels you were in — not just the default channel.

---

## Why it's one file

~12,000 lines in a single Python file. I know what you're thinking.

Here's the thing — when you're auditing a crypto protocol, you want to see the whole thing in one place. Not spread across 40 modules with import chains and circular dependencies. You open `otrv4+.py` and the entire protocol is right there: DAKE handshake, double ratchet, SMP, ring signatures, wire format, IRC client, terminal UI. Grep works. Ctrl+F works.

The three C extensions are separate because Python can't inline C. They handle constant-time arithmetic, ML-KEM-1024, ML-DSA-87, and Ed448 scalar multiplication. Everything else is in the one file.

| File | Lines | What it does |
|------|-------|-------------|
| `otrv4+.py` | ~12,000 | Everything |
| `otr4_crypto_ext.c` | 1,866 | BN arithmetic, ML-KEM (NTT), ring sigs, mlock |
| `otr4_ed448_ct.c` | 867 | Constant-time Ed448 scalar multiply (Montgomery ladder) |
| `otr4_mldsa_ext.c` | 321 | ML-DSA-87 via OpenSSL EVP |
| `Rust/src/*.rs` | ~800 | Double ratchet + SMP vault with zeroize-on-drop |

---

## Memory security

This is the part I spent the most time on. Crypto libraries are fine at encrypting — the hard part is making sure secrets actually disappear from memory when you're done with them.

**Rust ratchet** — all chain keys, root keys, brace keys, message keys, and skipped keys are zeroed on drop. Rust's `Zeroize` trait guarantees this. The Python `DoubleRatchet` class has been removed — there is no fallback path that could leak secrets via the GC.

**Rust SMP vault** — all SMP secret exponents are stored in the Rust vault between protocol steps and deterministically zeroed on completion. They only exist as Python ints briefly during each computation step.

**C extensions** — everything goes through `OPENSSL_cleanse()` after use. The Montgomery ladder in `otr4_ed448_ct.c` uses XOR-based cswap so secret scalar bits never hit a branch predictor. `SecureMemory.write()` uses `ctypes.memset`.

**Python** — X448 private keys live in OpenSSL's C heap (the cryptography library holds a pointer, not the bytes). DAKE DH shared secrets pass through Python briefly before entering the KDF (microseconds).

**On shutdown** — `/quit` triggers `Zeroize::drop()` on all Rust ratchets and SMP vaults, `OPENSSL_cleanse` on C extension secrets, clears the screen, and wipes `~/.otrv4plus/`. No trace left.

---

## Security audit (v10.4)

Seven vulnerabilities identified and fixed:

1. **Unsafe byte wiping** — `_secure_wipe_bytes` used a dangerous ctypes-into-immutable-bytes hack. Replaced with safe stub; all call sites now use `bytearray` + `_ossl.cleanse()`.
2. **Ratchet key swap** — `RustBackedDoubleRatchet` passed the wrong `is_initiator` flag to Rust, causing AES-GCM auth failure on first message for responders.
3. **SMP cross-session brute-force** — `start_smp()` didn't always bind the secret to the session. Now always includes session ID + both fingerprints.
4. **Weak SMP secrets** — Raised from soft 6-char warning to hard 8-char minimum across all entry points.
5. **Expired session encryption** — `encrypt_with_tlvs()` didn't check session age. Now raises error after 24-hour max.
6. **ML-DSA truncation** — DAKE1/2/3 now validates exact byte lengths for ML-DSA-87 public keys and signatures.
7. **Fragment memory exhaustion** — Hard ceiling of 1,000 fragments regardless of per-sender limit.

---

## Wire format

```
DAKE1: 0x35 ‖ X448_eph(56) ‖ MLKEM_ek(1568) ‖ profile(var) [‖ MLDSA_pub(2592)]
DAKE2: 0x36 ‖ X448_eph(56) ‖ MLKEM_ct(1568) ‖ profile(var) [‖ MLDSA_pub(2592)] ‖ MAC(64)
DAKE3: 0x37 ‖ ring_sigma(228) ‖ flag(1) [‖ MLDSA_sig(4627)]
DATA:  0x00 ‖ 0x04 ‖ 0x03 ‖ header(64) ‖ nonce(12) ‖ ct(var) ‖ tag(16)
```

ML-DSA fields use a flag byte — `0x01` present, `0x00` absent. Peers without ML-DSA fall back to classical ring sigs only. Messages are fragmented at 300 bytes for IRC line limits using OTR §4.7 wire format.

---

## Signal comparison

Signal's PQXDH adds ML-KEM to the handshake but their own spec says "Authentication in PQXDH is not quantum-secure." They also only do PQC at the initial handshake — after that, the ratchet is classical.

This client does ML-KEM at the handshake AND rotates fresh KEM material every DH ratchet epoch. Plus ML-DSA-87 for post-quantum authentication. The tradeoff is no async support (both parties need to be online, it's IRC) and no PQ deniability (that's an open research problem — nobody has it).

---

## Commands

**IRC:** `/join` `/part` `/nick` `/msg` `/names` `/topic` `/list` `/whois` `/invite` `/kick` `/mode` `/notice` `/away` `/back` `/raw` `/reconnect` `/quit`

**OTR:** `/otr nick` `/endotr nick` `/fingerprint` `/trust nick` `/smp secret` `/smp start` `/smp abort` `/smp status` `/secure`

**UI:** `/switch` `/tabs` `/tab-next` `/tab-prev` `/tab-close` `/clear` `/ignore` `/unignore` `/ignored` `/status` `/debug` `/version`

---

## Tests

### Repository layout

All test files live in `tests/`. The `.so` extensions and the main module live in the project root. The correct way to run everything is from the project root with `PYTHONPATH=.` so Python can see both.

```
OTRv4Plus/
├── otrv4+.py               ← main module
├── otrv4_.py               ← symlink → otrv4+.py  (needed by tests)
├── otrv4plus.py            ← symlink → otrv4+.py  (needed by tests)
├── otrv4_testlib.py        ← shared test helper
├── otr4_crypto_ext.so      ← built C extension
├── otr4_ed448_ct.so        ← built C extension
├── otr4_mldsa_ext.so       ← built C extension
├── otrv4_core.so           ← built Rust extension
├── fuzz_harnesses.py       ← fuzz entry point
├── Rust/
└── tests/
    ├── test_attacks.py
    ├── test_differential.py
    ├── test_final_boss.py
    ├── test_harness_audit.py
    ├── test_master_protocol_verifier.py
    ├── test_mldsa_smoke.py
    ├── test_mlkem_kat.py
    ├── test_otr.py
    ├── test_otrv4_integration.py
    ├── test_property.py
    ├── test_ratchet_torture.py
    ├── test_ring_android.py
    ├── test_rust_security.py
    ├── test_rust_security_adversarial.py
    └── test_v10_4_security_fixes.py
```

### One-time setup after cloning

`otrv4+.py` can't be imported directly — `+` is illegal in Python module names. Three symlinks are needed:

```bash
# From the project root
ln -sf otrv4+.py otrv4_.py           # for: import otrv4_
ln -sf otrv4+.py otrv4plus.py        # for: import otrv4plus
ln -sf ../otrv4+.py tests/otrv4+.py  # for: otrv4_testlib's importlib path load
```

All three should be committed to the repo so a fresh clone works without this step.

### Rust tests

```bash
cd Rust && cargo test --release && cd ..
```

Expected: `14 passed`.

### Python tests

```bash
pip install pytest hypothesis

# Run all tests from the project root
PYTHONPATH=. pytest tests/ -v
```

To run a single file:

```bash
PYTHONPATH=. pytest tests/test_property.py -v
```

To run the fuzz harnesses:

```bash
PYTHONPATH=. python fuzz_harnesses.py
```

### What each file tests

| File | What it covers |
|------|----------------|
| `test_differential.py` | TLV encoding, KDF vectors, ratchet differential, wire format regression |
| `test_property.py` | AES-GCM, KDF, MAC, TLV, ML-KEM, ring sigs, double ratchet, network detection |
| `test_harness_audit.py` | Full DAKE + SMP protocol flow |
| `test_master_protocol_verifier.py` | End-to-end protocol state machine |
| `test_final_boss.py` | Composite integration (depends on master verifier) |
| `test_otrv4_integration.py` | DAKE handshake, ratchet, fragmentation |
| `test_ratchet_torture.py` | 100k-message ratchet, replay, out-of-order delivery |
| `test_rust_security.py` | Rust vault zeroization, AES-GCM key storage |
| `test_rust_security_adversarial.py` | Adversarial Rust ratchet scenarios |
| `test_mlkem_kat.py` | ML-KEM-1024 known-answer test vectors |
| `test_mldsa_smoke.py` | ML-DSA-87 sign/verify smoke test |
| `test_ring_android.py` | Ring signature correctness on Android/aarch64 |
| `test_otr.py` | C extension import and smoke test |
| `test_v10_4_security_fixes.py` | v10.4 regression suite (7 security fixes) |
| `test_attacks.py` | Replay, forgery, and protocol attack resistance |
| `fuzz_harnesses.py` | Wire format and fragment fuzzing |

313 tests total (299 Python + 14 Rust). Covers: double ratchet across 100k messages, replay resistance, forward secrecy, post-compromise recovery, out-of-order delivery, ML-KEM roundtrips, ML-DSA hybrid verification, ring signature non-malleability, SMP zero-knowledge proofs, SMP full protocol flow with vault integration, constant-time comparison verification, AES-GCM key storage round-trips, Rust vault zeroization, DAKE state machine transitions, wire format fuzzing, v10.4 regression suite, and property-based protocol verification.

---

## Known issues

The honest list:

- SMP exponents briefly exist as Python ints during each computation step (microseconds) before being stored in the Rust vault
- DAKE DH shared secrets pass through Python briefly before entering the KDF (microseconds — private keys stay in OpenSSL's C heap)
- Fragment count reveals message type to a local observer (DAKE = 20–25 fragments in a burst)
- The nick pool is ~11,000 names — reduces but doesn't eliminate cross-session correlation
- Clearnet exposes your IP in WHOIS until cloaking kicks in (use I2P or Tor)
- PQ deniability doesn't exist as a primitive anywhere — when it does, the flag-byte mechanism supports upgrading

None of these are cryptographic breaks. The first two are memory hygiene gaps measured in microseconds. The rest are metadata/network issues that apply to every IRC client.

---

## Development

This project was built with AI-assisted development (Claude). All cryptographic implementations have been verified through 294 automated tests, live DAKE and SMP exchanges between Termux instances over I2P, a security audit that identified and fixed vulnerabilities, and manual review of constant-time properties in the C extensions. The Rust ratchet core contains zero unsafe blocks.

---

## WeeChat plugin

Same crypto, different frontend. Drop the files into `~/.local/share/weechat/python/` and `/python load weechat_otrv4plus.py` inside WeeChat.

---

## License

GPL-3.0. See LICENSE. Commercial licensing available — see COMMERCIAL-LICENSE.md.

---

*"Arguing that you don't care about the right to privacy because you have nothing to hide is no different than saying you don't care about free speech because you have nothing to say."* — Edward Snowden
