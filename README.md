<p align="center">
  <img src="icon.png" width="200" alt="OTRv4+">
</p>

# Off The Record v4 + PQC

Post-quantum OTR for IRC. The whole thing runs on a phone over I2P.

I built this because nobody else was going to. The OTRv4 spec has been sitting there for years with zero complete implementations, and meanwhile every messaging protocol is scrambling to bolt on post-quantum crypto before Q-day arrives. So I did both — implemented the full OTRv4 spec and added PQC to every layer while I was at it.

It defaults to `irc.postman.i2p`. Point it at any server and it figures out the network — `.i2p` goes through I2P, `.onion` through Tor, everything else gets TLS. No config files, no setup wizards.

---

## Get it running

You need Python 3.9+, OpenSSL 3.5+ (for ML-KEM and ML-DSA), and a C compiler.

**On Termux (Android):**
```bash
pkg install python openssl clang build-essential git
pip install cryptography pysocks

git clone https://github.com/muc111/OTRv4Plus.git
cd OTRv4Plus
python setup_otr4.py build_ext --inplace
bash build_ed448.sh
gcc -shared -fPIC -O2 -o otr4_mldsa_ext.so otr4_mldsa_ext.c \
    $(python3-config --includes) $(python3-config --ldflags --embed) -lcrypto

PYTHONMALLOC=malloc python otrv4+.py
```

That connects to `irc.postman.i2p:6667` through I2P's SOCKS5 proxy on port 4447. You need i2pd or the Java I2P app running.

**On Debian/Ubuntu** (23.04+ blocks pip, so use a venv):
```bash
sudo apt install python3 python3-dev python3-venv libssl-dev build-essential git
python3 -m venv ~/otr-env
source ~/otr-env/bin/activate
pip install cryptography pysocks

git clone https://github.com/muc111/OTRv4Plus.git
cd OTRv4Plus
python setup_otr4.py build_ext --inplace
bash build_ed448.sh
gcc -shared -fPIC -O2 -o otr4_mldsa_ext.so otr4_mldsa_ext.c \
    $(python3-config --includes) $(python3-config --ldflags --embed) -lcrypto

PYTHONMALLOC=malloc python otrv4+.py -s irc.libera.chat:6697
```

Always `source ~/otr-env/bin/activate` before running.

**On Arch:**
```bash
sudo pacman -S python python-pip openssl base-devel git
python3 -m venv ~/otr-env && source ~/otr-env/bin/activate
pip install cryptography pysocks
```

**On macOS:**
```bash
brew install python openssl@3 git
python3 -m venv ~/otr-env && source ~/otr-env/bin/activate
LDFLAGS="-L$(brew --prefix openssl@3)/lib" CFLAGS="-I$(brew --prefix openssl@3)/include" \
pip install cryptography pysocks
```

Then clone, build the C extensions, and run. Same steps as above.

### Rust ratchet (optional but recommended)

The double ratchet can run in Rust instead of Python. Same protocol, same wire format, but Rust guarantees all secret keys are zeroed on drop — Python's garbage collector can't promise that.

```bash
cd Rust
cargo test --release          # 11 tests, 0.01s
maturin build --release
pip install target/wheels/otrv4_core-*.whl
cd ..
```

On Termux add `export ANDROID_API_LEVEL=24` before `maturin build`. The startup banner tells you which backend is active:

```
Ratchet : 🦀 Rust (zeroize-on-drop)
```

If you skip this, the client uses Python with C extension crypto. Everything still works.

### I2P setup

The client expects I2P's SOCKS5 proxy on `127.0.0.1:4447`.

Termux: `pkg install i2pd && i2pd --daemon`
Debian: `sudo apt install i2pd` (starts automatically)
Arch: `sudo pacman -S i2pd && sudo systemctl enable --now i2pd`
macOS: `brew install i2pd && brew services start i2pd`

Tor works too — SOCKS5 on port 9050. The client picks it up automatically from `.onion` hostnames.

### SAM vs SOCKS5

When connecting to I2P, the client tries the SAM bridge first and falls back to SOCKS5 if SAM isn't available.

SAM v3.1 is used — just the basic stream connection features that both i2pd and Java I2P have supported for years. No dependency on newer SAM versions.

Why this matters: with SOCKS5, every connection you make shares the same local I2P destination. The IRC server, and anyone watching it, sees the same .b32.i2p address every time you connect. If you disconnect and reconnect with a new nick, you're still the same destination. Cross-session tracking is trivial.

SAM creates a fresh transient destination for each session. Every time you launch the client, you get a new I2P identity. There's nothing to correlate between sessions. This is how Tor does it one circuit per target and it's the right way to do it on I2P too.

The startup banner tells you which one is active:
I2P     : SAM bridge (unique destination per session)
or if SAM isn't running:
I2P     : SOCKS5 (shared destination SAM not available)
To enable SAM on i2pd, add this to your `i2pd.conf` (usually `~/.i2pd/i2pd.conf` or `/etc/i2pd/i2pd.conf`):

```ini
[sam]
enabled = true
address = 127.0.0.1
port = 7656
Then restart i2pd. On Termux: pkill i2pd && i2pd --daemon. On systemd: sudo systemctl restart i2pd.
Java I2P has SAM enabled by default on port 7656. No config change needed.
Tor connections still use SOCKS5 — Tor already creates separate circuits per destination, so the shared-destination problem doesn't apply. 

Clearnet connections go direct with TLS.
```

## Check your OPENSSL

openssl version

Needs to 3.5.0 or later. ML-KEM-1024 and ML-DSA-87 don't exist in older versions and the C extensions won't compile without them. Termux ships 3.5+ already.

---

## What's actually in here

The crypto isn't one trick. Every layer got upgraded:

**Key exchange** — Triple X448 Diffie-Hellman plus ML-KEM-1024 (FIPS 203). The KEM shared secret mixes into the root key, so even if X448 falls to a quantum computer, the session keys are still safe. This happens during a three-message DAKE handshake.

**Authentication** — Ed448 ring signatures give you classical deniability (neither side can prove the other was there). On top of that, ML-DSA-87 (FIPS 204) gives post-quantum authentication — a quantum adversary can't forge your identity. Both run in DAKE3.

**Ratchet** — Standard double ratchet, but with a brace key that rotates via fresh ML-KEM encapsulation every DH ratchet epoch. Most PQC messaging protocols only do KEM at the handshake. This one self-heals — if an attacker compromises a session, the next DH ratchet restores PQC protection with fresh KEM material.

**Per-message** — AES-256-GCM, SHAKE-256 KDFs, random 12-byte nonces. Nothing exotic at the symmetric level, just stuff that Grover's algorithm can't halve faster than 128-bit security.

**SMP** — Socialist Millionaires' Protocol for identity verification. Both sides type the same passphrase, the protocol proves they match without revealing it. Uses 3072-bit DH (RFC 3526 Group 15) with zero-knowledge proofs. The passphrase gets stretched through 10,000 rounds of SHAKE-256 so short secrets aren't immediately brute-forceable.

No liboqs. All PQC goes through OpenSSL 3.5+ native providers.

---

## How it looks

```
OTRv4 IRC Client
==================================================
Version : OTRv4+ 10.3
Server  : irc.postman.i2p:6667
Network : 🧅 I2P (plaintext)
Auth    : anonymous
Channel : #otr
Debug   : OFF
Ratchet : 🦀 Rust (zeroize-on-drop)
==================================================
```

Once connected, `/join #otr` and `/otr somenick` to start an encrypted session. The indicator shows security level:

🔴 plaintext — 🟡 encrypted, unverified — 🟢 fingerprint trusted — 🔵 SMP verified

Session established looks like:
```
🔒 OTR session with Bob established — Ed448/X448, AES-256-GCM (initiator) [🦀 Rust]
```

On `/quit`:
```
🦀 2 Rust ratchet(s) zeroized (deterministic memory wipe)
OTRv4+ terminated — 🦀 Rust memory zeroized — screen cleared
```

---

## The network thing

The client inspects the server hostname and does the right thing:

- `*.i2p` → routes through I2P SOCKS5 on 127.0.0.1:4447
- `*.onion` → routes through Tor SOCKS5 on 127.0.0.1:9050
- anything else → direct connection with TLS

No flags. `irc.postman.i2p` just works if i2pd is running. `irc.libera.chat:6697` just works over TLS. You can also force things with `-s server:port --no-tls` or `--sasl -n YourNick`.

---

## Why it's one file

~12,000 lines in a single Python file. I know what you're thinking.

Here's the thing — when you're auditing a crypto protocol, you want to see the whole thing in one place. Not spread across 40 modules with import chains and circular dependencies. You open `otrv4+.py` and the entire protocol is right there: DAKE handshake, double ratchet, SMP, ring signatures, wire format, IRC client, terminal UI. Grep works. Ctrl+F works.

The three C extensions are separate because Python can't inline C. They handle constant-time arithmetic, ML-KEM-1024, ML-DSA-87, and Ed448 scalar multiplication. Everything else is in the one file.

| File | Lines | What it does |
|---|---|---|
| `otrv4+.py` | ~12,000 | Everything |
| `otr4_crypto_ext.c` | 1,866 | BN arithmetic, ML-KEM (NTT), ring sigs, mlock |
| `otr4_ed448_ct.c` | 867 | Constant-time Ed448 scalar multiply (Montgomery ladder) |
| `otr4_mldsa_ext.c` | 321 | ML-DSA-87 via OpenSSL EVP |
| `Rust/src/*.rs` | ~800 | Double ratchet with zeroize-on-drop |

---

## Memory security

This is the part I spent the most time on. Crypto libraries are fine at encrypting — the hard part is making sure secrets actually disappear from memory when you're done with them.

**Rust ratchet** — all chain keys, root keys, brace keys, message keys, and skipped keys are zeroed on drop. Rust's `Zeroize` trait guarantees this. No "the GC will probably get to it eventually."

**C extensions** — everything goes through `OPENSSL_cleanse()` after use. The Montgomery ladder in `otr4_ed448_ct.c` uses XOR-based `cswap` so secret scalar bits never hit a branch predictor.

**Python** — X448 private keys live in OpenSSL's C heap (the `cryptography` library holds a pointer, not the bytes). SMP exponents are stored in the Rust vault between protocol steps and deterministically zeroed on completion — they only exist as Python ints briefly during each computation step.

**On shutdown** — `/quit` triggers `Zeroize::drop()` on all Rust ratchets, `OPENSSL_cleanse` on C extension secrets, clears the screen, and wipes `~/.otrv4plus/`. No trace left.

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

**IRC**: `/join` `/part` `/nick` `/msg` `/names` `/topic` `/list` `/whois` `/invite` `/kick` `/mode` `/notice` `/away` `/back` `/raw` `/reconnect` `/quit`

**OTR**: `/otr nick` `/endotr nick` `/fingerprint` `/trust nick` `/smp secret` `/smp start` `/smp abort` `/smp status` `/secure`

**UI**: `/switch` `/tabs` `/tab-next` `/tab-prev` `/tab-close` `/clear` `/ignore` `/unignore` `/ignored` `/status` `/debug` `/version`

---

## Tests

```bash
pytest -v test_*.py fuzz_harnesses.py -k "not 300k"
```

224 tests. Double ratchet across 100k messages, state fork attacks, replay resistance, forward secrecy, post-compromise recovery, out-of-order delivery, ML-KEM roundtrips, ML-DSA hybrid verification, ring signature non-malleability, SMP zero-knowledge proofs, DAKE state machine transitions, wire format fuzzing.

---

## Known issues

The honest list:

- SMP exponents are stored in the Rust vault between protocol steps (deterministic zeroize) but briefly exist as Python ints during computation within each step
- DAKE DH shared secrets pass through Python briefly before entering the KDF (microseconds — private keys stay in OpenSSL's C heap)
- Fragment count reveals message type to a local observer (DAKE = 20-25 fragments in a burst)
- The nick pool is ~11,000 names — reduces but doesn't eliminate cross-session correlation
- Clearnet exposes your IP in WHOIS until cloaking kicks in (use I2P or Tor)
- PQ deniability doesn't exist as a primitive anywhere — when it does, the flag-byte mechanism supports upgrading

None of these are cryptographic breaks. The first two are memory hygiene gaps. The rest are metadata/network issues that apply to every IRC client.

---

## Development

This project was built with AI-assisted development (Claude). All cryptographic implementations have been verified through 224 automated tests, live DAKE and SMP exchanges between Termux instances over I2P, and manual review of constant-time properties in the C extensions. The Rust ratchet core contains zero `unsafe` blocks.

---

## WeeChat plugin

Same crypto, different frontend. Drop the files into `~/.local/share/weechat/python/` and `/python load weechat_otrv4plus.py` inside WeeChat.

---

## License

GPL-3.0. See [LICENSE](LICENSE). Commercial licensing available — see [COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md).

---

> *"Arguing that you don't care about the right to privacy because you have nothing to hide is no different than saying you don't care about free speech because you have nothing to say."* — Edward Snowden
