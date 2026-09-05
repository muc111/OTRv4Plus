# Monero multisig escrow — audit and integration plan

**Status: the courier recommendation in §2.2 was approved and shipped in
v10.20.0** — `otrv4plus_trade.py`, INV-25 and INV-26, no Rust changes and no
new dependencies. See [TRADE.md](TRADE.md) for the runbook and the wire
protocol. The rest of this document is the audit that led there and is kept as
the record of why.

Two decisions were settled at approval:

* **No arbitration service.** The maintainer will not act as arbitrator and
  ships no arbitrator key. §2.4.3 asked the question; the answer is that users
  bring their own third party. 2-of-3 works — the third party runs a trade
  session like anyone else — but this project holds none of the three keys.
* **The Rust-core path stays closed for now.** Phase 4 below (reassess
  `monero-oxide` after FCMP++) is the only route back to it.

Audited at `v10.19.0` / `otrv4_core 0.10.28`, commit `f89b328`, 2026-09-05.

---

## 0. Executive summary

The communication side of this is easy and the codebase is genuinely well suited
to it. The OTRv4+ channel already carries a control protocol with arbitrary
binary payloads (`?OTRv4-FILE:`), already has an extensible TLV framework whose
spec mandates that unknown types be ignored, and already has a tested
SMP-verification predicate that the voice path gates on. A trade-signalling
layer is a straightforward, low-risk addition that reuses all three.

The Monero side is where the brief's assumptions break, in four places:

1. **`monero-serai` is not a live crate.** Latest is `0.1.4-alpha`, published
   May 2023, and **every version is yanked**. It was superseded by the
   `monero-oxide` family — `monero-wallet 0.2.0`, published 2026-07-31. The
   brief's table rates monero-serai as active and audited; on crates.io it is
   neither, because it is not there.

2. **`monero-oxide`'s multisig is FROST, not Monero's multisig.** From
   `monero-oxide/wallet/Cargo.toml`:
   `multisig = ["std", "transcript", "frost", "monero-clsag/multisig"]`, with
   `frost = { package = "modular-frost", version = "0.11", features = ["ed25519"] }`.
   A FROST-CLSAG wallet is not a native Monero multisig wallet. `monero-wallet-cli`
   cannot create one, join one, or spend from one. **This is incompatible with
   requirement B2.2 — "users run their own Monero wallets (CLI, GUI, mobile)."**
   You can have the Rust library or you can have wallet interoperability, not both.

3. **Native Monero multisig is still experimental and off by default.** It must
   be enabled per-wallet with `set enable-multisig-experimental 1` in
   `monero-wallet-cli`, and [that flag is not settable over
   RPC](https://github.com/monero-project/monero/issues/9488) — which is a real
   obstacle for any automated flow. It also carries a
   [2021 disclosure](https://www.getmonero.org/2021/12/06/vulnerability-multisig.html)
   covering both wallet creation and transaction signing, where the failure mode
   is *funds stolen by one of the signing parties* and the view secret key can be
   recovered by an eavesdropper on the setup exchange.

4. **CLSAG is being removed.** FCMP++ replaces ring signatures outright. As of
   May 2026 the FCMP++ stressnet does not support multisig, hardware wallets or
   watch-only wallets, and the plan of record is that CLSAG multisig is either
   reimplemented in C++ or delegated to Rust. Anything built on CLSAG multisig
   today has an expiry date that nobody has published, and multisig is
   specifically one of the features not yet ported.

**Recommendation: build the signalling layer, do not build the Monero
cryptography.** Details and the argument in §2.4. The short version is that the
strongest possible reading of your own invariant "private keys never cross the
PyO3 boundary" is *private keys never enter this process at all* — which is what
you get by carrying opaque blobs between two wallets the users already run, and
is roughly what Haveno does with `monero-wallet-rpc`.

---

# Part 1 — Audit

## 1.1 Cryptographic inventory (A1)

18 modules, 9,601 lines. The cryptographic ones:

| Module | Lines | Primitives |
|---|---:|---|
| `smp.rs` | 2415 | MODP-3072 Schnorr ZKP, constant-time `modpow` via `crypto-bigint` `DynResidue`, Argon2id stretch, ML-KEM-1024 + ML-DSA-87 binding |
| `ratchet.rs` | 1425 | Double ratchet, skipped-key cache, MKmac revelation and cross-check |
| `dake.rs` | 1314 | X448 + ML-KEM-1024 + ML-DSA-87 interactive DAKE |
| `voice.rs` | 937 | HKDF-SHA512 key schedule, AES-256-GCM media, epoch roots |
| `filetransfer.rs` | 674 | Per-transfer FileKey sealing, chunk tags, dual hashing |
| `key_handles.rs` | 527 | Ed448 / X448 opaque long-term key handles |
| `ring_sig.rs` | 499 | Ed448 ring signature (deniability), 228-byte sigs |
| `identity.rs` | 285 | Sealed identity records, AES-256-GCM under a DEK |
| `smp_vault.rs` | 248 | Write-only passphrase vault |
| `mlkem.rs` / `mldsa.rs` / `aead.rs` / `kdf.rs` / `header.rs` | 637 | FIPS 203 / FIPS 204 / AES-256-GCM / SHAKE-256 |

**Curve families present: Ed448 and X448 only** (`ed448-goldilocks-plus 0.16`,
`x448 0.6`). There is **no Ed25519 and no curve25519-dalek anywhere in the tree**
— I checked `Cargo.lock` directly. Monero is Ed25519. Adding it is not extending
an existing primitive; it is a second curve family with its own scalar
arithmetic, its own constant-time properties and its own audit surface.

**Zeroization mechanism** (`secure_mem.rs`, 91 lines) is small and uniform:

```rust
#[derive(Zeroize, ZeroizeOnDrop)] pub struct SecretBytes<const N: usize>([u8; N]);
#[derive(Zeroize, ZeroizeOnDrop)] pub struct SecretVec(Vec<u8>);
#[derive(ZeroizeOnDrop)] pub struct DakeSessionKeys { … }
#[derive(ZeroizeOnDrop)] pub struct EphemeralX448 { … }
#[derive(ZeroizeOnDrop)] pub struct Ed448IdentityKey { … }
```

Anything new would follow the same pattern, and `monero-wallet` does depend on
`zeroize` with `zeroize_derive`, so the idiom carries over cleanly. That part
would not be the problem.

## 1.2 The PyO3 boundary (A4)

This was fully mapped at v10.19.0 for GHSA-36hh-v3qg-5jq4 and the finding stands:

**Python → Rust accepts exactly five shapes.** `&[u8]`, `&str`, `u32`/`u64`,
`bool`, `&Bound<PyByteArray>` / `&Bound<PyAny>`, plus opaque pyclass handles.
No lists, no tuples, no dicts as input, no iterators, no callbacks. 93 functions
across `#[pyfunction]` and `#[pymethods]` blocks, counting getters and the
helpers nested inside them.

**Rust → Python returns** `PyBytes` (public material, ciphertext, hashes,
envelopes), `String`, `Vec<String>` (vault entry *names*, never values),
integers, and opaque handles (`Ed448KeyHandle`, `X448KeyHandle`,
`RustVoiceRoot`, `RustVoiceCipher`, `RustSMPVault`, `DakeOutput`).

**Secret material still crossing**, per INV-08: ML-KEM/ML-DSA private keys as
`PyBytes` from the keygen functions, the identity DEK and device seeds read from
disk as `bytes`, and the typed SMP passphrase and account password as Python
`str` before anything can touch them. Everything derived from those is
Rust-owned. The legacy DAKE key getters are compiled out by default
(`legacy-dake-keys` off, `build.rs` refuses without an explicit env var).

`tests/test_pyo3_boundary.py` (44 tests) drives the *installed* module with
hostile input and asserts every rejection returns to Python as an exception.
That matters for this project specifically: **`panic = "abort"` in the release
profile**, so a Rust panic is not catchable — it takes the client down
mid-session. A panic inside a Monero library during a trade would abort the
process with funds locked in a half-built multisig. Any new Rust crate is
subject to that, and third-party crates panic more freely than this one does.

## 1.3 I2P / SAM (A2)

`I2PSAMConnection`, `otrv4+.py:1027-1300`. SAM v3.1, default port 7656.

```
SESSION CREATE STYLE=STREAM ID=otrv4plus_<8 hex> DESTINATION=TRANSIENT SIGNATURE_TYPE=7
STREAM CONNECT ID=<id> DESTINATION=<b32> SILENT=false
```

Three findings that bear on escrow:

- **`DESTINATION=TRANSIENT` — a fresh destination every session.** The class
  docstring is explicit that this is the point: with SOCKS5 all sessions share
  one local destination and an observer at the IRC server can correlate
  reconnects. **This is in direct tension with escrow.** Trading wants a durable
  counterparty identity — reputation, dispute history, "the same seller as last
  week". Unlinkability per session is the opposite property. The resolution is
  that trade identity must be **cryptographic, not transport-level**: bound to
  the pinned OTRv4+ fingerprint and SMP verification, never to an I2P
  destination. That is a design constraint, not a blocker, but getting it wrong
  would silently undo the transport's main privacy property.

- **Tunnel length is not pinned.** `SESSION CREATE` sets no
  `inbound.length` / `outbound.length`, so the client inherits whatever i2pd is
  configured for (default 3 hops each way, 6 end-to-end). Already flagged in an
  earlier session; it matters more for a long-lived trade than for chat.

- **90-second SAM deadline**, and a documented cold-tunnel latency of 60-90s.
  Multi-round protocols over this are slow, and the trade protocol has to be
  designed asynchronously from the start. See §1.5.

## 1.4 Message format and extensibility (A3)

**The TLV framework is the clean extension point.** `OTRv4TLV`,
`otrv4+.py:1444`. Wire format `uint16 type | uint16 length | value`, big-endian.
The docstring states the rule that makes this safe:

> Unknown TLV types MUST be silently ignored (forward compatibility).

Allocated types run `0x0000`–`0x0009` (PADDING, DISCONNECTED, SMP 1-4 + ABORT +
1Q, EXTRA_SYMMETRIC_KEY). Everything from `0x0010` up is free. Per-TLV value cap
is 65535 bytes.

**The control-channel precedent already exists and is proven.** File transfer
does not use TLVs; it rides the encrypted channel as prefixed text:

```
FILE_PREFIX = "?OTRv4-FILE:"
verbs: OFFER | ACCEPT | DECLINE | DATA | DONE | CANCEL
payloads: base64, pipe-delimited fields
dispatch: FileTransferManager.handle_control(peer, body) -> bool
transport: OtrChunkTransport.send_control / send_chunk
```

This is the model a trade layer should copy verbatim — `?OTRv4-TRADE:` with its
own verb set and its own manager — because it is already carrying multi-megabyte
binary payloads across two handsets in production, and because it keeps trade
code out of the ratchet entirely.

**Throughput, measured from the constants, not estimated:**

| Constant | Value | Where |
|---|---|---|
| `WIRE_CHUNK_PLAIN` | 16 KiB | `otrv4plus_filetransfer.py:75` |
| `_STANZAS_PER_CHUNK_CEILING` | 8 | `:217` |
| `_FILE_FRAGMENTS_PER_SEC` | 8.0 | `otrv4plus_xmpp.py:624` |
| `_RATE_MAX` / `_RATE_MAX_BULK` | 20 / 120 per 5 s | `:600, :617` |
| IRC raw line cap | 510 bytes | `otrv4+.py:11327` |
| Fragment reassembly cap | 1000 absolute | `:9783` |

So roughly **16 KiB/s sustained on the XMPP path**, and far less on IRC where
every line is capped at 510 bytes. Monero multisig `kex` blobs and unsigned
transaction sets are kilobytes to tens of kilobytes; they fit, but a full trade
is minutes of channel time, not seconds.

## 1.5 SMP verification as the trade gate (A3)

The predicate exists and is already load-bearing. `is_smp_verified(peer)` at
`otrv4+.py:8535`, plus `get_smp_status(peer)["verified"]` and the session-level
check. `otrv4plus_voice.py:6735` reads all three and treats verification as true
if *any* says so — with a docstring explaining that a single reading could report
an actively failed session as verified.

INV-12 already states that a failure to determine SMP state does not authorise a
call. **A trade gate should be the same predicate with the same fail-closed
posture**, and reusing it costs nothing. Note the security levels:
`PLAINTEXT(0) … ENCRYPTED … FINGERPRINT … SMP_VERIFIED(3)`, rendered 🔵.

## 1.6 Dependencies (A5)

134 crates in `Cargo.lock`. **Zero Monero-related code anywhere in the
repository** — I grepped every `.py`, `.rs` and `.toml` for
`monero|xmr|multisig|escrow|wallet|payment|bitcoin` and got nothing. This is a
greenfield addition.

Direct dependencies are 23, all mainstream, and the tree carries no known
advisories after the v10.19.0 PyO3 remediation. `cargo audit` against the live
RustSec database is the authoritative check and is documented in DEVELOPMENT.md.

### What adding `monero-wallet` would actually cost

| | Now | With `monero-wallet 0.2.0 --features multisig` |
|---|---|---|
| Curve families | Ed448, X448 | **+ Ed25519 (curve25519-dalek 4)** |
| Threshold schemes | none | **+ modular-frost 0.11, flexible-transcript 0.3** |
| Rust MSRV | 1.85 | **1.89** (from `monero-wallet`'s own manifest) |
| Crates in lock | 134 | materially more; `monero-oxide` alone is a family of ~6 |
| Consensus coupling | none | the transaction format, hard-fork-versioned |

That last row is the one that does not shrink with care. Chat and voice have no
consensus deadline. A Monero transaction builder does: it must track the network,
and it breaks at hard forks. This project's entire pitch is a small, auditable
Rust core; this would be the first dependency that is neither small nor optional
nor stationary.

---

# Part 2 — Integration plan

## 2.1 The library landscape, corrected

Evidence from crates.io and the upstream manifests, fetched 2026-09-05.

| Crate | Newest | Published | Status | Multisig |
|---|---|---|---|---|
| `monero-serai` | 0.1.4-alpha | 2023-05-27 | **all versions yanked** | (FROST, historical) |
| `monero-serai-mirror` | 0.1.5-alpha | 2024-09-22 | third-party republish by `sneurlax` | inherited |
| **`monero-wallet`** | **0.2.0** | **2026-07-31** | live; `monero-oxide` org | **FROST via `modular-frost 0.11`** |
| `monero-oxide` | 0.1.0 | 2026-07-31 | live; blockchain protocol | n/a (no wallet) |
| `monero` | 0.22.0 | 2026-07-13 | live, 552k downloads | serialization only, no multisig |
| `monero-rpc` | 0.5.1 | 2026-07-18 | live, 60k downloads | **RPC client — the practical path** |
| `monero-rs`, `monero-ct` | — | — | **do not exist on crates.io** | — |

The brief's table has four of six rows wrong. `monero-serai` is not active,
`monero-rs` and `monero-ct` are not crates, and `monero`/`monero-rpc` do not
implement multisig cryptography — `monero-rpc` *talks to* a wallet that does.

`monero-oxide` maintains an `audits/` directory and a serious disclosure policy
(three-month fallback timeline, coordinated multi-project disclosure). It is a
credible project. But "audited" is a claim about specific documents covering
specific versions, and it is not a claim I can make on its behalf from the
outside — if you go down this route, read what is actually in `audits/` and check
which commit it covers.

### The interoperability problem, stated plainly

FROST threshold Ed25519 and Monero's native `MSk`/`exchange_multisig_keys`
scheme are different protocols that produce different wallets.

- A FROST group signing key produces a valid Monero address and valid CLSAG
  signatures. The chain cannot tell.
- But **`monero-wallet-cli` has no way to participate.** There is no import path,
  no `make_multisig` equivalent, no wallet file format in common.
- Therefore **every participant, including the arbitrator, must run your
  software.** Requirement B2.2 as written cannot be satisfied on this path.

That is not a defect in `monero-oxide` — FROST is genuinely better engineering
than Monero's multisig, and materially faster. It is a statement about what the
requirement costs.

### Native multisig, if you want wallet interoperability

Four coordination rounds for 2-of-3, from the wallet RPC:

```
1. each party:  prepare_multisig                 -> "Multisig…" init blob
2. each party:  make_multisig(threshold=2, [other init blobs])
3. each party:  exchange_multisig_keys([blobs])  ┐  N - M + 1 = 3 - 2 + 1
4. each party:  exchange_multisig_keys([blobs])  ┘  = 2 rounds
   -> multisig address
```

Then per spend: `export_multisig_info` / `import_multisig_info` between
participants, `transfer` to produce a partially-signed set,
`sign_multisig` by the second party, `submit_multisig`.

Constraints that follow, all of them load-bearing:

- Each round is a **synchronisation barrier across three parties**. Over I2P with
  60-90 s cold-tunnel latency and an offline arbitrator, wallet setup is
  realistically **tens of minutes**, and the state must survive both parties
  going offline mid-setup.
- Multisig is **disabled by default** and needs `set enable-multisig-experimental 1`
  in the CLI, which
  [cannot be set over RPC](https://github.com/monero-project/monero/issues/9488).
  Every user does a manual step before their first trade.
- The [2021 disclosure](https://www.getmonero.org/2021/12/06/vulnerability-multisig.html)
  covered creation *and* signing, with theft by a signing party as the impact and
  view-secret-key recovery by an eavesdropper on the setup exchange. Fixes
  shipped; the "experimental" label did not come off.
- **FCMP++ removes CLSAG.** The stressnet does not support multisig yet. Whatever
  you build against CLSAG multisig gets rewritten at the fork.

## 2.2 Recommended architecture

Not Option 1. **A fourth option the brief did not list:**

```
   ┌──────────────────────── your software ────────────────────────┐
   │                                                               │
   │  otrv4plus_trade.py          Rust core (unchanged)            │
   │  ─────────────────           ─────────────────────            │
   │  trade state machine   ────► existing OTRv4+ ratchet          │
   │  verb dispatch               existing SMP verification        │
   │  timeout / retry             existing file-transfer framing   │
   │  opaque blob relay           NO Monero code                   │
   │                                                               │
   └───────────────────────────────┬───────────────────────────────┘
                                   │  blobs the client cannot read
                                   ▼
                    the user's OWN Monero wallet
              monero-wallet-cli / monero-wallet-rpc / Feather
                     (holds the keys, signs, submits)
```

The client is a **secure courier for multisig blobs and a state machine for the
trade**, and nothing else. It never sees a spend key, a view key, a wallet file,
or a seed — because it never opens a wallet.

Why this and not Rust-core integration:

| Requirement | Rust core (`monero-wallet`) | Courier |
|---|---|---|
| B1.1 non-custodial | yes | yes |
| B2.1 no wallet embedded | **no — you'd be a wallet** | yes |
| **B2.2 users run their own wallets** | **no — FROST, not interoperable** | yes |
| B2.4 keys never cross PyO3 | yes | **stronger: never in the process** |
| H1 no private keys in client memory | needs care | **structurally impossible** |
| Audit surface | +Ed25519 +FROST +consensus format | **+0 crypto** |
| `panic = "abort"` exposure | third-party crate can abort a trade | **no new Rust** |
| FCMP++ hard fork | **rewrite** | wallet's problem, not yours |
| Arbitrator can use any wallet | **no** | yes |

The courier design also matches what actually works in the field: Haveno drives
`monero-wallet-rpc` and holds the third key with an arbitrator, rather than
reimplementing Monero's transaction stack.

**The honest counter-argument**, so you can weigh it: the courier design cannot
verify anything about the blobs it carries. It cannot check that a multisig
address was formed from the three keys it thinks it was, cannot detect a
malformed `kex` round, cannot scan for the incoming payment itself. Every
verification is delegated to the user's wallet and, ultimately, to the user
reading their own wallet's output. That is a genuinely weaker product experience
and it is the price of not becoming a wallet. If you decide that price is too
high, the Rust-core path becomes defensible — but then requirement B2.2 has to be
struck, and the plan below changes shape completely.

### Where the parts live

| File | Change | Why |
|---|---|---|
| `otrv4plus_trade.py` | **new** | trade state machine, verbs, timeouts, persistence |
| `otrv4plus_xmpp.py` | route `?OTRv4-TRADE:` to the manager; add commands | mirrors the `_filetransfer` wiring at `:1128` |
| `otrv4+.py` | route the same prefix on the IRC path; add commands | IRC client is in this file, not a separate module |
| `tests/test_trade_protocol.py` | **new** | state machine, replay, timeout, SMP gate |
| `tests/security_invariants.py` | INV-25, INV-26 | see §2.6 |
| `Rust/` | **nothing** | that is the point |

Note for the brief's F1/F2: there is no `otrv4plus_irc.py`, no `Rust/src/crypto/`
directory, and `otrv4plus.py` is a symlink to `otrv4+.py`. The IRC client lives
inside `otrv4+.py`, and the Rust modules are flat under `Rust/src/`.

## 2.3 Message protocol

`?OTRv4-TRADE:VERB:payload`, base64 fields, pipe-delimited — identical framing to
`?OTRv4-FILE:`, dispatched by a `TradeManager.handle_control(peer, body) -> bool`.
Every message travels inside the established, ratcheted, SMP-verified OTRv4+
session. There is no separate trade transport and no plaintext fallback.

```
trade_id  := 16 random bytes, generated by the initiator, in every message
nonce     := monotonic per-sender counter, rejected if not strictly increasing
deadline  := absolute unix time; a message past its deadline is dropped, not queued
```

```
  A                                                     B
  │  INIT     trade_id, amount, asset, terms_hash,       │
  │           arbitrator_fpr?, deadline                  │
  │ ───────────────────────────────────────────────────► │
  │                                                      │
  │  ◄─────────────────────────────────────────────────  │
  │           ACCEPT  trade_id, terms_hash (echo)         │
  │           DECLINE trade_id, reason                    │
  │                                                      │
  ├─ multisig setup — opaque blobs, N-M+1 = 2 kex rounds ─┤
  │  MS_INIT  trade_id, round=0, blob   (prepare_multisig)│
  │  MS_KEX   trade_id, round=1..2, blob                  │
  │  MS_ADDR  trade_id, address, address_hash             │
  │           ► both sides compare address_hash and STOP  │
  │             the trade if they differ                  │
  │                                                      │
  ├─ funding — verified by each party's own wallet ──────┤
  │  FUNDED   trade_id, txid, confirmations_seen          │
  │  FUNDCONF trade_id, txid, confirmations_seen          │
  │                                                      │
  ├─ settlement ─────────────────────────────────────────┤
  │  MS_INFO  trade_id, blob        (export_multisig_info)│
  │  PSIG     trade_id, blob        (partially signed set)│
  │  PSIG     trade_id, blob        (countersigned)       │
  │  DONE     trade_id, txid                              │
  │                                                      │
  ├─ exception paths ────────────────────────────────────┤
  │  DISPUTE  trade_id, reason, evidence_hash             │
  │  CANCEL   trade_id, reason                            │
  │  ABORT    trade_id, reason      (protocol violation)  │
```

Design rules, each of which exists because of a specific failure:

- **Every blob is opaque to the client.** It is base64 in and base64 out. The
  client must never parse a multisig blob, because parsing is the first step
  toward interpreting, and interpreting a Monero structure is the thing this
  design exists to avoid.
- **`terms_hash` is echoed, not restated.** If B's ACCEPT carries a different
  hash, the two sides disagree about what was agreed and the trade stops. Never
  reconcile silently.
- **`address_hash` is compared by both sides.** This is the single most important
  check in the protocol: it is what stops a MITM (or a bug) substituting an
  address. It is cheap and it must be mandatory.
- **Nonces are strictly increasing per sender**; a replayed or reordered message
  is dropped, not processed. The ratchet already gives replay protection at the
  transport layer, but the trade state machine must not rely on a lower layer for
  its own state transitions.
- **Deadlines are absolute and enforced locally.** A stalled counterparty must
  not hold a trade open forever. Every state has a timeout and a defined
  expiry action.
- **`DISPUTE` carries a hash, never evidence.** Evidence goes over the existing
  file transfer, which is already verified end-to-end.
- **Unknown verbs are consumed and dropped**, exactly as `handle_control` does
  for file transfer, so a newer peer cannot wedge an older one.

### Size and pacing

At ~16 KiB/s on XMPP, a 2-of-3 setup (4 rounds × 3 parties) plus a signing
exchange is on the order of minutes of channel time. The trade layer must reuse
`absorb_transfer_message`-style rate-limit exemption or it will be throttled by
the client's own flood protection, exactly as file transfer was before v10.18.
On IRC, with 510-byte lines, this is slow enough that the honest answer may be
"XMPP only for trades".

## 2.4 What I recommend you decide first

Three questions, in order. The second and third only matter if the first is
answered a particular way.

1. **Interoperability or Rust?** They are mutually exclusive today. Courier +
   native multisig means anyone with `monero-wallet-cli` can trade with your
   users and the arbitrator can be anyone. `monero-oxide` + FROST means better
   cryptography, real verification inside your client, and a closed ecosystem
   where every participant runs your build.

2. **If Rust: what is the FCMP++ plan?** Not rhetorical. CLSAG multisig has no
   published migration path and the stressnet does not support multisig. Building
   on it means committing to a rewrite on someone else's schedule.

3. **Who is the arbitrator?** This is the part of the design with the most
   unexamined weight in the brief. "Optional arbitrator" is a cryptographic
   role with a key, a liveness requirement, a dispute policy, and — in several
   jurisdictions — the characteristic that most attracts money-transmitter
   analysis, precisely because it is the party that can move someone else's
   funds. Non-custodial helps; holding one of three keys is not obviously
   nothing. Worth actual legal advice for your jurisdiction before it ships,
   alongside the AI-copyrightability question already outstanding from the
   licence work.

## 2.5 Roadmap

Revised from the brief's D1-D4 to put the decisions before the code.

**Phase 0 — decide and prototype by hand (no code).**
Run a 2-of-3 native multisig by hand between your two handsets and a third
wallet, pasting the blobs through an existing OTRv4+ session. Time each round.
This answers §2.4 empirically, produces real blob sizes, and costs a day. If
this is painful by hand it will be painful automated, and better to know now.

**Phase 1 — signalling only, no funds.**
`otrv4plus_trade.py` with the full state machine and every verb, carrying blobs
that both sides paste in and out of their own wallets manually. SMP gate,
timeouts, nonces, `address_hash` comparison. Testable end to end on stagenet
with no automation and no RPC. This is the piece that is genuinely low-risk and
reuses everything the codebase already proves.

**Phase 2 — optional wallet RPC convenience.**
`monero-rpc 0.5.1` driving a *locally running* `monero-wallet-rpc` the user
starts themselves, over loopback, to remove the copy-paste. Strictly optional;
Phase 1 must keep working without it. Bind loopback only, never expose the RPC
port to I2P, and treat the RPC socket as a trust boundary.

**Phase 3 — arbitration.**
Dispute flow, arbitrator liveness, timeout-to-refund. Needs the answer to §2.4.3
first.

**Phase 4 — reassess.**
Revisit `monero-oxide` after FCMP++ has landed and multisig has a supported
story. That is the point at which the Rust-core option becomes a real choice
rather than a bet.

I would not schedule Phase 2 before Phase 1 has run a real trade on stagenet
between the two handsets.

## 2.6 Security invariants to add

Drafted for `tests/security_invariants.py` in the existing format, so they land
with enforcing tests rather than as prose.

**INV-25 — No Monero key material exists in the client process.**
`ENFORCED`. The client carries opaque base64 blobs between two wallets it does
not run. No wallet file is opened, no seed or spend key or view key is read,
parsed, derived or stored. Enforced by a source-level assertion that the trade
module contains no wallet-file, seed or key-derivation code paths, and by a
test that every trade payload is handled as an opaque byte string.
*Limit if Phase 2 ships:* the wallet RPC password would be a Python `str`, with
the same unwipeable-string limit as INV-02.

**INV-26 — A trade never starts, and never advances, on an unverified peer.**
`ENFORCED`. `is_smp_verified(peer)` must be true at `INIT`, at `ACCEPT`, and at
every state transition that moves funds — not once at the start. Fail-closed:
an error determining SMP state is treated as unverified, matching INV-12. A
trade whose peer's fingerprint changes mid-trade is aborted, never re-pinned.

Both would need their enforcing test modules to exist before the registry test
passes — `tests/test_invariant_registry.py` fails on an invariant that names a
module that is not there, which is exactly the drift guard you want here.

---

## 3. Risk register

Only rows where my assessment differs materially from the brief's, plus the ones
the brief did not have.

| Risk | Brief's rating | Mine | Note |
|---|---|---|---|
| Multisig protocol bug | Medium / High | **Medium / Critical** | impact is stolen funds, not degraded service; and the 2021 disclosure was exactly this |
| Library compatibility | Medium / Medium | **High / High** | `monero-serai` is yanked; FCMP++ removes CLSAG; MSRV moves 1.85 → 1.89 |
| Arbitrator compromise | Low / Medium | **Low / High** | one of three keys can move funds with either counterparty's cooperation |
| I2P latency | Medium / Low | **High / Medium** | 4 sync barriers × 3 parties × 60-90 s cold tunnels |
| Legal | High / Critical | **agreed** | the arbitrator role is the exposure; get advice before it ships |
| **Address substitution** | *not listed* | **Low / Critical** | mandatory `address_hash` comparison, §2.3 |
| **Panic aborts a live trade** | *not listed* | **Medium / High** | `panic = "abort"`; funds locked in a half-built multisig. Argues against new Rust crypto |
| **Transient I2P destination vs. trade identity** | *not listed* | **Medium / Medium** | §1.3; bind identity to fingerprint, never to destination |
| **Multisig disabled by default** | *not listed* | **High / Low** | manual CLI step per user before first trade |

---

## 4. Sources

- [GHSA-36hh-v3qg-5jq4](https://github.com/advisories/GHSA-36hh-v3qg-5jq4) — the PyO3 advisory remediated at v10.19.0, context for §1.2
- [Monero multisig vulnerability disclosure, 2021-12-06](https://www.getmonero.org/2021/12/06/vulnerability-multisig.html)
- [monero#3389 — multisig view secret key disclosure](https://github.com/monero-project/monero/issues/3389)
- [monero#9488 — multisig disabled, `enable-multisig-experimental` not settable over RPC](https://github.com/monero-project/monero/issues/9488)
- [monero-oxide](https://github.com/monero-oxide/monero-oxide) and its [`monero-wallet` manifest](https://github.com/monero-oxide/monero-oxide/blob/main/monero-oxide/wallet/Cargo.toml) — the FROST multisig feature
- [monero-serai on crates.io](https://crates.io/crates/monero-serai) — 0.1.4-alpha, yanked
- [monero-wallet on crates.io](https://crates.io/crates/monero-wallet) — 0.2.0, 2026-07-31
- [monero-rpc on crates.io](https://crates.io/crates/monero-rpc) — 0.5.1, 2026-07-18
- [Haveno trade protocol](https://github.com/haveno-dex/haveno/blob/master/docs/trade_protocol/trade-protocol.md) and [docs](https://docs.haveno.exchange/overview/trade-protocol/)
- [Monero multisig documentation](https://docs.getmonero.org/multisignature/) — round counts, `N - M + 1`
- Codebase, at `f89b328`: `Rust/src/*.rs`, `Rust/Cargo.{toml,lock}`, `otrv4+.py`,
  `otrv4plus_filetransfer.py`, `otrv4plus_xmpp.py`, `otrv4plus_voice.py`,
  `tests/security_invariants.py`
