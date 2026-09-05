# Security

Threat model, known issues, and reporting.

## What OTRv4+ tries to defend against

| Adversary | Defense |
|---|---|
| Passive network eavesdropper | TLS 1.3 transport (when used over plain IRC), or I2P / Tor onion routing |
| Active MITM at first contact | Hybrid PQC SMP zero-knowledge proof out-of-band (user types same secret on both sides); classical Schnorr ZKP wrapped in ML-KEM-1024 + ML-DSA-87 binding |
| Long-term key compromise after the fact | Per-message forward secrecy via double ratchet; PCS via DH ratchet at 100-message / 24-hour boundaries |
| Future quantum adversary recording today | ML-KEM-1024 hybrid in DAKE; ML-DSA-87 hybrid signatures; hybrid PQC SMP (ML-KEM-1024 + ML-DSA-87 binding the identity proof) |
| Python heap inspection (post-exploitation) | Long-term private bytes live inside Rust `SecretBytes<N>` (ZeroizeOnDrop); session keys move Rust-to-Rust via the `DakeOutput` opaque handle. Voice too since v10.13.2: the epoch root, media keys and X448 scalar are Rust-owned with no accessor; the ML-KEM decapsulation key is the one secret still Python-side (see caveat 11). |
| AES-GCM nonce reuse | Counter-based nonce per ratchet step, KDF-derived; nonce never reused across messages. For voice the nonce is `epoch ‖ counter`, derived from authenticated header fields and never transmitted |
| Recording a voice call for later quantum decryption | Voice media root requires **both** X448 and ML-KEM-1024; neither alone suffices |
| Peer identity silently swapped between XMPP sessions | Fingerprint pinned on first contact; a change is reported, never auto-accepted, and refuses voice until cleared deliberately (XMPP only — IRC identities change by design) |
| A remote peer making your next typed line a secret | An inbound SMP request can only ask; it moves the flow to AWAITING_LOCAL_CONSENT and no further. Only a local `y` opens the hidden passphrase read, and an ordinary message typed at the request is sent as an ordinary message (`otrv4plus_smpflow.py`) |
| Forged, replayed or rolled-back voice endpoint address | `MEDIAPATH` announcements carry a tag derived from the committed epoch root over call_id, epoch, sequence, destination and role; sequence must strictly increase, and no state moves before the tag verifies |
| Reflection of a voice frame back at its sender | The direction byte is in the AAD but not on the wire, so a reflected frame fails authentication |
| Speech-dependent traffic analysis on voice | Constant 279-byte packet every 60 ms for the whole call; mute sends digital silence; DTX and variable packet sizing are off in the privacy profile |

## What OTRv4+ does not defend against

| Threat | Why not |
|---|---|
| Compromised endpoint at time of message | Out of scope. If the device has malware, no messaging app helps. |
| Compromised endpoint after message is sent | Skipped message keys cached for up to 1000 messages for out-of-order delivery. They are wiped on session close, not after each message. |
| Side-channel timing analysis on Python | Python is not constant-time. Rust core uses constant-time crypto via `ed448-goldilocks-plus` and `subtle`. |
| Side-channel on SMP modular exponentiation | Constant-time as of v10.7.6: SMP `modpow` uses `crypto-bigint` `DynResidue` (Montgomery form), not `num-bigint`'s variable-time `modpow`. The secret SMP exponents (blinding scalars, the secret, ZKP randomisers) no longer leak via exponentiation timing. |
| Side-channel on the Rust core | `ed448-goldilocks-plus`, `x448`, and `crypto-bigint` claim constant-time but have not been formally audited. Treat as best-effort. |
| Traffic analysis | Visible message size and timing leak metadata. Use a transport that pads (I2P with destinations does some of this; Tor does less). |
| Replay across sessions | DAKE includes both peers' fresh randomness, so a replay of an old DAKE produces a different session. Replay within a session is rejected by ratchet message counters. |
| State actor with quantum capability today | ML-KEM-1024 and ML-DSA-87 are best-current-knowledge post-quantum primitives. They are not formally proven; future cryptanalysis could break them. |
| Real-time MITM of a voice call by a quantum adversary | The ephemeral voice keys are authenticated by the surrounding OTR channel, so live voice authentication is only as post-quantum as the DAKE. Recorded calls stay protected by ML-KEM-1024. |
| Voice call metadata | Constant-rate shaping removes speech-dependent size and timing, not the fact of the call. Start, end, duration, loss, congestion and tunnel behaviour remain observable, and the XMPP server sees that two JIDs exchanged encrypted stanzas. |
| Loss of a voice call to a hostile network | Media liveness detection and authenticated endpoint recovery (v10.12.0) handle a path that *stops*. An adversary who can persistently block the media path can still end the call; the design fails closed rather than downgrading transport. |

## Memory safety model (v10.7)

| Key material | Storage | Wiping |
|---|---|---|
| Long-term Ed448 identity | Rust `SecretBytes<57>` inside `Ed448KeyHandle` | `ZeroizeOnDrop` when handle is GC'd |
| Long-term X448 prekey | Rust `SecretBytes<56>` inside `X448KeyHandle` | `ZeroizeOnDrop` when handle is GC'd |
| DAKE DH secrets (dh1, dh2, dh3) | Rust heap inside `DakeState` | `ZeroizeOnDrop` when `DakeState` drops |
| Ratchet X448 ephemeral keys | Rust `SecretBytes<56>` inside `X448KeyHandle` | `ZeroizeOnDrop` when handle is GC'd |
| ML-KEM shared secret | Rust heap | Wiped after KDF derivation |
| DAKE session keys (root, chain×2, brace, mac) | Rust `DakeSessionKeys` to `DoubleRatchet::SecretBytes` via Rust-to-Rust move | `ZeroizeOnDrop` end-to-end |
| Ratchet chain / root keys | Rust `SecretBytes<32>` | `ZeroizeOnDrop` |
| Per-message keys | Derived from chain key, used once, dropped | `ZeroizeOnDrop` on `SecretBytes<32>` |
| Skipped message keys | Rust `HashMap<u64, SecretBytes<32>>` | `ZeroizeOnDrop` on values; map cleared on session close |
| SMP secret | Rust `SecretVec` inside `RustSMPVault` | `ZeroizeOnDrop` when vault drops |
| SMP exponents (a2, a3, b2, b3, r, etc.) | Rust scalars | `ZeroizeOnDrop` on the `Scalar` wrapper |
| SMP ML-KEM-1024 secret key | Rust heap, hybrid PQC SMP | Wiped after decapsulation |
| SMP ML-DSA-87 signing key | Rust heap, hybrid PQC SMP | `ZeroizeOnDrop` |
| SMP pq_binding_key | Rust `SecretBytes<32>` | `ZeroizeOnDrop`, wiped per step |

The table above covers **chat**. No long-term private key material appears on the Python heap as `bytes` or `bytearray` during normal chat operation, and no chat key material transits an OpenSSL-backed Python object.

### Voice key material (v10.13.2 onward)

Voice did not meet that standard between v10.11.0 and v10.13.2, and this table
listed every item below as a Python `bytearray` or an OpenSSL object. It moved
at v10.13.2; the table was corrected at v10.16.1, later than it should have
been. What is left in Python is named honestly rather than omitted.

| Key material | Storage | Wiping |
|---|---|---|
| Voice epoch root (64 B) | Rust `SecretBytes<64>` in `RustVoiceRoot`; no accessor, Python holds a handle | `ZeroizeOnDrop` |
| Directional media keys (2 × 32 B per epoch) | Rust `SecretBytes<32>` in `RustVoiceCipher`; no getter, Python calls `seal`/`open` | `ZeroizeOnDrop` |
| Voice X448 **private** scalar (56 B) | Rust `SecretBytes<56>` in `RustVoiceKex`, single-use | `ZeroizeOnDrop` |
| Live AEAD state | Rust, inside `RustVoiceCipher` | dropped with the epoch |
| Voice X448 shared secret | Python `bytearray` for the moment between agreement and being consumed | zeroed **in place** by Rust as it is taken (`take_shared`), not by a `finally` the caller must remember |
| Voice ML-KEM shared secret | as above | as above |
| Voice ML-KEM decapsulation key (3168 B) | **Python `bytearray`** | explicit `_wipe()` in a `finally` and the reference dropped, the moment decapsulation completes |

So one long-ish-lived secret is still Python-side: the initiator's ML-KEM
decapsulation key, which exists from keygen until the peer's ciphertext
arrives. Explicit wiping is best-effort in CPython — the allocator may have
copied a `bytearray` before it is overwritten — and that caveat applies to it
and to the two shared secrets in the instant before Rust takes them. It no
longer applies to the epoch root or the media keys, which are the material a
copy of would decrypt the call. See caveat 11.

## Build-time invariants

The Python module enforces these at import time via `_check_rust_requirements()`:

- `otrv4_core.RustDAKE` present with methods `new_from_bytearrays`, `sign_profile_body_and_construct`, `sign_profile_body_and_construct_with_handles`, `ed448_sign_test`, `generate_dake2_output`, `process_dake2_output`
- `otrv4_core.py_ring_sign` and `otrv4_core.py_ring_verify` present
- `otrv4_core.Ed448KeyHandle`, `otrv4_core.X448KeyHandle`, `otrv4_core.generate_ed448_keypair`, `otrv4_core.generate_x448_keypair`, `otrv4_core.verify_ed448_sig` present
- `otrv4_core.mldsa87_keygen`, `mldsa87_sign`, `mldsa87_verify` present
- `otrv4_core.aes256gcm_encrypt`, `aes256gcm_decrypt` present

Missing anything raises `ImportError` at startup with a rebuild instruction. The app cannot accidentally fall back to a less-safe code path — and as of v10.7 there is no Python-crypto fallback path to fall back to.

## Build-time invariants for crypto correctness

v10.6.17 (Phase 5.3f-narrow) replaced the previous Python-side boot-time cross-verification with Rust-side RFC 8032 Ed448 test vectors in `Rust/src/test_vectors.rs`. v10.6.21 added an RFC 7748 §5.2 X448 known-answer vector in `Rust/src/key_handles.rs`. Both are exercised by `#[cfg(test)]` harnesses.

Run before every release:

```
cargo test --release --no-default-features --features pq-rust
```

Expected: **30+ tests pass** (17 prior + 3 ML-KEM + 15 hybrid PQC SMP tests added in v10.9.0: classical roundtrip, hybrid PQ roundtrip, mismatched secrets in both modes, version-mismatch rejection, ML-DSA context sign/verify, wrong-context rejection, ML-KEM encaps/decaps roundtrip, pq_binding_key determinism).  If `ed448_rfc8032_vectors_byte_exact` fails, the `ed448-goldilocks-plus` crate has diverged from RFC 8032.  If `x448_rfc7748_known_answer` fails, the `x448` crate has diverged from RFC 7748 and the ratchet would desync against any peer — do not ship.  If `mlkem1024_byte_sizes_match_spec` or `mlkem1024_roundtrip_shared_secret_matches` fails, the `pqcrypto-mlkem` crate has diverged from FIPS 203.  All four are build-time gates against the spec documents themselves.

Two helper functions were removed at v10.6.17: `_verify_ed448_rust_compat()` and `_verify_ring_sig_rust_compat()`.  The previous comparison against the C extension's `ring_sign` and `ring_verify` is no longer performed.  As of v10.7.5 the C extension itself has been retired (see caveat 4 below), so these comparison paths are doubly obsolete.

## Dependency security on the Python/Rust boundary

PyO3 is not an ordinary dependency. It *is* the boundary between the Python
client and the Rust cryptographic core, so an advisory against it is an
advisory against the boundary, and remediating one is not finished when
`Cargo.lock` shows a new number — the compiled artifact has to be rebuilt and
re-tested. The order, as run for GHSA-36hh-v3qg-5jq4 at v10.19.0:

```
Cargo.lock audit → cargo build → PyO3 boundary tests → Python suite
                 → cargo test → security-invariant tests → installed-wheel tests
```

`tests/test_dependency_advisories.py` (INV-23) pins two things at once, because
either alone decays into a false guarantee:

- **the resolved version**, from `Cargo.lock`, not from `Cargo.toml` — the
  manifest states an intent, the lock states what is compiled;
- **the unreachability of the vulnerable path**, so that the day someone puts a
  Python sequence across the boundary, the analysis below is flagged as expired
  rather than quietly wrong.

`tests/test_pyo3_boundary.py` then drives the **installed extension module**
with hostile input — out-of-range integers, non-bytes objects, lone surrogates,
a lying `int` subclass, a 4 MB message — and asserts every one comes back as a
Python exception. That matters more here than in most projects: the release
profile sets `panic = "abort"`, so a Rust panic is not something Python can
catch, it takes the client down mid-session with the peer left waiting.

### GHSA-36hh-v3qg-5jq4 — PyO3 out-of-bounds read (assessed v10.19.0)

| | |
|---|---|
| Advisory | GHSA-36hh-v3qg-5jq4 (CVSS 8.7, CWE-125), PyO3/pyo3#6086 |
| Affected | pyo3 < 0.29.0 |
| Was installed | pyo3 0.24.2 — direct dependency, single version in the tree, nothing else constrained it |
| Now installed | pyo3 0.29.2 |
| Vulnerable path reachable from OTRv4+ | **No** |
| Severity for this project | **Informational** — upgraded regardless |

`BoundListIterator` and `BoundTupleIterator` computed `index + n` in
`Iterator::nth` / `DoubleEndedIterator::nth_back` before bounds-checking it, then
read the element with `get_item_unchecked`. On `nth` the addition can wrap and
re-yield elements from the front; on `nth_back` the subtraction can underflow
and read memory past the sequence's storage.

**Why it was not reachable.** The entire Python→Rust surface of `otrv4_core` is
`&[u8]`, `&str`, `u32`/`u64`, `bool`, `&Bound<PyByteArray>`, `&Bound<PyAny>` and
opaque pyclass handles. No `#[pyfunction]` or `#[pymethods]` entry point accepts
a Python list or tuple, `PyList` and `PyTuple` appear nowhere in the crate, and
`nth`/`nth_back`/`step_by` are called on nothing. There is no sequence for the
vulnerable iterators to walk, and no attacker-controlled `n` to overflow. This
is asserted, not asserted-once: the reachability check is a test.

**Why it was upgraded anyway.** An unreachable bug in the boundary layer is one
refactor away from reachable, and 0.29.2 was a compatible release: MSRV 1.83
against our declared 1.85, `abi3-py39` still offered, no new transitive
dependencies (four were *removed*: `indoc`, `unindent`, `memoffset`,
`rustversion`).

**API changes required.** One, at two call sites: `Bound::downcast` was renamed
`Bound::cast` (same signature; `CastError` replaces `DowncastError`) —
`ratchet.rs:718` and `voice.rs:458`. No ownership, lifetime, conversion or
exception-propagation behaviour changed. No secret material moved.

**Verification.** `cargo test` 111 passed; `cargo clippy --all-targets` clean;
release `.so` rebuilt with `--features extension-module` and installed; Python
suite 2538 passed, 0 failed; the 44 new boundary tests pass against the
installed module.

## Trade coordination is a courier, not a wallet (v10.20.0)

`otrv4plus_trade.py` relays multisig coordination blobs between two people
inside the OTRv4+ channel. It is a transport, and the security argument rests
on it staying one.

**What it never does** (INV-25). It opens no wallet file, reads no seed, spend
key or view key, derives no address and signs nothing. A blob is checked for
base64 alphabet and length and passed through verbatim — never parsed, because
parsing is the first step toward interpreting. Its import list is asserted
exactly (`base64`, `hashlib`, `re`, `secrets`, `time`, `typing`), so it cannot
reach a daemon or a wallet at all, and `tests/test_trade_courier.py` walks its
identifiers for anything key-, network- or wallet-shaped.

This is INV-08 in its strongest form. INV-08 says Python does not receive key
material Rust can own instead; here there is no key material in either, because
the keys never enter the process.

**What gates a trade** (INV-26). `is_smp_verified(peer)` is checked on every
message in both directions, not once when the trade opens. A trade agreed at
09:00 and still running at 14:00 would otherwise span five hours in which a
session teardown or a fingerprint change goes unnoticed while blobs keep
flowing. Fail-closed, matching INV-12: a predicate that raises counts as
unverified. The peer's fingerprint is bound when the trade opens and re-checked
with it; a change cancels the trade and never re-pins, matching INV-11.

Binding is to the **fingerprint**, never to the I2P destination. Destinations
are `TRANSIENT` and change every session by design — that is the transport's
main privacy property, and tying a trade to one would either undo it or break
the trade.

**Trade output never reaches the session log.** `trade` is deliberately absent
from `_LOG_SAFE_TAGS`, so every `[trade]` line is redacted to
`<unlogged line: N chars>` by the allowlist in INV-03 rather than by a rule
someone remembered to write. That matters because a multisig blob is
sensitive: the 2021 Monero disclosure included recovery of the view secret key
by an eavesdropper on the setup exchange. A test pins the tag's absence,
because the obvious "improvement" is to add it so the transcript reads better.

**State is in memory only** and is cleared on disconnect, `/quit` and process
exit, alongside the scrollback purge (INV-24). A trade does not survive a
restart: resuming from a file would mean trusting that file about who the
counterparty was and how far the trade had got.

**What it does not protect you from.** It cannot tell you a multisig address
was formed from the right keys, that a payment landed, or that a partial
signature is well formed. Your wallet tells you that, and comparing the
multisig address with your counterparty out of band is the one check nothing
here can do for you. This is a real limitation and the price of the client not
becoming a wallet — [MONERO_ESCROW_AUDIT.md](MONERO_ESCROW_AUDIT.md) §2.2
states the counter-argument in full.

**No arbitration.** The project does not act as an arbitrator and ships no
arbitrator key. 2-of-3 works by the participants choosing their own third
party. There is no code path that would let this client hold one of three keys.

## Known issues and limitations

1. **Rust crypto crates are not audited.** `ed448-goldilocks-plus` 0.16 is the only viable pure-Rust Ed448, and `x448` 0.6 the X448, but neither has had a formal review. `pqcrypto-mlkem 0.1.1` (FIPS 203 ML-KEM-1024) and `pqcrypto-mldsa 0.1.2` (ML-DSA-87) are PQClean-derived reference implementations.

2. **No persistent identity vault for IRC.** IRC identity keys regenerate at every launch and fingerprints change each time — correct for ephemeral IRC nicks. **XMPP is different as of v10.12.0**: it holds a persistent sealed identity so that a stable JID has a stable fingerprint and TOFU can mean something. See caveats 5 and 5b.

3. **The Python cryptography library has been fully removed (v10.7).** Earlier versions of this document listed the `cryptography` library as load-bearing in production. As of v10.7 it is no longer imported or used anywhere in the codebase. The removal was a staged sequence:
   - v10.6.18 — ML-DSA-87 moved off the `otr4_mldsa_ext` C extension to `pqcrypto-mldsa`.
   - v10.6.19 — AES-256-GCM moved from `cryptography.AESGCM` to the Rust `aes-gcm` crate; six `Ed448PublicKey.from_public_bytes` wrap sites replaced with raw bytes; `AESGCM` and `hashes` imports dropped.
   - v10.6.20 — `ClientProfile.decode()` Ed448 signature verification moved from `cryptography.Ed448PublicKey.verify` to the Rust `verify_ed448_sig` function.
   - v10.6.21 — the double ratchet's X448 Diffie-Hellman moved from `cryptography.x448` to the Rust `X448KeyHandle`.
   - v10.7 — the dead pure-Python `OTRv4DAKE` fallback class (the last `ed448`/`x448`/`serialization` consumer) was deleted, the four remaining `serialization.Raw` byte-conversion sites were removed, and the `from cryptography...` import was deleted entirely.

4. **All C extensions have been retired (v10.7.5, Phase 5.3k).**  Earlier versions of this document listed two C extensions (`otr4_crypto_ext`, `otr4_ed448_ct`) as load-bearing in production.  Both are gone, as is the long-dead `otr4_mldsa_ext` (retired at v10.6.18).  The migration was staged across several sub-phases of 5.3i, each one isolating a single C-extension surface and moving it to Rust before the next was touched:
   - **v10.7.1 (5.3i-A)** — four dead bignum wrappers (`_ct_mod_exp`, `_ct_mod_inv`, `_ct_rand_range`, `SHA3_512.hash_to_int`) deleted; `disable_core_dumps` moved to Python `resource.setrlimit`.
   - **v10.7.2 (5.3i-B)** — `_ossl.cleanse` replaced by a module-level `_secure_wipe(bytearray)` using `ctypes.memset` (dead-store-resistant, no DLL surface).
   - **v10.7.3 (5.3i-C)** — `MLKEM1024BraceKEM.keygen/encaps/decaps` migrated from `_ossl.mlkem1024_*` to Rust `pqcrypto-mlkem` via a new `mlkem.rs` PyO3 module.  After this, `otr4_crypto_ext` had no callers.
   - **v10.7.4 (5.3i-D)** — `aead.rs` migrated off the deprecated `aes-gcm` `GenericArray::from_slice` helper to `Aes256Gcm::new_from_slice` and `Nonce::from(*&[u8;12])`.  Zero-warning Rust build restored.
   - **v10.7.4 (5.3k)** — the `otr4_ed448_ct` import was deleted (it had no callers; it was loaded as a defensive ground-truth but every Ed448 operation already ran in Rust).  The `.c`/`.h`/`.so` files and `setup_otr4.py` were removed from the repository.  Seven test files in `tests/` were rewritten onto Rust `otrv4_core` (the C-extension-only `test_otr.py` was deleted; the pre-broken `test_v10_4_security_fixes.py` is unrelated and tracked separately).

   The architectural consequence: there is a **single cryptographic implementation surface** for chat.  No second backend to drift against, no compile-time conditionals selecting between paths, no "Rust verified against C" comparison checks.  Whatever the Rust core computes is what gets transmitted on a chat message; there is nothing else for a reviewer to look at.  *(This was true of the whole project when written.  The voice subsystem added at v10.11.0 broke it by carrying a second AES-256-GCM and its own key schedule in Python; v10.13.2 moved them into the same core, and the only remaining `AESGCM(` call sites in the repository are in `.attic/`.  See caveat 11.)*

5. **Ephemeral identity is a deliberate design choice for IRC, not a missing feature.** IRC regenerates identity keys at every launch; fingerprints do not persist across sessions. **XMPP does not do this** (caveat 5b). Rationale for IRC:
   - **Threat model fits ephemeral.** OTRv4+ runs over I2P for an IRC channel; the assumption is short-lived sessions, not long-term identity binding.
   - **No on-disk attack surface.** A persistent vault would create a high-value target for offline brute-force.
   - **No passphrase to forget.** Termux has no OS keyring; a vault would require a user passphrase at every launch.
   - **Aligns with privacy-oriented messaging norms.** Tor Browser, Cwtch (default), and Briar (before user opt-in) all keep identities short-lived.

   SMP trust binding is meaningful within a session. Across sessions, peers must re-verify. See ROADMAP Phase 5.3g.

6. **Single-author project, AI-assisted.** Each release is live-tested between two I2P peers but has not been reviewed by another human cryptographer. Use as a research prototype.

7. **No interop with stock OTRv4.** Wire-incompatible with `pidgin-otr4`, CoyIM, and similar implementations due to ML-DSA-87, ML-KEM-1024, and SHAKE-256 OTRv4+ additions.

5b. **XMPP has a persistent identity and pinned trust; IRC has neither (v10.12.0).**  The two protocols were treated identically until v10.12.0 and should not have been.  A JID is a durable name, so an identity that changed under it every launch made a changed fingerprint carry no information — and because both protocols shared `~/.otrv4plus/trust.json`, `add_trust` raised `FingerprintMismatchError` on the *second* session with any peer, so every ordinary reconnect printed "This may indicate a MITM attack".  A warning shown every time is a warning that will be ignored the once it matters.

   What now holds:

   * **XMPP** — one Ed448 identity, sealed on disk, reloaded every run.  Peer fingerprints are pinned on first contact under `~/.otrv4plus/xmpp/trust.json`.  A matching fingerprint asks nothing.  A **changed** fingerprint is reported, the stored pin is **not** replaced, no `y`-answerable prompt is offered, the session does not continue into SMP setup, and voice is refused for that peer until the user deliberately runs `/trust-reset <jid>`.
   * **IRC** — unchanged.  Fresh identity every run, trust held in memory for the session only, nothing written to disk.  Because IRC no longer writes trust records, it can no longer produce the false mismatch either.

   **TOFU is identity continuity, not authentication.**  A matching pin authorises nothing on its own.  SMP remains the authentication mechanism and `_smp_verified` remains the only gate on voice; the fingerprint-mismatch refusal is an *additional* refusal layered on top, never an alternative route through.

   **At-rest protection is filesystem permissions, not cryptography.**  The sealed record is AES-256-GCM twice over — inside Rust (`Rust/src/identity.rs`, so the Ed448 seed never becomes a Python object) and again bound to its record slot — but the key protecting it is a 32-byte file at `~/.otrv4plus/xmpp/.identity_dek`, mode 0600, with no passphrase.  Termux has no OS keyring.  **An attacker who can read your home directory can read the identity.**  This is the same posture `SMPAutoRespondStorage` has always had for SMP secrets (`.smp_seed`), so it adds no new class of exposure, but it must not be described as hardware-backed, passphrase-protected, or simply "encrypted at rest".  What it does defend against is a process that obtains the sealed blob without also holding the key file, and backup or sync tools that capture one and not the other.

   **The pins themselves are plaintext.**  `~/.otrv4plus/xmpp/trust.json` is an unencrypted JSON file listing the JIDs you have talked to and their fingerprints.  It is a contact list, and anyone who can read it learns who you correspond with.  Encrypting it is tracked in `ANDROID_STORAGE_AUDIT.md` row 4 and is not done here.  Note the asymmetry with the identity: an attacker who can *write* to this file can replace a pin, which would make a substituted identity look expected — so the integrity of this file matters as much as its confidentiality, and neither is cryptographically protected today.

   **Failure is closed.**  A record that exists and will not open is never silently replaced: regenerating would change the local fingerprint with no signal, and every peer holding a pin would see the identity change TOFU exists to report — caused by us and indistinguishable from an attack.  The client refuses to start instead.

8. **ClientProfile lifetime: 14 days (v10.7.5).**  Earlier versions used a 365-day expiry, which was incoherent with the ephemeral-identity design (caveat 5).  The OTRv4 spec §4.1 recommends short profile lifetimes; v10.7.5 reduces the validity to 14 days, matching `otr4j`'s default.  Because IRC regenerates identity keys at every launch, this is an upper bound on how long an *offline* peer will still accept a previously-cached profile (on XMPP the identity persists, so the profile is re-signed under the same key rather than a new one) — it is not the practical lifetime of any single key, which is hours at most.

9. **SMP modular exponentiation is constant-time (v10.7.6, Phase 5.4).**  Prior to v10.7.6, SMP used `num-bigint`'s `modpow`, whose running time depends on the exponent's bit pattern.  Because SMP exponentiates with secret values (the per-session blinding scalars, the SMP secret itself, and the ZKP randomisers), this was a timing side-channel: an attacker able to measure SMP-round timing precisely could in principle recover bits of those secrets.  v10.7.6 routes every secret-exponent `modpow` through `crypto-bigint`'s `DynResidue` (Montgomery-form modular exponentiation, constant-time in the exponent).  The MODP-3072 group (OTRv4 §5.3) is unchanged — same prime, same generator — so the wire format and spec compliance are identical; only the implementation changed.  Caveats: (a) the *public*-value arithmetic in the ZKP reconstruction (challenge/response combination) remains on `num-bigint`, which is correct because those operands are public and carry no secret-dependent timing; (b) `crypto-bigint`'s constant-time claims, like those of the other Rust crypto crates here, have not been formally audited.  The practical attack surface for this side-channel was always narrow over I2P (multi-second fragmentation latency drowns the signal), but constant-time is the correct posture regardless.

10. **SMP is hybrid post-quantum (v10.9.0).**  The classical OTRv4 four-step Schnorr ZKP over the 3072-bit MODP group is preserved unchanged and now runs alongside an ML-KEM-1024 and ML-DSA-87 binding layer.  In SMP1 the initiator appends an ML-KEM-1024 encapsulation key and ML-DSA-87 public key.  In SMP2 the responder encapsulates to derive `kem_ss`, derives `pq_binding_key = KDF(PQ_BRACE_KEY, domain || kem_ss || transcript_tag, 32)`, and signs the entire SMP2 body with ML-DSA-87 under that binding key.  SMP3/4 each verify the previous step's ML-DSA-87 signature before processing classical fields, then sign their own output.  Forging a false "verified" requires breaking the 3072-bit discrete log, ML-KEM-1024, and ML-DSA-87 simultaneously.  The wire format is versioned (`0x01` classical, `0x02` hybrid PQ) with no silent downgrade.  **Known limitation:** the ZKP scalar arithmetic (the `d = r - c*x` response computation) still uses variable-time `num-bigint`; the exponentiation is constant-time via `crypto-bigint` Montgomery form but the surrounding scalar multiply is not yet. A fully constant-time ZKP is tracked as future work.  The SMP session timeout was raised to 45 minutes (from 10) at v10.9.1 to accommodate the hybrid-PQ wire overhead over I2P, where SMP2 is 49 fragments and a full verification takes ~15–16 minutes.

## Chat scrollback is not a store (v10.19.0)

An IRC message must not outlive the connection it arrived on (INV-24). Until
v10.19.0 it did: panel history was unbounded and nothing ever cleared it, so a
disconnect-and-reconnect replayed the whole previous conversation into the new
session, under whatever nick the client had been forced to take. A tester
watched it happen three times in one evening, with the unread badge climbing
`system(53)` → `system(105)` → `system(158)` as each reconnect appended another
copy.

That is a privacy problem before it is a cosmetic one. This client runs over
I2P, where the point of a new session is that it is not linkable to the one
before it. Replaying the old conversation into the new one links them on the
screen no matter what the transport did.

What v10.19.0 does:

- history is capped at 1000 messages per panel, oldest pruned first;
- it is emptied at every boundary between one connection and the next —
  disconnect, reconnect, `/quit`, and process exit via `atexit` (so SIGINT and
  an unhandled exception are covered too);
- unread counters and recent-user sets go with it, and on the paths where the
  user is leaving or has asked — `/quit`, process exit, `/clear` — the
  terminal's own saved scrollback is cleared too (`\033[3J`), because on Termux
  the visible history *is* the scrollback;
- **not** on an automatic reconnect, deliberately: blanking the emulator during
  a dropped connection would destroy the error messages the user is reading to
  find out what happened, on a transport where a blip is routine. What the
  reconnect purge stops is the replay, which was the reported bug;
- `/clear` does all of the above on demand without touching the connection;
  `/clear <panel>` keeps the old single-tab behaviour.

**What this does not do.** It does not scrub the text from process memory. A
Python `str` is immutable and may be interned; the purge drops the last
reference the client holds, and the bytes remain in freed heap until the
allocator reuses them. That limit is the same one as for passwords (INV-02) and
it is not fixable while the UI is Python-side. Material that must genuinely be
destroyed is not kept in a chat panel at all — it lives in Rust behind
`zeroize()`.

The reconnect backoff was raised from 5s-doubling to a flat 30/60/90/120s for
the same reason a ghost session causes the collision: five seconds is shorter
than any server's ping timeout, so the reconnect arrived while the previous
session still held the nick. A 433 now takes a temporary nick only if
registration has not completed, and schedules up to four attempts to reclaim
the original — instead of renaming permanently, which is how one dropped
connection used to cost the user their identity.

## Reporting issues

Open a GitHub issue at <https://github.com/muc111/OTRv4Plus/issues>. For anything that looks like an actual security flaw (key disclosure, signature forgery, MITM bypass, panic on adversarial input), tag the issue `security` and include reproduction steps. If you would prefer to disclose privately first, the maintainer is on I2P (see the GitHub profile for an `i2p` contact).

There is no bug bounty. The project is solo and unfunded.

11. **The voice key path is Rust-owned, and this caveat used to say otherwise (updated v10.13.2).**  Until v10.13.2 `otrv4plus_voice.py` used the Python `cryptography` library for the media AES-256-GCM, the HKDF-SHA512 key schedule and the X448 half of the voice key exchange.  All three moved.  **Media keys** are `SecretBytes<32>` inside `RustVoiceCipher`, zeroized on drop, with no getter — Python calls `seal`/`open` and never sees a key.  The old arrangement kept keys in a wipeable `bytearray` and then handed each to OpenSSL as `AESGCM(bytes(key))`, an immutable copy nothing could wipe and that the AESGCM object retained: roughly 276 of them over a 69-minute call.  **The epoch root** is `SecretBytes<64>` inside `RustVoiceRoot`; Python holds a handle that produces a cipher, a confirmation pair or an endpoint tag, and cannot produce the root.  The initial derivation and the rekey chaining happen inside Rust, and the X448 / ML-KEM shared secrets are zeroed by Rust before the call returns rather than by a `finally` the caller must remember.  **The voice X448 private scalar** was a `cryptography` object Python could neither wipe nor reach; it is now `SecretBytes<56>` in `RustVoiceKex`, single-use, carrying the reflection / all-zero / degenerate-shared-secret checks that were previously Python-side.  What stays in Python is protocol logic that touches no key material: the frame header, the AAD construction, the replay window, the jitter buffer and the rekey state machine — the last deliberately, because it owns the convergence properties fixed at v10.13.1 and putting freshly-audited behaviour through an unnecessary rewrite is how stable systems break.  **This does not defend against a compromised kernel or a device in someone else's hands.**  It stops keys outliving their use and being reachable by ordinary Python introspection, which is narrower and real.

12. **Voice media liveness and endpoint recovery change no cryptography (v10.12.0).**  A call whose inbound media stopped used to stay "up" indefinitely, because a datagram handed to the local SAM UDP bridge is accepted whether or not the session behind it still exists — the transmit counters kept climbing over a dead path.  v10.12.0 detects that and can replace the media endpoint mid-call, announcing the new destination in an authenticated `MEDIAPATH` control message.  What this explicitly does **not** change: the cryptographic primitives, the key schedule, media authentication, the replay window, epoch ordering, the call-identity binding, or endpoint authentication.  It changes *when* a rebuild is requested, never what a rebuild does or how its announcement is proven.  Three properties matter for review: no media key derives from the destination (the transcript covers call_id, OTR binding, both fingerprints, the X448 and ML-KEM material and the epoch, and nothing else), so moving the address invalidates no key and a packet already accepted stays rejected; the announcement tag comes from the *committed* epoch root and the sequence must strictly increase, so forgery, replay and rollback are refused; and no state moves before the tag verifies, so a forged announcement costs nothing.  Recovery is confirmed by inbound media resuming rather than by an acknowledgement, and the whole state machine is bounded (465 s proven path / 795 s cold) with `OTRV4PLUS_RECOVER_ATTEMPTS=0` restoring the plain fail-safe.

13. **Voice liveness and signalling liveness are separate, deliberately.**  The XMPP keepalive does not read voice state and voice recovery does not read keepalive state.  Neither plane may stand in as evidence for the other: healthy media does not prove the XMPP stream is alive, and a healthy XMPP stream does not prove the SAM datagram session is alive.  The v10.12.0 keepalive work (quiet threshold 180 s, ping timeout 60 s, two consecutive failures required) widened the thresholds to stop false positives over three I2P hops; it did not make either plane conditional on the other.

14. **The SMP passphrase is stretched with Argon2id as of v10.13.0, and an offline dictionary attack on it is still possible (v10.13.0).**  SMP proves two people know the same passphrase without revealing it, but the transcript is enough for a party who *completes* SMP with you — including an attacker who is talking to you — to test candidate passphrases offline.  That is a property of SMP, not of this implementation, and it does not go away.  What changed is the cost per guess.  Until v10.13.0 the passphrase was stretched by 50,000 rounds of SHAKE-256 over the passphrase **alone**; the session ID and fingerprints were mixed in afterwards by a single HMAC.  Two consequences followed: the work was CPU-only, so a GPU ran thousands of candidates in parallel, and — worse — nothing user-specific entered the expensive part, so `stretch(candidate)` was computable once and reusable against every OTRv4Plus user and every session that ever ran.  The 50,000 rounds bought far less than the number suggested.  Wire version `0x03` derives the scalar with Argon2id (m=64 MiB, t=3, p=4), salted with the session ID and both fingerprints, so each guess costs 64 MiB of memory and no precomputation carries from one session to the next.  **This raises the cost of a dictionary attack; it does not make a weak passphrase safe.**  A short or guessable SMP passphrase is still a short or guessable SMP passphrase.  The `0x02` derivation is retained, unchanged, only so that a peer who has not updated fails at the version check with a message saying so rather than reporting a passphrase mismatch — there is no negotiation and no downgrade.

15. **A documentation claim of Argon2id in the Rust core predated the implementation by several releases (v10.13.0).**  `FEATURES.md` and `README.md` stated that an "Argon2id KDF protecting the SMP vault" ran inside `otrv4_core`, and audit finding 6 below is recorded as closed on the same premise.  No such code existed: `argon2` was not a dependency of the crate, no Rust source referenced it, and `src/smp_vault.rs` is an in-memory zeroizing store with no key derivation in it at all.  The Argon2id that did exist was Python-side and at-rest only.  The claim survived a documentation-synchronisation pass because the table was read and not checked against the source.  It was retracted, and then made true in the place that mattered, at v10.13.0.  Recorded here because a security document that has overstated a property once should say so plainly: the correction is now pinned by `tests/test_kdf_claims_are_true.py`, which reads `Cargo.toml` and the Rust sources rather than the prose.


16. **A remote peer could decide what your next keystroke meant, until v10.13.1.**  Completing a DAKE caused the client to arm a pending-input state (`_pending[peer] = "smp_secret"`), and the line dispatcher consumed that state ahead of all command parsing with only `/quit` exempt.  Because the arming path ran from the inbound message handler, a peer who started an OTR session could make the next line the user typed -- a message, a command, anything -- be swallowed and stored as an SMP passphrase.  The line was masked and never transmitted, so this was not exfiltration; it was a remote party choosing the meaning of local input, which is the property being defended.  Supplying the secret now requires the user to type `/smp-secret` themselves, and the request is single-use: it is taken unconditionally on the next dispatched line and cannot survive into a later one.  `tests/test_no_remote_input_capture.py` walks the inbound call graph transitively and fails if any remote-driven path can reach the armer again.

    Revisited at v10.15.0, when the responder flow was made automatic. A peer's SMP1 may now open a prompt — that is the point of the feature — so the property had to be re-stated rather than re-asserted: a remote message moves `otrv4plus_smpflow.SmpFlow` to `AWAITING_LOCAL_CONSENT`, and the only edges into `AWAITING_SECRET`, the state in which a typed line is read as a passphrase, are `local_secret_needed` (the user typed `/smp`) and `local_consent` (the user typed `y`). A chat message typed at a consent prompt is not `y`, so it falls through and is sent as a message. The same audit found the IRC client still had the original defect — `_set_pending("smp_secret", …)`, armed from a remote-completed DAKE and not even masked — and it was removed along with the branch that consumed it.

17. **The session transcript now writes only what it recognises (v10.13.1).**  `--debug` writes `~/.otrv4plus/logs/session-*.log`, and that file is what people paste into bug reports.  It used to redact one line shape and write everything else verbatim, which fails open: a `print()` added anywhere carrying a passphrase, a key or a token reached the file with nothing objecting.  It is now an allowlist -- message-content lines keep their prefix and lose their body, structural rules pass, `[tag] text` passes for a fixed set of diagnostic tags, and anything else is recorded as `<unlogged line: N chars>`.  A sweep of every non-test source found no call site printing a secret value, so this closed a latent hole rather than an active leak.  `tests/test_log_boundary.py` puts realistic passphrases, keys, seeds and tokens through the boundary in nine carrier shapes and fails if any of it survives.

18. **Account credentials were in the config's `repr()` (v10.13.1).**  `OTRConfig` is a dataclass, so its generated `__repr__` printed every field including `sasl_pass` and `nickserv_pass`.  The config is passed around, appears in debug output and lands in exception text, so `repr(cfg)` alone was enough to put the account password on screen -- it was found by a test doing exactly that and printing it in the failure message.  Both fields are now declared `repr=False`.  **The residual limit is unchanged**: credentials are `str`, so setting the attribute to `None` after use drops the reference but cannot overwrite the buffer, which may have been interned or copied by the allocator.  This is recorded as a limitation, not as zeroization.  It is unfixable *while credential handling is Python-side* -- which today means while slixmpp is the XMPP client and `otrv4+.py` is the IRC one -- rather than unfixable in principle.  Note what the fix would actually require: moving the *storage* into Rust is not enough, because `getpass.getpass()` returns a `str` and the credential exists in that buffer before anything else can touch it.  The capture has to happen in Rust too.  slixmpp is a test dependency and the production XMPP client is planned to be Rust-hardened; until that lands, this stays a limitation and not a plan.

19. **Rejected media is now counted by cause (v10.13.1).**  Every rejection used to increment `auth_fail` unless its exception text happened to contain the word "replay", so `authfail=87` on a live call could equally mean a forged frame, a peer that had rekeyed ahead of us, a frame from a retired epoch, or a byte stream that had lost sync.  Only the first is an authentication failure, and the second is what actually happened -- which took a 69-minute call to work out because the number could not distinguish them.  `FrameError` now carries a `reason`, set at each raise site and mapped to its own counter.  **Classifying a rejection does not soften it**: every reason still discards the frame, the AES-256-GCM tag check is unconditional, and no path accepts unauthenticated media.

20. **A rekey could strand the two peers permanently (v10.13.1).**  Two defects, both reachable on a real call.  First, `abort_rekey` removed the pending epoch's cipher from the *receive* set; since the initiator commits as soon as the responder's tag verifies and only then sends REKEYCOMMIT, it is already sending on the new epoch while the responder still has it pending, so a responder that aborted on a timeout could no longer decrypt anything the peer sent.  Second, an incoming REKEY had to name exactly `ours + 1`, so a responder that missed one REKEYCOMMIT stayed behind forever -- every later REKEY was two ahead and rejected, including the ones that would have repaired it.  A timeout abort now keeps the receive cipher (silence is not evidence; a failed confirmation tag still discards, because that is), and a bounded forward jump is accepted as a catch-up.  **Neither change weakens authentication**: committing still requires a confirmation tag only the real peer can produce, the epoch counter still only moves forward, and a jump beyond `VOICE_REKEY_MAX_CATCHUP` is still refused.  **What is still missing** is a positive acknowledgement proving both peers switched -- closing that needs a fourth message and therefore a wire change.  What replaces it is convergence rather than proof, and `tests/test_rekey_divergence.py` holds that line.


21. **Two wipes that were being undone by an immutable copy (v10.13.2).**  Both were places where the code was already trying to do the right thing and the attempt was defeated one line away.  `set_smp_secret` built a wipeable `bytearray` from the typed passphrase, passed `bytes(raw)` to the vault — creating an immutable copy nothing could overwrite — and then carefully zeroed the bytearray in a `finally`, wiping the one object that no longer mattered.  `RustSMPVault.store_from_bytearray` now takes the bytearray itself, copies it into a `ZeroizeOnDrop` entry and zeroes the caller's buffer before returning, including on the error path, because a rejected secret is still a secret.  The voice case was the same shape at larger scale and is covered in caveat 11.  **The residual limit is unchanged**: the passphrase is a Python `str` before anything can touch it, and a `str` cannot be wiped.

22. **A differential test that had stopped being differential (v10.13.2).**  Worth recording because it is a failure mode of testing rather than of the code.  `tests/test_voice_rust_parity.py` was written to catch the Rust media-key derivation drifting from the Python one — and it did catch a real bug during development, a four-byte length prefix written as eight, which made every cross-implementation frame fail its tag with no error and no clue.  But once `VoiceFrameCrypto` began delegating to Rust, "seal with Python, open with Rust" became Rust against Rust: a mutation changed both sides identically and the reintroduced bug passed clean.  Found by mutation testing, not by reading.  The reference derivation is now rebuilt inside the test from `cryptography`'s HKDF with the length-prefix rule written out literally, so it cannot follow the code under test.  Ten of the thirty-five tests now fail on that mutant.


23. **The blue OTRv4+ marker in `/names` is client identification and is not authentication (v10.13.3).**  It comes from the realname ("gecos") the peer's own client sent in its IRC `USER` registration line, which the server relays verbatim in `RPL_WHOREPLY`.  CTCP VERSION is deliberately refused by this client, so that field is the only identification channel there is — and **nobody validates it**.  Any IRC user, running any client, can put `OTRv4+ 10.13.3` in their own gecos and appear blue; equally, an OTRv4+ user who overrides their realname will not.  The marker answers "is this peer likely to understand `/otr`" and nothing else.  It does not authenticate the peer, does not mark them trusted, does not satisfy TOFU, does not stand in for SMP verification, and does not enable voice.  The OTR DAKE is what authenticates a session, TOFU is what pins a persistent identity on XMPP, and SMP is what authorises a call — none of them consult this map, and `tests/test_irc_names_list.py` fails if any of them starts to (INV-20).  Selecting a blue entry in the pager is a shortcut for typing `/otr <nick>`; it starts a DAKE exactly like the typed command and confers nothing on its own.

24. **What `/sendfile` protects, and what it does not (v10.14.0).**  The file is encrypted with a fresh AES-256-GCM key generated inside Rust, wrapped under a key derived from the session's DAKE extra symmetric key, and every chunk is authenticated with the transfer id, the chunk index and a final flag in its AAD — so reordering, duplication, replay into another transfer and truncation all fail the tag.  A file is placed only after the chunk tags, the chunk count, both SHA-256 hashes and the on-disk size all verify, by atomic rename; any failure deletes the temporary file.  The remote filename can never select a directory, because the directory is fixed locally and only a sanitised basename comes from the offer.  **Three limits, stated plainly.**  First, once decrypted the file sits on disk protected by filesystem permissions and nothing else — the same limitation this document records for the identity and SMP stores, and `~/.otrv4plus/files/` is a private directory, not a vault.  Second, the offer's filename, sizes and hashes are claims by the sender: they are authenticated as *coming from that peer* by the OTR channel, and verified against what actually arrives, but a peer you have SMP-verified can still send you a file you did not want.  Third, this has been exercised against real DAKE-derived sessions in tests and has **never moved a file between two devices**; the transport is the OTR channel, so a large file will be slow.

## What "audit closed" means

`v10.6.3 - 11/11 audit findings closed` refers to the internal audit that drove the v10.5.x and v10.6.x development sequence. Findings were:

1. Private bytes extracted from DakeState into Python (closed at v10.6.3 via the opaque `DakeOutput` handle)
2. `is_initiator` hardcoded True in `consume_into_ratchet` (closed at v10.6.3)
3. Chain-key role-based swap done in Python before handoff (closed at v10.6.3)
4. Ratchet chain key reset bug after DH ratchet (closed in v10.6.0-ish)
5. SMP scalar arithmetic done in Python (closed at v10.5)
6. Argon2id KDF parameters too weak for SMP vault (recorded closed at v10.5 — **this record was wrong**; no Argon2 existed in the Rust core until v10.13.0, and the vault has never had a KDF.  See caveat 15.)
7. ML-KEM ciphertext byte order on the wire (closed at v10.5)
8. Fragment buffer collision when same nick sends two parallel fragmented messages (closed at v10.5)
9. SMP secret stored as Python `bytes` (closed at v10.5, now lives in `RustSMPVault`)
10. Skipped message keys not zeroized (closed at v10.5)
11. NIST SP 800-88r1 secure file destruction missing (closed at v10.5)

Phase 5.x changes since v10.6.3 are architectural hardening beyond audit scope. The audit count remains at 11/11 closed.
