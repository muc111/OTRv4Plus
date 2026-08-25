# OTRv4+ Android — Phase 1 Repository Audit & Architecture Proposal

> **Status note (v10.12.0) — historical audit, findings not retracted.** Test
> counts below (`45 passed` for Rust, the Python baselines) are from the date of
> this audit; the current figures are 65 Rust and 1431 Python passed. The
> architectural findings stand. Note also that this audit predates the voice
> subsystem's arrival, so its account of the cryptographic surface — "everything
> in Rust" — does not cover `otrv4plus_voice.py`, which uses the Python
> `cryptography` library for the media AEAD, the HKDF-SHA512 voice key schedule
> and the voice X448 (see [SECURITY.md](SECURITY.md) caveat 11).


**Status:** Phase 1 deliverable. No cryptographic code was modified. Awaiting approval before
any architectural change.
**Date:** 2026-08-17
**Scope:** Audit of the existing OTRv4+ Python/Rust codebase as the engine for a commercially
distributable Android application, per the Android Product & Security Specification §22.

---

## 0. Executive summary

The existing codebase is in better shape for this than expected. The Rust core is clean,
self-contained, builds without warnings, and passes its full test suite. The security boundary
it advertises — secrets live in Rust, Python never sees them — is real and is enforced by the
type system rather than by convention. **That boundary should be preserved exactly as it is.**

The work is therefore *not* a crypto port. It is:

1. Extracting a **headless application core** out of a monolithic terminal client.
2. Deciding **how CPython runs inside an APK**.
3. Replacing a **plaintext-on-disk storage layer** with Keystore-backed AES-256-GCM.
4. Building the Android presentation layer on top of a small typed API.

Three items block the plan and need a product decision from you before Phase 2. They are set
out in §14.1 and summarised here:

| # | Blocker | Why it blocks |
|---|---|---|
| **B1** | **Identity is ephemeral by deliberate design.** Fingerprints regenerate every launch. | The spec's Contacts (§11), SMP verification (§13) and Identity (§15) screens all assume a stable long-term identity. As built, "Contact verified ✓" cannot survive an app restart. |
| **B2** | **No decision on how Python runs on Android.** Termux is the only supported host today. | Termux cannot be shipped as a consumer APK. Everything downstream depends on this choice. |
| **B3** | **Voice requires a local I2P router** (SAM API on `127.0.0.1:7656`). | A consumer app cannot assume the user has i2pd installed and running. |

### Build and test baseline (established during this audit)

The `AUDIT_HANDOFF.md` warned that the Rust changes shipped **unbuilt** and untested. That is no
longer true — I built and ran everything:

| Suite | Command | Result |
|---|---|---|
| Rust core | `cargo test` | **45 passed, 0 failed** (36.8s) |
| Rust release wheel | `maturin build --release` | **Built OK**, abi3 ≥ 3.9, 49.8s |
| Python import gate | `import otrv4_core` | **OK** — all 20 required symbols present |
| Python suite | `pytest tests/` | See Appendix B |

The `AUDIT_HANDOFF.md` §9 release gates 1 and 2 (`ring_sig` nonce-reuse test, SMP KATs under the
new subgroup check) both pass. Toolchain floor `rust-version = "1.85"` is accurate.

**New finding: `otrv4+.py` requires Python 3.12 or newer.** It does not parse on 3.11 or earlier:

```
otrv4+.py:4268:  raise ValueError(f"Key component empty or too long: {s !r }")
                 SyntaxError on 3.11: f-string: expecting '}'
```

The codebase uses a `{expr !r }` spacing style throughout that is only legal under **PEP 701**
(Python 3.12+). This is undocumented — `Rust/pyproject.toml` declares `requires-python = ">=3.9"`,
which is wrong for the application layer. It directly constrains the runtime choice in §12: the
embedded interpreter **must be 3.12+**. Verified: parses and runs clean on 3.12.3.

**Second finding: `tests/test_otrv4_integration.py` is stale and blocks collection.** It imports
`OTRv4DAKE`, which was deleted at v10.7 when the pure-Python DAKE was removed:

```
ImportError: cannot import name 'OTRv4DAKE' from 'otrv4_'
```

Because a collection error is fatal to the run, this single dead module prevents the **entire
`tests/` suite** from executing unless explicitly ignored. Low severity and a trivial fix, but it
means the protocol suite has not been run as a whole in some time. Recommend deleting or rewriting
it in Phase 2 so the suite is usable as a regression gate for the Android work.

---

## 1. Current architecture

### 1.1 Layer map (as built)

```
┌──────────────────────────────────────────────────────────────┐
│ TERMINAL UI                                                  │
│ otrv4plus_tui.py (1.1k) · Screen/PanelManager/ChatPanel      │
│ in otrv4+.py · raw-mode termios · ANSI colour · slash cmds   │
├──────────────────────────────────────────────────────────────┤
│ TRANSPORT + CLIENT (monolithic)                              │
│ otrv4plus_xmpp.py (4.1k)  OTRv4PlusXMPP(ClientXMPP)          │
│ otrv4+.py         (13.8k) OTRv4IRCClient / Enhanced…         │
│ weechat_otrv4plus.py (0.9k) WeeChat plugin                   │
│ I2P SAM bridge · SOCKS5 · fragmentation · roster · rate-limit│
├──────────────────────────────────────────────────────────────┤
│ APPLICATION / SESSION LAYER  ← the reusable part             │
│ EnhancedSessionManager · EnhancedOTRSession · SessionManager │
│ RustDAKEAdapter · ClientProfile · TrustDatabase              │
│ SecureKeyStorage · SMPAutoRespondStorage · OTRTracer         │
├──────────────────────────────────────────────────────────────┤
│ VOICE                                                        │
│ otrv4plus_voice.py (3.9k) VoiceCallManager/Session/KeySched  │
│ otrv4plus_audio.py (1.2k) AAudio (Android!) + PulseAudio     │
├──────────────────────────────────────────────────────────────┤
│ RUST CORE — otrv4_core (PyO3, 6.4k lines, 15 modules)        │
│ #![forbid(unsafe_code)] · ZeroizeOnDrop · SecretBytes<N>     │
│ dake · smp · smp_vault · ratchet · ring_sig · key_handles    │
│ aead · kdf · mlkem · mldsa · secure_mem · header             │
├──────────────────────────────────────────────────────────────┤
│ AUDITED-BY-REPUTATION CRATES (not reviewed)                  │
│ ed448-goldilocks-plus · x448 · pqcrypto-mlkem/mldsa          │
│ aes-gcm · sha3 · crypto-bigint · zeroize · subtle            │
└──────────────────────────────────────────────────────────────┘
```

### 1.2 What is genuinely good

- **`#![forbid(unsafe_code)]` holds.** No `unsafe` anywhere in the crate.
- **Secrets are structurally unreachable from Python.** `Ed448KeyHandle` exposes only
  `public_bytes()`, `sign()`, `ring_sign()`. The private seed has no PyO3 accessor.
  `DakeOutput` moves session keys Rust→Rust via `consume_into_ratchet()`; they are never
  marshalled into `PyBytes`.
- **The `test-only-kdf` Cargo feature** gates the read-back paths that *would* let Python
  extract vault secrets. It is off by default (see §14.4 for a hardening item here).
- **Fail-closed import gate.** `_check_rust_requirements()` (otrv4+.py:70) raises `ImportError`
  at import time if any of 6 `RustDAKE` methods or 13 module symbols are missing. There is no
  silent Python-crypto fallback — the pure-Python DAKE was deleted at v10.7.
- **Voice state machine is explicit.** `CallState.ALLOWED` (otrv4plus_voice.py:1040) is a full
  transition table with `ENDED` as an absorbing state, and `transition()` enforces it.
- **Two-phase rekey commit.** `VoiceKeySchedule` derives a pending epoch and only destroys the
  current root after the peer's confirmation verifies — a failed rekey does not kill a live call.
- **Decrypt authenticates before mutating ratchet state** (v10.11.1). Both `decrypt_same_dh` and
  `decrypt_new_dh` derive into scratch, verify the tag, then commit.

### 1.3 What is structurally in the way

- **`otrv4+.py` is 13,818 lines in one file** and mixes constants, crypto adapters, session
  management, a trust database, an ANSI terminal renderer, a pager, a tab bar, and two IRC client
  classes. The session layer is reusable; it is not currently *separable*.
- **`print()` is globally shadowed.** `otrv4plus_xmpp.py:307` replaces the builtin so every output
  line is routed to the TUI *and* appended to an encrypted channel log. UI state is inferred by
  **substring-matching printed English text** (`_latch_smp_from_trace`, `_tui_route_output`
  matching `"SMP VERIFIED"`). This is the single largest refactor item — an Android UI cannot
  scrape terminal strings.
- **`OTRv4PlusXMPP.__init__` builds everything**: OTR engine, thread pool, XEP plugins, event
  handlers, voice manager, channel log, and registers itself in a module global `_ACTIVE_CLIENT`.
  There is one instance per process and it assumes it owns stdout.

---

## 2. Python/Rust boundaries

### 2.1 The boundary as it stands

| Direction | What crosses | Secret? |
|---|---|---|
| Py → Rust | passphrases (into `RustSMPVault.store`), wire bytes, public keys, AAD | secret in, one-way |
| Rust → Py | public bytes, wire frames, booleans, phase strings, opaque handles | **no secrets** |
| Rust → Rust | `DakeSessionKeys` → ratchet `SecretBytes` via `consume_into_ratchet()` | never touches Python |

### 2.2 Where orchestration lives — important

Per `AUDIT_HANDOFF.md` §2 and confirmed by reading the source:

> **The DAKE is ORCHESTRATED in Python.** `DakeState::process_dake3` exists in Rust but is *not*
> on the live path; Python does DAKE3 verification itself.

This matters enormously for the Android plan. `RustDAKEAdapter` (otrv4+.py:3489, ~600 lines) and
`EnhancedSessionManager._handle_dake1/2/3` contain **security-critical sequencing logic** — profile
signature verification, the ML-DSA-mandatory downgrade check (fix H2), the profile-binding abort
(fix H3/PY1), and DAKE glare tie-breaking.

**Consequence:** rewriting the orchestration in Kotlin would mean re-implementing verified
security logic in a language with no test coverage for it. Spec §17 and §19 forbid exactly this.
**The Python orchestration layer must ship on Android.** This is the load-bearing constraint
behind the runtime recommendation in §12.

### 2.3 Leaks across the boundary that remain

- **M3 (from the prior audit, still open):** legacy Rust DAKE methods that hand session keys to
  Python as `PyBytes` are still present as a fallback path. Decide whether to remove or gate them
  *before* the Android release, not after.
- **`SMPEngine` compat shim** (`smp_engine_compat.py`) re-implements the Rust SMP KDF in pure
  Python (50,000-round SHAKE-256 chain) to expose a derived secret for test assertions. It is
  test-only and injected by `conftest.py`. **It must not be packaged into the APK.**

---

## 3. Existing public APIs

### 3.1 `EnhancedSessionManager` — the transport-agnostic core

This is the class the Android app should build on. It is already transport-independent: it takes
strings in and gives strings out, and knows nothing about IRC or XMPP.

```python
# Session lifecycle
get_or_create_session(peer, is_initiator=False) -> EnhancedOTRSession
has_session(peer) -> bool
has_encrypted_session(peer) -> bool
list_sessions() / list_encrypted_sessions() -> List[dict]
get_session_state(peer) -> dict | None
terminate_session(peer, reason) / clear_all_sessions(reason)
cleanup_expired_sessions(timeout=3600.0)

# Message path
handle_outgoing_message(peer, message) -> (payload | None, was_encrypted: bool)
handle_incoming_message(peer, message) -> bytes | None
encrypt_message(peer, plaintext) -> str | None
decrypt_message(peer, encrypted_msg) -> bytes

# DAKE
handle_dake1(peer, payload) -> str | None
handle_dake2(peer, payload) -> str | None
handle_dake3(peer, payload) -> bool

# SMP
start_smp(peer, secret, question="") -> str | None
set_smp_secret(peer, secret) -> bool
process_smp_message(peer, data: bytes) -> str | None
get_smp_status(peer) -> dict
get_smp_progress(peer) -> (current, total)

# Identity / trust
get_fingerprint() -> str
get_peer_fingerprint(peer) -> str | None
trust_fingerprint(peer, fingerprint) -> bool
is_peer_trusted(peer) -> bool
get_security_level(peer) -> UIConstants.SecurityLevel
display_fingerprints(peer) -> str
```

**Assessment: reusable essentially as-is.** This is the single most important finding in the audit.

### 3.2 `UIConstants` — ready-made UI state enums

`UIConstants.SecurityLevel`: `PLAINTEXT(0)`, `ENCRYPTED(1)`, `FINGERPRINT(2)`, `SMP_VERIFIED(3)`.
`UIConstants.SMPState`: `NONE`, `EXPECT1…4`, `SENT1…3`, `SUCCEEDED(8)`, `FAILED(9)`.

These map cleanly onto the spec §11 contact badges. See §10.3 for the proposed mapping.

---

## 4. Existing crypto APIs (`otrv4_core`)

Confirmed present in the built wheel:

| Symbol | Kind | Notes |
|---|---|---|
| `Ed448KeyHandle` | class | `public_bytes()`, `sign(msg)→114B`, `ring_sign()→228B`. Wraps `SecretBytes<57>`, ZeroizeOnDrop. No private accessor. |
| `X448KeyHandle` | class | `public_bytes()`, `dh()`. Wraps `SecretBytes<56>`. |
| `generate_ed448_keypair()` / `generate_x448_keypair()` | fn | Generated **inside Rust**; seed never observed from Python. |
| `verify_ed448_sig(pub, msg, sig)` | fn | Pure Ed448 (RFC 8032 §5.2, empty context). Returns `false` for bad sig, raises only on malformed length. |
| `aes256gcm_encrypt/decrypt(key, nonce, pt, aad)` | fn | Returns `ct‖tag`. **Stateless — nonce uniqueness is the caller's obligation** (issue M4). |
| `mlkem1024_keygen/encaps/decaps` | fn | FIPS 203 ML-KEM-1024. Note: binding normalises `(ct, ss)` ordering vs pqcrypto's `(ss, ct)`. |
| `mldsa87_keygen/sign/verify` | fn | FIPS 204 ML-DSA-87. |
| `py_ring_sign` / `py_ring_verify` | fn | 1-of-2 Ed448 ring signature (deniable auth). |
| `RustDAKE` | class | DAKE state; `sign_profile_body_and_construct_with_handles` etc. |
| `RustSMP` | class | `generate_smp1` … `process_smp4`, `is_verified()`, `get_phase()`. |
| `RustSMPVault` | class | `store(name, bytes) → u64 handle`. Read-back gated behind `test-only-kdf`. |
| `RustDoubleRatchet` | class | Opaque handle; keys never reach Python. |

**Reuse verdict: 100% reusable, zero changes.** Do not touch this layer.

---

## 5. Existing voice-call APIs

### 5.1 Control surface — `VoiceCallManager` (otrv4plus_voice.py:2801)

```python
VoiceCallManager(xmpp_client, loop, sam_host="127.0.0.1", sam_port=7656)

await start_call(peer) -> bool
await answer_call(peer)
await reject_call(peer)
await end_call(peer, notify_peer=True)
toggle_mute(peer)
has_active_call(peer=None) -> bool
any_active_peer()
status_line() -> str
await handle_signal(peer, body)     # inbound VOICE signalling
await cleanup() / cleanup_sync()
```

### 5.2 State machine — `CallState`

`IDLE → INVITING|RINGING → CONNECTING → KEY_CONFIRMING → MEDIA_CONNECTING → ACTIVE → ENDING → ENDED`

This maps **1:1** onto the spec §14 call UI states (incoming / outgoing / connecting / connected /
ended). No new state machine is needed — the UI should be a pure projection of `CallState`.

### 5.3 Security gate worth preserving

`VoiceCallManager._smp_verified(peer)` gates calls on the engine's cryptographic predicate. The
code comments explicitly note that the display-hint set (`_smp_display_hints`, populated by
substring-matching printed text) must **never** be used for this decision. Preserve that
separation exactly when the UI is rewritten — the Android UI will have its own display state, and
it must not become the gate.

### 5.4 Transport constraint — **Blocker B3**

Media rides a **single full-duplex I2P SAM TCP stream** (`otrv4plus_voice.py:1876–1990`),
requiring a SAM bridge at `127.0.0.1:7656`. Signalling goes over XMPP message bodies parsed by
`parse_signal()`. Crypto: X448 + ML-KEM-1024 hybrid → HKDF → per-epoch AES-256-GCM with
`media_nonce(epoch, counter)`, replay window, Opus 16 kHz/20 ms, jitter buffer, two-phase rekey.

**The crypto and framing are transport-agnostic; only the socket acquisition is I2P-specific.**
`bind_host()` (otrv4plus_voice.py:206) already exists as an injection seam for `sam_open`,
`sam_read_line`, `sam_parse`, `sam_release`. That seam is how Android supplies its own transport.

### 5.5 Audio backend — a significant free win

`otrv4plus_audio.py` **already has an AAudio backend** (`_load_aaudio()` at line 262) that
`ctypes.CDLL`s `libaaudio.so` and binds `AAudio_createStreamBuilder` with correct 64-bit
`restype`s. `open_capture()`/`open_playback()` select AAudio first, PulseAudio second, and never
fall back *silently* (the code notes that a silent demotion would "encrypt and transmit silence
while reporting a healthy call").

In a real APK this works unchanged — it is an ordinary Android process with `libaaudio.so`
available. The `MICROPHONE_PERMISSION_DENIED` error code already propagates correctly and refuses
to try another backend, which is exactly right for a manifest-permission failure.

**Only the PulseAudio/Termux path (`pulseaudio` subprocess, `termux-microphone-record`) becomes
dead code.**

---

## 6. Existing XMPP APIs

`OTRv4PlusXMPP(ClientXMPP)` — slixmpp-based, 2,400 lines. Reusable methods:

```python
send_user_text(peer, text)      send_otr(peer, payload)      send_plain(peer, text)
send_otr_fragmented(peer, payload)
start_otr(peer)                 smp_start(peer, secret=None)  store_smp_secret(peer, secret)
roster_list() / roster_add(jid) / roster_remove(jid)
accept_subscription(jid) / deny_subscription(jid)
block_peer(jid) / unblock_peer(jid)     ping_peer(jid)
show_status(peer)               cleanup()
```

XEPs registered: 0030 (disco), 0085 (chat states — gives spec §12 typing indicators for free),
0115 (caps), 0184 (delivery receipts — gives §12 delivery state for free), 0198 (stream
management, degrades gracefully), 0199 (ping).

**Security properties already implemented and worth keeping:** subscription requests are never
auto-approved (`auto_authorize=False`, `auto_subscribe=False`, queued for explicit accept/deny);
per-peer inbound rate limiting (20 msgs / 5 s); bounded fragment reassembly with per-peer caps;
SMP secret length validation (8–512 chars); session-local block list; I2P-aware reconnect with
exponential backoff.

**What must be separated:** the same class also owns the TUI, the raw-mode terminal, slash-command
dispatch (`dispatch_line`, ~330 lines), panel routing, and the global `print()` shadow. Roughly
**40% of this file is terminal UI** and does not belong on Android.

---

## 7. Existing DAKE / SMP APIs

### 7.1 DAKE

`RustDAKEAdapter` (otrv4+.py:3489) drives the three-message handshake:

```python
generate_dake1() -> str        process_dake1(msg, peer_key) -> bool
generate_dake2() -> str|None   process_dake2(msg) -> bool
generate_dake3() -> str|None   process_dake3(msg) -> bool
state / is_established() / has_failed() / is_session_expired()
get_session_keys() -> dict|None       # legacy fallback path — see M3, §2.3
```

`DAKEState`: `IDLE → SENT_DAKE1 / RECEIVED_DAKE1 → SENT_DAKE2 → ESTABLISHED | FAILED`.
Timeout `DAKE_TIMEOUT = 120.0s`. Rate-limited by `DAKE1RateLimiter` (otrv4+.py:3449).

Measured performance (README, live-tested): **DAKE completes in under 20 s over XMPP/I2P.**
Acceptable for a mobile UX with a progress indicator.

### 7.2 SMP

Hybrid PQ SMP (v10.9.1): classical Schnorr ZKP over the RFC 3526 3072-bit MODP group, running
alongside ML-KEM-1024 encapsulation and per-step ML-DSA-87 signatures bound by
`pq_binding_key = KDF(kem_ss ‖ transcript_tag)`. Wire version `0x02` — a downgrade to classical is
not silent.

**UX-critical performance facts:**

- SMP secret derivation is a **50,000-round SHAKE-256 chain** — deliberately slow.
- SMP1 grows to ~8.1 KB, SMP2 to ~16.4 KB (ML-KEM + ML-DSA material).
- The XMPP client runs SMP on a **dedicated 2-worker thread pool** because "SMP runs multi-minute
  3072-bit DH computations; a separate pool keeps the event loop free."
- Measured: **~1 minute** to SMP-verified over XMPP/I2P. (Over IRC/I2P it is ~15 minutes.)

**Implication for spec §13:** verification is a **minutes-long background operation on mobile**,
not a modal spinner. `get_smp_progress(peer) → (current, total)` already exists and must drive a
real progress UI, with the work continuing in a foreground Service if the user leaves the screen.

---

## 8. Existing storage and key management

This is the weakest area and the one requiring the most Android work.

| Component | File | Location | Encryption | Key protection | Verdict |
|---|---|---|---|---|---|
| `SecureKeyStorage` | otrv4+.py:4130 | `~/.otrv4plus/keys/*.bin` | AES-256-GCM (Rust) | **Argon2id/scrypt over a plaintext `.device_seed` file (0600)** | ⚠️ Replace key protection. **Also currently unused** — see §8.1 |
| `SMPAutoRespondStorage` | otrv4+.py:4355 | `~/.otrv4plus/smp_secrets.json` | AES-256-GCM (Rust) | same plaintext device-seed pattern | ⚠️ Replace key protection |
| `TrustDatabase` | otrv4+.py:4510 | `~/.otrv4plus/trust.json` | **NONE — plaintext JSON** | n/a | ❌ **Must be encrypted** |
| `ChannelLogManager` | otrv4plus_log.py | `~/.otrv4plus/logs/channels/*.enc` | **Hand-rolled AEAD** | **plaintext `channel_log.key` (0600)** | ❌ **Must be replaced** |
| OTR identity keys | — | not persisted | n/a | n/a | See §8.1 |
| Ratchet / session state | — | memory only (Rust) | n/a | ZeroizeOnDrop | ✅ Correct |

### 8.1 Identity is not persisted at all — **Blocker B1**

`ClientProfile.__init__` (otrv4+.py:2424) documents it plainly:

> *"Keys are ALWAYS generated fresh - no saved profile file is consulted. This is intentional and
> correct for random/ephemeral IRC nicks: each session gets brand-new cryptographic identity."*

`EnhancedSessionManager._store_identity()` is now a **no-op** that only emits a trace line reading
`"identity stored (Phase 5.3b: no private material persisted)"`. `SecureKeyStorage` is
instantiated (otrv4+.py:7344) but nothing calls `store_key()` for the identity.

`ROADMAP.md` §"Phase 5.3g" records this as a **decided design choice**, with the rationale: the
threat model is short-lived I2P sessions; a persistent vault is a high-value offline-brute-force
target; Termux has no OS keyring.

**Two of those three rationales do not survive the move to Android:**

- *"Termux has no OS keyring"* → **Android has one.** Hardware-backed Keystore/StrongBox is
  exactly the missing piece, and the spec (§4, §6) mandates it.
- *"A persistent vault is a high-value offline-brute-force target"* → mitigated by the spec's own
  design: Argon2id + Keystore-wrapped DEK + rate limiting (§8) makes offline guessing infeasible
  without extracting a non-exportable hardware key.
- *"Short-lived sessions"* → **this is the genuine product conflict.** A consumer messenger with
  a contact list is not a short-lived session.

The ROADMAP already anticipates the resolution: *"`Ed448KeyHandle.from_seed_bytes()` and
`X448KeyHandle.from_priv_bytes()` already support reconstructing a handle from raw bytes — so an
external user-managed vault is possible without further code changes in OTRv4+ itself."*

**So this is implementable without modifying the cryptographic core.** But it is a reversal of a
documented security decision and it is your call, not mine. See §14.1 for the options.

### 8.2 The hand-rolled message-log AEAD

`otrv4plus_log.py:73` implements its own AEAD: SHAKE-256 keystream XOR + HMAC-SHA3-512 truncated
to 16 bytes. Spec §5 forbids exactly this ("Do not invent a cryptographic construction without
documenting and testing it") and §5's "Never use" list is violated by the plaintext key file.

It is not obviously *broken* — encrypt-then-MAC with domain separation and a random 96-bit nonce
per record — but there is no reason to keep a bespoke construction when `aes256gcm_encrypt` is
right there in the Rust core and already used by the other two stores. **Replace it.**

Note also that `print()` routes **every UI line** into this log, including full message bodies.
The separate session log (`_log_to_file`, otrv4plus_xmpp.py:292) *does* redact bodies
(`<message body redacted: N chars>`), but the channel log does not. On Android that is the
message database and it must live under the Keystore-wrapped DEK.

---

## 9. What can be reused directly

**Reuse unchanged (no modification):**

| Component | Lines | Why |
|---|---|---|
| Entire Rust core `otrv4_core` | ~6,400 | Builds clean, 45/45 tests pass, boundary is sound |
| `EnhancedSessionManager` / `EnhancedOTRSession` | ~2,200 | Already transport-agnostic |
| `RustDAKEAdapter` | ~600 | Contains verified DAKE sequencing (fixes H2/H3/PY1) |
| `ClientProfile`, `OTRv4TLV`, `OTRv4DataMessage`, `BinaryReader` | ~900 | Wire format |
| `VoiceCallSession`, `VoiceKeySchedule`, `VoiceFrameCrypto`, `JitterBuffer`, `ReplayWindow` | ~2,400 | Voice crypto + media pipeline |
| `otrv4plus_audio.py` **AAudio path** | ~400 | Already Android-native |
| `OTRFragmentBuffer` / `OTRMessageFragmenter` | ~330 | Bounded, hostile-input-tested |
| `UIConstants.SecurityLevel` / `SMPState` | — | UI state enums |
| XMPP protocol handling (`_on_message`, `_handle_otr_in_async`, roster, subscriptions, rate limiting) | ~1,200 | Security-hardened |

**Reuse with the key-protection layer swapped:** `SecureKeyStorage`, `SMPAutoRespondStorage`
(swap `.device_seed` → Keystore-wrapped DEK; the AES-GCM record format itself is fine).

**Do not ship:** all TUI code (`otrv4plus_tui.py`, `Screen`, `PanelManager`, `ChatPanel`,
`TabBar`, `Pager`, `DebugPanel`, raw-mode termios helpers), both IRC clients, the WeeChat plugin,
`_bootstrap_termux()` and every `pkg install`/`apt`/`pip install` subprocess helper, the
PulseAudio backend, the `print()` shadow, and `smp_engine_compat.py`.

---

## 10. What needs an Android bridge

### 10.1 New module: `otrv4plus_app.py` — headless application facade

A **new** Python module (no cryptography in it) that composes the existing pieces and exposes a
small typed, event-driven API. This is the *only* surface Kotlin talks to.

```python
class OtrApp:
    # lifecycle
    def start(self, config: dict) -> None
    def stop(self) -> None
    def connect(self, jid: str, credential_handle: int) -> None
    def disconnect(self) -> None

    # contacts
    def list_contacts(self) -> list[dict]        # jid, display, presence, sec_level, last_seen
    def add_contact(self, jid: str) -> None
    def remove_contact(self, jid: str) -> None
    def accept_subscription(self, jid: str) -> None
    def deny_subscription(self, jid: str) -> None

    # messaging
    def send_message(self, jid: str, text: str) -> str       # returns message_id
    def start_session(self, jid: str) -> None                # DAKE
    def list_messages(self, jid: str, before: int, limit: int) -> list[dict]

    # verification
    def smp_start(self, jid: str, secret: str, question: str = "") -> None
    def smp_respond(self, jid: str, secret: str) -> None
    def smp_abort(self, jid: str) -> None
    def smp_progress(self, jid: str) -> tuple[int, int]

    # identity
    def identity_info(self) -> dict              # fingerprint, created, verified_count
    def security_details(self, jid: str) -> dict # for the §10 advanced screen

    # calls
    def call_start(self, jid: str) -> None
    def call_answer(self, jid: str) -> None
    def call_reject(self, jid: str) -> None
    def call_end(self, jid: str) -> None
    def call_set_mute(self, jid: str, muted: bool) -> None

    # events → Kotlin (replaces the print() shadow entirely)
    def set_event_sink(self, sink) -> None
```

**Event types** (structured, never English prose): `ConnectionStateChanged`, `ContactPresence`,
`MessageReceived`, `MessageDelivered`, `TypingState`, `SessionStateChanged`, `DakeProgress`,
`SmpProgress`, `SmpResult`, `FingerprintChanged`, `CallStateChanged`, `CallStats`, `Error`.

`FingerprintChanged` is what drives the spec §11 "⚠ Security identity changed" badge — it comes
from `TrustDatabase.FingerprintMismatch`, which already exists.

### 10.2 New Rust module: `storage.rs` — Keystore-anchored at-rest crypto

**Additive only — does not modify any existing crypto module.** Spec §17 says secrets must not
cross into Kotlin as raw buffers, and §5 mandates a versioned authenticated record format.

```
Kotlin: Android Keystore (AES-256-GCM, hardware-backed / StrongBox if available)
          │  unwraps the wrapped DEK  (setUserAuthenticationRequired where configured)
          ▼
        JNI: hand the 32-byte DEK straight into Rust; zero the Kotlin ByteArray immediately
          ▼
Rust:   StorageKey (SecretBytes<32>, ZeroizeOnDrop) — returned to Python as an opaque u64 handle
          ▼
Python: storage.seal(handle, record_type, record_id, schema_ver, plaintext) -> bytes
        storage.open(handle, record_type, record_id, schema_ver, blob)      -> bytes
```

Record format (spec §5):

```
version(1) ‖ key_id(4) ‖ nonce(12) ‖ ciphertext ‖ tag(16)
AAD = version ‖ key_id ‖ record_type ‖ schema_version ‖ record_id
```

Nonce policy — this closes prior-audit issue **M4** rather than inheriting it: a per-key
**deterministic counter** persisted alongside the key (`key_id` increments on rotation, counter
resets), not `random(12)`. Random 96-bit nonces have a birthday bound that a message database
will approach; a counter does not. If a counter cannot be reliably persisted across process death,
rotate `key_id` on every process start instead.

### 10.3 Security-state mapping (spec §10/§11)

Never surface `X448/Ed448/DAKE/SMP` terminology on the primary screens:

| Engine state | Contact badge | Conversation banner |
|---|---|---|
| `SecurityLevel.PLAINTEXT` | ○ Not connected | "Not encrypted" |
| `SecurityLevel.ENCRYPTED` | ⚠ Identity not yet verified | "Encrypted — verify to confirm identity" |
| `SecurityLevel.FINGERPRINT` | ⚠ Identity not yet verified | (TOFU-pinned; still prompt to verify) |
| `SecurityLevel.SMP_VERIFIED` | ✓ Cryptographic identity verified | **"Connection verified ✓"** |
| `TrustDatabase.FingerprintMismatch` | ⚠ **Security identity changed** | Blocking interstitial |

Advanced screen (opt-in) shows: DAKE state, ring-sig ✓ / ML-DSA-87 ✓, ratchet epoch, ML-KEM-1024
brace-key rotation count, SMP wire version, full fingerprints, and the wording from spec §13
("Verified using Socialist Millionaires' Protocol (SMP)").

### 10.4 Also needs a bridge

- **Audio focus / routing** — `AudioManager`, earpiece↔speaker, Bluetooth SCO, `MODE_IN_COMMUNICATION`.
  `otrv4plus_audio.py` handles the *stream*, not Android call semantics.
- **Telecom integration** — `ConnectionService` so calls survive and interact with the system dialer.
- **Notifications** — high-priority full-screen intent for incoming calls; content-hiding message
  notifications.
- **Foreground Service** — required to hold XMPP presence and an in-progress SMP/call.
- **Doze / battery** — XMPP long-lived TCP under Doze needs a wake-lock strategy per call/handshake.
- **I2P transport** (Blocker B3) — see §14.1.

---

## 11. Recommended Android architecture

```
┌───────────────────────────────────────────────────────────────┐
│ PRESENTATION — Jetpack Compose, single Activity               │
│ CalculatorScreen (launcher, no branding)                      │
│ UnlockFlow · Onboarding · Home · Contacts · Conversation      │
│ CallScreen · Identity · Security · Settings                   │
│ NO CRYPTO. Reads immutable UiState. FLAG_SECURE on all        │
│ post-unlock screens.                                          │
├───────────────────────────────────────────────────────────────┤
│ APPLICATION / SECURITY — Kotlin                               │
│ AppLockManager   LOCKED→AUTHENTICATING→UNLOCKED→              │
│                  BACKGROUND_LOCK_PENDING→LOCKED               │
│ UnlockCredentialService  Argon2id → unwrap DEK (never a key)  │
│ KeystoreManager  DEK generation/wrapping, StrongBox probe,    │
│                  security-level diagnostics, key rotation     │
│ BiometricGate    BiometricPrompt bound to a Keystore Cipher   │
│ AttemptThrottle  counters + backoff, persisted encrypted      │
│ SecureStore      typed accessors over the Rust storage layer  │
│ OtrService       foreground Service; owns the Python runtime  │
├───────────────────────────────────────────────────────────────┤
│ BRIDGE — typed, narrow, no raw secrets                        │
│ Kotlin `OtrCore` interface  ⇄  Python `OtrApp` facade         │
│ Structured events only. Secrets cross as opaque handles.      │
├───────────────────────────────────────────────────────────────┤
│ PYTHON ORCHESTRATION — unchanged                              │
│ EnhancedSessionManager · RustDAKEAdapter · ClientProfile      │
│ VoiceCallManager · XMPP protocol layer (TUI stripped)         │
├───────────────────────────────────────────────────────────────┤
│ RUST — otrv4_core  (+ new additive storage.rs)                │
│ arm64-v8a, armeabi-v7a, x86_64                                │
└───────────────────────────────────────────────────────────────┘
```

### 11.1 Unlock flow (spec §4) — the credential is never the key

```
Calculator "1337" + ENTER
   → UnlockCredentialService.attempt(credential)
   → AttemptThrottle.check()                       ← rate limit BEFORE any KDF work
   → Argon2id(credential, salt, tuned params)      → KEK        [never stored]
   → AES-256-GCM unwrap of the Keystore-held wrapped DEK, with AAD
   → tag verifies?  ── no ──→ generic failure, increment counter, backoff
        │ yes
   → DEK handed to Rust over JNI → opaque handle; Kotlin buffer zeroed
   → AppLockManager → UNLOCKED
   → OtrService starts the Python runtime, opens encrypted stores
```

Properties this gives you: the unlock credential is **an authentication input**, not the
encryption key (§3); it is changeable by re-wrapping the same DEK under a new KEK, with **no
re-encryption of user data**; there is no stored plaintext comparison (§8); failure is a GCM tag
mismatch, which is indistinguishable across failure modes (§8 "no useful error differentiation");
and offline guessing requires the Keystore-held wrapping key, which is non-exportable.

**"1337" is a dev-only default seed value for the credential**, stored only as the Argon2id-derived
wrapping input. It never appears as a constant anywhere in the APK.

### 11.2 Recommended UI framework — Jetpack Compose

Recommending **Kotlin + Jetpack Compose** (Material 3), single-Activity, unidirectional data flow,
Hilt for DI, Compose Navigation.

Rationale: Compose makes the calculator disguise trivial (it is genuinely just a small Compose
screen — it should be a *real* working calculator, not a facade); it makes `FLAG_SECURE` and
lifecycle-driven relocking easy to apply globally; state-hoisting matches the event-stream bridge
naturally; and it avoids XML layout resources, which reduces the amount of APK-readable
configuration (§3). Views/XML would work but buys nothing here. Avoid Flutter/React Native — a
second FFI hop for a security-critical app is a liability, not a feature.

### 11.3 Threading model

`EnhancedSessionManager` uses `threading.RLock` with timeouts and the XMPP client already runs
SMP on a dedicated 2-worker `ThreadPoolExecutor`. Preserve that: **one Python thread owns the
asyncio loop; crypto runs on the existing executor; Kotlin calls are marshalled onto the loop and
return via the event sink.** Never block the Android main thread on a Python call — SMP takes
minutes and DAKE takes ~20 s.

---

## 12. Recommended Python runtime — **Blocker B2**

Because security-critical DAKE orchestration lives in Python (§2.2), CPython must ship in the APK.

| Option | Verdict |
|---|---|
| **Chaquopy** (recommended) | Gradle plugin, mature, first-class Kotlin↔Python interop, bundles CPython + native wheels per ABI, works with a normal Android Studio build and Play signing. Commercial licence required for closed-source apps — **budget for it**. |
| python-for-android / Briefcase | Designed to drive the *whole* app from Python; fighting it to get a Compose UI is the wrong shape. |
| Termux | Not distributable as a consumer APK. Development only. |
| Rewrite orchestration in Kotlin | **Rejected.** Re-implements verified security logic; violates spec §17/§19. |

**Consequences to plan for:** APK size grows materially (CPython + stdlib + `otrv4_core.so` +
`slixmpp` per ABI — expect 25–40 MB; use ABI splits or App Bundle); cold start pays interpreter
init (do it in the foreground Service, behind the unlock screen, so it is invisible); and
`slixmpp` + `aiodns` must build for all target ABIs — verify early, in Phase 2, not Phase 5.

### 12.1 Recommended project structure

```
OTRv4Plus/
├── Rust/                          # UNCHANGED + new additive storage.rs
│   └── src/storage.rs             # NEW: Keystore-anchored AES-256-GCM records
├── otrv4+.py, otrv4plus_*.py      # UNCHANGED core (TUI stripped at packaging)
├── android_bridge/                # NEW — Python, no cryptography
│   ├── otrv4plus_app.py           # OtrApp facade (§10.1)
│   ├── events.py                  # structured event types
│   ├── android_host.py            # bind_host() impl: AAudio + Android transport
│   └── storage_bindings.py        # thin wrapper over Rust storage.rs
├── android/                       # NEW — Gradle project
│   ├── app/                       # Compose UI, single Activity
│   ├── core-security/             # Keystore, Argon2id, lock lifecycle, throttle
│   ├── core-bridge/               # OtrCore interface + Chaquopy impl
│   ├── core-data/                 # encrypted repositories
│   ├── feature-calculator/        # disguise (a real calculator)
│   ├── feature-messaging/  feature-contacts/
│   ├── feature-calls/      feature-identity/  feature-settings/
│   └── build.gradle.kts
├── tests/                         # UNCHANGED Python suite
└── android/**/src/test|androidTest # NEW JVM + instrumented tests
```

---

## 13. Threat model (spec §18)

Split into the four categories the spec requires.

### 13.1 Protection of data at rest

| Threat | Mitigation |
|---|---|
| Device seized, filesystem imaged | All records AES-256-GCM under a DEK wrapped by a non-exportable Keystore key. Nothing decryptable off-device. |
| Offline brute-force of the unlock credential | Argon2id (params tuned by on-device measurement, §21 Phase 11) **plus** the Keystore wrapping key, which cannot leave the device. Attacker must break hardware isolation. |
| Malicious modification of local ciphertext | GCM tag + AAD binding record type, schema version, record id, key version. Rejected records surface as a security event, never as silently-empty data. |
| Nonce reuse | Per-key persisted counter (§10.2), not random. Explicit test (spec §20). |
| Downgrade of the record format | `version` byte is inside the AAD; older versions are readable, but a record cannot be re-labelled. |
| Android auto-backup exfiltration | `android:allowBackup="false"`, `android:fullBackupContent` exclusions, no `dataExtractionRules` opt-in. |

### 13.2 Protection of communication

**Inherited unchanged and unweakened** — this is the whole point of not touching the core: OTRv4+
DAKE (X448 + ML-KEM-1024 hybrid, Ed448 ring signature + ML-DSA-87), double ratchet with forward
secrecy and post-compromise security, SMP identity verification, TLS/I2P/Tor transports,
per-epoch AES-256-GCM for voice with replay windows.

The Android layer must **not** add a code path that can weaken this. Specifically: no
"compatibility mode", no plaintext fallback when the DAKE fails, and the call gate must keep
asking `_smp_verified()` rather than any UI state (§5.3).

### 13.3 Protection of application access

| Threat | Mitigation |
|---|---|
| Casual device inspection | Calculator disguise; no messaging/vault/OTRv4Plus branding pre-auth; launcher icon and label are a calculator. |
| Brute-forcing the unlock sequence | Attempt counter + exponential backoff, persisted encrypted so an app restart does not reset it. **No data destruction** without an explicit product decision (§8). |
| Shoulder-surfing / recents screen | `FLAG_SECURE` on every post-unlock screen; recents thumbnail suppressed; sensitive state cleared on `ON_STOP`. |
| App left unlocked | `BACKGROUND_LOCK_PENDING` with configurable timeout; DEK handle dropped and the Rust `SecretBytes` zeroized on relock. |
| Biometric bypass | `BiometricPrompt` bound to a Keystore `Cipher` that actually unwraps the DEK — **not** an `isAuthenticated=true` boolean (spec §9). `BIOMETRIC_STRONG` only. |

### 13.4 Protection against reverse engineering

**Stated honestly, per spec §18: a normal Android application cannot be made impossible to
reverse engineer.** An attacker with the APK can decompile the Kotlin, disassemble the `.so`, and
read the bundled `.py` sources (Chaquopy compiles to `.pyc`, which is trivially decompiled).

What is actually achievable, and what it is worth:

- **R8 + resource shrinking + obfuscation** — raises effort, does not stop a determined analyst.
- **No secrets in the APK at all** — this is the real defence, and it is fully achievable. Every
  key is either device-generated or Keystore-wrapped. There is nothing static to extract.
- **Root/emulator/debugger signals as telemetry, not gates** — never make security depend on them.
- **Play Integrity API** for server-side signals if a backend is ever added.
- **Key attestation** to verify hardware backing (spec §6 links the attestation docs).

The honest claim to make in marketing material: *"No cryptographic secret is stored in the
application package; keys are generated on-device and protected by hardware-backed key storage
where available."* Not *"the app cannot be reverse engineered."*

---

## 14. Security risks introduced by the Android layer

### 14.1 The three blockers, with options

**B1 — Ephemeral identity vs. a persistent contact list.**

| Option | Consequence |
|---|---|
| **(a) Persistent identity** *(recommended for the stated product)* | Enables Contacts, Identity, backup/recovery, durable "verified ✓". Requires storing the Ed448 seed under the Keystore-wrapped DEK via `Ed448KeyHandle.from_seed_bytes()` — **no crypto-core change**. Reverses ROADMAP 5.3g and creates the on-disk target that decision avoided. |
| (b) Keep ephemeral | Preserves the current threat model exactly. But spec §11/§13/§15 largely collapse: no stable fingerprint, verification does not survive a restart, "identity changed" is meaningless. This is a different product. |
| (c) Hybrid — user opt-in | Ephemeral by default, persistent identity behind an explicit informed opt-in (Briar's model, cited in the ROADMAP's own rationale). More work; defensible. |

I recommend **(a)** for a commercial consumer app, or **(c)** if you want to keep the current
threat model available. **This needs your decision — it changes Phases 4, 5, 6 and 7.**

**B2 — Python runtime.** Recommend **Chaquopy**; confirm the commercial licence is acceptable
before Phase 2, and validate `slixmpp`/`aiodns` build for all target ABIs in Phase 2.

**B3 — Voice transport.** Options: bundle an I2P router (large, complex, battery-hungry); require
the separate I2P for Android app and connect to its SAM port (simplest, but a hard dependency the
user must install); or add a direct/TURN transport behind the existing `bind_host()` seam
(smallest engineering change, but **weakens the metadata-privacy property** the I2P transport
provides, and must be presented honestly in the UI). **Needs your decision.**

### 14.2 New risks the Android layer creates

| Risk | Mitigation |
|---|---|
| **Secrets crossing Kotlin↔Python↔Rust** — every new boundary is a chance for a `String` copy that lands in a GC heap and then a crash dump | Secrets cross as opaque handles only. The single exception is the DEK on the JNI hop, which is zeroed immediately (§10.2). Never `String` — `ByteArray`/`bytes` only. Spec §17. |
| **Android logging** — `Log.d`, Logcat, Crashlytics, StrictMode can capture anything printed | Strip the `print()` shadow entirely. No logging framework in release. Crash reporting must exclude message content and all state. Explicit tests that logs contain no plaintext (spec §20). |
| **Rust `panic = "abort"`** kills the whole Android process, not just a call | This is a deliberate fail-closed choice in `Cargo.toml` and I would keep it — but it is a **remote-DoS surface** now that hostile input reaches it. Fuzz the parsers (prior audit §8.3) and treat process death as a handled state with a clean relock. |
| **Process death mid-handshake** — Android kills backgrounded processes freely | Foreground Service for active DAKE/SMP/calls; on restart, sessions are torn down cleanly, never resumed from partial state. |
| **Clipboard** — fingerprints/SMP secrets copied by the user | `FLAG_SECURE`, no auto-copy, `ClipDescription` sensitive flag, and never place an SMP secret on the clipboard. |
| **Keyboard IME** — third-party keyboards see everything typed, including the SMP secret | Not fully solvable. Use `IME_FLAG_NO_PERSONALIZED_LEARNING` and `textNoSuggestions` on secret inputs; document the residual risk. |
| **Screenshots / recents** | `FLAG_SECURE` on all post-unlock windows. |
| **Multi-window / accessibility services** | Detect and warn; accessibility services can read the UI by design. Document it. |
| **Backup** | `allowBackup=false`. Any user-driven identity export must be independently passphrase-encrypted (spec §15). |

### 14.3 Pre-existing issues inherited (from `AUDIT_HANDOFF.md`)

These are the prior audit's open items. They do not block Phase 2 but should be scheduled:

- **M3** — legacy Rust DAKE methods returning session keys as `PyBytes` are still present as a
  Python fallback. **Decide before release**: remove, or gate behind a feature flag.
  **Gated.** The five `Dakeresult` session-key getters are compiled out unless
  `legacy-dake-keys` is enabled, `build.rs` refuses that feature without an explicit opt-in
  environment variable, and the Python fallback that reads them is unreachable because
  `_check_rust_requirements()` hard-requires `generate_dake2_output` / `process_dake2_output`
  at import. Verified against the built artifact, not only the source: the production `.so`
  contains no `__pymethod_get_root_key__` / `chain_key_a` / `chain_key_b` / `brace_key` /
  `mac_key` symbols, and `Dakeresult` is not registered on the module, so Python cannot obtain
  or construct one. The corresponding *setters* are still compiled in; they are write-only,
  guarded by the consumption check, and unreachable for the same reason, so they were left
  alone rather than churned.
- **M4** — stateless AEAD, caller-owned nonce uniqueness. The new `storage.rs` counter design
  (§10.2) closes this *for storage*; the wire path is unchanged.
- **L1** — MAC-key revelation. **Re-scoped, not closed.** The mechanism is implemented,
  integrated into the ratchet and tested end to end against the real reveal queue; formal
  deniability is a protocol-level property with no proof offered and is **not claimed**. The
  four claims are separated in `MAC_FIX_REVIEW.md` §13.4. Do not use "deniable" in marketing
  material until a cryptographic review says otherwise.
- **Transport/framing layers were never professionally audited** — the prior audit names this as
  the #1 target ("historically where this codebase's bugs have appeared"). The Android app puts
  this code in front of far more users.
- **Wire-format-locked**: ring challenge uses a 57-byte reduction with ~2⁻¹⁰ bias (cosmetic); the
  optional ML-DSA key is detected by leftover length rather than an explicit flag. A versioned
  wire revision should fix both — best done **before** a public release, since afterwards it
  becomes a compatibility break. Note that the data-message revision has since moved to
  `0x0005` for the MKmac fix (`MAC_FIX_REVIEW.md` §13.1); if these two are to be fixed in a
  wire revision, that break has already been taken and doing them now costs nothing extra.
  The ClientProfile/DAKE version deliberately stayed at `0x04`, so a profile-format change
  would still be a separate, additional break.

### 14.4 Build-hardening item found during this audit

`Rust/Cargo.toml` documents in a comment that `test-only-kdf` + `extension-module` together would
produce *"a shippable wheel with the test gates open"* — i.e. Python could read SMP vault secrets.
The comment even contains the fix, but it was **never added to `lib.rs`**:

```rust
#[cfg(all(feature = "test-only-kdf", feature = "extension-module"))]
compile_error!("test-only-kdf exposes SMP vault secrets to Python and must never be \
                combined with extension-module");
```

Right now only a comment prevents that build. For a release pipeline that is not enough.

**However — the two comments in `Cargo.toml` are in tension, and the test run proved it.** A few
lines above the proposed guard, the same file documents the *supported* way to run the Python-side
internals tests:

```
cargo build --release --features extension-module,test-only-kdf
```

That is precisely the combination `compile_error!` would forbid. Adding the guard verbatim would
make those tests **unrunnable**, not merely inconvenient. Confirmed empirically: on a production
build (gates closed), `tests/test_harness_audit.py` and `tests/test_rust_security.py` fail with
`AttributeError: 'RustSMPVault' object has no attribute 'load'` — which is the gate *working
correctly*, but it means those tests genuinely require the forbidden build.

So this needs a slightly better answer than pasting the comment in. Options:

- **(i) Guard the release path only** — key the `compile_error!` off a `release-build` feature or a
  build-script check for a `RELEASE=1` environment marker, so CI release jobs cannot open the gates
  but a developer can still build the test wheel. *Recommended.*
- **(ii) Add the guard as written** and delete or rewrite the vault read-back tests to assert the
  gate is closed rather than to read secrets back. Strictly safer; loses the internals coverage.
- **(iii) Leave it and enforce in CI** — assert the shipped `.so` has no `load` symbol as a release
  gate. No crate change at all, but the protection lives outside the compiler.

Whichever you pick, the current state — a comment as the only control — should not survive to
release. This touches the Rust crate, so it needs your go-ahead.

**Resolved: option (i), plus (iii) as a second control.** `Rust/build.rs` refuses to build with
`test-only-kdf` unless `OTRV4PLUS_ALLOW_TEST_GATES=1`, and with `legacy-dake-keys` unless
`OTRV4PLUS_ALLOW_LEGACY_DAKE_KEYS=1`. `tests/test_release_guard.py` then asserts against the
artifact that is actually installed, so a gate-open wheel built elsewhere is caught too.

**Re-confirmed at the artifact level.** Three wheels were built from this tree and inspected as
binaries rather than through the source or the module's registration table:

| Build | `from_seed_bytes` / `from_priv_bytes` | `Dakeresult` getters, `get_session_keys` | .so size |
|---|---|---|---|
| production (`pq-rust,extension-module`) | absent | absent | 1,233,136 |
| `+test-only-kdf` (opt-in set) | **present** | absent | 1,247,392 |
| `+legacy-dake-keys` (opt-in set) | absent | **present** | 1,249,704 |

Both opt-in features fail the build outright when their environment variable is unset
(`build.rs:53` and `build.rs:93` panic).

The gate was checked in both directions, which matters more than the passing case: with the
internals-test wheel installed and no opt-in variable set, the production assertions **fail**
(`test_production_artifact_exposes_no_seed_injection`,
`test_production_artifact_exposes_no_vault_readback`,
`test_production_object_file_contains_no_gated_symbols`); with the legacy wheel, the M3 assertions
fail. So the guard is not vacuous — it distinguishes the artifacts it claims to distinguish.

`test_production_object_file_contains_no_gated_symbols` was added in this pass. Every other
assertion in that file asks Python what the module exposes, which goes through the module's
registration table: a gated entry point compiled in but left unregistered would pass all of them.
Reading the object file closes that gap. One entry point is in exactly that state today —
`kdf::kdf_1_py` is `#[cfg(feature = "test-only-kdf")]` but is never registered in `lib.rs`, so it
is unreachable from Python in *every* build, including the internals-test one.

A `Dakeresult` skip was also turned into an assertion: it reported "skipped" when the type is not
exported, which reads in CI as "not checked" rather than "cannot happen".

---

## 15. Phased implementation plan

Mapped to the spec §21 phases, with an explicit exit gate on each. **Nothing proceeds past a
failing gate without being reported first.**

| Phase | Work | Exit gate |
|---|---|---|
| **1. Audit** ✅ | This document. Rust built, 45/45 pass; wheel builds; Python baseline established. | **Complete — awaiting approval + B1/B2/B3 decisions.** |
| **2. Shell** | Gradle project, module skeleton, Chaquopy integration, `slixmpp`/`aiodns`/`otrv4_core` building for arm64-v8a + armeabi-v7a + x86_64. Land the §14.4 `compile_error!`. | App launches on device; `import otrv4_core` succeeds **on-device**; `cargo test` still 45/45. |
| **3. Calculator + unlock prototype** | Real working calculator; hidden sequence; `AppLockManager` states; Argon2id; throttle. No real data yet. | Calculator arithmetic tests pass; unlock succeeds/fails correctly; throttle backoff verified; no credential in logs. |
| **4. Keystore + AES-GCM storage** | `KeystoreManager` (StrongBox probe, graceful degradation), new Rust `storage.rs`, versioned records, nonce counter, key rotation, diagnostics. | Round-trip; corrupted-ciphertext rejection; AAD-mismatch rejection; nonce uniqueness across 10⁶ records; rotation; Keystore-failure paths; survives reboot. |
| **5. OTRv4+ integration** | `otrv4plus_app.py` facade; strip TUI; remove `print()` shadow; event sink; foreground Service; migrate the three stores onto Keystore-backed storage. **Depends on B1.** | Live DAKE between two devices; existing `tests/` suite still passes unchanged; zero plaintext in Logcat. |
| **6. Contacts + messaging UI** | Compose contact list, conversation, bubbles, delivery state (XEP-0184), typing (XEP-0085), encrypted message store. | Send/receive over XMPP; message DB encrypted at rest; `FLAG_SECURE` verified; relock clears UI state. |
| **7. DAKE/SMP UX** | Verification flow, progress UI driven by `get_smp_progress`, verified badges, advanced security screen. | SMP completes device-to-device; progress accurate; secrets absent from logs/crash reports. |
| **8. Voice** | `bind_host()` Android impl, AAudio wiring, call UI as a projection of `CallState`, audio focus, Telecom, call notifications. **Depends on B3.** | Two-way call between devices; mid-call rekey; `authfail=0 replay=0 resync=0`. |
| **9. Hardening** | R8, `allowBackup=false`, FLAG_SECURE audit, clipboard/IME, key attestation, resolve M3, parser fuzzing. | Security review of the diff; fuzz harnesses run clean. |
| **10. Automated testing** | Full spec §20 matrix, including process-death, reboot, backup/restore, and the explicit "no secrets in logs" tests. | All green; coverage reported on every security boundary. |
| **11. Performance** | **Measure Argon2id params on real devices** (spec §4 requires measured, not arbitrary). Cold start, SMP under Doze, call latency/battery. | Argon2id params chosen from measurement on a low-end device; documented. |
| **12. Release + polish** | Signing, Play Bundle, ABI splits, final UX pass, honest security documentation. | Release build verified; no `test-only-kdf`; no debug symbols; reproducible build. |

---

## Appendix A — Files inspected

`otrv4+.py` (13,818) · `otrv4plus_xmpp.py` (4,067) · `otrv4plus_voice.py` (3,858) ·
`otrv4plus_audio.py` (1,241) · `otrv4plus_tui.py` (1,119) · `weechat_otrv4plus.py` (871) ·
`otrv4plus_log.py` (280) · `smp_engine_compat.py` (249) · all 15 `Rust/src/*.rs` (6,462) ·
`Rust/Cargo.toml` · `conftest.py` · `tests/conftest.py` · 13 test modules (5,200) ·
`README.md` · `SECURITY.md` · `AUDIT_HANDOFF.md` · `ROADMAP.md` · `DEVELOPMENT.md` · `SPEC.md`

## Appendix B — Test baseline, measured

All figures below were produced during this audit on Python 3.12.3 / Rust 1.85+, x86_64.

| Suite | Config | Result |
|---|---|---|
| `cargo test` (Rust core) | default features | **45 passed, 0 failed** — 36.8s |
| `maturin build --release` | `pyo3/extension-module` | wheel builds; imports; 20/20 required symbols |
| `test_voice_security.py`, `test_audio_backend.py`, `test_voice_audio_integration.py` | production wheel | **210 passed, 0 failed** — 5.2s |
| `tests/` | production wheel (gates closed) | 245 passed, **26 failed** — 336s |
| `tests/` | `test-only-kdf` wheel (gates open) | 248 passed, **23 failed** — 173s |
| `tests/test_otrv4_integration.py` | any | **collection error** — excluded from the runs above |

### B.1 The failures are harness rot, not cryptographic regressions

Every failure investigated traces to a test that was **never updated for the v10.7 "Rust-core-only"
migration**. Three distinct causes, all on the test side:

```
AttributeError: 'RustSMPVault' object has no attribute 'load'
  → the test-only-kdf security gate working exactly as designed.
    Accounts for the 26 → 23 delta. Not a defect.

AttributeError: 'cryptography...Ed448PrivateKey' object has no attribute 'ring_sign'
  → tests build keys with the `cryptography` library and pass them where a Rust
    Ed448KeyHandle is now required. `cryptography` was removed from runtime at v10.7.

AttributeError: module 'otrv4_' has no attribute 'OTRv4DAKE'
  → the pure-Python DAKE was deleted at v10.7. Same cause as the stale module.

TypeError: argument 'dk': 'bytearray' cannot be converted to 'PyBytes'
  → PyO3 signatures tightened to `bytes`; tests still pass `bytearray`.
```

**Conclusion:** the Rust core is healthy — its own 45 tests pass, and the 210 voice/audio tests
(written after the migration) pass in every configuration. The rot is confined to the **older
Python protocol tests**, roughly **10% of that suite**, plus one module that cannot even be
collected.

This matters for the Android work specifically. Spec §19 requires identifying the existing tests
and §20 requires a full regression matrix; the suite the Android integration will lean on as its
"did I break the engine?" gate is currently ~10% non-functional and cannot be run as a whole
without an `--ignore` flag. **Recommend repairing it in Phase 2**, before any integration work
starts — otherwise Phase 5's exit gate ("existing `tests/` suite still passes unchanged") is not
measurable.

Repair is mechanical, not cryptographic: update the tests to use Rust key handles instead of
`cryptography` objects, pass `bytes` instead of `bytearray`, and delete or rewrite the two
`OTRv4DAKE` references. No core change is implied.

## Appendix C — Decisions required before Phase 2

1. **B1 — Identity persistence:** (a) persistent, (b) keep ephemeral, or (c) opt-in hybrid?
2. **B2 — Python runtime:** approve Chaquopy, including its commercial licence?
3. **B3 — Voice transport:** bundle I2P, depend on the external I2P app, or add a direct transport?
4. **§14.4** — approve the 3-line `compile_error!` guard in `Rust/src/lib.rs`?
5. **M3** — remove or gate the legacy `PyBytes` session-key DAKE methods before release?
6. **Spec §8** — confirm: **no** data destruction after N failed unlock attempts (my recommendation),
   or define an explicit policy?

*No cryptographic code was modified during this audit.*
