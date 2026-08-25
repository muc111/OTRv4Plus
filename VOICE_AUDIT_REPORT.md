# OTRv4+ voice subsystem — audit, repair and hybrid-PQ upgrade

> **Status banner added at v10.12.0 — this is a historical audit; its findings
> are not retracted.** Two of the rows below were closed by the work the audit
> prompted, and are recorded here so the table is not read as current state:
> media confidentiality is now hybrid post-quantum (X448 **and** ML-KEM-1024,
> both mandatory, neither alone sufficient), and the media header is
> authenticated — the AAD is
> `"OTRv4+Voice/AAD/v3" || LP(call_id) || dir_byte || header[0..21]`, not a
> constant. The current protocol is specified in [SPEC.md §9](SPEC.md); the
> current media path, including liveness detection and authenticated endpoint
> recovery, is in [VOICE_MEDIA_PATH.md](VOICE_MEDIA_PATH.md). Test counts quoted
> below are from the date of the audit and have moved, as has the wire
> geometry: the 199-byte/40 ms packet quoted later is the then-default; the
> current default is 279 bytes every 60 ms.


Source inspected: `otrv4plus_xmpp.py` (6199 lines), `lib.rs`, `kdf.rs`, `aead.rs`,
`mlkem.rs`, `secure_mem.rs`, plus `dake.rs`, `smp.rs`, `ratchet.rs`,
`key_handles.rs`, `mldsa.rs`, `ring_sig.rs`, `error.rs`, `smp_vault.rs`,
`test_vectors.rs`.

The source was treated as authoritative. Where it contradicted the brief, the
source won and the contradiction is recorded below.

---

## A. Audit findings — what was actually implemented

| Property | v2 status | Evidence |
|---|---|---|
| Media confidentiality (classical) | IMPLEMENTED | X448 + AES-256-GCM |
| Media confidentiality (post-quantum) | **NOT IMPLEMENTED** | `VoiceKeyExchange` is X448-only |
| Voice key authentication | PARTIAL | authenticated by the OTR channel; no PQ claim verifiable |
| SMP gating | **BROKEN** | satisfiable by a printed log string |
| Mutual key confirmation | **PARTIAL** | one-way only; callee never verified the caller |
| Call-ID binding | **BROKEN** | only INVITE carried a call_id |
| Epoch binding | **BROKEN** | 8-bit wrapping generation, no ordering check |
| Authenticated media header | **NOT IMPLEMENTED** | AAD was the constant `b"OTRv4+voice"` |
| Replay protection | PARTIAL | per-generation set, unbounded to 20 000, not epoch/call-scoped |
| Directional keys | IMPLEMENTED | correct in v2 |
| Symmetric ratchet | IMPLEMENTED | correct, but documented as giving PCS, which it does not |
| Post-compromise recovery | **BROKEN** | rekey destroyed the current root before confirming |
| State machine | NOT IMPLEMENTED | scattered `session.state = …` with no validation |
| Constant-rate shaping | IMPLEMENTED | CBR + DTX off + fixed slot; claim was overstated |
| I2P/SAM transport | IMPLEMENTED | transient destinations, correct lifecycle, correct teardown |
| Zeroisation | PARTIAL | good in Python; ratchet probe keys and roots leaked copies |
| DoS resistance | **NOT IMPLEMENTED** | no rate limit on INVITE, REKEY or control messages |
| Jitter/reorder handling | PARTIAL | plain FIFO, no sequence awareness, no late detection |
| Teardown | IMPLEMENTED | thorough; the one genuinely strong part of v2 |

**Correction to the brief.** The brief said not to carry over "identity and
handshakes are already resistant to quantum adversaries". That was right to
drop. The Rust core does hold ML-KEM-1024 (`mlkem.rs`) and ML-DSA-87
(`mldsa.rs`), and `kdf.rs` has a `PQ_BRACE_KEY` / `BRACE_KEY_ROTATE` usage ID
wired to `kdf_brace_rotate(brace_key, mlkem_ss)` — so ML-KEM is folded into the
**text ratchet's brace key**. Nothing in the uploaded sources shows what the
DAKE's ML-DSA actually signs, and I have not verified it. Separately, SMP
(`smp.rs`, 1828 lines, `crypto-bigint` `U3072` DynResidue) is a classical
discrete-log construction — it is **not** hybrid PQ, and calling it that would
be wrong regardless of what the surrounding engine does.

---

## B. Bugs found

### B1 — CRITICAL: the SMP gate was satisfiable by a log string

`OTRv4PlusXMPP._tui_route_output` scans every printed line for `"SMP VERIFIED"`,
`"SMP complete"`, `"IDENTITY VERIFIED"`, `"SMP_VERIFIED"`; on a match it takes the
first non-self JID in the line and adds `(peer, "SUCCEEDED")` to
`self._smp_reported`.

`VoiceCallManager._smp_verified` then does, **before** consulting the engine:

```python
if (peer, "SUCCEEDED") in getattr(self.client, "_smp_reported", set()):
    return True
```

Consequence: any path that renders peer-influenced text containing one of those
substrings alongside a JID unlocks voice calls with that peer — no SMP, no
cryptographic verification. This is precisely the failure mode §17 of the brief
names ("do not rely on UI text; log messages; string parsing").

Two further weakenings in the same function: `_SMP_OK_TOKENS` includes
`"STATE_UPDATED"`, a generic state-change notification; and the fallback checks
session attributes `smp_complete` / `is_complete`, but SMP completes on failure
as readily as on success. `_report_smp` (line 3736) repeats both.

### B2 — CRITICAL: voice media was not post-quantum

`VoiceKeyExchange` performs X448 only. `VoiceKeyExchange.build_binding` mixes
`ssid || dh_shared || fp_low || fp_high || call_id` through SHAKE-256.
`mlkem1024_keygen/encaps/decaps` are exported to Python from `mlkem.rs` and are
never called anywhere in the voice path. A recorded call is recoverable by an
adversary with a CRQC, whatever the OTR session does.

### B3 — CRITICAL: a failed rekey destroyed the working key

`VoiceCallSession.rekey()` computed the new root, called
`_install_generation()` (which reassigns `self._crypto`), then
`_ossl_cleanse(self._root)` — all before any confirmation.
`_on_rekey` called it straight off an inbound REKEY, and `_initiate_rekey`
called it and only then compared confirmations. A dropped REKEYACK, a replay, or
any derivation mismatch left the call encrypting under a key the peer did not
hold, with the previous root already wiped.

### B4 — HIGH: no call-ID binding on any control message except INVITE

`ACCEPT`, `REJECT`, `REKEY`, `REKEYACK`, `END` carried no call_id, and
`self._calls` is keyed by bare JID. A replayed `END` from a previous call
terminates the current one (`_on_end` → `end_call`); a replayed `REKEY` is
accepted by `_on_rekey`, which has no epoch-ordering check at all.

### B5 — HIGH: unauthenticated media header

AAD was the constant `b"OTRv4+voice"`. The wire header
`sync | generation | length` was entirely outside the AEAD. The generation byte
could be flipped freely; nothing bound a frame to its call, epoch, counter or
direction.

### B6 — HIGH: 8-bit wrapping generation, no ordering check

`VOICE_GEN_MASK = 0xFF`, and `_on_rekey` accepted any generation value.
`_install_generation` masks to 8 bits, so generation 256 collides with 0 in
`self._cryptos`. At `VOICE_REKEY_SECONDS = 120` that is an 8.5-hour call — long,
but the missing `new == current + 1` check is exploitable immediately.

### B7 — HIGH: one-way key confirmation; callee sent audio unconfirmed

`answer_call` derived keys, sent `ACCEPT` with its confirmation tag, then
immediately called `connect_media_stream()` and `start_audio()`. There was no
message carrying the caller's tag back, so the callee began transmitting under a
key it had no evidence the peer held.

### B8 — MEDIUM: send-path race between epoch and cipher

`_capture_worker` reads `self._crypto` and `self._send_gen` unsynchronised while
the event loop mutates both in `activate_generation`. A frame could be sealed
under generation N and labelled N−1.

### B9 — MEDIUM: no rate limiting

No bound on INVITE, REKEY or control-message frequency. Each INVITE costs an I2P
tunnel build on both sides — cheap remote resource exhaustion against a phone.

### B10 — MEDIUM: FIFO jitter buffer

`queue.Queue` with no sequence awareness: reordered frames played reordered, no
late detection, no gap concealment, and the overflow path could reorder further.

### B11 — LOW: dead code and misleading comments

`_session_binding()` is never called. `_otr_material()` returns the fixed string
`b"OTRv4+VoiceBind/no-ssid"` as the SSID, then checks `if not ssid: return None`
— unreachable — under a comment claiming the SSID "is still required". Domain
separators were inconsistent (`VoiceBind/v2`, `VoiceKey/v3`, `VoiceConfirm/v2`).

### B12 — LOW: unwiped intermediates

The speculative ratchet probe in `decrypt_frame` builds `probe_key` as immutable
`bytes`, so intermediate chain keys are left to the GC.

### B13 — LOW (found by the new tests): `bytes.fromhex("")` returns `b""`

An empty control-message field passed hex validation. Every current call site
passes an expected length so it was not reachable, but `_hex_field` now rejects
empty input outright.

---

## C. Changes made

New module **`otrv4plus_voice.py`** (3534 lines) replaces the v2 voice block.
It is a separate module because the v2 code was untestable — reaching it meant
importing a file that pulls in slixmpp, opuslib and PulseAudio at import time,
so the key agreement, rekey machine and replay window had no coverage at all.
Nothing security-relevant in it imports beyond the stdlib and `cryptography`.

| Fix | Where |
|---|---|
| Hybrid X448 + ML-KEM-1024, both mandatory | `VoiceKeyExchange`, `derive_voice_root` |
| Domain-separated HKDF-SHA512 with length-prefixed transcript | `build_transcript`, `_lp`, `_hkdf` |
| Two-way role-labelled key confirmation (`CONFIRM` verb added) | `derive_confirmations`, `_on_accept`, `_on_confirm` |
| Two-phase rekey commit; failed rekey never costs the call | `VoiceKeySchedule`, `_initiate_rekey`, `_on_rekey_commit` |
| Monotonic 64-bit epoch, `new == current + 1` enforced | `VoiceKeySchedule.begin_rekey` |
| Full header in AAD; nonce derived not transmitted | `media_aad`, `media_nonce`, `VoiceFrameCrypto` |
| call_id on every control message, matched before acting | `_call_for` |
| Explicit transition table; ENDED absorbing | `CallState`, `transition` |
| `start_audio` refuses without confirmed keys | `VoiceCallSession.start_audio` |
| Bounded bitmap replay window per (call, direction, epoch) | `ReplayWindow` |
| Sequence-aware bounded jitter buffer with PLC hooks | `JitterBuffer`, `_conceal` |
| SMP gate reads only the engine's predicate | `_smp_verified`, `_smp_query_default` |
| Rate limits on INVITE, REKEY and control plane | `RateLimiter` |
| Key lock across epoch selection and sealing | `_seal_frame`, `_key_lock` |
| Probe keys and roots wiped | `VoiceFrameCrypto.open`, `_wipe` |

**`integrate_voice_v3.py`** splices this into `otrv4plus_xmpp.py`. It matches on
content rather than line numbers, refuses to write unless every mandatory edit
succeeds, backs up first, and is idempotent. It keeps `_ossl_cleanse`,
`_pipe_read_exact`, `_pipe_write_all`, `_sam_*` and `SAMProtocolError` in place —
the I2P bridge uses them too, and duplicating them was not acceptable.

It also redirects the TUI's string-sniffed SMP writes to a display-only set, so
the badge still lights up from a log line but no security decision can ever read
it. **B1 is only fully closed once this script has been run.**

---

## D. Final protocol

```
OTR session (DAKE-authenticated) + cryptographic SMP verification
                              │
                    INVITE ───┼─── call_id | dest | X448_i | MLKEM_ek
                              │
              ephemeral X448   ephemeral ML-KEM-1024
                    │                 │
                    └────────┬────────┘
                             │
              HKDF-SHA512 over a length-prefixed transcript
              (version, call_id, otr binding, sorted fingerprints,
               both X448 publics in role order, ek, ct, epoch)
                             │
                        voice root (64 B)
                             │
              ┌──────────────┼──────────────┐
        confirm_initiator    │        confirm_responder
         (sent in CONFIRM)   │         (sent in ACCEPT)
                             │
              ┌──────────────┴──────────────┐
          SEND KEY                     RECV KEY
        AES-256-GCM                  AES-256-GCM
              │                             │
   symmetric ratchet every 500 frames (forward secrecy)
              │
   periodic hybrid rekey every 120 s (post-compromise recovery)
```

Media frame, all header fields authenticated:

```
sync(1) | version(1) | frame_type(1) | epoch(8) | counter(8) | length(2) | ct||tag(178)
AAD   = "OTRv4+Voice/AAD/v3" || LP(call_id) || dir_byte || header[0:21]
nonce = u32BE(epoch) || u64BE(counter)          derived, never transmitted
```

Constant packet size 199 bytes, one every 40 ms, for the whole call.

---

## E. State machine

```
initiator:  IDLE → INVITING → KEY_CONFIRMING → MEDIA_CONNECTING → ACTIVE → ENDING → ENDED
responder:  IDLE → RINGING → CONNECTING → KEY_CONFIRMING → MEDIA_CONNECTING → ACTIVE → ENDING → ENDED
```

Every state may go to ENDING or ENDED. ENDED is absorbing — no async callback
can resurrect a terminated call. `start_audio()` requires MEDIA_CONNECTING **and**
confirmed keys. All 9 states, every legal transition and every illegal
transition are covered by tests.

---

## F. Security properties

**PROVIDED**
- Media confidentiality and integrity against a classical adversary (X448).
- Store-now-decrypt-later resistance (ML-KEM-1024). Both components required.
- Forward secrecy within an epoch (symmetric ratchet) and across epochs (fresh
  ephemerals).
- Post-compromise recovery at each committed hybrid rekey.
- Binding of every frame to call, epoch, direction, counter, length, frame type.
- Replay rejection, bounded in memory.
- Independent directional keys; no shared key with two counters from zero.
- Calls gated on cryptographic SMP verification only.
- Application-layer constant-rate traffic shaping.

**PARTIALLY PROVIDED**
- *Authentication of the voice exchange.* The ephemeral publics are
  authenticated by the surrounding OTR channel. Whether that authentication is
  post-quantum depends on the DAKE, which I have not verified. A quantum
  adversary able to forge OTR authentication **in real time** could MITM a live
  call; recorded calls stay protected.
- *Metadata.* Constant-rate shaping removes speech-dependent packet size and
  timing. Call start/end, duration, tunnel behaviour, loss and congestion remain
  observable, and the XMPP server still sees that two parties exchanged
  encrypted stanzas.
- *Zeroisation.* Python-side buffers are wiped via `OPENSSL_cleanse`, but
  `cryptography`'s AESGCM holds an internal key copy outside our control, and
  CPython may have copied any `bytes` object before it was wiped.

**NOT PROVIDED**
- Anonymity beyond what I2P itself gives.
- Anything about the OTR session's own security — out of scope here.
- Protection against a compromised endpoint.

---

## G. Test results — actually run

```
$ OTRV4PLUS_ALLOW_PYTHON_MLKEM=1 python3 -m unittest test_voice_security -v
Ran 110 tests in 2.385s
OK
```

110 tests, 110 passing, 0 skipped. ML-KEM-1024 came from `kyber-py`, a real
FIPS 203 implementation (1568/3168/1568/32-byte sizes verified against the Rust
constants) — there is no stub KEM anywhere in the suite, because a placeholder
returning constant bytes would make every hybrid test pass while proving
nothing. On device the same tests run against `otrv4_core`.

Coverage: initial establishment (16), directional keys (5), media AEAD (12,
including a byte-by-byte check that every one of the 21 header bytes is
authenticated), replay/reorder (14), ratchet (4), two-phase rekey (16 including
a 300-epoch run), state machine (8), signalling and call-ID binding (11),
SMP gating (6), jitter buffer (8), DoS and fuzzing (7, ~8000 random inputs),
end-to-end (3).

Two tests failed on the first run and both were real: the empty-hex acceptance
(B13, fixed in the module) and a misuse of the confirmation API in my own test
helper. A third bug — a destructive re-run in `integrate_voice_v3.py`, which
would have cut its own shim apart while reporting success — was caught by
running the integrator twice against a fixture and is fixed.

**Not run:** the Rust suite (no `Cargo.toml`, `Cargo.lock` or `tests/` in the
upload, and the container has no `pqcrypto-mlkem`), and the two-device
Termux/I2P/XMPP integration run. Neither is claimed.

---

## H. Remaining limitations

1. `integrate_voice_v3.py` has been tested against a fixture reproducing the
   real anchors, not against your actual 6199-line file — the uploads were
   cleared mid-session. Read its report before letting it write; it backs up and
   refuses on any doubt.
2. The transcript's `otr_binding` is a fixed label, not live DAKE state. The
   engine's `session_id` falls back to `secrets.token_bytes(32)` per side when
   the DAKE does not populate it, which would guarantee divergent roots. If you
   can establish that the DAKE reliably populates it, feeding the real SSID in
   would bind the call to the specific OTR session rather than to the identity
   pair.
3. Voice authentication inherits the DAKE's properties. Nothing here upgrades it.
4. `kyber-py` is not constant-time; live calls refuse it unless
   `OTRV4PLUS_ALLOW_PYTHON_MLKEM=1`.
5. PLC calls `opus_dec.decode(None, …)`, which not every opuslib build supports;
   it degrades to no concealment.
6. No formal analysis of the hybrid KDF or the rekey protocol.
7. Packet size grew 194 → 199 bytes. v2 and v3 clients cannot interoperate; the
   version byte makes that a clean rejection rather than garbled audio.

---

## I. Suggested next audit

1. **The DAKE.** What does ML-DSA-87 sign, and what does ML-KEM-1024 protect in
   `dake.rs`? Until that is established, no PQ authentication claim is safe.
2. **The brace-key path.** `kdf_brace_rotate` folds an ML-KEM secret into the
   text ratchet; confirm both peers derive it identically and that it is not
   silently skipped when the C extension is absent.
3. **`smp.rs` constant-time behaviour** under the `crypto-bigint` DynResidue
   migration — 1828 lines and the highest-value target in the codebase.
4. **Independent review of the hybrid KDF and the two-phase rekey** by someone
   who did not write them.
5. **`_ossl_cleanse` effectiveness** on Termux/aarch64: verify the C path is
   actually taken and not silently falling back to the Python loop.
6. **The remaining `_smp_reported` readers** in the TUI. They are display-only
   after this change, but the pattern of inferring security state from rendered
   text is worth removing entirely rather than fencing off.

---

# Addendum — second session (Rust config audit + XMPP integration)

## Rust: could not be tested, and here is why

`cargo test` was not run. Two separate blockers:

1. **No `.rs` sources in this upload** — only `Cargo.toml` arrived. Without
   `src/lib.rs` and friends there is nothing to compile.
2. **No usable toolchain here.** `rustup`/`static.rust-lang.org` are blocked by
   the container's egress proxy, and the only Rust available from the Ubuntu
   archive is **1.75**, below this crate's MSRV of 1.80 (`LazyLock`).

Anything I said about `cargo test` passing would have been fabricated.

### What the Cargo.toml audit found

**R1 — CRITICAL for testability: `cargo test` cannot link, so the Rust unit
tests have never run.**

```toml
default = ["pyo3/extension-module", "pq-rust"]
```

`pyo3/extension-module` tells PyO3 *not* to link libpython — correct for a
`.so` the interpreter loads, fatal for anything else. `cargo test` builds a
standalone test binary; it references `Py_None`, `PyErr_SetString` and the rest
with nothing to resolve them against, and fails at link time. This is the
best-known PyO3 packaging trap and PyO3's own docs prescribe the fix.

Consequence: the `#[cfg(test)] mod tests` blocks I read in `aead.rs` (3 tests:
AEAD round-trip, wrong-AAD rejection, tampered-ciphertext rejection) and
`mlkem.rs` (3 tests: KEM round-trip, FIPS 203 byte sizes, wrong-key
divergence) are almost certainly dead code that has never executed. They look
like coverage and provide none.

Fix, in the corrected `Cargo.toml`:

```toml
default          = ["pq-rust"]
extension-module = ["pyo3/extension-module"]
```

**This changes your build command.** Wheel/`.so` becomes
`cargo build --release --features extension-module`; tests become plain
`cargo test`.

**R2 — `crate-type = ["cdylib"]` only.** Nothing can link the crate, so no
integration test under `tests/` can `use otrv4_core::…`. Changed to
`["cdylib", "rlib"]`.

**R3 — MSRV 1.80 is documented in a comment but not enforced.** No
`rust-version` field, so cargo does not check it and a 1.75 toolchain (exactly
what Ubuntu 24.04 ships) fails deep inside `smp.rs` with an error that reads
like a code bug. Added `rust-version = "1.80"`.

**R4 — `test-only-kdf` is guarded only by a comment.** The feature exposes raw
KDF access and SMP-vault secret read-back to Python. Nothing prevents someone
building a shippable wheel with it on. Suggested `compile_error!` guard in
`lib.rs` so `test-only-kdf` + `extension-module` cannot compile together —
turning "inadvisable" into "impossible".

**R5 — `panic = "abort"` + `overflow-checks = true` in release.** A defensible
fail-closed choice, but any arithmetic overflow on attacker-influenced input
aborts the whole Python process rather than raising an exception. Worth being
a decision rather than a default. Kept, with a comment saying why.

**Correct as-is:** `pqcrypto-mlkem`/`mldsa` pinned to
`default-features = false, features = ["std"]` — that is precisely what
disables the AVX2/NEON paths behind the Termux/aarch64 SIGILL, and it is right.
`dashmap 5.5` is clear of RUSTSEC-2022-0002 (which hit 5.0.0–5.1.0).
`rand 0.8` / `rand_core 0.6` / `getrandom 0.2` are a consistent generation.

**Not checkable without `Cargo.lock`:** resolved transitive versions and
advisory status. Run `cargo audit` and `cargo deny check` once the toolchain is
in place.

### To actually test the Rust core

```
rustup toolchain install 1.80          # or newer
cd otrv4_core
cargo test                             # with the corrected Cargo.toml
cargo test --features test-only-kdf    # the gated internals
cargo clippy --all-targets -- -D warnings
cargo audit
```

Re-upload `src/*.rs` and `Cargo.lock` and I can run it here.

---

## XMPP: upgraded

`integrate_voice_v3.py` ran against the real 6199-line file:

```
applied  voice constants block: removed 158 lines
applied  v2 voice classes: removed 2081 lines
applied  v2 _smp_query: removed 53 lines
applied  shim: inserted 91 lines
applied  TUI SMP sniffer: redirected 2 write site(s) to a display-only set
applied  _smp_display_hints: initialised in __init__
applied  badge lookup: now reads both sets
applied  _report_smp: verification banner restricted to the engine's predicate
skipped  state constants: nothing to rewrite
```

6199 → 4011 lines; the 3533-line voice module sits beside it. Re-running the
script reports "already integrated" and writes nothing.

### One further fix this session

**B14 — `_report_smp` announced "IDENTITY VERIFIED" on a heuristic.**

Not caught in the first pass because I was looking at the voice gate. The
banner

```
[smp] *** IDENTITY VERIFIED with <peer> - shared secret matched (SMP complete). ***
```

fired when the state name contained `"STATE_UPDATED"` or `"COMPLETE"`, or when
the session exposed `smp_complete` / `is_complete`. SMP completes on failure as
readily as on success. The voice gate no longer reads that set, so it is not an
authentication bypass — but it is a false statement to the user, who will speak
freely on the strength of it. The banner is now restricted to `_smp_query`'s
boolean; the heuristic path reports a terminal state without claiming
verification and points at `/smpstate`.

### Verification performed on the spliced file

- `py_compile`: clean.
- Full import under stubbed `slixmpp` and OTR engine: the shim executes,
  `VoiceCallManager` resolves to `otrv4plus_voice`, `VOICE_PACKET_LEN` is 199.
- Grep for every removed v2 symbol (`VoiceCallSession.*`, `_send_gen`,
  `_peer_kex`, `derive_keys`, `activate_generation`, `_cryptos`,
  `VOICE_GEN_MASK`, `build_binding`, `_pending_rekey`, `otr_material`): zero
  dangling references.
- Every manager entry point the client calls (`handle_signal`, `start_call`,
  `answer_call`, `reject_call`, `end_call`, `has_active_call`,
  `any_active_peer`, `toggle_mute`, `status_line`, `debug`, `_calls`,
  `_start_stats`, `cleanup`, `cleanup_sync`) is present with an unchanged
  signature.
- Behavioural: feeding `"[otr-trace] peer@example.org SMP VERIFIED now"` and
  `"[otr] <peer@example.org> IDENTITY VERIFIED"` through the real
  `_tui_route_output` leaves `_smp_reported` empty while `_smp_display_hints`
  gains the entry and the badge still lights.
- Behavioural: a `VoiceCallManager` built on a client whose `_smp_reported` is
  deliberately poisoned with `(peer, "SUCCEEDED")`, and an engine returning
  `is_smp_verified → False` with state `"STATE_UPDATED"`, refuses the call.
- Voice suite re-run: **110 tests, 110 pass**.

### Still not done

- Rust tests (blocked as above).
- Two-device Termux/I2P/XMPP integration run: call establishment, audio, loss,
  reordering, latency, rekey, teardown, reconnect. Nothing in this report
  substitutes for it.
- v2 and v3 clients do not interoperate — both ends must be upgraded together.
  The version byte makes the mismatch a clean rejection rather than garbled
  audio.

---

# Addendum 2 — Rust core: sources received

## Build attempt: real result

I obtained a toolchain (rustc/cargo **1.75.0**, extracted from Ubuntu debs —
rustup and `static.rust-lang.org` are blocked here) and assembled the crate.
It does **not** build, and the reason is a finding in itself.

**R6 — the crate's real MSRV is 1.85, not the documented 1.80.**

The 1.80 in the comments is the *language* floor (`std::sync::LazyLock` in
`smp.rs`). The *dependency* floor is higher, and it is what actually bites:

```
error: unsupported output in build script of `pqcrypto-mlkem v0.1.1`:
       `cargo::rustc-check-cfg=cfg(enable_x86_avx2)`
```
→ `cargo::` directive syntax requires cargo **≥ 1.77**. Same for
`pqcrypto-mldsa`, including 0.1.0.

```
error: feature `edition2024` is required
  (base64ct 1.8.3, zeroize 1.9.0, getrandom 0.3.4, wasip2 1.0.2)
```
→ edition2024 requires cargo **≥ 1.85**.

Cargo 1.75 cannot even resolve the graph, let alone compile it. `Cargo.toml`
now declares `rust-version = "1.85"`. Declaring 1.80 would let a 1.80–1.84
toolchain start a build that dies much later with an unrelated-looking error.

**So the Rust tests still have not been run.** Not by me, and — per finding R1
— not by anyone, because `pyo3/extension-module` in `default` makes `cargo
test` fail at link time. There are **35 `#[test]` functions** in the tree:

| file | tests | file | tests |
|---|---|---|---|
| `smp.rs` | 15 | `mldsa.rs` | 3 |
| `key_handles.rs` | 5 | `mlkem.rs` | 3 |
| `ring_sig.rs` | 5 | `test_vectors.rs` | 1 |
| `aead.rs` | 3 | | |

`dake.rs` (1213 lines), `kdf.rs`, `header.rs`, `smp_vault.rs`, `secure_mem.rs`
and `error.rs` have **zero**. `dake.rs` having none is the gap I would close
first — it is the largest module and it owns the handshake.

`ratchet.rs` was not in the upload (`lib.rs` declares it and `dake.rs` calls
`ratchet::RustDoubleRatchet::from_dake_keys`). I wrote a clearly-labelled stub
to let the other thirteen modules compile. **`ratchet.rs` is unaudited.**

## Correction to my previous report

I wrote that SMP "is a classical discrete-log construction — it is not hybrid
PQ, and calling it that would be wrong." **That was wrong**, and I had not read
`smp.rs` when I wrote it.

`smp.rs` implements a genuine hybrid PQ SMP (`SMP_VERSION_PQ = 0x02`, the
default): the initiator generates an ML-KEM-1024 keypair at SMP1, the responder
encapsulates and signs the SMP2 wire body with ML-DSA-87, and both sides derive
a `pq_binding_key` from `kem_ss || transcript` under the
`OTRv4+SMP-PQ-BIND-v1` domain. Breaking it requires breaking ML-KEM-1024 *and*
ML-DSA-87 *and* the classical group.

Better still, the downgrade defence is stronger than its own comment claims.
The header says a version mismatch will be caught because "the first ZKP or
signature verify will fail" — hand-wavy. The code actually does:

```rust
if wire_version != self.version {
    return Err(self.fail_and_zeroize(OtrError::Smp(
        "SMP version mismatch: peer and local version differ")));
}
```

An explicit strict equality check before any crypto runs. Fix the comment to
describe what the code does; it is selling itself short.

*Worth confirming:* whether anything Python-side can set `version` back to
`0x01`. The field is writable in Rust and the default is `0x02`; I did not
trace every setter.

## DAKE findings

**What ML-KEM-1024 actually protects (now confirmed).** In `generate_dake2` /
`process_dake2`:

```rust
combined = dh1 || dh2 || dh3 || mlkem_ss
mixed_secret = KDF_1(SHARED_SECRET, combined, 64)
```

The ML-KEM secret is mixed into the session root, not just the brace key. So
the **text** session root is genuinely hybrid (three X448 exchanges + ML-KEM-1024).
That is stronger than I could establish last time, and it makes the contrast
with the old voice path sharper: the text channel was hybrid, the voice channel
was X448 only.

**What ML-DSA-87 signs.** `mldsa_verify(peer_mldsa_pub, &self.transcript,
mldsa_sig)` at DAKE3 — the full DAKE transcript. Combined with the H2 downgrade
check, that is the right shape.

---

**R7 — HIGH: unauthenticated remote DoS on session establishment (`dake.rs:361`).**

DAKE1 detects the optional ML-DSA public key by trailing length alone:

```rust
// optional ML-DSA pub
if data.len() - off >= MLDSA_PUB_SIZE {
    self.peer_mldsa_pub = Some(data[off..off + MLDSA_PUB_SIZE].to_vec());
}
```

DAKE1 is the first message and carries no MAC. Append 2592 arbitrary bytes to
any DAKE1 in flight and the responder sets `peer_mldsa_pub = Some(garbage)`.
At DAKE3 that makes `mldsa_required = true`, so a genuine initiator with no
ML-DSA key sends flag `0x00` and the handshake aborts with:

```
ML-DSA signature stripped: peer committed a PQ key
```

Any on-path attacker — including the XMPP server — can stop OTR sessions from
ever forming, with 2592 bytes of padding and no key material. It is not a
confidentiality break, but the error blames the peer's PQ key, so the user will
misdiagnose it as an attack on their contact rather than injected bytes.

The codebase already contains the fix in two places:
- `assemble_dake3` uses an explicit presence flag: `msg.push(0x01)` / `0x00`.
- `process_dake2` bounds the parse by the MAC position, and DAKE2 *is* MAC'd.

DAKE1 is the only one of the three that does neither. Give it the same 1-byte
flag as DAKE3.

**R8 — MEDIUM: the raw shared secrets are never zeroized (`dake.rs:385-391`).**

```rust
let mut combined = Vec::new();          // dh1||dh2||dh3||mlkem_ss = 200 bytes
let mixed_secret = kdf::kdf_1(...);     // 64 bytes
let mac_key      = kdf::kdf_1(...);     // 64 bytes
```

All three are plain `Vec<u8>` dropped without wiping, and `x448_dh` returns
`Vec<u8>` too, so `dh1`/`dh2`/`dh3` leak as well. `kdf.rs` is meticulous about
this — every derivation there wipes its heap copy under an "audit M2" comment —
and `derive_session_keys` twenty lines further down calls `.zeroize()` on its
temporaries. This is the one function that holds *every* raw shared secret at
once, and it is the one that does not. Wrap them in `SecretVec`, or `.zeroize()`
before return on both the success and error paths.

**R9 — LOW: brittle bounds arithmetic in DAKE1 (`dake.rs:352`).**

`let num_versions = data[off + 1] as usize;` is protected only by the
hand-computed `+ 3` in the length guard on line 344. It is correct today
(`off+1 = 1626`, minimum length 1628). Change `X448_PUB_SIZE`, the header, or
the guard and it becomes an out-of-bounds index — which, with
`panic = "abort"`, kills the whole Python process from a remote message. Derive
the constant instead of hand-computing the margin.

## What is clean

- `#![forbid(unsafe_code)]` holds across all fourteen files.
- Only **four** `expect()` calls in non-test code, all on genuine invariants
  (HMAC accepting any key length ×3, one compile-time hex literal). No
  `unwrap()`, `panic!`, `todo!` or `unimplemented!` anywhere in production
  paths. For 5389 lines of crypto that is unusually disciplined.
- The `encapsulate` return-order inversion (pqcrypto gives `(ss, ct)`) is
  correct in **both** `dake.rs:631` and `mlkem.rs`, and flagged in comments at
  both sites. This is the classic silent-desync bug and it is handled.
- `test-only-kdf` gating is applied consistently in `kdf.rs`, `header.rs` and
  `smp_vault.rs`.
- `pqcrypto-*` pinned `default-features = false, features = ["std"]` — the
  correct AVX2/NEON disable for the Termux SIGILL.
- SMP secrets in `SecretVec`/`SecretBytes` with `ZeroizeOnDrop`;
  `fail_and_zeroize` on the failure path.

## To run the Rust tests

```
rustup toolchain install 1.85
cargo test                                  # needs the corrected Cargo.toml
cargo test --features test-only-kdf
cargo clippy --all-targets -- -D warnings
cargo audit && cargo deny check
```

Two things I still cannot check: `ratchet.rs` (not uploaded) and `Cargo.lock`
(not uploaded, so no advisory review of resolved transitive versions).
