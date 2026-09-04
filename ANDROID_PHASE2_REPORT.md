# OTRv4+ Android — Phase 2 report

> **Status note (v10.12.0) — historical report, results not retracted.** The test
> counts in the tables below are Phase 2 measurements. Current figures from a
> repo-root run are **1483 passed, 43 skipped, 1 xfailed** (Python 3.12) and
> **65 passed** (Rust). Phase 2 also predates encrypted voice being hardened:
> voice is verified under **Termux**, not inside the APK, and nothing in this
> report should be read as evidence that voice works in the Android application.


**Status: INCOMPLETE — blocked on environment, not on design.**

Phase 2 asked for a production-viable Android foundation. Everything that could
be built and verified without an Android toolchain has been, and is green.
Everything requiring the Android SDK, the NDK, Chaquopy or a physical device is
blocked by this environment's egress policy and is **not** claimed as done.

The exit-gate table in §11 marks each item honestly. Six gates cannot be met
here. Section §2 says exactly why and what unblocks them.

No cryptographic primitive, protocol or orchestration path was modified.

---

## 1. What was delivered

| Area | State |
|---|---|
| Python test suite repaired | **Done** — runs without `--ignore` |
| Release build guard (`test-only-kdf`) | **Done** — fails closed, verified in 4 states |
| Persistent identity architecture + tests | **Done** — including a real cross-process test |
| Typed bridge (structured state, no terminal scraping) | **Done** — 50 tests |
| Android bootstrap + diagnostics (Python side) | **Done** — verified end to end |
| Application security layer (lock machine, throttle) | **Done** — 35 JVM tests pass |
| Keystore / credential / SecureStore contracts | **Done** — interfaces, no concrete default |
| Sensitive storage audit | **Done** — `ANDROID_STORAGE_AUDIT.md`, 17 categories |
| AAudio path reachability | **Done** (structural) / device half blocked |
| Storage nonce design corrected to CSPRNG | **Done** — per specification |
| Android project shell (Gradle/Kotlin sources) | **Written, not compiled** |
| M3 disposition | **Done** — documented with caller evidence |
| L1 tracking | **Done** — `SECURITY_ISSUES.md` |
| I2P feasibility | **Done** — `ANDROID_I2P_FEASIBILITY.md` |
| Python 3.12 documentation corrected | **Done** |
| On-device verification | **BLOCKED** |

Twelve commits on `claude/otrv4plus-android-spec-a3oq4d`; 61 files changed,
48 of them new.

---

## 2. The blocker

Three things are unavailable in this environment, and all three are required for
the on-device gates:

```
dl.google.com   403 at the egress proxy  -> no Android SDK, no NDK, no AGP, no AndroidX
chaquo.com      403 at the egress proxy  -> (not decisive -- see below)
(no device)                              -> no real-device verification
```

**Refined 2026-08-21.** Re-probed after the MAC fix. The picture is narrower than
first reported, and one host is decisive:

| Artifact | Source | Status |
|---|---|---|
| Android SDK command-line tools | `dl.google.com` | **BLOCKED** (403) |
| Android NDK | `dl.google.com` | **BLOCKED** (403) |
| Android Gradle Plugin 8.7.3 | `dl.google.com` only | **BLOCKED** — 404 on Maven Central |
| AndroidX / Compose | `dl.google.com` only | **BLOCKED** — 404 on Maven Central |
| Chaquopy 16.0.0 | **Maven Central** | **AVAILABLE** (200) |
| Kotlin, kotlinx, JUnit | Maven Central | AVAILABLE |
| Gradle 8.14.3, JDK 21 | local | AVAILABLE |
| Rust `aarch64-linux-android` std | static.rust-lang.org | AVAILABLE |

`maven.google.com` is not a separate route: it 301-redirects to
`dl.google.com/dl/android/maven2/`, which the same policy refuses.

**So `dl.google.com` is the single blocking host.** `chaquo.com` turns out not to
be required — Chaquopy is mirrored on Maven Central (16.0.0 present, 17.0.0
latest), so the Gradle plugin can be resolved without it. Allowlisting
`dl.google.com` alone would unblock the SDK, the NDK, AGP and AndroidX, i.e.
everything the build needs.

**Re-probed at the end of the pre-Android hardening pass.** Unchanged:

```
https://dl.google.com/android/repository/repository2-3.xml
    curl: (56) CONNECT tunnel failed, response 403
https://maven.google.com/com/android/tools/build/gradle/8.7.0/gradle-8.7.0.pom
    301 -> https://dl.google.com/dl/android/maven2/...            (same policy)
https://repo.maven.apache.org/maven2/com/chaquo/python/gradle/16.0.0/gradle-16.0.0.pom
    200                                                            (not a blocker)
```

The refusal is at the CONNECT tunnel, so it is an environment network policy,
not a missing credential, a TLS problem or a build misconfiguration. No attempt
was made to work around it, and none should be: Chaquopy, Compose, Kotlin, Rust
and the approved architecture are not the obstacle and must not be swapped out
to dodge the SDK dependency. The fix is an allowlist entry or a build host that
has one.

Exact failing command:

```
$ cd android && gradle --offline --no-daemon tasks
Plugin [id: 'com.android.application', version: '8.7.3'] was not found
  could not resolve plugin artifact
  'com.android.application:com.android.application.gradle.plugin:8.7.3'
```

and for the native side:

```
$ cargo check --target aarch64-linux-android --release
error occurred in cc-rs: failed to find tool "aarch64-linux-android-clang"
```

(`pqcrypto-mlkem` / `pqcrypto-mldsa` compile C reference code and need the NDK
toolchain; the Rust std for the target installs fine.)

Both refusals were confirmed against the proxy's own status endpoint, which
records them as policy denials rather than transient failures. The proxy
documentation is explicit that policy denials must be reported, not retried or
routed around, so no workaround was attempted.

What this **does** rule out:

- Compiling the Android project (needs AGP from `dl.google.com`).
- Building `otrv4_core` for `aarch64-linux-android`. Confirmed concretely:
  `rustup target add aarch64-linux-android` succeeds, but
  `cargo check --target aarch64-linux-android` fails at
  `failed to find tool "aarch64-linux-android-clang"` — `pqcrypto-mlkem` and
  `pqcrypto-mldsa` compile C reference code and need the NDK toolchain.
- Any Chaquopy behaviour, including whether `slixmpp`, `aiodns` and
  `argon2-cffi` resolve for each ABI.
- Everything in §22 of the brief (real-device evidence).

What it does **not** rule out, and what was therefore verified:

- Gradle 8.14.3 **does** evaluate `settings.gradle.kts` and the root build
  script successfully, failing only at AGP resolution. The Kotlin DSL is
  syntactically valid; it is the plugin artifact that is unreachable.
- The entire **Python → Rust** half of the vertical slice runs, with a live
  self-test (§4).

### To unblock

Any one of: allowlist `dl.google.com` and `chaquo.com` for this environment; or
run Phase 2's build steps on a machine with the Android SDK/NDK installed; or
supply a prepared container image with them preinstalled. A device (or emulator,
which still needs the SDK) is needed for §22 regardless.

---

## 3. Test results

All figures measured in this environment on Python 3.12.3, x86_64.

| Suite | Before Phase 2 | After |
|---|---|---|
| `cargo test` | 45 passed | **45 passed** (unchanged) |
| `tests/` (production wheel) | 245 passed, 26 failed, 1 module uncollectable | **406 passed, 42 skipped, 1 xfailed, 0 failed** |
| `tests/` (`test-only-kdf` wheel) | 248 passed, 23 failed | **passes; the 3 gated tests run instead of skipping** |
| voice + audio suites | 210 passed | **210 passed** (unchanged) |
| Kotlin security layer | did not exist | **43 passed** (JVM, no Android SDK) |
| `--ignore` needed? | yes | **no** |

New tests added in Phase 2: **210** — Python 167 and Kotlin 43.

**On the skip count.** 42 skips on a production wheel is not lost coverage: 36
are the Option-A identity double, which injects a seed through
`from_seed_bytes` and is therefore gated out of production builds by decision
B1. The same lifecycle is covered on production by the 35 Rust-backed tests in
`tests/test_rust_identity_sealing.py`. On a `test-only-kdf` wheel the same suite
reports **441 passed, 7 skipped, 1 xfailed**.

The 4 skips are the three vault read-back tests on a production wheel (correct —
their absence *is* the security boundary) and one `importorskip`. The 1 xfail is
tracked gap G1 (§7).

### Test-suite repair

The suite had rotted against the v10.7 "Rust-core-only" migration. Four distinct
causes, all on the test side, none a cryptographic regression:

- `cryptography` key objects passed where Rust key handles are now required
  (`RingSignature.sign` calls `handle.ring_sign`).
- `bytearray` passed to `mlkem1024_decaps`, which takes `&[u8]`.
  `mlkem1024_keygen` returns `dk` as a bytearray so callers can wipe it;
  production wraps with `bytes(dk)` at every call site and the tests did not.
- References to `OTRv4DAKE`, deleted at v10.7. `RustDAKEAdapter` is
  constructor-compatible, so the UKS and ML-KEM integration tests ported across.
- Vault read-back tests assuming `test-only-kdf` is always on.

Two findings surfaced that were **not** rot and were left visible rather than
patched away: session keys no longer cross into Python at all (M3, §6), and the
DAKE handshake timeout is a stub (G1, §7).

---

## 4. Architecture implemented

```
Kotlin / Compose  (android/, written — not compiled here)
      |  OtrCore: typed interface, enums only, no key material
      v
Chaquopy / CPython 3.12+          [BLOCKED — not verified]
      v
android_bridge/                   [VERIFIED]
  bootstrap.py   loads otrv4+.py under the otrv4_ alias
  app.py         OtrApp facade over EnhancedSessionManager
  events.py      SecurityState / SmpState / ConnectionState / CallState
  identity.py    identity lifecycle
  secure_store.py versioned AES-256-GCM records; custody abstract
  diagnostics.py integration report + live Rust self-test
      v
otrv4+.py orchestration  (UNCHANGED)   [VERIFIED]
      v
otrv4_core Rust          (UNCHANGED)   [VERIFIED, 45/45]
```

**The Python → Rust half of the vertical slice works.** Verified in this
environment:

```
loaded  : otrv4_ | EnhancedSessionManager: True
python  : 3.12.3, meets_3_12_requirement: true
rust_core: loaded, 19/19 required symbols, missing: []
otrv4plus: imported, engine_constructed, initialized
rust_selftest: ed448_sign_verify ✓  mlkem1024_roundtrip ✓  aes256gcm_roundtrip ✓
ok      : true
```

The self-test matters: importing a `.so` is not proof it works on an ABI. On a
device this is the check that catches a wrong-ABI or stale build.

### Bridge API

`OtrApp` (Python) ⇄ `OtrCore` (Kotlin). Every method maps onto an
`EnhancedSessionManager` call that already exists — a test asserts each one is
present on the real class, so the facade cannot drift onto a vanished API.

```
initialize / shutdown          localFingerprint
securityState / smpState       smpProgress / securityDetails
contacts                       startSession / sendMessage
smpStart / smpRespond / smpAbort
```

Properties enforced by tests:

- **No terminal scraping.** An AST check rejects any string literal in the
  package matching engine display text.
- **No secret returns.** No method name may look like a key accessor; SMP
  secrets are absent from the facade, from events and from logs.
- **No silent downgrade.** `sendMessage` raises rather than transmitting when
  the engine reports the message was not encrypted.
- **Unknown state fails safe.** An unrecognised security level maps to
  `PLAINTEXT`, never to something more secure.
- **A raising UI callback cannot kill a session.**

State mappings are derived from engine values with provenance recorded:
`SecurityState` from `UIConstants.SecurityLevel` (numerically identical, with a
drift test), `SmpState` from `RustSMP.get_phase()`, `CallState` from
`otrv4plus_voice.CallState`. `ConnectionState` is the only new enum.

---

## 5. Identity persistence

Lifecycle implemented, with the vault's key custody left abstract for Phase 4:

```
first run  -> create -> serialize -> seal (AES-256-GCM) -> store
later runs -> load -> unseal -> restore handles -> same fingerprint
```

Record format:

```
version(1) || key_id(4) || nonce(12) || ciphertext || tag(16)
AAD = version || key_id || record_type || 0 || schema_version || 0 || record_id
```

`record_type` and `record_id` are NUL-terminated in the AAD so field boundaries
cannot be shifted to make one record authenticate as another. Nonces come from a
per-key monotonic counter rather than `random(12)` — closing prior audit item M4
for storage, since a random 96-bit nonce carries a birthday bound a message
database will approach.

Tested (31 tests): fingerprint stable across an in-process restart **and across
a genuine second interpreter**; tampered, truncated, bit-flipped, wrong-key and
wrong-slot records all rejected; no private material anywhere in the sealed
record; 500 records with no nonce collision; key rotation with old records still
readable; every insecure default fails closed.

### Open decision — B1-seed

`generate_ed448_keypair()` creates the seed **inside Rust** and there is no PyO3
accessor returning it (`expose_seed_slice` is `pub(crate)`). **An identity
generated the production way cannot be persisted at all.** The only
reconstruction path is `from_seed_bytes()`, which requires Python to have held
the seed — costing the documented property that private bytes never appear on
the Python heap.

Rather than resolve that silently, `IdentityKeyStore` is the swap point:

- **Option A** — seed generated in Python. No Rust change; weakens the boundary.
- **Option B** — additive Rust `seal_ed448_handle` / `unseal_ed448_handle`; only
  ciphertext crosses. **Recommended.**

The package ships no concrete implementation, and a test enforces that. The test
double uses Option A and is marked development/test only. **This needs your
decision before Phase 4.**

---

## 6. Security-layer architecture

The specification's five states, with an exhaustive transition table enforced on
every move — the same idiom the voice subsystem already uses for `CallState`,
where scattered unchecked assignments were replaced by one validated table:

```
LOCKED --> AUTHENTICATING --> UNLOCKED --> BACKGROUND_LOCK_PENDING --> LOCKED
```

`AUTHENTICATING` is reachable only from `LOCKED`, so a stale lifecycle callback
cannot push an unlocked session back through authentication; `LOCKED` cannot
jump straight to `UNLOCKED`. The data-key handle is released on every path out
of `UNLOCKED`, and relock completes even if releasing it throws.

Classes delivered (all pure Kotlin — no Android imports, so they are
unit-testable on a plain JVM):

| Class | State |
|---|---|
| `LockState` / `AppLockManager` | implemented, 20 tests |
| `AttemptThrottle` + `ThrottleStore` | implemented, 9 tests |
| `KeystoreManager`, `SecurityLevel`, `KeystoreDiagnostics`, `DataKeyHandle` | contract only |
| `UnlockCredentialService`, `UnlockOutcome`, `Argon2idParams` | contract only |
| `UnlockCredentialSource` | contract only; implementations live in test sources |
| `SecureStore`, `RecordType` | contract only |

**A flaw the tests caught before commit.** The first draft treated a backwards
clock as "no time passed", which keeps the app `UNLOCKED` — fail-open. Anyone
holding the device could keep a session alive indefinitely by winding the clock
back before returning to the app. A backwards clock now counts as expired and
relocks. The caller should supply a monotonic source
(`SystemClock.elapsedRealtime()`); this is defence for when it does not, and for
a reboot resetting the reference.

**`AttemptThrottle` never receives the credential** — it counts outcomes, not
inputs, and a test asserts its methods take no parameters at all. It is checked
*before* any key derivation, so the unlock screen cannot be used as a
CPU-exhaustion oracle. Counters persist through `ThrottleStore`, because a
throttle that forgets on restart is not a throttle. It has **no**
wipe/destroy/erase capability, and a test asserts that: the specification
forbids destroying user data after N failures without an explicit product
decision, so the capability does not exist rather than existing unused.

**`Argon2idParams` ships `calibrated = false`.** The specification requires the
parameters to come from measurement on real hardware. The desktop engine's
values (time=3, memory=64 MiB, parallelism=4) are carried as a starting point
explicitly marked uncalibrated; 64 MiB on a low-end phone may be unacceptably
slow or may push the app toward an OOM kill during unlock. Phase 12's release
checklist must assert `calibrated == true`.

### Keystore abstraction

`KeystoreManager` reports what a device actually provides rather than what the
app would prefer: `SOFTWARE_ONLY`, `KEYSTORE_SOFTWARE`, `HARDWARE_TEE`,
`STRONGBOX`. **StrongBox is preferred but never required** — a device without it
degrades and records the fact honestly. `KeystoreDiagnostics` exposes keystore
availability, hardware-backing, StrongBox availability, whether user
authentication is required, key version and encryption version. Every field is a
capability or a version number; none is derived from key material.

`unwrapDataKey` returns an opaque `DataKeyHandle` — the key bytes are not a
return value, so the software path cannot be more permissive than the hardware
one. `rewrapDataKey` is how the credential changes without re-encrypting user
data.

### Calculator unlock architecture (architecture only)

```
Calculator -> credential -> AttemptThrottle.check() -> Argon2id -> KEK
           -> unwrap Keystore-held DEK -> AEAD tag verifies -> UNLOCKED
```

The credential is an authentication input, never the key. There is no stored
plaintext to compare against: verification *is* the AEAD tag on the wrapped key,
so a wrong credential and a corrupt record fail identically. `"1337"` appears in
no production Kotlin constant, resource, asset, manifest entry, or Python/Rust
source — `tests/test_release_guard.py` enforces that, and was confirmed to fail
when a credential is deliberately introduced.

No calculator UI was built. That is Phase 3.

## 7. Storage architecture

Full table in `ANDROID_STORAGE_AUDIT.md` — 17 categories, enumerated from the
actual write sites rather than from the Phase 1 summary. The four that matter:

- **The device seed *is* the storage key.** `SecureKeyStorage` derives its AES
  key with Argon2id from a 32-byte seed sitting in plaintext next to the
  ciphertext, so the KDF adds nothing against filesystem access. This is the
  largest at-rest weakness and is exactly what a non-exportable Keystore
  wrapping key fixes.
- **The trust database is plaintext JSON** — a contact graph in the clear.
- **The message log is the worst combination**: full message bodies, a bespoke
  AEAD, and a plaintext key file in the same directory.
- **Ratchet state, session keys, SMP state and voice audio already never touch
  disk**, which is correct. `RecordType.NEVER_PERSISTED` encodes that so a
  future "cache the ratchet for faster resume" cannot be added quietly.

### Record format

```
version(1) || key_id(4) || nonce(12) || ciphertext || tag(16)
AAD = version || key_id || record_type || 0 || schema_version || 0 || record_id
```

**Nonces are a fresh 96-bit CSPRNG draw per operation**, per the specification.
An earlier Phase 2 draft used a deterministic counter; that was corrected.
Uniqueness is enforced by design rather than left to chance:
`MAX_RECORDS_PER_KEY` is the NIST SP 800-38D §8.3 bound of 2^32 invocations per
key, and `seal()` raises `KeyRotationRequired` on reaching it rather than
continuing past the analysed bound. The per-key counter survives only as a usage
meter for that bound and never contributes to the nonce.

## 8. AAudio

The existing AAudio backend loads `libaaudio.so` through `ctypes.CDLL`, so it
needs no per-ABI build or packaging of its own and works in any ordinary Android
process. 13 tests pin the properties that decide whether it works in an APK: the
system library paths are searched, the module imports with no audio device
present (Chaquopy imports it at startup, long before a call), `aaudio_available()`
reports absence rather than raising, and the host can pin the backend explicitly.

Failure behaviour is safe and stays that way: a missing `RECORD_AUDIO`
permission propagates rather than falling back, because every backend runs under
the same UID and a silent demotion would encrypt and transmit silence while
reporting a healthy call.

The voice host seam (`bind_host`) and the `CallState` machine are pinned by
tests, including one asserting `android_bridge.events.CallState` mirrors
`otrv4plus_voice.CallState` exactly so the two cannot diverge.

**Not verified**: any actual audio on a device. That is the blocked half.

## 9. M3 disposition

`PyDakeSessionKeys` exposes `root_key`, `chain_key_a/b`, `brace_key`, `mac_key`
as PyBytes via `get_session_keys()` and the legacy `generate_dake2`/
`process_dake2`.

Every caller was checked. Production runs
`use_output_api = hasattr(self._rust, "generate_dake2_output")`, and
`_check_rust_requirements()` (`otrv4+.py:70`) raises `ImportError` at import time
unless both `*_output` methods exist. **The `hasattr` cannot be false in any
importable build**, so the PyBytes branch is dead code on the live path —
established by reading the gate, not inferred. Android does not need it; the
bridge never touches session keys.

**Recommendation: (B) gate the legacy entry points behind an explicit test-only
Cargo feature**, reusing the `build.rs` mechanism now in place. Not executed in
Phase 2 because it touches `dake.rs` and the brief requires the disposition to be
agreed first. Full reasoning in `SECURITY_ISSUES.md`.

---

## 10. L1 and other tracked issues

`SECURITY_ISSUES.md` is new and tracks five items. **L1 is OPEN and is not
claimed as fixed.**

- **L1** — MAC-key revelation reveals all-zeros; **deniability is not achieved**.
  No speculative fix was attempted: revealing a key that is still live would be
  far worse than the current state. The document records current behaviour,
  expected OTR behaviour, impact, code paths, and what a real regression test
  must assert (that a revealed key verifies a prior MAC — not merely that the
  field is non-zero). **Do not use "deniable" as a product claim.** Note the ring
  signature *does* give participation deniability for the handshake; conflating
  that with transcript deniability would be a material error.
- **M3** — mitigated, disposition above.
- **G1** — `is_expired()` is a stub returning `False`; `DAKE_TIMEOUT` is
  referenced nowhere. Zero production callers today, so impact is nil, but a
  future caller would silently get "never expired". Kept visible as an
  `expectedFailure`.
- **G2** — two divergent copies of `otrv4_testlib.py`; which one loads depends on
  collection order, because `test_attacks.py` front-loads `tests/` onto
  `sys.path`. Mitigated by keeping the new helper block byte-identical in both.
- **B1-seed** — §5.

---

## 11. Release / test build separation

The Phase 1 audit found that only a *comment* prevented shipping a wheel with the
SMP vault read-back gates open. Enforcement now sits on both sides:

**`Rust/build.rs` (new)** refuses to build with `test-only-kdf` unless
`OTRV4PLUS_ALLOW_TEST_GATES=1` is set explicitly. Verified:

| Build | Result |
|---|---|
| `cargo build --release` | succeeds |
| `--features test-only-kdf` | **refused** |
| `OTRV4PLUS_ALLOW_TEST_GATES=1 --features test-only-kdf` | succeeds, warns |

The `compile_error!` the Cargo.toml comment proposed was **rejected**: the same
file documents `--features extension-module,test-only-kdf` as the supported way
to build the internals-test wheel, so adding it verbatim would make those tests
unrunnable. A macro cannot read the environment; a build script can.

**`tests/test_release_guard.py` (new)** asserts the *installed* artifact exposes
no gated API. Verified in all four states, including that it fails when a
gate-open wheel is present and when the opt-in is set but the wheel is not
actually the test build. Run it with the variable **unset** against the release
wheel — that is the pipeline's fail-closed assertion.

The reachable gated surface is exactly `RustSMPVault.load` and `load_by_handle`;
`kdf_1_py` and `encode_header_py` are behind the feature but `lib.rs` never
registers them, so they are unreachable from Python even when it is on. A further
test asserts the gated-surface list stays in step with the Rust sources.

Also asserted: no development credential (`"1337"`) in any shippable source, and
no secret-looking Android resources. Both were confirmed to fail when a
credential is deliberately introduced, so they are not vacuous.

---

## 12. Android configuration (written, not compiled)

- **Chaquopy** pinned to **Python 3.12** — a hard requirement, not a preference.
- **minSdk 26**, chosen from an actual constraint: AAudio, the Android audio
  backend `otrv4plus_audio.py` already implements, needs API 26.
- **ABIs**: `arm64-v8a` (production) and `x86_64` (emulator), delivered as ABI
  splits. **`armeabi-v7a` deliberately not enabled** — the 32-bit Rust build has
  never been exercised, and the pqcrypto crates are already pinned to portable C
  to avoid SIGILL on some aarch64 NEON paths. Adding it is a Phase 3 task with
  its own testing.
- `FLAG_SECURE` from the first Activity; `allowBackup=false` with matching
  data-extraction rules; cleartext traffic disabled; release strips all
  `android.util.Log` calls.
- A `syncPythonSources` task copies the orchestration layer from the repository
  root and **excludes** the TUI, both IRC clients, the WeeChat plugin and
  `smp_engine_compat.py` (which re-implements the SMP KDF in pure Python and must
  never reach a device). There is no second copy of `otrv4+.py` to drift.
- The diagnostics detail screen lives in `src/debug/`, so it is not compiled into
  a release APK at all rather than merely hidden behind a flag.

**Unverified**, because the toolchain is blocked: that any of this compiles; that
`slixmpp`/`aiodns`/`argon2-cffi` resolve per ABI; APK size; cold-start time.

---

## 13. I2P findings

Full report: `ANDROID_I2P_FEASIBILITY.md`. Headlines:

- **The naive "depend on the installed i2pd app" option does not work.** The SAM
  bridge binds localhost only, and on Android each app has its own UID and
  loopback view, so another app's `127.0.0.1:7656` is **not reachable** from our
  process. This is the most important technical finding.
- i2pd is **BSD-3** and ships `libi2pd_wrapper` for embedding, so bundling is
  viable licence-wise. The upstream Android project builds a standalone APK, not
  an AAR, so we would build `libi2pd` ourselves.
- **Recommended shape**: bundle i2pd in a **separate process of our own app**
  (`android:process=":i2p"`), reached over a socket we control — not in-process
  (a C++ router sharing an address space with the key material) and not another
  app.
- **A foreground service is unavoidable**, and its persistent notification is in
  direct tension with the calculator disguise. **That needs a product decision.**
- No performance, memory or battery numbers are given: none could be measured
  here, and inventing them for a transport decision would be worse than omitting
  them. §4 of that report lists exactly what to measure.
- Our own licensing was settled at v10.17.0: dual AGPL-3.0 plus a commercial licence. This bullet described the GPL-3.0 position and is kept for history —
  independent of I2P, but it surfaced here.

---

## 14. Exit gate

| Gate | Status |
|---|---|
| Android project builds | **BLOCKED** — no AGP/SDK |
| Python 3.12+ runs inside the Android application | **BLOCKED** — no Chaquopy |
| Rust extension loads on a real device | **BLOCKED** — no NDK, no device |
| OTRv4+ initializes on-device | **BLOCKED** — no device |
| Kotlin ↔ Python ↔ Rust path works | **PARTIAL** — Python↔Rust verified; Kotlin leg blocked |
| Typed bridge exists | **DONE** |
| No dependency on terminal scraping | **DONE** — enforced by test |
| Persistent identity implemented/tested | **DONE**, with decision B1-seed open |
| Security state machine exists | **DONE** — 35 JVM tests |
| Keystore abstraction exists | **DONE** — contract only; Phase 4 implements |
| Storage architecture documented | **DONE** — `ANDROID_STORAGE_AUDIT.md` |
| `cargo test` green | **DONE** — 45/45 |
| Voice/audio suite green | **DONE** — 210/210 |
| Python suite repaired, no `--ignore` | **DONE** — 386 passed |
| Release build cannot expose test-only KDF | **DONE** — verified 4 ways |
| No development credential in production artifacts | **DONE** — enforced by test |
| No plaintext cryptographic secrets introduced | **DONE** |
| I2P feasibility investigated | **DONE** |
| M3 disposition documented | **DONE** |
| L1 tracked, not falsely claimed resolved | **DONE** |
| `ANDROID_PHASE2_REPORT.md` complete | **DONE** |

**Phase 2 is not complete.** Six gates are blocked by the environment. The design
work behind each is finished and waiting.

---

## 15. Decisions required

1. **B1-seed** — Option A (seed in Python) or **Option B** (Rust-side sealing,
   recommended)? Blocks Phase 4.
2. **M3** — approve gating the legacy DAKE entry points behind a test-only
   feature?
3. **I2P** — approve the separate-process bundled-router shape, and accept the
   foreground-service notification versus the calculator disguise?
4. **Unblocking** — allowlist `dl.google.com` + `chaquo.com`, or provide a
   machine with the Android SDK/NDK and a device?
5. **Licensing** — RESOLVED at v10.17.0: dual AGPL-3.0 + commercial. Originally raised as "GPL-3.0 core versus commercial distribution".
6. **G1** — implement the DAKE handshake timeout (behaviour change), or leave
   tracked?

## 16. Phase 3 prerequisites

Before the calculator/unlock UX work begins:

- Decisions 1–4 above.
- A working Android build environment, and the first real-device run of the
  diagnostics screen.
- `libi2pd` built for arm64-v8a as the cheapest decisive I2P experiment.
- Confirmation that `slixmpp`, `aiodns` and `argon2-cffi` resolve for every
  enabled ABI. `argon2-cffi` matters most — without it the engine silently falls
  back to scrypt for the at-rest KDF.
- The Phase 4 `DekProvider` (Android Keystore/StrongBox) design reviewed, since
  the unlock UX and the vault are two halves of one mechanism.
