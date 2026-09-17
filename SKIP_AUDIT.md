<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial -->
<!-- Copyright (C) 2025-2026 muc111 -->

# The 46 skips, and where each property is actually tested

A suite that reports `5081 passed, 46 skipped` is making two claims, and only
the first one is checked. This is the second one.

The question asked of every skip was **not** "can we make this test run here?"
It was:

> For the security property this skipped test represents, where is that
> property tested against the **production** configuration?

Three answers are possible. Only the third is a problem.

| | Meaning |
|---|---|
| **Complementary** | The property is covered by a different suite that runs precisely when this one skips. |
| **Not a property** | The skip belongs to a diagnostic or an absent optional feature, not to a security claim. |
| **Uncovered** | The property is tested nowhere. |

**Result: 45 accounted for, 1 uncovered.** The uncovered one is `AAudio`, and
it can only be closed on a handset.

---

## The six groups

### 1. `seed injection is gated out of production builds (decision B1)` — 36

`tests/test_android_identity.py`. The doubles there rebuild identity handles
from a raw seed, which needs `Ed448KeyHandle.from_seed_bytes` — gated out of
production wheels by decision B1 precisely because it lets Python inject a
chosen identity.

**Complementary.** `tests/test_rust_identity_sealing.py` covers the same
lifecycle against the production build, sealing inside Rust. Verified: it runs
**36 passed, 0 skipped** on this wheel — the same count, which is a coincidence
worth not reading anything into, but the coverage is real.

### 2. `production build: nothing to confirm` — 3

`tests/test_release_guard.py`. These are **inverse meta-guards**, not the
production assertions. They run only when `OTRV4PLUS_ALLOW_TEST_GATES=1`
declares a test build, and confirm the opt-in actually took effect — guarding
against a wheel that claims to be a test build but was compiled without the
feature, in which case the internals tests would skip and nothing would notice.

**Not a property, by construction.** On a production build there is genuinely
nothing to confirm, and the *production* assertions in the same file —
`test_production_artifact_exposes_no_raw_kdf`, the `Dakeresult` getter check,
and the object-file symbol scan — run unskipped.

This is the opposite of the pattern that bit us elsewhere: someone built both
halves deliberately so exactly one runs per configuration, then added guards
against either passing vacuously.

### 3. `core built without test-only-kdf` — 3

`tests/test_rust_security.py` (1) and `tests/test_harness_audit.py` (2).
`RustSMPVault.load` / `load_by_handle` are compiled out of production wheels,
so read-back tests cannot run.

**Complementary.** Their absence *is* the security boundary, and the assertion
that a production build must not expose them lives in
`test_release_guard.py`, which runs on exactly the builds where these skip.

### 4. `this interpreter parses PEP 701 f-strings` — 2

`tests/test_android_failure_report.py`. These check that a `SyntaxError` from
`otrv4+.py` is diagnosed as "wrong interpreter version" rather than as a code
fault. On 3.12 the syntax parses, so the condition cannot be constructed.

**Not a property.** This is a diagnostic-quality test, and the thing it guards
(a Chaquopy build pinned below 3.12) is asserted separately by the build
configuration.

### 5. `handle_line is not in this build` — 1

`tests/test_irc_guided_smp.py`. One parameter of a parametrised test over
inbound entry points, asserting INV-06: no inbound path reaches the passphrase
armer. `handle_line` is a WeeChat plugin method absent from this build.

**Not a property.** The invariant is covered by the other parameters, which
run. Only this one method name is absent.

### 6. `AAudio not present on this host` — 1 ⚠

`tests/test_android_audio_path.py::test_a_present_backend_is_not_silently_replaced`

> *"when AAudio IS available, asking for it must give it, not a fallback that
> would transmit silence."*

**UNCOVERED.** Its complement — the no-backend case — does run here, so the
pair splits across platforms: one half runs on Linux, the other only on
Android. The Android half has never been executed, because no handset test has
been performed.

This is a real hole and it is not closeable by a unit test. It is now item 10
on the handset gate in `ANDROID_XMPP_MILESTONE.md` §7.

---

## What this audit changed in the code

Finding the 45 to be legitimate rested on comments — each gated file names its
counterpart in prose. Prose cannot check itself, and this project has now had
three separate instances of a check that existed and was not running
(`answer_subscription` with no caller, the Python suite with no workflow, the
licence guard skipping under the workflow meant to run it).

So the complementarity is now **executed**, by
`tests/test_gated_build_is_uniform.py`.

The failure it exists to catch is a **mixed wheel** — some gates compiled in,
others not. Nothing checked that. A capability in that state is covered by
neither suite: the internals tests skip because it is absent, and the
production assertions skip because `OTRV4PLUS_ALLOW_TEST_GATES=1` declares a
test build. Both halves stand down and the suite goes green.

`test_release_guard.py` already guards the single-capability version of this,
per capability. What is new is the **across-capability** invariant: they must
agree with each other, not merely each with the flag.

Verified by planting a mixed build (one gated method present, the rest absent):
2 tests fail.

### One correction that came out of writing it

The first version of that file probed the module-level gated functions with
`hasattr`, and reported three of them present on a clean release wheel.

`tests/conftest.py` monkey-patches pure-Python stand-ins for `kdf_1`,
`rust_kdf_1` and `rust_encode_header` onto `otrv4_core` so older tests can run.
A real PyO3 entry point is a `builtin_function_or_method`; a shim is a
`function`. `test_release_guard._exposed_module_functions` already encoded that
distinction, so the new file **reuses that helper** rather than carrying a
second copy — a second copy being exactly the drift this audit is about.

---

## Standing conclusion

| Group | n | Verdict |
|---|---|---|
| seed injection gated (B1) | 36 | Complementary — `test_rust_identity_sealing` |
| production build: nothing to confirm | 3 | Not a property — inverse meta-guards |
| core built without test-only-kdf | 3 | Complementary — `test_release_guard` |
| PEP 701 f-strings | 2 | Not a property — diagnostic path |
| `handle_line` absent | 1 | Not a property — other parameters cover INV-06 |
| **AAudio not present** | **1** | **Uncovered — handset only** |

The skip count is not a number to drive down. 45 of these should keep skipping
on a release wheel; a build where they stopped would be a build shipping
test-only entry points. What matters is that each one is classified, and that
the classification is checked rather than remembered.
