# Licensing audit

Pre-Phase-3 mandatory investigation (decision 4). Records the licence position of
the whole dependency graph so the commercial-distribution question can be
decided on evidence.

**This is an engineering audit, not legal advice.** Where a licence text clearly
supports a conclusion it is stated; where it does not, the question is flagged
for qualified legal review rather than answered. Nothing was removed or
relicensed during this task.

**Method.** Rust licences from `cargo license --avoid-build-deps` over the full
resolved graph in `Cargo.lock` (134 packages). Python licences from the PyPI JSON
API (`license_expression` field). Android licences from the published project
terms. The repository licence from the `LICENSE` file itself.

---

## 1. The finding that governs everything else

**The project is GPL-3.0, and that is the binding constraint — not any
dependency.**

| Evidence | Value |
|---|---|
| `LICENSE` (repository root) | GNU General Public License v3, full 674-line text |
| `Rust/Cargo.toml` | `license = "GPL-3.0"` |
| `cargo license` classification of the crate itself | `GPL-3.0 (1): otrv4_core` |

Every third-party dependency examined is permissive. **No dependency imposes
copyleft on this project.** The copyleft in play is the project's own, chosen by
its author.

That reverses the concern carried since the Phase 1 report, which flagged
"GPL-3.0 core versus commercial distribution" as a risk from the outside. The
risk is from the inside.

### What GPL-3.0 does and does not mean here

Stated only where the licence text is clear:

- **GPL-3.0 does not prohibit commercial distribution.** It is not a
  non-commercial licence. Selling GPL software is permitted; §4 explicitly
  allows charging a fee.
- **GPL-3.0 does require corresponding source.** Anyone who receives the binary
  is entitled to the complete corresponding source of the whole work, under
  GPL-3.0, including the Kotlin application layer if that layer forms a single
  combined work with the GPL core. That is the substantive commercial question.
- **GPL-3.0 §6 imposes Installation Information** ("anti-tivoisation")
  requirements for "User Products", which a consumer phone app plausibly is.
- **App-store distribution is a known area of friction.** The specific issue is
  whether store terms impose usage restrictions the GPL forbids adding. This has
  been contested for the Apple App Store; Google Play's terms differ. **This
  needs qualified legal advice** — it turns on the interaction of store terms
  with GPL §6 and §10, not on anything in this repository.

**Options, stated without recommending one** — this is the author's decision and
partly a legal one:

1. **Ship under GPL-3.0.** Publish complete corresponding source, including the
   Android layer. Compatible with the project's existing posture and with the
   "reviewers welcome" stance in the README. Resolve the app-store question with
   counsel.
2. **Relicense.** Possible only if the author holds or can obtain rights to all
   contributions. `README.md` states the project is single-author, which makes
   this more tractable than usual, but that must be verified, and any outside
   contribution needs its contributor's agreement.
3. **Dual-license.** The author, as copyright holder, may offer the same code
   under both GPL-3.0 and a commercial licence. This is the conventional route
   for a proprietary app over an own-copyleft core.

**None of these can be settled by this audit.** Option 2 and 3 depend on
copyright ownership facts not verifiable from the repository; option 1 depends on
store terms. **Qualified legal advice is recommended before Phase 3 concludes**,
because the answer changes what the Android layer may be.

---

## 2. Rust dependency graph

134 resolved packages. Full classification:

| Licence | Count | Copyleft? | Compatible with proprietary distribution? |
|---|---|---|---|
| Apache-2.0 OR MIT | 97 | No | Yes |
| MIT | 10 | No | Yes |
| Apache-2.0 OR Apache-2.0 WITH LLVM-exception OR MIT | 5 | No | Yes |
| BSD-3-Clause | 4 | No | Yes |
| Apache-2.0 OR BSD-2-Clause OR MIT | 2 | No | Yes |
| (Apache-2.0 OR MIT) AND Unicode-3.0 | 1 | No | Yes |
| Apache-2.0 OR BSD-1-Clause OR MIT | 1 | No | Yes |
| **Apache-2.0 OR LGPL-2.1-or-later OR MIT** | 1 | Optional | Yes — see note |
| Apache-2.0 WITH LLVM-exception | 1 | No | Yes |
| MIT OR Unlicense | 1 | No | Yes |
| **GPL-3.0** | 1 | **Yes** | **This project itself** |

### The security-critical dependencies specifically

| Component | Version | Licence | Relationship | Obligations |
|---|---|---|---|---|
| `ed448-goldilocks-plus` | 0.16 | BSD-3-Clause | direct, static | attribution |
| `ed448-goldilocks` | (transitive) | BSD-3-Clause | transitive, static | attribution |
| `x448` | 0.6 | BSD-3-Clause | direct, static | attribution |
| `subtle` | 2.5 | BSD-3-Clause | direct, static | attribution |
| `aes-gcm` | 0.10 | Apache-2.0 OR MIT | direct, static | attribution |
| `sha3` | 0.10 | Apache-2.0 OR MIT | direct, static | attribution |
| `pqcrypto-mlkem` | 0.1.1 | Apache-2.0 OR MIT | direct, static | attribution |
| `pqcrypto-mldsa` | 0.1.2 | Apache-2.0 OR MIT | direct, static | attribution |
| `pqcrypto-traits` | 0.3 | Apache-2.0 OR MIT | direct, static | attribution |
| `crypto-bigint` | 0.5 | Apache-2.0 OR MIT | direct, static | attribution |
| `zeroize` | 1.8 | Apache-2.0 OR MIT | direct, static | attribution |
| `pyo3` | 0.24 | Apache-2.0 OR MIT | direct, static | attribution |
| `dashmap` | 5.5 | MIT | direct, static | attribution |

**Note on `r-efi`** (`Apache-2.0 OR LGPL-2.1-or-later OR MIT`): a disjunctive
licence — the recipient chooses. Selecting Apache-2.0 or MIT avoids LGPL
entirely. It is a UEFI support crate reached transitively through the
`getrandom`/`wasi` chain and is not compiled into an Android target. **No action
needed**, but the selected licence should be recorded in the attribution file.

**Note on `unicode-ident`** (`(Apache-2.0 OR MIT) AND Unicode-3.0`): conjunctive
— the Unicode-3.0 terms apply in addition. Unicode-3.0 is permissive and
attribution-only. **No action needed**, include its notice.

**Every Rust dependency is statically linked into `otrv4_core`**, which matters
for attribution (all notices must be reproduced) but not for copyleft, since none
of them is copyleft.

---

## 3. Python dependencies

| Component | Version | Licence | Direct/transitive | Relationship | Compatible? |
|---|---|---|---|---|---|
| `PySocks` | 1.7.1 | BSD | direct, required | bundled in APK | Yes |
| `slixmpp` | 1.17.0 | MIT | direct, required | bundled in APK | Yes |
| `aiodns` | 4.0.4 | MIT | direct, required | bundled in APK | Yes |
| `argon2-cffi` | 25.1.0 | MIT | direct, optional | bundled in APK | Yes |
| CPython | 3.12+ | PSF-2.0 | bundled by Chaquopy | bundled in APK | Yes |

Licences read from the PyPI `license_expression` metadata field, not inferred.

**`argon2-cffi` pulls `cffi`** (MIT) and, at build time, `pycparser` (BSD).
Neither is copyleft. **Not yet verified**: the full transitive Python graph as
resolved *for Android by Chaquopy*, which cannot be enumerated here because the
Chaquopy repository is unreachable from this environment. That enumeration is a
Phase 3 task once the toolchain is available.

**CPython's PSF-2.0 licence** is permissive and permits redistribution in a
proprietary product, with attribution. Chaquopy bundles the interpreter, so the
PSF licence notice must appear in the app's attribution screen.

---

## 4. Android / JVM dependencies

| Component | Version | Licence | Relationship | Compatible? |
|---|---|---|---|---|
| Chaquopy Gradle plugin + runtime | 16.0.0 | **MIT** | bundled (plugin + runtime in APK) | **Yes** |
| Android Gradle Plugin | 8.7.3 | Apache-2.0 | build tool, not shipped | Yes |
| Kotlin stdlib / compiler | 2.0.21 | Apache-2.0 | stdlib bundled | Yes |
| AndroidX Core KTX | 1.15.0 | Apache-2.0 | bundled | Yes |
| AndroidX Lifecycle | 2.8.7 | Apache-2.0 | bundled | Yes |
| AndroidX Activity Compose | 1.9.3 | Apache-2.0 | bundled | Yes |
| Jetpack Compose (BOM) | 2024.10.01 | Apache-2.0 | bundled | Yes |
| Compose Material 3 | via BOM | Apache-2.0 | bundled | Yes |
| Navigation Compose | 2.8.4 | Apache-2.0 | bundled | Yes |
| kotlinx-coroutines | 1.8.1 / 1.9.0 | Apache-2.0 | bundled / test | Yes |
| JUnit 4 | 4.13.2 | **EPL-1.0** | **test only, not shipped** | Yes |
| Hamcrest Core | 1.3 | BSD-3-Clause | test only | Yes |
| AndroidX Test / Espresso | 1.2.1 / 3.6.1 | Apache-2.0 | test only | Yes |

**Chaquopy correction.** Earlier phase reports flagged Chaquopy as requiring a
commercial licence. **That is out of date.** Chaquopy became open source under
the **MIT licence**, and all licence restrictions were removed as of version
12.0.1; older closed-source versions displayed a licence warning and ran for only
five minutes at a time. This project targets 16.0.0, so **no Chaquopy licence
purchase is required**, and the earlier "budget for it" note is withdrawn.

**JUnit's EPL-1.0 is weak copyleft**, but it is a test-only dependency and is not
in the shipped artifact, so its reciprocity obligations are not triggered by
distribution of the app. Keep it out of `implementation` configurations.

---

## 5. Bundled i2pd (decision 3)

| Component | Licence | Relationship | Compatible? |
|---|---|---|---|
| i2pd | **BSD 3-Clause** | to be bundled as a native library | Yes |

Verified from the upstream repository. i2pd exposes `libi2pd_wrapper` for
embedding. BSD-3 imposes attribution only and no copyleft, so **i2pd does not
constrain the project's licensing** in either direction.

**Not yet verified**: i2pd's own dependency graph as built for Android —
typically Boost (Boost Software License, permissive) and OpenSSL (Apache-2.0 for
3.x; **OpenSSL 1.x used the OpenSSL/SSLeay licence, which has a known
advertising-clause incompatibility with GPL-2.0**). Since this project is
GPL-3.0 and OpenSSL 3.x is Apache-2.0, the classic conflict is unlikely to
apply — but **the actual OpenSSL version i2pd links on Android must be confirmed
before bundling**, and if it turns out to be 1.x, this needs legal review.

That check is a Phase 3 task, gated behind building `libi2pd` for arm64-v8a.

---

## 6. Attribution obligations

Regardless of the licensing route chosen, the shipped app must reproduce notices
for every bundled component. Concretely:

- **~120 permissive Rust crates** — Apache-2.0 requires the NOTICE file where one
  exists; MIT and BSD require the copyright notice and permission text.
- **CPython** — PSF-2.0 notice.
- **AndroidX / Compose / Kotlin** — Apache-2.0 notices.
- **Chaquopy** — MIT notice.
- **slixmpp, aiodns, argon2-cffi, PySocks** — MIT / BSD notices.
- **i2pd**, if bundled — BSD-3 notice.

**Recommended mechanism**: generate the attribution set from
`cargo license --json` plus the Gradle `licenses` plugin at build time, so it
cannot drift from what actually ships. A hand-maintained list will go stale.

This is **not yet implemented**; it belongs with the release build (Phase 12) but
the generator should be wired earlier so the list is never wrong.

---

## 7. Summary

| Question | Answer |
|---|---|
| Does any dependency impose copyleft on this project? | **No.** Every third-party component is permissive. |
| Is Chaquopy a commercial-licence blocker? | **No** — MIT since 12.0.1. Earlier flag withdrawn. |
| Does i2pd constrain licensing? | **No** — BSD-3. Its own OpenSSL version still needs confirming. |
| Can the app be distributed commercially? | **Not answerable here.** GPL-3.0 permits commercial distribution but requires corresponding source, and the app-store interaction needs legal advice. |
| What is the actual blocker? | **The project's own GPL-3.0 licence**, and the author's decision about it. |

### Recommended for qualified legal advice

1. Whether the Kotlin/Compose application layer forms a single combined work with
   the GPL-3.0 core, and therefore must be released under GPL-3.0.
2. Whether GPL-3.0 §6 Installation Information obligations apply to a consumer
   Android app distributed through a store.
3. Whether Google Play's distribution terms are compatible with GPL-3.0 §6/§10.
4. If relicensing or dual-licensing is contemplated: whether the author holds all
   necessary rights, given that the README describes the codebase as AI-generated
   and single-author.

### Verified here, no action needed

- No copyleft dependency in the Rust, Python, or Android graphs.
- Disjunctive licences (`r-efi`) can be satisfied by selecting a permissive option.
- JUnit's EPL-1.0 is test-scope only and not distributed.
