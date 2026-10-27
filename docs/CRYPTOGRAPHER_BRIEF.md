# Brief for a cryptographer

**The ask, first.** OTRv4+ is a solo, open-source messenger (AGPL-3.0)
that extends OTRv4 with ML-KEM-1024 and ML-DSA-87, with its cryptography in
a Rust core. It has not been independently reviewed. Seven questions came
out of its own audit that testing cannot settle
(docs/CRYPTOGRAPHER_QUESTIONS.md). Each can be answered yes, no, or with a
counterexample, and each says what the code changes under either answer.
An answer to any one of them is useful. Two matter most: **Q1** and **Q2**,
on 1:1 content deniability.

**What this describes.** The `dev` branch at `cc3a030` (2026-10-27). The
latest release, rc.184 on `main`, predates two fixes made in this audit
(P1 and P2, below). The questions are about the constructions, which are
the same in both.

## What is claimed, and what is not

The project says only what a test in the repository shows. Where a
property needs a proof, it is not claimed; the mechanism is described
instead.

| Area | Claimed (a test shows it) | Not claimed |
|---|---|---|
| 1:1 sessions (SPEC §4-5) | X448 + ML-KEM-1024 ratchet (A1); the v2 handshake authenticates both sides with ML-DSA-87 and refuses a downgrade or a changed key for a pinned contact, across restarts (A2, P1) | that the hybrid combiner is secure when X448 falls (Q4) |
| 1:1 content (L1, SPEC §5.8) | every message's MAC key reaches the wire after a close, never before the message is delivered (an outsider holding only the frames checks it) | **any deniability property.** L1 is RESOLVED-CODE: the mechanism is shown, the property is Q1 and Q2 |
| Participation (SPEC §10.1) | -- | stated as a limitation: the v2 handshake signs with long-term ML-DSA-87 keys, so a transcript shows the two identities talked (Q3) |
| Groups (F4, MLS+) | composite Ed448 + ML-DSA-87 leaf keys rotate, and the retired key, both halves, is published to the members | any deniability property (Q5); the hybrid suite 0xF0A1 is this project's own construction, unreviewed |
| SMP (SPEC §6) | each run signs with a fresh ML-DSA-87 key | that prefixing a binding key is sound domain separation (Q7) |

The full map from each sentence the project publishes to the code, the
test and the residual is docs/AUDIT_CLAIM_MATRIX.md. Its status words:
- DEMONSTRATED: a test proves the sentence;
- PARTIAL: a test proves a narrower one;
- UNSUPPORTED: no test proves it;
- EXTERNAL: your questions.

## The seven questions, in one line each

| # | Question | Where |
|---|---|---|
| **Q1** | Can a MAC key published under the retirement rule (R1 received, R2 skipped key deleted, R3 close) ever again verify a message its publisher would accept, under loss, reordering, eviction and DH steps? One interleaving the audit cannot rule out is written out. | SPEC §5.8; `Rust/src/ratchet.rs` |
| **Q2** | With AES-GCM keyed by an unpublished MKenc, does publishing MKmac give OTR-style transcript deniability and nothing stronger, or less, because the GCM tag is a second authenticator nobody else can forge? | SPEC §5.3, §5.8, §10.1 |
| Q3 | Is the v2 handshake (a 2-member Ed448 ring signature beside long-term ML-DSA-87 signatures) offline-deniable for participation in any setting? | SPEC §4.3, §10.1; `Rust/src/dake.rs` |
| Q4 | (a) Is the combiner `SHAKE-256(... root ‖ dh_secret ‖ brace_key)` a sound hybrid when X448 is broken later? (b) Since the P2 fix, can loss keep fresh ML-KEM secrets out of the root while the X448 ratchet still steps? | SPEC §5.1-5.2; docs/PQC_DECISIONS.md (d) |
| Q5 | Does releasing a retired group leaf key give a meaningful deniability statement, given that the 1:1 handshakes binding the key to a person are attributable? | docs/MLS_SECURITY_HARDENING.md §1 |
| Q6 | Is a KEM-based v3 handshake (pinned long-term ML-KEM keys, no signatures) sound, and offline-deniable? Is it worth building before Q5? | docs/PQC_DECISIONS.md (e) |
| Q7 | Is `pq_binding_key ‖ message` under pure ML-DSA-87 a sound domain separation for SMP, compared with the FIPS 204 context? | SPEC §6.7; `Rust/src/smp.rs` |

## Known issues, stated before you find them

All are in docs/SECURITY_ISSUES.md with their tests.
- **P1 (High, resolved 2026-10-27).** On Android and the desktop, the
  contact's Ed448 fingerprint pin was never checked. Only the terminal
  client called the check. The pins also lived in memory, so after a
  restart any changed key was a first contact.
  - The audit first rated this "true within one run". Its test had called
    the trust database directly, not the app. That miss is recorded.
  - Now the apps check the pin when a session comes up, and keep each
    account's pins sealed. The tests drive two real app instances over a
    wire. 14 of 14 mutants of the fix are killed.
- **P2 (High, resolved 2026-10-26).** The engine could take a second DH
  send step toward a remote key it had already stepped toward. The peer
  cannot follow that step, so every later message failed to decrypt,
  silently. It happened in ordinary use: measured, the 101st message from
  one side after a DH round trip, or a chat open across two days. The fix
  is in the engine, not the Rust core.
  - **Residual:** any v2 build before the fix, the released rc.184
    included, still takes the step. Our side cannot follow it either. It
    ends when the peer updates. The owner chose not to change the Rust
    receive path before review.
- **TOFU.** The first contact's key is pinned unchecked unless the two
  people run SMP. No primitive closes this.
- **Keys outside Rust.** Session keys stay in Rust; Python holds handles.
  Two secrets do not:
  - the voice ML-KEM decapsulation key, a Python `bytearray` wiped once
    decapsulation completes (SECURITY.md, memory model);
  - the key-encryption key of the at-rest stores (B1), a Python `bytes`,
    which cannot be wiped.
- **Pin stores that will not open** are refused, never replaced: contact
  pins in every client, and the X1 server pins. Until 2026-10-27 the
  terminal's contact pins were plaintext and failed open, and the server
  pins read a damaged file as empty. Both are fixed, with tests.

## How to check the work

Tests, not prose, are the evidence. From a checkout of `dev`:

```
# Rust core: the handshake, the ratchet (A1, L1, P2) and SMP
cd Rust && cargo test --release
#   dake::pq_auth_tests, ratchet::l1_retirement, ratchet::pq_ratchet,
#   smp::...pq_smp_each_run_signs_with_fresh_ml_dsa_keys

# MLS+: the provider, the composite keys, F4 publication
cd Rust/mls && cargo test --release
#   client::retired_key_tests, client::f4_containment_tests

# The Python engine and the apps' bridge, over the Rust extension.
# Python 3.12 or later (Rust/pyproject.toml); 3.11 cannot parse the engine.
python3.12 -m venv .venv && . .venv/bin/activate
pip install 'maturin>=1.0,<2.0' pytest cryptography
OTRV4PLUS_ALLOW_RAW_KEY_TEST_API=1 maturin develop --release \
  --manifest-path Rust/Cargo.toml \
  --features pyo3/extension-module,android-opus,mls,raw-key-test-api
python -m pytest -q tests/test_deniability_wire_audit.py \
  tests/test_l1_revelation_gate.py tests/test_l1_crash_during_close.py \
  tests/test_pq_auth_v2.py tests/test_p1_trust_pins_per_run.py \
  tests/test_p2_forced_steps.py
#   89 tests, in under a minute after the build
```

These steps were run as written in a fresh environment on 2026-10-27.
The Rust suites gave 199 and 70 passing tests. The full Python suite
(8182 passing) needs more packages; `.github/workflows/python.yml`
installs them. `raw-key-test-api` builds a test-only accessor, and
`tests/test_release_guard.py` checks that the shipped build has no such
entry point.

**How the claims were tested.** The audit of 2026-10-26 and 2026-10-27:
- docs/AUDIT_CLAIM_MATRIX.md: every sentence, its code, its test and its
  residual. It was re-run end to end after P1, with a check that the fix
  weakened no neighbouring claim. That check found two weakenings in the
  fix itself, both fixed before commit.
- docs/AUDIT_TEST_INTEGRITY.md: each test read against its name, and three
  rounds of mutation testing. Every surviving mutant is killed by a new
  test or shown equivalent.
- docs/AUDIT_THREAT_MODEL.md: each adversary walked against the code.
- docs/DENIABILITY_LAYERS.md: the three layers (1:1 content, group
  content, participation) on one page, for a reviewer who does not want
  to read `ratchet.rs`.

Gates in the suite keep the words honest:
- `tests/test_deniable_wording.py`: no user-visible string claims a
  property;
- `tests/test_security_doc_references.py`: every cited test exists.

## Not in scope of the questions

- Implementation review: side channels, constant time, memory hygiene.
  docs/AUDIT_HANDOFF.md is the brief for that kind of review.
- The I2P, XMPP and Android layers, and the server.
- The epochal ML-DSA prototype (`research/epochal-mldsa/`). It was
  evaluated and not adopted; its ANALYSIS.md explains why.

## Replying

Open an issue at <https://github.com/muc111/OTRv4Plus/issues>. To answer
privately first, use the I2P contact on the maintainer's GitHub profile
(SECURITY.md, "Reporting issues"). Partial answers, counterexamples and
"this question is wrongly posed" are all useful. The project is unfunded;
there is no bounty. Each answer, with credit if you want it, goes into
docs/SECURITY_ISSUES.md beside the entry it settles.
