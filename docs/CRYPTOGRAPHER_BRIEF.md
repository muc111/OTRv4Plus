# Brief for a cryptographer

**What deniability the shipped code provides, stated precisely.**
(The same statement closes docs/AUDIT_SUMMARY.md.)
- **1:1 content.** After a closed chat's MAC keys are published, anyone
  holding them can compute a valid outer MAC for any message of that
  session, so the MAC no longer singles out its sender. Whether the
  transcript then proves who wrote what is Q1 and Q2. It still proves that
  two identities ran a handshake, and the AES-GCM tag remains a second
  authenticator under a key that is never published (Q2).
- **Group content.** After a member's retired signing key is published,
  every member who received the publication can make signatures under it
  that verify exactly as the member's do. This holds only once every
  member has processed the rotation and deleted the old epoch's secrets.
  Before every other member has acknowledged it, the key is not published
  (SPEC §10, requirement 11): it stays on the publisher's device, and what
  it signed stays as provable as any signature.
- **Participation.** Not claimed. The v2 handshake's ML-DSA-87 signatures
  are attributable (A2, SPEC §10.1). Protocol v3's KEM-based handshake is
  the proposed fix, pending Q6a-6c.
- **What is not claimed:** pre-publication capture, partial close,
  crash-before-confirm, the second-closing gap, first contact (TOFU), and
  the A1 combiner under loss. Each is recorded as a residual with a named
  test, or as explicit review debt.
- **No deniability claim is made until Q1-Q7 are answered by an external
  cryptographer.** The mechanisms are built and demonstrated; the claim is
  not.

This describes `dev` as of 2026-10-27: the code at `d42add5` (F4
acknowledgement, in `e3f216a` and `d42add5`), and the documents of the
commit that adds this page. The release on `main`, rc.184, predates P1, P2
and F4.

## 1. The project

OTRv4+ is a solo, open-source messenger (AGPL-3.0). It extends OTRv4 with
ML-KEM-1024 and ML-DSA-87, keeps its cryptography in a Rust core, and has
MLS groups with a hybrid Ed448 + ML-DSA-87 suite. Nothing in it has been
independently reviewed.

## 2. What the epochal ML-DSA prototype demonstrates

From research/epochal-mldsa/RESULTS.md (`tools/prove.sh`, 2026-10-26).
The prototype was evaluated and not adopted (ANALYSIS.md).
- **FIPS 204:** keygen, signing and verification match NIST's ACVP vectors.
- **Exact forgery:** a holder of a 32-byte release reproduces the
  holder's signature byte for byte, for the same randomiser.
- **Three verifiers agree:** RustCrypto, PQClean and OpenSSL accept
  forgeries in the released epoch and reject them in any other (8/8).
- **Containment, over generated cases:** a release forges only its own
  epoch, and only closed epochs can be released.
- **Not vacuous:** 11/11 mutants are killed.
- **Not shown:** the assumptions (EUF-CMA, a one-way SHA3-256), a formal
  proof, erasure in memory, side channels, or the link from a key to a
  person.

## 3. The seven questions

Full entries are in docs/CRYPTOGRAPHER_QUESTIONS.md. Each one says what
the code changes under either answer.

| # | Question |
|---|---|
| **Q1** | Can a MAC key published under R1-R3 ever again verify a message its publisher would accept? One interleaving the audit cannot rule out is written out. |
| **Q2** | With AES-GCM keyed by an unpublished MKenc, does publishing MKmac give OTR-style transcript deniability, and nothing stronger or weaker? |
| Q3 | Is the v2 handshake (Ed448 ring signature beside long-term ML-DSA-87 signatures) offline-deniable for participation in any setting? |
| Q4 | (a) Is the SHAKE-256 hybrid combiner sound when X448 falls? (b) Since P2, can loss keep ML-KEM secrets out of the root while X448 steps? |
| Q5 | F4 containment rests on zero past epochs kept and on every member deleting them. Should that be (a) a documented invariant, (b) mandated at the wire level, or (c) never load-bearing, because publication waits for acknowledgement? |
| Q6 | Is a KEM-based v3 handshake sound and offline-deniable, and is it worth building first? |
| Q7 | Is prefixing a binding key to the message under pure ML-DSA-87 sound domain separation for SMP? |

## 4. What is explicitly not claimed

Each item is recorded in docs/DENIABILITY_LAYERS.md and
docs/SECURITY_ISSUES.md.
- **Participation attribution** (A2, SPEC §10.1): a transcript shows that
  the two identities ran a handshake.
- **Pre-publication capture:** a signature or MAC checked before its key
  is published stays checkable
  (`residual_a_signature_checked_before_release_still_checks_after_it`).
- **Partial close:** a lost part of a multi-part close leaves exactly its
  range provable until it is re-sent
  (`residual_a_lost_later_part_takes_its_range_with_it`).
- **Crash before confirmation:** a process killed between retirement and
  the server's confirmation leaves that close unpublished. Closing messages
  are kept in memory only, never on disk (`TestCrashDuringClose`).
- **The second-closing gap:** a contact whose app never closes keeps our
  lines' keys unrevealed
  (`test_residual_a_peer_that_never_closes_leaves_our_lines_provable`).
- **First contact (TOFU):** keys are pinned unchecked unless the two
  people run SMP. No primitive closes this.
- **A1 combiner under loss:** Q4.
- **F4 containment's own limits:** a modified client that keeps past
  epochs is undetectable by honest members (Q5). Publication waits for
  every member to come online.

## 5. What review is wanted

- Answers to Q1-Q7. Any one is useful, and Q1, Q2 and Q5 matter most.
- Optionally, the R1/R2/R3 retirement predicate (SPEC §5.8,
  `Rust/src/ratchet.rs`).
- Optionally, the F4 design with its containment rule (SPEC §10
  requirement 11, `Rust/mls/src/client.rs`, `f4_containment_tests`).
  `residual_a_member_that_has_not_processed_the_rotation_accepts_the_retired_key_until_it_does`
  shows the gap that the acknowledgement closes.

## 6. What the reviewer gets

- A working prototype and test suite to cite. Every claim maps to a test
  in docs/AUDIT_CLAIM_MATRIX.md.
- Credit in the repository (docs/SECURITY_ISSUES.md, beside the entry
  each answer settles) and in any write-up.
- The option to co-author the write-up of the F4 containment finding: a
  published group key stays live for members who have not processed the
  rotation.

**Checking the work.** On `dev`:
- `cd Rust && cargo test --release`: 199 tests;
- `cd Rust/mls && cargo test --release`: 78 tests;
- the Python suite, built as `.github/workflows/python.yml` builds it.

Gates keep the words honest: `tests/test_deniable_wording.py` and
`tests/test_security_doc_references.py`. Implementation review (side
channels, constant time) is out of scope here; docs/AUDIT_HANDOFF.md is
the brief for that.

**Replying.** Open an issue at
<https://github.com/muc111/OTRv4Plus/issues>, or use the I2P contact on the
maintainer's GitHub profile (SECURITY.md) to answer privately first.
Partial answers, counterexamples and "this question is wrongly posed" are
all useful. The project is unfunded; there is no bounty.
