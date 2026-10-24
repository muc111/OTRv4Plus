# Contributing

OTRv4+ is a solo, AI-assisted project. Contributions are welcome; review
capacity is one person's evenings, so scope matters more than speed.

> This file used to be a note describing a single-line edit to a document that
> no longer existed. That edit is applied below.

## Licensing: sign off on every commit

OTRv4+ is dual-licensed as of v10.17.0 — [AGPL-3.0](LICENSE) for everyone, plus
a [commercial licence](LICENSE-COMMERCIAL.md) for those who cannot comply with
it. That only works while one party can grant both, so contributions come in
under the [CLA](CLA.md):

```bash
git commit -s -m "your message"
```

The `-s` adds a `Signed-off-by:` line, and that line is your agreement to
[CLA.md](CLA.md). You keep your copyright — the CLA is a licence you grant, not
an assignment, and your contribution stays under the AGPL like everything else.
A patch contributed under the AGPL alone could never be offered commercially,
and after a few of those the commercial option would be gone without anyone
having decided to end it.

**Paid work is different.** A contractor's deliverable should be assigned, not
licensed; see [CONTRACTOR-IP.md](CONTRACTOR-IP.md) before commissioning any.

**Adding a dependency?** Say so in the pull request and name its licence. Every
dependency in the tree today is permissive (MIT, Apache-2.0, BSD-3-Clause,
PSF) — see [docs/LICENSING_AUDIT.md](docs/LICENSING_AUDIT.md). One copyleft library added
for convenience would make the commercial half unsellable, and it would not be
obvious from the diff.

Two guards enforce that, so a mistake here fails a build rather than reaching a
release:

```bash
python3 -m pytest tests/test_licence_declarations_agree.py   # the Rust graph
cd android && ./gradlew :app:checkRuntimeDependencyLicences  # the Android graph
```

Both resolve the real dependency graph rather than reading the build files, and
both fail on a module with no permissive option — or on one whose licence they
cannot determine, because "we could not tell" is exactly the state worth
stopping on. Test-only dependencies are excluded on purpose: JUnit is Eclipse
Public License and is fine, because it is not in the artifact anyone receives.

## New files carry an SPDX header

Any **new** source file — `.py`, `.rs`, `.kt`, `.kts` — starts with:

```
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
```

(`//` instead of `#` in Kotlin, Rust and Gradle files.) The repository-root
`LICENSE` already covers every file in the tree, so this changes nothing about
the terms. It means a file that gets copied out of the repository — into a bug
report, a gist, a vendored directory in someone else's project — carries its
terms with it instead of arriving bare.

**Existing files are deliberately left alone.** A retroactive sweep across
~200 files would be a large diff that changes no licence and buries real
history in `git blame`. `tests/test_spdx_headers_on_new_files.py` enforces the
rule on files added after 2026-09-14 and exempts everything older, so the
policy applies going forward without rewriting what is already here.

## Repository layout

| Path | What is there |
|---|---|
| `Rust/` | The core: every cryptographic primitive, built as the `otrv4_core` Python module |
| `client/` | The Python engine (`otrv4+.py`) and the terminal clients: IRC (`otrv4plus_irc.py`) and XMPP (`otrv4plus_xmpp.py` and its `otrv4plus_xmpp_*.py` parts) |
| `android_bridge/` | The app's Python API over the engine, used by the phone and the desktop app |
| `android/`, `desktop/` | The Android app and the desktop app (Kotlin, Compose) |
| `desktop_bridge/` | The desktop app's engine process |
| `prosody/`, `qubes/` | Server modules and the Qubes OS packaging |
| `tests/` | Every Python test (`pytest tests`) |
| `tools/` | One-off utilities |
| `docs/` | Specs, design notes, test plans and dated audits ([index](docs/README.md)) |

`otrv4+.py` and `otrv4plus_xmpp.py` at the top level are symlinks into
`client/`, so `python otrv4+.py` and `python otrv4plus_xmpp.py` still work.
Module names are flat (`import otrv4plus_voice`): `client/` is put on the import
path, not imported as a package.

## Regression guards

Checks added after something slipped through; each fails CI rather than
waiting for a phone to find it.

- `tests/test_no_unresolved_globals.py`: no function reads a global its
  module lacks (Python finds those only when the line runs; two were in
  error branches no test reached).
- `tests/test_failures_reach_the_screen.py`: every failure code the bridge
  emits has a sentence in the app (`FailureText`) or a `QUIET` entry saying
  why not; an unknown code is shown by name, never dropped.
- `tests/test_failure_codes_registered.py`: every failure code the bridge
  can produce is listed in `android_bridge/codes.py` with its meaning, and
  is written to the debug log when it happens; the diagnostic report opens
  with a tally of codes seen.
- `tests/test_dispatch_families.py`: every terminal command belongs to
  exactly one `_dispatch_*` family of `dispatch_line`.
- `RouterChoiceTest` and `tests/test_android_bundled_router.py`: an I2P
  router on the phone counts only when its SAM bridge answers our HELLO,
  and it is asked before the built-in router starts.
- `tests/test_client_finds_the_bridge.py`: a terminal client started from
  `client/` can import `android_bridge`.
- `tests/test_ci_watches_what_it_tests.py`: the desktop install job runs
  when anything it installs changes.
- `tests/source_of.py`: when a class or file is split, tests that scan
  "the whole client" read all of its parts, so a "this must never happen"
  check cannot go quiet because the code moved.

## Before you write code

Open an issue first to discuss. The single-file Python design is intentional —
new features should be integrated there unless they require a new Rust crate or
a new module in the Rust core (e.g. a new cryptographic primitive, a new secret
type). The C-extension path mentioned in earlier versions of this document was
retired at v10.7.5 (Phase 5.3k); new C code is no longer accepted into the
project.

## What will be rejected without discussion

These are not style preferences. They are the reasons the project exists.

- **Reducing the I2P hop count.** Three hops each way is the anonymity
  configuration and it is not negotiable, including as a latency fix.
- **Any automatic transport downgrade.** I2P or Tor falling back to TLS or
  clearnet, silently or otherwise. Failure is closed, never downgraded.
- **Voice over any transport other than I2P.** There is no Tor UDP transport,
  and carrying constant-rate media over TCP trades away the property the
  datagram transport exists to provide.
- **Weakening, reordering or bypassing** the OTRv4 DAKE, SMP verification, the
  double ratchet, message-key accountability, replay protection, skipped-key
  handling, epoch/rekey handling, AES-256-GCM media encryption, X448, Ed448,
  HKDF-SHA512, the ML-KEM or ML-DSA components, Rust secret handling, or
  fail-closed behaviour.
- **Making a UI string a security predicate.** Authorisation comes from the
  engine's cryptographic state, never from peer-controlled text.
- **Enabling DTX or variable packet sizing** in the production voice profile:
  both make packet size and timing depend on speech.
- **Logging** plaintext audio or messages, keys, seeds, session secrets,
  fingerprints, destinations, or raw sensitive payloads.
- **An unencrypted benchmark path** that could later be mistaken for production
  code.

## Comments

Comments say what the code is for and what must stay true. History goes
in the commit message and `CHANGELOG.md`.

- **Explain intent and invariants:** why a step happens in that order, what
  must never happen ("never plaintext once OTR was asked for"), which input
  is untrusted, why a bound exists.
- **No incident stories in code.** "Device report (date): …", "this used
  to …", "THE DEFECT THIS FIXES", quotes from a conversation, rc numbers and
  line references all go stale. Put the story in the commit; leave the rule
  in the code.
- **Keep it proportional.** A two-line method gets a one-line docstring. A
  long docstring is for real design (a wipe's ordering, a protocol step), not
  for narrating how it was found.
- **Name the test that holds a rule** when there is one
  (`tests/test_x.py`); that is more useful to a reader than prose.
- **Security notes stay.** What crosses a trust boundary, what is never
  logged, why a check is fail-closed: keep these, briefly.

## Testing

Run the suite from the repository root, not from `tests/` — the root-level
voice and audio suites are not under `tests/` and are otherwise skipped
silently:

```bash
python3.12 -m pytest -q          # 1483 passed, 43 skipped, 1 xfailed
cd Rust && cargo test --lib      # 65 passed
```

Python 3.12 or newer is required; on 3.11 `otrv4+.py` does not parse.

**A passing count is not evidence.** For any new production invariant: write the
test, then remove or invert the behaviour it protects and confirm the test
fails, then restore it and confirm it passes. A test that passes with the
production code deleted is worse than no test, because it reads as coverage.

Unit tests do not catch protocol desynchronisation between two peers, and they
have never caught a voice defect. Every voice bug fixed so far was found in a
live call. Live-test between two sessions over I2P before proposing anything
that touches the wire.

## Versioning

See [docs/VERSIONING.md](docs/VERSIONING.md). In particular: the wire-format version
constants are compatibility predicates, not release numbers, and must not be
bumped to mark a release.

## Scope of the security posture

The project is a research prototype. It has not had a third-party cryptographic
review, and nothing in a pull request should describe it as if it had. Claims in
documentation must be traceable to code or to a measurement — see
[SECURITY.md](SECURITY.md) for the standard the existing caveats are held to.
