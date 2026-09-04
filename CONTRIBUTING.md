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
PSF) — see [LICENSING_AUDIT.md](LICENSING_AUDIT.md). One copyleft library added
for convenience would make the commercial half unsellable, and it would not be
obvious from the diff.

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

See [VERSIONING.md](VERSIONING.md). In particular: the wire-format version
constants are compatibility predicates, not release numbers, and must not be
bumped to mark a release.

## Scope of the security posture

The project is a research prototype. It has not had a third-party cryptographic
review, and nothing in a pull request should describe it as if it had. Claims in
documentation must be traceable to code or to a measurement — see
[SECURITY.md](SECURITY.md) for the standard the existing caveats are held to.
