<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright (C) 2025-2026 muc111 -->

# What is licensed how

OTRv4+ contains software, documentation, legal texts, third-party material and
artwork, and they are not all under the same terms. This file is the map.
`REUSE.toml` states the same thing per path in machine-readable form, and
`tests/test_licensing_scope.py` checks that the two agree with the files.

| Material | Licence | Where |
|---|---|---|
| **Source code** — Python, Rust, Kotlin, build scripts, workflows, tests, XML resources | `AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial` | [`LICENSE`](LICENSE), [`LICENSE-COMMERCIAL.md`](LICENSE-COMMERCIAL.md). SPDX header on each source file added since the policy began (`CONTRIBUTING.md`); older files carry it by this declaration. |
| **Documentation and specifications** — every Markdown document listed under *documentation* in `REUSE.toml`, including `README.md`, `SPEC.md`, `SPEC_GROUP.md`, `SECURITY.md`, the design and audit documents, test plans and changelogs; and the README screenshots | [`CC-BY-SA-4.0`](LICENSES/CC-BY-SA-4.0.txt) | Chosen by the author on 2026-09-24. |
| **Code in documentation** — snippets, commands and examples inside those documents | `CC-BY-SA-4.0` **and also** the software licence | So a snippet copied from a document into the codebase does not import a second licence into it. |
| **Legal instruments** — `LICENSE`, `LICENSE-COMMERCIAL.md`, `CLA.md`, `CONTRACTOR-IP.md` | Not licensed for modification; reproduce them verbatim | They are the terms themselves. Relicensing a licence is not a thing. |
| **Licence texts** — `LICENSES/*.txt` | Their own terms (the SPDX-published texts) | `LICENSES/README.md` |
| **Third-party material** — Rust crates, Python packages and Android libraries bundled in a build, and `third_party/` | Each component's own licence | [`NOTICE`](NOTICE), [`LICENSING_AUDIT.md`](LICENSING_AUDIT.md) |
| **Artwork** — `icon.png` and the launcher icons derived from it | **No licence asserted.** AI-generated placeholder | [`ASSETS.md`](ASSETS.md) |

## Why a separate documentation licence

The specification exists so that someone else can implement the protocol and
check this one. Under the software licence, quoting `SPEC.md` at length in
another project's documentation would raise an AGPL question that has nothing
to do with software. CC BY-SA 4.0 lets anyone copy, adapt and quote the
documents, commercially or not, as long as they credit the source and share
adaptations of the documents themselves under the same terms. It says
nothing about the software, which stays under its own licence.

## What changed, and what did not

Before 2026-09-24 every file without its own notice was under the software
licence, documentation included. Earlier revisions of the documents remain
available under that licence; nothing already granted is withdrawn. From that
date the documents are offered under CC BY-SA 4.0.

Contributions are made under [`CLA.md`](CLA.md), which grants the project the
right to license a contribution under terms other than the AGPL. That is what
lets a contributed document be distributed under CC BY-SA 4.0; clause 4 of
the CLA still holds, so contributed text also remains available under the
AGPL.

## Attribution

When reusing documentation: "OTRv4+ documentation, © 2025-2026 muc111,
CC BY-SA 4.0, https://github.com/muc111/OTRv4Plus", with a note of any
changes.
