# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Every reference in the security record resolves (audit 2026-10-26).

A gate named in docs/SECURITY_ISSUES.md that no longer exists, a renamed
test, a moved file or a SPEC section that is not there makes a claim look
backed when it is not. This checks, in the documents that state or audit
claims:
  * every repository path (`docs/...`, `tests/...`, `Rust/...`, ...) exists;
  * every `SPEC §N` / `SPEC.md §N` names a section heading of docs/SPEC.md;
  * every test name cited exists as a Python test, a Rust test or a Kotlin
    test somewhere in the repository.
"""
import functools
import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCS = ["docs/SECURITY_ISSUES.md", "docs/DENIABILITY_LAYERS.md", "docs/PQC_DECISIONS.md",
        "docs/AUDIT_CLAIM_MATRIX.md", "docs/AUDIT_TEST_INTEGRITY.md",
        "docs/AUDIT_THREAT_MODEL.md", "docs/CRYPTOGRAPHER_QUESTIONS.md",
        "docs/CRYPTOGRAPHER_BRIEF.md",
        "docs/AUDIT_SUMMARY.md", "docs/MLS_SECURITY_HARDENING.md", "SECURITY.md", "README.md"]
PATH = re.compile(r"(?<![\w/.-])((?:docs|tests|Rust|android_bridge|client|desktop_bridge|"
                  r"research|android/app/src|desktop/src)/[\w./-]+\.(?:md|py|rs|kt|toml|json|sh|yml))")
SPEC_REF = re.compile(r"SPEC(?:\.md)?\)?\s*§\s*(\d+(?:\.\d+)*)")
TEST_NAME = re.compile(r"`(?:[\w:]+::)?((?:test|residual|p[0-9]|pq|a|the|each|after|across|"
                       r"retired|nothing|only)_[a-z0-9_]{12,})`")

# Tests the audit record cites by name although they were removed on
# purpose: each asserted a residual that a later fix closed. A name here
# must really be gone, so it cannot stand in for a live test.
REMOVED = {
    "test_within_one_run_a_changed_key_is_refused":
        "P1: tested TrustDatabase, not the app (docs/AUDIT_TEST_INTEGRITY.md Round 3)",
    "test_residual_after_a_restart_of_the_app_a_changed_key_is_a_first_contact":
        "P1: the residual it asserted is fixed",
    "test_the_app_engines_are_built_with_a_trust_database_in_memory":
        "P1: the residual it asserted is fixed",
    "test_residual_an_unreadable_pins_file_makes_the_next_connection_first_use":
        "X1 residual 5: the residual it asserted is fixed",
    "the_epoch_authenticator_is_checked_before_any_group_message_is_accepted":
        "F4: renamed max_past_epochs_is_zero_in_every_group_config; the old name "
        "claimed a check MLS does not make",
}


def _read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


@functools.lru_cache(maxsize=1)
def _all_test_names():
    names = set()
    for base, dirs, files in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in (".git", "target", ".venv", "node_modules",
                                                "build", "__pycache__", ".gradle")]
        for f in files:
            if not f.endswith((".py", ".rs", ".kt")):
                continue
            try:
                src = open(os.path.join(base, f), encoding="utf-8").read()
            except (UnicodeDecodeError, OSError):
                continue
            names.update(re.findall(r"\bdef (\w+)\(", src))
            names.update(re.findall(r"\bfn (\w+)\(", src))
    return frozenset(names)


@functools.lru_cache(maxsize=1)
def _spec_sections():
    return frozenset(re.findall(r"^#+\s+(\d+(?:\.\d+)*)[\s.]", _read("docs/SPEC.md"), re.M))


@pytest.mark.parametrize("doc", DOCS)
def test_every_path_exists(doc):
    if not os.path.exists(os.path.join(ROOT, doc)):
        pytest.fail("%s is listed but missing" % doc)
    missing = sorted({p for p in PATH.findall(_read(doc))
                      if not os.path.exists(os.path.join(ROOT, p.rstrip(".")))})
    assert missing == [], "%s cites paths that do not exist: %r" % (doc, missing)


@pytest.mark.parametrize("doc", DOCS)
def test_every_spec_section_exists(doc):
    sections = _spec_sections()
    missing = sorted({n for n in SPEC_REF.findall(_read(doc))
                      if n not in sections and n.split(".")[0] not in sections})
    assert missing == [], "%s cites SPEC sections that do not exist: %r" % (doc, missing)


@pytest.mark.parametrize("doc", DOCS)
def test_every_cited_test_exists(doc):
    names = _all_test_names()
    cited = set(TEST_NAME.findall(_read(doc)))
    missing = sorted(n for n in cited if n not in names and n not in REMOVED)
    assert missing == [], "%s cites tests that do not exist: %r" % (doc, missing)


def test_a_test_listed_as_removed_is_really_gone():
    back = sorted(n for n in REMOVED if n in _all_test_names())
    assert back == [], "listed as removed but still defined: %r" % back
