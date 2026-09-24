#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The licensing map (LICENSING.md, REUSE.toml) matches the files.

Documentation is CC BY-SA 4.0 and source code is AGPL-3.0-only OR the
commercial licence. A document that is not listed, or a document header that
names the wrong licence, would put the two in disagreement -- and the
disagreement is what a reader relies on the map to prevent.
"""

import os
import subprocess
import tomllib

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LEGAL = {"LICENSE-COMMERCIAL.md", "CLA.md", "CONTRACTOR-IP.md"}
SOFTWARE = "AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial"


def _reuse():
    with open(os.path.join(ROOT, "REUSE.toml"), "rb") as fh:
        return tomllib.load(fh)


def _paths_for(licence):
    out = []
    for a in _reuse()["annotations"]:
        if a["SPDX-License-Identifier"] == licence:
            out.extend(a["path"] if isinstance(a["path"], list) else [a["path"]])
    return out


def _tracked(pattern):
    try:
        return subprocess.run(["git", "ls-files", pattern], cwd=ROOT, capture_output=True,
                              text=True, check=True).stdout.split()
    except Exception:
        pytest.skip("not a git checkout")


def test_every_document_is_declared():
    docs = set(_paths_for("CC-BY-SA-4.0"))
    undeclared = [f for f in _tracked("*.md") if f not in docs and f not in LEGAL]
    assert undeclared == [], (
        "Markdown files with no licensing declaration in REUSE.toml: %s" % undeclared)


def test_declared_documents_exist():
    missing = [p for p in _paths_for("CC-BY-SA-4.0")
               if not os.path.exists(os.path.join(ROOT, p))]
    assert missing == [], "REUSE.toml names files that do not exist: %s" % missing


def test_no_document_header_names_the_software_licence():
    wrong = []
    for f in _paths_for("CC-BY-SA-4.0"):
        if not f.endswith(".md"):
            continue
        head = open(os.path.join(ROOT, f), encoding="utf-8").read(400)
        if "SPDX-License-Identifier: " + SOFTWARE in head:
            wrong.append(f)
    assert wrong == [], "documents whose header says the software licence: %s" % wrong


def test_legal_instruments_are_not_relicensed():
    docs = set(_paths_for("CC-BY-SA-4.0"))
    assert not (LEGAL & docs)
    assert set(_paths_for("LicenseRef-OTRv4Plus-Legal")) >= LEGAL


def test_the_icon_carries_no_licence():
    assert "icon.png" in _paths_for("LicenseRef-OTRv4Plus-NoLicense")


def test_the_licence_text_and_the_specs_agree():
    assert os.path.exists(os.path.join(ROOT, "LICENSES", "CC-BY-SA-4.0.txt"))
    for spec in ("SPEC.md", "SPEC_GROUP.md"):
        head = open(os.path.join(ROOT, spec), encoding="utf-8").read(1500)
        assert "CC BY-SA 4.0" in head, spec
        assert "open decision" not in head, spec
    licensing = open(os.path.join(ROOT, "LICENSING.md"), encoding="utf-8").read()
    for needle in ("CC-BY-SA-4.0", SOFTWARE, "ASSETS.md", "CLA.md"):
        assert needle in licensing, needle
