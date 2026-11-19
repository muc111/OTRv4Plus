# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The REUSE layout: every licence named has its text, and no text is idle.

LICENSES/ holds the licences this repository's own files are under;
third_party/licences/ holds the texts only bundled components use, which
NOTICE reproduces. docs/LICENCE_TEXTS.md says which is which. The copies of
the project's own licences must not drift from the root files people read.
"""
import importlib.util
import os
import re
import shutil
import subprocess
import tomllib

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LICENSES = os.path.join(ROOT, "LICENSES")
THIRD_PARTY_TEXTS = os.path.join(ROOT, "third_party", "licences")


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as handle:
        return handle.read()


def _words(text):
    return re.sub(r"[^a-z0-9]+", " ", text.lower()).split()


def _ids_in(directory):
    return {name[:-4] for name in os.listdir(directory) if name.endswith(".txt")}


def _identifiers_in_reuse_toml():
    found = set()
    for annotation in tomllib.loads(_read("REUSE.toml"))["annotations"]:
        found.update(re.findall(r"[A-Za-z0-9.+-]+",
                                annotation["SPDX-License-Identifier"]))
    return found - {"OR", "AND", "WITH"}


def test_the_commercial_licence_copy_is_the_root_file():
    assert (_read("LICENSES", "LicenseRef-OTRv4Plus-Commercial.txt")
            == _read("LICENSE-COMMERCIAL.md"))


def test_the_agpl_text_is_the_one_in_LICENSE():
    root = _read("LICENSE")
    spdx = _read("LICENSES", "AGPL-3.0-only.txt")
    title = "GNU AFFERO GENERAL PUBLIC LICENSE"
    assert _words(root[root.index(title):]) == _words(spdx[spdx.index(title):])


def test_every_identifier_used_has_a_text():
    have = _ids_in(LICENSES)
    software = {"AGPL-3.0-only", "LicenseRef-OTRv4Plus-Commercial"}
    assert (_identifiers_in_reuse_toml() | software) <= have


def test_licenses_holds_only_what_files_here_are_under():
    """A text nothing here is under belongs in third_party/licences/."""
    assert _ids_in(LICENSES) == _identifiers_in_reuse_toml() | {
        "AGPL-3.0-only", "LicenseRef-OTRv4Plus-Commercial"}
    assert not (_ids_in(LICENSES) & _ids_in(THIRD_PARTY_TEXTS))
    assert not os.path.exists(os.path.join(LICENSES, "README.md"))


def test_the_notice_generator_still_finds_every_text():
    spec = importlib.util.spec_from_file_location(
        "generate_notice", os.path.join(ROOT, "tools", "generate_notice.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for spdx_id in _ids_in(THIRD_PARTY_TEXTS) | {"Apache-2.0", "MIT"}:
        text = module.licence_text(spdx_id)
        assert text and len(text) > 200, spdx_id


def test_the_index_names_every_text():
    index = _read("docs", "LICENCE_TEXTS.md")
    for spdx_id in _ids_in(LICENSES) | _ids_in(THIRD_PARTY_TEXTS):
        assert spdx_id + ".txt" in index, spdx_id


def test_reuse_lint_passes():
    tool = shutil.which("reuse")
    if tool is None:
        pytest.skip("the reuse tool is not installed here")
    done = subprocess.run([tool, "lint"], cwd=ROOT, capture_output=True,
                          text=True, timeout=300)
    assert done.returncode == 0, done.stdout[-3000:]
