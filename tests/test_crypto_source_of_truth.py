#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""CRYPTO_SOURCE_OF_TRUTH.md must describe the code that exists.

A document that names the one place each primitive lives is only useful
while it is true. These checks tie its names to Cargo.toml, to the built
module's exports, and to the Kotlin sources.
"""

import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOC = os.path.join(ROOT, "CRYPTO_SOURCE_OF_TRUTH.md")
KOTLIN = os.path.join(ROOT, "android", "app", "src", "main", "java")


def _doc():
    return open(DOC, encoding="utf-8").read()


def _table_rows():
    text = _doc()
    start = text.index("## Primitive by primitive")
    end = text.index("\n## ", start + 5)
    return [l for l in text[start:end].splitlines() if l.startswith("| ") and "---" not in l][1:]


def test_every_crate_named_is_a_dependency_of_the_core():
    cargo = open(os.path.join(ROOT, "Rust", "Cargo.toml"), encoding="utf-8").read()
    named = set()
    for row in _table_rows():
        crate_col = row.split("|")[2]
        named.update(re.findall(r"`([a-z0-9_-]+)`", crate_col))
    assert named, "the table names no crates"
    missing = [c for c in sorted(named)
               if not re.search(r"^(%s)\s*=|\[dependencies\.%s\]" % (re.escape(c), re.escape(c)),
                                cargo, re.M)]
    assert not missing, "named in the document but not in Cargo.toml: %s" % missing


def test_every_rust_module_named_exists():
    for row in _table_rows():
        for module in re.findall(r"`([a-z_]+\.rs)`", row.split("|")[3]):
            assert os.path.exists(os.path.join(ROOT, "Rust", "src", module)), module


def test_every_python_facing_type_named_is_exported():
    core = pytest.importorskip("otrv4_core")
    for row in _table_rows():
        for name in re.findall(r"`((?:Rust|X448|Ed448|MlKem|MlDsa)[A-Za-z0-9]+)`", row.split("|")[4]):
            assert hasattr(core, name), "the document names %s; the core does not export it" % name


def test_only_the_vault_uses_platform_cryptography_in_kotlin():
    users = []
    for dirpath, _, files in os.walk(KOTLIN):
        for f in files:
            if f.endswith(".kt"):
                src = open(os.path.join(dirpath, f), encoding="utf-8").read()
                if re.search(r"^import (javax\.crypto|java\.security)\.", src, re.M):
                    users.append(f)
    assert users == ["KeystoreVault.kt"], (
        "the document says the vault is Kotlin's only cryptography; now: %s" % users)


def test_the_removed_duplicates_stay_removed():
    engine = open(os.path.join(ROOT, "otrv4+.py"), encoding="utf-8").read()
    voice = open(os.path.join(ROOT, "otrv4plus_voice.py"), encoding="utf-8").read()
    assert not os.path.exists(os.path.join(ROOT, ".attic"))
    for gone in ("def _unpack_session_keys", "def _kdf_ck", "def _enh_dec_legacy"):
        assert gone not in engine, gone
    for gone in ("def derive_media_key(", "def _hkdf(", "kyber_py", "_PurePythonKem"):
        assert gone not in voice, gone
