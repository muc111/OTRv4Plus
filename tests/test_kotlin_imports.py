# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Checks a Kotlin compiler would make, cheap enough to run before CI does.

Only CI can compile the apps. Moving code between files is where an import
gets lost: `@Composable` used in MainActivity.kt with no import failed every
Android job on rc.156. These catch that class of mistake in seconds.
"""
import glob
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOURCES = sorted(
    glob.glob(os.path.join(ROOT, "android", "app", "src", "*", "java", "**", "*.kt"), recursive=True)
    + glob.glob(os.path.join(ROOT, "desktop", "src", "*", "kotlin", "**", "*.kt"), recursive=True))


def _code(src):
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return re.sub(r"//[^\n]*", "", src)


def test_every_file_using_composable_imports_it():
    missing = []
    for path in SOURCES:
        src = open(path, encoding="utf-8").read()
        if re.search(r"^\s*@Composable\b", _code(src), re.M) and not re.search(
                r"^import androidx\.compose\.runtime\.(Composable|\*)$", src, re.M):
            missing.append(os.path.relpath(path, ROOT))
    assert not missing, "uses @Composable without importing it: %s" % missing


def test_fully_qualified_project_names_exist():
    """`org.otrv4plus.android.ui.ThemeTokens` named a class that lives in
    `...android.theme`: a qualified name must point at a real declaration."""
    declared = set()
    for path in SOURCES:
        src = open(path, encoding="utf-8").read()
        pkg = re.search(r"^package\s+([\w.]+)", src, re.M)
        names = re.findall(r"^(?:\w+\s+)*(?:class|object|interface|val)\s+(\w+)", src, re.M)
        # An extension's receiver is not a declaration: `fun A.B.c(` declares c.
        names += re.findall(r"^(?:\w+\s+)*fun\s+(?:<[^>]*>\s*)?(?:[\w.]+\.)?(\w+)\s*\(", src, re.M)
        for name in names:
            if pkg:
                declared.add(pkg.group(1) + "." + name)
    wrong = set()
    for path in SOURCES:
        code = _code(open(path, encoding="utf-8").read())
        for ref in re.findall(r"\b(org\.otrv4plus\.(?:android|desktop)(?:\.[a-z]\w*)+\.[A-Z]\w*)", code):
            if ref not in declared:
                wrong.add("%s: %s" % (os.path.relpath(path, ROOT), ref))
    assert not wrong, sorted(wrong)
