#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Every image the repository carries has a recorded origin (ASSETS.md).

The icon's origin went unrecorded for a month and was a release blocker until
the author supplied it. This makes the record a precondition: an image added
without an entry, or changed without its recorded hash following, fails here.
"""

import hashlib
import os
import re
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMAGE = re.compile(r"\.(png|jpe?g|webp|gif|svg|ico|ttf|otf|woff2?|heic|avif)$", re.I)


def _tracked_images():
    try:
        out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True,
                             text=True, check=True).stdout.split()
    except Exception:
        pytest.skip("not a git checkout")
    return [p for p in out if IMAGE.search(p) and not p.startswith("Rust/target")]


def _record():
    return open(os.path.join(ROOT, "ASSETS.md"), encoding="utf-8").read()


def test_every_image_is_recorded():
    record = _record()
    missing = [p for p in _tracked_images()
               if p not in record and p.split("android/app/src/main/res/")[-1] not in record]
    assert missing == [], "images with no provenance entry in ASSETS.md: %s" % missing


def test_recorded_hashes_match_the_files():
    record = _record()
    stale = []
    for p in _tracked_images():
        short = p.split("android/app/src/main/res/")[-1]
        m = re.search(r"`%s`[^\n]*?`([0-9a-f]{64})`" % re.escape(short), record)
        if not m:
            continue
        digest = hashlib.sha256(open(os.path.join(ROOT, p), "rb").read()).hexdigest()
        if digest != m.group(1):
            stale.append(p)
    assert stale == [], "changed without updating ASSETS.md: %s" % stale


def test_the_icon_says_what_it_is():
    record = _record()
    i = record.index("## The mascot icon")
    section = record[i:record.index("## Launcher icons", i)]
    assert "Grok (xAI)" in section and "PLACEHOLDER" in section
    assert "asserts no copyright in the icon" in section, (
        "the record must not imply the project holds a licence it cannot grant")
