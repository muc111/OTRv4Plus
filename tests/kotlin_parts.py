# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""A Kotlin class's source, with the files split out of it.

Kotlin has no partial classes. When a large class is split, its parts live in
sibling files (an interface plus an implementation it delegates to), and a
test that reads the class to check a rule must read the parts too, or it
checks less than it did. Audit tidy 4 (2026-11-14): ChaquopyOtrCore.
"""
import os

#: File name -> the sibling files split out of it, in the same directory.
PARTS = {
    "ChaquopyOtrCore.kt": ("PyResult.kt", "ChaquopyGroups.kt",
                           "ChaquopyAccountAdmin.kt", "ChaquopyMedia.kt"),
}


def parts_of(path):
    """[path] and the paths of its parts."""
    base, folder = os.path.basename(path), os.path.dirname(path)
    return [path] + [os.path.join(folder, p) for p in PARTS.get(base, ())]


def with_parts(path):
    """The text of [path] followed by its parts' text."""
    out = []
    for p in parts_of(path):
        with open(p, encoding="utf-8") as fh:
            out.append(fh.read())
    return "\n".join(out)
