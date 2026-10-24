# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Install instructions name their branch, and are right on either branch.

Owner, 2026-10-24 (the second time): the README's one-line install cloned the
default branch, `main`, which had fallen 46 commits behind `dev`, the branch
the Android test APK is built from -- so a desktop installed from it ran an
older protocol the app refuses. 805bf42 once pointed the docs at `dev`;
b914d5f pointed them back at a plain clone while `main` was kept current, and
it went stale again when it was not.

The fix that does not depend on which branch is current: every clone names
its branch, `dev` and `main` are both offered with what each is, and the same
text is correct on both branches, so merging one into the other cannot make
it wrong. `install.sh` builds the branch it finds and never switches it.
"""
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCS = ("README.md", os.path.join("desktop", "README.md"), os.path.join("docs", "TECHNICAL.md"))
CLONE = re.compile(r"git clone(?P<args>[^\n]*?)https://github\.com/muc111/OTRv4Plus")


def _read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


def test_every_clone_names_its_branch():
    for rel in DOCS:
        clones = list(CLONE.finditer(_read(rel)))
        assert clones, rel
        for m in clones:
            assert re.search(r"-b (dev|main)\b", m.group("args")), (rel, m.group(0))


def test_both_branches_are_offered_with_what_each_is():
    readme = _read("README.md")
    for branch in ("dev", "main"):
        line = ("sudo apt install -y git && git clone -b %s https://github.com/muc111/"
                "OTRv4Plus.git ~/OTRv4Plus && bash ~/OTRv4Plus/desktop/install.sh" % branch)
        assert line in readme, branch
        assert line in _read(os.path.join("desktop", "README.md")), branch
    table = readme[readme.index("**Pick a branch"):readme.index("### Desktop app")]
    assert "| `dev` |" in table and "| `main` |" in table
    assert "APK" in table.split("| `dev` |")[1].split("\n")[0], "dev is the APK's branch"
    assert "git fetch origin dev && git checkout dev" in table


def test_no_doc_says_main_is_what_the_apk_is_built_from():
    for rel in DOCS:
        assert "`main` matches the APK" not in _read(rel), rel


def test_the_installer_builds_the_branch_it_finds():
    script = _read(os.path.join("desktop", "install.sh"))
    assert "git pull --ff-only" in script
    assert "git checkout" not in script and "git switch" not in script, (
        "install.sh must not move a clone to another branch")


def test_the_readme_says_which_script_is_for_the_desktop():
    """Two scripts: desktop/install.sh does everything for the app (it pulls
    and runs Rust/build.sh itself); Rust/build.sh alone is the terminal
    clients' core build. The README must say so, and it must stay true."""
    readme = _read("README.md")
    desktop = readme[readme.index("### Desktop app"):readme.index("### Termux")]
    assert "**Desktop needs only `desktop/install.sh`.**" in desktop
    assert "runs `Rust/build.sh` for you" in desktop
    assert "no separate `git pull`" in desktop
    script = _read(os.path.join("desktop", "install.sh"))
    assert "(cd Rust && bash build.sh)" in script
    assert "git pull --ff-only" in script
