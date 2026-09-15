# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""New source files carry an SPDX header. Old ones are left alone.

WHY AT ALL
----------
The repository-root `LICENSE` covers every file in the tree, so a header
changes nothing about the terms. What it changes is what happens when a file
leaves the tree: pasted into a bug report, dropped into a gist, vendored into
someone else's project. A file with a header arrives carrying its terms; a bare
one arrives looking unlicensed, and under a DUAL licence the reader cannot even
guess, because there are two right answers and the file names neither.

WHY NOT RETROACTIVELY
---------------------
A sweep across ~200 existing files would be a large diff that changes no
licence, and it would put a mechanical commit on top of every `git blame` in
the project. The cost is real and the benefit is the same one a new-file rule
gets over time anyway. So the policy starts at a commit and looks forward.

HOW THE LINE IS DRAWN
---------------------
Not by a date in a filename or a hand-maintained list -- by git. Files ADDED
after [SPDX_POLICY_BASELINE] must have a header; everything that existed at
that commit is exempt, permanently and without an exception list. A file the
working tree has added but not yet committed counts too, so the rule applies
before the commit rather than after it.

If the baseline commit is not present -- a shallow clone, or a rewritten
history -- this skips rather than guessing. It is a policy check, not a
security invariant; failing closed here would mean failing in every CI
checkout that uses `fetch-depth: 1`.
"""

import io
import os
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: The commit the policy starts after: the last commit before the header rule
#: was introduced. Everything reachable from here is exempt.
SPDX_POLICY_BASELINE = "7a72641"

#: The identifier every new file must declare. The same string the rest of the
#: repository agrees on -- see tests/test_licence_declarations_agree.py.
SPDX = "AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial"

SOURCE_SUFFIXES = (".py", ".rs", ".kt", ".kts")

#: How far into the file the header may be. A shebang, an encoding line and a
#: couple of blank lines is the realistic worst case; a "header" on line 40 is
#: not a header.
HEADER_LINES = 6


def _git(*args):
    return subprocess.run(
        ("git",) + args, cwd=ROOT, capture_output=True, text=True, timeout=60)


def _baseline_exists():
    out = _git("cat-file", "-e", SPDX_POLICY_BASELINE + "^{commit}")
    return out.returncode == 0


def _files_added_since_baseline():
    """Source files added after the baseline, committed or not."""
    added = set()

    out = _git("log", "--diff-filter=A", "--name-only", "--pretty=format:",
               "%s..HEAD" % SPDX_POLICY_BASELINE)
    if out.returncode != 0:
        pytest.skip("git log failed: %s" % out.stderr.strip())
    added.update(p for p in out.stdout.split("\n") if p.strip())

    # Not yet committed: staged additions and untracked files. Without this
    # the rule would only bite one commit late, which in practice means the
    # author finds out after pushing.
    out = _git("status", "--porcelain", "--untracked-files=all")
    if out.returncode == 0:
        for line in out.stdout.split("\n"):
            if not line.strip():
                continue
            status, _, path = line[:2], line[2:3], line[3:]
            if status.strip() in ("A", "AM", "??"):
                added.add(path.strip())

    return sorted(
        p for p in added
        if p.endswith(SOURCE_SUFFIXES)
        and os.path.isfile(os.path.join(ROOT, p))
    )


def _header_of(path):
    with io.open(os.path.join(ROOT, path), encoding="utf-8",
                 errors="replace") as fh:
        lines = []
        for _ in range(HEADER_LINES):
            line = fh.readline()
            if not line:
                break
            lines.append(line)
    return "".join(lines)


@pytest.fixture(scope="module")
def new_files():
    if not os.path.isdir(os.path.join(ROOT, ".git")):
        pytest.skip("not a git checkout")
    if not _baseline_exists():
        pytest.skip(
            "baseline %s not in this checkout (shallow clone, or history "
            "rewritten)" % SPDX_POLICY_BASELINE)
    return _files_added_since_baseline()


class TestNewSourceFilesDeclareTheLicence:

    def test_every_new_source_file_has_the_identifier(self, new_files):
        missing = [p for p in new_files if "SPDX-License-Identifier" not in
                   _header_of(p)]
        assert missing == [], (
            "these files were added after %s and carry no SPDX header:\n  %s\n"
            "Add, as the first line (with // in .kt/.rs/.kts):\n"
            "  # SPDX-License-Identifier: %s\n"
            "  # Copyright (C) 2025-2026 muc111\n"
            "See CONTRIBUTING.md. Existing files are exempt on purpose."
            % (SPDX_POLICY_BASELINE, "\n  ".join(missing), SPDX))

    def test_the_identifier_is_the_dual_licence(self, new_files):
        """A header naming only the AGPL would be worse than none: it would
        state, in the file, that the commercial half does not apply to it."""
        wrong = []
        for path in new_files:
            header = _header_of(path)
            if "SPDX-License-Identifier" not in header:
                continue            # reported by the test above
            if SPDX not in header:
                wrong.append(path)
        assert wrong == [], (
            "these declare something other than %r: %s" % (SPDX, wrong))


class TestThePolicyDoesNotReachBackwards:
    """The promise that makes the rule acceptable: no retroactive sweep."""

    def test_the_baseline_is_an_ancestor_of_head(self):
        if not os.path.isdir(os.path.join(ROOT, ".git")):
            pytest.skip("not a git checkout")
        if not _baseline_exists():
            pytest.skip("baseline not in this checkout")
        out = _git("merge-base", "--is-ancestor", SPDX_POLICY_BASELINE, "HEAD")
        assert out.returncode == 0, (
            "the policy baseline is not an ancestor of HEAD, so 'added after "
            "the baseline' does not mean what this file says it means")

    def test_files_that_predate_the_baseline_are_not_required_to_have_one(self):
        """Stated as a test because it is the half of the policy that is a
        promise rather than a requirement, and a later well-meaning commit
        could quietly turn this into a whole-repository rule."""
        if not os.path.isdir(os.path.join(ROOT, ".git")):
            pytest.skip("not a git checkout")
        if not _baseline_exists():
            pytest.skip("baseline not in this checkout")
        out = _git("ls-tree", "-r", "--name-only", SPDX_POLICY_BASELINE)
        if out.returncode != 0:
            pytest.skip("git ls-tree failed")
        old = [p for p in out.stdout.split("\n")
               if p.endswith(SOURCE_SUFFIXES)]
        assert len(old) > 100, "expected the pre-baseline tree to be large"

        added = set(_files_added_since_baseline())
        overlap = sorted(set(old) & added)
        assert overlap == [], (
            "files present at the baseline are being treated as new: %s"
            % overlap[:10])
