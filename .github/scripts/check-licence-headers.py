#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Licence headers, checked in under a second.

    python3 .github/scripts/check-licence-headers.py

WHY A SCRIPT AS WELL AS THE TESTS. tests/test_spdx_headers_on_new_files.py
already holds new source files to the header rule, but it runs inside the
full suite: about eleven minutes into a CI job, after the Rust core has been
built. In rc.204 five new files went in with `AGPL-3.0-or-later` and the
first thing to say so was that job, thirteen minutes after the push. This
says it in the time it takes to list the tree, as a CI job of its own
(.github/workflows/python.yml, `licence-headers`) and by hand before a
commit. Standard library only: nothing to install, nothing to build.

THREE RULES

1. A file added after the policy began has a header. The policy looks
   forward from one commit (SPDX_POLICY_BASELINE) and leaves older files
   alone; CONTRIBUTING.md says why. Added-and-not-yet-committed counts.
2. A header, wherever it is, names the licence that file type is under:
   the dual software licence for code and configuration, CC-BY-SA-4.0 for
   documents (LICENSING.md). A header that names only the AGPL is worse
   than none: it says, in the file, that the commercial half does not
   apply to it. This rule covers every tracked file, old or new.
3. No build output is tracked. A `target/` or `.gradle/` directory in the
   index is thousands of generated lines with no licence, no author and a
   diff on every build.

Exit status: 0 nothing to report; 1 findings (printed, one per line, with
what to do); 2 the check could not run (not a git checkout, or the baseline
commit is not in it: fetch with full history).
"""
import os
import subprocess
import sys

#: The commit the header policy starts after. The same one
#: tests/test_spdx_headers_on_new_files.py uses.
SPDX_POLICY_BASELINE = "7a72641"

SOFTWARE = "AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial"
DOCUMENTS = "CC-BY-SA-4.0"

#: Built from two halves so that this file contains the tag once, in its own
#: header, and a search for it does not find the checker's own source.
TAG = "SPDX-License-" + "Identifier"

#: How far into a file a header may be: a shebang, an encoding line and a
#: blank or two. A "header" on line 40 is not one.
HEADER_LINES = 6

#: New files of these kinds must carry a header.
CODE_SUFFIXES = (".py", ".rs", ".kt", ".kts", ".sh", ".lua")
#: Configuration that takes comments: the same rule.
CONFIG_SUFFIXES = (".yml", ".yaml", ".toml")
DOCUMENT_SUFFIXES = (".md",)

#: Third-party code under its authors' licence (REUSE.toml): it keeps their
#: headers and does not gain ours.
THIRD_PARTY_PREFIXES = ("Rust/vendor/openmls_traits/",
                        "Rust/vendor/openmls_rust_crypto/",
                        "LICENSES/")

#: Generated or machine-owned files that cannot carry a comment header and
#: are covered by REUSE.toml instead.
NO_HEADER_NAMES = ("Cargo.lock", "gradle-wrapper.properties")

#: Files whose header is deliberately something else, with the reason.
#: Keyed on path; the value is the exact identifier expected there.
OTHER_IDENTIFIERS = {
    # Derived from openmls_memory_storage 0.6.0 (MIT) with this project's
    # changes; the file's own header and NOTICE say so.
    "Rust/mls/src/storage.rs":
        "MIT AND (AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial)",
}

#: Not documents by suffix, documents by what they are: declared CC-BY-SA on
#: purpose.
DOCUMENTS_BY_CONTENT = ("REUSE.toml",)

#: Other files under the software licence when they carry a header at all.
OTHER_SOFTWARE_SUFFIXES = (".xml", ".json", ".cfg", ".ini", ".pro",
                           ".properties", ".gradle", ".java", ".c", ".h")

#: Directory names that are build output wherever they appear.
BUILD_OUTPUT_PARTS = ("target", ".gradle", "__pycache__", "node_modules",
                      ".pytest_cache", ".hypothesis")
BUILD_OUTPUT_SUFFIXES = (".pyc", ".pyo", ".class", ".o", ".rlib", ".rmeta")


def identifier_in(header):
    """The licence expression a header declares, or None."""
    for line in header.splitlines():
        if TAG + ":" not in line:
            continue
        value = line.split(TAG + ":", 1)[1].strip()
        # A comment's closing marker is not part of the expression.
        for closing in ("-->", "*/"):
            if value.endswith(closing):
                value = value[:-len(closing)].strip()
        return value
    return None


def is_third_party(path):
    return path.startswith(THIRD_PARTY_PREFIXES)


def is_build_output(path):
    parts = path.split("/")
    if any(part in BUILD_OUTPUT_PARTS for part in parts[:-1]):
        return True
    return path.endswith(BUILD_OUTPUT_SUFFIXES)


def needs_header(path):
    """Whether a NEW file at this path must carry a header."""
    if is_third_party(path) or is_build_output(path):
        return False
    if os.path.basename(path) in NO_HEADER_NAMES:
        return False
    return path.endswith(CODE_SUFFIXES + CONFIG_SUFFIXES)


def expected_identifier(path):
    """What a header in this file should say, or None if any is fine."""
    if path in OTHER_IDENTIFIERS:
        return OTHER_IDENTIFIERS[path]
    if is_third_party(path):
        return None
    if path.endswith(DOCUMENT_SUFFIXES) or path in DOCUMENTS_BY_CONTENT:
        return DOCUMENTS
    if path.endswith(CODE_SUFFIXES + CONFIG_SUFFIXES + OTHER_SOFTWARE_SUFFIXES):
        return SOFTWARE
    return None


def wrong_identifier(path, header):
    """The finding for a header that names the wrong licence, or None."""
    declared = identifier_in(header)
    expected = expected_identifier(path)
    if declared is None or expected is None or declared == expected:
        return None
    return "%s: header says %r; expected %r" % (path, declared, expected)


def git(root, *args):
    return subprocess.run(("git",) + args, cwd=root, capture_output=True,
                          text=True, timeout=120)


def tracked_files(root):
    out = git(root, "ls-files", "-z")
    if out.returncode != 0:
        return None
    return [path for path in out.stdout.split("\0") if path]


def new_files(root, baseline):
    """Paths added after the baseline, committed or not; None if the
    baseline is not in this checkout."""
    if git(root, "cat-file", "-e", baseline + "^{commit}").returncode != 0:
        return None
    added = set()
    out = git(root, "log", "--diff-filter=A", "--name-only",
              "--pretty=format:", "%s..HEAD" % baseline)
    if out.returncode != 0:
        return None
    added.update(line for line in out.stdout.split("\n") if line.strip())
    out = git(root, "status", "--porcelain", "--untracked-files=all")
    if out.returncode == 0:
        for line in out.stdout.split("\n"):
            if line[:2].strip() in ("A", "AM", "??"):
                added.add(line[3:].strip().strip('"'))
    return sorted(path for path in added
                  if os.path.isfile(os.path.join(root, path)))


def header_of(root, path):
    try:
        with open(os.path.join(root, path), encoding="utf-8",
                  errors="replace") as handle:
            return "".join(handle.readline() for _ in range(HEADER_LINES))
    except OSError:
        return ""


def check(root, baseline=SPDX_POLICY_BASELINE):
    """(findings, error). `error` is set when the check could not run."""
    tracked = tracked_files(root)
    if tracked is None:
        return [], "not a git checkout: %s" % root
    added = new_files(root, baseline)
    if added is None:
        return [], (
            "baseline %s is not in this checkout (a shallow clone?). Fetch "
            "the full history: `git fetch --unshallow`, or `fetch-depth: 0` "
            "on actions/checkout." % baseline)
    findings = []

    # 1. A new file has a header.
    for path in added:
        if needs_header(path) and TAG not in header_of(root, path):
            comment = "//" if path.endswith((".rs", ".kt", ".kts")) else (
                "--" if path.endswith(".lua") else "#")
            findings.append(
                "%s: added after %s with no licence header. First lines "
                "(after a shebang, if any):\n      %s %s: %s\n      %s "
                "Copyright (C) 2025-2026 muc111"
                % (path, baseline, comment, TAG, SOFTWARE, comment))

    # 2. Any header names the right licence for its file.
    for path in sorted(set(tracked) | set(added)):
        if is_build_output(path):
            continue
        finding = wrong_identifier(path, header_of(root, path))
        if finding:
            findings.append(finding)

    # 3. No build output is tracked.
    built = [path for path in tracked if is_build_output(path)]
    if built:
        directories = sorted({"/".join(path.split("/")[:1 + next(
            (index for index, part in enumerate(path.split("/"))
             if part in BUILD_OUTPUT_PARTS), len(path.split("/")) - 1)])
            for path in built})
        findings.append(
            "%d tracked file(s) are build output, under: %s. Remove them "
            "from the index (`git rm -r --cached <dir>`) and add the "
            "directory to .gitignore."
            % (len(built), ", ".join(directories[:8])))
    return findings, None


def main(argv):
    root = os.path.abspath(argv[1]) if len(argv) > 1 else os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    findings, error = check(root)
    if error:
        print("licence headers: could not check: " + error, file=sys.stderr)
        return 2
    if findings:
        print("licence headers: %d finding(s)" % len(findings))
        for finding in findings:
            print("  - " + finding)
        return 1
    print("licence headers: nothing to report")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
