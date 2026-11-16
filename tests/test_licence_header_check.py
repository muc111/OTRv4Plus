# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The licence-header check that answers in a second.

.github/scripts/check-licence-headers.py runs as a CI job of its own, before
anything is built. rc.204 is why: five new files carried `AGPL-3.0-or-later`,
and the first thing to say so was the full suite, thirteen minutes after the
push. These hold the script to its three rules on a throwaway repository, to
the same policy as tests/test_spdx_headers_on_new_files.py, and to the tree
as it stands.
"""
import importlib.util
import os
import subprocess
import sys
import tempfile
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, ".github", "scripts", "check-licence-headers.py")

_spec = importlib.util.spec_from_file_location("check_licence_headers", SCRIPT)
checker = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(checker)

# REUSE-IgnoreStart
# Everything from here to the end of the file is test data: headers written
# into throwaway files, several of them wrong on purpose. The REUSE tool
# reads any line shaped like a declaration as one, so it is told not to.
DUAL = "AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial"
HEADER = "# SPDX-License-Identifier: %s\n# Copyright (C) 2025-2026 muc111\n" % DUAL
LATER = "# SPDX-License-Identifier: AGPL-3.0-or-later\n"
AGPL_ONLY = "# SPDX-License-Identifier: AGPL-3.0-only\n"
DOCUMENT = "<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->\n"


def _git(root, *args):
    done = subprocess.run(
        ("git", "-c", "user.name=test", "-c", "user.email=test@example.invalid",
         "-c", "commit.gpgsign=false") + args,
        cwd=root, capture_output=True, text=True, timeout=60)
    assert done.returncode == 0, done.stderr
    return done.stdout.strip()


def _write(root, path, text):
    full = os.path.join(root, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w", encoding="utf-8") as handle:
        handle.write(text)


@pytest.fixture
def repo():
    """A repository with one old file and a baseline commit after it."""
    with tempfile.TemporaryDirectory() as root:
        _git(root, "init", "-q")
        _write(root, "old.py", "print('here before the policy, no header')\n")
        _git(root, "add", "-A")
        _git(root, "commit", "-q", "-m", "before the policy")
        yield root, _git(root, "rev-parse", "HEAD")


def _findings(repo):
    root, baseline = repo
    findings, error = checker.check(root, baseline)
    assert error is None, error
    return findings


def test_a_file_from_before_the_policy_is_left_alone(repo):
    assert _findings(repo) == []


def test_a_new_file_without_a_header_is_found_committed_or_not(repo):
    root, _ = repo
    _write(root, "pkg/new.py", "x = 1\n")
    (finding,) = _findings(repo)                 # untracked: found already
    assert finding.startswith("pkg/new.py: added after")
    assert DUAL in finding, "the finding says what to write"
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "add")
    assert len(_findings(repo)) == 1             # and once committed
    _write(root, "pkg/new.py", HEADER + "x = 1\n")
    assert _findings(repo) == []


@pytest.mark.parametrize("path,comment", [
    ("a/tool.sh", "#"), ("a/mod.lua", "--"), ("a/lib.rs", "//"),
    ("a/Screen.kt", "//"), ("a/build.gradle.kts", "//"),
    (".github/workflows/x.yml", "#"), ("a/Cargo.toml", "#"),
])
def test_every_kind_of_new_source_and_config_file_needs_one(repo, path, comment):
    root, _ = repo
    _write(root, path, "content\n")
    (finding,) = _findings(repo)
    assert finding.startswith(path + ":")
    assert "\n      %s SPDX-License-Identifier: %s" % (comment, DUAL) in finding
    # A shebang first is fine: the header is looked for in the first lines.
    _write(root, path, "#!/bin/sh\n%s SPDX-License-Identifier: %s\n"
           % (comment, DUAL))
    assert _findings(repo) == []


@pytest.mark.parametrize("path", [
    "notes.txt", "data/vectors.json", "Cargo.lock", "a/Cargo.lock",
    "Rust/vendor/openmls_traits/src/lib.rs", "LICENSES/MIT.txt",
    "docs/GUIDE.md", "image.png",
])
def test_what_cannot_or_need_not_carry_one_is_not_asked_to(repo, path):
    root, _ = repo
    _write(root, path, "content\n")
    assert _findings(repo) == []


@pytest.mark.parametrize("header,said", [
    (LATER, "AGPL-3.0-or-later"),
    (AGPL_ONLY, "AGPL-3.0-only"),
    ("# SPDX-License-Identifier: MIT\n", "MIT"),
    (DOCUMENT, "CC-BY-SA-4.0"),
])
def test_a_header_naming_another_licence_is_found(repo, header, said):
    """rc.204's slip, and its relatives. `AGPL-3.0-only` alone is the worst
    of them: it states, in the file, that the commercial licence does not
    cover it."""
    root, _ = repo
    _write(root, "pkg/new.py", header + "x = 1\n")
    (finding,) = _findings(repo)
    assert finding == ("pkg/new.py: header says %r; expected %r" % (said, DUAL))


def test_the_wrong_licence_is_found_in_old_files_too(repo):
    """Rule 1 looks forward from the baseline. Rule 2 does not: a wrong
    header is wrong whenever it was written."""
    root, baseline = repo
    _write(root, "old.py", LATER + "print('old')\n")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "an old file gains a wrong header")
    findings, _ = checker.check(root, baseline)
    assert findings == ["old.py: header says 'AGPL-3.0-or-later'; expected %r"
                        % DUAL]


def test_documents_are_under_the_documentation_licence(repo):
    root, _ = repo
    _write(root, "docs/GUIDE.md", DOCUMENT + "# Guide\n")
    assert _findings(repo) == []
    _write(root, "docs/GUIDE.md", "<!-- SPDX-License-Identifier: %s -->\n" % DUAL)
    (finding,) = _findings(repo)
    assert "expected 'CC-BY-SA-4.0'" in finding


def test_third_party_code_keeps_its_authors_header(repo):
    root, _ = repo
    _write(root, "Rust/vendor/openmls_traits/src/lib.rs",
           "// SPDX-License-Identifier: MIT\n")
    assert _findings(repo) == []


def test_tracked_build_output_is_found(repo):
    root, _ = repo
    _write(root, "Rust/codec/target/release/.fingerprint/x/lib.json", "{}\n")
    _write(root, "android/.gradle/8.7/fileHashes.bin", "x\n")
    _write(root, "pkg/__pycache__/mod.cpython-312.pyc", "x\n")
    assert _findings(repo) == [], "untracked build output is not the index"
    _git(root, "add", "-A", "-f")
    _git(root, "commit", "-q", "-m", "oops")
    (finding,) = _findings(repo)
    assert finding.startswith("3 tracked file(s) are build output")
    for directory in ("Rust/codec/target", "android/.gradle", "pkg/__pycache__"):
        assert directory in finding
    assert "git rm -r --cached" in finding


def test_a_source_directory_called_target_is_not_what_this_means(repo):
    """Only directories count, never a file that happens to have the name."""
    assert checker.is_build_output("Rust/target/release/x.rlib")
    assert checker.is_build_output("a/b/__pycache__/m.pyc")
    assert not checker.is_build_output("docs/target")
    assert not checker.is_build_output("src/targeting/aim.py")
    assert not checker.is_build_output("tests/test_gradle_files.py")


def test_how_the_identifier_is_read():
    read = checker.identifier_in
    assert read(HEADER) == DUAL
    assert read(DOCUMENT) == "CC-BY-SA-4.0"
    assert read("/* SPDX-License-Identifier: MIT */\n") == "MIT"
    assert read("// SPDX-License-Identifier: %s\n" % DUAL) == DUAL
    assert read("no header here\n") is None
    # The key of a REUSE.toml annotation is not a header.
    assert read('SPDX-License-Identifier = "MIT"\n') is None


def test_exit_status(repo):
    root, baseline = repo

    def run(directory):
        return subprocess.run([sys.executable, SCRIPT, directory],
                              capture_output=True, text=True, timeout=60)

    # The script's own baseline is not in a throwaway repository: it says
    # it could not check, with the remedy, and that is its own status.
    could_not = run(root)
    assert could_not.returncode == 2
    assert "could not check" in could_not.stderr
    assert "fetch-depth: 0" in could_not.stderr
    with tempfile.TemporaryDirectory() as plain:
        assert run(plain).returncode == 2
    # On this repository: clean, and saying so.
    clean = run(ROOT)
    if clean.returncode == 2 and os.environ.get("CI", "").lower() not in (
            "1", "true", "yes"):
        pytest.skip("this checkout has no baseline commit (shallow clone)")
    assert clean.returncode == 0, clean.stdout + clean.stderr
    assert clean.stdout.strip() == "licence headers: nothing to report"


def test_this_tree_passes_and_quickly():
    began = time.monotonic()
    findings, error = checker.check(ROOT)
    took = time.monotonic() - began
    if error and os.environ.get("CI", "").lower() not in ("1", "true", "yes"):
        pytest.skip(error)
    assert error is None, error
    assert findings == [], "\n".join(findings)
    assert took < 15, "the point of this check is that it is quick (%.1fs)" % took


def test_it_agrees_with_the_policy_the_suite_enforces():
    sys.path.insert(0, os.path.join(ROOT, "tests"))
    import test_spdx_headers_on_new_files as policy
    assert checker.SPDX_POLICY_BASELINE == policy.SPDX_POLICY_BASELINE
    assert checker.SOFTWARE == policy.SPDX
    assert checker.HEADER_LINES == policy.HEADER_LINES
    assert set(policy.SOURCE_SUFFIXES) <= set(checker.CODE_SUFFIXES)
    assert set(policy.THIRD_PARTY_PREFIXES) <= set(checker.THIRD_PARTY_PREFIXES)


def test_every_exception_names_a_file_that_is_there():
    """An entry for a file that has gone would excuse the next file to take
    its path."""
    for path, identifier in checker.OTHER_IDENTIFIERS.items():
        full = os.path.join(ROOT, path)
        assert os.path.isfile(full), path
        assert checker.identifier_in(checker.header_of(ROOT, path)) == identifier
    for path in checker.DOCUMENTS_BY_CONTENT:
        assert os.path.isfile(os.path.join(ROOT, path)), path


def test_ci_runs_it_first_and_with_the_whole_history():
    """Its own job: no Rust build in front of it, and a full clone, without
    which the baseline is missing and the check cannot run."""
    yaml = pytest.importorskip("yaml")
    with open(os.path.join(ROOT, ".github", "workflows", "python.yml"),
              encoding="utf-8") as handle:
        workflow = yaml.safe_load(handle)
    job = workflow["jobs"]["licence-headers"]
    assert "needs" not in job
    steps = job["steps"]
    checkout = next(step for step in steps
                    if str(step.get("uses", "")).startswith("actions/checkout"))
    assert checkout["with"]["fetch-depth"] == 0
    assert any("check-licence-headers.py" in str(step.get("run", ""))
               for step in steps)
    assert not any("maturin" in str(step.get("run", "")) or
                   "rust-toolchain" in str(step.get("uses", ""))
                   for step in steps)
    assert job.get("timeout-minutes", 99) <= 5

# REUSE-IgnoreEnd
