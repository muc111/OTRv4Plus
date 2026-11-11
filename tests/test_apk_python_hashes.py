# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Every third-party file in the APK's Python is checked by SHA-256.

Owner, 2026-10-30, on Python's exposure to poisoned packages. The pip block
pinned versions only, so a compromised index could serve a different file
under the same version. Now tools/fetch-apk-python.sh downloads every file
with --require-hashes against android/app/python-lock.txt, and Chaquopy's pip
gets --no-index, so it can install nothing else. The Qubes build already
checks its wheels this way (qubes/packaging/lock-cp313.sha256).
"""
import os
import re
import subprocess
import sys

import pytest

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.join(ROOT, "tests"))
LOCK = os.path.join(ROOT, "android", "app", "python-lock.txt")
GRADLE = os.path.join(ROOT, "android", "app", "build.gradle.kts")
FETCH = os.path.join(ROOT, "tools", "fetch-apk-python.sh")
WORKFLOW = os.path.join(ROOT, ".github", "workflows", "android.yml")

from test_apk_python_deps import _pip_block  # noqa: E402


def _norm(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def _lock():
    """{name: (version, [hashes])} from the lock."""
    text = open(LOCK).read().replace("\\\n", " ")
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"([A-Za-z0-9_.-]+)==(\S+)\s+(.*)$", line)
        assert m, "every lock line names an exact version: %r" % line
        hashes = re.findall(r"--hash=sha256:([0-9a-f]+)", m.group(3))
        out[_norm(m.group(1))] = (m.group(2), hashes)
    return out


class TestTheLock:

    def test_every_shipped_package_is_locked_at_the_version_installed(self):
        installed = dict(re.findall(r'install\(\s*"([A-Za-z0-9_.-]+)==([^"]+)"', _pip_block()))
        assert installed, "the pip block names its third-party packages"
        lock = _lock()
        for name, version in installed.items():
            assert _norm(name) in lock, "%s ships without a hash" % name
            assert lock[_norm(name)][0] == version, (name, version, lock[_norm(name)][0])

    def test_every_entry_has_a_full_sha256(self):
        for name, (_v, hashes) in _lock().items():
            assert hashes, "%s has no hash" % name
            assert all(len(h) == 64 for h in hashes), name

    def test_slixmpps_build_tools_are_locked_too(self):
        """slixmpp is built from its sdist; with --no-index its build tools
        must come from the same checked directory."""
        lock = _lock()
        for tool in ("setuptools", "setuptools-rust", "setuptools-scm"):
            assert tool in lock, tool


class TestNothingElseCanBeInstalled:

    def test_chaquopys_pip_has_no_index(self):
        assert re.search(r'options\(\s*"--no-index"\s*\)', _pip_block())

    def test_the_fetch_requires_hashes(self):
        src = open(FETCH).read()
        assert "--require-hashes" in src and "-r android/app/python-lock.txt" in src
        assert "-d android/app/wheels" in src

    def test_every_ci_job_that_builds_fetches_first(self):
        """Each job that downloads the Rust core and runs Gradle fetches the
        locked files between the two."""
        text = open(WORKFLOW).read()
        jobs = text.split("pattern: otrv4_core-*")[1:]
        assert len(jobs) >= 4
        for job in jobs:
            before_gradle = job[:job.index("./gradlew")]
            assert "sh tools/fetch-apk-python.sh" in before_gradle

    def test_the_rust_core_check_looks_for_the_core_itself(self):
        """With the locked wheels in the same directory, `*.whl` would pass
        without the Rust core."""
        text = open(WORKFLOW).read()
        assert "ls android/app/wheels/*.whl" not in text
        assert "ls android/app/wheels/otrv4_core-*.whl" in text


def test_a_file_that_does_not_match_the_lock_is_refused():
    """pip under --require-hashes refuses a file whose hash is not the lock's.

    Offline: a local wheel stands in for the download (`--no-index
    --find-links`), and pip applies the same hash check to it. This used to
    fetch pyasn1 from PyPI and skipped unless OTR_NETWORK_TESTS=1, so it never
    ran. The control -- the same file under its real hash -- proves the
    refusal is the hash and not a broken setup.
    """
    import hashlib
    import shutil
    import tempfile
    import zipfile
    tmp = tempfile.mkdtemp(prefix="otr-lock-check-")
    try:
        index, out = os.path.join(tmp, "index"), os.path.join(tmp, "out")
        os.makedirs(index)
        wheel = os.path.join(index, "pyasn1-0.6.4-py3-none-any.whl")
        with zipfile.ZipFile(wheel, "w") as z:
            z.writestr("pyasn1/__init__.py", "")
            z.writestr("pyasn1-0.6.4.dist-info/METADATA",
                       "Metadata-Version: 2.1\nName: pyasn1\nVersion: 0.6.4\n")
            z.writestr("pyasn1-0.6.4.dist-info/WHEEL",
                       "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\n"
                       "Tag: py3-none-any\n")
            z.writestr("pyasn1-0.6.4.dist-info/RECORD", "")

        def pip_download(digest):
            lock = os.path.join(tmp, "lock.txt")
            with open(lock, "w") as fh:
                fh.write("pyasn1==0.6.4 --hash=sha256:%s\n" % digest)
            return subprocess.run(
                [sys.executable, "-m", "pip", "download", "--require-hashes",
                 "--no-deps", "--no-index", "--find-links", index,
                 "-r", lock, "-d", out],
                capture_output=True, text=True)

        bad = pip_download("0" * 64)
        assert bad.returncode != 0 and "HASH" in (bad.stdout + bad.stderr).upper()

        real = hashlib.sha256(open(wheel, "rb").read()).hexdigest()
        good = pip_download(real)
        assert good.returncode == 0, good.stdout + good.stderr
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


#: The build tested on phones and a laptop, the one main holds (CHANGELOG).
TESTED_RC = 194


def test_builds_after_the_tested_one_say_untested():
    """Owner, 2026-10-30: main holds the build tested on devices (rc.189,
    then rc.194 on 2026-11-10); an APK made after it is marked untested
    until it is tested too. So: exactly the tested build without the mark,
    or a later one with it -- never a later one without it."""
    gradle = open(GRADLE).read()
    name = re.search(r'versionName = "([^"]+)"', gradle).group(1)
    rc = int(re.search(r"experimental\.rc\.(\d+)", name).group(1))
    if "-untested" in name:
        assert rc > TESTED_RC
    else:
        assert rc == TESTED_RC, "a build after the tested one must say -untested"
    changelog = open(os.path.join(os.path.dirname(GRADLE), "..", "..", "CHANGELOG.md")).read()
    assert "rc.%d" % TESTED_RC in changelog[:3000]
