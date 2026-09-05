"""Rust dependencies on the Python/Rust security boundary carry advisories.

PyO3 is not an ordinary dependency: it *is* the boundary between the Python
client and the Rust cryptographic core, so an advisory against it is an
advisory against the boundary.

GHSA-36hh-v3qg-5jq4 (CVSS 8.7, CWE-125) is the one this file was written for.
`BoundListIterator` and `BoundTupleIterator` computed `index + n` in
`Iterator::nth` / `DoubleEndedIterator::nth_back` **before** bounds-checking it
against the sequence length, then read the element with
`get_item_unchecked`. On `nth` the addition can wrap and re-yield elements from
the front; on `nth_back` the subtraction can underflow and read arbitrary
memory past the storage. Fixed in PyO3 0.29.0 (PyO3/pyo3#6086).

Two independent things are asserted here, because either one alone would be a
weaker guarantee than it looks:

  1. The **resolved** version is >= the fixed release. Cargo.toml states an
     intent; Cargo.lock states what is compiled. Only the lock is evidence.

  2. The vulnerable code is **not reachable** from this crate. That was true
     at 0.24.2 as well -- OTRv4+ never puts a Python list or tuple across the
     boundary -- and it is the reason this advisory was INFO for us rather
     than high. It is asserted anyway so that the day someone does start
     iterating a Python sequence, this test tells them the reachability
     analysis in SECURITY.md has expired.

A version assertion alone would let (2) rot silently; a reachability assertion
alone would leave us on a known-vulnerable release. Both, or neither is worth
much.

Enforces INV-23.
"""

import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUST = os.path.join(ROOT, "Rust")
CARGO_LOCK = os.path.join(RUST, "Cargo.lock")
CARGO_TOML = os.path.join(RUST, "Cargo.toml")
SRC = os.path.join(RUST, "src")

#: The first PyO3 release in which GHSA-36hh-v3qg-5jq4 is fixed.
PYO3_FIXED_IN = (0, 29, 0)

#: Every crate the pyo3 workspace publishes in lockstep. They must all move
#: together: a 0.29 `pyo3` against a 0.24 `pyo3-ffi` does not link, and a lock
#: file that somehow held both would be a silent half-upgrade.
PYO3_CRATES = (
    "pyo3",
    "pyo3-build-config",
    "pyo3-ffi",
    "pyo3-macros",
    "pyo3-macros-backend",
)


def _parse_version(text):
    parts = text.split("-", 1)[0].split(".")
    return tuple(int(p) for p in parts[:3])


def _is_patched(version_text):
    """True if `version_text` carries the GHSA-36hh-v3qg-5jq4 fix.

    Split out from the assertion so the comparison itself can be tested on
    synthetic versions. Asserting only against the version that happens to be
    locked today would let `>=` decay to `>` unnoticed -- 0.29.2 satisfies
    both, and the release that matters, exactly 0.29.0, is the one no real
    lock file is currently pinning.
    """
    return _parse_version(version_text) >= PYO3_FIXED_IN


def _locked_versions():
    """Every version of every package in Cargo.lock, as {name: [version, ...]}."""
    with open(CARGO_LOCK, "r", encoding="utf-8") as fh:
        body = fh.read()
    found = {}
    for block in body.split("[[package]]"):
        name = re.search(r'^name\s*=\s*"([^"]+)"', block, re.M)
        version = re.search(r'^version\s*=\s*"([^"]+)"', block, re.M)
        if name and version:
            found.setdefault(name.group(1), []).append(version.group(1))
    return found


@pytest.fixture(scope="module")
def locked():
    if not os.path.exists(CARGO_LOCK):
        pytest.fail("Rust/Cargo.lock is missing; nothing pins the boundary")
    return _locked_versions()


@pytest.fixture(scope="module")
def rust_sources():
    files = {}
    for entry in sorted(os.listdir(SRC)):
        if entry.endswith(".rs"):
            path = os.path.join(SRC, entry)
            with open(path, "r", encoding="utf-8") as fh:
                files[entry] = fh.read()
    assert files, "no Rust sources found; the reachability check would pass vacuously"
    return files


class TestTheAdvisoryStaysFixed:

    def test_pyo3_is_locked_at_or_above_the_fixed_release(self, locked):
        versions = locked.get("pyo3")
        assert versions, "pyo3 is not in Cargo.lock at all"
        for v in versions:
            assert _is_patched(v), (
                "Cargo.lock resolves pyo3 %s, which is vulnerable to "
                "GHSA-36hh-v3qg-5jq4 (fixed in %s). Run "
                "`cargo update -p pyo3` and rebuild the wheel."
                % (v, ".".join(str(n) for n in PYO3_FIXED_IN))
            )

    def test_only_one_pyo3_is_compiled_in(self, locked):
        """Two pyo3 versions in one artifact would mean one of them is
        unaudited, and whichever the extension module actually binds is not
        something the lock file tells you."""
        assert len(locked.get("pyo3", [])) == 1, (
            "Cargo.lock holds more than one pyo3: %r" % (locked.get("pyo3"),)
        )

    @pytest.mark.parametrize("crate", PYO3_CRATES)
    def test_the_pyo3_crates_move_together(self, crate, locked):
        versions = locked.get(crate)
        assert versions, "%s is missing from Cargo.lock" % crate
        assert versions == locked["pyo3"], (
            "%s is at %r while pyo3 is at %r -- a half-upgrade"
            % (crate, versions, locked["pyo3"])
        )

    def test_the_manifest_cannot_resolve_back_to_a_vulnerable_release(self):
        """Cargo.lock can be regenerated. If Cargo.toml still said "0.24",
        `cargo update` would happily walk back to the vulnerable release and
        this file's other assertions would be the only thing in the way."""
        with open(CARGO_TOML, "r", encoding="utf-8") as fh:
            manifest = fh.read()
        m = re.search(r'^pyo3\s*=\s*\{[^}]*version\s*=\s*"([^"]+)"', manifest, re.M)
        assert m, "no pyo3 dependency line found in Rust/Cargo.toml"
        requirement = m.group(1).lstrip("^~>=< ")
        floor = _parse_version(requirement)
        # A caret requirement of "0.29" admits 0.29.x and 0.30+ is a separate
        # major for pyo3's 0.x versioning, so the floor is what matters.
        assert floor >= PYO3_FIXED_IN[:len(floor)], (
            'Rust/Cargo.toml asks for pyo3 "%s"; a fresh `cargo update` could '
            "resolve that to a release vulnerable to GHSA-36hh-v3qg-5jq4"
            % requirement
        )


class TestTheVersionComparisonItself:
    """The check above is only as good as this predicate."""

    @pytest.mark.parametrize("version", [
        "0.29.0",       # the exact fixed release -- inclusive, not exclusive
        "0.29.2",
        "0.30.0",
        "1.0.0",
        "0.29.0-beta.1",
    ])
    def test_patched_versions_pass(self, version):
        assert _is_patched(version)

    @pytest.mark.parametrize("version", [
        "0.24.2",       # what the advisory was filed against
        "0.28.3",       # the last vulnerable release
        "0.28.99",
        "0.9.0",        # 9 > 2 only if you compare strings instead of ints
        "0.0.1",
    ])
    def test_vulnerable_versions_fail(self, version):
        assert not _is_patched(version)


class TestTheVulnerableCodeIsUnreachable:
    """Nothing in this crate hands PyO3 a Python list or tuple to iterate.

    The whole Python->Rust surface is `&[u8]`, `&str`, integers, `bool`,
    `&Bound<PyByteArray>`, `&Bound<PyAny>` and opaque pyclass handles. There is
    no sequence for `BoundListIterator`/`BoundTupleIterator` to walk, and
    `nth`/`nth_back` are never called on anything.
    """

    #: Substrings that would mean the reachability analysis needs redoing.
    #: `.nth(` and `.nth_back(` are listed even though they are only dangerous
    #: on a Python sequence: a plain Rust-iterator `.nth()` is harmless, but it
    #: is rare enough here that reviewing the one that appears costs nothing.
    FORBIDDEN = (
        "BoundListIterator",
        "BoundTupleIterator",
        "PyList",
        "PyTuple",
        ".nth(",
        ".nth_back(",
        ".step_by(",
    )

    @pytest.mark.parametrize("needle", FORBIDDEN)
    def test_no_source_file_uses_it(self, needle, rust_sources):
        offenders = []
        for name, body in rust_sources.items():
            for lineno, line in enumerate(body.splitlines(), 1):
                stripped = line.strip()
                if stripped.startswith("//") or stripped.startswith("///"):
                    continue          # a mention in a comment is not a use
                if needle in line:
                    offenders.append("%s:%d: %s" % (name, lineno, stripped))
        assert not offenders, (
            "%r now appears in the Rust core. GHSA-36hh-v3qg-5jq4's "
            "unreachability argument in SECURITY.md assumed no Python "
            "sequence is ever iterated across the boundary; re-check it.\n%s"
            % (needle, "\n".join(offenders))
        )
