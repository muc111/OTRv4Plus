"""The APK's pip block, and the trade it makes.

`android/app/build.gradle.kts` sets `options("--no-deps")`. It has to: slixmpp
declares `aiodns` as a hard requirement in every release from 1.9.0 onwards,
aiodns requires pycares, and pycares compiles c-ares from source with cmake --
which Chaquopy answers with `Chaquopy_cannot_compile_native_code`. pip has no
way to drop one dependency and Chaquopy's `install()` takes one requirement, so
the only lever is global.

The cost is precise and worth stating: with resolution on, a missing dependency
is a build failure; with it off, it is an ImportError on a handset. Two things
therefore have to hold, and this file is the offline half of them.

  * `.github/scripts/verify_python_closure.py` re-resolves the declared roots
    WITH dependencies on every CI run and fails if anything is unnamed. That is
    the real check, and it needs an index.
  * this file pins what the list currently IS, so that adding or removing a
    package is a deliberate edit here rather than a quiet one there -- and in
    particular so that "tidying up" the list back down to the three packages
    anyone actually asked for shows up as a failure rather than as a green
    build and a dead app.
"""

import os
import re

import pytest

GRADLE = "android/app/build.gradle.kts"

#: What the pip block must contain, and why each one is there.
#:
#: Three of these were asked for; six are here only because --no-deps means
#: nothing else will ask for them. The distinction is kept because it is the
#: thing that goes stale: if slixmpp ever drops pyasn1, this comment is how
#: someone knows the line can go.
REQUIRED = {
    # asked for directly
    "otrv4_core": "the Rust core; every cryptographic operation is behind it "
                  "and there is no Python fallback",
    "PySocks": "imported at module scope by otrv4+.py",
    "slixmpp": "the XMPP transport",
    "argon2-cffi": "the at-rest KDF; without it the engine falls back to scrypt",
    # transitive, and named because of --no-deps
    "pyasn1": "slixmpp",
    "pyasn1-modules": "slixmpp",
    "argon2-cffi-bindings": "argon2-cffi",
    "cffi": "argon2-cffi-bindings",
    "pycparser": "cffi",
    "chaquopy-libffi": "cffi's android wheel",
}

#: Never in the APK.
FORBIDDEN = {
    "aiodns": "optional in slixmpp; this client only reaches 127.0.0.1 via "
              "the SAM bridge, so there is no SRV lookup to lose",
    "pycares": "compiles c-ares with cmake, which Chaquopy cannot do",
}

pytestmark = pytest.mark.skipif(
    not os.path.exists(GRADLE), reason="no android/ project in this checkout")


def _pip_block():
    """The body of `pip { ... }`, with // comments stripped.

    Comments come out first and it matters here more than usual: the block
    carries a long explanation of why aiodns is excluded, and that explanation
    quotes `install("aiodns")`. Matching before stripping would find the
    forbidden package inside the comment that forbids it.
    """
    src = open(GRADLE).read()
    start = src.index("pip {")
    depth = 0
    for i in range(start, len(src)):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return re.sub(r"//[^\n]*", "", src[start:i])
    raise AssertionError("the pip block in %s is unterminated" % GRADLE)


def _normalise(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def installed():
    return {_normalise(m)
            for m in re.findall(r'install\(\s*"([^"]+)"', _pip_block())}


class TestTheClosureIsNamed:

    def test_every_required_package_is_installed(self):
        missing = sorted(_normalise(n) for n in REQUIRED
                         if _normalise(n) not in installed())
        assert missing == [], (
            "--no-deps is set, so anything not named here never reaches the "
            "APK and the app ImportErrors at launch: %s" % missing)

    def test_the_list_is_exactly_the_closure(self):
        """No extras either.

        A package that nothing needs is dead weight in an APK that is trying
        to stay small, and worse, it is a distribution shipped to users that
        no one can say why they are running.
        """
        assert installed() == {_normalise(n) for n in REQUIRED}

    def test_the_transitive_packages_outnumber_the_asked_for_ones(self):
        """The point of the list, as an assertion.

        Six of the ten entries exist only because resolution is off. Someone
        reading the block and seeing pycparser or chaquopy-libffi may well
        wonder what they are doing in a messenger; this is the record that
        they are cffi's, not ours.
        """
        asked_for = {"otrv4-core", "pysocks", "slixmpp", "argon2-cffi"}
        assert asked_for < installed()
        assert len(installed() - asked_for) == 6


class TestTheThingThatForcedIt:

    def test_no_deps_is_set(self):
        block = _pip_block()
        assert re.search(r'options\([^)]*"--no-deps"', block), (
            "the explicit package list below only makes sense with --no-deps; "
            "without it pip resolves aiodns and the build dies on pycares")

    def test_aiodns_is_not_installed(self):
        for name, why in FORBIDDEN.items():
            assert _normalise(name) not in installed(), \
                "%s must not ship: %s" % (name, why)

    def test_the_reason_survives_in_the_file(self):
        """The comment is load-bearing, not decoration.

        Anyone who deletes --no-deps to "simplify" the block gets a build
        failure they have to diagnose from scratch unless the reason is
        written down next to it.
        """
        src = open(GRADLE).read()
        assert "pycares" in src
        assert "aiodns" in src


class TestTheCheckThatNeedsAnIndex:

    def test_the_ci_script_exists(self):
        """This file cannot re-resolve; something has to.

        Everything above pins the list as it is. None of it would notice
        slixmpp gaining a new pure-Python dependency in some future release --
        which with --no-deps is a green build and a dead app. That is what the
        CI script is for, so its absence is a hole in this file's coverage
        rather than a missing convenience.
        """
        assert os.path.exists(".github/scripts/verify_python_closure.py")

    def test_the_workflow_runs_it(self):
        workflow = ".github/workflows/android.yml"
        assert "verify_python_closure.py" in open(workflow).read(), (
            "the closure check is only worth having if it runs")

    def test_the_exclusions_agree_with_this_file(self):
        """Two lists of what is deliberately missing; they must not drift.

        If someone re-adds aiodns to the build file and to the script's
        exclusions but not here, the build breaks on pycares again with a test
        suite that said nothing.
        """
        src = open(".github/scripts/verify_python_closure.py").read()
        block = src[src.index("EXCLUDED_BY_DESIGN = {"):]
        block = block[:block.index("\n}")]
        for name in FORBIDDEN:
            assert '"%s"' % name in block, (
                "%s is forbidden here but not excluded in the CI script, "
                "which will therefore report it as a missing dependency"
                % name)
