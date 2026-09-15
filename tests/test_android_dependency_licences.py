# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The Android half of the copyleft guard.

`tests/test_licence_declarations_agree.py` has walked the Rust graph since
v10.17.2 and fails if a crate with no permissive option appears. The Android
graph had no equivalent, so an `implementation("...")` of an LGPL or EPL
library would have passed every check in the repository and shipped.

That is not merely an attribution problem. The commercial half of the dual
licence is grantable only while every line distributed can be licensed both
ways; one copyleft dependency in the shipped graph ends that. The audit that
chose AGPL-3.0 turned on the finding that nothing imposed copyleft except the
project's own licence.

WHAT IS CHECKED WHERE
---------------------
The real guard is `:app:checkRuntimeDependencyLicences` in
android/app/build.gradle.kts. It resolves Gradle's actual runtime classpaths,
fetches each module's POM and classifies what it declares. It cannot run here:
this environment cannot reach dl.google.com, which is why the Android build
lives in GitHub Actions at all.

So this file checks two things it *can*:

  1. that the guard exists, is wired into `check`, and runs in CI -- a guard
     nothing invokes is not a guard; and
  2. that its licence-name PATTERNS classify a known-answer table correctly,
     by extracting the two regexes from the build script and evaluating them.

(2) is where the subtle failures live -- an `mit` that also matches "permit",
an alternative quietly added to the permissive side. It tests the patterns
only. The full rule, including the disjunction handling, is self-tested inside
the Gradle task on every run, because a classifier that has been neutered
passes everything and reads as green.
"""

import io
import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD_FILE = os.path.join(ROOT, "android", "app", "build.gradle.kts")
WORKFLOW = os.path.join(ROOT, ".github", "workflows", "android.yml")
TASK = "checkRuntimeDependencyLicences"


def _read(path):
    with io.open(path, encoding="utf-8") as fh:
        return fh.read()


@pytest.fixture(scope="module")
def build_script():
    return _read(BUILD_FILE)


def _kotlin_regex(script, name):
    """The pattern text of `val <name> = Regex(...)` from the build script.

    The literal is written as adjacent triple-quoted chunks joined with `+`,
    so the pattern is every chunk between `Regex(` and the closing
    `RegexOption`. Extracted rather than restated: a test carrying its own
    copy of the pattern would pass while the build script's copy was wrong,
    which is the exact failure this is meant to catch.
    """
    start = script.index("val %s = Regex(" % name)
    end = script.index("RegexOption.IGNORE_CASE", start)
    body = script[start:end]
    chunks = re.findall(r'"""(.*?)"""', body, re.S)
    assert chunks, "no pattern literal found for %s" % name
    return "".join(chunks)


@pytest.fixture(scope="module")
def patterns(build_script):
    return (
        re.compile(_kotlin_regex(build_script, "permissiveLicence"), re.I),
        re.compile(_kotlin_regex(build_script, "copyleftLicence"), re.I),
    )


def _classify(names, permissive, copyleft):
    """The build script's rule, applied to the build script's patterns."""
    declared = [n.strip() for n in names if n and n.strip()]
    if not declared:
        return "unknown"
    if any(permissive.search(n) and not copyleft.search(n) for n in declared):
        return "permissive"
    if any(copyleft.search(n) for n in declared):
        return "copyleft"
    return "unknown"


class TestTheGuardIsActuallyWiredUp:
    """A verification task nothing depends on runs on nobody's machine."""

    def test_the_task_exists(self, build_script):
        assert 'tasks.register("%s")' % TASK in build_script

    def test_it_is_part_of_check(self, build_script):
        assert 'tasks.named("check") { dependsOn("%s") }' % TASK in build_script

    def test_ci_runs_it(self):
        """CI is the only place it can run: this development environment is
        blocked from dl.google.com, so `./gradlew` cannot resolve AndroidX
        here at all."""
        assert TASK in _read(WORKFLOW), (
            "the guard is not invoked by .github/workflows/android.yml, so "
            "nothing runs it -- this environment cannot")

    def test_it_reads_the_resolved_graph_not_the_build_file(self, build_script):
        """The distinction the whole design turns on. A grep over
        `dependencies {}` would miss every transitive dependency, and there
        are roughly ten of those for each line written down."""
        assert "incoming.artifacts.artifacts" in build_script
        assert "RuntimeClasspath" in build_script

    def test_it_checks_both_shipped_variants(self, build_script):
        """The debug APK is what the release job publishes as the rolling
        experimental build, so debug is shipped too -- and debugImplementation
        adds ui-tooling to it."""
        assert "debugRuntimeClasspath" in build_script
        assert "releaseRuntimeClasspath" in build_script

    def test_test_only_configurations_are_not_checked(self, build_script):
        """JUnit is EPL, which is copyleft, and is entirely fine because it is
        not in the artifact. Flagging it would train everyone to ignore this
        check. The exclusion is structural -- the runtime classpaths simply do
        not contain test dependencies -- so what this asserts is that no
        unit-test or androidTest classpath was added to the list."""
        for cfg in ("UnitTestRuntimeClasspath", "AndroidTestRuntimeClasspath"):
            assert cfg not in build_script, (
                "%s is being checked; test-only dependencies are not "
                "distributed and must not fail the guard" % cfg)

    def test_it_fails_closed_on_an_undeterminable_licence(self, build_script):
        """`unknown` must be an offender. A guard that passes what it could
        not read reports green on exactly the cases worth looking at."""
        assert 'filterValues { it.first != "permissive" }' in build_script


class TestThePatternsClassifyRealLicenceNames:
    """Licence names as they actually appear in POMs, not as SPDX ids."""

    @pytest.mark.parametrize("name", [
        "The Apache Software License, Version 2.0",
        "Apache License, Version 2.0",
        "Apache-2.0",
        "MIT License",
        "The MIT License",
        "MIT",
        "BSD 3-Clause License",
        "The BSD License",
        "BSD-2-Clause",
        "ISC License",
        "Python Software Foundation License",
        "The zlib/libpng License",
        "Unicode/ICU License",
        "CC0 1.0 Universal",
        "Bouncy Castle Licence",
        "Universal Permissive License v1.0",
    ])
    def test_permissive_names_are_permissive(self, name, patterns):
        assert _classify([name], *patterns) == "permissive", name

    @pytest.mark.parametrize("name", [
        "GNU General Public License, version 3",
        "GNU General Public License v2.0 only",
        "GPL-3.0-only",
        "GNU Lesser General Public License",
        "LGPL-2.1",
        "GNU Affero General Public License v3.0",
        "AGPL-3.0",
        "Mozilla Public License 2.0",
        "MPL-2.0",
        "Eclipse Public License 2.0",
        "Eclipse Public License - v 1.0",
        "Common Development and Distribution License",
        "CDDL-1.1",
        "European Union Public Licence 1.2",
        "Server Side Public License",
        "Business Source License 1.1",
    ])
    def test_copyleft_names_are_copyleft(self, name, patterns):
        assert _classify([name], *patterns) == "copyleft", name

    @pytest.mark.parametrize("name", [
        "Android Software Development Kit License",
        "Some Bespoke Vendor Terms",
        "Proprietary",
        "All rights reserved",
    ])
    def test_unrecognised_names_are_unknown_not_permissive(self, name, patterns):
        """Fail closed. A proprietary vendor licence is emphatically not
        permissive, and the safe answer for anything unrecognised is to make
        a person look at it."""
        assert _classify([name], *patterns) == "unknown", name

    def test_a_module_declaring_nothing_is_unknown(self, patterns):
        assert _classify([], *patterns) == "unknown"
        assert _classify(["", "   "], *patterns) == "unknown"


class TestThePermissivePatternIsNotOverBroad:
    """The way this guard dies quietly: a pattern that matches everything."""

    @pytest.mark.parametrize("word", [
        "permit", "permitted", "submit", "transmit",     # ...mit...
        "miscellaneous", "discussion",                    # ...isc...
        "embsden", "absd",                                # ...bsd... nonsense
    ])
    def test_short_alternatives_do_not_match_inside_words(self, word, patterns):
        permissive, _copyleft = patterns
        assert not permissive.search(word), (
            "%r matches the permissive pattern, so a licence name merely "
            "containing it would be waved through" % word)

    def test_a_bare_reciprocity_clause_is_not_permissive(self, patterns):
        """"You must retain..." appears in the Apache body and once fooled
        the NOTICE generator into attributing it as a copyright line. It must
        not, on its own, read as a licence name."""
        assert _classify(
            ["You must retain, in the Source form of any Derivative Works"],
            *patterns) == "unknown"


class TestTheDisjunctionRuleMatchesTheCargoCheck:
    """Multiple <license> entries in a POM are a choice, exactly as an SPDX
    `OR` is. The Rust guard already takes the permissive branch; the Android
    one must agree, or the same dependency would be judged differently
    depending on which language it arrived in."""

    def test_a_permissive_option_alongside_a_copyleft_one_passes(self, patterns):
        assert _classify(
            ["GPL-2.0-with-classpath-exception", "Apache License 2.0"],
            *patterns) == "permissive"

    def test_copyleft_only_still_fails(self, patterns):
        assert _classify(
            ["GNU General Public License v3", "GNU Affero General Public "
             "License v3"], *patterns) == "copyleft"

    def test_the_gradle_task_self_tests_the_same_rule(self, build_script):
        """The Kotlin side checks its own classifier against known answers
        before trusting its verdict on the real graph. Without that, an
        inverted or over-broad rule passes everything and reads as green --
        and this Python file only sees the patterns, not the rule."""
        assert "the licence classifier itself is wrong" in build_script
        assert 'to "copyleft"' in build_script
        assert 'to "unknown"' in build_script
