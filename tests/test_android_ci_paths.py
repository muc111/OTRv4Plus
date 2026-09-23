#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Android CI watches everything the APK ships.

THE GAP
=======
`android.yml` triggered on `android/**`, `android_bridge/**` and `Rust/**`.
The APK also packages the shared orchestration layer -- `otrv4+.py` and its
import closure -- and the workflow did not watch any of it.

So a change to the engine Android runs produced NO Android job. Measured, not
supposed: b6e82b8 fixed the DAKE1 rate limiter on the live Android path,
touched only `otrv4+.py`, matched no filter, and had to be dispatched by hand.
Without that manual step a shared-engine change would have shipped with the
Kotlin tests, the APK assembly and the packaging checks all unrun.

WHY NOT "EVERY PYTHON FILE"
===========================
Most of this repository is the terminal client, which the APK does not ship.
Triggering a full Android build -- two Rust cross-compiles, Gradle, Chaquopy
-- on a change to a Termux-only module would be minutes of CI for a file that
cannot affect the APK.

The precise answer already existed: `syncPythonSources` in
android/app/build.gradle.kts copies a computed module-scope import closure
into the APK. That list is exactly "what Android depends on", and the build
file even documents how to re-derive it.

WHY THIS TEST HAS TO EXIST
==========================
GitHub path filters cannot run code, so the list is duplicated into the YAML.
Two lists that must agree and nothing checking them is how the first gap
appeared. This is the check: add a module to the build and forget the
workflow, and this fails rather than the dependency going quietly unwatched.
"""

import io
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKFLOW = os.path.join(ROOT, ".github", "workflows", "android.yml")
GRADLE = os.path.join(ROOT, "android", "app", "build.gradle.kts")


def _read(path):
    with io.open(path, encoding="utf-8") as handle:
        return handle.read()


def _packaged_modules():
    """The .py files `syncPythonSources` copies into the APK."""
    source = _read(GRADLE)
    start = source.index("val syncPythonSources by tasks.registering")
    block = source[start:start + 6000]
    return set(re.findall(r'^\s+"([A-Za-z0-9_+.-]+\.py)",?\s*$', block, re.M))


def _watched_paths():
    """The path globs `android.yml` triggers on."""
    source = _read(WORKFLOW)
    block = source[source.index("paths: &android_paths"):]
    block = block[:block.index("pull_request:")]
    return set(re.findall(r'^\s+-\s+"([^"]+)"\s*$', block, re.M))


@pytest.fixture(scope="module")
def packaged():
    return _packaged_modules()


@pytest.fixture(scope="module")
def watched():
    return _watched_paths()


class TestTheTwoListsAgree:

    def test_the_parses_found_something(self, packaged, watched):
        """A regex that matched nothing would make everything below vacuous."""
        assert len(packaged) >= 15, (
            "only found %d packaged modules; the gradle parse is wrong"
            % len(packaged))
        assert "otrv4+.py" in packaged
        assert len(watched) >= 15

    def test_every_packaged_module_is_watched(self, packaged, watched):
        missing = sorted(packaged - watched)
        assert not missing, (
            "the APK packages %s and android.yml does not watch them, so a "
            "change to any of them runs no Android job at all. Add them to "
            "the `paths:` list in .github/workflows/android.yml."
            % ", ".join(missing))

    def test_the_watch_list_has_no_module_the_apk_does_not_ship(
            self, packaged, watched):
        """The other direction. A stale entry is not dangerous, but it costs
        a full Android build -- two Rust cross-compiles and Gradle -- on a
        file that cannot affect the APK."""
        directories = {"android/**", "android_bridge/**", "Rust/**",
                       ".github/workflows/android.yml"}
        stale = sorted(w for w in watched
                       if w.endswith(".py") and w not in packaged
                       and w not in directories)
        assert not stale, (
            "android.yml watches %s, which the APK does not package; either "
            "add them to syncPythonSources or drop them from the filter"
            % ", ".join(stale))

    def test_the_directory_watches_are_still_there(self, watched):
        """Widening the filter must not have replaced what it already had."""
        for required in ("android/**", "android_bridge/**", "Rust/**",
                         ".github/workflows/android.yml"):
            assert required in watched, "%s is no longer watched" % required

    def test_pull_request_uses_the_same_list(self):
        """A push-only widening would leave every PR unchecked, which is the
        gap again with a different trigger."""
        source = _read(WORKFLOW)
        assert "paths: &android_paths" in source
        assert "paths: *android_paths" in source, (
            "pull_request does not reuse the push path list, so the two can "
            "drift and PRs can go unbuilt")

    def test_the_yaml_anchor_resolves(self):
        """The anchor is what keeps push and pull_request identical. If PyYAML
        cannot resolve it, neither can GitHub."""
        try:
            import yaml
        except ImportError:
            # CI installs PyYAML (python.yml); there, a missing module is a
            # broken environment and this check must not quietly skip.
            if os.environ.get("CI"):
                pytest.fail("PyYAML is required in CI to resolve the anchor")
            pytest.skip("PyYAML is not installed here")
        parsed = yaml.safe_load(_read(WORKFLOW))
        triggers = parsed[True] if True in parsed else parsed["on"]
        push = set(triggers["push"]["paths"])
        pull = set(triggers["pull_request"]["paths"])
        assert push == pull and push, (
            "push and pull_request resolve to different path lists")

    def test_workflow_dispatch_survives(self):
        """The manual escape hatch stays. It is what covered b6e82b8 and is
        still the answer for a change this filter deliberately excludes."""
        assert "workflow_dispatch:" in _read(WORKFLOW)


class TestTheEngineChangeThatExposedThis:
    """Named cases, so the specific regression cannot come back quietly."""

    def test_a_change_to_the_orchestration_layer_triggers_android(
            self, watched):
        assert "otrv4+.py" in watched, (
            "the file b6e82b8 changed is still unwatched")

    @pytest.mark.parametrize("module", [
        "otrv4plus_fragment.py",   # the wire format both clients share
        "otrv4plus_mode.py",       # whether a conversation may send in clear
        "otrv4plus_smpflow.py",    # the SMP consent state machine, INV-06
        "otrv4plus_voice.py",      # the voice path
        "otrv4plus_filetransfer.py",
        "otrv4plus_xmpp.py",
    ])
    def test_security_relevant_shared_modules_are_watched(
            self, watched, module):
        assert module in watched, (
            "%s is packaged into the APK and a change to it would run no "
            "Android job" % module)
