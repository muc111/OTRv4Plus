# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""A workflow with a path filter must watch everything its jobs depend on.

rc.134 moved the Python modules into client/. desktop.yml, whose job runs
desktop/install.sh on a clean Ubuntu, watched only desktop files -- so the
install broke and no run noticed for eight builds (found 2026-10-24). These
assert the dependencies are in the filter.
"""
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _paths(workflow):
    text = open(os.path.join(ROOT, ".github", "workflows", workflow), encoding="utf-8").read()
    block = text[text.index("paths:"):text.index("workflow_dispatch:")]
    return set(re.findall(r'^\s+-\s+"([^"]+)"\s*$', block, re.M))


def test_the_desktop_install_runs_when_what_it_installs_changes():
    watched = _paths("desktop.yml")
    for dep in ("desktop/**", "desktop_bridge/**", "client/**", "android_bridge/**",
                "Rust/**", ".github/workflows/desktop.yml"):
        assert dep in watched, "desktop.yml does not run when %s changes" % dep


def test_python_has_no_path_filter():
    """python.yml runs on every push, deliberately (see its header)."""
    text = open(os.path.join(ROOT, ".github", "workflows", "python.yml"), encoding="utf-8").read()
    on = text[text.index("\non:"):text.index("\npermissions:")]
    assert "paths:" not in on
