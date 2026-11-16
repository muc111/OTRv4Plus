# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The Rust workflows run when Rust changes, and on a cadence that covers dev.

Three workflows look only at the Rust core: its own tests (rust.yml), the
advisory audit of its lock files (rust-audit.yml) and the fuzz harnesses
(fuzz.yml). Each is filtered by path, so a change to Kotlin, Python or the
docs does not pay for them. A filter is also how coverage is lost without
anyone deciding to lose it:

- the list for a pull request drifts from the list for a push (both audit
  and fuzz had: a change to Rust/mls/Cargo.toml or Rust/Cargo.lock ran on
  a push and not on a pull request);
- the weekly run covers only `main`, because a scheduled workflow runs from
  the default branch, while `dev` is where a dependency or a change lands
  first;
- a job with no time limit hangs for six hours instead of failing.

And one gap these do not describe: until rust.yml, no workflow ran the
core's own `cargo test` at all.

Read with PyYAML, which resolves the anchor the lists are shared through.
"""
import os

import pytest

yaml = pytest.importorskip("yaml")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKFLOWS = os.path.join(ROOT, ".github", "workflows")

#: workflow -> what it reads, which its filter therefore has to watch.
WATCHES = {
    "rust.yml": ("Rust/src/**", "Rust/build.rs", "Rust/Cargo.toml",
                 "Rust/Cargo.lock", "Rust/mls/**", "Rust/vendor/**",
                 "Rust/opus-codec/**", ".github/workflows/rust.yml"),
    "rust-audit.yml": ("Rust/Cargo.toml", "Rust/Cargo.lock",
                       "Rust/.cargo/audit.toml", "Rust/mls/Cargo.toml",
                       "Rust/mls/Cargo.lock", "Rust/mls/.cargo/audit.toml",
                       ".github/workflows/rust-audit.yml"),
    "fuzz.yml": ("Rust/src/**", "Rust/build.rs", "Rust/Cargo.toml",
                 "Rust/Cargo.lock", "Rust/fuzz/**",
                 ".github/workflows/fuzz.yml"),
}

#: workflow -> the job that does the work on the weekly run.
SCHEDULED_JOB = {"rust.yml": "test", "rust-audit.yml": "audit",
                 "fuzz.yml": "run"}


def _load(name):
    with open(os.path.join(WORKFLOWS, name), encoding="utf-8") as handle:
        workflow = yaml.safe_load(handle)
    # YAML 1.1 reads the key `on` as the boolean True.
    return workflow, workflow.get("on", workflow.get(True))


@pytest.mark.parametrize("name", sorted(WATCHES))
def test_a_push_and_a_pull_request_watch_the_same_paths(name):
    _, on = _load(name)
    pushed = on["push"]["paths"]
    assert on["pull_request"]["paths"] == pushed, (
        "%s: a change that runs on a push must run on a pull request" % name)
    assert len(pushed) == len(set(pushed))


@pytest.mark.parametrize("name", sorted(WATCHES))
def test_the_filter_watches_everything_the_jobs_read(name):
    _, on = _load(name)
    watched = set(on["push"]["paths"])
    for needed in WATCHES[name]:
        assert needed in watched, "%s does not run when %s changes" % (
            name, needed)


@pytest.mark.parametrize("name", sorted(WATCHES))
def test_every_watched_path_exists(name):
    """A pattern with a typo watches nothing and says nothing."""
    _, on = _load(name)
    for pattern in on["push"]["paths"]:
        fixed = pattern.split("*", 1)[0].rstrip("/")
        assert os.path.exists(os.path.join(ROOT, fixed)), (name, pattern)


@pytest.mark.parametrize("name", sorted(WATCHES))
def test_a_change_elsewhere_does_not_pay_for_it(name):
    """Filtered on both events, and never on the whole tree: these are
    minutes of Rust building for a change that cannot affect Rust."""
    _, on = _load(name)
    for event in ("push", "pull_request"):
        paths = on[event]["paths"]
        assert paths, (name, event)
        for pattern in paths:
            assert pattern.startswith(("Rust/", ".github/workflows/")), pattern
            assert pattern not in ("**", "Rust/**"), pattern
    assert on["push"]["branches"] == ["main", "dev", "claude/**"]


@pytest.mark.parametrize("name", sorted(WATCHES))
def test_it_also_runs_weekly_and_on_demand(name):
    """Advisories, and a toolchain called `stable`, arrive against code
    that has not moved."""
    _, on = _load(name)
    (schedule,) = on["schedule"]
    minute, hour, day, month, weekday = schedule["cron"].split()
    assert day == "*" and month == "*" and weekday in "0123456", schedule
    assert minute.isdigit() and hour.isdigit()
    assert "workflow_dispatch" in on


@pytest.mark.parametrize("name", sorted(WATCHES))
def test_the_weekly_run_covers_dev_as_well_as_main(name):
    """A scheduled workflow runs from the default branch only. `dev` is
    where a dependency arrives first and what the test builds are made
    from, so the job checks out each branch in turn on the weekly run and
    the triggering commit otherwise."""
    workflow, _ = _load(name)
    job = workflow["jobs"][SCHEDULED_JOB[name]]
    ref = job["strategy"]["matrix"]["ref"]
    assert "github.event_name == 'schedule'" in ref
    assert '["main", "dev"]' in ref and "'[\"\"]'" in ref, ref
    assert job["strategy"]["fail-fast"] is False
    checkout = next(step for step in job["steps"]
                    if str(step.get("uses", "")).startswith("actions/checkout"))
    assert checkout["with"]["ref"] == "${{ matrix.ref }}"


@pytest.mark.parametrize("name", sorted(WATCHES))
def test_every_job_has_a_time_limit(name):
    workflow, _ = _load(name)
    for job_name, job in workflow["jobs"].items():
        assert 0 < job.get("timeout-minutes", 0) <= 60, (name, job_name)
        assert workflow["permissions"] == {"contents": "read"}


def test_the_cores_own_tests_run_in_ci():
    """`cargo test` in Rust/, as locked, for the default build and for the
    feature set the apps are built with."""
    workflow, _ = _load("rust.yml")
    job = workflow["jobs"]["test"]
    assert job["defaults"]["run"]["working-directory"] == "Rust"
    commands = [str(step.get("run", "")) for step in job["steps"]]
    assert "cargo test --release --locked" in commands
    assert "cargo test --release --locked --features mls" in commands
    # A PyO3 crate's test binary links libpython.
    assert any(str(step.get("uses", "")).startswith("actions/setup-python")
               for step in job["steps"])
    # None of the gated test features: this is the core as it ships.
    for command in commands:
        for feature in ("raw-key-test-api", "test-only-kdf", "legacy-dake-keys"):
            assert feature not in command


def test_the_fuzz_run_still_needs_the_harnesses_to_compile():
    workflow, _ = _load("fuzz.yml")
    assert workflow["jobs"]["run"]["needs"] == "compile"
    assert "schedule" in workflow["jobs"]["run"]["if"]
    assert "if" not in workflow["jobs"]["compile"]
