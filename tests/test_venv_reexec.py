# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""`python otrv4+.py` with the system Python: the clients re-run themselves
with ~/OTRv4Plus/.venv/bin/python, where build.sh installs otrv4_core
(device report, 2026-10-05: the IRC client said the core "was not built with
the dake module" when there was simply no core for that Python)."""
import os
import pathlib
import sys
import tempfile

import otrv4plus_venv as V


def _tmp():
    # Not pytest's tmp_path: other suites stub `pwd`, which getuser() reads.
    return pathlib.Path(tempfile.mkdtemp())


def _repo(tmp_path, with_venv=True):
    script = tmp_path / "otrv4+.py"
    script.write_text("")
    if with_venv:
        bin_dir = tmp_path / ".venv" / "bin"
        bin_dir.mkdir(parents=True)
        py = bin_dir / "python"
        py.write_text("")
        py.chmod(0o755)
    return str(script)


def _ensure(script, monkeypatch, argv=("-n", "nick")):
    monkeypatch.delenv(V.GUARD, raising=False)
    monkeypatch.delenv(V.OPT_OUT, raising=False)
    calls = []
    V.ensure(script, list(argv), execv=lambda *a: calls.append(a))
    return calls


def test_another_python_is_replaced_by_the_project_one(monkeypatch):
    tmp_path = _tmp()
    script = _repo(tmp_path)
    calls = _ensure(script, monkeypatch)
    assert len(calls) == 1
    target, args, env = calls[0]
    assert target == str(tmp_path / ".venv" / "bin" / "python")
    assert args[1:] == [os.path.realpath(script), "-n", "nick"]
    assert env[V.GUARD] == "1" and env["PYTHONMALLOC"] == "malloc"


def test_no_venv_means_no_change(monkeypatch):
    tmp_path = _tmp()
    assert _ensure(_repo(tmp_path, with_venv=False), monkeypatch) == []


def test_never_twice_and_can_be_turned_off(monkeypatch):
    tmp_path = _tmp()
    script = _repo(tmp_path)
    monkeypatch.setenv(V.GUARD, "1")
    assert V.ensure(script, [], execv=lambda *a: (_ for _ in ()).throw(AssertionError)) is None
    monkeypatch.delenv(V.GUARD)
    monkeypatch.setenv(V.OPT_OUT, "1")
    assert V.ensure(script, [], execv=lambda *a: (_ for _ in ()).throw(AssertionError)) is None


def test_already_the_project_python(monkeypatch):
    tmp_path = _tmp()
    script = _repo(tmp_path)
    monkeypatch.setattr(sys, "prefix", str(tmp_path / ".venv"))
    assert _ensure(script, monkeypatch) == []


def test_both_clients_call_it_before_loading_the_core():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    # The IRC client imports the core itself; the XMPP client loads it with
    # the engine, after its first import line.
    for name, before in (("otrv4+.py", "from otrv4_core"),
                         ("otrv4plus_xmpp.py", "\nimport argparse")):
        src = open(os.path.join(root, name), encoding="utf-8").read()
        at = src.index('import_module("otrv4plus_venv").ensure(__file__)')
        assert at < src.index(before), name
