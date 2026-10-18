# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Stress run of 2026-10-18: the admin account's phone signed in mid-run,
the server (one session per account) ended the test's admin session, and
all 300 delete-user commands at the end failed with an unreadable stanza."""
import asyncio
import os
import types

import otrv4plus_stresstest as st

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_a_failed_command_says_its_condition_not_its_stanza():
    IqError = type("IqError", (Exception,), {})
    exc = IqError("<iq id='x' type='set' to='otrv4plus.i2p'>")
    exc.iq = {"error": {"condition": "forbidden", "text": ""}}
    assert st._why(exc) == "forbidden"
    IqTimeout = type("IqTimeout", (Exception,), {})
    assert st._why(IqTimeout("<iq ...>")) == "no answer from the server"
    assert "<iq" not in st._why(Exception("<iq id='x'>"))


class _Admin:
    def __init__(self, connected):
        self.connected, self.authenticated = connected, connected

    def is_connected(self):
        return self.connected


def test_the_admin_signs_in_again_when_its_session_went(monkeypatch):
    said, signed = [], []

    async def online(c, host, port, **_k):
        signed.append((host, port))
        c.connected = c.authenticated = True

    monkeypatch.setattr(st, "_online", online)
    gone = _Admin(False)
    assert asyncio.run(st._admin_back(gone, "127.0.0.1", 5222, said.append))
    assert signed == [("127.0.0.1", 5222)] and "one session" in said[0]
    signed.clear()
    assert asyncio.run(st._admin_back(_Admin(True), "127.0.0.1", 5222, said.append))
    assert signed == []


def test_accounts_left_behind_come_with_a_cleanup_line():
    line = st.CLEANUP_HINT % "otrv4plus.i2p"
    assert line.startswith("> ") and 'local d = "otrv4plus.i2p"' in line
    # Only the run's own accounts: stress-<run hex>-<number>.
    assert 'u:match("^stress%-%x+%-%d+$")' in line
    with open(os.path.join(ROOT, "otrv4plus_stresstest.py"), encoding="utf-8") as fh:
        src = fh.read()
    assert "await _admin_back(admin, args.host, args.port, say)" in src
    assert "str(exc)[:60]" not in src


def test_the_cleanup_pattern_matches_only_stress_accounts():
    lupa = __import__("pytest").importorskip("lupa")
    lua = lupa.LuaRuntime()
    match = lua.eval('function(u) return u:match("^stress%-%x+%-%d+$") ~= nil end')
    assert match("stress-8a4b89-000") and match("stress-8a4b89-299")
    assert not match("alice") and not match("stress-8a4b89-g01")
    assert not match("xstress-8a4b89-001")


def test_the_run_records_prosodys_peak_cpu_and_memory(monkeypatch):
    """Owner, 2026-10-18: "did we record the peak usage?" -- it did not."""
    sampler = st.ServerSampler.__new__(st.ServerSampler)
    sampler._os, sampler._tick, sampler.pid, sampler._last = os, 100, 4242, None
    sampler.minute_cpu, sampler.minute_rss, sampler.peak_cpu, sampler.peak_rss = [], 0.0, 0.0, 0.0
    proc = {"stat": "4242 (lua5.4) S " + " ".join(["0"] * 10) + " 100 50 0",
            "status": "Name:\tlua5.4\nVmRSS:\t  71680 kB\n"}
    real_open = open

    def fake_open(path, *a, **k):
        if str(path).startswith("/proc/4242/"):
            import io
            return io.StringIO(proc[str(path).rsplit("/", 1)[1]])
        return real_open(path, *a, **k)

    clock = [1000.0]
    monkeypatch.setattr("builtins.open", fake_open)
    monkeypatch.setattr(st.time, "time", lambda: clock[0])
    sampler.sample()
    clock[0] += 5
    proc["stat"] = "4242 (lua5.4) S " + " ".join(["0"] * 10) + " 300 100 0"
    sampler.sample()
    row = sampler.minute()
    # 250 ticks = 2.5 s of CPU in 5 s: 50% of one core.
    assert row["prosody_cpu_peak_pct"] == 50.0 and row["prosody_rss_mib"] == 70.0
    assert sampler.peak_cpu == 50.0 and sampler.peak_rss == 70.0
    src = real_open(os.path.join(ROOT, "otrv4plus_stresstest.py"), encoding="utf-8").read()
    assert "row.update(server.minute())" in src and "Prosody peak:" in src
