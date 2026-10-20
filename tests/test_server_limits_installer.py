# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""prosody/install-server-limits.sh on a throwaway config. Owner
(2026-10-20), after the stress runs: "remove the account cap and add 1600
users online at once", then a 5,000-account backstop; the generational collector is what let the 1,600
run recover from a join burst (STRESS_TEST.md)."""
import os
import shutil
import pathlib
import subprocess
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "prosody", "install-server-limits.sh")

CFG = """admins = { "alice@x.i2p" }
modules_enabled = {
\t"roster";
}
max_online_users = 2000
max_registered_users = 2000
VirtualHost "x.i2p"
"""


@pytest.fixture
def tmp_path():
    # pytest's own tmp_path asks for the user name, which conftest stubs.
    with tempfile.TemporaryDirectory() as d:
        yield pathlib.Path(d)


def _run(tmp_path, **env):
    cfg = tmp_path / "prosody.cfg.lua"
    if not cfg.exists():
        cfg.write_text(CFG)
    e = dict(os.environ, RESTART="0", PROSODYCTL="true", PROSODY_CFG=str(cfg),
             PROSODY_MODULES=str(tmp_path / "mods"), **env)
    subprocess.run(["bash", SCRIPT], env=e, check=True, capture_output=True)
    return cfg.read_text()


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_defaults_online_1600_accounts_5000_generational_gc(tmp_path):
    out = _run(tmp_path)
    assert "max_online_users = 1600\n" in out
    assert "max_registered_users = 5000\n" in out
    assert 'gc = { mode = "generational" }\n' in out
    # Global options stay before the first VirtualHost.
    assert out.index("gc =") < out.index("VirtualHost")


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_safe_to_run_again_and_overridable(tmp_path):
    _run(tmp_path)
    out = _run(tmp_path, MAX_ONLINE_USERS="1800")
    assert out.count("gc =") == 1 and out.count("max_online_users") == 1
    assert "max_online_users = 1800\n" in out


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_the_result_is_valid_lua(tmp_path):
    lupa = pytest.importorskip("lupa")
    out = _run(tmp_path)
    lua = lupa.LuaRuntime()
    lua.execute("function VirtualHost() end\n" + out.replace('VirtualHost "x.i2p"',
                                                              'VirtualHost("x.i2p")'))
    assert lua.eval("gc.mode") == "generational"
    assert lua.eval("max_online_users") == 1600
