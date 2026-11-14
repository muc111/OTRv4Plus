# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""prosody/install-server-limits.sh on a throwaway config. Owner
(2026-10-20), after the stress runs: "remove the account cap and add 1600
users online at once", then a 5,000-account backstop; the generational collector is what let the 1,600
run recover from a join burst (docs/STRESS_TEST.md)."""
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


# ── red team 2026-11: a hidden server must not be findable ──────────────────

def _run_out(tmp_path, **env):
    cfg = tmp_path / "prosody.cfg.lua"
    if not cfg.exists():
        cfg.write_text(CFG)
    e = dict(os.environ, RESTART="0", PROSODYCTL="true", PROSODY_CFG=str(cfg),
             PROSODY_MODULES=str(tmp_path / "mods"), **env)
    done = subprocess.run(["bash", SCRIPT], env=e, check=True,
                          capture_output=True, text=True)
    return cfg.read_text(), done.stdout


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_by_default_nothing_about_listening_changes_and_it_says_so(tmp_path):
    out, said = _run_out(tmp_path)
    assert "interfaces" not in out and "modules_disabled" not in out
    assert "federation (s2s) is on" in said
    assert "HIDDEN_SERVICE=1" in said


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_hidden_service_binds_to_loopback_and_turns_federation_off(tmp_path):
    out, said = _run_out(tmp_path, HIDDEN_SERVICE="1")
    assert 'interfaces = { "127.0.0.1" }\n' in out
    assert 'modules_disabled = { "s2s"; }\n' in out
    assert "hide_os_type = true\n" in out
    for key in ("interfaces =", "modules_disabled =", "hide_os_type ="):
        assert out.index(key) < out.index("VirtualHost"), key
    assert "federation (s2s) is on" not in said
    again, _ = _run_out(tmp_path, HIDDEN_SERVICE="1")
    assert again == out


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
@pytest.mark.parametrize("existing,entries", [
    ('modules_disabled = {\n\t"offline";\n}\n', ('"s2s"', '"offline"')),
    ('modules_disabled = { "offline" }\n', ('"s2s"', '"offline"')),
    ('modules_disabled = { }\n', ('"s2s"',)),
    ('modules_disabled = {\n\t"s2s";\n}\n', ('"s2s"',)),
])
def test_an_existing_disabled_list_keeps_what_it_had(tmp_path, existing,
                                                     entries):
    (tmp_path / "prosody.cfg.lua").write_text(
        CFG.replace("VirtualHost", existing + "VirtualHost"))
    out, _ = _run_out(tmp_path, HIDDEN_SERVICE="1")
    assert out.count("modules_disabled") == 1
    block = out[out.index("modules_disabled"):]
    block = block[:block.index("}") + 1]
    for entry in entries:
        assert block.count(entry) == 1, (entry, block)
    lua = shutil.which("lua5.4") or shutil.which("lua") or shutil.which("luajit")
    if lua:
        check = "VirtualHost = function() end\n" + out
        subprocess.run([lua, "-e", check], check=True, capture_output=True)


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_a_narrower_interface_option_is_not_mistaken_for_the_global_one(
        tmp_path):
    (tmp_path / "prosody.cfg.lua").write_text(
        CFG.replace("VirtualHost", 'c2s_interfaces = { "*" }\nVirtualHost'))
    out, _ = _run_out(tmp_path, HIDDEN_SERVICE="1")
    assert 'c2s_interfaces = { "*" }\n' in out
    assert '\ninterfaces = { "127.0.0.1" }\n' in out


def test_the_session_module_logs_no_names():
    with open(os.path.join(ROOT, "prosody",
                           "mod_otrv4plus_one_session.lua")) as fh:
        source = fh.read()
    for line in source.splitlines():
        if "module:log(" in line:
            assert "%s" not in line, line
