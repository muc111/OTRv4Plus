# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""prosody/mod_otrv4plus_moderation.lua against stubbed Prosody APIs
(tests/lua/moderation_harness.lua). Needs `lupa`; skipped without it."""
import os

import pytest

lupa = pytest.importorskip("lupa")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_ban_unban_status_and_the_bind_refusal():
    lua = lupa.LuaRuntime()
    lua.globals().arg_path = os.path.join(ROOT, "prosody", "mod_otrv4plus_moderation.lua")
    with open(os.path.join(ROOT, "tests", "lua", "moderation_harness.lua")) as fh:
        report = lua.execute(fh.read())
    lines = report.splitlines()
    assert len(lines) >= 26
    assert [l for l in lines if not l.startswith("ok ")] == []


def test_the_same_with_prosody_roles_and_no_legacy_is_admin():
    """Prosody 13 has roles: the module must use them, never is_admin()."""
    with open(os.path.join(ROOT, "tests", "lua", "moderation_harness.lua")) as fh:
        harness = fh.read()
    stub = '  is_admin=function(j) return j=="alice@x.i2p" end,'
    assert stub in harness
    harness = harness.replace(stub,
        '  get_jid_role=function(j) if j=="alice@x.i2p" then return {name="prosody:admin"} end '
        'return {name="prosody:registered"} end,\n'
        '  is_admin=function() error("the legacy is_admin() API was used") end,')
    lua = lupa.LuaRuntime()
    lua.globals().arg_path = os.path.join(ROOT, "prosody", "mod_otrv4plus_moderation.lua")
    lines = lua.execute(harness).splitlines()
    assert len(lines) >= 26
    assert [l for l in lines if not l.startswith("ok ")] == []


def test_the_installer_installs_and_enables_it():
    """One list names the modules and one loop installs what is in it; the
    module is in the list and is added to modules_enabled. (That it really
    lands in the modules directory is tests/test_server_limits_installer.py
    and, on a real Prosody, tests/test_real_prosody.py.)

    This test read for the old script's literal `install` line and went
    stale when the script was rewritten. Nothing said so: CI had no `lupa`,
    so this whole file was skipped there."""
    with open(os.path.join(ROOT, "prosody", "install-server-limits.sh")) as fh:
        script = fh.read()
    modules = script[script.index('\nMODULES="'):].split('"')[1].split()
    assert "mod_otrv4plus_moderation.lua" in modules
    assert 'install -m 644 "$HERE/$module" "$MODDIR/"' in script
    assert "add_module otrv4plus_moderation" in script


def test_ci_can_run_this_file():
    """`lupa` is what runs the server modules in-process. Without it this
    file, the capacity module's and the installer's Lua check all skip."""
    with open(os.path.join(ROOT, ".github", "workflows", "python.yml")) as fh:
        workflow = fh.read()
    install = workflow[workflow.index("- name: Install what the suite imports"):
                       workflow.index("- name: Show what is actually installed")]
    assert " lupa" in install.split("pip install")[-1]


def test_the_installer_arms_xmpp_guard_maintenance_mode():
    with open(os.path.join(ROOT, "prosody", "install-server-limits.sh")) as fh:
        script = fh.read()
    arm = script.index('touch "$GUARD_STATE/maintenance"')
    assert arm < script.index('cp -a "$CFG" "$BACKUP"')


def test_capacity_refusals_reach_xmpp_guard():
    with open(os.path.join(ROOT, "prosody", "mod_otrv4plus_capacity.lua")) as fh:
        mod = fh.read()
    assert mod.count('module:fire_event("user-limits/refused"') == 2
    assert 'what = "online"' in mod and 'what = "registration"' in mod
