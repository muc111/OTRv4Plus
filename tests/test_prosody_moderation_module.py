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
    with open(os.path.join(ROOT, "prosody", "install-server-limits.sh")) as fh:
        script = fh.read()
    assert 'install -m 644 "$HERE/mod_otrv4plus_moderation.lua"' in script
    assert "add_module otrv4plus_moderation" in script


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
