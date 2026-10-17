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
    assert len(lines) >= 18
    assert [l for l in lines if not l.startswith("ok ")] == []


def test_the_installer_installs_and_enables_it():
    with open(os.path.join(ROOT, "prosody", "install-server-limits.sh")) as fh:
        script = fh.read()
    assert 'install -m 644 "$HERE/mod_otrv4plus_moderation.lua"' in script
    assert "add_module otrv4plus_moderation" in script
