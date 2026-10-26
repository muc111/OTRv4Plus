# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The creator's Deny is kept with the group (real Rust MLS).

Owner (2026-10-25): a denied requester waits 15 minutes, then 30, 60 ...
The count lives in the group's sealed state, so restarting the app does not
reset a pest's wait; leaving or wiping the group forgets it. The rules
themselves run in test_group_entry_requests.
"""
from __future__ import annotations

import pytest

core = pytest.importorskip("otrv4_core")
if not hasattr(core, "RustMlsClient"):
    pytest.skip("this core was built without the mls feature", allow_module_level=True)

from test_secure_groups import ROOM, _group                           # noqa: E402

PEST = "pest@x.i2p"


def test_the_creator_is_the_first_member():
    w, (a, b, c) = _group(3)
    assert a.groups.coordinator(ROOM) == a.jid
    assert b.groups.coordinator(ROOM) == a.jid


def test_denials_count_up_and_survive_a_restart():
    w, (a, b) = _group(2)
    assert a.groups.entry_denial(ROOM, PEST) == (0, 0.0)
    assert a.groups.deny_entry(ROOM, PEST, 1000.0) == 1
    assert a.groups.deny_entry(ROOM, PEST, 2000.0) == 2
    a.groups._store_app_state()
    a.groups._entry_denied.clear()
    a.groups._load_app_state()
    assert a.groups.entry_denial(ROOM, PEST) == (2, 2000.0)


def test_accepting_clears_it_and_leaving_forgets_it():
    w, (a, b) = _group(2)
    a.groups.deny_entry(ROOM, PEST, 1000.0)
    a.groups.clear_entry_denial(ROOM, PEST)
    assert a.groups.entry_denial(ROOM, PEST) == (0, 0.0)
    a.groups.deny_entry(ROOM, PEST, 1000.0)
    a.groups.leave(ROOM)
    assert a.groups.entry_denial(ROOM, PEST) == (0, 0.0)
