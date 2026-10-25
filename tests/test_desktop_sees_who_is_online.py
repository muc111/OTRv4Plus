# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The desktop asks who is online, as Android does.

Device report (2026-10-25): "Invite people online" on the desktop said nobody
was online while Android users were. ChatState builds the list from the roster,
the Welcome room's people and the server's own list -- and the desktop never
read the last two, so it showed contacts only. These pin that it does, on a
timer and when the dialog or the People tab opens.
"""
import io
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DESK = os.path.join(ROOT, "desktop", "src", "main", "kotlin", "org", "otrv4plus", "desktop")


def _read(*parts):
    with io.open(os.path.join(DESK, *parts), encoding="utf-8") as fh:
        return fh.read()


CORE = _read("engine", "DesktopCore.kt")
MODEL = _read("AppModel.kt")


def test_the_core_reads_the_welcome_room_and_the_servers_list():
    assert 'call("welcome_directory")' in CORE
    assert 'controller("discover_online_users")' in CORE
    from desktop_bridge import host
    assert "welcome_directory" in host.APP_OPS or "welcome_directory" in host.CONTROLLER_OPS
    assert "discover_online_users" in host.APP_OPS or "discover_online_users" in host.CONTROLLER_OPS


def test_the_model_feeds_both_into_the_one_directory():
    assert "chat.applyWelcome(withContext(Dispatchers.IO) { core.welcomeDirectory() })" in MODEL
    assert "if (found != null) chat.applyDiscovery(found)" in MODEL, \
        "a failed ask keeps the last answer, never 'nobody is online'"
    tick = MODEL[MODEL.index("if (tick % 10 == 3) refreshAvatars()"):]
    tick = tick[:400]
    assert "refreshWelcome()" in tick and "refreshOnline()" in tick


def test_opening_the_picker_or_people_asks_again():
    assert "model.refreshOnline(force = true)" in _read("ui", "GroupPane.kt")
    people = _read("ui", "Panes.kt")
    pane = people[people.index("fun PeoplePane("):]
    assert "LaunchedEffect(Unit) { model.refreshOnline(force = true) }" in pane
    assert "Look again" in pane
