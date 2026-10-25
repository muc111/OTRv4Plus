# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Group verification starts from the chat, by the group's creator.

Owner (2026-10-25): no passphrase when a group is made, in any app; the
creator starts verifying from the group's chat and sets the passphrase then;
every member is asked; every pair who typed the same one runs SMP (all pairs,
as before) and is labelled verified; files, locations, voice notes and calls
only between verified members. The engine rule is driven for real in
test_secure_groups (TestGroupVerification); these pin the apps around it.
"""
import io
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AND = os.path.join(ROOT, "android", "app", "src", "main", "java", "org", "otrv4plus", "android")
DESK = os.path.join(ROOT, "desktop", "src", "main", "kotlin", "org", "otrv4plus", "desktop")


def _read(*parts):
    with io.open(os.path.join(*parts), encoding="utf-8") as fh:
        return fh.read()


def test_no_passphrase_when_a_group_is_made():
    rooms = _read(AND, "ui", "RoomsScreen.kt")
    assert "Group passphrase (for verifying members)" not in rooms
    assert 'model.createSecure(groupName.trim(), nick.trim(), "")' in rooms
    groups = _read(ROOT, "client", "otrv4plus_groups.py")
    create = groups[groups.index("    async def _create(self, room: str)"):]
    create = create[:create.index("    async def _accept(")]
    assert "_ask_passphrase(room, creating=True)" not in create


def test_only_the_creator_is_offered_verify_group():
    ui = _read(AND, "ui", "ConversationGroupUi.kt")
    assert "verify.canStart ->" in ui
    assert "GroupText.waitingForCreator(verify.coordinator)" in ui
    pane = _read(DESK, "ui", "GroupPane.kt")
    assert "verify.startedBy.isNotEmpty() || verify.canStart" in pane
    assert "GroupText.waitingForCreator(verify.coordinator)" in pane


def test_the_bridge_says_who_starts():
    groups = _read(ROOT, "android_bridge", "connection_groups.py")
    assert '"coordinator": v.coordinator(room), "can_start": v.may_start(room)' in groups
    assert 'coordinator = entry(value, "coordinator")' in _read(AND, "bridge", "ChaquopyOtrCore.kt")
    assert 'coordinator = v.str("coordinator"), canStart = v["can_start"].flag()' in \
        _read(DESK, "engine", "DesktopCore.kt")


def test_members_are_told_and_the_label_names_what_it_unlocks():
    text = _read(AND, "chat", "GroupText.kt")
    line = text[text.index('"member_verified" ->'):text.index('"held_change"')]
    for word in ("files", "locations", "voice notes", "calls"):
        assert word in line
    assert '"only_the_creator_starts" ->' in text
    attention = _read(AND, "chat", "Attention.kt")
    assert 'event.change == "verify_started") Kind.GROUP_VERIFY' in attention


def test_the_gates_on_what_verification_unlocks_are_kept():
    files = _read(ROOT, "android_bridge", "group_files.py")
    assert 'if not all(m.get("verified") for m in others):' in files
    loc = _read(AND, "chat", "Location.kt")
    assert '"A location goes only to a group whose members are all verified."' in loc


def test_the_engine_refuses_a_start_by_anyone_else():
    v = _read(ROOT, "android_bridge", "group_verify.py")
    start = v[v.index("    def start(self, room: str"):v.index("    def status(self")]
    assert 'raise ValueError("only_the_creator_starts")' in start
    rec = v[v.index("    def _reconcile("):v.index("    def _on_epoch(")]
    assert "if (by or sender) != self.coordinator(room):" in rec
