# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""A secure group's members, kept readable at 100 members.

Owner (2026-10-25): "The im group chat members view has regressed it needs
to work with many users ... these groups could have 100 users so clean
display is needed. Ensure protection from regression". It had become every
member inline under the chat, a sentence and a Remove button each (for
everyone, not just the creator), plus lines naming everyone not verified.
These pin the shape on both apps; GroupRosterTest runs the rules.
"""
import io
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ANDROID = os.path.join(ROOT, "android", "app", "src", "main", "java", "org", "otrv4plus", "android")
DESKTOP = os.path.join(ROOT, "desktop", "src", "main", "kotlin", "org", "otrv4plus", "desktop")


def _read(*parts):
    with io.open(os.path.join(*parts), encoding="utf-8") as fh:
        return fh.read()


def _fn(src, signature):
    start = src.index(signature)
    depth, i = 0, src.index("{", src.index(")", start))
    for j in range(i, len(src)):
        depth += {"{": 1, "}": -1}.get(src[j], 0)
        if depth == 0:
            return src[start:j + 1]
    raise AssertionError(signature)


PHONE = _read(ANDROID, "ui", "ConversationGroupUi.kt")
DESK = _read(DESKTOP, "ui", "GroupPane.kt")
GRADLE = _read(ROOT, "desktop", "build.gradle.kts")


class TestThePhone:
    def test_the_chat_shows_one_line_not_the_list(self):
        panel = _fn(PHONE, "internal fun SecureGroupPanel(")
        assert "GroupRoster.summary(members, verify.members)" in panel
        assert "maxLines = 1" in panel
        assert "for (m in" not in panel, "no member rows under the chat"
        assert "GroupMembersSheet(model, jid, members, verify)" in panel

    def test_the_list_is_a_lazy_sheet_with_sections_and_search(self):
        sheet = _fn(PHONE, "internal fun GroupMembersSheet(")
        assert "ModalBottomSheet(" in sheet and "LazyColumn(" in sheet
        assert "roster.sections(members, verify.members, query, verify.canStart)" in sheet
        assert "members.size >= roster.SEARCH_FROM" in sheet
        assert 'items(section.rows, key = { "m:" + it.jid })' in sheet

    def test_remove_is_the_creators_and_asks_first(self):
        sheet = _fn(PHONE, "internal fun GroupMembersSheet(")
        assert "if (row.canRemove)" in sheet
        assert "removing = listOf(row.jid)" in sheet
        assert "roster.removeConfirm(removing)" in sheet
        assert "if (verify.canStart && failed.isNotEmpty())" in sheet
        assert "model.removeFailedGroupMembers(jid)" in sheet
        # Nothing removes without the dialog.
        assert sheet.count("model.removeGroupMember(") == 1


class TestTheDesktop:
    def test_the_panel_is_a_lazy_list_in_sections(self):
        panel = _fn(DESK, "fun GroupMembersPanel(")
        assert "LazyColumn(" in panel and "ScrollColumn(" not in panel
        assert "roster.sections(members, verify.members, query, verify.canStart)" in panel
        assert "members.size >= roster.SEARCH_FROM" in panel
        assert "for (m in members)" not in panel

    def test_remove_is_the_creators_and_asks_first(self):
        panel = _fn(DESK, "fun GroupMembersPanel(")
        assert "if (row.canRemove)" in panel
        assert "roster.removeConfirm(removing)" in panel
        assert "if (verify.canStart && failed.isNotEmpty())" in panel
        assert "model.removeFailedGroupMembers(room)" in panel
        assert panel.count("model.removeGroupMember(") == 1

    def test_the_rules_are_the_phones(self):
        assert '"org/otrv4plus/android/chat/GroupRoster.kt",' in GRADLE


class TestNoLineNamesEveryone:
    def test_neither_bar_lists_who_is_not_verified(self):
        for src in (PHONE, DESK):
            assert "notYet.keys.joinToString()" not in src
            assert "GroupText.verifiedSoFar(verify.members)" in src

    def test_progress_and_finish_count_rather_than_name(self):
        text = _read(ANDROID, "chat", "GroupText.kt")
        progress = _fn(text, "fun verifyProgress(")
        assert "excluded.joinToString" not in progress
        assert '"${excluded.size} failed (wrong passphrase)"' in progress
        assert '"verify_finished" -> verifyFinished(event.room, event.detail)' in text


class TestVerifyOnce:
    def test_the_verify_button_goes_once_everyone_is_settled(self):
        for src in (PHONE, DESK):
            assert "GroupText.leftToVerify(verify.members)" in src
        text = _read(ANDROID, "chat", "GroupText.kt")
        rule = _fn(text, "fun leftToVerify(")
        assert 'it != "verified" && it != "failed"' in rule

    def test_the_apps_can_ask_the_engine_to_remove_who_failed(self):
        assert 'call("remove_failed_group_members", room)' in _read(
            ANDROID, "bridge", "ChaquopyOtrCore.kt")
        assert 'controller("remove_failed_group_members", "room" to room)' in _read(
            DESKTOP, "engine", "DesktopCore.kt")
        from desktop_bridge import host
        assert host.CONTROLLER_OPS["remove_failed_group_members"] == ("room",)
        from android_bridge.connection_groups import GroupsControlMixin
        assert callable(GroupsControlMixin.remove_failed_group_members)
