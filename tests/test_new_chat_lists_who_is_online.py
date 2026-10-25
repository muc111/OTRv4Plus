# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""New chat lists who is online (owner, 2026-10-25).

"When we click on it we should be given a list of users who are online to
start a new otrv4+ chat with instead of manually typing names in." The
button opened an "Add a contact" box that took an address and only added it.
These pin the wiring; NewChatTest runs the rules (who is listed, the typed
address).
"""
import io
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UI = os.path.join(ROOT, "android", "app", "src", "main", "java", "org", "otrv4plus", "android", "ui")


def _screen():
    with io.open(os.path.join(UI, "ConversationsScreen.kt"), encoding="utf-8") as fh:
        return fh.read()


def _dialog(src):
    start = src.index("private fun NewChatDialog(")
    return src[start:src.index("\n}\n", start)]


def test_new_chat_opens_the_online_list():
    src = _screen()
    assert '{ showAdd = true }) { Text("+  New chat") }' in src
    shown = src[src.index("if (showAdd) {"):]
    assert shown.index("NewChatDialog(") < shown.index("\n    }\n")
    assert "onStart = { jid -> showAdd = false; onOpen(jid) }" in shown
    assert "AddContactDialog" not in src


def test_the_list_is_the_one_directory_fresh_when_opened():
    d = _dialog(_screen())
    assert "LaunchedEffect(Unit) { model.refreshDiscovery() }" in d
    assert "NewChat.online(model.directory, query)" in d
    assert "LazyColumn(" in d and ".clickable { start(e.jid) }" in d


def test_a_tap_opens_the_chat_and_asks_a_non_contact_once():
    d = _dialog(_screen())
    start = d[d.index("fun start(jid: String)"):]
    start = start[:start.index("}") + 1]
    assert "if (!model.isContact(jid)) model.addContact(jid)" in start
    assert "onStart(jid)" in start


def test_anyone_else_by_address():
    d = _dialog(_screen())
    assert "NewChat.address(query, model.ownJid())" in d
    assert "TextButton(onClick = { start(typed) })" in d
