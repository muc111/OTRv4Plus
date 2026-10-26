# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The creator is asked, wherever they are, and answers Accept / Deny / Later.

Device report (2026-10-25): "No notification came to creator of the room
where a new user asked to join". The alert rang only for a request that
arrived live, so one replayed from history (the creator was away) said
nothing; with the app open it was a tone and a banner on the Chats list
only, never seen from inside a chat. These pin the wiring on both apps;
test_group_entry_requests and test_join_request_creator_decides run the
rules (creator only, 15 minutes doubling after each Deny).
"""
import io
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
A = os.path.join(ROOT, "android", "app", "src", "main", "java", "org", "otrv4plus", "android")
D = os.path.join(ROOT, "desktop", "src", "main", "kotlin", "org", "otrv4plus", "desktop")


def _read(*parts):
    with io.open(os.path.join(*parts), encoding="utf-8") as fh:
        return fh.read()


def test_every_request_the_engine_sends_alerts():
    att = _read(A, "chat", "Attention.kt")
    assert "is OtrEvent.GroupEntryRequested -> Kind.ENTRY_REQUEST" in att
    assert "if (event.live) Kind.ENTRY_REQUEST" not in att
    service = _read(A, "connection", "OtrConnectionService.kt")
    assert "Attention.of(event)?.let { needAttention(it) }" in service


def test_the_prompt_is_on_every_screen():
    main = _read(A, "MainActivity.kt")
    assert ("EntryRequestPrompt(chat, shown = screen != Screen.CONNECT && "
            "chat.fingerprintAlert == null)") in main
    ui = _read(A, "ui", "ConversationGroupUi.kt")
    prompt = ui[ui.index("fun EntryRequestPrompt("):ui.index("internal fun EntryRequestDialog(")]
    assert "if (!shown) return" in prompt
    assert "model.entryRequests().firstOrNull()?.let { request -> EntryRequestDialog(model, request) }" in prompt


def test_the_prompt_offers_accept_deny_and_later():
    ui = _read(A, "ui", "ConversationGroupUi.kt")
    d = ui[ui.index("internal fun EntryRequestDialog("):]
    assert "model.answerEntryRequest(request.room, request.requester, true)" in d
    assert "model.answerEntryRequest(request.room, request.requester, false)" in d
    assert "model.laterEntryRequest(request.room, request.requester)" in d
    for screen in (_read(A, "ui", "ConversationsScreen.kt"), _read(D, "ui", "Panes.kt")):
        assert "GroupText.ENTRY_ACCEPT" in screen and "GroupText.ENTRY_DENY" in screen
        assert "GroupText.ENTRY_LATER" in screen
        assert 'Text("Dismiss")' not in screen.split("entryRequests()")[1][:1500]


def test_the_answer_goes_to_the_engine_which_keeps_the_count():
    vm = _read(A, "chat", "ChatViewModel.kt")
    fn = vm[vm.index("fun answerEntryRequest("):vm.index("fun laterEntryRequest(")]
    assert "c.answerEntryRequest(room, requester, invite)" in fn
    assert "GroupText.entryDenied(requester, wait)" in fn
    assert "inviteToGroup(" not in fn, "Accept goes through the creator check in the engine"
    core = _read(A, "bridge", "ChaquopyOtrCore.kt")
    assert 'call("answer_entry_request", room, requester, accept)' in core
    desk = _read(D, "engine", "DesktopCore.kt")
    assert 'controller("answer_entry_request", "room" to room, "requester" to requester, "accept" to accept)' in desk
    model = _read(D, "AppModel.kt")
    fn = model[model.index("fun answerEntryRequest("):model.index("fun laterEntryRequest(")]
    assert "core.answerEntryRequest(room, requester, invite)" in fn
    assert "GroupText.entryDenied(" in fn
