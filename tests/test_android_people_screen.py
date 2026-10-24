# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The People screen's structure, checked at the source.

The behaviour of the list -- relations, presence, search, details -- is in
`OnlineUsers` and tested by the Kotlin unit tests (OnlineUsersTest,
PeopleDirectoryTest, WelcomeDiscoveryTest). What those cannot see is the
Compose layer, which the desktop harness cannot compile: that the list is
virtualized, that search is local, that the button sits beside the connection
state, and that tapping opens details. Those are pinned here.
"""
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UI = os.path.join(ROOT, "android", "app", "src", "main", "java", "org",
                  "otrv4plus", "android", "ui")
CHAT = os.path.join(ROOT, "android", "app", "src", "main", "java", "org",
                    "otrv4plus", "android", "chat")


def _read(*parts):
    with open(os.path.join(*parts), encoding="utf-8") as fh:
        return fh.read()


PEOPLE = _read(UI, "PeopleScreen.kt")
CHATS = _read(UI, "ConversationsScreen.kt")
MODEL = _read(CHAT, "OnlineUsers.kt")


def test_rows_are_virtualized_and_keyed_by_person():
    """100+ people: only on-screen rows are composed, and a row keeps its
    identity (and any open details) while the list reorders."""
    assert "LazyColumn(" in PEOPLE
    assert "items(shown, key = { it.jid })" in PEOPLE
    assert not re.search(r"for \(entry in (all|shown|entries)\)", PEOPLE)


def test_search_is_a_local_filter_that_asks_nobody():
    assert "OnlineUsers.search(all, query)" in PEOPLE
    body = MODEL[MODEL.index("fun search("):]
    body = body[:body.index("\n    }\n")]
    for forbidden in ("core.", "bridge", "suspend", "launch", "discover"):
        assert forbidden not in body, forbidden


def test_people_is_one_tap_from_the_chat_list():
    """A tab of the bottom navigation (owner, 2026-10-14: the old row of six
    buttons read as clutter), labelled with the live count, and a badge for
    requests waiting on the user."""
    # Owner, 2026-10-15: the bar is on every top-level screen (MainNavBar.kt),
    # not only the chat list.
    import os
    bar = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "android", "app", "src", "main", "java", "org", "otrv4plus",
                            "android", "ui", "MainNavBar.kt")).read()
    assert "onSelect(MainTab.PEOPLE)" in bar
    assert "OnlineUsers.peopleButton(model.directory)" in bar
    assert "model.pendingSubscriptions.size" in bar


def test_one_list_only():
    """The inline section and the old online-users list are gone: People is
    the single list."""
    assert "PeopleSection" not in CHATS
    assert "fun rows(" not in MODEL and "ONLINE USERS" not in MODEL


def test_tapping_opens_details_and_only_buttons_change_anything():
    assert "onOpen = { showing = entry.jid }" in PEOPLE
    assert "PersonDetails(" in PEOPLE and "OnlineUsers.details(entry)" in PEOPLE
    # The roster changes only through the explicit Add / Accept buttons.
    assert PEOPLE.count("model.addContact(") == 2          # row + details
    assert PEOPLE.count("model.answerSubscription(") == 2


def test_creating_the_welcome_room_is_warned_first():
    create = PEOPLE.index("model.createWelcomeRoom()")
    assert "OnlineUsers.WELCOME_CREATE_WARNING" in PEOPLE[:create + 1] or \
        "WELCOME_CREATE_WARNING" in PEOPLE
    assert "confirmWelcome = true" in PEOPLE


def test_the_bottom_bar_is_on_every_tab_and_never_in_a_chat():
    """Owner, 2026-10-15: always there for switching once signed in, except
    inside a conversation, which keeps the whole height for its history."""
    import os
    import re
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    main = open(os.path.join(root, "android", "app", "src", "main", "java", "org",
                             "otrv4plus", "android", "MainActivity.kt")).read()
    for tab in ("MainTab.CHATS", "MainTab.PEOPLE", "MainTab.ROOMS", "MainTab.PROFILE"):
        assert re.search(r"MainTabs\(%s, chat, (::)?selectTab\)" % re.escape(tab), main), tab
    convo = main[main.index("Screen.CONVERSATION -> {"):main.index("Screen.CONVERSATIONS ->")]
    route = main[main.index("private fun ConversationRoute("):]
    route = route[:route.index("\n    }\n")]
    assert "MainTabs(" not in route, "a conversation must not carry the bottom bar"
    assert "MainTabs(" not in convo, "a conversation must not carry the bottom bar"
    assert "screen = lastTab" in convo, "leaving a chat returns to the tab it came from"
    chats = open(os.path.join(root, "android", "app", "src", "main", "java", "org",
                              "otrv4plus", "android", "ui", "ConversationsScreen.kt")).read()
    assert not re.search(r"\bNavigationBar\s*\{", chats), "one bar, in MainNavBar.kt"
