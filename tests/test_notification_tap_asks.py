# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Tapping the message notification asks in the app before showing anyone.

The notification names nobody. Tapping it used to bring back whatever screen
was last open, often a conversation, so the user saw messages they had not
chosen to read. Now the tap lands on the chat list and the app asks "A new
message from <name> is waiting. View it?", one sender at a time, and "Not
now" leaves the conversation closed.

The queue's rules run as a JVM test (ArrivalPromptTest.kt); these pin the
wiring around it.
"""

import io
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
JAVA = os.path.join(ROOT, "android", "app", "src", "main", "java", "org", "otrv4plus", "android")


def _read(*parts):
    with io.open(os.path.join(*parts), encoding="utf-8") as fh:
        return fh.read()


def _code_only(text):
    text = re.sub(r"/\*(?:.|\n)*?\*/", " ", text)
    return re.sub(r"//[^\n]*", "", text)


SERVICE = _code_only(_read(JAVA, "connection", "OtrConnectionService.kt"))
ACTIVITY = _code_only(_read(JAVA, "MainActivity.kt"))
PROMPT = _read(JAVA, "chat", "ArrivalPrompt.kt")
DIALOG = _read(JAVA, "ui", "ArrivalPromptDialog.kt")


def _block(text, start_marker):
    start = text.index(start_marker)
    return text[start:text.index("\n    }", start)]


def _effect(text, key):
    """The body of LaunchedEffect(key) { ... }, by brace matching."""
    start = text.index("LaunchedEffect(%s) {" % key)
    depth, i = 0, text.index("{", start)
    for j in range(i, len(text)):
        depth += {"{": 1, "}": -1}.get(text[j], 0)
        if depth == 0:
            return text[i:j + 1]
    raise AssertionError("unbalanced LaunchedEffect")


class TestTheNotificationStillNamesNobody:
    def test_the_tap_intent_carries_an_action_and_no_sender(self):
        arrival = _block(SERVICE, "private fun buildArrivalNotification(")
        assert ".setAction(MainActivity.ACTION_OPEN_ARRIVAL)" in arrival
        assert "putExtra" not in arrival
        assert "setData" not in arrival

    def test_the_sender_is_kept_in_memory_only(self):
        imports = re.findall(r"^import (\S+)", PROMPT, re.M)
        assert imports == []
        assert "SharedPreferences" not in PROMPT


class TestTheServiceRemembersWhoTheAlertWasFor:
    def test_a_posted_notification_records_its_sender(self):
        announce = _block(SERVICE, "private fun announceArrival(from: String)")
        note = announce.index("alerts.note() ?: return")
        assert announce.index("arrivals.arrived(from)") > note

    def test_sign_out_wipe_and_account_change_forget_the_senders(self):
        # Every place the arrival count is cleared, the names are too.
        assert SERVICE.count("alerts.clear()") == SERVICE.count("arrivals.clear()") == 3


class TestTheTapNeverOpensAConversation:
    def test_the_activity_counts_taps_from_new_and_first_intents(self):
        assert "override fun onNewIntent(intent: Intent)" in ACTIVITY
        assert ACTIVITY.count("== ACTION_OPEN_ARRIVAL) arrivalTaps++") == 2
        # A rotation is not a second tap.
        assert "savedInstanceState == null && intent?.action == ACTION_OPEN_ARRIVAL" in ACTIVITY

    def test_the_tap_goes_to_the_chat_list_and_asks(self):
        effect = _effect(ACTIVITY, "arrivalTaps")
        assert "screen = Screen.CONVERSATIONS" in effect
        assert "chat.closeConversation()" in effect
        assert "askAbout = connection.nextArrival()" in effect
        assert "openChat" not in effect
        assert "Screen.CONVERSATION\n" not in effect.replace("== Screen.CONVERSATION)", "")

    def test_only_view_opens_the_conversation(self):
        call = ACTIVITY[ACTIVITY.index("ArrivalPromptDialog("):]
        call = call[:call.index("\n                    )")]
        view = re.search(r"onView = \{([^}]*)\}", call).group(1)
        not_now = call[call.index("onNotNow"):]
        assert "openChat(who)" in view
        assert "openChat" not in not_now
        assert "connection.arrivalAnswered(who)" in not_now

    def test_the_prompt_waits_for_sign_in_and_a_key_change_alert(self):
        assert "who != null && screen != Screen.CONNECT && chat.fingerprintAlert == null" in ACTIVITY

    def test_opening_a_chat_any_other_way_answers_it(self):
        open_chat = ACTIVITY[ACTIVITY.index("fun openChat(jid: String) {"):]
        open_chat = open_chat[:open_chat.index("}")]
        assert "connection.arrivalAnswered(jid)" in open_chat


class TestTheDialog:
    def test_it_names_the_sender_and_offers_both_answers(self):
        assert "A new message from $name is waiting. View it?" in DIALOG
        assert 'Text("View")' in DIALOG and 'Text("Not now")' in DIALOG

    def test_dismissing_it_is_not_now(self):
        assert "onDismissRequest = onNotNow" in DIALOG
