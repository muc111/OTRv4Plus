# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""What a notification may say, and who is allowed to be interrupted.

The decision half -- when to alert, how the count behaves, when the phone may
ring -- is `InboundAlertsTest`, which EXECUTES. What is here is the part no
unit test can see:

  * the strings themselves, which are what actually appear on a lock screen;
  * that the Kotlin builds the notification from the count and from nothing
    else, so a peer's JID or a message body cannot reach it;
  * that POST_NOTIFICATIONS is asked for, which on API 33+ is the difference
    between notifications and silence;
  * that the drain loop notifies only for messages the store accepted.

The last is a security property rather than a nicety. `handle` returns whether
a NEW message was stored; notifying on anything else would let a peer who
simply resends the same stanza vibrate the phone as often as they cared to.
"""

import io
import os
import re
import xml.etree.ElementTree as ET

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAIN = os.path.join(ROOT, "android", "app", "src", "main")
JAVA = os.path.join(MAIN, "java", "org", "otrv4plus", "android")


def _read(*parts):
    with io.open(os.path.join(*parts), encoding="utf-8") as fh:
        return fh.read()


def _code_only(text):
    """Strip comments and string literals, leaving only executable Kotlin."""
    text = re.sub(r"/\*(?:.|\n)*?\*/", " ", text)
    text = re.sub(r"//[^\n]*", "", text)
    return re.sub(r'"(?:\\.|[^"\\\n])*"', '""', text)


@pytest.fixture(scope="module")
def service():
    return _read(JAVA, "connection", "OtrConnectionService.kt")


@pytest.fixture(scope="module")
def service_code(service):
    return _code_only(service)


@pytest.fixture(scope="module")
def arrival(service):
    """Just the function that builds the arrival notification."""
    start = service.index("private fun buildArrivalNotification(")
    return service[start:service.index("\n    }", start)]


@pytest.fixture(scope="module")
def strings():
    root = ET.parse(os.path.join(MAIN, "res", "values", "strings.xml")).getroot()
    return {el.get("name"): (el.text or "") for el in root.findall("string")}


# ── what the user actually sees ──────────────────────────────────────────────

class TestTheStringsSayOnlyHowMany:

    def test_the_strings_exist(self, strings):
        for name in ("message_channel_name", "message_channel_description",
                     "message_arrived_one", "message_arrived_many"):
            assert name in strings, "%s is missing" % name

    def test_the_single_case_takes_no_arguments(self, strings):
        """A format argument is the door a name would come through."""
        assert "%" not in strings["message_arrived_one"]

    def test_the_plural_case_takes_exactly_one_and_it_is_a_number(self, strings):
        text = strings["message_arrived_many"]
        args = re.findall(r"%(\d+\$)?([a-zA-Z])", text)
        assert len(args) == 1, "more than one value reaches the notification"
        assert args[0][1] == "d", (
            "a %s in the arrival notification is a place for a JID or a "
            "message body to be substituted in later")

    def test_no_arrival_string_names_a_sender(self, strings):
        """The two strings that are rendered AS the notification.

        Not the channel name and description, which appear in Android's own
        settings rather than in the shade -- and whose whole job is to promise
        in words that this notification will not say who it is from. Banning
        the word "from" there would ban stating the guarantee. Their leak
        vector is a format argument, and that is checked below.
        """
        for name in ("message_arrived_one", "message_arrived_many"):
            lowered = strings[name].lower()
            for word in ("from", "@", "says", "sender", ":"):
                assert word not in lowered, (
                    "%s could name who messaged: %r" % (name, strings[name]))

    def test_the_channel_text_is_fixed(self, strings):
        for name in ("message_channel_name", "message_channel_description"):
            assert "%" not in strings[name], (
                "%s takes a format argument, so it can be given a name" % name)


# ── the notification the service builds ──────────────────────────────────────

class TestTheNotificationCarriesNothingElse:

    def test_the_text_comes_from_the_count_and_nothing_else(self, arrival):
        code = _code_only(arrival)
        # The only value interpolated is the alert's count.
        assert "alert.count" in code
        for forbidden in ("peer", "jid", "body", "displayName", "conversation"):
            assert forbidden not in code, (
                "%s reaches the arrival notification" % forbidden)

    def test_it_takes_an_alert_and_not_an_event(self, service_code):
        """An Alert has one integer field. A signature that accepted the
        message itself would make the leak a one-line edit away."""
        assert "buildArrivalNotification(alert: InboundAlerts.Alert)" in \
            service_code.replace("private fun ", "")

    def test_the_title_is_the_app_name(self, arrival):
        assert "R.string.app_name" in arrival

    def test_there_is_no_expandable_style(self, arrival):
        """BigTextStyle, InboxStyle and MessagingStyle all exist to show more.
        There is no more to show."""
        for style in ("BigTextStyle", "InboxStyle", "MessagingStyle",
                      "setTicker", "setSubText"):
            assert style not in arrival

    def test_it_is_hidden_on_a_locked_screen(self, arrival):
        assert "VISIBILITY_SECRET" in arrival

    def test_a_burst_does_not_ring_repeatedly(self, arrival):
        assert "setOnlyAlertOnce" in arrival

    def test_it_can_be_dismissed(self, arrival):
        assert "setAutoCancel(true)" in arrival


class TestTheChannel:

    def test_arrivals_have_their_own_channel(self, service_code):
        assert "MESSAGE_CHANNEL_ID" in service_code, (
            "arrivals share the connection channel, so silencing the "
            "persistent connection notice also silences every message")

    def test_the_channel_is_secret_on_the_lock_screen(self, service):
        block = service[service.index("private fun createChannel("):]
        block = block[:block.index("\n    private fun ", 10)]
        assert "lockscreenVisibility = Notification.VISIBILITY_SECRET" in block

    def test_the_channel_shows_no_badge(self, service):
        block = service[service.index("MESSAGE_CHANNEL_ID,"):]
        block = block[:block.index("createNotificationChannels")]
        assert "setShowBadge(false)" in block

    def test_one_notification_id_for_every_conversation(self, service_code):
        """One per conversation would make the shade a contact list by
        cardinality, even with every name removed."""
        assert "MESSAGE_NOTIFICATION_ID" in service_code
        # No id derived from a peer.
        assert not re.search(r"NOTIFICATION_ID\s*\+", service_code)
        assert not re.search(r"hashCode\(\)[^\n]*notify", service_code)


# ── who gets interrupted ─────────────────────────────────────────────────────

class TestOnlyANewMessageNotifies:

    def test_the_drain_loop_gates_on_what_handle_returned(self, service_code):
        block = service_code[service_code.index("private fun startDraining("):]
        block = block[:block.index("private suspend fun watchUntilDropped")]
        assert "if (chat.handle(event)) announceArrival()" in block, (
            "the drain loop notifies for events the store rejected, so a "
            "peer who resends can buzz the phone at will")

    def test_handle_reports_whether_it_stored_anything(self):
        state = _code_only(_read(JAVA, "chat", "ChatState.kt"))
        assert "fun handle(event: OtrEvent): Boolean" in state

    def test_the_service_makes_no_decision_of_its_own(self, service):
        """Every rule lives in InboundAlerts, which is executed by tests. The
        service may only act on the answer."""
        block = service[service.index("private fun announceArrival("):]
        block = block[:block.index("\n    private fun cancelArrivalNotification")]
        code = _code_only(block)
        assert "alerts.note()" in code
        assert "if" not in re.sub(r"\w*[Ii]f\w+", "", code).replace(
            "notify", ""), "the service second-guesses InboundAlerts"


class TestTheServiceIsToldWhatTheUserCanSee:

    def test_the_service_accepts_a_visibility_signal(self, service_code):
        assert "fun setUiVisible(visible: Boolean)" in service_code

    def test_coming_to_the_front_takes_the_notification_down(self, service_code):
        assert "if (alerts.setUiVisible(visible)) cancelArrivalNotification()" \
            in service_code

    def test_it_comes_from_the_lifecycle_and_not_from_the_binding(self):
        """The binding is held for the ViewModel's whole life, so it stays up
        while the app is backgrounded -- which is the one state a notification
        exists for. ON_START/ON_STOP is what "the user can see this" means."""
        activity = _code_only(_read(JAVA, "MainActivity.kt"))
        assert "Lifecycle.Event.ON_START -> connection.setUiVisible(true)" in activity
        assert "Lifecycle.Event.ON_STOP -> connection.setUiVisible(false)" in activity

    def test_leaving_the_composition_counts_as_leaving(self):
        activity = _code_only(_read(JAVA, "MainActivity.kt"))
        block = activity[activity.index("DisposableEffect(lifecycle"):]
        assert "onDispose" in block
        assert block.index("connection.setUiVisible(false)",
                           block.index("onDispose")) > 0

    def test_a_rebind_re_delivers_it(self):
        """A service that has just been reconnected to knows nothing about
        what the user can see, and would notify for a message they are
        watching arrive."""
        vm = _code_only(_read(JAVA, "ConnectionViewModel.kt"))
        assert "bound?.setUiVisible(uiVisible)" in vm

    def test_the_view_model_remembers_it(self):
        vm = _code_only(_read(JAVA, "ConnectionViewModel.kt"))
        assert "private var uiVisible: Boolean = false" in vm


# ── the permission, without which none of this happens ───────────────────────

class TestThePermissionIsActuallyRequested:

    def test_it_is_declared(self):
        manifest = _read(MAIN, "AndroidManifest.xml")
        assert "android.permission.POST_NOTIFICATIONS" in manifest

    def test_it_is_asked_for_at_runtime(self):
        """Declared is not granted. On API 33+ a permission that was never
        requested is denied, and EVERY notification is dropped silently --
        including the foreground-service one, so the connection would have run
        with nothing on screen saying so."""
        activity = _code_only(_read(JAVA, "MainActivity.kt"))
        assert "ActivityResultContracts.RequestPermission()" in activity
        assert "askNotifications.launch" in activity

    def test_it_is_only_asked_for_where_it_exists(self):
        activity = _code_only(_read(JAVA, "MainActivity.kt"))
        assert "Build.VERSION_CODES.TIRAMISU" in activity

    def test_a_refusal_is_not_treated_as_an_error(self):
        """The app works without it. Nagging or blocking on a permission the
        user declined is how an app gets uninstalled."""
        activity = _read(JAVA, "MainActivity.kt")
        block = activity[activity.index("registerForActivityResult"):]
        block = block[:block.index("\n\n")]
        assert "{ }" in block, "the refusal path does something"


# ── and none of it may leak ──────────────────────────────────────────────────

class TestNothingSensitiveReachesTheShade:

    def test_the_alerts_type_has_no_android_import(self):
        """So its rules are executed by tests rather than asserted about."""
        alerts = _read(JAVA, "chat", "InboundAlerts.kt")
        assert "import android" not in alerts
        assert "import androidx" not in alerts

    def test_it_never_holds_a_peer(self):
        alerts = _code_only(_read(JAVA, "chat", "InboundAlerts.kt"))
        for forbidden in ("jid", "peer", "body", "Message"):
            assert forbidden not in alerts, (
                "InboundAlerts holds %s, which a notification could then "
                "render" % forbidden)

    def test_no_notification_in_the_service_carries_a_peer(self, service_code):
        """Both notifications, checked together: the connection one has always
        said only what the connection is doing, and the arrival one says only
        how many."""
        for block_start in ("private fun buildNotification(",
                            "private fun buildArrivalNotification("):
            start = service_code.index(block_start)
            block = service_code[start:service_code.index("\n    }", start)]
            for forbidden in ("jid", "peer", "server", "displayName"):
                assert forbidden not in block, (
                    "%s reaches a notification built in %s"
                    % (forbidden, block_start))

    def test_signing_out_takes_the_notification_with_it(self, service_code):
        """A count of unread messages left in the shade after a sign-out is a
        statement about an account that is no longer on this device."""
        block = service_code[service_code.index("ACTION_LOGOUT ->"):]
        block = block[:block.index("ACTION_START ->")]
        assert "alerts.clear()" in block
        assert "cancelArrivalNotification()" in block
