# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The chat milestone: outbound semantics, and the shape of the UI layer.

TWO KINDS OF TEST HERE, AND THEY ARE NOT EQUALLY STRONG.

`TestSendUserText` is behavioural. It drives the real `OtrApp` against a fake
engine and a fake transport and asserts what happens, including the case that
was wrong: the engine holding text until a session exists is not a send
failure.

Everything after it is STRUCTURAL -- it parses Kotlin, because Kotlin does not
run under pytest and the JVM unit tests need Gradle, which this environment
cannot reach (dl.google.com is blocked; see .github/workflows/android.yml).
Structural assertions are weaker than running the code and are not pretended
otherwise. They exist because the faults they catch -- a Composable owning the
connection again, a padlock derived from transport state, history kept in a
composition -- each cost a device round trip to find, and each is visible in
the source.

The real behavioural coverage of the Kotlin lives in
android/app/src/test/java/org/otrv4plus/android/chat/, which CI runs.
"""

import io
import os
import re

import pytest

from android_bridge.app import OtrApp

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ANDROID = os.path.join(ROOT, "android", "app", "src", "main", "java", "org",
                       "otrv4plus", "android")
UNIT_TESTS = os.path.join(ROOT, "android", "app", "src", "test", "java", "org",
                          "otrv4plus", "android")

PEER = "bob@xmpp-elite.i2p"


def _read(*parts):
    with io.open(os.path.join(*parts), encoding="utf-8") as fh:
        return fh.read()


def _uncommented(text):
    """Kotlin with comments removed and string literals kept.

    A structural assertion must be about the code. Matching a comment means
    the test passes when someone deletes the explanation and fails when
    someone writes one -- which has already happened once on this branch.

    String bodies are kept because some of them ARE the code: the Python
    method name in `callAttr("send_user_text", ...)` is the whole seam, and a
    leak of a secret into the UI would most likely arrive as an interpolation
    inside a string.
    """
    text = re.sub(r"/\*(?:.|\n)*?\*/", " ", text)
    return re.sub(r"//[^\n]*", "", text)


def _code_only(text):
    """`_uncommented`, with string bodies blanked as well.

    For assertions about structure -- what a class extends, what it
    constructs, what it calls -- where a word inside a user-facing sentence is
    not evidence either way.
    """
    return re.sub(r'"(?:\\.|[^"\\\n])*"', '""', _uncommented(text))


# ── the outbound path ────────────────────────────────────────────────────────

class FakeEngine:
    """Enough EnhancedSessionManager for the facade's outbound path."""

    def __init__(self, payload="?OTRv4:ciphertext", should_send=True,
                 raises=False):
        self.payload = payload
        self.should_send = should_send
        self.raises = raises
        self.calls = []

    def handle_outgoing_message(self, peer, body):
        self.calls.append((peer, body))
        if self.raises:
            raise RuntimeError("engine said no")
        return self.payload, self.should_send

    def security_state(self, peer):
        return 0


class FakeTransport:
    def __init__(self, raises=False):
        self.sent = []
        self.raises = raises

    def send(self, peer, payload):
        if self.raises:
            raise OSError("socket gone")
        self.sent.append((peer, payload))

    def connect(self):
        pass

    def disconnect(self):
        pass

    def roster(self):
        return []


def build(**kw):
    engine = FakeEngine(**kw)
    transport = FakeTransport(raises=kw.pop("transport_raises", False))
    app = OtrApp(engine, transport=transport)
    return app, engine, transport


class TestSendUserText:
    """The terminal client's semantics, on Android.

    `send_message` raises `not_encrypted` when there is no session. That is the
    right GUARANTEE -- it never downgrades to plaintext -- but the wrong
    REPORT: the engine does not discard the text, it holds it and flushes it
    after the DAKE, which the terminal client shows as
    `[queued] will send once OTR with <peer> is ready`.

    So the Android side was calling a normal, recoverable, expected state a
    send failure, and telling the user to retype something already waiting.
    """

    def test_an_encrypted_send_reports_encrypted(self):
        app, _engine, transport = build(should_send=True)
        assert app.send_user_text(PEER, "hello") == OtrApp.SEND_ENCRYPTED
        assert transport.sent == [(PEER, "?OTRv4:ciphertext")]

    def test_no_session_reports_queued_rather_than_failed(self):
        app, _engine, transport = build(should_send=False)
        assert app.send_user_text(PEER, "hello") == OtrApp.SEND_QUEUED
        assert transport.sent == [], (
            "something went on the wire without a session")

    def test_queued_is_not_an_error(self):
        """It must not raise: the caller has nothing to recover from and the
        message is not lost."""
        app, _engine, _transport = build(should_send=False)
        app.send_user_text(PEER, "hello")     # must not raise

    def test_an_engine_that_raises_reports_failed(self):
        app, _engine, transport = build(raises=True)
        assert app.send_user_text(PEER, "hello") == OtrApp.SEND_FAILED
        assert transport.sent == []

    def test_a_transport_that_raises_reports_failed(self):
        """Encrypted but did not leave. Distinct from queued: nothing is
        holding it and nothing will retry."""
        app, _engine, transport = build()
        transport.raises = True
        assert app.send_user_text(PEER, "hello") == OtrApp.SEND_FAILED

    def test_an_empty_payload_reports_failed(self):
        app, _engine, transport = build(payload=None, should_send=True)
        assert app.send_user_text(PEER, "hello") == OtrApp.SEND_FAILED
        assert transport.sent == []

    def test_it_never_sends_plaintext(self):
        """The whole point. Whatever the engine says, the body itself must not
        reach the transport unless the engine produced it."""
        app, _engine, transport = build(should_send=False)
        app.send_user_text(PEER, "the secret")
        assert all("the secret" not in payload for _peer, payload in transport.sent)

    def test_bytes_from_the_engine_are_decoded(self):
        app, _engine, transport = build(payload=b"?OTRv4:bytes")
        app.send_user_text(PEER, "hello")
        assert transport.sent == [(PEER, "?OTRv4:bytes")]

    def test_without_a_transport_it_raises(self):
        app = OtrApp(FakeEngine())
        with pytest.raises(Exception):
            app.send_user_text(PEER, "hello")

    def test_send_message_still_refuses_plaintext(self):
        """The existing guarantee is untouched. `send_user_text` reports
        better; it does not relax anything."""
        app, _engine, _transport = build(should_send=False)
        with pytest.raises(Exception) as caught:
            app.send_message(PEER, "hello")
        assert getattr(caught.value, "code", "") == "not_encrypted"

    def test_the_three_outcomes_are_distinct(self):
        assert len({OtrApp.SEND_ENCRYPTED, OtrApp.SEND_QUEUED,
                    OtrApp.SEND_FAILED}) == 3


class TestTheKotlinSeamAgrees:
    """The Kotlin enum and the Python constants must name the same things."""

    def test_every_python_outcome_has_a_kotlin_branch(self):
        kotlin = _read(ANDROID, "bridge", "OtrCore.kt")
        for outcome in (OtrApp.SEND_ENCRYPTED, OtrApp.SEND_QUEUED):
            assert '"%s"' % outcome in kotlin, (
                "SendOutcome.fromName does not handle %r, so it would fall "
                "through to FAILED and a queued message would be shown as "
                "undeliverable" % outcome)

    def test_the_bridge_calls_the_new_method(self):
        # The string literal is the seam, so this one reads the strings.
        kotlin = _uncommented(_read(ANDROID, "bridge", "ChaquopyOtrCore.kt"))
        assert 'callAttr("send_user_text"' in kotlin


# ── the state model ──────────────────────────────────────────────────────────

class TestStateLivesInAViewModel:
    """A Composable is a description of what to draw, not a place to keep what
    was said. State held in one is gone the moment the composition is."""

    @staticmethod
    @pytest.fixture(scope="class")
    def chat_vm():
        return _read(ANDROID, "chat", "ChatViewModel.kt")

    def test_the_chat_state_holder_is_a_view_model(self, chat_vm):
        assert "class ChatViewModel" in chat_vm
        assert ": ViewModel()" in chat_vm

    def test_it_does_not_construct_a_core(self, chat_vm):
        """Two cores means two engines over the same identity and trust
        files. The connection's ViewModel owns the only one."""
        assert "ChaquopyOtrCore(" not in _code_only(chat_vm)

    def test_attaching_twice_does_not_start_a_second_poll(self, chat_vm):
        """A recomposition can call attach, and a recreated Activity will.
        Two loops draining one event queue lose every other message."""
        assert "if (this.core === core" in chat_vm

    def test_the_screens_hold_no_history(self):
        for name in ("ConversationScreen.kt", "ConversationsScreen.kt"):
            source = _code_only(_read(ANDROID, "ui", name))
            assert "mutableStateMapOf" not in source, (
                "%s keeps state that should be in the ViewModel" % name)
            assert "InMemoryMessageStore" not in source

    def test_the_old_screen_is_gone(self):
        """Replaced by the conversation list and the conversation. Leaving it
        would mean two chat implementations and one of them unreachable."""
        assert not os.path.exists(os.path.join(ANDROID, "ui", "ChatScreen.kt"))

    def test_drafts_live_in_the_view_model(self, chat_vm):
        """So a draft survives a recomposition, a presence update redrawing
        the screen, and Activity recreation."""
        assert "drafts" in chat_vm
        composer = _code_only(_read(ANDROID, "ui", "ConversationScreen.kt"))
        assert "remember { mutableStateOf" not in composer, (
            "the composer keeps its own draft, which a recomposition loses")


class TestNavigationCarriesNoObjects:

    @staticmethod
    @pytest.fixture(scope="class")
    def activity():
        return _code_only(_read(ANDROID, "MainActivity.kt"))

    def test_the_open_conversation_is_a_jid(self, activity):
        assert "var openJid by rememberSaveable" in activity

    def test_no_core_in_navigation_state(self, activity):
        assert "mutableStateOf<ChaquopyOtrCore?>" not in activity

    def test_screen_selection_survives_recreation(self, activity):
        assert "var screen by rememberSaveable" in activity

    def test_connect_hands_over_no_object(self):
        connect = _code_only(_read(ANDROID, "ui", "ConnectScreen.kt"))
        assert "onConnected: () -> Unit" in connect, (
            "the connect screen passes an object to the next screen; a stale "
            "or duplicated core is exactly what navigation must not carry")

    def test_both_chat_screens_take_the_model_and_a_jid(self):
        conversation = _code_only(_read(ANDROID, "ui", "ConversationScreen.kt"))
        assert "jid: String" in conversation
        assert "model: ChatViewModel" in conversation


class TestTheSecurityBoundaryHoldsInTheUi:
    """Transport connectivity is not OTR security, and the UI must not be able
    to confuse them even by accident."""

    @staticmethod
    @pytest.fixture(scope="class")
    def conversation():
        return _read(ANDROID, "ui", "ConversationScreen.kt")

    def test_the_security_line_comes_from_the_engine(self, conversation):
        assert "conversation.security" in conversation
        assert "SecurityState." in conversation

    def test_connection_state_never_sets_the_security_line(self, conversation):
        """The failure this whole file guards: a padlock because the network
        is up."""
        code = _code_only(conversation)
        line = code[code.index("fun SecurityLine"):]
        line = line[:line.index("\n}")]
        assert "connected" not in line, (
            "the security line reads connection state")

    def test_there_is_no_padlock(self, conversation):
        """A padlock is read as "safe". ENCRYPTED without verification means
        the traffic is encrypted to somebody -- the DAKE ran, nobody checked
        who answered -- and no icon distinguishes those."""
        assert "\N{LOCK}" not in conversation
        assert "Icons.Filled.Lock" not in conversation

    def test_unencrypted_is_stated_not_omitted(self, conversation):
        assert "Not encrypted" in conversation

    def test_encrypted_and_verified_do_not_read_the_same(self, conversation):
        assert "not verified" in conversation
        assert "Encrypted and verified" in conversation

    def test_an_outgoing_message_is_labelled_from_the_engines_answer(self):
        state = _read(ANDROID, "chat", "ChatState.kt")
        block = state[state.index("security = when (outcome)"):]
        block = block[:block.index("},")]
        assert "SendOutcome.ENCRYPTED -> SecurityLabel.ENCRYPTED" in block
        assert "else -> SecurityLabel.UNKNOWN" in block, (
            "an outcome other than ENCRYPTED can label a message encrypted")

    def test_inbound_labelling_asks_the_engine(self):
        models = _read(ANDROID, "chat", "ChatModels.kt")
        assert "fun forInbound(state: SecurityState)" in models

    def test_a_fingerprint_mismatch_is_not_labelled_encrypted(self):
        """Encrypted-to-somebody is true and is the wrong thing to say when
        the somebody is the open question."""
        models = _read(ANDROID, "chat", "ChatModels.kt")
        block = models[models.index("fun forInbound(state: SecurityState)"):]
        block = block[:block.index("\n        }")]
        assert "SecurityState.FINGERPRINT_MISMATCH -> UNKNOWN" in block

    def test_every_security_state_is_decided_explicitly(self):
        """No `else` branch: a state added to the engine must not inherit
        whatever the fallback happened to say, in the model or on screen."""
        for path, marker in (
            (("chat", "ChatModels.kt"), "fun forInbound(state: SecurityState)"),
            (("ui", "ConversationScreen.kt"), "fun SecurityLine("),
        ):
            code = _code_only(_read(ANDROID, *path))
            block = code[code.index(marker):]
            block = block[:block.index("\n    }")]
            assert "else ->" not in block, (
                "%s falls back instead of deciding each SecurityState" % path[-1])

    def test_a_changed_pinned_key_is_actually_shown(self):
        """The engine raising FingerprintChanged and nothing rendering it is
        a silent security failure -- which is what it was until this test."""
        activity = _code_only(_read(ANDROID, "MainActivity.kt"))
        assert "fingerprintAlert" in activity, (
            "the fingerprint warning is captured and never displayed")
        assert "FingerprintAlertDialog(" in activity

    def test_the_fingerprint_warning_cannot_be_tapped_away(self):
        dialog = _code_only(_read(ANDROID, "ui", "FingerprintAlertDialog.kt"))
        assert "dismissOnBackPress = false" in dialog
        assert "dismissOnClickOutside = false" in dialog

    def test_acknowledging_the_warning_does_not_re_pin_the_key(self):
        """Re-pinning because the user wanted the dialog gone is how a
        machine-in-the-middle gets accepted."""
        dialog = _code_only(_read(ANDROID, "ui", "FingerprintAlertDialog.kt"))
        for trusting in ("pin", "trust", "accept"):
            assert trusting not in dialog.lower(), (
                "the dialog offers to %s the new key" % trusting)


class TestTheRulesAreExecutable:
    """The reason there is so little regex below.

    Routing, presence, history, drafts and send outcomes all live in
    `ChatState`, which is plain Kotlin: no Compose, no lifecycle, no Looper.
    That is not a stylistic preference. `androidx.*` is published only to
    Google's Maven repository, which this environment cannot reach, so
    anything that imports it cannot be compiled or run here -- and logic that
    cannot be run gets checked by reading it.

    `ChatStateTest` drives those rules directly and is where the real
    assertions are. What this class guards is that they STAY runnable: if the
    rules drift back into the ViewModel they become unverifiable again, and no
    amount of source-matching here would replace them.
    """

    @staticmethod
    @pytest.fixture(scope="class")
    def state():
        return _read(ANDROID, "chat", "ChatState.kt")

    @staticmethod
    @pytest.fixture(scope="class")
    def chat_vm():
        return _uncommented(_read(ANDROID, "chat", "ChatViewModel.kt"))

    def test_the_rules_import_nothing_from_android(self, state):
        # Import lines only. The package itself is org.otrv4plus.android.chat,
        # which says nothing about what it depends on.
        imports = re.findall(r"^import\s+([\w.]+)", _code_only(state), re.M)
        for line in imports:
            assert line.startswith("org.otrv4plus.") or line.startswith("kotlin."), (
                "ChatState imports %s, so it can no longer be compiled or "
                "unit-tested without an Android build" % line)

    def test_the_view_model_keeps_no_rules_of_its_own(self, chat_vm):
        """Every one of these is a decision with a test in ChatStateTest.
        Duplicated here, the copy is the one without coverage."""
        for rule in ("store.", "Presence.of(", "SecurityLabel.forInbound(",
                     "substringBefore(", "compareByDescending",
                     "isBlank()"):
            assert rule not in chat_vm, (
                "ChatViewModel decides '%s' itself instead of delegating to "
                "ChatState, putting it beyond the reach of the JVM tests"
                % rule)

    def test_the_view_model_holds_no_history_or_drafts(self, chat_vm):
        for owned in ("mutableStateMapOf", "InMemoryMessageStore", "drafts["):
            assert owned not in chat_vm, (
                "ChatViewModel owns %s; ChatState does" % owned)

    def test_the_rules_have_executed_tests(self):
        """Named against the bypasses the brief calls out, so deleting the
        coverage for one of them is visible."""
        tests = _read(UNIT_TESTS, "chat", "ChatStateTest.kt")
        for covered in (
            # skip persistence
            "an inbound message is kept",
            "an outgoing message is kept",
            "history survives the contact leaving the roster entirely",
            # skip presence update
            "presence follows the roster",
            "presence is unknown while disconnected, not offline",
            # route everything to the active conversation
            "a message goes to its sender, not to the open conversation",
            "resources collapse onto one conversation",
            # send twice
            "a sent message appears exactly once through its whole lifecycle",
            "the draft is cleared before the send completes",
            # the security boundary
            "being connected does not make an inbound message encrypted",
            "a message keeps the label it had when it arrived",
        ):
            assert "`%s`" % covered in tests, (
                "no executed test for: %s" % covered)


class TestPresenceInTheUi:

    def test_disconnection_makes_presence_unknown(self):
        """A disconnected client knows nothing about anyone. Continuing to
        show contacts as online after our own stream dies is a stale claim.

        Behaviourally covered by ChatStateTest; kept here because it is the
        exact defect the device report described."""
        state = _read(ANDROID, "chat", "ChatState.kt")
        assert "known = connection.connected" in state

    def test_unknown_is_not_rendered_as_offline(self):
        screen = _read(ANDROID, "ui", "ConversationsScreen.kt")
        assert "presence unknown" in screen

    def test_presence_is_a_word_not_only_a_colour(self):
        """A coloured dot alone is unreadable to anyone who cannot
        distinguish the colours, and unknown/offline are genuinely different
        states that no pair of colours makes obvious."""
        screen = _read(ANDROID, "ui", "ConversationsScreen.kt")
        assert 'Presence.ONLINE -> "online"' in screen
        assert 'Presence.OFFLINE -> "offline"' in screen

    def test_a_presence_change_does_not_touch_history(self):
        state = _code_only(_read(ANDROID, "chat", "ChatState.kt"))
        block = state[state.index("fun applyRoster("):]
        block = block[:block.index("fun handle(")]
        assert "store.clear()" not in block, (
            "a roster update clears history; a contact going offline is not a "
            "reason to forget what was said")


class TestTheConversationList:

    @staticmethod
    @pytest.fixture(scope="class")
    def state():
        return _read(ANDROID, "chat", "ChatState.kt")

    def test_the_list_is_the_union_of_roster_and_history(self, state):
        """A roster entry with no history still gets a row, because you have
        to be able to start a conversation with someone you have never
        messaged; and history with no roster entry still gets a row, because a
        message from a stranger is still a message.

        Both directions are asserted behaviourally in ChatStateTest."""
        assert "contacts.keys + store.conversationIds()" in state

    def test_no_contact_is_hard_coded(self):
        for name in ("ConversationsScreen.kt", "ConversationScreen.kt"):
            source = _read(ANDROID, "ui", name)
            for planted in ("alice@", "bob@", "carol@"):
                assert planted not in source, (
                    "%s hard-codes %s" % (name, planted))
        assert "alice@" not in _read(ANDROID, "chat", "ChatViewModel.kt")

    def test_rows_carry_a_preview_and_unread(self):
        screen = _read(ANDROID, "ui", "ConversationsScreen.kt")
        assert "conversation.preview" in screen
        assert "conversation.unread" in screen
        assert "formatTimestamp(conversation.lastAt)" in screen


class TestTheComposer:

    @staticmethod
    @pytest.fixture(scope="class")
    def conversation():
        return _read(ANDROID, "ui", "ConversationScreen.kt")

    def test_it_is_pinned_to_the_bottom(self, conversation):
        assert "bottomBar = {" in conversation

    def test_the_ime_action_sends(self, conversation):
        assert "ImeAction.Send" in conversation
        assert "KeyboardActions(onSend" in conversation

    def test_the_button_sends(self, conversation):
        block = conversation[conversation.index("private fun Composer("):]
        assert "onClick = onSend" in block

    def test_blank_input_disables_the_button(self, conversation):
        assert "draft.isNotBlank()" in conversation

    def test_it_is_keyboard_safe(self, conversation):
        assert "imePadding()" in conversation

    def test_disconnection_is_stated_rather_than_silent(self, conversation):
        assert "you can type, but nothing will be sent" in conversation


class TestNothingSensitiveReachesTheUi:

    def test_no_screen_renders_a_password(self):
        for name in os.listdir(os.path.join(ANDROID, "ui")):
            if not name.endswith(".kt"):
                continue
            source = _uncommented(_read(ANDROID, "ui", name))
            # The connect screen has a password FIELD; nothing may render the
            # value anywhere else. Strings are kept, so an interpolation
            # inside one is caught rather than blanked away.
            assert "Text(password" not in source, name
            assert "$password" not in source, name

    def test_the_chat_layer_never_touches_a_password(self):
        for name in ("ChatViewModel.kt", "ChatModels.kt", "MessageStore.kt"):
            source = _uncommented(_read(ANDROID, "chat", name))
            assert "password" not in source.lower(), name

    def test_exception_messages_are_not_rendered(self):
        """An exception's text can carry what the engine was handling."""
        chat_vm = _code_only(_read(ANDROID, "chat", "ChatViewModel.kt"))
        # `.message` exactly -- `.messages(jid)` is the history accessor and
        # is not a Throwable.
        assert not re.search(r"\.message\b", chat_vm)


class TestTheStorageAbstraction:

    @staticmethod
    @pytest.fixture(scope="class")
    def store():
        # Uncommented: this class asks what the store DOES, and the header
        # comment names the very things it must not do.
        return _uncommented(_read(ANDROID, "chat", "MessageStore.kt"))

    def test_it_is_an_interface(self, store):
        assert "interface MessageStore" in store

    def test_it_knows_nothing_about_compose_or_transport(self, store):
        assert "androidx.compose" not in store
        assert "Chaquopy" not in store
        assert "XmppTransport" not in store

    def test_history_is_bounded(self, store):
        """Unbounded is a memory leak with a polite name."""
        assert "perConversationLimit" in store

    def test_no_plaintext_file_or_database_was_introduced(self, store):
        """The project's position on message bodies is that they are sealed --
        RecordType.MESSAGE exists for it -- and the key for that comes from an
        app unlock that is not built yet. Adding a plaintext store in the
        meantime would be the thing the sealed design exists to prevent."""
        for banned in ("Room", "SQLite", "openFileOutput", "FileWriter",
                       "SharedPreferences"):
            assert banned not in store, (
                "%s writes message bodies to disk unsealed" % banned)

    def test_the_sealed_category_already_exists(self):
        secure = _read(ANDROID, "security", "SecureStore.kt")
        assert 'MESSAGE("otr.message")' in secure


class TestTheJvmUnitTestsExist:
    """Structural tests are not a substitute for running the code. These name
    the suites CI actually executes."""

    def test_the_store_has_unit_tests(self):
        assert os.path.exists(
            os.path.join(UNIT_TESTS, "chat", "MessageStoreTest.kt"))

    def test_the_model_has_unit_tests(self):
        assert os.path.exists(
            os.path.join(UNIT_TESTS, "chat", "ChatModelsTest.kt"))

    def test_they_cover_de_duplication(self):
        source = _read(UNIT_TESTS, "chat", "MessageStoreTest.kt")
        assert "not appended twice" in source

    def test_they_cover_the_security_boundary(self):
        source = _read(UNIT_TESTS, "chat", "ChatModelsTest.kt")
        assert "only a real session labels a message encrypted" in source
