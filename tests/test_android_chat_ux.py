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
    """Enough EnhancedSessionManager for the facade's outbound path.

    `level` is what `get_security_level` answers -- 0 is PLAINTEXT. The real
    engine is opportunistic (`handle_outgoing_message` starts a DAKE on the
    first message), which is exactly why the facade must not reach it for an
    ordinary plaintext send.
    """

    def __init__(self, payload="?OTRv4 ciphertext", should_send=True,
                 raises=False, level=0):
        self.payload = payload
        self.should_send = should_send
        self.raises = raises
        self.level = level
        self.calls = []

    def handle_outgoing_message(self, peer, body):
        self.calls.append((peer, body))
        if self.raises:
            raise RuntimeError("engine said no")
        return self.payload, self.should_send

    def get_security_level(self, peer):
        return self.level

    def get_or_create_session(self, peer, is_initiator=False):
        return object()

    def handle_incoming_message(self, peer, payload):
        return self.incoming

    incoming = None


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
    """What happens to a typed line, and when it may go in the clear.

    Four outcomes now, because there are four things that can happen and
    describing any of them with another's word is a lie to the user:

      ENCRYPTED  the engine produced ciphertext and it went
      PLAINTEXT  nobody has asked for OTR here, so it went as typed
      QUEUED     the engine is holding it until a session exists
      FAILED     it did not go and nothing is holding it
    """

    # -- plaintext before OTR (the interoperability requirement) -------------

    def test_an_ordinary_message_goes_out_as_typed(self):
        """A conversation nobody has asked to encrypt is ordinary XMPP."""
        app, _engine, transport = build()
        assert app.send_user_text(PEER, "hello") == OtrApp.SEND_PLAINTEXT
        assert transport.sent == [(PEER, "hello")]

    def test_a_plaintext_send_does_not_start_a_dake(self):
        """`handle_outgoing_message` is opportunistic: reaching it at all
        would create a session, start a handshake and queue the text, so
        typing "hello" would emit an 11 KB DAKE1 and deliver nothing."""
        app, engine, transport = build()
        app.send_user_text(PEER, "hello")
        assert engine.calls == [], "the engine was asked, and it starts a DAKE"
        assert transport.sent == [(PEER, "hello")]

    def test_several_plaintext_messages_all_go(self):
        app, _engine, transport = build()
        for word in ("one", "two", "three"):
            assert app.send_user_text(PEER, word) == OtrApp.SEND_PLAINTEXT
        assert [body for _p, body in transport.sent] == ["one", "two", "three"]

    def test_a_transport_failure_on_a_plaintext_send_reports_failed(self):
        app, _engine, transport = build()
        transport.raises = True
        assert app.send_user_text(PEER, "hello") == OtrApp.SEND_FAILED

    # -- and never once OTR is in the picture --------------------------------

    def test_starting_otr_stops_anything_going_in_the_clear(self):
        app, _engine, transport = build(should_send=False)
        app.start_session(PEER)
        assert app.send_user_text(PEER, "the secret") == OtrApp.SEND_QUEUED
        assert all("the secret" not in body for _p, body in transport.sent)

    def test_a_failed_handshake_does_not_fall_back_to_plaintext(self):
        """The downgrade this policy exists to prevent. "The session broke"
        is not consent to carry on without one."""
        app, engine, transport = build(should_send=False)
        app.start_session(PEER)
        engine.raises = True
        assert app.send_user_text(PEER, "the secret") == OtrApp.SEND_FAILED
        assert all("the secret" not in body for _p, body in transport.sent)

    def test_the_peer_starting_otr_also_stops_plaintext(self):
        """A responder must not answer a handshake with a cleartext line.
        Marked from the peer's first protocol frame, before the session
        exists -- the gap between their DAKE1 and a completed session is
        exactly where a downgrade would fit."""
        app, engine, transport = build(should_send=False)
        engine.incoming = None
        app.receive_message(PEER, "?OTRv4 NvM3G22wZ5AUSVebh8ZenAA")
        assert app.send_user_text(PEER, "the secret") == OtrApp.SEND_QUEUED
        assert all("the secret" not in body for _p, body in transport.sent)

    def test_an_established_session_is_never_downgraded(self):
        """Even with nobody having called start_session: the ENGINE says
        there is a session, and that alone forbids the clear."""
        app, _engine, transport = build(should_send=True, level=3)
        assert app.send_user_text(PEER, "the secret") == OtrApp.SEND_ENCRYPTED
        assert all("the secret" not in body for _p, body in transport.sent)

    def test_an_ordinary_body_that_looks_like_protocol_is_still_plaintext(self):
        """A user may type anything. It is where the conversation is, not what
        the body looks like, that decides."""
        app, _engine, transport = build()
        assert app.send_user_text(PEER, "?OTRv4 is a protocol") == \
            OtrApp.SEND_PLAINTEXT
        assert transport.sent == [(PEER, "?OTRv4 is a protocol")]

    # -- the encrypted path, unchanged ---------------------------------------

    def test_an_encrypted_send_reports_encrypted(self):
        app, _engine, transport = build(should_send=True, level=1)
        assert app.send_user_text(PEER, "hello") == OtrApp.SEND_ENCRYPTED
        assert transport.sent == [(PEER, "?OTRv4 ciphertext")]

    def test_no_session_yet_reports_queued_rather_than_failed(self):
        """Mid-handshake: the engine holds the text and will flush it.

        Measured as a DELTA across `send_user_text`, not as an empty list.
        `start_session` legitimately puts the OTR query on the wire, and
        counting everything the transport ever saw would confuse "the send
        was queued" with "the handshake was never requested"."""
        app, _engine, transport = build(should_send=False)
        app.start_session(PEER)
        before = list(transport.sent)
        assert app.send_user_text(PEER, "hello") == OtrApp.SEND_QUEUED
        assert transport.sent == before, "a queued message went out anyway"

    def test_queued_is_not_an_error(self):
        app, _engine, _transport = build(should_send=False)
        app.start_session(PEER)
        app.send_user_text(PEER, "hello")     # must not raise

    def test_an_engine_that_raises_reports_failed(self):
        app, _engine, transport = build(raises=True, level=1)
        assert app.send_user_text(PEER, "hello") == OtrApp.SEND_FAILED
        assert transport.sent == []

    def test_a_transport_that_raises_reports_failed(self):
        app, _engine, transport = build(level=1)
        transport.raises = True
        assert app.send_user_text(PEER, "hello") == OtrApp.SEND_FAILED

    def test_an_empty_payload_reports_failed(self):
        app, _engine, transport = build(payload=None, should_send=True, level=1)
        assert app.send_user_text(PEER, "hello") == OtrApp.SEND_FAILED
        assert transport.sent == []

    def test_bytes_from_the_engine_are_decoded(self):
        app, _engine, transport = build(payload=b"?OTRv4 bytes", level=1)
        app.send_user_text(PEER, "hello")
        assert transport.sent == [(PEER, "?OTRv4 bytes")]

    def test_without_a_transport_it_raises(self):
        app = OtrApp(FakeEngine())
        with pytest.raises(Exception):
            app.send_user_text(PEER, "hello")

    def test_send_message_still_refuses_plaintext(self):
        """The old guarantee is untouched. `send_message` is the method that
        promises ciphertext or nothing, and it still does."""
        app, _engine, _transport = build(should_send=False)
        with pytest.raises(Exception) as caught:
            app.send_message(PEER, "hello")
        assert getattr(caught.value, "code", "") == "not_encrypted"

    def test_the_four_outcomes_are_distinct(self):
        assert len({OtrApp.SEND_ENCRYPTED, OtrApp.SEND_QUEUED,
                    OtrApp.SEND_FAILED, OtrApp.SEND_PLAINTEXT}) == 4


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

    def test_attaching_twice_does_not_start_a_second_redraw_loop(self, chat_vm):
        """A recomposition can call attach, and a recreated Activity will."""
        assert "this.core === core && this.state === state" in chat_vm

    def test_the_view_model_does_not_drain_the_event_queue(self, chat_vm):
        """THE REASON BACKGROUND DELIVERY COULD NOT WORK.

        The queue is destructive -- a drain removes what it returns -- so
        whoever drains it is the only one who will ever see those events. A
        ViewModel does not exist while the UI is gone, so a message arriving
        with the app backgrounded was dropped or left unread, and no amount of
        persistence further down would have helped.

        The service drains now. Two drainers would lose every other message."""
        code = _code_only(chat_vm)
        for pulled in ("drainEvents", "contacts()", "eventsDropped",
                       "connectionStatus"):
            assert pulled not in code, (
                "ChatViewModel reads %s itself; the service does that, and "
                "two readers of a destructive queue lose messages" % pulled)

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

    def test_drafts_survive_the_screen(self, chat_vm):
        """They live in ChatState, which the SERVICE owns -- so a draft now
        survives not just a recomposition and a recreation but the Activity
        being destroyed entirely."""
        assert "state?.setDraft" in chat_vm
        assert "state?.draft" in chat_vm
        screen = _code_only(_read(ANDROID, "ui", "ConversationScreen.kt"))

        # SCOPED TO THE COMPOSER, and it did not used to be. This asserted
        # that `remember { mutableStateOf` appeared NOWHERE in the file, which
        # is the mechanism rather than the rule -- and the rule is about the
        # DRAFT. It went red when `VerificationPrompt` was added, whose
        # passphrase field is deliberately composition-local and deliberately
        # not in the ViewModel: a secret held there would outlive the dialog.
        # A guard that forbids the correct handling of a passphrase in order
        # to protect a draft is guarding the wrong thing.
        composer = screen[screen.index("private fun Composer("):]
        assert "remember { mutableStateOf" not in composer, (
            "the composer keeps its own draft, which a recomposition loses")

    def test_only_the_passphrase_is_composition_local(self):
        """The other half of the rule above, now that it is scoped.

        Exactly one piece of state may live in this file's composition, and it
        is the SMP passphrase -- because it must not survive the dialog.
        Anything else appearing here is state that belongs in `ChatState`,
        which the service owns and which outlives the Activity.
        """
        screen = _code_only(_read(ANDROID, "ui", "ConversationScreen.kt"))
        holders = screen.count("remember { mutableStateOf")
        assert holders == 1, (
            "%d pieces of composition-local state; only the SMP passphrase "
            "may be one" % holders)
        prompt = screen[screen.index("private fun VerificationPrompt("):]
        prompt = prompt[:prompt.index("AlertDialog(")]
        assert "remember { mutableStateOf" in prompt, (
            "the one composition-local value is not the passphrase")


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
        # Via canSend(), which is `link == OK && connection.connected` -- so a
        # poll that could not read the bridge also stops claiming knowledge of
        # anyone's presence, rather than freezing the last thing it saw.
        #
        # The parameter is `linkKnown` since presence became three-state: it
        # was `known`, which read as though it were about the PEER when it has
        # always been about our own link. Both facts now reach Presence.of --
        # the peer's state and whether our link is readable -- and this is the
        # second one.
        assert "linkKnown = canSend() && contact != null" in state

    def test_the_peers_own_state_reaches_the_ui(self):
        """The presence fix. A Boolean could not say "no stanza has arrived
        for this peer yet", so a just-added contact was inferred OFFLINE and
        rendered as unknown forever."""
        state = _read(ANDROID, "chat", "ChatState.kt")
        assert "peer = contact?.presence ?: PeerPresence.UNKNOWN" in state, (
            "presence is derived from a boolean again, which cannot "
            "distinguish offline from never-heard")

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

        Both directions are asserted behaviourally in ChatStateTest.

        THE PROPERTY, NOT THE SPELLING. This pinned the exact expression
        `contacts.keys + store.conversationIds()`, which is not what it is
        protecting: the union acquired a third arm (locally saved contacts)
        and then a `bare(...)` fold on each arm so one person cannot occupy
        two rows, and neither change touched the rule. Asserted as "the
        statement that builds `jids` reads BOTH sources", so dropping either
        one still fails and a fold over them does not.
        """
        body = state[state.index("fun conversations()"):]
        union = body[body.index("val jids"):body.index("return jids")]
        assert "contacts.keys" in union, (
            "the conversation list no longer includes the roster, so a "
            "contact you have never messaged has no row to start from")
        assert "store.conversationIds()" in union, (
            "the conversation list no longer includes the message store, so "
            "a message from somebody not on the roster has nowhere to appear")

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
        # `.message` as a PROPERTY read, which is what Throwable.message is.
        # `.messages(jid)` is the history accessor and `result.message()` is
        # RosterResult's own sentence; neither is a Throwable.
        assert not re.search(r"\.message\b(?!\()", chat_vm)


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


class TestTheOtrTapReachesTheWire:
    """THE HANDSET BUG, from the Kotlin end.

    Tapping OTRv4+ did nothing: no visible change, no DAKE, nothing arriving
    at the other end. The defect was in Python -- `OtrApp.start_session`
    generated DAKE1 and never handed it to the transport, which
    `test_android_bridge` now pins directly.

    What made it INVISIBLE is on this side, and that is what these guard.
    Every layer between the tap and the bridge reported success, because
    every layer had succeeded, and the two places a failure could have been
    swallowed on the way back are the two checked here.
    """

    @staticmethod
    @pytest.fixture(scope="class")
    def chat_vm():
        return _code_only(_read(ANDROID, "chat", "ChatViewModel.kt"))

    @staticmethod
    @pytest.fixture(scope="class")
    def provider():
        return _code_only(_read(ANDROID, "crypto", "OtrV4PlusProvider.kt"))

    def test_the_tap_has_a_caller_all_the_way_down(self):
        """The chain, named link by link, because each one was once absent:
        screen -> ChatViewModel.startEncryption -> EncryptionLauncher ->
        OtrV4PlusProvider.establish -> OtrCore.startSession -> Python."""
        screen = _code_only(_read(ANDROID, "ui", "ConversationScreen.kt"))
        assert "model.startEncryption(jid)" in screen

        vm = _code_only(_read(ANDROID, "chat", "ChatViewModel.kt"))
        assert "launcher.startDefault(" in vm
        assert "core.startSession(jid)" in vm

        launcher = _code_only(_read(ANDROID, "crypto", "EncryptionLauncher.kt"))
        assert "provider.establish(conversation)" in launcher

        provider = _code_only(_read(ANDROID, "crypto", "OtrV4PlusProvider.kt"))
        assert "startSession(conversation.target)" in provider

    def test_the_view_model_has_no_discarding_start_session(self, chat_vm):
        """The removed method. It read

            withContext(Dispatchers.IO) { runCatching { core.startSession(jid) } }

        with the result dropped -- a failed handshake and a successful one
        were the same event. `start_session` now RAISES on a send that did not
        happen, so a wrapper like this would put the silence straight back."""
        assert "fun startSession(" not in chat_vm, (
            "ChatViewModel has a startSession again; the encryption path goes "
            "through startEncryption and the launcher, and a second entry "
            "point is where the discarded result came back")

    def test_the_failure_of_the_tap_is_shown_to_the_user(self, chat_vm):
        """A control that silently does nothing is the whole complaint."""
        assert "if (!outcome.ok)" in chat_vm
        assert "state.note(" in chat_vm

    def test_the_provider_reports_a_refused_start_rather_than_claiming_one(
            self, provider):
        """`establish` does not await the DAKE -- that is correct, it takes an
        I2P round trip. But it must distinguish "asked" from "could not ask",
        or a start that threw would still return ESTABLISHING."""
        assert ".onFailure {" in provider
        assert "EncryptionOutcome.failed(" in provider

    def test_nothing_on_this_path_fakes_an_established_session(self, provider):
        """ESTABLISHING is what the tap earns: a request was sent. ACTIVE and
        VERIFIED are the engine's word, and this class only ever reports them
        by reading `securityOf`."""
        started = provider.split("override suspend fun establish", 1)[1] \
            .split("override suspend fun encrypt", 1)[0]
        for claimed in ("EncryptionState.ACTIVE", "EncryptionState.VERIFIED"):
            assert claimed not in started, (
                "establish returns %s before the engine has said so" % claimed)


class TestIdentityVerificationReachesTheUser:
    """The SMP milestone, from the Kotlin end.

    The cryptography is `Rust/src/smp.rs` and is covered by
    `tests/test_smp_end_to_end.py`; the state machine is
    `otrv4plus_smpflow.py`, shared with both terminal clients. NONE of that
    changed, and nothing here re-implements any of it.

    What these guard is the part that is new and is only visible in source:
    the control appears at the right moment, the incoming prompt does not
    depend on a button, and the passphrase does not go anywhere it should not.
    """

    @staticmethod
    @pytest.fixture(scope="class")
    def screen():
        return _code_only(_read(ANDROID, "ui", "ConversationScreen.kt"))

    @staticmethod
    @pytest.fixture(scope="class")
    def screen_text():
        """With string bodies KEPT. The user-facing sentences are the subject
        of some of these, and `_code_only` blanks them."""
        return _uncommented(_read(ANDROID, "ui", "ConversationScreen.kt"))

    @staticmethod
    @pytest.fixture(scope="class")
    def rules():
        return _read(ANDROID, "crypto", "Verification.kt")

    # -- the rules are executed, not reviewed --------------------------------

    def test_the_rules_import_nothing_from_android(self, rules):
        """A `when` inside a Composable is checked by reading it. This
        environment cannot reach dl.google.com, so Compose is compiled by CI
        and never run -- which is why every decision here lives in a leaf."""
        imports = re.findall(r"^import\s+([\w.]+)", _code_only(rules), re.M)
        for line in imports:
            assert line.startswith("org.otrv4plus.") or line.startswith("kotlin."), (
                "Verification imports %s, so its rules can no longer be "
                "unit-tested without an Android build" % line)

    def test_the_rules_have_executed_tests(self):
        tests = _read(UNIT_TESTS, "crypto", "VerificationTest.kt")
        for covered in (
            "nothing is offered before OTR is established",
            "the button appears once the session is encrypted",
            "an incoming request opens a prompt with no button pressed",
            "a successful run replaces the button with the verified state",
            "a call is not offered on an encrypted but unverified session",
        ):
            assert covered in tests, (
                "the JVM test for '%s' is gone" % covered)

    # -- no second implementation --------------------------------------------

    def test_no_cryptography_is_implemented_in_kotlin(self, rules):
        """One SMP implementation, in Rust. A Kotlin one would be a second
        thing to audit and the first to drift."""
        for banned in ("MessageDigest", "Mac(", "SecretKey", "Cipher",
                       "BigInteger", "SecureRandom", "sha256", "hmac"):
            assert banned not in rules, (
                "Verification.kt contains %s; SMP is implemented in "
                "Rust/src/smp.rs and nowhere else" % banned)

    def test_the_kotlin_layer_has_no_smp_state_machine_of_its_own(self, rules):
        """The phases belong to the core. Naming them here would be a parallel
        state machine, which is what `otrv4plus_smpflow` exists to prevent."""
        for phase in ("AWAITING_MSG2", "AWAITING_MSG3", "AWAITING_MSG4",
                      "generate_smp1", "process_smp"):
            assert phase not in rules, (
                "Verification.kt names the protocol phase %s; the core owns "
                "the state machine" % phase)

    # -- when the control appears --------------------------------------------

    def test_the_control_is_drawn_from_the_rule_not_from_a_local_condition(
            self, screen):
        assert "model.verificationOffer(jid)" in screen
        assert "Verification.Offer.HIDDEN" in screen, (
            "the screen does not handle the hidden case, so it will draw a "
            "verification row on a plaintext conversation")

    def test_the_verified_state_is_not_a_button(self, screen):
        """Offering to verify an already-verified peer implies the last answer
        expired. It did not."""
        block = screen[screen.index("private fun VerificationOffer"):]
        block = block[:block.index("private fun VerificationPrompt")]
        # The CONTROL branch, not the first mention of VERIFIED -- that one is
        # in the `when` that picks the sentence, and slicing from it swept in
        # every button below.
        # `rindex`: there are TWO `when (offer)` blocks -- the first picks the
        # sentence, the second picks the control -- and anchoring on the first
        # was measuring the wrong one.
        controls = block[block.rindex("when (offer) {"):]
        assert "Verification.Offer.VERIFIED" not in controls, (
            "the verified state has a control arm; it is a statement, not a "
            "button")
        assert "else -> Unit" in controls, (
            "the verified state has no arm and no `else`, so the control "
            "block does not handle it at all")

    # -- the incoming prompt is automatic ------------------------------------

    def test_the_incoming_prompt_does_not_depend_on_a_button(self, screen):
        """THE RECEIVING REQUIREMENT. `verificationPrompt` is derived from the
        engine's own `smpSecretRequired`, so a held SMP1 opens the dialog with
        nothing pressed. A prompt gated on the tap would mean a responder had
        to guess that a request had arrived."""
        assert "model.verificationPrompt(jid)" in screen
        vm = _code_only(_read(ANDROID, "chat", "ChatViewModel.kt"))
        prompt = vm[vm.index("fun verificationPrompt("):]
        prompt = prompt[:prompt.index("fun verificationOffer(")]
        assert "core.smpSecretRequired(jid)" in prompt, (
            "the prompt is not driven by the engine's held-request state")

    def test_answering_goes_to_respond_and_not_to_start(self):
        """`smpRespond` binds the secret AND resumes the peer's held SMP1 into
        SMP2. `smpStart` would begin a second, competing run against a core
        that is already holding one."""
        vm = _code_only(_read(ANDROID, "chat", "ChatViewModel.kt"))
        submit = vm[vm.index("fun submitVerification("):]
        submit = submit[:submit.index("fun verificationOutcome(")]
        assert "core.smpRespond(jid, secret)" in submit
        assert "core.smpStart(jid, secret)" in submit
        assert "if (incoming)" in submit, (
            "one call is made for both directions; the responder path must "
            "resume the held SMP1 rather than start a new run")

    def test_dismissing_an_incoming_prompt_tells_the_engine(self):
        """The peer's SMP1 is held in the core. Closing the dialog without
        aborting would leave it held while the initiator waited."""
        vm = _code_only(_read(ANDROID, "chat", "ChatViewModel.kt"))
        dismiss = vm[vm.index("fun dismissVerification("):]
        dismiss = dismiss[:dismiss.index("fun submitVerification(")]
        assert "core.smpAbort(jid)" in dismiss

    # -- the passphrase ------------------------------------------------------

    def test_the_passphrase_field_is_masked(self, screen):
        """A passphrase prompt that shows the passphrase is not a passphrase
        prompt -- the same rule the connect screen applies to the password."""
        block = screen[screen.index("private fun VerificationPrompt"):]
        assert "PasswordVisualTransformation()" in block

    def test_the_passphrase_is_not_written_to_the_saved_state_bundle(
            self, screen):
        """`rememberSaveable` puts a value in savedInstanceState, which
        Android serialises to disk. `remember` keeps it in the composition."""
        block = screen[screen.index("private fun VerificationPrompt"):]
        field = block[:block.index("AlertDialog(")]
        assert "rememberSaveable" not in field, (
            "the passphrase would be written to the saved-state Bundle")
        assert "remember {" in field

    def test_the_passphrase_is_cleared_on_both_exits(self, screen):
        block = screen[screen.index("private fun VerificationPrompt"):]
        assert block.count('secret = ""') >= 2, (
            "the passphrase survives in the composition after submit or "
            "cancel")

    def test_the_passphrase_is_never_logged_or_put_in_a_notice(self):
        """A notice is rendered on screen and an SMP secret in one would be
        the shared secret in the user's own scrollback -- the thing the
        terminal client's hidden read exists to avoid."""
        vm = _uncommented(_read(ANDROID, "chat", "ChatViewModel.kt"))
        submit = vm[vm.index("fun submitVerification("):]
        submit = submit[:submit.index("fun verificationOutcome(")]
        for line in submit.splitlines():
            if "secret" not in line:
                continue
            for leak in ("Log.", "println", "state.note(", "$secret"):
                assert leak not in line, (
                    "the passphrase reaches %s: %s" % (leak, line.strip()))

    def test_the_passphrase_is_not_held_on_the_view_model(self):
        """`verifyRequested` is a JID. A field holding the secret would
        outlive the dialog and survive into the next conversation."""
        vm = _code_only(_read(ANDROID, "chat", "ChatViewModel.kt"))
        for banned in ("private var verifySecret", "var smpSecret",
                       "private var secret"):
            assert banned not in vm, (
                "%s keeps a passphrase on the ViewModel" % banned)

    # -- what the user is told -----------------------------------------------

    def test_both_prompts_say_the_passphrase_was_agreed_out_of_band(
            self, rules):
        """A passphrase invented on the spot verifies nothing. The security of
        SMP is entirely in the secret having been agreed over a channel an
        attacker does not control."""
        explanation = rules[rules.index("fun explanation("):]
        explanation = explanation[:explanation.index("fun outcome(")]
        assert explanation.count("another channel") == 2, (
            "one of the two prompts does not name an out-of-band channel")

    def test_encrypted_and_verified_are_not_shown_as_the_same_thing(
            self, screen_text):
        """The distinction SMP exists for. A conversation that is encrypted
        and unverified must not read as verified."""
        block = screen_text[screen_text.index("private fun VerificationOffer"):]
        block = block[:block.index("private fun VerificationPrompt")]
        assert "Identity Verified" in block
        assert "have not checked who is on the other end" in block

    # -- voice stays gated ---------------------------------------------------

    def test_voice_is_still_gated_on_verification(self, rules):
        """The existing rule, restated rather than relaxed. `callOffered` only
        decides whether a button is drawn -- the gate itself is
        `VoiceCallManager._smp_verified` in the engine -- and it draws nothing
        until SMP has passed."""
        gate = rules[rules.index("fun callOffered("):]
        assert "SecurityState.SMP_VERIFIED" in gate
        assert "SmpState.VERIFIED" in gate
        assert "ENCRYPTED" not in gate.split("\n")[1], (
            "an encrypted but unverified session would be offered a call")
