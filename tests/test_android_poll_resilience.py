# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The failure that made a live connection read as "Not connected".

Reported from a handset: the app showed the red "Not connected — messages
cannot be sent or received" banner, no messages, and an Add Contact button
that appeared to do nothing.

Three symptoms, one shape. The UI poll gathered four values from Python in a
single try, so ONE raise discarded all four; the screen then fell back to a
default `ConnectionStatus()` whose `connected` is false and announced a
disconnection it had never observed. The raise came from `security_state`,
which was the only unguarded reader in `OtrApp` and is called for every roster
entry on every poll -- so it started the moment a peer the engine was unhappy
about appeared, which is what "as soon as Alice sent a message" looked like.

These tests pin the Python half: no single peer, and no engine mood, may take
out the contact list or the inbound path.
"""

import io
import os
import re

import pytest

from android_bridge.app import OtrApp, Transport
from android_bridge.events import SecurityState

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ANDROID = os.path.join(ROOT, "android", "app", "src", "main", "java", "org",
                       "otrv4plus", "android")

ALICE = "alice@xmpp-elite.i2p"
BOB = "bob@xmpp-elite.i2p"


def _read(*parts):
    with io.open(os.path.join(*parts), encoding="utf-8") as fh:
        return fh.read()


def _code_only(text):
    text = re.sub(r"/\*(?:.|\n)*?\*/", " ", text)
    text = re.sub(r"//[^\n]*", "", text)
    return re.sub(r'"(?:\\.|[^"\\\n])*"', '""', text)


class Engine:
    """The EnhancedSessionManager surface OtrApp uses, with a fuse."""

    def __init__(self):
        self.level = 0
        self.angry_about = set()
        self.incoming = b"hello"

    def get_security_level(self, peer):
        if peer in self.angry_about:
            raise RuntimeError("no session state for %s" % peer)
        return self.level

    def get_smp_status(self, peer):
        return {"state": "IDLE", "verified": False, "failed": False}

    def get_smp_progress(self, peer):
        return (0, 4)

    def handle_incoming_message(self, peer, payload):
        return self.incoming

    def handle_outgoing_message(self, peer, body):
        return ("?OTRv4 ZW5j", True)


class FakeTransport(Transport):
    def __init__(self, entries=None):
        self.sent = []
        self.entries = entries if entries is not None else [
            {"jid": ALICE, "name": "Alice"},
            {"jid": BOB, "name": "Bob"},
        ]

    def send(self, peer, payload):
        self.sent.append((peer, payload))

    def connect(self):
        pass

    def disconnect(self):
        pass

    def roster(self):
        return self.entries


class Sink:
    def __init__(self):
        self.events = []

    def on_event(self, event):
        self.events.append(event)


@pytest.fixture
def app():
    engine, transport, sink = Engine(), FakeTransport(), Sink()
    return OtrApp(engine, transport, sink), engine, transport, sink


# ── the root cause ───────────────────────────────────────────────────────────

class TestSecurityStateFailsSafe:
    """It is called twice a second for every contact. It must not raise."""

    def test_an_engine_that_raises_does_not_propagate(self, app):
        facade, engine, _, _ = app
        engine.angry_about.add(ALICE)
        assert facade.security_state(ALICE) is SecurityState.PLAINTEXT

    def test_it_fails_to_plaintext_and_never_to_something_reassuring(self, app):
        """The direction matters more than the guard. A state we could not
        read must never be rendered as more secure than it is."""
        facade, engine, _, _ = app
        engine.level = 3                      # SMP_VERIFIED when it works
        engine.angry_about.add(ALICE)
        assert facade.security_state(ALICE) is SecurityState.PLAINTEXT

    def test_a_working_peer_is_unaffected(self, app):
        facade, engine, _, _ = app
        engine.level = 3
        assert facade.security_state(BOB) is SecurityState.SMP_VERIFIED


class TestOneBadPeerCannotEmptyTheContactList:

    def test_contacts_survives_a_raising_peer(self, app):
        facade, engine, _, _ = app
        engine.angry_about.add(ALICE)
        jids = [c.jid for c in facade.contacts()]
        assert BOB in jids, "one awkward peer emptied the whole roster"

    def test_the_awkward_peer_is_still_listed(self, app):
        """Dropping them would make a contact vanish from the list because
        the engine had an opinion about them, which is worse than showing
        them as plaintext."""
        facade, engine, _, _ = app
        engine.angry_about.add(ALICE)
        by_jid = {c.jid: c for c in facade.contacts()}
        assert ALICE in by_jid
        assert by_jid[ALICE].security is SecurityState.PLAINTEXT

    def test_contacts_never_raises_even_when_every_peer_is_bad(self, app):
        facade, engine, _, _ = app
        engine.angry_about.update({ALICE, BOB})
        assert len(facade.contacts()) == 2

    def test_a_malformed_roster_entry_is_skipped_not_fatal(self, app):
        facade, _, transport, _ = app
        transport.entries = [{"name": "no jid"}, {"jid": BOB}]
        assert [c.jid for c in facade.contacts()] == [BOB]

    def test_an_entry_that_raises_while_being_read_is_skipped(self, app):
        """The per-entry guard, exercised through something `security_state`
        cannot absorb.

        Without this the guard had no test at all: removing it left the suite
        green, because the only fault being simulated was one the inner guard
        already caught. A defence with no failing case is decoration.
        """
        facade, _, transport, _ = app

        class Hostile(dict):
            def get(self, key, *a):
                if key == "name":
                    raise RuntimeError("roster entry is malformed")
                return dict.get(self, key, *a)

        transport.entries = [Hostile(jid=ALICE), {"jid": BOB}]
        assert [c.jid for c in facade.contacts()] == [BOB]

    def test_a_transport_that_raises_gives_an_empty_list_not_an_error(self, app):
        facade, _, transport, _ = app

        def boom():
            raise OSError("stream gone")

        transport.roster = boom
        assert facade.contacts() == []


class TestInboundSurvivesTheSameFault:
    """`receive_message` samples `security_state` before the engine runs. That
    read was unguarded too, so the same fault silently swallowed the message —
    which is the "no messages shown in the app" half of the report."""

    def test_a_message_still_arrives_when_the_state_read_fails(self, app):
        facade, engine, _, sink = app
        engine.angry_about.add(ALICE)
        assert facade.receive_message(ALICE, "hello") == "hello"
        assert [type(e).__name__ for e in sink.events] == ["MessageReceived"]

    def test_the_message_is_not_labelled_secure_because_the_read_failed(self, app):
        facade, engine, _, _ = app
        engine.level = 3
        engine.angry_about.add(ALICE)
        facade.receive_message(ALICE, "hello")
        assert facade.security_state(ALICE) is SecurityState.PLAINTEXT


# ── the amplifier, in the Kotlin that reads all this ─────────────────────────

class TestThePollDoesNotGambleEverythingOnOneCall:
    """Structural, because the ViewModel needs Compose to run. The
    behavioural coverage is ChatStateTest; this pins the shape that caused
    the outage."""

    @staticmethod
    @pytest.fixture(scope="class")
    def view_model():
        return _code_only(_read(ANDROID, "chat", "ChatViewModel.kt"))

    def test_each_read_is_attempted_separately(self, view_model):
        block = view_model[view_model.index("fun gather("):]
        block = block[:block.index("\n    private fun codeOf")]
        for call in ("connectionStatus()", "contacts()", "drainEvents()",
                     "eventsDropped()"):
            assert "runCatching { core.%s }" % call in block, (
                "%s shares a try with the other reads, so its failure "
                "discards them too" % call)

    def test_a_failed_status_read_is_not_reported_as_disconnected(self, view_model):
        assert "noteLinkFailure" in view_model, (
            "a status read that failed falls back to a default "
            "ConnectionStatus, which renders as a disconnection that was "
            "never observed")

    def test_no_exception_text_reaches_the_ui(self, view_model):
        """A PyException carries the engine's own message."""
        # `Throwable.message` is a PROPERTY, so no parens. `result.message()`
        # is RosterResult's own sentence, written by us, and is allowed.
        assert re.search(r"\.message\b(?!\()", view_model) is None
        assert "simpleName" in view_model, "the code should be the TYPE only"


class TestTheUiDistinguishesUnknownFromDisconnected:

    @staticmethod
    @pytest.fixture(scope="class")
    def screen():
        return _read(ANDROID, "ui", "ConversationsScreen.kt")

    def test_the_red_banner_needs_a_successful_read(self, screen):
        code = _code_only(screen)
        assert "Link.OK && !model.connection.connected ->" in code, (
            "the disconnected banner can fire without the app having "
            "successfully read the connection state")

    def test_there_is_a_separate_wording_for_not_knowing(self, screen):
        assert "Cannot read the connection state" in screen
        assert "Checking the connection" in screen

    def test_unknown_does_not_claim_messages_cannot_be_sent(self, screen):
        """That sentence is a statement about the network. It belongs only to
        the state where the transport actually said so."""
        assert screen.count(
            "Not connected. Messages cannot be sent or received.") == 1


class TestAddingAContactReportsWhatHappened:

    def test_the_bridge_returns_the_result(self):
        core = _code_only(_read(ANDROID, "bridge", "ChaquopyOtrCore.kt"))
        assert "fun addContact(jid: String, name: String = \"\"): RosterResult" \
            in core.replace('""', '"\\"\\""') or "): RosterResult" in core, (
            "addContact discards Python's {ok, code, detail}")

    def test_the_result_type_exists_and_carries_a_code(self):
        types = _read(ANDROID, "bridge", "OtrCore.kt")
        assert "data class RosterResult(" in types
        assert "val code: String" in types

    def test_the_view_model_shows_the_answer(self):
        vm = _code_only(_read(ANDROID, "chat", "ChatViewModel.kt"))
        block = vm[vm.index("fun addContact("):]
        block = block[:block.index("fun dismissNotice")]
        assert "state.note(result.message())" in block, (
            "the outcome is computed and thrown away, which is what made the "
            "button look inert")

    def test_a_refusal_has_a_sentence(self):
        types = _read(ANDROID, "bridge", "OtrCore.kt")
        assert "Connect before changing the contact list." in types
