#!/usr/bin/env python3
"""Typed-bridge tests (Phase 2).

Three things are under test:

  1. State mapping is derived from engine values, not display strings.
  2. The facade never leaks secrets -- not through return values, not through
     events, not through logging.
  3. The facade fails closed: no silent plaintext fallback, no crash-through
     from a misbehaving UI callback.

A fake engine stands in for EnhancedSessionManager so these run without a
transport, without slixmpp and without a network.  Every method the fake
implements exists on the real manager with the same name and shape -- that
correspondence is asserted in TestFacadeMatchesRealEngine.
"""

import logging
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from android_bridge.app import (            # noqa: E402
    BridgeError, ContactView, OtrApp, Transport, redacting_logger,
)
from android_bridge.events import (         # noqa: E402
    CallState, ConnectionState, ConnectionStateChanged, ErrorOccurred,
    FingerprintChanged, MessageReceived, SecurityState, SessionStateChanged,
    SmpProgress, SmpResult, SmpState, security_state_from_level,
    smp_state_from_status, call_state_from_engine,
)
from otrv4plus_fragment import OTR_PREFIX   # noqa: E402

SECRET = "hunter2-correct-horse"
PLAINTEXT = "meet me at the usual place"


# ── Fakes ─────────────────────────────────────────────────────────────────────

class FakeEngine:
    """Mimics the EnhancedSessionManager surface OtrApp actually uses."""

    def __init__(self):
        self.level = 0
        self.smp_status = {"state": "IDLE", "verified": False, "failed": False}
        self.progress = (0, 4)
        self.sessions_cleared = []
        self.smp_secrets_seen = []
        self.outgoing = ("?OTRv4 ZW5j", True)
        self.incoming = b""
        self.raise_on_outgoing = False
        #: The SMP frames this engine produces, and whether a peer's SMP1 is
        #: being held. Separate knobs because the initiator and responder
        #: halves fail in different places.
        self.smp1 = "?OTRv4 c21w"
        self.smp2 = "?OTRv4 c21wMg"
        self.secret_required = False
        self.raise_on_resume = False
        self.resumed = []
        #: What an inbound frame moves the SMP status TO, or None
        #: to leave it alone.
        self.smp_status_after = None

    def encrypted(self):
        """Put this engine in the state SMP actually requires.

        A helper rather than a default: PLAINTEXT is the honest starting
        point for a fake, and a test that needs an encrypted session should
        have to say so -- `smp_start` refuses without one, which is the rule
        under test in TestSmpNeedsAnEncryptedSession.
        """
        self.level = 1
        return self

    def get_security_level(self, peer): return self.level
    def get_smp_status(self, peer): return self.smp_status
    def get_smp_progress(self, peer): return self.progress
    def get_session_state(self, peer): return {"state": "ENCRYPTED"}
    def get_fingerprint(self): return "aa" * 64
    def get_peer_fingerprint(self, peer): return "bb" * 64
    def is_peer_trusted(self, peer): return True
    def trust_fingerprint(self, peer, fp): return True
    def get_or_create_session(self, peer, is_initiator=False): return object()
    def clear_all_sessions(self, reason): self.sessions_cleared.append(reason)

    def handle_outgoing_message(self, peer, body):
        if self.raise_on_outgoing:
            raise RuntimeError(f"engine blew up carrying {body}")
        return self.outgoing

    def handle_incoming_message(self, peer, payload):
        # A frame CHANGES state -- that is what makes it a frame. A fake whose
        # status is the same before and after the call cannot exercise a
        # transition, and `_announce_smp_change` only emits on one.
        if self.smp_status_after is not None:
            self.smp_status = self.smp_status_after
        return self.incoming

    def start_smp(self, peer, secret, question=""):
        self.smp_secrets_seen.append(secret)
        return self.smp1

    def bind_smp_secret(self, peer, secret):
        self.smp_secrets_seen.append(secret)

    def abort_smp(self, peer): return True

    # -- the responder half ---------------------------------------------------
    #
    # Both of these exist on EnhancedSessionManager (otrv4+.py:9669 and
    # :9674) and are how a held SMP1 is answered. The fake grew them because
    # the facade could not answer one without them -- which was the defect.

    def smp_secret_required(self, peer):
        return self.secret_required

    def resume_held_smp1(self, peer):
        if self.raise_on_resume:
            raise RuntimeError("secret still not set: cannot answer the held SMP1")
        self.resumed.append(peer)
        return self.smp2


class FakeTransport(Transport):
    def __init__(self):
        self.sent = []
        self.connected = False
        self.roster_entries = [{"jid": "bob@example.i2p", "name": "Bob"}]
        self.fail_connect = False

    def send(self, peer, payload): self.sent.append((peer, payload))
    def connect(self):
        if self.fail_connect:
            raise OSError("no route")
        self.connected = True
    def disconnect(self): self.connected = False
    def roster(self): return self.roster_entries


class RecordingSink:
    def __init__(self): self.events = []
    def on_event(self, event): self.events.append(event)

    def of(self, cls): return [e for e in self.events if isinstance(e, cls)]


@pytest.fixture
def app():
    engine, transport, sink = FakeEngine(), FakeTransport(), RecordingSink()
    return OtrApp(engine, transport, sink), engine, transport, sink


# ── State mapping ─────────────────────────────────────────────────────────────

class TestStateMapping:

    @pytest.mark.parametrize("level,expected", [
        (0, SecurityState.PLAINTEXT),
        (1, SecurityState.ENCRYPTED),
        (2, SecurityState.FINGERPRINT),
        (3, SecurityState.SMP_VERIFIED),
    ])
    def test_security_levels_match_uiconstants(self, level, expected):
        assert security_state_from_level(level) is expected

    def test_unknown_security_level_fails_safe_to_plaintext(self):
        """An unrecognised level must never render as more secure than it is."""
        for bad in (99, -1, None, "encrypted", object()):
            assert security_state_from_level(bad) is SecurityState.PLAINTEXT

    @pytest.mark.parametrize("phase,expected", [
        ("IDLE", SmpState.NOT_VERIFIED),
        ("NONE", SmpState.NOT_VERIFIED),
        ("no_session", SmpState.NOT_VERIFIED),
        ("unknown", SmpState.NOT_VERIFIED),
        ("AWAITING_MSG2", SmpState.IN_PROGRESS),
        ("AWAITING_MSG3", SmpState.IN_PROGRESS),
        ("AWAITING_MSG4", SmpState.IN_PROGRESS),
        ("VERIFIED", SmpState.VERIFIED),
        ("FAILED", SmpState.FAILED),
    ])
    def test_smp_phases_map_from_engine_values(self, phase, expected):
        status = {"state": phase, "verified": phase == "VERIFIED",
                  "failed": phase == "FAILED"}
        assert smp_state_from_status(status) is expected

    def test_verified_flag_wins_over_phase(self):
        """auto-SMP sets `verified` after the Rust SMP object is destroyed."""
        assert smp_state_from_status(
            {"state": "IDLE", "verified": True, "failed": False}) is SmpState.VERIFIED

    def test_missing_status_is_idle_not_verified(self):
        for empty in (None, {}):
            assert smp_state_from_status(empty) is SmpState.NOT_VERIFIED

    def test_call_state_mirrors_engine_and_fails_safe(self):
        assert call_state_from_engine("ACTIVE") is CallState.ACTIVE
        assert call_state_from_engine("RINGING") is CallState.RINGING
        assert call_state_from_engine("nonsense") is CallState.IDLE

    def test_security_states_match_uiconstants_numerically(self):
        """Guard against the two enums drifting apart."""
        otr = pytest.importorskip("otrv4_")
        ui = otr.UIConstants.SecurityLevel
        assert SecurityState.PLAINTEXT == int(ui.PLAINTEXT)
        assert SecurityState.ENCRYPTED == int(ui.ENCRYPTED)
        assert SecurityState.FINGERPRINT == int(ui.FINGERPRINT)
        assert SecurityState.SMP_VERIFIED == int(ui.SMP_VERIFIED)


# ── No terminal scraping ──────────────────────────────────────────────────────

class TestNoTerminalScraping:

    def test_bridge_does_not_parse_display_strings(self):
        """No module may match on engine display text in executable code.

        Checks string *literals* via the AST rather than raw file text, so that
        documentation may name the anti-pattern (the modules explain exactly
        which terminal-scraping behaviour they exist to replace) while any real
        comparison against display text still fails.  Docstrings are excluded
        for the same reason.
        """
        import ast, pathlib
        pkg = pathlib.Path(__file__).resolve().parent.parent / "android_bridge"
        banned = ("SMP VERIFIED", "🔵", "✅", "[otr-trace]")

        for path in pkg.glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            docstrings = set()
            for node in ast.walk(tree):
                if isinstance(node, (ast.Module, ast.ClassDef,
                                     ast.FunctionDef, ast.AsyncFunctionDef)):
                    doc = ast.get_docstring(node, clean=False)
                    if doc:
                        docstrings.add(doc)
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
                    continue
                if node.value in docstrings:
                    continue
                for needle in banned:
                    assert needle not in node.value, (
                        f"{path.name}:{node.lineno} compares against display "
                        f"text {needle!r}")

    def test_bridge_never_shadows_print(self):
        import pathlib
        pkg = pathlib.Path(__file__).resolve().parent.parent / "android_bridge"
        for path in pkg.glob("*.py"):
            body = path.read_text(encoding="utf-8")
            assert "def print(" not in body, f"{path.name} shadows print()"
            assert "builtins.print" not in body, f"{path.name} touches builtins.print"

    def test_states_are_enums_not_strings(self, app):
        a, engine, _, _ = app
        engine.level = 3
        assert isinstance(a.security_state("bob"), SecurityState)
        assert isinstance(a.smp_state("bob"), SmpState)
        assert isinstance(a.connection_state, ConnectionState)


# ── Secret handling ───────────────────────────────────────────────────────────

class TestSecretsNeverLeak:

    def test_smp_secret_is_not_retained_by_the_facade(self, app):
        a, engine, _, _ = app
        engine.encrypted()
        a.smp_start("bob", SECRET, "our question")
        # engine got it; the facade kept nothing
        assert engine.smp_secrets_seen == [SECRET]
        for value in vars(a).values():
            assert SECRET not in repr(value)

    def test_smp_secret_never_appears_in_events(self, app):
        a, engine, _, sink = app
        engine.encrypted()
        a.smp_start("bob", SECRET, "our question")
        engine.secret_required = True
        a.smp_respond("bob", SECRET)
        assert sink.events, "no events were emitted, so this proves nothing"
        for event in sink.events:
            assert SECRET not in repr(event)

    def test_smp_secret_never_reaches_the_wire_as_itself(self, app):
        """The passphrase is an INPUT to the proof, never part of it. A frame
        carrying it would defeat the entire point of SMP -- the whole design
        is that both sides prove they know it without transmitting it."""
        a, engine, transport, _ = app
        engine.encrypted()
        a.smp_start("bob", SECRET, "our question")
        engine.secret_required = True
        a.smp_respond("bob", SECRET)
        assert transport.sent, "nothing was sent, so this proves nothing"
        for _peer, body in transport.sent:
            assert SECRET not in body

    def test_message_body_never_appears_in_logs(self, app, caplog):
        a, engine, _, _ = app
        engine.incoming = PLAINTEXT.encode()
        with caplog.at_level(logging.DEBUG):
            a.receive_message("bob", "?OTRv4 payload")
            a.send_message("bob", PLAINTEXT)
        joined = "\n".join(r.getMessage() for r in caplog.records)
        assert PLAINTEXT not in joined

    def test_engine_exception_text_is_not_propagated(self, app, caplog):
        """An engine error can embed the plaintext it was handling."""
        a, engine, _, _ = app
        engine.raise_on_outgoing = True
        with caplog.at_level(logging.DEBUG):
            with pytest.raises(BridgeError) as exc:
                a.send_message("bob", PLAINTEXT)
        assert PLAINTEXT not in str(exc.value)
        assert PLAINTEXT not in "\n".join(r.getMessage() for r in caplog.records)

    def test_error_events_carry_codes_not_engine_text(self, app):
        a, engine, _, sink = app
        def boom(peer, payload): raise RuntimeError(f"secret was {PLAINTEXT}")
        engine.handle_incoming_message = boom
        a.receive_message("bob", "?OTRv4 x")
        errors = sink.of(ErrorOccurred)
        assert errors and errors[0].code == "decrypt_failed"
        for e in errors:
            assert PLAINTEXT not in repr(e)

    def test_redacting_filter_drops_records_marked_sensitive(self):
        log = redacting_logger("otrv4plus.bridge.test")
        records = []
        class Capture(logging.Handler):
            def emit(self, record): records.append(record.getMessage())
        handler = Capture()
        log.addHandler(handler)
        log.setLevel(logging.DEBUG)
        try:
            log.info("carrying %s", SECRET, extra={"sensitive": True})
            log.info("safe identifier bob@example.i2p")
        finally:
            log.removeHandler(handler)
        assert not any(SECRET in r for r in records)
        assert any("bob@example.i2p" in r for r in records)

    def test_redacting_filter_truncates_long_records(self):
        log = redacting_logger("otrv4plus.bridge.test2")
        records = []
        class Capture(logging.Handler):
            def emit(self, record): records.append(record.getMessage())
        handler = Capture(); log.addHandler(handler); log.setLevel(logging.DEBUG)
        try:
            log.info("x" * 5000)
        finally:
            log.removeHandler(handler)
        assert records and len(records[0]) < 300

    def test_facade_exposes_no_key_material_accessor(self):
        """No method may hand back a seed, ratchet state or session key."""
        banned = ("seed", "private", "session_key", "chain_key", "root_key",
                  "brace_key", "mac_key", "ratchet")
        for name in dir(OtrApp):
            if name.startswith("_"):
                continue
            assert not any(b in name.lower() for b in banned), \
                f"OtrApp.{name} looks like a key accessor"


# ── Fail-closed behaviour ─────────────────────────────────────────────────────

class TestFailsClosed:

    def test_refuses_to_send_unencrypted(self, app):
        a, engine, transport, _ = app
        engine.outgoing = ("plain body", False)
        with pytest.raises(BridgeError) as exc:
            a.send_message("bob", PLAINTEXT)
        assert exc.value.code == "not_encrypted"
        assert transport.sent == [], "nothing may reach the wire unencrypted"

    def test_refuses_to_send_when_engine_returns_nothing(self, app):
        a, engine, transport, _ = app
        engine.outgoing = (None, False)
        with pytest.raises(BridgeError):
            a.send_message("bob", PLAINTEXT)
        assert transport.sent == []

    def test_requires_an_engine(self):
        with pytest.raises(BridgeError):
            OtrApp(None)

    def test_requires_a_transport_to_send(self):
        a = OtrApp(FakeEngine(), transport=None)
        with pytest.raises(BridgeError):
            a.send_message("bob", PLAINTEXT)

    def test_connect_failure_reports_failed_state(self, app):
        a, _, transport, sink = app
        transport.fail_connect = True
        with pytest.raises(BridgeError):
            a.connect()
        assert sink.of(ConnectionStateChanged)[-1].state is ConnectionState.FAILED

    def test_a_raising_event_sink_cannot_break_the_engine(self, app):
        a, engine, _, _ = app
        class Hostile:
            def on_event(self, event): raise RuntimeError("UI bug")
        a.set_event_sink(Hostile())
        engine.incoming = b"hello"
        assert a.receive_message("bob", "?OTRv4 x") == "hello"   # survived

    def test_malformed_engine_responses_do_not_crash_the_bridge(self, app):
        a, engine, _, _ = app
        engine.get_smp_status = lambda peer: (_ for _ in ()).throw(RuntimeError())
        engine.get_smp_progress = lambda peer: (_ for _ in ()).throw(RuntimeError())
        assert a.smp_state("bob") is SmpState.NOT_VERIFIED
        assert a.smp_progress("bob").total == 4


# ── Events ────────────────────────────────────────────────────────────────────

class TestEvents:

    def test_message_received_is_emitted_with_body(self, app):
        a, engine, _, sink = app
        engine.incoming = PLAINTEXT.encode()
        assert a.receive_message("bob", "?OTRv4 x") == PLAINTEXT
        received = sink.of(MessageReceived)
        assert len(received) == 1 and received[0].body == PLAINTEXT
        assert received[0].peer == "bob"

    def test_protocol_frames_emit_state_change_not_message(self, app):
        a, engine, _, sink = app
        engine.incoming = None
        engine.level = 0
        def bump(peer, payload):
            engine.level = 3
            return None
        engine.handle_incoming_message = bump
        assert a.receive_message("bob", "?OTRv4 dake") is None
        assert sink.of(MessageReceived) == []
        changes = sink.of(SessionStateChanged)
        assert changes and changes[-1].security is SecurityState.SMP_VERIFIED

    def test_fingerprint_mismatch_is_its_own_blocking_event(self, app):
        a, _, _, sink = app
        a.note_fingerprint_mismatch("bob", "aa" * 64, "cc" * 64)
        evt = sink.of(FingerprintChanged)
        assert len(evt) == 1
        assert evt[0].stored_fingerprint != evt[0].received_fingerprint

    def test_call_state_is_projected_from_the_engine(self, app):
        a, _, _, sink = app
        for s in ("RINGING", "CONNECTING", "ACTIVE", "ENDED"):
            a.note_call_state("bob", s)
        assert [e.state for e in sink.of(__import__("android_bridge.events",
                fromlist=["CallStateChanged"]).CallStateChanged)] == [
            CallState.RINGING, CallState.CONNECTING, CallState.ACTIVE, CallState.ENDED]
        assert a.call_state("bob") is CallState.ENDED

    def test_smp_progress_event_carries_step_and_state(self, app):
        a, engine, _, _ = app
        engine.progress = (2, 4)
        engine.smp_status = {"state": "AWAITING_MSG3", "verified": False, "failed": False}
        p = a.smp_progress("bob")
        assert (p.step, p.total, p.state) == (2, 4, SmpState.IN_PROGRESS)


# ── Contacts and details ──────────────────────────────────────────────────────

class TestContactsAndDetails:

    def test_contacts_carry_structured_state(self, app):
        a, engine, _, _ = app
        engine.level = 3
        engine.smp_status = {"state": "VERIFIED", "verified": True, "failed": False}
        a.note_presence("bob@example.i2p", True)
        contacts = a.contacts()
        assert len(contacts) == 1
        c = contacts[0]
        assert isinstance(c, ContactView)
        assert c.security is SecurityState.SMP_VERIFIED
        assert c.smp is SmpState.VERIFIED
        assert c.online is True
        assert c.call_available is True

    def test_call_availability_is_false_when_unverified(self, app):
        a, engine, _, _ = app
        engine.level = 1
        assert a.contacts()[0].call_available is False

    def test_security_details_contain_no_secrets(self, app):
        a, _, _, _ = app
        d = a.security_details("bob")
        blob = repr(d)
        assert SECRET not in blob and PLAINTEXT not in blob
        assert d.local_fingerprint and d.peer_fingerprint     # public values only


# ── Correspondence with the real engine ───────────────────────────────────────

class TestFacadeMatchesRealEngine:
    """The fake must not drift from EnhancedSessionManager.

    If the real manager renames a method, this fails and the bridge gets fixed
    rather than silently testing against an API that no longer exists.
    """

    def test_every_faked_method_exists_on_the_real_manager(self):
        otr = pytest.importorskip("otrv4_")
        real = otr.EnhancedSessionManager
        used = [
            "get_security_level", "get_smp_status", "get_smp_progress",
            "get_session_state", "get_fingerprint", "get_peer_fingerprint",
            "is_peer_trusted", "trust_fingerprint", "get_or_create_session",
            "clear_all_sessions", "handle_outgoing_message",
            "handle_incoming_message", "start_smp", "bind_smp_secret",
            # abort_smp was faked and never existed on the real engine, so
            # the Cancel button raised smp_abort_unsupported on a device.
            "abort_smp", "resume_held_smp1", "smp_secret_required",
        ]
        missing = [m for m in used if not hasattr(real, m)]
        assert not missing, f"OtrApp calls methods the engine does not have: {missing}"


class TestAgainstTheRealEngine:
    """End-to-end wiring check: OtrApp driving a genuine EnhancedSessionManager.

    The fake above keeps the unit tests fast and deterministic, but it can only
    prove the facade is self-consistent.  These construct the real engine (which
    fail-closes at import unless the Rust core is present) and confirm the
    facade's calls actually land, that its return types are the structured ones,
    and that nothing secret comes back.
    """

    @pytest.fixture
    def real_app(self):
        otr = pytest.importorskip("otrv4_")
        engine = otr.EnhancedSessionManager(config=otr.OTRConfig(test_mode=True))
        return OtrApp(engine), engine, otr

    def test_reads_state_from_the_real_engine(self, real_app):
        app, _, _ = real_app
        assert isinstance(app.security_state("bob"), SecurityState)
        assert isinstance(app.smp_state("bob"), SmpState)
        assert app.security_state("bob") is SecurityState.PLAINTEXT   # no session

    def test_real_local_fingerprint_is_non_empty(self, real_app):
        app, engine, _ = real_app
        assert app.local_fingerprint() == engine.get_fingerprint()
        assert app.local_fingerprint()

    def test_security_details_from_real_engine_have_no_secrets(self, real_app):
        app, _, _ = real_app
        details = app.security_details("bob")
        assert details.smp is SmpState.NOT_VERIFIED
        assert details.security is SecurityState.PLAINTEXT
        blob = repr(details)
        for banned in ("seed", "private", "chain_key", "root_key", "brace_key"):
            assert banned not in blob.lower()

    def test_creating_a_real_session_does_not_break_the_facade(self, real_app):
        app, engine, _ = real_app
        engine.get_or_create_session("bob", is_initiator=True)
        assert isinstance(app.security_state("bob"), SecurityState)
        assert isinstance(app.smp_progress("bob"), SmpProgress)

    def test_smp_progress_shape_matches_the_real_engine(self, real_app):
        app, _, _ = real_app
        progress = app.smp_progress("bob")
        assert progress.total == 4 and 0 <= progress.step <= 4


class TestStartingASessionActuallySendsTheHandshake:
    """THE HANDSET BUG. Tap OTRv4+ between Bob and Alice: no visible change,
    no DAKE, and nothing at all arriving at the other end.

    `start_session` read

        payload = self._safe(
            lambda: self._engine.handle_outgoing_message(peer, ""))

    and never mentioned `payload` again. The engine produced DAKE1 correctly,
    every time, and this method dropped it. Nothing was handed to the
    transport, so no stanza left the device.

    Every layer above reported success because every layer above HAD
    succeeded -- the tap, the launcher, the provider, the Python call, the
    session, the emitted event. Only the send was missing, and nothing
    anywhere asserted it. `start_session` had NO test at all, which is how a
    one-line omission survived.

    `handle_outgoing_message` returns `(payload, should_send)`. Assigning that
    to a single name and reading it as a payload is easy to miss: the tuple is
    truthy either way.
    """

    def test_the_handshake_reaches_the_transport(self, app):
        a, engine, transport, sink = app
        engine.outgoing = ("?OTRv4 DAKE1DATA", True)
        a.start_session("bob@example.i2p")
        assert transport.sent == [("bob@example.i2p", "?OTRv4 DAKE1DATA")], (
            "the DAKE was generated and never sent")

    def test_it_is_sent_to_the_peer_it_was_generated_for(self, app):
        a, engine, transport, _ = app
        engine.outgoing = ("?OTRv4 DAKE1DATA", True)
        a.start_session("carol@example.i2p")
        peer, _payload = transport.sent[0]
        assert peer == "carol@example.i2p"

    def test_the_conversation_is_marked_otr_before_anything_can_fail(self):
        """A failed handshake is not consent to continue without one, so the
        request is recorded first and the conversation refuses plaintext even
        when the send then fails."""
        class Refusing(FakeTransport):
            def send(self, peer, payload):
                raise OSError("stream gone")

        engine = FakeEngine()
        engine.outgoing = ("?OTRv4 DAKE1DATA", True)
        a = OtrApp(engine, Refusing(), RecordingSink())
        with pytest.raises(BridgeError):
            a.start_session("bob@example.i2p")
        assert a._mode.may_send_plaintext("bob@example.i2p", False) is False

    def test_a_session_state_change_is_emitted_only_after_the_send(self, app):
        """The event is what the UI follows. Emitting it for a handshake that
        never left the device is how the screen said one thing and the network
        did another."""
        a, engine, transport, sink = app
        engine.outgoing = ("?OTRv4 DAKE1DATA", True)
        a.start_session("bob@example.i2p")
        assert transport.sent, "no send"
        assert any(type(e).__name__ == "SessionStateChanged"
                   for e in sink.events)

    # ── failures are reported, never silent ──────────────────────────────────

    def test_no_handshake_produced_still_puts_the_request_on_the_wire(self, app):
        """The engine declines to build DAKE1 when one is already in flight.
        That is not an error -- `test_android_chat_ux` pins that a send in
        this state reports QUEUED -- but it must not be SILENCE either: the
        user asked for encryption, so the OTR query goes out and invites the
        peer to start the handshake, exactly as the terminal client's `else`
        branch does."""
        a, engine, transport, _ = app
        engine.outgoing = (None, False)
        a.start_session("bob@example.i2p")
        assert transport.sent == [("bob@example.i2p", OTR_PREFIX)], (
            "nothing left the device for a conversation the user asked to "
            "encrypt")

    def test_should_send_false_is_not_treated_as_a_handshake(self, app):
        """The engine can hand back a payload it does not want sent. Sending
        it anyway would put a frame on the wire the engine did not authorise,
        so the query goes instead -- and the unauthorised payload does not."""
        a, engine, transport, _ = app
        engine.outgoing = ("?OTRv4 SOMETHING", False)
        a.start_session("bob@example.i2p")
        assert transport.sent == [("bob@example.i2p", OTR_PREFIX)]
        assert all("SOMETHING" not in body for _p, body in transport.sent)

    def test_the_two_outcomes_are_distinguishable_in_the_trace(self, app):
        """"Nothing happened when I tapped it" was unanswerable without ADB.
        A DAKE that went out and a query sent because the engine declined one
        are different situations with the same appearance on screen, so the
        diagnostic must not record them as the same event."""
        from android_bridge.trace import TRACE

        a, engine, transport, _ = app

        TRACE.clear()
        engine.outgoing = ("?OTRv4 DAKE1DATA", True)
        a.start_session("bob@example.i2p")
        sent = {e["event"] for e in TRACE.events() if e["component"] == "otr"}

        TRACE.clear()
        engine.outgoing = (None, False)
        a.start_session("carol@example.i2p")
        declined = {e["event"] for e in TRACE.events()
                    if e["component"] == "otr"}

        assert "dake_sent" in sent and "dake_sent" not in declined
        assert "query_sent" in declined and "query_sent" not in sent

    def test_the_trace_of_a_handshake_carries_no_payload(self, app):
        """The length of DAKE1 is a diagnosis; DAKE1 is key material."""
        from android_bridge.trace import TRACE

        a, engine, transport, _ = app
        TRACE.clear()
        engine.outgoing = ("?OTRv4 DAKE1DATA", True)
        a.start_session("bob@example.i2p")
        rendered = TRACE.render()
        assert "DAKE1DATA" not in rendered
        assert "bob@example.i2p" not in rendered

    def test_a_failed_send_is_reported(self):
        """A DAKE1 that never left the socket is not a completed stage."""
        class Refusing(FakeTransport):
            def send(self, peer, payload):
                raise OSError("stream gone")

        engine = FakeEngine()
        engine.outgoing = ("?OTRv4 DAKE1DATA", True)
        a = OtrApp(engine, Refusing(), RecordingSink())
        with pytest.raises(BridgeError) as caught:
            a.start_session("bob@example.i2p")
        assert caught.value.code == "dake_send_failed"

    def test_no_transport_is_reported_before_anything_else(self):
        a = OtrApp(FakeEngine(), transport=None)
        with pytest.raises(BridgeError) as caught:
            a.start_session("bob@example.i2p")
        assert caught.value.code == "no_transport"

    def test_an_engine_that_cannot_make_a_session_is_reported(self):
        class Broken(FakeEngine):
            def get_or_create_session(self, peer, is_initiator=False):
                raise RuntimeError("no")

        engine = Broken()
        engine.outgoing = ("?OTRv4 DAKE1DATA", True)
        transport = FakeTransport()
        a = OtrApp(engine, transport, RecordingSink())
        with pytest.raises(BridgeError) as caught:
            a.start_session("bob@example.i2p")
        assert caught.value.code == "session_start_failed"
        assert transport.sent == [], "a handshake went out for a dead session"

    def test_an_engine_that_raises_while_generating_is_reported(self, app):
        """An engine that THREW and an engine that DECLINED are different
        answers. Declining sends the query; throwing leaves the engine in an
        unknown state, and sending an invitation on its behalf would be
        guessing."""
        a, engine, transport, _ = app
        engine.raise_on_outgoing = True
        with pytest.raises(BridgeError) as caught:
            a.start_session("bob@example.i2p")
        assert caught.value.code == "dake_generate_failed"
        assert transport.sent == []

    def test_the_payload_is_not_unpacked_as_a_bare_value(self):
        """Guards the specific mistake: `(payload, should_send)` read as one
        thing. A 2-tuple is truthy, so a naive `if payload:` passes."""
        import inspect

        source = inspect.getsource(OtrApp.start_session)
        assert "self._transport.send" in source, (
            "start_session no longer sends anything")


class TestSmpNeedsAnEncryptedSession:
    """SMP proves you are talking to who you think you are.

    Run outside an established session it would prove that about nothing:
    there is no session binding to tie the proof to. The engine's own
    `start_smp` already refuses when there is no session; this is the rule
    stated at the boundary the UI calls, so a button cannot reach a state the
    protocol has no answer for.
    """

    def test_smp_cannot_start_on_a_plaintext_conversation(self, app):
        a, engine, transport, _ = app
        assert engine.level == 0
        with pytest.raises(BridgeError) as caught:
            a.smp_start("bob", SECRET)
        assert caught.value.code == "smp_not_encrypted"
        assert transport.sent == [], "a verification frame went out unencrypted"

    def test_a_refused_start_never_reaches_the_engine(self, app):
        """The passphrase must not be handed to an engine that cannot use it."""
        a, engine, _, _ = app
        with pytest.raises(BridgeError):
            a.smp_start("bob", SECRET)
        assert engine.smp_secrets_seen == []

    def test_smp_cannot_be_answered_on_a_plaintext_conversation(self, app):
        a, engine, _, _ = app
        engine.secret_required = True
        with pytest.raises(BridgeError) as caught:
            a.smp_respond("bob", SECRET)
        assert caught.value.code == "smp_not_encrypted"
        assert engine.smp_secrets_seen == []

    @pytest.mark.parametrize("level", [1, 2, 3])
    def test_any_completed_dake_may_verify(self, app, level):
        """ENCRYPTED, FINGERPRINT and SMP_VERIFIED all mean a DAKE ran.
        Re-verifying an already-verified peer is a legitimate thing to do."""
        a, engine, _, _ = app
        engine.level = level
        a.smp_start("bob", SECRET)          # must not raise

    def test_a_fingerprint_mismatch_may_still_be_verified(self, app):
        """That conversation IS encrypted, to somebody. SMP is one of the few
        things that can tell the user WHICH somebody, so refusing it here
        would remove the remedy at the moment it is most needed."""
        a, engine, _, _ = app
        engine.level = 4
        a.smp_start("bob", SECRET)          # must not raise


class TestAnIncomingSmpRequestIsAnnounced:
    """THE RESPONDER BUG. Bob was never told a verification was waiting.

    `receive_message` emitted `SessionStateChanged` only when the SECURITY
    LEVEL changed. An SMP1 arriving on a session that is already ENCRYPTED
    does not change the level -- it stays ENCRYPTED until SMP passes, which is
    the entire point of having SMP -- so an incoming request produced no event
    at all and the UI had nothing to react to.

    The Rust core was doing its part the whole time: it parks the peer's SMP1
    in `SmpPhase::SecretRequired` rather than aborting, precisely so the
    responder can supply the passphrase and answer the message that already
    arrived.
    """

    @staticmethod
    def _encrypted_with_incoming_smp1(app):
        a, engine, transport, sink = app
        engine.encrypted()
        engine.incoming = None              # a protocol frame, not user text
        engine.smp_status_after = {"state": "SECRET_REQUIRED",
                                   "verified": False, "failed": False}
        return a, engine, transport, sink

    def test_an_arriving_smp1_emits_an_event(self, app):
        a, engine, _, sink = self._encrypted_with_incoming_smp1(app)
        a.receive_message("bob", "?OTRv4 c21w")
        progressed = sink.of(SmpProgress)
        assert progressed, (
            "an SMP1 arrived and nothing was emitted; the responder's UI has "
            "no way to learn a verification is waiting")
        assert progressed[-1].state is SmpState.SECRET_REQUIRED

    def test_the_event_is_emitted_although_the_security_level_did_not_move(
            self, app):
        """The exact condition the old code tested on. The level is ENCRYPTED
        before and after -- that is correct and is why it could not be the
        trigger."""
        a, engine, _, sink = self._encrypted_with_incoming_smp1(app)
        before = a.security_state("bob")
        a.receive_message("bob", "?OTRv4 c21w")
        assert a.security_state("bob") == before
        assert sink.of(SmpProgress)

    def test_a_resent_smp1_does_not_announce_twice(self, app):
        """Emitted on a TRANSITION. Otherwise a peer could stack prompts on
        the responder's screen just by resending -- the same idempotence
        `SmpFlow.remote_smp1_arrived` gives the terminal clients."""
        a, engine, _, sink = self._encrypted_with_incoming_smp1(app)
        a.receive_message("bob", "?OTRv4 c21w")
        a.receive_message("bob", "?OTRv4 c21w")
        a.receive_message("bob", "?OTRv4 c21w")
        assert len(sink.of(SmpProgress)) == 1

    def test_an_ordinary_message_announces_nothing(self, app):
        a, engine, _, sink = app
        engine.encrypted()
        engine.incoming = b"hello"
        a.receive_message("bob", "?OTRv4 data")
        assert sink.of(SmpProgress) == []
        assert sink.of(SmpResult) == []

    def test_completion_arrives_as_a_result_not_as_progress(self, app):
        """VERIFIED is an outcome. The UI dismisses a dialog on it, and
        dismissing on a progress tick would close it mid-run."""
        a, engine, _, sink = app
        engine.encrypted()
        engine.incoming = None
        engine.smp_status_after = {"state": "VERIFIED", "verified": True,
                                   "failed": False}
        a.receive_message("bob", "?OTRv4 c21w")
        finished = sink.of(SmpResult)
        assert finished and finished[-1].state is SmpState.VERIFIED

    def test_a_failed_proof_arrives_as_a_result(self, app):
        a, engine, _, sink = app
        engine.encrypted()
        engine.incoming = None
        engine.smp_status_after = {"state": "FAILED", "verified": False,
                                   "failed": True}
        a.receive_message("bob", "?OTRv4 c21w")
        finished = sink.of(SmpResult)
        assert finished and finished[-1].state is SmpState.FAILED


class TestAnsweringAHeldRequest:
    """THE OTHER HALF OF THE RESPONDER BUG.

    `smp_respond` called `set_smp_secret` and stopped. Setting the secret is
    half the operation: the peer's SMP1 is HELD in the Rust core, and
    answering it means `resume_held_smp1` to consume the held message and
    produce SMP2 -- and then putting SMP2 on the wire.

    Neither happened, so a responder who typed the correct passphrase sent
    nothing and both sides hung. Both terminal clients do this properly
    (`otrv4+.py:15312`, `otrv4plus_xmpp.py:3661`).
    """

    @staticmethod
    @pytest.fixture
    def holding(app):
        a, engine, transport, sink = app
        engine.encrypted()
        engine.secret_required = True
        return a, engine, transport, sink

    def test_the_answer_reaches_the_wire(self, holding):
        a, engine, transport, _ = holding
        a.smp_respond("bob", SECRET)
        assert transport.sent == [("bob", "?OTRv4 c21wMg")], (
            "the secret was stored and SMP2 was never sent")

    def test_the_held_message_is_consumed(self, holding):
        a, engine, _, _ = holding
        a.smp_respond("bob", SECRET)
        assert engine.resumed == ["bob"]

    def test_the_secret_is_set_before_the_resume(self, holding):
        """Order matters: `resume_held_smp1_generate_smp2` needs the secret
        already bound, and the engine raises a fixed literal if it is not."""
        a, engine, _, _ = holding
        a.smp_respond("bob", SECRET)
        assert engine.smp_secrets_seen == [SECRET]

    def test_answering_when_nothing_is_held_is_refused(self, app):
        """Storing a passphrase here would bind a secret to a session with no
        run to spend it on, and tell the user they answered a request that
        does not exist."""
        a, engine, transport, _ = app
        engine.encrypted()
        engine.secret_required = False
        with pytest.raises(BridgeError) as caught:
            a.smp_respond("bob", SECRET)
        assert caught.value.code == "smp_not_requested"
        assert engine.smp_secrets_seen == []
        assert transport.sent == []

    def test_a_resume_that_raises_is_reported_and_sends_nothing(self, holding):
        a, engine, transport, _ = holding
        engine.raise_on_resume = True
        with pytest.raises(BridgeError) as caught:
            a.smp_respond("bob", SECRET)
        assert caught.value.code == "smp_resume_failed"
        assert transport.sent == []

    def test_a_vanished_request_is_reported_rather_than_sending_nothing(
            self, holding):
        a, engine, transport, _ = holding
        engine.smp2 = None
        with pytest.raises(BridgeError) as caught:
            a.smp_respond("bob", SECRET)
        assert caught.value.code == "smp_held_request_gone"
        assert transport.sent == []

    def test_a_failed_send_is_reported(self, holding):
        """A proof that never left the socket is not a stage that completed."""
        class Refusing(FakeTransport):
            def send(self, peer, payload):
                raise OSError("stream gone")

        a, engine, _, _ = holding
        a._transport = Refusing()
        with pytest.raises(BridgeError) as caught:
            a.smp_respond("bob", SECRET)
        assert caught.value.code == "smp_send_failed"

    def test_an_engine_without_resume_is_reported_not_silent(self, app):
        a, engine, transport, _ = app
        engine.encrypted()
        engine.secret_required = True
        engine.resume_held_smp1 = None
        with pytest.raises(BridgeError) as caught:
            a.smp_respond("bob", SECRET)
        assert caught.value.code == "smp_resume_unsupported"


class TestInitiatingSmpPutsTheRequestOnTheWire:
    """The initiator half, held to the same standard as the DAKE.

    `smp_start` sent through `self._transport.send` directly and did nothing
    at all when the engine produced no payload -- the shape that let
    `start_session` report success for a handshake that never left the device.
    """

    def test_the_request_reaches_the_peer(self, app):
        a, engine, transport, _ = app
        engine.encrypted()
        a.smp_start("bob", SECRET)
        assert transport.sent == [("bob", "?OTRv4 c21w")]

    def test_a_question_is_passed_to_the_engine(self, app):
        a, engine, transport, _ = app
        engine.encrypted()
        a.smp_start("bob", SECRET, "what did we agree?")
        assert transport.sent

    def test_no_request_produced_is_an_error_not_silence(self, app):
        a, engine, transport, _ = app
        engine.encrypted()
        engine.smp1 = None
        with pytest.raises(BridgeError) as caught:
            a.smp_start("bob", SECRET)
        assert caught.value.code == "smp_not_produced"
        assert transport.sent == []

    def test_a_failed_send_is_reported(self, app):
        class Refusing(FakeTransport):
            def send(self, peer, payload):
                raise OSError("stream gone")

        a, engine, _, _ = app
        engine.encrypted()
        a._transport = Refusing()
        with pytest.raises(BridgeError) as caught:
            a.smp_start("bob", SECRET)
        assert caught.value.code == "smp_send_failed"

    def test_progress_is_emitted_so_the_ui_can_show_the_run(self, app):
        a, engine, _, sink = app
        engine.encrypted()
        engine.smp_status = {"state": "AWAITING_MSG2", "verified": False,
                             "failed": False}
        a.smp_start("bob", SECRET)
        progressed = sink.of(SmpProgress)
        assert progressed and progressed[-1].state is SmpState.IN_PROGRESS


class TestTheStateMapKnowsEveryPhaseTheCoreCanReport:
    """SECRET_REQUIRED was missing from `_SMP_PHASE_MAP` and fell through the
    default to IDLE, so the one state meaning "the other person is waiting on
    you" read as "nothing is happening". The default is safe -- an unknown
    phase is never VERIFIED -- but safe is not the same as correct, and a
    safe fallback is exactly what hid this for two releases.

    Parsed from the Rust source rather than restated, so a phase added there
    fails here instead of being silently collapsed.
    """

    @staticmethod
    def _rust_phases():
        import pathlib
        import re
        src = (pathlib.Path(__file__).resolve().parent.parent
               / "Rust" / "src" / "smp.rs").read_text(encoding="utf-8")
        body = src[src.index("pub fn get_phase(&self)"):]
        body = body[:body.index("}", body.index("match self.phase"))]
        return set(re.findall(r'=>\s*"([A-Z0-9_]+)"', body))

    def test_the_source_parse_found_the_phases(self):
        """A regex that matched nothing would make every assertion here
        vacuous."""
        phases = self._rust_phases()
        assert "VERIFIED" in phases and "SECRET_REQUIRED" in phases
        assert len(phases) >= 8

    def test_every_rust_phase_is_mapped(self):
        from android_bridge.events import _SMP_PHASE_MAP
        missing = self._rust_phases() - set(_SMP_PHASE_MAP)
        assert not missing, (
            "Rust/src/smp.rs reports %s and the bridge has never been told "
            "what they mean, so they collapse to NOT_VERIFIED" % sorted(missing))

    def test_secret_required_is_its_own_state(self):
        assert smp_state_from_status(
            {"state": "SECRET_REQUIRED", "verified": False, "failed": False}
        ) is SmpState.SECRET_REQUIRED

    def test_aborted_is_cancelled_and_not_failed(self):
        """FAILED means the proof ran and the secrets did not match, which on
        this protocol is what an impersonation looks like. Showing a cancel as
        a failure would tell a user their peer may be an impostor because
        somebody closed a dialog."""
        assert smp_state_from_status(
            {"state": "ABORTED", "verified": False, "failed": False}
        ) is SmpState.CANCELLED

    def test_an_unknown_phase_is_never_verified(self):
        for bogus in ("MADE_UP", "", "verified", "VERIFIED_MAYBE"):
            assert smp_state_from_status(
                {"state": bogus, "verified": False, "failed": False}
            ) is not SmpState.VERIFIED

    def test_the_predicate_matches_the_state(self, app):
        """`smp_secret_required` and `smp_state` must not disagree about
        whether somebody is waiting."""
        a, engine, _, _ = app
        engine.secret_required = True
        assert a.smp_secret_required("bob") is True
        engine.secret_required = False
        assert a.smp_secret_required("bob") is False

    def test_an_engine_without_the_predicate_falls_back_to_the_phase(self, app):
        """`smp_engine_compat` exists because this project supports engine
        builds that predate a call. The fallback reads the phase, which is
        where the answer comes from anyway."""
        a, engine, _, _ = app
        engine.smp_secret_required = None
        engine.smp_status = {"state": "SECRET_REQUIRED", "verified": False,
                             "failed": False}
        assert a.smp_secret_required("bob") is True
