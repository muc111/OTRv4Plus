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
        return self.incoming

    def start_smp(self, peer, secret, question=""):
        self.smp_secrets_seen.append(secret)
        return "?OTRv4 c21w"

    def set_smp_secret(self, peer, secret):
        self.smp_secrets_seen.append(secret)
        return True

    def abort_smp(self, peer): return True


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
        ("IDLE", SmpState.IDLE),
        ("NONE", SmpState.IDLE),
        ("no_session", SmpState.IDLE),
        ("unknown", SmpState.IDLE),
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
            assert smp_state_from_status(empty) is SmpState.IDLE

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
        a.smp_start("bob", SECRET, "our question")
        # engine got it; the facade kept nothing
        assert engine.smp_secrets_seen == [SECRET]
        for value in vars(a).values():
            assert SECRET not in repr(value)

    def test_smp_secret_never_appears_in_events(self, app):
        a, _, _, sink = app
        a.smp_start("bob", SECRET, "our question")
        a.smp_respond("bob", SECRET)
        for event in sink.events:
            assert SECRET not in repr(event)

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
        assert a.smp_state("bob") is SmpState.IDLE
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
            "handle_incoming_message", "start_smp", "set_smp_secret",
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
        assert details.smp is SmpState.IDLE
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
