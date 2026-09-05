"""`/otr` must be able to unstick a hung handshake.

`EnhancedSessionManager.end_session` did not exist. Three call sites in the
XMPP client had been calling it since they were written — clearing an offline
peer's session, yielding the initiator role on DAKE glare, and `/otr`
force-resetting a stuck handshake — and all three raised AttributeError into
an `except` that printed it and carried on. None of them ever tore anything
down, so the documented promise that `/otr` "can always unstick a hung
handshake" was untrue for the whole life of the feature, and stayed untrue
until a device got wedged and printed the error.

The second half was worse than the missing method: the reset's client-side
cleanup lived in the same `try`, so when the first line raised, every line
below it was skipped too. A failure in the engine left the client holding
stale state as well, and the retry could not have worked either way.
"""

import inspect
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

otr = pytest.importorskip("otrv4_")
xmpp = pytest.importorskip("otrv4plus_xmpp")


class _Session:
    def __init__(self):
        self.terminated_with = None

    def terminate(self, reason="x"):
        self.terminated_with = reason


class _AngrySession(_Session):
    """A half-built session from an interrupted DAKE."""

    def terminate(self, reason="x"):
        raise RuntimeError("half-built session cannot terminate")


def _manager():
    mgr = otr.EnhancedSessionManager.__new__(otr.EnhancedSessionManager)
    import threading
    mgr.lock = threading.RLock()
    mgr.sessions = {}
    mgr.dake_engines = {}
    mgr.logger = type("L", (), {"debug": lambda *a, **k: None})()
    mgr.tracer = type("T", (), {"trace": lambda *a, **k: None})()
    return mgr


class TestEndSessionExists:

    def test_the_manager_the_client_uses_has_it(self):
        """The whole defect in one line."""
        assert hasattr(otr.EnhancedSessionManager, "end_session"), (
            "the three call sites in the XMPP client still raise "
            "AttributeError, so /otr cannot unstick a handshake")

    def test_it_removes_the_session_not_just_terminates_it(self):
        """`terminate_session` leaves the entry in place, so the next
        get_or_create_session hands back the dead one and the handshake
        stays stuck. That is why it could not stand in for this."""
        mgr = _manager()
        session = _Session()
        mgr.sessions["bob"] = session
        assert mgr.end_session("bob") is True
        assert "bob" not in mgr.sessions, "the dead session is still findable"
        assert session.terminated_with is not None

    def test_it_removes_the_dake_engine_too(self):
        """A stuck handshake is stuck in the DAKE engine. Leaving it behind
        leaves the state that was stuck."""
        mgr = _manager()
        mgr.sessions["bob"] = _Session()
        mgr.dake_engines["bob"] = object()
        mgr.end_session("bob")
        assert "bob" not in mgr.dake_engines

    def test_it_is_idempotent(self):
        mgr = _manager()
        assert mgr.end_session("nobody") is False
        mgr.sessions["bob"] = _Session()
        assert mgr.end_session("bob") is True
        assert mgr.end_session("bob") is False

    def test_a_session_that_cannot_terminate_is_still_removed(self):
        """The reset must work on exactly the sessions that are broken.
        Raising here would put us back to the reset not working."""
        mgr = _manager()
        mgr.sessions["bob"] = _AngrySession()
        assert mgr.end_session("bob") is True
        assert "bob" not in mgr.sessions

    def test_it_touches_only_the_named_peer(self):
        mgr = _manager()
        mgr.sessions["bob"] = _Session()
        mgr.sessions["carol"] = _Session()
        mgr.dake_engines["carol"] = object()
        mgr.end_session("bob")
        assert "carol" in mgr.sessions and "carol" in mgr.dake_engines


class TestItIsATeardownNotAGoodbye:
    """All three callers want local state gone, not a wire message."""

    def test_no_disconnected_tlv_is_sent(self):
        """A stuck handshake has no encrypted session to send through, and on
        glare we are about to answer the peer's DAKE1 as responder -- saying
        we disconnected first is the opposite of what is happening."""
        src = inspect.getsource(otr.EnhancedSessionManager.end_session)
        assert "send_disconnect" not in src
        assert "_disconnect_callbacks" not in src

    def test_the_trust_database_is_not_touched(self):
        """A pinned fingerprint is long-term identity. Forgetting it on reset
        would turn every reset into a fresh trust-on-first-use decision --
        the failure mode TOFU exists to make visible."""
        src = inspect.getsource(otr.EnhancedSessionManager.end_session)
        assert "trust_db" not in src

    def test_the_graceful_path_still_announces(self):
        """SessionManager.end_session is the goodbye path and keeps its TLV;
        this is a different method for a different job."""
        src = inspect.getsource(otr.SessionManager.end_session)
        assert "send_disconnect" in src


class TestTheResetCleansUpEvenIfTheEngineFails:

    def test_client_cleanup_is_not_inside_the_engine_try(self):
        """They were one try block. When end_session raised, every line below
        it was skipped, so an engine failure also left the client holding
        stale state and the retry had no chance."""
        src = inspect.getsource(xmpp.OTRv4PlusXMPP.start_otr)
        reset = src[src.index("resetting stuck session"):]
        engine_try = reset.index("self.otr.end_session(peer)")
        discard = reset.index("self._encrypted.discard(peer)")
        between = reset[engine_try:discard]
        assert "except" in between, (
            "the client-side cleanup is still inside the engine's try, so an "
            "engine failure skips it")

    def test_every_piece_of_stale_state_is_dropped(self):
        src = inspect.getsource(xmpp.OTRv4PlusXMPP.start_otr)
        reset = src[src.index("resetting stuck session"):]
        for cleanup in ("self._encrypted.discard(peer)",
                        "self._last_dake1.pop(peer, None)",
                        "self._smp_reported",
                        "self._smp_flows.drop(peer)"):
            assert cleanup in reset, "the reset leaves behind: %s" % cleanup

    def test_the_engine_failure_is_reported_not_swallowed(self):
        """Silence would make a broken engine look like a working reset."""
        src = inspect.getsource(xmpp.OTRv4PlusXMPP.start_otr)
        assert "engine teardown failed" in src


class TestEverySiteThatCallsItStillCan:
    """Three callers, all of which were silently failing."""

    @pytest.mark.parametrize("method", ["start_otr", "_forget_otr"])
    def test_the_named_callers_exist_and_call_it(self, method):
        fn = getattr(xmpp.OTRv4PlusXMPP, method, None)
        assert fn is not None, "%s is gone; this test needs rereading" % method
        assert "end_session" in inspect.getsource(fn)

    def test_forgetting_a_peer_really_ends_the_session(self):
        """`_forget_otr` drops a peer whose session should not survive --
        an offline peer, a reset. It cleared the CLIENT's view and, because
        end_session raised, left the engine's session in place."""
        assert "end_session" in inspect.getsource(xmpp.OTRv4PlusXMPP._forget_otr)

    def test_the_glare_path_calls_it(self):
        """Yielding the initiator role means dropping our own session."""
        source = open(xmpp.__file__, encoding="utf-8").read()
        assert "glare teardown error" in source
        window = source[source.index("yielding initiator"):]
        assert "end_session" in window[:600]
