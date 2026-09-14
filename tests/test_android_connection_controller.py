"""Bringing a connection up, stage by stage, with nothing simulated.

Two things this file is really about.

**A failure must name its stage.** "Could not connect" is four different
problems with four different remedies, separated by three orders of magnitude
in how long they take to appear: a refused SAM port answers in milliseconds, a
cold tunnel can take four minutes. A user who cannot tell which one they are
looking at will restart the app during the one case where waiting was correct.

**Nothing is simulated.** The controller holds the real OtrApp and the real
XmppTransport. It is deliberately easy to write a connection screen that looks
alive by inventing a security state, and that screen is worse than no screen:
it says ENCRYPTED when nothing has been encrypted. `TestNothingIsSimulated`
asserts the controller has no opinion of its own about security.
"""

import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from android_bridge.connection import ConnectionController, SamProbe
from android_bridge.settings import ConnectionProfile
from android_bridge.transport import TransportError

JID = "alice@xmpp-elite.i2p"
SERVER = "hq4t24b7vkllfbk55e5xfocqhfi7hxprwc47zyuilbg6wgzikidq.b32.i2p"


class FakeApp:
    """Stands in for OtrApp at the two points the controller touches it."""

    def __init__(self):
        self._transport = None
        self.received = []

    def receive_message(self, peer, payload):
        self.received.append((peer, payload))


class FakeTransport:
    def __init__(self, profile, password, *, on_payload, on_state=None,
                 fail=None):
        self.profile = profile
        self.password = password
        self.on_payload = on_payload
        self.on_state = on_state
        self.fail = fail
        self.is_connected = False
        self.closed = False

    def connect(self):
        if self.fail is not None:
            raise self.fail
        if self.on_state:
            self.on_state("building_tunnels", "")
            self.on_state("connected", "")
        self.is_connected = True

    def close(self):
        self.closed = True
        self.is_connected = False


def build(*, probe=None, fail=None, profile=None):
    made = {}

    def factory(p, password, **kw):
        made["transport"] = FakeTransport(p, password, fail=fail, **kw)
        return made["transport"]

    app = FakeApp()
    ctl = ConnectionController(
        app, profile or ConnectionProfile(jid=JID, server=SERVER),
        transport_factory=factory,
        prober=lambda _p, **_kw: probe or SamProbe(True, "ok", "fine", "3.1"),
    )
    made["app"] = app
    return ctl, made


class TestTheHappyPath:

    def test_it_connects_and_says_where(self):
        ctl, made = build()
        got = ctl.connect("pw")
        assert got["ok"] and got["stage"] == "connected"
        assert SERVER in got["detail"] and JID in got["detail"]
        assert ctl.stage == "connected"

    def test_the_transport_is_given_to_otrapp(self):
        """OtrApp.send_message raises no_transport without this."""
        ctl, made = build()
        ctl.connect("pw")
        assert made["app"]._transport is made["transport"]

    def test_inbound_payloads_are_routed_to_the_engine(self):
        """Not parsed, not filtered -- handed to OtrApp.receive_message,
        which is the only thing entitled to decide what a payload is."""
        ctl, made = build()
        ctl.connect("pw")
        made["transport"].on_payload("bob@x.i2p", "?OTRv4+ frame")
        assert made["app"].received == [("bob@x.i2p", "?OTRv4+ frame")]

    def test_the_sam_version_is_reported(self):
        ctl, _ = build(probe=SamProbe(True, "ok", "fine", "3.1"))
        assert ctl.connect("pw")["sam_version"] == "3.1"

    def test_stages_are_entered_in_order(self):
        seen = []
        ctl, _ = build()
        ctl._on_state = lambda s, _srv: seen.append(s)
        ctl.connect("pw")
        assert seen[0] == "checking_router"
        assert "building_tunnels" in seen
        assert seen[-1] == "connected"


class TestAFailureNamesItsStage:
    """Four problems, four remedies, three orders of magnitude apart in how
    long they take to show up."""

    def test_no_router_fails_at_checking_router(self):
        ctl, made = build(probe=SamProbe(False, "refused", "start i2pd"))
        got = ctl.connect("pw")
        assert not got["ok"]
        assert got["stage"] == "checking_router"
        assert got["code"] == "refused"
        assert "transport" not in made, (
            "the transport was built despite no router; that is four minutes "
            "of tunnel timeout for a failure already known")

    def test_a_tunnel_that_never_builds_fails_at_connecting(self):
        ctl, _ = build(fail=TransportError("sam_unavailable", "no stream"))
        got = ctl.connect("pw")
        assert not got["ok"] and got["stage"] == "connecting"
        assert got["code"] == "sam_unavailable"

    def test_a_rejected_password_is_reported_as_auth(self):
        ctl, _ = build(fail=TransportError("auth_failed", "rejected"))
        got = ctl.connect("pw")
        assert got["code"] == "auth_failed"
        assert not got["ok"]

    def test_an_unexpected_exception_still_produces_a_result(self):
        """Every caller is Kotlin. An exception crossing Chaquopy arrives as a
        PyException whose message is all that survives -- which is exactly the
        failure that made the first handset report say only "PyException"."""
        ctl, _ = build(fail=RuntimeError("something internal"))
        got = ctl.connect("pw")
        assert got["ok"] is False
        assert got["code"] == "connect_failed"
        assert got["detail"] == "RuntimeError"

    def test_connect_never_raises(self):
        for boom in (TransportError("x", "y"), RuntimeError("z"),
                     OSError("w"), ValueError("v")):
            ctl, _ = build(fail=boom)
            ctl.connect("pw")   # must not raise

    def test_the_stage_is_failed_afterwards(self):
        ctl, _ = build(probe=SamProbe(False, "refused", "start i2pd"))
        ctl.connect("pw")
        assert ctl.stage == "failed"


class TestDisconnect:

    def test_it_closes_the_transport(self):
        ctl, made = build()
        ctl.connect("pw")
        ctl.disconnect()
        assert made["transport"].closed

    def test_it_clears_otrapps_transport(self):
        """A stale transport would let send_message aim at a dead socket."""
        ctl, made = build()
        ctl.connect("pw")
        ctl.disconnect()
        assert made["app"]._transport is None

    def test_it_ends_at_idle_not_failed(self):
        ctl, _ = build()
        ctl.connect("pw")
        assert ctl.disconnect()["stage"] == "idle"
        assert ctl.stage == "idle"

    def test_disconnect_before_connect_is_harmless(self):
        ctl, _ = build()
        assert ctl.disconnect()["ok"]

    def test_a_transport_that_raises_on_close_still_reaches_idle(self):
        ctl, made = build()
        ctl.connect("pw")
        made["transport"].close = lambda: (_ for _ in ()).throw(OSError("x"))
        ctl.disconnect()
        assert ctl.stage == "idle"

    def test_disconnect_is_idempotent(self):
        ctl, _ = build()
        ctl.connect("pw")
        ctl.disconnect()
        ctl.disconnect()
        assert ctl.stage == "idle"


class TestStatus:

    def test_it_carries_everything_the_screen_renders(self):
        ctl, _ = build()
        ctl.connect("pw")
        got = ctl.status()
        assert got["stage"] == "connected"
        assert got["connected"] is True
        assert got["jid"] == JID
        assert got["server"] == SERVER
        assert got["is_default_server"] is True
        assert got["sam"] == "127.0.0.1:7656"

    def test_a_custom_server_is_not_reported_as_the_default(self):
        ctl, _ = build(profile=ConnectionProfile(jid=JID,
                                                 server="mine.i2p"))
        assert ctl.status()["is_default_server"] is False

    def test_status_before_connecting_is_idle_and_honest(self):
        ctl, _ = build()
        got = ctl.status()
        assert got["stage"] == "idle" and got["connected"] is False

    def test_status_is_plain_data(self):
        """It crosses into Kotlin; a PyObject graph would not survive."""
        ctl, _ = build()
        ctl.connect("pw")
        for value in ctl.status().values():
            assert isinstance(value, (str, bool, int, dict, list)), value


class TestNothingIsSimulated:
    """A screen that looks alive by inventing a security state is worse than
    no screen: it says ENCRYPTED when nothing has been encrypted."""

    def test_the_controller_has_no_security_state_of_its_own(self):
        names = [n for n in dir(ConnectionController)
                 if not n.startswith("__")]
        for invented in ("security", "encrypted", "verified", "fingerprint",
                         "smp", "trust"):
            assert not any(invented in n.lower() for n in names), names

    def test_status_reports_no_security_fields(self):
        ctl, _ = build()
        ctl.connect("pw")
        keys = " ".join(ctl.status()).lower()
        for invented in ("security", "encrypted", "verified", "fingerprint"):
            assert invented not in keys, (
                "the connection screen must read security state from the "
                "engine through OtrApp, not from the controller")

    def test_it_builds_a_real_transport_by_default(self):
        """The default factory is the transport from 22fc255, not a stub."""
        from android_bridge.connection import _default_transport_factory
        from android_bridge.transport import XmppTransport
        assert _default_transport_factory() is XmppTransport


# ── Added after the first handset Connect failure ────────────────────────────

class TestEveryFailureClassIsDistinguishable:
    """The eight cases a handset report has to tell apart.

    Before this, a slixmpp that would not import, a forwarder that would not
    import, and a genuine bug all arrived as code "failed" carrying an
    exception class name. That sends someone to look at their router when the
    fault is in packaging.
    """

    def test_a_forwarder_that_will_not_import_is_not_a_router_problem(self):
        from android_bridge.transport import TransportError
        ctl, _ = build(fail=TransportError(
            "forwarder_import_failed", "packaging fault, not a router"))
        got = ctl.connect("pw")
        assert got["code"] == "forwarder_import_failed"
        assert "router" not in got["detail"].split("not a router")[0]

    def test_a_client_that_will_not_build_has_its_own_code(self):
        from android_bridge.transport import TransportError
        ctl, _ = build(fail=TransportError("client_build_failed", "no slixmpp"))
        assert ctl.connect("pw")["code"] == "client_build_failed"

    def test_a_timeout_is_not_reported_as_a_failure(self):
        """Case 8: nothing raised, the work simply never finished."""
        from android_bridge.transport import TransportError
        ctl, _ = build(fail=TransportError("timeout", "still in progress"))
        got = ctl.connect("pw")
        assert got["code"] == "timeout"

    def test_a_genuine_bug_is_labelled_as_unexpected(self):
        ctl, _ = build(fail=RuntimeError("boom"))
        got = ctl.connect("pw")
        assert got["code"] == "connect_failed"
        assert got["detail"] == "RuntimeError"


class TestWhatCrossedTheBoundary:
    """"Did the call fail, or did it get the wrong arguments" are two
    questions, and from a handset they are indistinguishable without this."""

    def test_it_reports_the_jid_and_its_parts(self):
        ctl, _ = build()
        got = ctl.inputs()
        assert got["jid"] == JID
        assert got["jid_localpart_present"] is True
        assert got["jid_domain"] == "xmpp-elite.i2p"

    def test_the_tunnel_target_is_the_server_not_the_jid_domain(self):
        """These differ on purpose: the SAM stream goes to the c2s
        destination, the JID domain is the XMPP virtual host."""
        ctl, _ = build()
        got = ctl.inputs()
        assert got["tunnel_target"] == SERVER
        assert got["jid_domain"] != got["tunnel_target"]

    def test_it_reports_ports_and_tls_mode(self):
        ctl, _ = build()
        got = ctl.inputs()
        assert got["sam_port"] == 7656
        assert got["c2s_port"] == 5222
        # Says what was decided, not what was intended. Those differed once:
        # the transport never set an SSL context, so slixmpp verified against
        # a CA over I2P, STARTTLS failed, and its retry loop hung the connect.
        assert got["tls_mode"].startswith("starttls")
        assert "certificate checks off" in got["tls_mode"]
        assert "authenticated by I2P" in got["tls_mode"]

    def test_a_clearnet_profile_still_reports_a_required_certificate(self):
        ctl, _ = build(profile=ConnectionProfile(
            jid=JID, server="example.test", use_i2p=False))
        assert "certificate required" in ctl.inputs()["tls_mode"]

    def test_password_presence_is_a_boolean_and_nothing_more(self):
        ctl, _ = build()
        assert ctl.inputs()["password_present"] is False
        ctl.connect("hunter2")
        got = ctl.inputs()
        assert got["password_present"] is True
        blob = repr(ctl.status())
        assert "hunter2" not in blob

    def test_no_length_is_reported(self):
        """A length is a real clue to anyone who gets the report, and answers
        no question a boolean does not."""
        ctl, _ = build()
        ctl.connect("hunter2")
        for key in ctl.inputs():
            assert "len" not in key.lower()

    def test_profile_errors_travel_with_the_inputs(self):
        ctl, _ = build(profile=ConnectionProfile(jid=JID, server=SERVER))
        assert ctl.inputs()["profile_errors"] == []

    def test_the_whole_snapshot_is_plain_data(self):
        ctl, _ = build()
        for value in ctl.inputs().values():
            assert isinstance(value, (str, bool, int, list)), value


class TestTheWorkerThreadIsObservable:
    """The transport works off the calling thread on purpose, so "nothing
    happened" has two causes: the work failed, or the thread that should have
    done it is gone. A dead loop under a connected-looking status is a
    lifecycle bug and is invisible unless something asks."""

    def test_no_transport_means_no_worker(self):
        ctl, _ = build()
        assert ctl.status()["worker_alive"] is False

    def test_a_live_transport_reports_its_thread(self):
        ctl, made = build()
        ctl.connect("pw")

        class Alive:
            def is_alive(self):
                return True

        made["transport"]._thread = Alive()
        assert ctl.status()["worker_alive"] is True

    def test_a_dead_thread_is_reported_as_dead(self):
        ctl, made = build()
        ctl.connect("pw")

        class Dead:
            def is_alive(self):
                return False

        made["transport"]._thread = Dead()
        assert ctl.status()["worker_alive"] is False
