"""The transport, driven end to end without slixmpp, SAM, or a network.

Everything the transport touches on the way out is injected -- the client
factory and the SAM forwarder -- so these tests run the real state machine
against fakes. That is not a convenience. The alternative is testing a
transport by connecting it to something, which on this project means a router
building tunnels for up to four minutes, and a test nobody runs is a test that
does not exist.

Three properties are load-bearing here.

The password must not appear anywhere this object is rendered. It is held
because SASL needs it again on every reconnect, and an object holding a
credential is one logging call away from putting it in a file.

A callback that raises must not take the connection down. The handlers are UI
code across a language boundary; a screen bug is not a reason to drop a
session. `OtrApp._emit` has the same rule for the same reason.

The transport must not learn what an OTR frame looks like. It hands every body
up and lets the engine decide. A transport that filtered would be a second
opinion about what counts as protocol, in a place with no way to be right.
"""

import logging
import os
import sys
import threading

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from android_bridge.settings import ConnectionProfile
from android_bridge.transport import (
    CONNECT_TIMEOUT, DEFAULT_C2S_PORT, TransportError, XmppTransport,
)

JID = "alice@xmpp-elite.i2p"
SERVER = "hq4t24b7vkllfbk55e5xfocqhfi7hxprwc47zyuilbg6wgzikidq.b32.i2p"
PASSWORD = "correct-horse-battery-staple"


class FakeStanza(dict):
    """Enough of a slixmpp stanza to be read the way the transport reads one."""

    def __init__(self, frm, body, type_="chat"):
        super().__init__({"from": frm, "body": body, "type": type_})

    def get(self, key, default=None):
        return super().get(key, default)


class FakeClient:
    """A slixmpp ClientXMPP that never opens a socket."""

    def __init__(self, jid, password, *, fail_auth=False):
        self.jid = jid
        self.password = password
        self.fail_auth = fail_auth
        self.handlers = {}
        self.sent = []
        self.connected_to = None
        self.disconnected = False
        self.client_roster = {}

    def add_event_handler(self, name, fn):
        self.handlers.setdefault(name, []).append(fn)

    def fire(self, name, arg=None):
        for fn in list(self.handlers.get(name, [])):
            fn(arg)

    # Signature copied from slixmpp.ClientXMPP.connect, and checked against it
    # by TestTheFakeCannotAgreeWithAMistake below.
    #
    # This used to be `connect(self, address=None, **_kw)`, which accepted the
    # transport's `client.connect(address=(host, port))` happily. No such
    # parameter exists in slixmpp: the real signature is connect(host, port).
    # Every test in this file passed while the app raised TypeError on a
    # handset before it opened a socket, because the fake had been written
    # from the same wrong assumption as the code it stood in for. A fake is
    # only evidence if it is wrong in the same places the real thing is.
    def connect(self, host=None, port=None):
        self.connected_to = (host, port) if (host and port) else None
        # A real client reaches these asynchronously; firing inline is enough
        # because the transport awaits a future either of them resolves.
        self.fire("failed_auth" if self.fail_auth else "session_start", None)

    def send_message(self, mto=None, mbody=None, mtype=None):
        self.sent.append((mto, mbody, mtype))

    def disconnect(self, *_a, **_kw):
        self.disconnected = True


def profile(**over):
    base = dict(jid=JID, server=SERVER)
    base.update(over)
    return ConnectionProfile(**base)


def build(*, fail_auth=False, forwarder=None, **kw):
    made = {}

    def factory(jid, password):
        made["client"] = FakeClient(jid, password, fail_auth=fail_auth)
        return made["client"]

    async def default_forwarder(dest, port, sam_host, sam_port):
        made["forward"] = (dest, port, sam_host, sam_port)
        return ("127.0.0.1", 41234)

    t = XmppTransport(
        kw.pop("profile", profile()), kw.pop("password", PASSWORD),
        on_payload=kw.pop("on_payload", lambda *a: None),
        client_factory=factory,
        forwarder=forwarder if forwarder is not None else default_forwarder,
        **kw)
    return t, made


class TestItConnectsThroughTheTunnel:

    def test_the_sam_stream_is_opened_to_the_profile_server(self):
        t, made = build()
        try:
            t.connect()
            assert made["forward"] == (SERVER, DEFAULT_C2S_PORT,
                                       "127.0.0.1", 7656)
        finally:
            t.close()

    def test_slixmpp_is_pointed_at_the_local_end_not_the_domain(self):
        """getaddrinfo is never called on a .i2p name. This is that line."""
        t, made = build()
        try:
            t.connect()
            assert made["client"].connected_to == ("127.0.0.1", 41234)
            assert t.is_connected
        finally:
            t.close()

    def test_a_clearnet_profile_skips_the_forwarder(self):
        t, made = build(profile=profile(server="example.test", use_i2p=False))
        try:
            t.connect()
            assert "forward" not in made
            assert made["client"].connected_to == ("example.test",
                                                   DEFAULT_C2S_PORT)
        finally:
            t.close()

    def test_a_router_that_is_not_there_says_so(self):
        async def broken(*_a):
            raise OSError("connection refused")

        t, _ = build(forwarder=broken)
        try:
            with pytest.raises(TransportError) as caught:
                t.connect()
            assert caught.value.code == "sam_unavailable"
            assert "router" in caught.value.detail
            assert not t.is_connected
        finally:
            t.close()

    def test_a_rejected_password_is_reported_as_such(self):
        t, _ = build(fail_auth=True)
        try:
            with pytest.raises(TransportError) as caught:
                t.connect()
            assert caught.value.code == "auth_failed"
            assert not t.is_connected
        finally:
            t.close()

    def test_the_connect_budget_outlasts_a_cold_tunnel(self):
        """SAM_CONNECT_TIMEOUT is 240s; a smaller budget here would report a
        working router as a failure while it was still building."""
        assert CONNECT_TIMEOUT > 240


class TestTheFakeCannotAgreeWithAMistake:
    """The bug the rest of this file failed to catch, and why.

    The transport called `client.connect(address=(host, port))`. slixmpp has no
    such parameter -- the real signature is `connect(host, port)` -- so on a
    handset it raised TypeError before a socket was opened, and the connect
    screen reported "failed: TypeError". Every test here passed, because
    FakeClient.connect had been written from the same wrong assumption as the
    code it stood in for.

    A fake is only evidence if it is wrong in the same places the real thing
    is. These bind the actual call against the installed slixmpp, so agreement
    between the transport and the fake stops being self-certifying.
    """

    def test_the_transports_call_binds_against_real_slixmpp(self):
        slixmpp = pytest.importorskip("slixmpp")
        import inspect
        sig = inspect.signature(slixmpp.ClientXMPP.connect)
        # Exactly what android_bridge/transport.py calls.
        sig.bind(object(), host="127.0.0.1", port=41234)

    def test_address_is_not_a_parameter_slixmpp_has(self):
        slixmpp = pytest.importorskip("slixmpp")
        import inspect
        sig = inspect.signature(slixmpp.ClientXMPP.connect)
        assert "address" not in sig.parameters, (
            "slixmpp grew an `address` parameter again; check which form this "
            "project should be using rather than assuming")
        with pytest.raises(TypeError):
            sig.bind(object(), address=("127.0.0.1", 41234))

    def test_the_fake_matches_the_real_signature(self):
        slixmpp = pytest.importorskip("slixmpp")
        import inspect
        real = inspect.signature(slixmpp.ClientXMPP.connect)
        fake = inspect.signature(FakeClient.connect)
        assert list(fake.parameters) == list(real.parameters), (
            "the fake client's connect() has drifted from slixmpp's: %s vs %s"
            % (list(fake.parameters), list(real.parameters)))

    def test_no_connect_call_in_the_transport_passes_address(self):
        """Checked against the parsed code, not the prose.

        A substring search matches the comment that explains the bug, which is
        how this test failed the first time it ran.
        """
        import ast
        import inspect
        import android_bridge.transport as mod

        offenders = []
        for node in ast.walk(ast.parse(inspect.getsource(mod))):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr == "connect":
                for kw in node.keywords:
                    if kw.arg == "address":
                        offenders.append(node.lineno)
        assert not offenders, (
            "a .connect(address=...) call is back, at line(s) %r; slixmpp "
            "takes host and port" % (offenders,))

    def test_the_tls_settings_reach_a_real_client(self):
        """enable_direct_tls and enable_starttls are INSTANCE attributes, not
        class ones -- hasattr on the class says False. The factory guards on
        the instance, so they do apply; this pins that, because a guard that
        silently skips is indistinguishable from one that works."""
        slixmpp = pytest.importorskip("slixmpp")
        import asyncio
        from android_bridge.transport import _default_client_factory

        async def build():
            return _default_client_factory()("alice@example.invalid", "pw")

        client = asyncio.run(build())
        assert client.enable_direct_tls is False
        assert client.enable_starttls is True


class TestItCarriesPayloadsBothWays:

    def test_a_payload_goes_out_as_a_chat_body(self):
        t, made = build()
        try:
            t.connect()
            t.send("bob@xmpp-elite.i2p", "?OTRv4+ ...frame...")
            assert made["client"].sent == [
                ("bob@xmpp-elite.i2p", "?OTRv4+ ...frame...", "chat")]
        finally:
            t.close()

    def test_sending_before_connecting_is_refused(self):
        t, _ = build()
        try:
            with pytest.raises(TransportError) as caught:
                t.send("bob@xmpp-elite.i2p", "x")
            assert caught.value.code == "not_connected"
        finally:
            t.close()

    def test_an_inbound_body_reaches_the_handler_with_a_bare_jid(self):
        got = []
        t, made = build(on_payload=lambda p, b: got.append((p, b)))
        try:
            t.connect()
            made["client"].fire("message", FakeStanza(
                "bob@xmpp-elite.i2p/phone-a1b2", "?OTRv4+ frame"))
            assert got == [("bob@xmpp-elite.i2p", "?OTRv4+ frame")]
        finally:
            t.close()

    def test_it_does_not_decide_what_counts_as_a_frame(self):
        """Plain text goes up too. The engine is the only thing entitled to
        decide whether a payload is protocol."""
        got = []
        t, made = build(on_payload=lambda p, b: got.append(b))
        try:
            t.connect()
            made["client"].fire("message", FakeStanza(
                "bob@xmpp-elite.i2p", "hello, this is not an OTR frame"))
            assert got == ["hello, this is not an OTR frame"]
        finally:
            t.close()

    def test_an_empty_body_is_not_forwarded(self):
        """Typing notifications and receipts are stanzas with no body."""
        got = []
        t, made = build(on_payload=lambda p, b: got.append(b))
        try:
            t.connect()
            made["client"].fire("message", FakeStanza("bob@x.i2p", ""))
            assert got == []
        finally:
            t.close()

    def test_a_groupchat_stanza_is_ignored(self):
        got = []
        t, made = build(on_payload=lambda p, b: got.append(b))
        try:
            t.connect()
            made["client"].fire("message",
                                FakeStanza("room@x.i2p", "hi", "groupchat"))
            assert got == []
        finally:
            t.close()


class TestACallbackThatRaisesDoesNotDropTheSession:

    def test_an_exploding_payload_handler_is_contained(self, caplog):
        def boom(_peer, _body):
            raise RuntimeError("a bug on the conversation screen")

        t, made = build(on_payload=boom)
        try:
            t.connect()
            with caplog.at_level(logging.WARNING):
                made["client"].fire("message",
                                    FakeStanza("bob@x.i2p", "frame"))
            assert t.is_connected, "a UI bug took the connection down"
        finally:
            t.close()

    def test_an_exploding_presence_handler_is_contained(self):
        def boom(_peer, _online):
            raise RuntimeError("bug")

        t, made = build()
        t._on_presence = boom
        try:
            t.connect()
            made["client"].fire("presence_available", {"from": "bob@x.i2p"})
            assert t.is_connected
        finally:
            t.close()

    def test_a_malformed_stanza_does_not_raise(self):
        t, made = build()
        try:
            t.connect()
            made["client"].fire("message", object())
            assert t.is_connected
        finally:
            t.close()


class TestTheCredentialDoesNotLeak:

    def test_it_is_absent_from_repr(self):
        t, _ = build()
        try:
            assert PASSWORD not in repr(t)
            assert PASSWORD not in str(t)
        finally:
            t.close()

    def test_repr_is_written_out_rather_than_inherited(self):
        """A default repr on a class holding a credential is one logging call
        away from putting it in a file."""
        assert "__repr__" in vars(XmppTransport)

    def test_repr_still_says_what_is_useful(self):
        t, _ = build()
        try:
            text = repr(t)
            assert JID in text and SERVER in text
        finally:
            t.close()

    def test_a_failure_carries_a_type_not_a_message(self):
        """An exception raised inside SASL can quote what it was given."""
        async def leaky(*_a):
            raise OSError("auth failed for password=%s" % PASSWORD)

        t, _ = build(forwarder=leaky)
        try:
            with pytest.raises(TransportError) as caught:
                t.connect()
            assert PASSWORD not in str(caught.value)
            assert PASSWORD not in caught.value.detail
        finally:
            t.close()


class TestItRefusesAnUnusableProfile:

    def test_an_invalid_profile_is_rejected_at_construction(self):
        from android_bridge.settings import ProfileError
        with pytest.raises(ProfileError):
            XmppTransport(ConnectionProfile(jid="no-at-sign"), PASSWORD,
                          on_payload=lambda *a: None)

    def test_an_incomplete_profile_is_rejected_at_construction(self):
        """Valid but empty: nothing wrong with it, nothing to connect to."""
        with pytest.raises(TransportError) as caught:
            XmppTransport(ConnectionProfile(), PASSWORD,
                          on_payload=lambda *a: None)
        assert caught.value.code == "profile_incomplete"


class TestLifecycle:

    def test_disconnect_before_connect_is_harmless(self):
        t, _ = build()
        t.disconnect()
        t.close()

    def test_close_is_idempotent(self):
        t, _ = build()
        t.connect()
        t.close()
        t.close()

    def test_disconnecting_clears_connected(self):
        t, made = build()
        try:
            t.connect()
            t.disconnect()
            assert made["client"].disconnected
            assert not t.is_connected
        finally:
            t.close()

    def test_the_server_dropping_us_clears_connected(self):
        t, made = build()
        try:
            t.connect()
            made["client"].fire("disconnected", None)
            assert not t.is_connected
        finally:
            t.close()

    def test_state_changes_are_reported_in_order(self):
        seen = []
        t, _ = build(on_state=lambda s, _server: seen.append(s))
        try:
            t.connect()
            t.disconnect()
            assert seen == ["building_tunnels", "connected", "disconnected"]
        finally:
            t.close()

    def test_it_never_runs_on_the_calling_thread(self):
        """On Android the caller may be the UI thread, where a tunnel build
        would be an ANR rather than a slow connection."""
        where = []
        t, _ = build(on_payload=lambda *a: None)

        async def watching_forwarder(*_a):
            where.append(threading.current_thread().name)
            return ("127.0.0.1", 41234)

        t._forwarder = watching_forwarder
        try:
            t.connect()
            assert where and where[0] != threading.current_thread().name
            assert where[0].startswith("otrv4plus-transport")
        finally:
            t.close()


class TestTheRoster:

    def test_it_reads_names_and_subscriptions(self):
        t, made = build()
        try:
            t.connect()
            made["client"].client_roster = {
                "bob@xmpp-elite.i2p": {"name": "Bob",
                                       "subscription": "both"}}
            assert t.roster() == [{"jid": "bob@xmpp-elite.i2p",
                                   "name": "Bob",
                                   "subscription": "both"}]
        finally:
            t.close()

    def test_it_is_read_on_the_loop_thread(self):
        """slixmpp mutates the roster from its own coroutines as presence and
        roster pushes arrive. Iterating it from a Kotlin thread is a data race
        that shows up as an occasional empty contact list, not as a crash."""
        where = []

        class Watching(dict):
            def __iter__(self):
                where.append(threading.current_thread().name)
                return iter(())

        t, made = build()
        try:
            t.connect()
            made["client"].client_roster = Watching()
            t.roster()
            assert where and where[0].startswith("otrv4plus-transport"), where
        finally:
            t.close()

    def test_no_client_means_an_empty_roster_not_a_crash(self):
        t, _ = build()
        assert t.roster() == []
        t.close()

    def test_a_roster_that_raises_is_survivable(self):
        class Hostile:
            def __iter__(self):
                raise RuntimeError("slixmpp internals changed")

        t, made = build()
        try:
            t.connect()
            made["client"].client_roster = Hostile()
            assert t.roster() == []
        finally:
            t.close()


class TestItIsTheTransportOtrAppExpects:

    def test_it_implements_the_four_methods(self):
        for name in ("send", "connect", "disconnect", "roster"):
            assert callable(getattr(XmppTransport, name))

    def test_it_is_a_transport(self):
        from android_bridge.app import Transport
        assert issubclass(XmppTransport, Transport)

    def test_it_does_not_import_the_terminal_client_at_module_scope(self):
        """Importing otrv4plus_xmpp pulls in the whole engine, and a settings
        screen has no business loading it."""
        import ast
        import inspect
        import android_bridge.transport as mod
        tree = ast.parse(inspect.getsource(mod))
        top = []
        for node in tree.body:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = ([a.name for a in node.names]
                         if isinstance(node, ast.Import)
                         else [node.module or ""])
                top += names
        for banned in ("otrv4plus_xmpp", "slixmpp", "otrv4_", "otrv4plus"):
            assert not any((n or "").startswith(banned) for n in top), (
                "%r is imported at module scope: %r" % (banned, top))
