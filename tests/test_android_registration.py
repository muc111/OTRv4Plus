# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Register, driven through the transport without slixmpp, SAM or a network.

`tests/test_registration.py` covers the rules. This covers the PATH: that the
submission goes out over the same SAM tunnel a login uses, that the plugin is
enabled on a client that has not connected yet, that the stream is always given
back, and that each way a server can refuse arrives at the Register screen as a
code it knows.

THE PROPERTY WORTH STATING. Registration is the one operation where the
credential is new and the user is least able to tell whether anything went
wrong. So it is not allowed its own network path: `_endpoint` and
`_make_client` are the same two calls `connect` makes, which is what keeps the
I2P policy, the TLS decision and the local-end host and port identical between
creating an account and using it. The first two tests below are that.
"""

import asyncio
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import otrv4plus_registration as reg
from android_bridge.settings import ConnectionProfile
from android_bridge.transport import DEFAULT_C2S_PORT, XmppTransport

JID = "alice@xmpp-elite.i2p"
SERVER = "hq4t24b7vkllfbk55e5xfocqhfi7hxprwc47zyuilbg6wgzikidq.b32.i2p"
PASSWORD = "correct-horse-battery-staple"


# ── fakes ────────────────────────────────────────────────────────────────────

class IqError(Exception):
    """slixmpp's, including the part where its text carries the JID."""

    def __init__(self, condition):
        super().__init__("iq error <%s/> for %s" % (condition, JID))
        self.condition = condition


class FakeIq(dict):
    """`iq['register']['username'] = ...`, and a `send` that can refuse."""

    def __init__(self, outcome):
        super().__init__({"type": "", "register": {}})
        self._outcome = outcome
        self.sent = False

    async def send(self):
        self.sent = True
        self._outcome.submitted = dict(self["register"])
        if self._outcome.refuse is not None:
            raise self._outcome.refuse
        return self


class Plugin:
    def __init__(self):
        self.create_account = False
        self.force_registration = False


class Outcome:
    """What the fake server does, and what it saw."""

    def __init__(self, *, offers=True, refuse=None, auth_fails=False):
        self.offers = offers
        self.refuse = refuse
        self.auth_fails = auth_fails
        self.submitted = None


class FakeClient:
    """A ClientXMPP that negotiates XEP-0077 the way slixmpp does.

    The shape that matters: `register` fires DURING negotiation, before
    authentication, and only when the server offered the feature. A server
    that does not offer it goes straight to SASL -- which for an account that
    does not exist yet is a failed_auth, and that is the case the transport
    has to tell apart from a wrong password.
    """

    def __init__(self, jid, password, outcome):
        self.jid = jid
        self.password = password
        self.outcome = outcome
        self.handlers = {}
        self.plugins = {}
        self.connected_to = None
        self.aborted = False
        self.ssl_context = None

    # -- surface the transport uses --------------------------------------
    def add_event_handler(self, name, fn):
        self.handlers.setdefault(name, []).append(fn)

    def register_plugin(self, name):
        self.plugins[name] = Plugin()

    def __getitem__(self, name):
        return self.plugins[name]

    def Iq(self):
        return FakeIq(self.outcome)

    def connect(self, host=None, port=None):
        self.connected_to = (host, port)
        asyncio.get_event_loop().create_task(self._negotiate())

    def abort(self):
        self.aborted = True

    def disconnect(self, *_a, **_kw):
        self.aborted = True

    # -- the server's half ------------------------------------------------
    async def _negotiate(self):
        if self.outcome.offers:
            for fn in list(self.handlers.get("register", [])):
                await fn(FakeIq(self.outcome))
            if self.outcome.refuse is None:
                self._fire("session_start")
            return
        # No register feature: straight to SASL against an account that does
        # not exist.
        self._fire("failed_auth" if self.outcome.auth_fails
                   else "session_start")

    def _fire(self, name):
        for fn in list(self.handlers.get(name, [])):
            fn(None)


def build(outcome, **kw):
    made = {}

    def factory(jid, password):
        made["client"] = FakeClient(jid, password, outcome)
        return made["client"]

    async def forwarder(dest, port, sam_host, sam_port):
        made["forward"] = (dest, port, sam_host, sam_port)
        return ("127.0.0.1", 41234)

    t = XmppTransport(
        ConnectionProfile(jid=kw.pop("jid", JID), server=SERVER),
        kw.pop("password", PASSWORD),
        on_payload=lambda *a: None,
        client_factory=factory,
        forwarder=kw.pop("forwarder", forwarder),
        **kw)
    return t, made


# ── it does not get its own way out ──────────────────────────────────────────

class TestItTravelsTheSamePathAsALogin:

    def test_the_submission_goes_through_the_sam_tunnel(self):
        t, made = build(Outcome())
        try:
            assert t.register_account()[0] == reg.OK
            assert made["forward"] == (SERVER, DEFAULT_C2S_PORT,
                                       "127.0.0.1", 7656)
        finally:
            t.close()

    def test_slixmpp_is_pointed_at_the_local_end_not_the_domain(self):
        """getaddrinfo is never called on a .i2p name -- during registration
        either, which is where the new credential is."""
        t, made = build(Outcome())
        try:
            t.register_account()
            assert made["client"].connected_to == ("127.0.0.1", 41234)
        finally:
            t.close()

    def test_the_tls_decision_is_the_one_connect_would_make(self):
        t, made = build(Outcome())
        try:
            t.register_account()
            assert "endpoint authenticated by I2P" in t.tls_policy
        finally:
            t.close()


class TestThePluginIsEnabledBeforeTheStreamIsUp:
    """A plugin added after negotiation never sees the feature go past."""

    def test_xep_0077_is_registered(self):
        t, made = build(Outcome())
        try:
            t.register_account()
            assert "xep_0077" in made["client"].plugins
        finally:
            t.close()

    def test_account_creation_is_asked_for_rather_than_assumed(self):
        t, made = build(Outcome())
        try:
            t.register_account()
            assert made["client"].plugins["xep_0077"].create_account is True
        finally:
            t.close()

    def test_registration_is_forced_so_sasl_does_not_win_the_race(self):
        """Without this a server advertising SASL alongside `<register/>`
        authenticates an account that does not exist, and the user is told
        their password is wrong."""
        t, made = build(Outcome())
        try:
            t.register_account()
            assert made["client"].plugins["xep_0077"].force_registration is True
        finally:
            t.close()


# ── the submission itself ────────────────────────────────────────────────────

class TestWhatIsSubmitted:

    def test_the_username_is_the_localpart_not_the_whole_jid(self):
        t, made = build(Outcome())
        try:
            t.register_account()
            assert made["client"].outcome.submitted["username"] == "alice"
        finally:
            t.close()

    def test_the_password_is_the_one_a_later_login_will_use(self):
        """Registering one credential while configured for another creates an
        account nobody can then log into."""
        t, made = build(Outcome())
        try:
            t.register_account()
            assert made["client"].outcome.submitted["password"] == PASSWORD
        finally:
            t.close()

    def test_success_is_reported_as_ok_with_a_sentence(self):
        t, _ = build(Outcome())
        try:
            code, detail = t.register_account()
            assert code == reg.OK
            assert detail == reg.CODES[reg.OK]
        finally:
            t.close()


# ── the ways a server refuses ────────────────────────────────────────────────

class TestRefusals:

    def test_a_taken_username_is_a_conflict(self):
        t, _ = build(Outcome(refuse=IqError("conflict")))
        try:
            assert t.register_account()[0] == "conflict"
        finally:
            t.close()

    def test_details_the_server_dislikes_are_not_acceptable(self):
        t, _ = build(Outcome(refuse=IqError("not-acceptable")))
        try:
            assert t.register_account()[0] == "not_acceptable"
        finally:
            t.close()

    def test_a_server_that_will_not_do_it_says_unsupported(self):
        t, _ = build(Outcome(refuse=IqError("service-unavailable")))
        try:
            assert t.register_account()[0] == "service_unavailable"
        finally:
            t.close()

    def test_a_refusal_never_shows_the_servers_own_words(self):
        t, _ = build(Outcome(refuse=IqError("conflict")))
        try:
            _, detail = t.register_account()
            assert "alice" not in detail
            assert "xmpp-elite" not in detail
        finally:
            t.close()


class TestAServerWithNoInBandRegistration:
    """The case that must not read as "wrong password": there is no password
    to be wrong yet."""

    def test_reaching_sasl_without_the_feature_is_unsupported(self):
        t, _ = build(Outcome(offers=False, auth_fails=True))
        try:
            assert t.register_account()[0] == "unsupported"
        finally:
            t.close()

    def test_even_a_stream_that_comes_up_is_unsupported_if_nothing_was_asked(
            self):
        """A server that let us in without ever offering registration created
        nothing. Reporting success sends the user to sign in as an account
        that does not exist."""
        t, _ = build(Outcome(offers=False, auth_fails=False))
        try:
            assert t.register_account()[0] == "unsupported"
        finally:
            t.close()


class TestTheNetworkNotBeingThere:

    def test_a_tunnel_that_will_not_open_is_a_network_failure(self):
        async def forwarder(*_a, **_kw):
            raise OSError("no SAM bridge")

        t, _ = build(Outcome(), forwarder=forwarder)
        try:
            code, detail = t.register_account()
            assert code == "network"
            assert detail == reg.CODES["network"]
        finally:
            t.close()

    def test_the_router_error_text_does_not_reach_the_screen(self):
        async def forwarder(*_a, **_kw):
            raise OSError("destination b32 hq4t24b7 unreachable")

        t, _ = build(Outcome(), forwarder=forwarder)
        try:
            assert "hq4t24b7" not in t.register_account()[1]
        finally:
            t.close()


# ── local refusal costs no round trip ────────────────────────────────────────

class TestItIsCheckedLocallyFirst:

    def test_a_short_password_never_opens_a_tunnel(self):
        """Over three I2P hops a wasted round trip is tens of seconds."""
        t, made = build(Outcome(), password="short")
        try:
            assert t.register_account()[0] == "not_acceptable"
            assert "forward" not in made, "a tunnel was built to be refused"
        finally:
            t.close()

    def test_a_malformed_username_never_opens_a_tunnel(self):
        t, made = build(Outcome(), jid="al ice@xmpp-elite.i2p")
        try:
            assert t.register_account()[0] == "not_acceptable"
            assert "forward" not in made
        finally:
            t.close()


# ── it always gives the stream back ──────────────────────────────────────────

class TestTheStreamIsAlwaysReturned:

    def test_a_successful_registration_does_not_leave_a_session(self):
        """`connect()` stays the only way to arrive at a live session."""
        t, made = build(Outcome())
        try:
            t.register_account()
            assert made["client"].aborted is True
            assert t.is_connected is False
        finally:
            t.close()

    def test_a_refused_registration_leaves_nothing_dialling(self):
        """slixmpp reschedules a failed connection rather than giving up, so
        a client that is merely dropped keeps dialling for the life of the
        process."""
        t, made = build(Outcome(refuse=IqError("conflict")))
        try:
            t.register_account()
            assert made["client"].aborted is True
        finally:
            t.close()

    def test_the_transport_is_usable_afterwards(self):
        t, _ = build(Outcome(refuse=IqError("conflict")))
        try:
            t.register_account()
            assert t.register_account()[0] == "conflict", (
                "the second attempt found the loop or the client in a state "
                "the first one left")
        finally:
            t.close()


# ── nothing escapes as an exception ──────────────────────────────────────────

class TestItNeverRaises:
    """Every outcome is something the Register screen shows. An exception
    crossing Chaquopy arrives as a PyException with the stanza in its text."""

    @pytest.mark.parametrize("outcome", [
        Outcome(),
        Outcome(refuse=IqError("conflict")),
        Outcome(refuse=IqError("policy-violation")),
        Outcome(refuse=RuntimeError("boom")),
        Outcome(offers=False, auth_fails=True),
    ])
    def test_every_outcome_is_a_pair(self, outcome):
        t, _ = build(outcome)
        try:
            result = t.register_account()
            assert isinstance(result, tuple) and len(result) == 2
            assert result[0] in reg.CODES
            assert result[1] == reg.CODES[result[0]]
        finally:
            t.close()


class TestTheFakeCannotAgreeWithAMistake:
    """Bound against real slixmpp, because a fake written from the same wrong
    assumption as the code is not evidence.

    This is the discipline that caught `async_ping`: every test passed while
    the handset failed, because the fake had the method slixmpp does not.
    """

    def test_the_plugin_has_the_two_flags_the_transport_sets(self):
        slixmpp = pytest.importorskip("slixmpp")
        from slixmpp.plugins.xep_0077 import XEP_0077

        config = XEP_0077.default_config
        assert "create_account" in config
        assert "force_registration" in config

    def test_the_register_stanza_has_the_two_fields_submitted(self):
        pytest.importorskip("slixmpp")
        from slixmpp.plugins.xep_0077.stanza import Register

        assert "username" in Register.interfaces
        assert "password" in Register.interfaces

    def test_the_plugin_name_is_the_one_registered(self):
        pytest.importorskip("slixmpp")
        from slixmpp.plugins.xep_0077 import XEP_0077

        assert XEP_0077.name == "xep_0077"

    def test_the_register_event_is_what_slixmpp_fires(self):
        """`_handle_register_feature` fires `register` with the form, and only
        when a handler for that exact name exists -- it checks
        `event_handled('register')` first. A renamed handler here is not a
        wiring bug that shows up as an error, it is registration silently
        never being attempted."""
        pytest.importorskip("slixmpp")
        import inspect

        from slixmpp.plugins.xep_0077 import register as module

        source = inspect.getsource(module.XEP_0077._handle_register_feature)
        assert "'register'" in source or '"register"' in source

    def test_a_client_really_exposes_its_plugins_by_subscript(self):
        pytest.importorskip("slixmpp")
        from slixmpp import ClientXMPP

        assert hasattr(ClientXMPP, "__getitem__")

    def test_iq_send_is_awaitable_on_the_real_stanza(self):
        """`await iq.send()` is what the submission does. In older slixmpp
        `send` took a callback instead."""
        pytest.importorskip("slixmpp")
        import inspect

        from slixmpp.stanza import Iq

        assert callable(Iq.send)
        assert "timeout" in inspect.signature(Iq.send).parameters


class TestItLeavesNothingIdentifyingInTheTrace:
    """§7: the diagnostic log carries no usernames, JIDs or hostnames."""

    def test_the_trace_records_the_attempt_without_the_account(self):
        from android_bridge.trace import TRACE

        t, _ = build(Outcome(refuse=IqError("conflict")))
        try:
            before = len(TRACE.events())
            t.register_account()
            text = repr(TRACE.events()[before:])
            assert "alice" not in text
            assert PASSWORD not in text
            assert "xmpp-elite" not in text
        finally:
            t.close()

    def test_the_password_is_not_in_the_transports_repr(self):
        t, _ = build(Outcome())
        try:
            t.register_account()
            assert PASSWORD not in repr(t)
        finally:
            t.close()
