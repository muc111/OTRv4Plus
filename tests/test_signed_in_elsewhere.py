# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Signed out by a newer sign-in of the same account: stop, do not retry.

T450, 2026-10-16: with mod_c2s_limit_sessions (the first session wins) a
phone that lost its connection could not sign back in -- its own dead
session held the only slot. prosody/mod_otrv4plus_one_session.lua lets the
newest sign-in win and closes the older one with the stream error
`conflict`. The client that is closed must then stop: reconnecting would sign
the other device out, which would do the same back, forever.
"""

import os
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from android_bridge import transport as T
from android_bridge.connection import ConnectionController, SamProbe
from android_bridge.settings import ConnectionProfile

JID = "alice@otrv4plus.i2p"


def _transport():
    t = T.XmppTransport.__new__(T.XmppTransport)
    t._profile = ConnectionProfile(jid=JID)
    t._connected = threading.Event()
    t._connected.set()
    t._caps, t._welcome, t._room_nicks = {}, set(), {}
    t._last_inbound = time.monotonic()
    t.states = []
    t._on_state = lambda state, _server: t.states.append(state)
    return t


def _stanza(condition, text="Replaced by a newer sign-in"):
    return {"condition": condition, "text": text}


class TestTheTransportSaysReplaced:

    def test_a_conflict_then_the_drop_is_replaced(self):
        t = _transport()
        t._on_live_stream_error(_stanza("conflict"))
        t._on_disconnected(None)
        assert t.states == ["replaced"]

    def test_only_once(self):
        t = _transport()
        t._on_live_stream_error(_stanza("conflict"))
        t._on_disconnected(None)
        t._on_disconnected(None)
        assert t.states == ["replaced", "disconnected"]

    def test_any_other_drop_is_a_drop(self):
        t = _transport()
        t._on_live_stream_error(_stanza("system-shutdown"))
        t._on_disconnected(None)
        assert t.states == ["disconnected"]


class FakeApp:
    def __init__(self):
        self.presence_lost = 0

    def receive_message(self, peer, payload):
        pass

    def note_presence(self, peer, online, show=""):
        pass

    def note_presence_lost(self):
        self.presence_lost += 1

    def set_event_sink(self, sink):
        pass


class TestTheControllerStopsThere:

    def _ctl(self):
        app = FakeApp()
        ctl = ConnectionController(
            app, ConnectionProfile(jid=JID),
            transport_factory=lambda *a, **k: None,
            prober=lambda _p, **_kw: SamProbe(True, "ok", "fine", "3.1"))
        return ctl, app

    def test_it_fails_with_the_code_the_apps_do_not_retry(self):
        ctl, app = self._ctl()
        ctl._on_transport_state("replaced", "otrv4plus.i2p")
        status = ctl.status()
        assert status["stage"] == "failed"
        assert status["last"]["code"] == T.REPLACED_CODE == "signed_in_elsewhere"
        assert "signed in on another device" in status["last"]["detail"]
        assert "change your password" in status["last"]["detail"]
        assert app.presence_lost == 1

    def test_kotlin_treats_the_code_as_needing_the_user(self):
        kt = open(os.path.join(ROOT, "android/app/src/main/java/org/otrv4plus/"
                               "android/connection/ConnectProblem.kt")).read()
        assert 'SIGNED_IN_ELSEWHERE = "%s"' % T.REPLACED_CODE in kt
        needs = kt[kt.index("val NEEDS_YOU"):kt.index("val TRANSIENT")]
        assert "SIGNED_IN_ELSEWHERE" in needs

    def test_the_service_stops_on_it_after_a_drop(self):
        svc = open(os.path.join(ROOT, "android/app/src/main/java/org/otrv4plus/"
                                "android/connection/OtrConnectionService.kt")).read()
        watch = svc[svc.index("private suspend fun watchUntilDropped"):]
        watch = watch[:watch.index("private fun codeOf")]
        assert "ConnectProblem.SIGNED_IN_ELSEWHERE" in watch
        assert "reconnect.onFailure" in watch


class TestTheTerminalClientStopsToo:

    def test_conflict_is_fatal(self):
        import otrv4plus_xmpp as X
        cls = next(v for v in vars(X).values()
                   if isinstance(v, type) and "_FATAL_STREAM_ERRORS" in vars(v))
        assert "conflict" in cls._FATAL_STREAM_ERRORS
        assert "change your password" in cls._FATAL_STREAM_ERRORS["conflict"]


class TestTheServerModule:
    """The Lua is checked against a simulated Prosody in development; here,
    that it says what SECURITY_SESSIONS.md promises."""

    SRC = open(os.path.join(ROOT, "prosody", "mod_otrv4plus_one_session.lua")).read()

    def test_it_closes_the_old_session_with_conflict(self):
        assert '"pre-resource-bind"' in self.SRC
        assert 'condition = "conflict"' in self.SRC
        assert "old:close(" in self.SRC
        assert "policy-violation" not in self.SRC   # never refuses the new one

    def test_it_reads_max_resources(self):
        assert 'get_option_number("max_resources", 1)' in self.SRC


class TestAFullServer:
    """prosody/mod_otrv4plus_capacity.lua refuses a new person at bind with
    resource-constraint once max_online_users are online."""

    SRC = open(os.path.join(ROOT, "prosody", "mod_otrv4plus_capacity.lua")).read()

    def test_the_module_refuses_with_resource_constraint_and_spares_reconnects(self):
        assert 'get_option_number("max_online_users", 2000)' in self.SRC
        assert 'condition = "resource-constraint"' in self.SRC
        assert "if host_sessions[session.username] then" in self.SRC
        assert 'module:hook("user-registering"' in self.SRC
        assert 'module:hook("user-registered"' in self.SRC

    def test_the_app_names_it_and_keeps_trying(self):
        assert T.SERVER_FULL_CODE == "server_full"
        kt = open(os.path.join(ROOT, "android/app/src/main/java/org/otrv4plus/"
                               "android/connection/ConnectProblem.kt")).read()
        assert 'SERVER_FULL = "server_full"' in kt
        needs = kt[kt.index("val NEEDS_YOU"):kt.index("val TRANSIENT")]
        assert "SERVER_FULL" not in needs        # retried, never latched


class TestSignInPacing:
    """mod_otrv4plus_capacity login_rate: a crowd of sign-ins (a server
    restart) is let in a few a second; the rest retry, spread out."""

    SRC = open(os.path.join(ROOT, "prosody", "mod_otrv4plus_capacity.lua")).read()

    def test_the_module_refuses_before_tls_once_per_connection(self):
        assert 'get_option_number("login_rate", 10)' in self.SRC
        assert 'module:hook("stream-features"' in self.SRC
        assert 'session.type ~= "c2s_unauthed" or session.otrv4plus_admitted' in self.SRC
        assert "busy" in self.SRC

    def test_the_app_says_busy_not_full(self):
        assert T.SERVER_BUSY_CODE == "server_busy"
        kt = open(os.path.join(ROOT, "android/app/src/main/java/org/otrv4plus/"
                               "android/connection/ConnectProblem.kt")).read()
        assert 'SERVER_BUSY = "server_busy"' in kt

    def test_reconnects_are_spread(self):
        svc = open(os.path.join(ROOT, "android/app/src/main/java/org/otrv4plus/"
                                "android/connection/OtrConnectionService.kt")).read()
        assert "ReconnectPolicy(jitter = RECONNECT_JITTER)" in svc
        import otrv4plus_xmpp as X
        import inspect
        src = inspect.getsource(X)
        assert "secrets.randbelow(501)" in src


class TestABanIsNamedAndNotRetried:
    """A server admin's ban (mod_otrv4plus_moderation) ends the stream with
    policy-violation; the drop is reported as "banned", never a reconnect."""

    def test_the_live_ban_becomes_banned(self):
        t = _transport()
        t._on_live_stream_error(_stanza(
            "policy-violation", "This account is banned from this server permanently (until=0)."))
        t._on_disconnected(None)
        assert t.states == ["banned"]

    def test_the_controller_fails_with_the_ban(self):
        app = FakeApp()
        ctl = ConnectionController(
            app, ConnectionProfile(jid=JID),
            transport_factory=lambda *a, **k: None,
            prober=lambda _p, **_kw: SamProbe(True, "ok", "fine", "3.1"))
        ctl._transport = type("T", (), {"banned_text": "This account is banned from "
                                        "this server permanently by its administrator."})()
        ctl._on_transport_state("banned", "otrv4plus.i2p")
        status = ctl.status()
        assert status["stage"] == "failed"
        assert status["last"]["code"] == T.BANNED_CODE
        assert "banned" in status["last"]["detail"]

