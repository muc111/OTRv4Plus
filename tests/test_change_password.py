# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Changing the account password from the app (XEP-0077 §3.3).

Owner request, 2026-10-16: users need a way to change their password, above
all after "Your account is also signed in on another device" -- signing the
other session out does not stop it signing in again; a new password does.
"""

import asyncio
import os
import sys
import threading

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from android_bridge import transport as T
from android_bridge.trace import TRACE
from slixmpp import JID

OLD = "old-password"
NEW = "correct-horse-battery"


class _Condition(Exception):
    """Shaped like slixmpp's IqError: the stanza's condition under .iq."""

    def __init__(self, condition):
        super().__init__(condition)
        self.iq = {"error": {"condition": condition}}


class FakeIq(dict):
    def __init__(self, client):
        super().__init__()
        self.client = client
        self.children = []

    def append(self, element):
        self.children.append(element)

    async def send(self, timeout=None):
        self.client.sent.append(self)
        if self.client.answer is not None:
            raise self.client.answer
        return self


class FakeClient:
    def __init__(self, answer=None):
        self.boundjid = JID("alice@otrv4plus.i2p/phone")
        self.answer = answer
        self.sent = []
        self.password = "old-password"

    def Iq(self):
        return FakeIq(self)


@pytest.fixture
def make():
    made = []

    def build(answer=None):
        t = T.XmppTransport.__new__(T.XmppTransport)
        t._lock = threading.Lock()
        t._closed = False
        t._connected = threading.Event()
        t._connected.set()
        t._password = "old-password"
        t._client = FakeClient(answer)
        loop = asyncio.new_event_loop()
        thread = threading.Thread(target=loop.run_forever, daemon=True)
        thread.start()
        t._loop, t._thread = loop, thread
        made.append(loop)
        return t

    yield build
    for loop in made:
        loop.call_soon_threadsafe(loop.stop)


class TestWhatGoesToTheServer:

    def test_one_register_query_to_our_own_server(self, make):
        t = make()
        assert t.change_password(OLD, NEW)[0] == "ok"
        (iq,) = t._client.sent
        assert iq["type"] == "set"
        assert str(iq["to"]) == "otrv4plus.i2p"
        (query,) = iq.children
        assert query.tag == "{jabber:iq:register}query"
        fields = {c.tag.split("}")[1]: c.text for c in query}
        assert fields == {"username": "alice", "password": NEW}

    def test_a_reconnect_signs_in_with_the_new_one(self, make):
        t = make()
        t.change_password(OLD, NEW)
        assert t._password == NEW
        assert t._client.password == NEW

    def test_neither_password_is_traced(self, make):
        t = make()
        t.change_password(OLD, NEW)
        text = TRACE.render() if hasattr(TRACE, "render") else repr(TRACE.__dict__)
        assert NEW not in text
        assert "old-password" not in text


class TestRefusals:

    @pytest.mark.parametrize("condition,code", [
        ("not-authorized", "refused"),
        ("forbidden", "refused"),
        ("not-allowed", "refused"),
        ("not-acceptable", "not_acceptable"),
        ("bad-request", "not_acceptable"),
        ("service-unavailable", "unsupported"),
        ("feature-not-implemented", "unsupported"),
        ("internal-server-error", "unknown"),
    ])
    def test_each_is_named_and_the_old_password_stays(self, make, condition, code):
        t = make(_Condition(condition))
        got, detail, _ = t.change_password(OLD, NEW)
        assert got == code
        assert detail
        assert t._password == "old-password"

    def test_too_short_never_reaches_the_server(self, make):
        t = make()
        assert t.change_password(OLD, "short")[0] == "not_acceptable"
        assert t._client.sent == []

    def test_the_wrong_current_password_never_reaches_the_server(self, make):
        t = make()
        got, detail, _ = t.change_password("guess", NEW)
        assert got == "wrong_current"
        assert t._client.sent == []
        assert t._password == OLD

    def test_not_connected(self, make):
        t = make()
        t._connected.clear()
        assert t.change_password(OLD, NEW)[0] == "network"
        assert t._client.sent == []


class TestTheControllerAndTheDesktopBridge:

    def test_the_controller_answers_the_one_shape(self):
        from android_bridge.connection import ConnectionController, SamProbe
        from android_bridge.settings import ConnectionProfile

        class App:
            def set_event_sink(self, sink):
                pass

        ctl = ConnectionController(
            App(), ConnectionProfile(jid="alice@otrv4plus.i2p"),
            transport_factory=lambda *a, **k: None,
            prober=lambda _p, **_kw: SamProbe(True, "ok", "fine", "3.1"))
        got = ctl.change_password(OLD, NEW)
        assert set(got) == {"ok", "code", "detail", "value"}
        assert got["code"] == "network"

    def test_the_desktop_can_call_it(self):
        from desktop_bridge.host import CONTROLLER_OPS
        assert CONTROLLER_OPS["change_password"] == ("current_password", "new_password")
