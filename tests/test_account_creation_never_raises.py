# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Create account answers with a code; it never raises into Kotlin.

Handset report, 2026-10-27: Create account on Android said only
"The account could not be created (PyException)". Kotlin calls
`controller_for` (which binds the account's identity and contact pins, F3
and P1) and then `register`; anything either raised crossed Chaquopy as a
bare PyException, and the service kept only the class name. Now:
  * a bind that is refused (`identity_unavailable`, `trust_unavailable`) is
    carried by the controller, and `register` and `connect` answer that code
    and a sentence, with no transport built and nothing sent;
  * `register` keeps its own "never raises" promise for anything else;
  * the Android sequence -- the stores Kotlin attaches, `controller_for`,
    `register` -- returns a result for a new account on every route.
"""
from __future__ import annotations

import os
import tempfile

import pytest

import test_smp_end_to_end as E

otr = E.otr
pytest.importorskip("otrv4_core")

from android_bridge import connection as C  # noqa: E402
from android_bridge.app_base import BridgeError  # noqa: E402


@pytest.fixture
def home(monkeypatch):
    root = tempfile.mkdtemp(prefix="otrv4plus-create-")
    monkeypatch.setenv("HOME", root)
    return root


class _RefusingApp:
    def __init__(self, code):
        self.code = code

    def bind_identity_account(self, jid):
        raise BridgeError(self.code, "lower-level detail")

    def set_event_sink(self, sink):
        pass


@pytest.mark.parametrize("code", ["identity_unavailable", "trust_unavailable"])
def test_a_refused_bind_answers_create_account_with_its_code(code):
    built = []
    ctl = C.controller_for(_RefusingApp(code), "new@example.i2p")
    ctl._transport_factory = lambda *a, **kw: built.append(a) or pytest.fail("built")
    result = ctl.register("correct horse battery staple 9")
    assert result["ok"] is False and result["code"] == code
    assert "not been replaced" in result["detail"]
    assert built == [], "a transport was built for a refused account"


@pytest.mark.parametrize("code", ["identity_unavailable", "trust_unavailable"])
def test_a_refused_bind_answers_log_in_with_its_code(code):
    ctl = C.controller_for(_RefusingApp(code), "old@example.i2p")
    ctl._transport_factory = lambda *a, **kw: pytest.fail("built")
    result = ctl.connect("correct horse battery staple 9")
    assert result["ok"] is False and result["code"] == code


def test_register_never_raises_even_when_its_own_steps_do(monkeypatch):
    ctl = C.ConnectionController(object(), C.ConnectionProfile(jid="new@example.i2p"))

    def boom():
        raise RuntimeError("password hunter2 in the text")

    monkeypatch.setattr(ctl, "_gate_route", boom)
    result = ctl.register("hunter2")
    assert result["ok"] is False and result["code"]
    assert "hunter2" not in repr(result)
    assert ctl.register("hunter2")["ok"] is False, "not left marked as running"


class _KeystoreLikeVault:
    """KeystoreVault's contract: get -> bytes or None, put, remove."""

    def __init__(self):
        self.records = {}

    def put(self, name, data):
        self.records[name] = bytes(data)

    def get(self, name):
        return self.records.get(name)

    def remove(self, name):
        self.records.pop(name, None)


@pytest.mark.parametrize("jid,server", [
    ("newuser@otrv4plus.i2p", ""), ("newuser@example.i2p", ""),
    ("newuser@example.com", "127.0.0.1"), ("New User@otrv4plus.i2p", ""),
])
def test_the_android_sequence_returns_a_result_for_a_new_account(home, jid, server):
    from android_bridge import account_identity, account_trust
    from android_bridge import app as appmod
    app = appmod.OtrApp(otr.EnhancedSessionManager(otr.OTRConfig()))
    app.use_identity_store(account_identity.for_android(_KeystoreLikeVault()))
    app.use_trust_store(account_trust.for_android(_KeystoreLikeVault(), True))
    ctl = C.controller_for(app, jid, server, "127.0.0.1", 1)     # no router there
    result = ctl.register("correct horse battery staple 9")
    assert isinstance(result, dict) and result["ok"] is False and result["code"]


def test_android_reports_a_failure_by_its_code_not_its_class():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    src = open(os.path.join(root, "android", "app", "src", "main", "java", "org", "otrv4plus",
                            "android", "connection", "OtrConnectionService.kt"),
               encoding="utf-8").read()
    body = src[src.index("private fun codeOf(t: Throwable)"):][:220]
    assert "OtrBridgeException.reportableCode(t)" in body
    assert body.index("reportableCode(t)") < body.index("simpleName"), \
        "the code first, the class name only as the fallback"


@pytest.mark.parametrize("code", ["identity_unavailable", "trust_unavailable"])
def test_the_desktop_host_answers_create_account_with_the_code_too(code):
    from desktop_bridge import host as H
    host = H.Host(lambda *a: None, app_factory=lambda: _RefusingApp(code),
                  controller_factory=C.controller_for)
    host.app = host._app_factory()
    host.call("prepare", {"jid": "new@example.i2p"})
    result = host.call("register", {"password": "correct horse battery staple 9"})
    assert result["ok"] is False and result["code"] == code
