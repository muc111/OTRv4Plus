# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Wipe & Exit, opt-in: delete the account on the server (XEP-0077).

The order: keys destroyed in Rust first, then the server is asked over the
live session, then the transport closes. Never asked unless the user ticked
it; never a reason for the wipe to wait long or stop."""
from __future__ import annotations

import asyncio
import os
import tempfile
import xml.etree.ElementTree as ET

import pytest

otr = pytest.importorskip("otrv4_")
pytest.importorskip("slixmpp")

from android_bridge.app import OtrApp, Transport                    # noqa: E402
from test_android_sync import FakeStanza, transport                 # noqa: E402


def _manager():
    d = tempfile.mkdtemp()
    config = otr.OTRConfig(test_mode=True)
    for attribute, name in (("trust_db_path", "trust.json"), ("smp_secrets_path", "smp.json"),
                            ("key_storage_path", "keys")):
        setattr(config, attribute, os.path.join(d, name))
    return otr.EnhancedSessionManager(config=config)


def test_the_transport_sends_the_xep0077_remove():
    t, c, _ = transport()
    asked = []

    def answer(iq):
        asked.append(iq)

        async def ok():
            return FakeStanza(c, ET.Element("{jabber:client}iq", {"type": "result"}))
        return ok()
    c.answer = answer
    assert t.delete_account(timeout=1) == "deleted"
    q = asked[0].find("{jabber:iq:register}query")
    assert asked[0].get("type") == "set" and q.find("{jabber:iq:register}remove") is not None
    assert asked[0].get("to") is None, "the account's own server, nobody else"


def test_refusal_silence_and_offline_are_reported_not_raised():
    t, c, _ = transport()

    class IqError(Exception):
        pass

    def refuse(iq):
        async def no():
            raise IqError("not-allowed")
        return no()
    c.answer = refuse
    assert t.delete_account(timeout=1) == "refused"

    def silence(iq):
        async def wait():
            raise asyncio.TimeoutError()
        return wait()
    c.answer = silence
    assert t.delete_account(timeout=1) == "unconfirmed"
    t._connected.clear()
    assert t.delete_account(timeout=1) == "offline"


class Wire(Transport):
    def __init__(self, log):
        self.log = log

    def send(self, peer, payload): pass
    def connect(self): pass
    def disconnect(self): self.log.append("closed")
    def close(self): self.log.append("closed")
    def roster(self): return []

    def delete_account(self, timeout=None):
        self.log.append("delete_account")
        return "deleted"


def test_rust_first_then_the_server_then_the_transport_closes():
    log = []
    app = OtrApp(_manager(), Wire(log))
    real = app.wipe_crypto

    def crypto():
        log.append("rust")
        return real()
    app.wipe_crypto = crypto
    report = app.wipe(delete_account=True)
    assert log[:3] == ["rust", "delete_account", "closed"]
    assert report["server_account"] == "deleted"


def test_never_asked_unless_ticked():
    log = []
    app = OtrApp(_manager(), Wire(log))
    report = app.wipe()
    assert "delete_account" not in log
    assert report["server_account"] == "not_requested"


def test_no_connection_means_offline_and_the_wipe_still_completes():
    app = OtrApp(_manager(), None)
    report = app.wipe(delete_account=True)
    assert report["server_account"] == "offline"


def test_the_desktop_host_passes_the_choice():
    from desktop_bridge.host import Host
    calls = []

    class Target:
        def wipe(self, delete_account=False):
            calls.append(delete_account)
            return {"ok": True}

    h = Host.__new__(Host)
    h.controller, h.app = Target(), None
    import threading
    h._stop = threading.Event()
    h.call("wipe", {"delete_account": True})
    h.call("wipe", {})
    assert calls == [True, False]
