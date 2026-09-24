#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Server-side deletion: what the server says, and nothing more.

"Delete chat" on Android deletes locally. Whether the server keeps a copy is
a question for the server, asked with disco#info, and the answer is reported
to the user, never acted on. No XEP lets a client delete a server archive, so
there is nothing to act with. These tests hold:

* the probe reads the features a server advertises and reports them;
* a server that advertises nothing is reported as nothing, not as "deleted";
* a failed probe is a failure code, not a false "no archive";
* the probe never sends anything that would change server state -- it is
  one disco#info query, and destroying a room is not reachable from it.
"""

import asyncio
import threading
import types

import pytest

from android_bridge.transport import XmppTransport


class _Disco:
    def __init__(self, features, fail=False):
        self.features = features
        self.fail = fail
        self.asked = []

    async def get_info(self, jid=None, timeout=None):
        self.asked.append(jid)
        if self.fail:
            raise TimeoutError("no answer")
        return {"disco_info": {"features": list(self.features)}}


class _Muc:
    def __init__(self):
        self.destroyed = []

    async def destroy(self, room, reason="", timeout=None):
        self.destroyed.append(room)


def _transport(features, fail=False):
    t = XmppTransport.__new__(XmppTransport)
    disco, muc = _Disco(features, fail), _Muc()
    client = {"xep_0030": disco, "xep_0045": muc}
    t._client = _Client(client, "me@example.test")
    return t, disco, muc


class _Client(dict):
    def __init__(self, plugins, bare):
        super().__init__(plugins)
        self.boundjid = types.SimpleNamespace(bare=bare, domain="example.test")


def test_an_archive_and_retraction_are_reported():
    t, disco, _ = _transport(["urn:xmpp:mam:2", "urn:xmpp:message-retract:1",
                              "http://jabber.org/protocol/disco#info"])
    found = asyncio.run(t._archive_support(""))
    assert found == {"mam": True, "retract": True, "moderate": False}
    # Our own account, when no JID is given: that is where a 1:1 archive is.
    assert disco.asked == ["me@example.test"]


def test_a_room_is_asked_about_itself():
    t, disco, _ = _transport(["urn:xmpp:mam:2", "urn:xmpp:message-moderate:1"])
    found = asyncio.run(t._archive_support("english@rooms.example.test"))
    assert found["mam"] and found["moderate"]
    assert disco.asked == ["english@rooms.example.test"]


def test_a_server_that_advertises_nothing_is_reported_as_nothing():
    t, _, _ = _transport(["http://jabber.org/protocol/disco#info"])
    assert asyncio.run(t._archive_support("")) == {
        "mam": False, "retract": False, "moderate": False}


def test_asking_never_destroys_a_room():
    t, _, muc = _transport(["urn:xmpp:mam:2"])
    asyncio.run(t._archive_support("english@rooms.example.test"))
    assert muc.destroyed == []


def test_the_controller_reports_a_failed_probe_as_a_failure():
    from android_bridge.connection import ConnectionController
    from android_bridge.settings import ConnectionProfile
    import otrv4_
    from android_bridge.app import OtrApp
    ctl = ConnectionController(
        OtrApp(otrv4_.EnhancedSessionManager(otrv4_.OTRConfig(test_mode=True)), None, None),
        ConnectionProfile(jid="me@example.test", server="example.test"))
    ctl._transport = types.SimpleNamespace(
        archive_support=lambda jid: ("timeout", "The server did not answer.", None))
    out = ctl.archive_support("")
    assert out["ok"] is False and out["code"] == "timeout"
    assert out["value"] is None      # not {"mam": False}: unknown is not "no"

    ctl._transport = None
    out = ctl.archive_support("")
    assert out["ok"] is False and out["code"] == "network"


def test_a_disconnected_transport_does_not_ask():
    t, disco, _ = _transport(["urn:xmpp:mam:2"])
    t._connected = threading.Event()          # not set: not connected
    code, _detail, value = t.archive_support("")
    assert code == "network" and value is None
    assert disco.asked == []


class _LeavingMuc:
    def __init__(self, nicks):
        self.our_nicks = dict(nicks)
        self.left = []
        self.destroyed = []

    def leave_muc(self, room, nick):
        self.left.append((room, nick))

    async def destroy(self, room, reason="", timeout=None):
        self.destroyed.append(room)


def test_delete_and_leave_uses_the_joined_nickname_and_never_destroys():
    t = XmppTransport.__new__(XmppTransport)
    muc = _LeavingMuc({"english@rooms.example.test": "me"})
    t._client = _Client({"xep_0045": muc}, "me@example.test")
    asyncio.run(t._leave_room("english@rooms.example.test", ""))
    assert muc.left == [("english@rooms.example.test", "me")]
    assert muc.destroyed == []


def test_leaving_a_room_not_joined_this_session_sends_nothing():
    t = XmppTransport.__new__(XmppTransport)
    muc = _LeavingMuc({})
    t._client = _Client({"xep_0045": muc}, "me@example.test")
    asyncio.run(t._leave_room("english@rooms.example.test", ""))
    assert muc.left == [] and muc.destroyed == []
