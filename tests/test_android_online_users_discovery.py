# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Who is online on the server: asked of the server, never guessed.

A roster is not a directory. The only standard way for a client to ask an
XMPP server who is online is XEP-0133 `get-online-users-list`, which Prosody
serves through `mod_admin_adhoc` -- to admin accounts only. So discovery:

  * asks the server which ad-hoc commands it offers this account;
  * runs the online-users command only when it is offered, and reports the
    server's own answer;
  * otherwise says "none" and returns NO users. It never probes, enumerates
    or invents JIDs.

The stanza shapes in `PROSODY_*` are Prosody's (mod_admin_adhoc, 0.12):
a form asking `max_items`, then a completed form with `onlineuserjids`.
"""

import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from android_bridge.transport import XmppTransport
from tests.test_android_rooms import FakeDisco, IqError, build

slixmpp = pytest.importorskip("slixmpp")
from slixmpp.xmlstream import ET  # noqa: E402

DOMAIN = "xmpp-elite.i2p"
NODE = XmppTransport.ONLINE_USERS_NODE

PROSODY_FORM = """
<iq xmlns="jabber:client" type="result" from="{d}" id="1">
 <command xmlns="http://jabber.org/protocol/commands" node="{n}"
          sessionid="s-1" status="executing">
  <actions execute="complete"><complete/></actions>
  <x xmlns="jabber:x:data" type="form">
   <field type="hidden" var="FORM_TYPE">
    <value>http://jabber.org/protocol/admin</value></field>
   <field type="list-single" var="max_items" label="Maximum number of users">
    <option><value>25</value></option>
    <option><value>50</value></option>
    <option><value>all</value></option>
    <value>25</value></field>
   <field type="boolean" var="details"><value>0</value></field>
  </x>
 </command>
</iq>""".format(d=DOMAIN, n=NODE)

PROSODY_DONE = """
<iq xmlns="jabber:client" type="result" from="{d}" id="2">
 <command xmlns="http://jabber.org/protocol/commands" node="{n}"
          sessionid="s-1" status="completed">
  <x xmlns="jabber:x:data" type="result">
   <field type="hidden" var="FORM_TYPE">
    <value>http://jabber.org/protocol/admin</value></field>
   <field type="text-multi" var="onlineuserjids">
    <value>bob@{d}/phone</value>
    <value>Carol@{d}/laptop</value>
    <value>bob@{d}/tablet</value>
    <value>not-a-jid</value>
   </field>
  </x>
 </command>
</iq>""".format(d=DOMAIN, n=NODE)


def stanza(xml):
    client = slixmpp.ClientXMPP("alice@%s" % DOMAIN, "pw")
    client.register_plugin("xep_0004")
    client.register_plugin("xep_0050")
    return client.Iq(xml=ET.fromstring(xml)), client


class FakeCommands:
    """slixmpp XEP_0050.send_command, answering like Prosody."""

    def __init__(self, replies):
        self.replies = list(replies)
        self.sent = []

    async def send_command(self, jid, node, ifrom=None, action="execute",
                           payload=None, sessionid=None, **_kw):
        self.sent.append({"jid": str(jid), "node": node, "action": action,
                          "payload": payload, "sessionid": sessionid})
        return self.replies.pop(0)


class OfferingDisco(FakeDisco):
    def __init__(self, nodes=(), fail=None):
        super().__init__(fail=fail)
        self.nodes = list(nodes)
        self.nodes_asked = []

    async def get_items(self, jid=None, node=None, timeout=None, **kw):
        self.asked.append(str(jid))
        self.nodes_asked.append(node)
        if self._fail is not None:
            raise self._fail
        from tests.test_android_rooms import Items
        return Items([(str(jid), n, "") for n in self.nodes])


def with_commands(disco, commands):
    t, made = build(disco=disco)
    client = made["client"]
    client.plugins["xep_0050"] = commands
    real_forms = stanza(PROSODY_FORM)[1]
    client.plugins["xep_0004"] = real_forms.plugin["xep_0004"]
    return t, made


class TestTheServersAnswerIsUsed:

    def test_prosody_admin_command_lists_online_bare_jids(self):
        form, _ = stanza(PROSODY_FORM)
        done, _ = stanza(PROSODY_DONE)
        commands = FakeCommands([form, done])
        t, _ = with_commands(OfferingDisco([NODE]), commands)
        try:
            code, _detail, value = t.discover_online_users()
        finally:
            t.close()
        assert code == "ok"
        assert value["mechanism"] == "xep-0133"
        # Bare, case-folded, de-duplicated across resources; junk dropped.
        assert value["users"] == ["bob@%s" % DOMAIN, "carol@%s" % DOMAIN]

    def test_the_form_is_submitted_with_the_servers_own_session(self):
        form, _ = stanza(PROSODY_FORM)
        done, _ = stanza(PROSODY_DONE)
        commands = FakeCommands([form, done])
        t, _ = with_commands(OfferingDisco([NODE]), commands)
        try:
            t.discover_online_users()
        finally:
            t.close()
        first, second = commands.sent
        assert first["action"] == "execute" and first["jid"] == DOMAIN
        assert second["action"] == "complete"
        assert second["sessionid"] == "s-1"
        submitted = second["payload"]
        assert submitted["type"] == "submit"
        assert submitted.get_fields()["max_items"]["value"] == "all"
        # The hidden FORM_TYPE goes back exactly as the server sent it.
        assert "<value>http://jabber.org/protocol/admin</value>" in str(submitted)


class TestNothingIsInvented:

    def test_not_offered_means_no_users_and_no_command(self):
        commands = FakeCommands([])
        t, made = with_commands(
            OfferingDisco(["http://jabber.org/protocol/rc#set-status"]),
            commands)
        try:
            code, _detail, value = t.discover_online_users()
        finally:
            t.close()
        assert code == "ok"
        assert value["mechanism"] == "none"
        assert value["users"] == []
        assert commands.sent == [], "ran a command the server did not offer"
        assert made["client"]["xep_0030"].nodes_asked == [
            XmppTransport.COMMANDS_NODE]

    def test_a_refusal_is_a_code_not_a_list(self):
        t, _ = with_commands(
            OfferingDisco(fail=IqError("forbidden")), FakeCommands([]))
        try:
            code, _detail, value = t.discover_online_users()
        finally:
            t.close()
        assert code != "ok"
        assert value is None

    def test_an_unfinished_command_lists_nobody(self):
        form, _ = stanza(PROSODY_FORM)
        assert XmppTransport._jids_from_command(form) is None

    def test_only_the_asked_domain_is_ever_addressed(self):
        """No per-user probing: one disco#items on our own server."""
        disco = OfferingDisco([])
        t, _ = with_commands(disco, FakeCommands([]))
        try:
            t.discover_online_users()
        finally:
            t.close()
        assert disco.asked == [DOMAIN]


class TestTheControllerPassesItThrough:

    def test_connection_exposes_it(self):
        from android_bridge import connection
        assert hasattr(connection.ConnectionController, "discover_online_users")
