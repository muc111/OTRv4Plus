# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The XMPP profile (vcard-temp): a fixed set of fields, each sanitised.

Owner's request, 2026-10-03: a Profile screen to "edit the entire xmpp
profile ... all fields which xmpp servers use", with the same rule as the
avatar -- nothing a peer wrote is trusted as-is.
"""
import json
import os
import sys
import threading
import xml.etree.ElementTree as ET

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from android_bridge import profile as P  # noqa: E402

Q = "{vcard-temp}"


def vcard(xml_body: str) -> ET.Element:
    return ET.fromstring('<vCard xmlns="vcard-temp">%s</vCard>' % xml_body)


class TestSanitising:

    def test_bidi_overrides_and_controls_are_removed(self):
        # "Bob" + RIGHT-TO-LEFT OVERRIDE + "gpj.exe" displays as "exe.jpg".
        assert P.clean_field("fn", "Bob‮gpj.exe") == "Bobgpj.exe"
        assert P.clean_field("nickname", "a\x00b\x07c​d⁦e") == "abcde"

    def test_newlines_only_in_the_note(self):
        assert P.clean_field("fn", "Al\nice") == "Al ice"
        assert P.clean_field("desc", "line one\n\n\n\nline two") == "line one\n\nline two"

    def test_lengths_are_capped(self):
        assert len(P.clean_field("fn", "x" * 5000)) == 100
        assert len(P.clean_field("desc", "y" * 5000)) == 1000

    @pytest.mark.parametrize("key,good,bad", [
        ("bday", "1990-04-01", "01/04/1990"),
        ("tel", "+44 (0)20 7946-0000", "call me; rm -rf /"),
        ("email", "alice@example.org", "alice at example"),
        ("url", "https://example.org/me", "javascript:alert(1)"),
        ("url", "http://otrv4plus.i2p/", "file:///etc/passwd"),
    ])
    def test_shaped_fields(self, key, good, bad):
        assert P.clean_field(key, good) == good
        assert P.clean_field(key, bad) == ""

    def test_unknown_fields_never_pass(self):
        assert P.clean_profile({"fn": "Alice", "PHOTO": "AAAA", "x": "y"}) == {"fn": "Alice"}
        assert P.clean_field("PHOTO", "anything") == ""

    def test_the_whole_profile_is_capped(self):
        values = {k: "z" * 1000 for k, *_ in P.FIELDS if k not in ("bday", "tel", "email", "url")}
        assert sum(len(v) for v in P.clean_profile(values).values()) <= P.MAX_TOTAL


class TestReadingAndWriting:

    def test_a_full_profile_round_trips(self):
        values = {"fn": "Alice Liddell", "given": "Alice", "family": "Liddell",
                  "nickname": "al", "bday": "1852-05-04", "email": "a@x.org",
                  "tel": "+44 1865 000000", "url": "https://x.org",
                  "org": "Christ Church", "title": "Reader", "role": "Muse",
                  "locality": "Oxford", "region": "Oxfordshire", "country": "UK",
                  "desc": "Down the rabbit hole.\nAnd back."}
        element = P.to_vcard(values)
        back = P.from_vcard(ET.fromstring(ET.tostring(element)))
        assert back == values
        # The type flags clients expect are present.
        assert element.find(Q + "EMAIL/" + Q + "INTERNET") is not None
        assert element.find(Q + "TEL/" + Q + "VOICE") is not None

    def test_a_received_photo_and_extras_are_ignored(self):
        got = P.from_vcard(vcard(
            "<FN>Mallory</FN><PHOTO><TYPE>image/jpeg</TYPE><BINVAL>/9j/AAA</BINVAL>"
            "</PHOTO><KEY><CRED>x</CRED></KEY><X-EVIL>boom</X-EVIL>"))
        assert got == {"fn": "Mallory"}

    def test_a_hostile_profile_is_cleaned(self):
        got = P.from_vcard(vcard(
            "<FN>%s</FN><BDAY>tomorrow</BDAY><URL>javascript:alert(1)</URL>"
            "<DESC>%s</DESC>" % ("A" * 100000, "‮" + "B" * 9000)))
        assert got == {"fn": "A" * 100, "desc": "B" * 1000}

    def test_no_vcard_is_an_empty_profile(self):
        assert P.from_vcard(None) == {}
        assert P.from_vcard(vcard("")) == {}

    def test_writing_drops_what_would_not_pass(self):
        element = P.to_vcard({"fn": "Bob", "bday": "soon", "PHOTO": "x"})
        tags = [child.tag for child in element]
        assert tags == [Q + "FN"]


class TestTheBridge:

    def _transport(self, reply_xml=None, error=None):
        from android_bridge import transport as T

        sent = []

        class Iq(dict):
            def __init__(self):
                super().__init__()
                self.children = []

            def append(self, el):
                self.children.append(el)

            async def send(self, timeout=None):
                sent.append(self)
                if error:
                    raise error
                r = type("R", (), {})()
                r.xml = ET.fromstring(reply_xml or "<iq xmlns='jabber:client'/>")
                return r

        class Client:
            def Iq(self):
                return Iq()

        import asyncio
        t = T.XmppTransport.__new__(T.XmppTransport)
        t._client = Client()
        t._connected = threading.Event()
        t._connected.set()
        t._run = lambda coro, timeout: asyncio.run(coro)
        return t, sent

    def test_get_sanitises_what_the_server_returns(self):
        t, sent = self._transport(
            "<iq xmlns='jabber:client'><vCard xmlns='vcard-temp'><FN>Bob‮X</FN>"
            "<PHOTO><BINVAL>AAA</BINVAL></PHOTO></vCard></iq>")
        assert t.get_profile("Bob@x.i2p/phone") == {"fn": "BobX"}
        assert sent[0]["type"] == "get" and sent[0]["to"] == "Bob@x.i2p"

    def test_set_publishes_only_clean_fields(self):
        t, sent = self._transport()
        published = t.set_profile({"fn": "Alice", "url": "javascript:x", "PHOTO": "y"})
        assert published == {"fn": "Alice"}
        assert sent[0]["type"] == "set"
        assert [c.tag for c in sent[0].children[0]] == [Q + "FN"]

    def test_the_controller_speaks_json_and_lists_the_fields(self):
        from android_bridge.connection import ConnectionController
        t, _sent = self._transport(
            "<iq xmlns='jabber:client'><vCard xmlns='vcard-temp'><NICKNAME>al</NICKNAME>"
            "</vCard></iq>")
        ctl = ConnectionController.__new__(ConnectionController)
        ctl._transport = t
        got = ctl.profile_get_json("")
        assert got["ok"] and json.loads(got["value"]) == {"nickname": "al"}
        saved = ctl.profile_set_json(json.dumps({"fn": "Alice", "tel": "nope"}))
        assert saved["ok"] and json.loads(saved["value"]) == {"fn": "Alice"}
        assert ctl.profile_set_json("[1,2]")["code"] == "bad_request"
        fields = ctl.profile_fields()
        assert fields[0] == "fn\tFull name\t100\t0"
        assert "desc\tAbout me\t1000\t1" in fields
