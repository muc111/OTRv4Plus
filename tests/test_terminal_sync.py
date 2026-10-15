# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The terminal client's carbons, history, blocking, replies and reactions
(otrv4plus_termsync), with real OTRv4 engines where it matters."""
from __future__ import annotations

import os
import tempfile
import xml.etree.ElementTree as ET

import pytest

otr = pytest.importorskip("otrv4_")
pytest.importorskip("otrv4_core")
pytest.importorskip("slixmpp")

import otrv4plus_actions as A                                     # noqa: E402
import otrv4plus_xmpp as X                                        # noqa: E402
from xmpp_double import bare_client                               # noqa: E402

ALICE, BOB = "alice@t.test", "bob@t.test"


def _manager():
    d = tempfile.mkdtemp()
    config = otr.OTRConfig(test_mode=True)
    for attribute, name in (("trust_db_path", "trust.json"),
                            ("smp_secrets_path", "smp.json"),
                            ("key_storage_path", "keys")):
        if hasattr(config, attribute):
            setattr(config, attribute, os.path.join(d, name))
    return otr.EnhancedSessionManager(config=config)


def _relay(current, a, b, a_id, b_id):
    for _ in range(10):
        if not current:
            return
        out = b.handle_incoming_message(a_id, current)
        text = out.decode() if isinstance(out, (bytes, bytearray)) else out
        if not text or not text.startswith("?OTRv4"):
            return
        current = text
        a, b = b, a
        a_id, b_id = b_id, a_id


@pytest.fixture
def pair():
    otr._dake1_rate_limiter._attempts.clear()
    am, bm = _manager(), _manager()
    dake1, _ = am.handle_outgoing_message(BOB, "")
    _relay(dake1, am, bm, ALICE, BOB)
    alice, bob = bare_client(X.OTRv4PlusXMPP), bare_client(X.OTRv4PlusXMPP)
    alice.otr, bob.otr = am, bm
    for c in (alice, bob):
        c._ts_install()
    return alice, bob


def test_a_typed_message_and_its_id_arrive_together(pair):
    alice, bob = pair
    frame, ok, mid = alice._ts_encrypt(BOB, "hello")
    assert ok and mid and frame.startswith("?OTRv4")
    out, meta = bob._ts_decrypt(ALICE, frame)
    assert out in (b"hello", "hello")
    assert meta["id"] == mid and meta["action"] == ""


def test_an_action_frame_is_authenticated_and_carries_no_stray_meta(pair):
    alice, bob = pair
    frame = alice.otr.send_text_with_tlv(
        BOB, "", A.META_TLV, A.encode_meta("R1", react="M0", emojis=["ok"]))
    out, meta = bob._ts_decrypt(ALICE, frame)
    assert meta["action"] == "react" and meta["emojis"] == ["ok"]
    # The next, plain frame does not inherit it.
    plain, _ = alice.otr.handle_outgoing_message(BOB, "no meta")
    out, meta = bob._ts_decrypt(ALICE, plain if isinstance(plain, str) else plain.decode())
    assert meta is None


def test_otr_frames_get_the_private_hints_and_nothing_else_does():
    c = bare_client(X.OTRv4PlusXMPP)

    class St:
        def __init__(self, body):
            self.xml = ET.Element("{jabber:client}message")
            ET.SubElement(self.xml, "{jabber:client}body").text = body

    otr_msg, chat = St("?OTRv4 AAAA"), St("hi")
    assert c._ts_out_filter(otr_msg) is otr_msg
    assert c._ts_out_filter(chat) is chat
    tags = {e.tag for e in otr_msg.xml}
    assert "{urn:xmpp:carbons:2}private" in tags
    assert "{urn:xmpp:hints}no-permanent-store" in tags
    assert {e.tag for e in chat.xml} == {"{jabber:client}body"}
    c._ts_out_filter(otr_msg)                       # not added twice
    assert [e.tag for e in otr_msg.xml].count("{urn:xmpp:carbons:2}private") == 1


def test_the_author_rule_and_what_is_printed(capsys):
    c = bare_client(X.OTRv4PlusXMPP)
    c._ts_remember(BOB, "M1", "my words", True)
    c._ts_remember(BOB, "T1", "teh", False)
    c._ts_show_action(BOB, "edit", "M1", "I owe you", [])
    assert "ignored" in capsys.readouterr().out
    c._ts_show_action(BOB, "edit", "T1", "the", [])
    out = capsys.readouterr().out
    assert "[edited]" in out and '"teh"' in out
    c._ts_show_action(BOB, "react", "M1", "", ["\U0001F44D"])
    assert "\U0001F44D" in capsys.readouterr().out


def test_commands_need_something_to_act_on(capsys):
    c = bare_client(X.OTRv4PlusXMPP)
    assert c._ts_command("/edit fixed", BOB)
    assert "usage" in capsys.readouterr().out
    assert c._ts_command("/react", BOB)
    assert not c._ts_command("/hello", BOB)


def test_an_action_never_goes_in_the_clear_to_an_otr_conversation(capsys):
    c = bare_client(X.OTRv4PlusXMPP)
    c._encrypted = set()
    c._otr_capable = {BOB}
    c._otr_mode = X._OtrMode()
    sent = []
    c.make_message = lambda **kw: sent.append(kw)
    c._ts_remember(BOB, "T1", "theirs", False)
    c._ts_command("/react \U0001F44D", BOB)
    assert sent == [] and "waiting for encryption" in capsys.readouterr().out
