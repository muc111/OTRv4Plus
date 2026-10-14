# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""otrv4plus_sync: carbons, the archive, ids, receipts -- the rules.

Owner (2026-10-14): "we must add message carbons and server side message
history xep-0313 and anything else conversations app uses".
"""
from __future__ import annotations

import os
import tempfile
import xml.etree.ElementTree as ET

import otrv4plus_sync as S

ME = "alice@example.i2p"
BOB = "bob@example.i2p"


def X(text: str) -> ET.Element:
    return ET.fromstring(text)


def msg(frm, to, body, extra="", mtype="chat", mid="m1"):
    return ("<message xmlns='jabber:client' from='%s' to='%s' type='%s' id='%s'>"
            "<body>%s</body>%s</message>" % (frm, to, mtype, mid, body, extra))


# -- XEP-0359 ids --------------------------------------------------------------

def test_only_our_own_servers_stanza_id_is_trusted():
    good = S.parse_message(X(msg(BOB + "/phone", ME, "hi",
        "<stanza-id xmlns='urn:xmpp:sid:0' by='%s' id='A1'/>" % ME)), ME)
    forged = S.parse_message(X(msg(BOB + "/phone", ME, "hi",
        "<stanza-id xmlns='urn:xmpp:sid:0' by='%s' id='A1'/>" % BOB)), ME)
    assert good.stanza_id == "A1"
    assert forged.stanza_id == ""


def test_direction_peer_and_ids():
    out = S.parse_message(X(msg(ME + "/laptop", BOB + "/phone", "yo",
        "<origin-id xmlns='urn:xmpp:sid:0' id='O9'/>"
        "<request xmlns='urn:xmpp:receipts'/><markable xmlns='urn:xmpp:chat-markers:0'/>")), ME)
    assert (out.direction, out.peer, out.origin_id, out.ref) == ("out", BOB, "O9", "O9")
    assert out.receipt_request and out.markable
    inn = S.parse_message(X(msg(BOB + "/phone", ME, "yo")), ME)
    assert (inn.direction, inn.peer, inn.full_jid) == ("in", BOB, BOB + "/phone")


def test_rooms_and_messages_to_ourselves_are_not_1to1():
    assert S.parse_message(X(msg("room@muc.x/bob", ME, "hi", mtype="groupchat")), ME) is None
    assert S.parse_message(X(msg(ME + "/a", ME + "/b", "note")), ME) is None


def test_new_ids_are_random_and_say_nothing():
    a, b = S.new_message_id(), S.new_message_id()
    assert a != b and len(a) == 32 and ME not in a


# -- XEP-0280 carbons ----------------------------------------------------------

def carbon(kind, inner, frm=ME):
    return X("<message xmlns='jabber:client' from='%s' to='%s/phone'>"
             "<%s xmlns='urn:xmpp:carbons:2'><forwarded xmlns='urn:xmpp:forward:0'>"
             "%s</forwarded></%s></message>" % (frm, ME, kind, inner, kind))


def test_a_sent_carbon_is_our_message_from_another_device():
    item = S.unwrap_carbon(carbon("sent", msg(ME + "/laptop", BOB, "from laptop")), ME)
    assert item.direction == "out" and item.source == "carbon" and item.peer == BOB
    assert S.classify(item) == S.SHOW_OUT


def test_a_received_carbon_is_a_message_to_another_device():
    item = S.unwrap_carbon(carbon("received", msg(BOB + "/phone", ME + "/laptop", "hey")), ME)
    assert item.direction == "in" and S.classify(item) == S.SHOW_IN


def test_a_carbon_from_anyone_else_is_a_forgery():
    forged = carbon("sent", msg(ME + "/laptop", BOB, "I owe you 100"), frm=BOB + "/x")
    assert S.unwrap_carbon(forged, ME) is None


def test_a_carbon_whose_direction_disagrees_is_dropped():
    # "sent" wrapping a message that is not from us.
    assert S.unwrap_carbon(carbon("sent", msg(BOB + "/x", ME, "trick")), ME) is None
    assert S.unwrap_carbon(carbon("received", msg(ME + "/x", BOB, "trick")), ME) is None


def test_an_otr_frame_from_a_copy_never_reaches_the_screen_or_the_engine():
    for body in ("?OTRv4 AAAA", "?OTRv4F|1|1|2|xx", "?OTR?v4?", "?OTR Error: x"):
        item = S.unwrap_carbon(carbon("received", msg(BOB + "/p", ME + "/l", body)), ME)
        assert S.classify(item) == S.ELSEWHERE
    live = S.parse_message(X(msg(BOB + "/p", ME, "?OTRv4 AAAA")), ME)
    assert S.classify(live) == S.ENGINE     # live traffic: unchanged


def test_empty_and_oversized_copies_are_skipped():
    empty = S.unwrap_carbon(carbon("received", msg(BOB + "/p", ME, "")), ME)
    assert S.classify(empty) == S.SKIP
    big = S.unwrap_carbon(carbon("received", msg(BOB + "/p", ME, "x" * (S.MAX_BODY + 1))), ME)
    assert S.classify(big) == S.SKIP


def test_the_otr_whitespace_tag_is_stripped():
    tagged = "hello" + " \t  \t\t\t\t \t \t \t  " + "  \t\t  \t\t"
    assert S.strip_whitespace_tag(tagged) == "hello"
    assert S.strip_whitespace_tag("plain  text\t") == "plain  text\t"


# -- XEP-0313 archive ----------------------------------------------------------

def result(inner, archive_id="R1", frm=None, qid="q1", stamp="2026-10-14T09:30:00Z"):
    f = (" from='%s'" % frm) if frm else ""
    return X("<message xmlns='jabber:client'%s to='%s/phone'>"
             "<result xmlns='urn:xmpp:mam:2' queryid='%s' id='%s'>"
             "<forwarded xmlns='urn:xmpp:forward:0'>"
             "<delay xmlns='urn:xmpp:delay' stamp='%s'/>%s</forwarded></result></message>"
             % (f, ME, qid, archive_id, stamp, inner))


def test_an_archived_message_carries_its_time_and_archive_id():
    got = S.parse_archive_result(result(msg(BOB + "/p", ME, "while you were away")), ME, "q1")
    archive_id, item = got
    assert archive_id == "R1" and item.stanza_id == "R1" and item.source == "archive"
    assert item.when == S.parse_stamp("2026-10-14T09:30:00Z")
    assert S.classify(item) == S.SHOW_IN


def test_someone_elses_archive_or_query_is_refused():
    assert S.parse_archive_result(result(msg(BOB, ME, "x"), frm=BOB), ME, "q1") is None
    assert S.parse_archive_result(result(msg(BOB, ME, "x"), qid="other"), ME, "q1") is None
    assert S.parse_archive_result(result(msg(BOB, ME, "x"), frm=ME), ME, "q1") is not None


def test_archive_plan_newest_page_first_then_after_the_cursor():
    assert S.archive_plan("") == {"max": S.FIRST_PAGE, "before": ""}
    assert S.archive_plan("R7") == {"max": S.PAGE, "after": "R7"}


def test_stamps():
    assert S.parse_stamp("2026-10-14T10:00:00+01:00") == S.parse_stamp("2026-10-14T09:00:00Z")
    assert S.parse_stamp("2026-10-14T09:00:00.250Z") == S.parse_stamp("2026-10-14T09:00:00Z") + 0.25
    assert S.parse_stamp("yesterday") is None


# -- dedupe and the cursor -----------------------------------------------------

def test_the_same_message_live_as_a_carbon_and_archived_is_seen_once():
    seen = S.Seen()
    live = S.parse_message(X(msg(BOB + "/p", ME, "hi",
        "<origin-id xmlns='urn:xmpp:sid:0' id='O1'/>"
        "<stanza-id xmlns='urn:xmpp:sid:0' by='%s' id='A1'/>" % ME)), ME)
    archived = S.parse_archive_result(result(msg(BOB + "/p", ME, "hi",
        "<origin-id xmlns='urn:xmpp:sid:0' id='O1'/>"), archive_id="A1"), ME, "q1")[1]
    assert seen.first_time(live)
    assert not seen.first_time(archived)
    other = S.parse_message(X(msg(BOB + "/p", ME, "hi", mid="m2")), ME)
    assert seen.first_time(other)


def test_the_cursor_is_per_account_private_and_opaque():
    path = os.path.join(tempfile.mkdtemp(), "sync", "cursor.json")
    c = S.ArchiveCursor(path)
    assert c.get(ME) == ""
    c.set(ME, "R42")
    c.set(BOB, "R7")
    assert (c.get(ME), c.get(BOB)) == ("R42", "R7")
    text = open(path).read()
    assert ME not in text and BOB not in text
    assert oct(os.stat(path).st_mode & 0o777) == "0o600"
    c.forget()
    assert c.get(ME) == ""


# -- what we put on our own messages -----------------------------------------

def test_otr_frames_are_kept_off_other_devices_and_out_of_the_archive():
    tags = {e.tag for e in S.otr_hints()}
    assert "{urn:xmpp:carbons:2}private" in tags
    assert "{urn:xmpp:hints}no-copy" in tags
    assert "{urn:xmpp:hints}no-permanent-store" in tags
    # Offline storage is still allowed: the contact may be away a minute.
    assert "{urn:xmpp:hints}no-store" not in tags


def test_a_typed_message_asks_for_receipts_and_carries_its_id():
    els = S.user_message_extras("ID1")
    tags = [e.tag for e in els]
    assert "{urn:xmpp:sid:0}origin-id" in tags and els[0].get("id") == "ID1"
    assert "{urn:xmpp:receipts}request" in tags
    assert "{urn:xmpp:chat-markers:0}markable" in tags
    assert "{http://jabber.org/protocol/chatstates}active" in tags
    quiet = [e.tag for e in S.user_message_extras("ID1", chat_states=False)]
    assert "{http://jabber.org/protocol/chatstates}active" not in quiet


def test_receipts_markers_and_chat_states_are_read():
    r = X("<message xmlns='jabber:client' from='%s/p'><received xmlns='urn:xmpp:receipts' id='ID1'/></message>" % BOB)
    assert S.receipt_of(r) == "ID1"
    m = X("<message xmlns='jabber:client' from='%s/p'><displayed xmlns='urn:xmpp:chat-markers:0' id='ID2'/></message>" % BOB)
    assert S.marker_of(m) == ("displayed", "ID2")
    c = X("<message xmlns='jabber:client' from='%s/p'><composing xmlns='http://jabber.org/protocol/chatstates'/></message>" % BOB)
    assert S.chat_state_of(c) == "composing"
