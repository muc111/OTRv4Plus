# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2025-2026 muc111
"""A DTD, or a stanza without end, never reaches the XML parser.

Red team 2026-11, R1: slixmpp feeds the socket to expat, and expat accepts a
DOCTYPE at the start of a stream and expands its entities. These tests hold
`android_bridge.xmlguard` to: every forbidden construct refused at every
possible split between reads, before the byte that decides it is passed on;
nothing a real stream contains refused; and the real client class closing
the connection instead of parsing.
"""
import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from android_bridge import xmlguard  # noqa: E402
from android_bridge.xmlguard import StreamGuard  # noqa: E402

HEADER = (b"<?xml version='1.0'?><stream:stream "
          b"xmlns:stream='http://etherx.jabber.org/streams' "
          b"xmlns='jabber:client' id='s1' version='1.0'>")
STANZAS = (b"<stream:features><starttls xmlns='urn:ietf:params:xml:ns:"
           b"xmpp-tls'/></stream:features>"
           b"<message from='a@x/1' to='b@x'><body>1 &lt; 2 &amp;&amp; "
           b"x&lt;!y \xe2\x9c\x93 a!b ?c</body></message>"
           b"<iq type='result' id='q?1'/>")


def feed(guard, data, cuts=()):
    """Feed `data` split at `cuts`; return (allowed, bytes passed on)."""
    passed = b""
    last = 0
    for cut in list(cuts) + [len(data)]:
        chunk = data[last:cut]
        last = cut
        if not guard.allows(chunk):
            return False, passed
        passed += chunk
    return True, passed


def every_split(data):
    yield ()
    for cut in range(1, len(data)):
        yield (cut,)


@pytest.mark.parametrize("stream", [
    HEADER + STANZAS,
    b"\xef\xbb\xbf" + HEADER + STANZAS,                    # UTF-8 BOM
    b"  \n" + HEADER[21:] + STANZAS,                       # no XML declaration
    HEADER + b"<message><body><![CDATA[<!DOCTYPE x [<!ENTITY a 'b'>]>]]>"
             b"</body></message>",
    HEADER + b"<message><body><![CDATA[]]]]><![CDATA[>]]></body></message>",
    HEADER + b"<!-- <!DOCTYPE x> <!ENTITY --><presence/>",
    b"<?xml version='1.0'?><?pi <!DOCTYPE x> ?>" + HEADER[21:],
])
def test_a_real_stream_passes_whole_at_every_split(stream):
    for cuts in every_split(stream):
        ok, passed = feed(StreamGuard(), stream, cuts)
        assert ok, cuts
        assert passed == stream


@pytest.mark.parametrize("attack", [
    b"<!DOCTYPE s [<!ENTITY a 'AAAA'>]>",
    b"<!DOCTYPE s SYSTEM 'http://example.invalid/x.dtd'>",
    b"<!ENTITY a 'b'>",
    b"<!ELEMENT a ANY>",
    b"<!ATTLIST a b CDATA #IMPLIED>",
    b"<!NOTATION n SYSTEM 'x'>",
    b"<![INCLUDE[ <!ENTITY a 'b'> ]]>",
    b"<![IGNORE[ x ]]>",
    b"<!doctype s>",
    b"<! DOCTYPE s>",
    b"<!-x>",
])
@pytest.mark.parametrize("before", [
    b"",
    b"<?xml version='1.0'?>",
    b"<?xml version='1.0'?>\n",
    HEADER + STANZAS,
    HEADER + b"<!-- c --><![CDATA[x]]>",
])
def test_a_declaration_is_refused_before_its_deciding_byte(attack, before):
    stream = before + attack + HEADER
    for cuts in every_split(stream):
        guard = StreamGuard()
        ok, passed = feed(guard, stream, cuts)
        assert not ok, cuts
        assert guard.reason == "declaration"
        # What the parser was given stops short of the declaration: at most
        # `<!` and a prefix that could still have been a comment or CDATA.
        tail = passed[len(before):]
        assert (b"<!--".startswith(tail) or b"<![CDATA[".startswith(tail)), (
            cuts, tail)


def test_another_encoding_cannot_carry_the_markup_past_the_scan():
    doc = "<!DOCTYPE s [<!ENTITY a 'b'>]><s>&a;</s>"
    for codec in ("utf-16", "utf-16-le", "utf-16-be", "utf-32"):
        guard = StreamGuard()
        assert not guard.allows(doc.encode(codec)), codec
        assert guard.reason == "nul_byte"
    # An 8-bit encoding expat accepts keeps ASCII where it is.
    latin = b"<?xml version='1.0' encoding='iso-8859-1'?>" + doc.encode()
    guard = StreamGuard()
    assert not guard.allows(latin)
    assert guard.reason == "declaration"


def test_a_nul_byte_is_refused():
    guard = StreamGuard()
    assert guard.allows(HEADER)
    assert not guard.allows(b"<message>\x00</message>")


def test_refused_stays_refused_until_the_stream_restarts():
    guard = StreamGuard()
    assert not guard.allows(b"<!DOCTYPE s>")
    assert not guard.allows(HEADER)
    guard.reset()
    assert guard.reason is None
    assert guard.allows(HEADER)


def test_text_is_accepted_as_well_as_bytes():
    guard = StreamGuard()
    assert guard.allows(HEADER.decode())
    assert not guard.allows("<!DOCTYPE s>")


def test_the_scan_keeps_no_more_than_a_few_bytes():
    guard = StreamGuard()
    assert guard.allows(HEADER + b"<message><body>" + b"x" * 200_000)
    assert len(guard._carry) <= 8
    assert guard.allows(b"<![CDAT")
    assert len(guard._carry) <= 9


# ── on the real client class ────────────────────────────────────────────────

def _client():
    slixmpp = pytest.importorskip("slixmpp")

    class Guarded(xmlguard.GuardedStream, slixmpp.ClientXMPP):
        pass

    # On whatever loop slixmpp picks, as the other tests that build a real
    # client do: a loop set and closed here would be the "current" one for
    # every test after this file.
    client = Guarded("user@example.invalid/r", "pw")
    client.sent, client.aborted, client.refusals = [], [], []
    client.send_raw = lambda data, *a, **k: client.sent.append(data)
    client.abort = lambda: client.aborted.append(True)
    client.add_event_handler(xmlguard.REFUSED_EVENT, client.refusals.append)
    client.init_parser()
    return client, client.loop


def _spin(loop):
    loop.run_until_complete(asyncio.sleep(0))


def _close(client, loop):
    """Leave nothing for the garbage collector: slixmpp's `__del__` cancels
    the client's filter task, and a task cancelled with nobody running its
    loop is reported as destroyed while pending."""
    task = client._run_out_filters
    client._run_out_filters = None
    if task is not None and not task.done():
        task.cancel()
        loop.run_until_complete(asyncio.gather(task, return_exceptions=True))
    _spin(loop)


def test_expat_would_have_expanded_the_entity():
    """The reason for the guard, kept as a test: plain expat, as slixmpp
    drives it, accepts the DTD and expands what it declares."""
    from xml.etree import ElementTree as ET
    parser = ET.XMLPullParser(("start", "end"))
    parser.feed(b"<!DOCTYPE s [<!ENTITY a 'EXPANDED'>]><s><b>&a;</b></s>")
    texts = [el.text for event, el in parser.read_events() if event == "end"]
    assert "EXPANDED" in texts


def test_the_client_closes_instead_of_parsing_a_dtd():
    client, loop = _client()
    try:
        seen = []
        real_feed = client.parser.feed
        client.parser.feed = lambda data: (seen.append(bytes(data)),
                                           real_feed(data))[1]
        client.data_received(b"<?xml version='1.0'?>")
        client.data_received(b"<!DOCTYPE s [<!ENTITY a 'AAAA'>]>" + HEADER)
        client.data_received(STANZAS)          # after the refusal: dropped
        _spin(loop)
        assert client.aborted == [True]
        assert client.refusals == ["declaration"]
        assert b"".join(seen) == b"<?xml version='1.0'?>"
    finally:
        _close(client, loop)


def test_the_client_still_reads_a_normal_stream():
    client, loop = _client()
    try:
        got = []
        client.add_event_handler("message", got.append)
        stream = HEADER + STANZAS
        for at in range(0, len(stream), 7):
            client.data_received(stream[at:at + 7])
        _spin(loop)
        assert client.aborted == []
        assert len(got) == 1
        assert "x<!y" in got[0]["body"]
    finally:
        _close(client, loop)


def test_a_new_stream_gets_a_fresh_guard():
    """After STARTTLS and after SASL slixmpp starts a new document, where a
    DOCTYPE is possible again and a state left from the old one would be
    wrong."""
    client, loop = _client()
    try:
        client.data_received(HEADER + b"<message><body><![CDATA[ open")
        client.init_parser()
        client.data_received(b"<!DOCTYPE s>")
        _spin(loop)
        assert client.refusals == ["declaration"]
    finally:
        _close(client, loop)


def test_a_stanza_without_end_is_cut_off(monkeypatch):
    monkeypatch.setattr(xmlguard, "MAX_OPEN_STANZA_BYTES", 64 * 1024)
    client, loop = _client()
    try:
        client.data_received(HEADER + b"<message><body>")
        for _ in range(70):
            client.data_received(b"x" * 1024)
        _spin(loop)
        assert client.aborted == [True]
        assert client.refusals == ["stanza_too_large"]
    finally:
        _close(client, loop)


def test_many_complete_stanzas_are_never_counted_together(monkeypatch):
    monkeypatch.setattr(xmlguard, "MAX_OPEN_STANZA_BYTES", 64 * 1024)
    client, loop = _client()
    try:
        client.data_received(HEADER)
        stanza = b"<message><body>" + b"x" * 900 + b"</body></message>"
        blob = stanza * 400                      # ~370 KiB, far over the cap
        # Split so that every read ends inside a stanza.
        for at in range(0, len(blob), 1500):
            client.data_received(blob[at:at + 1500])
        _spin(loop)
        assert client.aborted == []
        assert client.refusals == []
    finally:
        _close(client, loop)


def test_both_clients_are_built_on_the_guard():
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(here, "android_bridge", "transport.py")) as fh:
        transport = fh.read()
    assert "class GuardedClient(GuardedStream, ClientXMPP)" in transport
    assert "client = GuardedClient(jid, password)" in transport
    assert "client = ClientXMPP(jid, password)" not in transport
    with open(os.path.join(here, "client", "otrv4plus_xmpp.py")) as fh:
        terminal = fh.read()
    assert "class OTRv4PlusXMPP(_GuardedStream," in terminal
