# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The messages that publish MAC keys reach the server before the stream ends.

Owner (2026-10-26): "when [the] user hits wipe ... ensure all chats release
MACs for all deniability to be achieved before wiping". The engine already
retires every MAC key and makes each session's closing message before it
destroys anything (L1, tests/test_l1_revelation_gate.py). What was not
ensured is that those messages LEFT: `send` only queues a stanza in slixmpp,
and the teardown then aborted the client (Wipe & Exit) or closed the I2P
tunnel right after slixmpp's non-blocking `disconnect()` (sign-out). A queued
stanza is dropped by an abort -- shown below with real slixmpp.

Now `XmppTransport._end_stream` drains the queue, sends our end of stream
after it and waits for the server's, which an XMPP server sends only after
reading everything before it. These tests run real slixmpp against a
scripted server on loopback.
"""
import asyncio
import os

import pytest

slixmpp = pytest.importorskip("slixmpp")
from slixmpp.xmlstream import XMLStream  # noqa: E402

from android_bridge.transport import XmppTransport, END_OF_STREAM_TIMEOUT  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLOSING = "?OTRv4 closing-message-that-publishes-the-mac-keys"
SERVER_HEADER = (b"<?xml version='1.0'?><stream:stream xmlns='jabber:client' "
                 b"xmlns:stream='http://etherx.jabber.org/streams' id='s1' "
                 b"from='example.test' version='1.0'><stream:features/>")


class _Stream(XMLStream):
    def __init__(self):
        super().__init__()
        self.default_ns = "jabber:client"
        self.stream_header = ("<stream:stream xmlns='jabber:client' "
                              "xmlns:stream='http://etherx.jabber.org/streams' "
                              "to='example.test' version='1.0'>")
        self.stream_footer = "</stream:stream>"
        # Loopback to a scripted server: plain TCP, the one method it speaks.
        self.enable_plaintext = True
        self.enable_starttls = False
        self.enable_direct_tls = False


async def _session(teardown, answer_delay=0.0, answers=True):
    """Connect real slixmpp to a scripted server, queue the closing message,
    tear down with [teardown]. Returns (what the server received before it
    saw our end of stream, whether [teardown] reported success)."""
    seen = {"before_footer": b"", "all": bytearray()}

    async def handle(reader, writer):
        writer.write(SERVER_HEADER)
        await writer.drain()
        while True:
            data = await reader.read(65536)
            if not data:
                break
            seen["all"].extend(data)
            if b"</stream:stream>" in seen["all"]:
                seen["before_footer"] = bytes(seen["all"]).split(b"</stream:stream>")[0]
                if answers:
                    await asyncio.sleep(answer_delay)
                    writer.write(b"</stream:stream>")
                    await writer.drain()
                    writer.close()
                break

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    stream = _Stream()
    stream.connect("127.0.0.1", port)
    await stream.wait_until("connected", 5)
    await asyncio.sleep(0.05)                      # the server's header parsed
    stream.event("session_start")                  # bound, as a signed-in client is
    stream.send("<message to='bob@example.test'><body>%s</body></message>" % CLOSING)
    ok = await teardown(stream)
    await asyncio.sleep(0.1)
    server.close()
    return bytes(seen["all"]), seen["before_footer"], ok


async def _end(stream, budget=END_OF_STREAM_TIMEOUT):
    return await XmppTransport._end_stream(None, stream, budget)


async def _old_wipe(stream):
    stream.abort()                                 # what close() did first
    return True


def test_an_abort_drops_a_queued_closing_message():
    """The defect, with real slixmpp: why a confirmed end of stream is needed."""
    got, _, _ = asyncio.run(_session(_old_wipe))
    assert CLOSING.encode() not in got


def test_the_closing_message_arrives_before_the_end_of_stream():
    got, before, ok = asyncio.run(_session(_end))
    assert ok, "the server answered: it has read everything before our end"
    assert CLOSING.encode() in before


def test_a_slow_server_is_waited_for():
    _, before, ok = asyncio.run(_session(_end, answer_delay=1.0))
    assert ok and CLOSING.encode() in before


def test_a_server_that_never_answers_costs_the_budget_not_a_hang():
    loop_time = {}

    async def bounded(stream):
        start = asyncio.get_running_loop().time()
        ok = await _end(stream, budget=1.0)
        loop_time["took"] = asyncio.get_running_loop().time() - start
        return ok

    got, _, ok = asyncio.run(_session(bounded, answers=False))
    assert ok is False, "not confirmed is reported as not confirmed"
    assert loop_time["took"] < 3.0
    assert CLOSING.encode() in got, "it was still sent first"


# ── where it is used ────────────────────────────────────────────────────────

def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as fh:
        return fh.read()


def test_sign_out_waits_for_the_end_of_stream_before_closing_the_tunnel():
    src = _read("android_bridge", "transport.py")
    fn = src[src.index("    async def _disconnect(self)"):src.index("    async def _end_stream(")]
    assert fn.index("await self._end_stream(client, END_OF_STREAM_TIMEOUT)") \
        < fn.index("self._release_i2p()")


def test_wipe_sends_the_closing_messages_then_ends_the_stream_then_closes():
    src = _read("android_bridge", "app_wipe.py")
    body = src[src.index("    def wipe(self, delete_account"):src.index("    def wipe_crypto(self)")]
    order = [body.index("crypto = self.wipe_crypto()"),
             body.index("self._send_final_revelations()"),
             body.index("transport.disconnect()"),
             body.index("closer()")]
    assert order == sorted(order)


def test_wipe_reports_whether_the_server_confirmed():
    """Behaviour, with the app's own wipe: the end of stream comes before the
    close, and its confirmation is in the report."""
    from android_bridge.app import OtrApp
    import test_smp_end_to_end as E

    calls = []

    class _Transport:
        is_connected = True
        end_confirmed = False

        def send(self, peer, wire):
            calls.append(("send", peer))

        def disconnect(self):
            calls.append(("end_of_stream",))
            self.end_confirmed = True

        def close(self):
            calls.append(("close",))

    app = OtrApp(E._manager(), transport=_Transport())
    report = app.wipe()
    assert report["closing_confirmed"] is True
    assert calls.index(("end_of_stream",)) < calls.index(("close",))
