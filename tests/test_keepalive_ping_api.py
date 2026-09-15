# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The keepalive called a method slixmpp does not have.

THE BUG
-------
Both clients did:

    await self["xep_0199"].async_ping(host, timeout=...)

**slixmpp 1.17 has no `async_ping`.** It was removed upstream in favour of
`ping`. So the call raised `AttributeError`, both callers classified anything
that was not `IqError` as "the server did not answer", and every probe reported
a dead stream on a perfectly healthy connection.

On Android the keepalive then tore the session down after two failures --
roughly two minutes after connecting, whatever the user was doing. Because
everything downstream keys off `is_connected`, that ONE defect produced three
separate handset reports:

  * an unexplained drop into DISCONNECTING;
  * every contact showing "presence unknown";
  * Add Contact silently doing nothing (`not_connected`).

Termux survived it only because its keepalive skips the probe while the stream
is delivering traffic, so an active conversation never pinged. A quiet session
would have been reconnected every couple of minutes there too.

WHY IT SURVIVED THE TEST SUITE
------------------------------
Nothing ever ran `_probe_stream`. The keepalive tests asserted intervals and
thresholds -- numbers -- and never executed the one line that talks to slixmpp.
These tests execute it, against the real plugin class and against fakes.
"""

import asyncio
import inspect

import pytest

import otrv4plus_ping as _ping


# ── the fact that started it ────────────────────────────────────────────────

class TestAgainstTheRealSlixmpp:
    """Not a fake. The installed plugin, whatever version it is."""

    @staticmethod
    def _plugin_class():
        slixmpp = pytest.importorskip("slixmpp")
        from slixmpp.plugins.xep_0199.ping import XEP_0199
        return XEP_0199

    def test_a_round_trip_method_is_found(self):
        cls = self._plugin_class()
        name, _ = _ping.ping_method(cls)
        assert name is not None, (
            "no XEP-0199 round trip on the installed slixmpp; the keepalive "
            "has nothing to call and every probe would report a dead stream")

    def test_the_method_found_is_a_coroutine(self):
        cls = self._plugin_class()
        name, fn = _ping.ping_method(cls)
        assert inspect.iscoroutinefunction(fn), (
            "%s is not awaitable, so `await` on it would raise" % name)

    def test_async_ping_is_gone_which_is_the_whole_bug(self):
        """Documents the fact rather than asserting a version.

        If a future slixmpp brings `async_ping` back this test says so and
        nothing breaks: `ping_method` tries it first.
        """
        cls = self._plugin_class()
        name, _ = _ping.ping_method(cls)
        if not hasattr(cls, "async_ping"):
            assert name == "ping", (
                "async_ping is absent, so `ping` must be what gets called")

    def test_send_ping_is_never_chosen(self):
        """It returns a Future for a stanza rather than making the round trip,
        so awaiting it answers a different question."""
        assert "send_ping" not in _ping.PING_METHODS


# ── the helper, executed ────────────────────────────────────────────────────

class Plugin:
    """A XEP-0199 stand-in whose one method can be aimed anywhere."""

    def __init__(self, name="ping", behaviour=None):
        self.calls = []
        self._behaviour = behaviour or (lambda: None)
        if name:
            setattr(self, name, self._make(name))

    def _make(self, name):
        async def call(jid, timeout=None):
            self.calls.append((jid, timeout))
            result = self._behaviour()
            if isinstance(result, BaseException):
                raise result
            return result
        return call


class IqError(Exception):
    """Named to match slixmpp's, which is how the helper classifies it."""


class IqTimeout(Exception):
    pass


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


class TestRoundTrip:

    def test_an_answer_is_alive(self):
        assert _run(_ping.round_trip(Plugin(), "server", 5)) is True

    def test_the_jid_and_timeout_are_passed_through(self):
        plugin = Plugin()
        _run(_ping.round_trip(plugin, "xmpp-elite.i2p", 60))
        assert plugin.calls == [("xmpp-elite.i2p", 60)]

    def test_an_iq_error_is_alive(self):
        """A server replying `service-unavailable` has proven the stream
        works, which is the only thing being asked."""
        plugin = Plugin(behaviour=lambda: IqError("service-unavailable"))
        assert _run(_ping.round_trip(plugin, "server", 5)) is True

    def test_a_timeout_is_dead(self):
        plugin = Plugin(behaviour=lambda: IqTimeout())
        assert _run(_ping.round_trip(plugin, "server", 5)) is False

    def test_an_unexpected_exception_is_dead(self):
        plugin = Plugin(behaviour=lambda: OSError("stream gone"))
        assert _run(_ping.round_trip(plugin, "server", 5)) is False

    def test_async_ping_is_preferred_when_present(self):
        plugin = Plugin(name="async_ping")
        assert _run(_ping.round_trip(plugin, "server", 5)) is True
        assert plugin.calls

    def test_ping_is_used_when_async_ping_is_not_there(self):
        plugin = Plugin(name="ping")
        assert _run(_ping.round_trip(plugin, "server", 5)) is True
        assert plugin.calls


class TestBeingUnableToAskIsNotADeadStream:
    """The heart of the fix. Every one of these used to read as a timeout."""

    def test_no_method_at_all_raises_rather_than_returning_false(self):
        with pytest.raises(_ping.PingUnsupported):
            _run(_ping.round_trip(Plugin(name=None), "server", 5))

    def test_that_is_exactly_the_shape_of_the_original_bug(self):
        """A plugin with `ping` but no `async_ping` -- slixmpp 1.17. The old
        code called the absent one and read AttributeError as silence."""
        plugin = Plugin(name="ping")
        assert not hasattr(plugin, "async_ping")
        assert _run(_ping.round_trip(plugin, "server", 5)) is True, (
            "the helper must find `ping` rather than failing on `async_ping`")

    def test_a_wrong_signature_is_unsupported_not_dead(self):
        class Awkward:
            def ping(self, jid):          # no timeout keyword
                raise AssertionError("must not be reached")

        with pytest.raises(_ping.PingUnsupported):
            _run(_ping.round_trip(Awkward(), "server", 5))

    def test_a_non_awaitable_result_is_unsupported_not_dead(self):
        class Blocking:
            def ping(self, jid, timeout=None):
                return 0.25          # an old blocking API returning millis

        with pytest.raises(_ping.PingUnsupported):
            _run(_ping.round_trip(Blocking(), "server", 5))

    def test_cancellation_propagates_and_is_not_a_verdict(self):
        """A cancelled probe is a shutdown, not evidence about the server."""
        plugin = Plugin(behaviour=lambda: asyncio.CancelledError())
        with pytest.raises(asyncio.CancelledError):
            _run(_ping.round_trip(plugin, "server", 5))


# ── both callers must fail safe on it ───────────────────────────────────────

class TestTheCallersTreatUnsupportedAsAlive:
    """Structural, over both `_probe_stream` bodies.

    A regression here is silent and expensive: it does not fail a test, it
    disconnects a handset two minutes into every conversation.
    """

    @staticmethod
    def _body(path, marker):
        """The executable half of one method, with prose stripped.

        Docstrings here EXPLAIN the bug and so contain the name of the method
        that must never be called again. Banning a string has to mean banning
        a call, not banning the comment that says why.
        """
        import io
        import os
        import re
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with io.open(os.path.join(root, path), encoding="utf-8") as fh:
            text = fh.read()
        start = text.index(marker)
        body = text[start:]
        end = re.search(r"\n    (?:async )?def ", body[len(marker):])
        body = body[:len(marker) + end.start()] if end else body
        body = re.sub(r'"""(?:.|\n)*?"""', " ", body)
        return re.sub(r"#[^\n]*", "", body)

    def test_the_android_transport_uses_the_shared_helper(self):
        body = self._body("android_bridge/transport.py",
                          "async def _probe_stream(self)")
        assert "_ping.round_trip(" in body
        assert "async_ping" not in body, (
            "the call that does not exist is back")

    def test_the_android_transport_survives_an_unusable_ping(self):
        body = self._body("android_bridge/transport.py",
                          "async def _probe_stream(self)")
        assert "except _ping.PingUnsupported:" in body
        after = body[body.index("except _ping.PingUnsupported:"):]
        assert "return True" in after[:400], (
            "an unusable ping API reads as a dead stream, which is the "
            "original bug with a different exception type")

    def test_the_terminal_client_uses_the_shared_helper(self):
        body = self._body("otrv4plus_xmpp.py",
                          "async def _probe_stream(self)")
        assert "_ping.round_trip(" in body
        assert "async_ping" not in body

    def test_the_terminal_client_survives_an_unusable_ping(self):
        body = self._body("otrv4plus_xmpp.py",
                          "async def _probe_stream(self)")
        assert "except _ping.PingUnsupported:" in body
        after = body[body.index("except _ping.PingUnsupported:"):]
        assert "return True" in after[:200]

    def test_neither_client_calls_the_plugin_directly_any_more(self):
        """One implementation, so a fix to one is a fix to both."""
        import io
        import os
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        for path in ("android_bridge/transport.py", "otrv4plus_xmpp.py"):
            with io.open(os.path.join(root, path), encoding="utf-8") as fh:
                text = fh.read()
            # The /ping COMMAND in the terminal client is a different thing:
            # a user asking about one peer, where a failure is reportable.
            probe = text[text.index("async def _probe_stream(self)"):]
            probe = probe[:2000]
            assert ".async_ping(" not in probe
