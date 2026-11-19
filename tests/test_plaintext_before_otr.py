# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""An ordinary XMPP message, before anyone asks for OTR.

WHY THIS WAS IMPOSSIBLE

`EnhancedSessionManager.handle_outgoing_message` is opportunistic. For a peer
with no session it does not send what you typed: it creates a session, starts a
DAKE, queues the text, and returns DAKE1 for the caller to send. Both clients
went straight to it, so typing "hello" put an 11 KB handshake frame on the wire
and delivered nothing. Against a peer that could not answer the handshake -- an
ordinary XMPP client, or, as it turned out, our own Android build -- the message
never arrived at all.

So the decision of when to involve OTR moved up to the clients, into
`otrv4plus_mode.OtrMode`, and these tests pin both halves of it:

  * an ordinary conversation sends as typed, and does NOT start a handshake;
  * a conversation anyone has asked to encrypt never sends in the clear again,
    including while a handshake is in flight and including after one fails.

The second half is the one that matters. A policy that only got the first half
right would be a downgrade attack implemented on purpose.
"""

from source_of import app_source, client_source  # noqa: E402
import re

import pytest

from otrv4plus_mode import OtrMode


def _code_only(text):
    """Python with docstrings and comments removed.

    A structural assertion must be about the code. The first version of the
    ordering test below matched the word `handle_outgoing_message` in the
    method's own docstring and failed on correct code.
    """
    text = re.sub(r'"""(?:.|\n)*?"""', '""', text)
    return re.sub(r"#[^\n]*", "", text)

PEER = "alice@otrv4plus.i2p"
OTHER = "carol@otrv4plus.i2p"


class TestTheRule:

    def test_an_untouched_conversation_may_send_in_the_clear(self):
        assert OtrMode().may_send_plaintext(PEER, encrypted=False)

    def test_an_encrypted_session_may_not(self):
        """Even though nobody called `request`: the ENGINE says there is a
        session, and that alone settles it."""
        assert not OtrMode().may_send_plaintext(PEER, encrypted=True)

    def test_a_requested_conversation_may_not(self):
        mode = OtrMode()
        mode.request(PEER)
        assert not mode.may_send_plaintext(PEER, encrypted=False)

    def test_a_request_survives_a_failed_handshake(self):
        """`encrypted=False` after a request means the handshake did not
        finish. That is not permission to continue without one -- it is the
        exact moment a downgrade would be most useful to an attacker."""
        mode = OtrMode()
        mode.request(PEER)
        for _ in range(3):
            assert not mode.may_send_plaintext(PEER, encrypted=False)

    def test_the_rule_is_per_peer(self):
        mode = OtrMode()
        mode.request(PEER)
        assert not mode.may_send_plaintext(PEER, encrypted=False)
        assert mode.may_send_plaintext(OTHER, encrypted=False)

    def test_requesting_twice_is_idempotent(self):
        mode = OtrMode()
        mode.request(PEER)
        mode.request(PEER)
        assert mode.peers() == {PEER}

    def test_an_explicit_end_restores_plaintext(self):
        mode = OtrMode()
        mode.request(PEER)
        mode.clear(PEER)
        assert mode.may_send_plaintext(PEER, encrypted=False)

    def test_is_otr_is_not_a_security_state(self):
        """It answers "was OTR asked for here", and a caller that treats it as
        "is this encrypted" has a bug. Pinned so the docstring is not the only
        thing saying so."""
        mode = OtrMode()
        mode.request(PEER)
        assert mode.is_otr(PEER)
        assert not mode.may_send_plaintext(PEER, encrypted=False)

    def test_an_empty_peer_is_not_recorded(self):
        mode = OtrMode()
        mode.request("")
        assert mode.peers() == set()

    def test_peers_returns_a_copy(self):
        mode = OtrMode()
        mode.request(PEER)
        mode.peers().add(OTHER)
        assert mode.peers() == {PEER}


class TestTheTerminalClientUsesIt:
    """The terminal client's send path, driven (Phase 5, 2026-11-11: these
    read `send_user_text`'s source until now).

    A real `OTRv4PlusXMPP` needs slixmpp, a profile and an engine, so the
    methods run on a bare instance carrying only the state they read; the
    network and the engine are recorders. What is checked is what goes on
    the wire: plaintext, a held line, or the engine.
    """

    class _Engine:
        def __init__(self, fail=False):
            self.calls = []
            self.fail = fail

        def handle_outgoing_message(self, peer, text):
            self.calls.append((peer, text))
            if self.fail:
                raise RuntimeError("engine down")
            return None, False

    @classmethod
    def _client(cls, mode, encrypted=(), capable=(), online=True, outbox=True,
                engine=None):
        import types
        import otrv4plus_xmpp as xmpp
        c = xmpp.OTRv4PlusXMPP.__new__(xmpp.OTRv4PlusXMPP)
        c._run_out_filters = None          # slixmpp's __del__ reads it
        if mode is not None:
            c._otr_mode = mode
        c._encrypted = set(encrypted)
        c._otr_capable = set(capable)
        c._peer_resources = {PEER: {"phone"}} if online else {}
        c._hs_started = {}
        c._hs_hist = []
        if outbox:
            c._outbox = {}
        else:
            # No outbox: the engine branch's own "queued" fallback records.
            c.held = []
            c._hold = lambda peer, text: (c.held.append((peer, text)), True)[1]
        c.wire = []
        c.send_otr_fragmented = lambda peer, text: c.wire.append((peer, text))
        c.otr = engine or cls._Engine()
        c.boundjid = types.SimpleNamespace(bare="me@otrv4plus.i2p")
        c._erase_plain_echo = lambda text: None
        return c

    def test_an_untouched_conversation_goes_out_plain_without_a_handshake(self, capsys):
        c = self._client(OtrMode())
        c.send_user_text(PEER, "hello")
        assert c.wire == [(PEER, "hello")]
        assert c.otr.calls == [], "the engine was reached: a DAKE would start"

    def test_a_requested_conversation_never_goes_out_plain(self, capsys):
        mode = OtrMode()
        mode.request(PEER)
        c = self._client(mode)
        c.send_user_text(PEER, "secret")
        assert all(text != "secret" for _, text in c.wire)
        assert c._outbox[PEER] == ["secret"], "the line should wait for OTR"

    def test_without_the_outbox_a_requested_line_goes_to_the_engine(self, capsys):
        mode = OtrMode()
        mode.request(PEER)
        c = self._client(mode, outbox=False)
        c.send_user_text(PEER, "secret")
        assert c.wire == []
        assert c.otr.calls == [(PEER, "secret")]

    def test_an_uninitialised_client_does_not_send_plaintext(self, capsys):
        """No policy object at all ("I do not know whether OTR was asked
        for") falls through to the engine, never to the clear."""
        c = self._client(None, outbox=False)
        c.send_user_text(PEER, "hello")
        assert c.wire == []
        assert c.otr.calls == [(PEER, "hello")]

    def test_the_peer_asking_marks_the_conversation(self, monkeypatch):
        import types
        import otrv4plus_xmpp as xmpp
        mode = OtrMode()
        c = self._client(mode)
        c._blocked = set()
        c._peer_is_alive = lambda peer: None
        c._check_rate_limit = lambda peer: True
        scheduled = []
        monkeypatch.setattr(xmpp.asyncio, "ensure_future",
                            lambda coro: (scheduled.append(coro), coro.close()))
        msg = {"type": "chat", "from": types.SimpleNamespace(bare=PEER),
               "body": xmpp.OTR_PREFIX + "AAAA"}
        c._on_message(msg)
        assert mode.is_otr(PEER) and scheduled
        assert not mode.may_send_plaintext(PEER, False)

    def test_starting_otr_marks_it_before_anything_can_fail(self, capsys):
        mode = OtrMode()
        c = self._client(mode, engine=self._Engine(fail=True))
        c.start_otr(PEER)
        assert mode.is_otr(PEER), "a failed start re-opened the clear"
        assert not mode.may_send_plaintext(PEER, False)

    def test_the_plaintext_echo_carries_no_padlock(self, capsys):
        """A message that went in the clear must not wear a padlock, or the
        transcript makes a claim the wire does not."""
        c = self._client(OtrMode())
        c.send_user_text(PEER, "hello")
        out = capsys.readouterr().out
        assert "[plain]" in out and "hello" in out
        assert "\U0001f512" not in out and "\U0001f510" not in out

    def test_the_plaintext_echo_sanitises_the_body(self, capsys):
        c = self._client(OtrMode())
        c._echo_plain_sent(PEER, "hi\x1b]0;owned\x07there")
        out = capsys.readouterr().out
        assert "\x1b]0;" not in out and "\x07" not in out


class TestBothClientsShareOneRule:

    def test_the_policy_module_has_no_dependencies(self):
        """It is imported by `android_bridge`, which may not reach the
        terminal client or the engine."""
        import otrv4plus_mode
        with open(otrv4plus_mode.__file__, encoding="utf-8") as fh:
            source = fh.read()
        for banned in ("otrv4plus_xmpp", "otrv4+", "slixmpp", "android_bridge"):
            assert banned not in source, banned

    def test_neither_client_reimplements_the_rule(self):
        """Two copies of this rule would drift, and one direction of the drift
        sends plaintext where the user expected encryption."""
        source = client_source()
        assert "may_send_plaintext" in source, "the XMPP client"
        # The decision is the module's; a client that recomputes it from
        # its own set has forked the policy.
        assert "def may_send_plaintext" not in source, "the XMPP client"
        # The app is stricter (owner, 2026-10-24): it never sends a 1:1
        # message in the clear, so it does not ask the rule at all.
        app = app_source()
        assert "may_send_plaintext" not in app and "def may_send_plaintext" not in app
