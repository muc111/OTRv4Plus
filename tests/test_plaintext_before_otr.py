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

PEER = "alice@xmpp-elite.i2p"
OTHER = "carol@xmpp-elite.i2p"


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
    """Structural: constructing a real `OTRv4PlusXMPP` needs slixmpp, a
    profile and an engine. What is checked here is that the send path consults
    the policy at all, and that its failure direction is the safe one."""

    @staticmethod
    @pytest.fixture(scope="class")
    def source():
        with open("otrv4plus_xmpp.py", encoding="utf-8") as fh:
            return fh.read()

    def test_the_send_path_consults_the_policy(self, source):
        block = source[source.index("def send_user_text(self, peer, text):"):]
        block = block[:block.index("def _echo_plain_sent")]
        assert "may_send_plaintext" in block

    def test_the_plaintext_branch_comes_before_the_engine(self, source):
        """Reaching `handle_outgoing_message` at all is what starts a DAKE, so
        the check has to happen first or the damage is already done."""
        block = _code_only(
            source[source.index("def send_user_text(self, peer, text):"):])
        block = block[:block.index("def _echo_plain_sent")]
        assert block.index("may_send_plaintext") < \
            block.index("handle_outgoing_message")

    def test_an_uninitialised_client_does_not_send_plaintext(self, source):
        """Test stubs drive this method unbound, and so would a partially
        constructed client. "I do not know" must fall through to the engine,
        never to the clear."""
        block = source[source.index("def send_user_text(self, peer, text):"):]
        block = block[:block.index("def _echo_plain_sent")]
        assert 'getattr(self, "_otr_mode", None)' in block
        assert "_mode is not None and _mode.may_send_plaintext" in block

    def test_the_peer_asking_marks_the_conversation(self, source):
        block = source[source.index("if body.startswith(OTR_PREFIX):"):]
        block = block[:block.index("elif body.startswith(")]
        assert "request(peer)" in block

    def test_starting_otr_marks_it_before_anything_can_fail(self, source):
        block = source[source.index("def start_otr(self, peer):"):]
        block = block[:block.index("handle_outgoing_message")]
        assert "request(peer)" in block

    def test_the_plaintext_echo_carries_no_padlock(self, source):
        """`_otr_prefix` is the padlock. A message that went in the clear must
        not wear one, or the transcript makes a claim the wire does not."""
        block = source[source.index("def _echo_plain_sent"):]
        block = block[:block.index("def _echo_sent")]
        assert "_otr_prefix" not in block
        assert "[plain]" in block

    def test_the_plaintext_echo_sanitises_the_body(self, source):
        block = source[source.index("def _echo_plain_sent"):]
        block = block[:block.index("def _echo_sent")]
        assert "_sanitise(text)" in block


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
        for path in ("otrv4plus_xmpp.py", "android_bridge/app.py"):
            with open(path, encoding="utf-8") as fh:
                source = fh.read()
            assert "may_send_plaintext" in source, path
            # The decision is the module's; a client that recomputes it from
            # its own set has forked the policy.
            assert "def may_send_plaintext" not in source, path
