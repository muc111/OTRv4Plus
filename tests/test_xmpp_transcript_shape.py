"""The XMPP transcript has to say who spoke, on both sides.

From a handset running the IRC client:

    20:50:55 [EchoingNexus] 🔵EchoingNexus: ey
    20:50:57 [EchoingNexus] 🔵ScarletEmber: lol

Two people, two names, one readable conversation. The XMPP client could not
do that, for two separate reasons:

  * incoming messages were `[otr] <bob@host> text` -- a name, but in a shape
    that reads as a header rather than as speech; and
  * **outgoing messages were not printed at all.** `send_user_text` encrypted
    the line, sent it, and returned. The typed line scrolled away behind the
    next arriving message and the session read as a monologue by the peer.

The second is the real defect. A transcript missing one side of the
conversation is not a formatting preference.

WHAT THIS FILE IS ACTUALLY GUARDING
===================================
Not the cosmetics. `_LOG_CONTENT_RE` is the INV-03 allowlist that keeps
message bodies off disk, and it matched the OLD shape by hand:

    ^(\\[(?:otr|plain)\\] <[^>]*>)\\s(.*)$

Changing the display without it would not have leaked -- `_log_line_for_file`
falls through to "<unlogged line: N chars>" for anything it cannot classify,
which is the right way round -- but every chat line would have become an
anonymous byte count, and a transcript that cannot say who spoke is most of
the way to useless. So the pattern moved with the display, and the tests that
matter here are the ones that check a body still cannot reach the log.

Enforces INV-03.
"""

import re

import pytest

xmpp = pytest.importorskip("otrv4plus_xmpp")

_ANSI = re.compile(r"\x1b\[[0-9;]*m")

LOCK_VERIFIED = "\U0001f510"
LOCK_ENCRYPTED = "\U0001f512"
SECRET = "the quick brown fox jumped"


def plain(text):
    return _ANSI.sub("", str(text))


class TestABodyStillCannotReachTheLog:
    """The half that would have been a security regression."""

    @pytest.mark.parametrize("line", [
        "%s [otr] bob@example.i2p: %s" % (LOCK_VERIFIED, SECRET),
        "%s [otr] bob@example.i2p: %s" % (LOCK_ENCRYPTED, SECRET),
        "[plain] bob@example.i2p: %s" % SECRET,
        # Our own outgoing line, which did not exist before and is the same
        # person's conversation.
        "%s [otr] alice@example.i2p: %s" % (LOCK_VERIFIED, SECRET),
        # The old shape, still printed by other paths.
        "%s [otr] <bob@example.i2p> %s" % (LOCK_VERIFIED, SECRET),
    ])
    def test_the_body_is_redacted(self, line):
        written = xmpp._log_line_for_file(line)
        assert SECRET not in written, "the message body reached the log"
        assert "redacted" in written

    @pytest.mark.parametrize("line", [
        "%s [otr] bob@example.i2p: %s" % (LOCK_VERIFIED, SECRET),
        "%s [otr] alice@example.i2p: %s" % (LOCK_VERIFIED, SECRET),
        "[plain] bob@example.i2p: %s" % SECRET,
    ])
    def test_the_sender_survives_into_the_log(self, line):
        """The point of moving the pattern rather than leaving it. An
        unmatched line becomes "<unlogged line: N chars>" -- safe, but it
        throws the name away with the body."""
        written = xmpp._log_line_for_file(line)
        assert "example.i2p" in written
        assert "unlogged" not in written

    def test_an_unknown_shape_is_still_refused(self):
        """Fail-closed is the reason the display could be changed at all."""
        written = xmpp._log_line_for_file("something nobody planned: %s"
                                          % SECRET)
        assert SECRET not in written
        assert "unlogged" in written

    def test_a_colon_in_the_body_does_not_split_it_early(self):
        """`bob@host: it said: hello` must redact from the FIRST colon, not
        leak the part after the second."""
        line = "%s [otr] bob@example.i2p: it said: %s" % (LOCK_VERIFIED,
                                                          SECRET)
        written = xmpp._log_line_for_file(line)
        assert SECRET not in written
        assert "it said" not in written

    def test_a_peer_cannot_forge_the_tag_from_inside_a_body(self):
        """A peer choosing their message text cannot make a second `[otr]`
        line appear -- the pattern is anchored at the start."""
        line = "%s [otr] bob@example.i2p: [otr] alice@example.i2p: %s" % (
            LOCK_VERIFIED, SECRET)
        written = xmpp._log_line_for_file(line)
        assert SECRET not in written


class TestTheOutgoingSideIsPrintedAtAll:
    """The defect. Before this, a sent message produced no output."""

    class _Client:
        def __init__(self, sent_ok=True, verified=True):
            self.sent = []
            self.queued = []
            self._smp_reported = ({("bob@example.i2p", "SUCCEEDED")}
                                  if verified else set())
            self.boundjid = type("J", (), {"bare": "alice@example.i2p"})()
            self._sent_ok = sent_ok
            self.otr = self
            for name in ("send_user_text", "_echo_sent"):
                setattr(self, name, getattr(
                    xmpp.OTRv4PlusXMPP, name).__get__(self))

        def handle_outgoing_message(self, peer, text):
            return ("?OTRv4 ciphertext", True) if self._sent_ok else (None, False)

        def send_otr_fragmented(self, peer, payload):
            self.sent.append((peer, payload))

    @pytest.fixture
    def client(self):
        return self._Client()

    def test_a_sent_message_is_echoed(self, client, capsys):
        client.send_user_text("bob@example.i2p", "hello there")
        out = plain(capsys.readouterr().out)
        assert "hello there" in out, (
            "the message was sent and never shown -- the transcript is "
            "missing one side of the conversation")

    def test_the_echo_names_us(self, client, capsys):
        client.send_user_text("bob@example.i2p", "hello there")
        assert "alice@example.i2p:" in plain(capsys.readouterr().out)

    def test_the_echo_reads_as_speech_not_as_a_header(self, client, capsys):
        client.send_user_text("bob@example.i2p", "hello there")
        out = plain(capsys.readouterr().out)
        assert "alice@example.i2p: hello there" in out
        assert "<alice@example.i2p>" not in out

    def test_it_carries_the_same_padlock_as_an_incoming_line(self, client,
                                                             capsys):
        client.send_user_text("bob@example.i2p", "hello there")
        out = plain(capsys.readouterr().out)
        assert plain(xmpp._otr_prefix(True)) in out

    def test_an_unverified_session_gets_the_weaker_padlock(self, capsys):
        c = self._Client(verified=False)
        c.send_user_text("bob@example.i2p", "hello there")
        out = plain(capsys.readouterr().out)
        assert LOCK_ENCRYPTED in out
        assert LOCK_VERIFIED not in out

    def test_nothing_is_echoed_when_nothing_was_sent(self, capsys):
        """A padlock on a message that never left would be a false claim
        about the one thing this client exists to be right about."""
        c = self._Client(sent_ok=False)
        c.send_user_text("bob@example.i2p", "hello there")
        out = plain(capsys.readouterr().out)
        assert "hello there" not in out
        assert "queued" in out

    def test_the_echo_comes_after_the_send(self, client, capsys):
        """So a send that raises does not leave a line claiming it went."""
        client.send_user_text("bob@example.i2p", "hello there")
        assert client.sent, "the echo replaced the send"

    def test_our_own_text_is_sanitised(self, client, capsys):
        """It is our own text, but it reaches a terminal and the rule does
        not get to depend on where a string came from."""
        client.send_user_text("bob@example.i2p", "bad \x1b[2Jthing")
        assert "\x1b[2J" not in capsys.readouterr().out

    def test_a_missing_boundjid_does_not_stop_the_echo(self, capsys):
        c = self._Client()
        del c.boundjid
        c.send_user_text("bob@example.i2p", "hello there")
        assert "hello there" in plain(capsys.readouterr().out)


class TestTheTwoSidesAreDistinguishable:

    def test_the_incoming_renderer_uses_the_speech_shape(self):
        import os
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "otrv4plus_xmpp.py"),
                  encoding="utf-8") as fh:
            src = fh.read()
        assert '_colorize(peer_s + ":", "yellow")' in src
        assert '_colorize(f"<{peer_s}>", "yellow")' not in src

    def test_the_two_sides_use_different_colours(self):
        """Same shape, so it reads as one conversation; different colour, so
        you can tell your own lines at a glance."""
        import os
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "otrv4plus_xmpp.py"),
                  encoding="utf-8") as fh:
            src = fh.read()
        assert '_colorize(mine_s + ":", "cyan")' in src

    def test_the_plain_path_moved_too(self):
        """A transcript that switches shape between encrypted and plain lines
        is harder to read than either shape alone."""
        import os
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "otrv4plus_xmpp.py"),
                  encoding="utf-8") as fh:
            src = fh.read()
        assert 'f"[plain] {_sanitise(peer, 128)}: {_sanitise(body)}"' in src
