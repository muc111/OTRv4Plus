"""The prefix on an incoming chat line is a security claim.

Reported from a handset: an SMP-verified session showed
`[otr] <bob@xmpp-elite.i2p> ohhh lala` with `[otr]` in green, and nothing else
said the line was encrypted or that the peer's identity had been proved. The
reassurance was a colour, and only a colour.

Two things had to be true of the fix, and both are asserted here:

1. **The two states must not look alike.** An unverified session really is
   encrypted, so a padlock on it is not a lie -- but if it is the *same*
   padlock, a reader who never ran SMP gets the same reassurance as one who
   did, which is worse than no padlock at all. So the glyph differs AND the
   colour differs: emoji are small on a handset, and colour is invisible to
   some readers, so either signal alone is weak.

2. **Redaction must survive the new prefix.** `_log_line_for_file` is an
   allowlist (INV-03) that redacts message bodies by matching
   `[otr] <peer> body`. A prefix not listed in `_LOG_MARKERS` would stop that
   pattern matching and write every received message to the session log in
   plaintext. Both padlocks were already in the tuple; the test is here so a
   third marker cannot be added without someone checking.

The colours are the project's own, not new ones. `UIConstants.SECURITY_ICONS`
and the level->colour tables in `otrv4+.py` say yellow is ENCRYPTED and blue is
SMP_VERIFIED. The prefix used to be GREEN when verified, which contradicted
that table -- green there is FINGERPRINT, meaning pinned but *not* SMP-verified
-- so the tab bar and the message prefix were telling the reader two different
things with the same colour.
"""

import os
import re

import pytest

xmpp = pytest.importorskip("otrv4plus_xmpp")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

LOCK_WITH_KEY = "\U0001f510"      # verified
PLAIN_LOCK = "\U0001f512"         # encrypted, not verified

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def strip_ansi(text):
    return _ANSI.sub("", text)


class TestTheTwoStatesAreDistinguishable:

    def test_a_verified_session_gets_a_padlock(self):
        assert LOCK_WITH_KEY in xmpp._otr_prefix(True)

    def test_an_unverified_session_gets_a_different_padlock(self):
        """Not no padlock -- the session IS encrypted and saying otherwise
        would be its own lie. A different one."""
        prefix = xmpp._otr_prefix(False)
        assert PLAIN_LOCK in prefix
        assert LOCK_WITH_KEY not in prefix

    def test_they_differ_by_glyph_alone(self):
        """The colourblind reader, and the reader on a monochrome terminal."""
        assert strip_ansi(xmpp._otr_prefix(True)) != \
            strip_ansi(xmpp._otr_prefix(False))

    def test_they_differ_by_colour_alone(self):
        """The reader whose font renders both padlocks near-identically at
        handset size."""
        def colours(text):
            return set(_ANSI.findall(text))
        assert colours(xmpp._otr_prefix(True)) != colours(xmpp._otr_prefix(False))

    def test_both_still_say_otr(self):
        for verified in (True, False):
            assert "[otr]" in strip_ansi(xmpp._otr_prefix(verified))


class TestTheColoursAreTheProjectsOwn:
    """`UIConstants.SECURITY_ICONS`: yellow = ENCRYPTED, blue = SMP_VERIFIED.
    A second, contradicting vocabulary in the message prefix is how a reader
    ends up trusting the wrong one."""

    @staticmethod
    @pytest.fixture(scope="class")
    def engine():
        return pytest.importorskip("otrv4plus")

    def test_verified_is_blue_like_the_smp_verified_icon(self, engine):
        assert xmpp._otr_prefix(True).count(xmpp._colorize("[otr]", "blue"))
        assert engine.UIConstants.SECURITY_ICONS[
            engine.UIConstants.SecurityLevel.SMP_VERIFIED] == "\U0001f535"

    def test_unverified_is_yellow_like_the_encrypted_icon(self, engine):
        assert xmpp._colorize("[otr]", "bold_yellow") in xmpp._otr_prefix(False)
        assert engine.UIConstants.SECURITY_ICONS[
            engine.UIConstants.SecurityLevel.ENCRYPTED] == "\U0001f7e1"

    def test_green_is_no_longer_claimed_for_smp_verification(self, engine):
        """Green is FINGERPRINT in the project's table -- pinned, but NOT
        SMP-verified. Using it for the strongest state was the original
        contradiction."""
        assert engine.UIConstants.SECURITY_ICONS[
            engine.UIConstants.SecurityLevel.FINGERPRINT] == "\U0001f7e2"
        assert xmpp._colorize("[otr]", "green") not in xmpp._otr_prefix(True)


class TestRedactionSurvivesThePrefix:
    """The half that would have been a security regression rather than a
    cosmetic one."""

    @pytest.mark.parametrize("marker", [LOCK_WITH_KEY, PLAIN_LOCK])
    def test_the_marker_is_known_to_the_log_stripper(self, marker):
        assert marker in xmpp._LOG_MARKERS, (
            "a prefix that _strip_log_markers does not know about stops "
            "_LOG_CONTENT_RE matching, and every received message is then "
            "written to the session log in plaintext"
        )

    @pytest.mark.parametrize("marker", ["", LOCK_WITH_KEY + " ", PLAIN_LOCK + " "])
    def test_a_message_body_is_still_redacted(self, marker):
        line = marker + "[otr] <bob@xmpp-elite.i2p> ohhh lala"
        written = xmpp._log_line_for_file(line)
        assert "ohhh lala" not in written, "the message body reached the log"
        assert "redacted" in written

    def test_every_marker_the_prefix_uses_is_registered(self):
        """Derived from the prefixes themselves, so adding a third state with
        a new glyph fails here rather than in production."""
        for verified in (True, False):
            glyph = strip_ansi(xmpp._otr_prefix(verified))[0]
            assert glyph in xmpp._LOG_MARKERS, (
                "the prefix uses %r, which is not in _LOG_MARKERS" % glyph)

    def test_the_redaction_still_works_with_colour_codes_present(self):
        """The real line carries ANSI. `_log_line_for_file` strips ANSI
        before the markers, and both have to happen for the pattern to
        match."""
        line = (xmpp._otr_prefix(True) + " "
                + xmpp._colorize("<bob@xmpp-elite.i2p>", "yellow")
                + " " + xmpp._colorize("ohhh lala", "dark_blue"))
        written = xmpp._log_line_for_file(line)
        assert "ohhh lala" not in written
        assert "redacted" in written


class TestTheRendererUsesIt:
    """Having the helper is not the fix; calling it is."""

    @staticmethod
    @pytest.fixture(scope="class")
    def source():
        with open(os.path.join(ROOT, "otrv4plus_xmpp.py"),
                  encoding="utf-8") as fh:
            return fh.read()

    def test_the_inbound_chat_path_calls_the_helper(self, source):
        assert "_otr_prefix(smp_ok)" in source, (
            "the message renderer no longer derives its prefix from the SMP "
            "state"
        )

    def test_the_prefix_is_not_hard_coded_beside_it(self, source):
        """The old line built `_colorize("[otr] ", "green")` inline. Leaving
        that anywhere in the chat path means two sources of truth for what a
        verified session looks like."""
        assert '_colorize("[otr] ", "green")' not in source

    def test_the_peer_is_still_sanitised_in_both_states(self, source):
        """A padlock must not come with a relaxation elsewhere: peer text is
        attacker-controlled and printed to a terminal, verified or not."""
        start = source.index("smp_ok = ")
        block = source[start:start + 1200]
        assert "_sanitise(peer, 128)" in block
        assert "_sanitise(text)" in block
