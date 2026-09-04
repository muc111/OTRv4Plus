#!/usr/bin/env python3
"""INV-03: nothing secret reaches the session transcript.

The transcript (`--debug`, `~/.otrv4plus/logs/session-*.log`) is the file
people paste into bug reports.  It used to be a denylist: one regex redacted
`[otr] <peer> body` lines and everything else was written verbatim.  That
fails open -- a `print()` added anywhere carrying a passphrase, a key or a
token reached the file with nothing objecting.

It is now an allowlist.  A line is written only if its shape is recognised:
message-content lines (prefix kept, body dropped), structural rules, and
`[tag] text` for a fixed set of diagnostic tags.  Anything else becomes
`<unlogged line: N chars>`.

These tests attempt to leak.  Each one takes a real secret-shaped string,
puts it through the boundary, and fails if any of it survives.
"""

import os
import re
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

xmpp = pytest.importorskip("otrv4plus_xmpp")
LINE = xmpp._log_line_for_file


#: Realistic secret material.  None of it may survive the boundary in any
#: form, in any of the shapes below.
SECRETS = {
    "smp passphrase":   "correct-horse-battery-staple-9911",
    "account password": "hunter2-not-a-real-password",
    "ed448 seed":       "3f7a9c1e" * 14,
    "session key":      "a1b2c3d4" * 8,
    "media key":        "deadbeefcafebabe" * 4,
    "auth token":       "Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig",
    "fingerprint":      "1A2B 3C4D 5E6F 7081 92A3 B4C5 D6E7 F809",
}

#: The shapes a leak plausibly arrives in.
CARRIERS = [
    "%s",
    "Password for alice@server.b32.i2p: %s",
    "DEBUG storing secret=%s",
    "Traceback (most recent call last):\n  ValueError: %s",
    "AssertionError: expected %s",
    "[UNKNOWN] %s",
    "[smp-debug] %s",
    "urllib3 warning: retrying with %s",
    "  File \"x.py\", line 1, in f\n    key = %r",
]


def _survives(secret, rendered):
    """True if any recognisable piece of `secret` is still present."""
    if secret in rendered:
        return True
    # A leak split by formatting still counts: check the longest runs.
    for chunk_len in (24, 16):
        for i in range(0, max(1, len(secret) - chunk_len + 1), 4):
            chunk = secret[i:i + chunk_len]
            if len(chunk) == chunk_len and chunk in rendered:
                return True
    return False


class TestLeakAttempts:

    @pytest.mark.parametrize("name,secret", sorted(SECRETS.items()))
    @pytest.mark.parametrize("carrier", CARRIERS)
    def test_secret_does_not_survive(self, name, secret, carrier):
        rendered = LINE(carrier % secret)
        assert not _survives(secret, rendered), (
            "%s survived the log boundary as %r" % (name, rendered))

    @pytest.mark.parametrize("name,secret", sorted(SECRETS.items()))
    def test_secret_does_not_survive_ansi_wrapping(self, name, secret):
        """Escape sequences must not be a way round the shape check."""
        rendered = LINE("\x1b[31m%s\x1b[0m" % secret)
        assert not _survives(secret, rendered)

    @pytest.mark.parametrize("name,secret", sorted(SECRETS.items()))
    def test_secret_in_a_message_body_does_not_survive(self, name, secret):
        rendered = LINE("[otr] <alice@example.i2p> %s" % secret)
        assert not _survives(secret, rendered)
        assert "redacted" in rendered

    def test_a_multiline_traceback_is_dropped_whole(self):
        tb = ("Traceback (most recent call last):\n"
              '  File "otrv4plus_xmpp.py", line 1, in f\n'
              "    self.otr.set_smp_secret(peer, 'my-real-passphrase')\n"
              "ValueError: boom")
        rendered = LINE(tb)
        assert "my-real-passphrase" not in rendered
        assert "set_smp_secret" not in rendered

    def test_an_unrecognised_line_still_records_that_it_happened(self):
        rendered = LINE("Password for alice: hunter2")
        assert rendered.startswith("<unlogged line:")
        assert "27" in rendered, "the length is the whole diagnostic value"


class TestDiagnosticsStillWork:
    """Fail-closed is only useful if the log stays worth reading."""

    @pytest.mark.parametrize("line", [
        "[voice] rekey 3 committed",
        "[smp] passphrase stored for auto-respond.",
        "[trust] Fingerprint matches the pinned identity for this JID.",
        "[i2p] SAM control socket open",
        "[media] rx=0 dg=0 authfail=87",
        "[auth] retrying with the new password",
        "[xmpp] reconnecting in 30s",
        "[identity] local identity : PERSISTENT",
    ])
    def test_tagged_diagnostics_are_written_verbatim(self, line):
        assert LINE(line) == line

    @pytest.mark.parametrize("line", ["", "---------", "=========", "!!!!!!"])
    def test_structural_lines_survive(self, line):
        assert LINE(line) == line

    def test_message_lines_keep_who_and_when(self):
        rendered = LINE("[otr] <alice@example.i2p> hello there")
        assert "alice@example.i2p" in rendered
        assert "hello there" not in rendered
        assert "11 chars" in rendered


class TestTheBoundaryIsAnAllowlist:

    def test_unknown_tags_are_not_written(self):
        assert LINE("[newsubsystem] some value").startswith("<unlogged")

    def test_the_safe_tag_set_is_explicit_and_small(self):
        tags = xmpp._LOG_SAFE_TAGS
        assert isinstance(tags, frozenset)
        assert len(tags) < 40, (
            "the allowlist has grown large enough to stop being one")
        assert all(t == t.lower() for t in tags)

    def test_adding_a_print_without_a_tag_does_not_leak(self):
        """The regression this exists for: a future bare print()."""
        assert LINE("storing key material for peer").startswith("<unlogged")

    def test_no_denylist_survives_in_the_writer(self):
        import inspect
        src = inspect.getsource(xmpp._log_line_for_file)
        assert "redact" in src.lower()
        # An allowlist returns the input only on a matched shape; the final
        # fallthrough must be the redacted form, not `clean`.
        assert src.rstrip().endswith('return "<unlogged line: %d chars>" % len(clean)')


class TestTheWriterUsesTheBoundary:

    def test_log_to_file_delegates(self):
        import inspect
        src = inspect.getsource(xmpp._log_to_file)
        assert "_log_line_for_file(msg)" in src, (
            "the file writer bypasses the boundary")
        assert "_ANSI_RE" not in src, (
            "the writer is stripping and formatting on its own again")


class TestStatusGlyphsDoNotChangeWhatIsWritten:
    """Every SMP line is printed with a leading padlock.

    The allowlist matches on shape, and "MARKER [smp] ..." is not "[smp] ...",
    so the markers have to be understood somewhere.  Where turns out to matter
    a great deal.
    """

    PADLOCK = "\U0001f510"

    def test_a_marked_diagnostic_is_still_written(self):
        """Otherwise every SMP line in the transcript reads <unlogged line>."""
        assert LINE(self.PADLOCK + " [smp] passphrase stored for auto-respond.") \
            == "[smp] passphrase stored for auto-respond."

    def test_the_marker_survives_being_coloured(self):
        """The tag is printed blue, so the real line carries ANSI too."""
        assert LINE(self.PADLOCK + " \033[94m[smp]\033[0m started with bob") \
            == "[smp] started with bob"

    def test_a_marker_cannot_carry_a_message_body_past_the_redaction(self):
        """The reason markers are stripped BEFORE any rule is matched.

        Strip them only inside the `[tag]` rule and this line stops being a
        message line and becomes a diagnostic one -- and `otr` is an allowed
        tag, so the words a user typed would be written to a file people paste
        into bug reports.
        """
        rendered = LINE(self.PADLOCK + " [otr] <alice@example.i2p> the words")
        assert "the words" not in rendered
        assert "redacted" in rendered
        assert "alice@example.i2p" in rendered

    def test_an_unknown_glyph_is_not_a_marker(self):
        """The list is exact.  "Any leading emoji" would be a way in."""
        rendered = LINE("\U0001f600 [smp] not one of ours")
        assert rendered.startswith("<unlogged line:")

    def test_a_run_of_markers_is_bounded(self):
        """A long prefix must not become an unbounded strip loop."""
        rendered = LINE(self.PADLOCK * 40 + " [smp] hello")
        assert rendered.startswith("<unlogged line:")

    def test_an_unmarked_line_is_untouched(self):
        assert LINE("[i2p] SAM control socket open") \
            == "[i2p] SAM control socket open"


class TestTheSmpTagIsMarkedEverywhere:
    """The padlock is not decoration applied at one print site.

    A bare "[smp]" left in a string literal is a line that prints without the
    marker, which is how a convention rots.
    """

    def test_no_bare_smp_tag_is_left_in_the_client(self):
        source = open(xmpp.__file__, encoding="utf-8").read()
        bare = [n for n, line in enumerate(source.split("\n"), 1)
                if ('"[smp]' in line or "'[smp]" in line)
                and not line.startswith("_SMP =")]
        assert bare == [], \
            "these lines print an unmarked SMP tag: %s" % bare

    def test_the_marker_is_defined_once(self):
        assert xmpp._SMP.endswith("[smp]") or "[smp]" in xmpp._SMP
        assert xmpp._SMP.startswith("\U0001f510")

    def test_the_marker_is_one_the_transcript_knows(self):
        """Print a glyph the log does not know and every SMP line is redacted.

        This is the coupling that broke first, so it is asserted rather than
        remembered.
        """
        assert any(xmpp._SMP.startswith(m) for m in xmpp._LOG_MARKERS)

    def test_blue_is_not_the_verified_marker(self):
        """The blue circle means SMP *finished* and matched.  Putting it on
        every SMP line would announce the end state at the start."""
        assert "\U0001f535" not in xmpp._SMP
