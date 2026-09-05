"""The XMPP client's status tags, coloured by what they mean.

Almost every line this client prints is `[tag] free text`, and every one of
those tags used to be the same colour as the sentence after it.  On a handset
that is a wall of grey in which a fingerprint-change warning and a keepalive
tick look identical until both have been read.

Colour is display only, and the two things it must not disturb are the two
that already work: the on-disk transcript, whose redaction (INV-03) reasons
about the SHAPE of a line, and the TUI's panel routing, which decides where a
line goes with `startswith("[keepalive]")`.  An escape sequence in front of
the tag defeats both.  Those are what most of this file is about.
"""

import re

import pytest


def _module_constant(name):
    """Read one module-level literal out of the source, without importing.

    Parsed rather than sliced out with str.index: the earlier version of this
    looked for the closing brace and found the one inside `frozenset({`.
    """
    import ast
    tree = ast.parse(open("otrv4plus_xmpp.py").read())
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if any(getattr(t, "id", None) == name for t in node.targets):
            return eval(compile(ast.Expression(node.value), "<c>", "eval"),
                        {"frozenset": frozenset})
    raise AssertionError("%s is no longer a module-level assignment" % name)


def _load(colorize=None):
    """Exec just the colouring helper, with a visible stand-in for ANSI.

    Importing otrv4plus_xmpp pulls in slixmpp and the OTR engine, neither of
    which this code touches. The real `_colorize` is the engine's, and is
    substituted here so an assertion failure prints `<yellow>[keepalive]</>`
    instead of a line of escape bytes.
    """
    src = open("otrv4plus_xmpp.py").read()
    start = src.index("_TAG_COLOURS = {")
    end = src.index("def print(*args, **kwargs):")
    ns = {"re": re,
          "_colorize": colorize or (lambda s, c: "<%s>%s</>" % (c, s))}
    exec(compile(src[start:end], "otrv4plus_xmpp.py", "exec"), ns)
    return ns


@pytest.fixture(scope="module")
def mod():
    return _load()


@pytest.fixture(scope="module")
def colour(mod):
    return mod["_colour_tag"]


# ---------------------------------------------------------------------------
# what gets coloured
# ---------------------------------------------------------------------------

class TestItColoursTheTag:

    def test_a_known_tag_is_coloured(self, colour):
        assert colour("[keepalive] tick 3") == "<yellow>[keepalive]</> tick 3"

    def test_only_the_tag_is_coloured(self, colour):
        out = colour("[voice] call active with alice@example.i2p")
        assert out.endswith(" call active with alice@example.i2p")

    def test_a_tag_with_a_space_is_matched(self, colour):
        # "[auth failed]" is one tag, not a tag and a word.
        assert colour("[auth failed] 3 attempts used").startswith(
            "<bold_red>[auth failed]</>")

    def test_an_unknown_tag_is_left_alone(self, colour):
        assert colour("[wibble] hello") == "[wibble] hello"

    def test_an_untagged_line_is_left_alone(self, colour):
        assert colour("just some text") == "just some text"

    def test_a_tag_that_is_not_at_the_start_is_left_alone(self, colour):
        # Only a leading tag is the line's subject. One in the middle of a
        # sentence is quoted text, and colouring it would be wrong.
        assert colour("see [voice] for details") == "see [voice] for details"

    def test_an_indented_line_is_left_alone(self, colour):
        # The continuation lines of a multi-line report are indented under
        # their own heading; colouring them would repeat the heading's mark
        # down the block.
        assert colour("  [i2p] more") == "  [i2p] more"

    def test_an_empty_line_survives(self, colour):
        assert colour("") == ""

    def test_none_survives(self, colour):
        assert colour(None) is None


# ---------------------------------------------------------------------------
# what must NOT be recoloured
# ---------------------------------------------------------------------------

class TestItLeavesTheExistingPaletteAlone:

    def test_an_smp_prompt_is_untouched(self, colour):
        # Safe by construction, not by a guard: the tag is already wrapped in
        # an escape sequence, so the anchored pattern does not match.
        line = "\x1b[94m[smp]\x1b[0m enter the passphrase"
        assert colour(line) is line

    def test_otr_is_not_in_the_table(self, mod):
        # [otr] and [smp] carry their own padlock-and-colour prefixes. A
        # second scheme applied here would fight them on the same line.
        assert "otr" not in mod["_TAG_COLOURS"]
        assert "smp" not in mod["_TAG_COLOURS"]

    def test_the_chat_transcript_shape_is_untouched(self, colour):
        # The padlock comes first, so there is no leading bare tag to match.
        line = "\U0001f512 \x1b[93m[otr]\x1b[0m \x1b[93malice@x:\x1b[0m hi"
        assert colour(line) is line

    def test_the_voice_summary_keeps_its_banded_latency_colour(self, colour):
        # The one line that reaches here already carrying colour. Its tag is
        # coloured like the rest of the call's output, and the mouth-to-ear
        # reading keeps the green/amber/red its band gave it.
        line = ("[voice] \U0001f7e2 call ended — good — 2m14s, mouth-to-ear "
                "~\x1b[92m340ms\x1b[0m, 99.8% of audio delivered")
        out = colour(line)
        assert out.startswith("<magenta>[voice]</>")
        assert "\x1b[92m340ms\x1b[0m" in out


# ---------------------------------------------------------------------------
# it can never break the caller
# ---------------------------------------------------------------------------

class TestItNeverRaises:

    def test_a_hostile_object_does_not_explode(self, colour):
        class Hostile:
            def __contains__(self, _x):
                raise RuntimeError("boom")

        assert colour(Hostile()) is not None

    def test_an_unknown_colour_name_degrades_to_plain(self):
        # The engine's colorize() returns the text unchanged for a colour it
        # does not know, so a table entry naming one that has been renamed
        # away costs the line its colour and nothing else.
        ns = _load(colorize=lambda s, c: s)
        assert ns["_colour_tag"]("[i2p] hello") == "[i2p] hello"


# ---------------------------------------------------------------------------
# the two things colour must not disturb
# ---------------------------------------------------------------------------

class TestItDoesNotBreakTheTranscript:

    def test_colouring_a_tag_grants_it_nothing_on_disk(self, mod):
        """The two tables are independent, and must stay that way.

        Eleven of the coloured tags are deliberately NOT in _LOG_SAFE_TAGS --
        [file] prints filenames, [roster] prints contacts, [tip] prints a
        Monero address, [trade] prints trade detail -- so those lines reach
        the transcript as "<unlogged line: N chars>".  That is INV-03 working:
        the allowlist asks "can this tag ever print a secret", and the answer
        for each of them is yes.

        The hazard is the obvious-looking tidy-up: noticing the mismatch and
        "fixing" it by pasting the colour table into the allowlist, which
        would put filenames, contacts and payment addresses on disk to make
        a cosmetic table symmetrical.  This test exists to make that show up
        as a deliberate edit here rather than a quiet one there.
        """
        safe = _module_constant("_LOG_SAFE_TAGS")
        coloured_and_unlogged = sorted(
            t for t in mod["_TAG_COLOURS"] if t not in safe)
        assert coloured_and_unlogged == [
            "auth failed", "fatal", "file", "keepalive", "rate-limit",
            "reconnect", "roster", "tip", "tor", "trade",
        ]

    def test_every_coloured_tag_is_one_the_client_actually_prints(self, mod):
        """No colours for tags that do not exist.

        A table entry for a tag nothing emits is a claim about the output
        that is not true, and it is how a table drifts: the entry survives
        every rename because nothing ever contradicts it.
        """
        # The opening quote is part of the needle: a bare "[tag]" would match
        # a comment or a docstring that merely mentions the tag, and the
        # claim being checked is that something PRINTS it.  Both plain and
        # f-string forms are used in this client.
        src = (open("otrv4plus_xmpp.py").read()
               + open("otrv4plus_voice.py").read())
        for tag in mod["_TAG_COLOURS"]:
            assert ('"[%s]' % tag) in src, (
                "[%s] is coloured but nothing prints it" % tag)

    def test_the_log_is_written_before_the_colour_is_applied(self):
        src = open("otrv4plus_xmpp.py").read()
        body = src[src.index("def print(*args, **kwargs):"):]
        body = body[:body.index("\ntry:")]
        assert body.index("_log_to_file(msg)") < body.index("_colour_tag(msg)")

    def test_the_channel_log_is_written_before_the_colour_is_applied(self):
        src = open("otrv4plus_xmpp.py").read()
        body = src[src.index("def print(*args, **kwargs):"):]
        body = body[:body.index("\ntry:")]
        assert body.index("channel_log.append") < body.index("_colour_tag(msg)")


class TestItDoesNotBreakPanelRouting:

    def test_the_tui_is_handed_the_plain_line(self):
        """The failure this pins, precisely.

        _tui_route_output routes with `stripped.startswith("[keepalive]")`
        and the rest of _SYS_PREFIXES. Hand it a coloured line and every one
        of those tests fails silently: keepalive ticks stop going to the
        debug panel and land in whichever chat panel was last active.
        """
        src = open("otrv4plus_xmpp.py").read()
        body = src[src.index("def print(*args, **kwargs):"):]
        body = body[:body.index("\ntry:")]
        assert "_tui_route_output(msg)" in body
        assert "_tui_route_output(shown)" not in body

    def test_routing_still_matches_a_plain_tag(self):
        src = open("otrv4plus_xmpp.py").read()
        assert '"[keepalive]",' in src        # still a bare-prefix match
