"""Our own messages appeared twice, and the terminal printed one of them.

v10.27.0 fixed a real bug -- outgoing messages were never echoed at all, so
the session read as a monologue by the peer -- by printing an attributed copy
after each send.  In the TUI that is correct: it owns the screen in raw mode
and does its own echoing.

In PLAIN mode, which is the default, the input loop sits in
`sys.stdin.readline()` with the tty in canonical mode, so the terminal has
already drawn what the user typed before our echo runs.  Reported from a
handset:

    i shiuld not seewgat i type twice
    🔒 [otr] alice@xmpp-elite.i2p: i shiuld not seewgat i type twice

The fix rewrites the terminal's copy rather than printing underneath it, and
almost all of these tests are about the cases where it must NOT do that.
Moving the cursor up is destructive: if the rows above are not the user's
input, the erase eats somebody's conversation.  Printing twice is ugly;
deleting a received message is not recoverable.
"""

import io
import os

import pytest

xmpp = pytest.importorskip("otrv4plus_xmpp")


class Terminal(list):
    """Everything written to the terminal, in order.

    Both seams are patched rather than sys.stdout, and that is not squeamish-
    ness: pytest re-binds sys.stdout for the CALL phase, AFTER fixtures run
    in the SETUP phase, so a fixture that patched it would be silently
    undone and the escape would go to the real terminal. Asking the code for
    its two seams -- how wide is the terminal, write this to it -- tests the
    logic instead of pytest's capture plumbing.
    """

    def text(self):
        return "".join(self)


class Client:
    """Only what `_erase_plain_echo` touches."""

    PLAIN_ECHO_MAX_ROWS = xmpp.OTRv4PlusXMPP.PLAIN_ECHO_MAX_ROWS
    _erase_plain_echo = xmpp.OTRv4PlusXMPP._erase_plain_echo

    def __init__(self, tui=False, pending=None):
        self._tui_enabled = tui
        self._plain_echo = pending


@pytest.fixture
def term(monkeypatch):
    """A 40-column terminal, with everything written to it captured."""
    out = Terminal()
    monkeypatch.setattr(xmpp, "_terminal_cols", lambda: 40)
    monkeypatch.setattr(xmpp, "_raw_write", out.append)
    return out


@pytest.fixture
def no_term(monkeypatch):
    """A stdout that is not a terminal we can measure."""
    out = Terminal()
    monkeypatch.setattr(xmpp, "_terminal_cols", lambda: None)
    monkeypatch.setattr(xmpp, "_raw_write", out.append)
    return out


def _armed(text):
    """The state the input loop leaves behind for a line it just read."""
    return (xmpp._PRINT_SEQ, text)


# ---------------------------------------------------------------------------
# the fix
# ---------------------------------------------------------------------------

class TestItRewritesTheTerminalsCopy:

    def test_a_short_line_erases_one_row(self, term):
        Client(pending=_armed("hello"))._erase_plain_echo("hello")
        assert term.text() == "\x1b[1A\r\x1b[J"

    def test_a_wrapped_line_erases_every_row_it_used(self, term):
        text = "x" * 85                      # 3 rows at 40 columns
        Client(pending=_armed(text))._erase_plain_echo(text)
        assert term.text() == "\x1b[3A\r\x1b[J"

    def test_a_line_exactly_the_terminal_width_is_one_row(self, term):
        # The wrap happens on the character AFTER the last column, so an
        # exactly-full line has not wrapped. Off by one here erases a row of
        # real output on every full-width message.
        text = "x" * 40
        Client(pending=_armed(text))._erase_plain_echo(text)
        assert term.text() == "\x1b[1A\r\x1b[J"

    def test_one_over_the_width_is_two_rows(self, term):
        text = "x" * 41
        Client(pending=_armed(text))._erase_plain_echo(text)
        assert term.text() == "\x1b[2A\r\x1b[J"

    def test_the_arming_is_consumed(self, term):
        c = Client(pending=_armed("hello"))
        c._erase_plain_echo("hello")
        assert c._plain_echo is None

    def test_it_only_fires_once(self, term):
        c = Client(pending=_armed("hello"))
        c._erase_plain_echo("hello")
        del term[:]
        c._erase_plain_echo("hello")
        assert term.text() == ""


# ---------------------------------------------------------------------------
# every case where moving the cursor would be destructive
# ---------------------------------------------------------------------------

class TestItRefusesWhenItCannotBeSure:

    def test_the_tui_is_left_alone(self, term):
        # The TUI echoes input itself and owns the screen; there is no
        # terminal copy to remove and the escape would corrupt a panel.
        Client(tui=True, pending=_armed("hello"))._erase_plain_echo("hello")
        assert term.text() == ""

    def test_nothing_happens_without_a_read_to_match(self, term):
        # A message sent by something other than the keyboard -- a command
        # handler, a reconnect replay -- has no terminal echo above it.
        Client(pending=None)._erase_plain_echo("hello")
        assert term.text() == ""

    def test_a_different_line_is_not_erased(self, term):
        Client(pending=_armed("hello"))._erase_plain_echo("goodbye")
        assert term.text() == ""

    def test_output_arriving_in_between_cancels_it(self, term, monkeypatch):
        """The race this exists to lose safely.

        Between the user pressing Enter and the echo running, an inbound
        message can print. The row above the cursor is then that message, and
        erasing it would delete what the peer said.
        """
        c = Client(pending=_armed("hello"))
        monkeypatch.setattr(xmpp, "_PRINT_SEQ", xmpp._PRINT_SEQ + 1)
        c._erase_plain_echo("hello")
        assert term.text() == ""

    def test_a_stdout_that_is_not_a_terminal_is_left_alone(self, no_term):
        Client(pending=_armed("hello"))._erase_plain_echo("hello")
        assert no_term.text() == ""

    def test_an_unknown_terminal_width_is_left_alone(self, no_term):
        # `_terminal_cols` collapses "not a terminal" and "a terminal whose
        # width we could not read" into one answer on purpose: both must fail
        # by not moving the cursor.
        Client(pending=_armed("hello"))._erase_plain_echo("hello")
        assert no_term.text() == ""

    def test_a_pasted_wall_of_text_is_left_alone(self, term):
        # Unwinding twelve-plus rows is not worth the chance of getting the
        # count wrong and scrolling real output away.
        text = "x" * (40 * (Client.PLAIN_ECHO_MAX_ROWS + 1))
        Client(pending=_armed(text))._erase_plain_echo(text)
        assert term.text() == ""

    def test_it_never_raises(self, monkeypatch):
        def boom():
            raise RuntimeError("boom")

        monkeypatch.setattr(xmpp, "_terminal_cols", boom)
        Client(pending=_armed("hello"))._erase_plain_echo("hello")

    def test_the_cursor_move_is_not_logged_as_content(self):
        """Cursor movement must not reach the transcript or the counter.

        `_raw_write` rather than `print`: the escape is not content, it must
        not be written to the session log, and it must not advance
        `_PRINT_SEQ` -- the counter whose whole job is to say whether
        content was printed since the user pressed Enter.
        """
        import inspect
        src = inspect.getsource(xmpp.OTRv4PlusXMPP._erase_plain_echo)
        assert "_raw_write(" in src
        assert "print(" not in src
        # Code only. An earlier version of this matched the docstring,
        # which explains exactly the thing it must not do.
        import ast
        import textwrap
        tree = ast.parse(textwrap.dedent(inspect.getsource(xmpp._raw_write)))
        fn = tree.body[0]
        if (fn.body and isinstance(fn.body[0], ast.Expr)
                and isinstance(fn.body[0].value, ast.Constant)):
            fn.body = fn.body[1:]
        names = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name)}
        names |= {n.attr for n in ast.walk(fn) if isinstance(n, ast.Attribute)}
        assert "_log_to_file" not in names
        assert "_PRINT_SEQ" not in names


class TestTerminalCols:

    @staticmethod
    def _cols(monkeypatch, tty, size):
        """Drive _terminal_cols with a stdout of our own.

        Patched inside the test body, never in a fixture: pytest re-binds
        sys.stdout between setup and call.
        """
        class Out:
            def isatty(self):
                if isinstance(tty, Exception):
                    raise tty
                return tty

        monkeypatch.setattr(xmpp.sys, "stdout", Out())
        if isinstance(size, Exception):
            def boom(*_a):
                raise size
            monkeypatch.setattr(xmpp.os, "get_terminal_size", boom)
        else:
            monkeypatch.setattr(xmpp.os, "get_terminal_size",
                                lambda *a: os.terminal_size((size, 24)))
        return xmpp._terminal_cols()

    def test_a_stream_that_is_not_a_tty_measures_nothing(self, monkeypatch):
        assert self._cols(monkeypatch, False, 80) is None

    def test_an_unreadable_size_measures_nothing(self, monkeypatch):
        assert self._cols(monkeypatch, True, OSError("TIOCGWINSZ")) is None

    def test_a_zero_width_terminal_measures_nothing(self, monkeypatch):
        assert self._cols(monkeypatch, True, 0) is None

    def test_a_stdout_that_explodes_measures_nothing(self, monkeypatch):
        assert self._cols(monkeypatch, RuntimeError("boom"), 80) is None

    def test_a_real_width_is_returned(self, monkeypatch):
        assert self._cols(monkeypatch, True, 132) == 132


# ---------------------------------------------------------------------------
# the wiring
# ---------------------------------------------------------------------------

class TestTheWiring:

    def test_printing_advances_the_counter(self, capsys):
        before = xmpp._PRINT_SEQ
        xmpp.print("anything")
        assert xmpp._PRINT_SEQ > before

    def test_the_input_loop_arms_it(self):
        src = open("otrv4plus_xmpp.py").read()
        assert "client._plain_echo = (_PRINT_SEQ, line.rstrip(\"\\n\"))" in src

    def test_the_echo_erases_before_it_prints(self):
        """Order matters: erase, then print.

        Printing first advances _PRINT_SEQ, so the guard that compares it
        would never match and the erase would never fire.
        """
        import inspect
        src = inspect.getsource(xmpp.OTRv4PlusXMPP._echo_sent)
        assert src.index("_erase_plain_echo") < src.index("print(")

    def test_the_message_still_reaches_the_log(self):
        # The v10.27.0 bug underneath all of this: without the echo the
        # channel log recorded only one side of the conversation. Erasing the
        # terminal's copy must not turn into erasing the record.
        import inspect
        src = inspect.getsource(xmpp.OTRv4PlusXMPP._echo_sent)
        assert "print(" in src
