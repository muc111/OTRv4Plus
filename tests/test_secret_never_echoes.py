#!/usr/bin/env python3
"""INV-04, INV-05 -- The SMP passphrase must not be echoed.

It never was hidden -- neither client ever masked it -- and that surfaced the
hard way: five of six session captures sent in a bug report contained a line
typed straight after the passphrase prompt, each followed by "passphrase
stored". A shared secret in a log file that gets emailed around is the whole
threat SMP exists to defend against, arriving by the back door.

The engine clears the input line on Enter, so it vanishes from the screen. It
does NOT vanish from a `script` capture, which records the keystrokes as they
were echoed, before the erase. Masking the echo is the only thing that helps.
"""

import inspect
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

otr = pytest.importorskip("otrv4_")
xmpp = pytest.importorskip("otrv4plus_xmpp")


class TestTheEngineCanHideIt:

    def test_the_mask_switch_exists_and_defaults_off(self):
        assert hasattr(otr, "set_input_mask")
        assert otr._mask_input is False, (
            "the mask is on by default, so ordinary commands would be hidden")

    def test_masking_replaces_the_display_but_not_the_value(self):
        otr._input_buffer[:] = list("hunter2")
        try:
            otr.set_input_mask(True)
            shown = otr._display_buffer()
            assert shown == "•" * 7, shown
            assert "hunter2" not in shown
            assert "".join(otr._input_buffer) == "hunter2", (
                "masking altered the buffer; the passphrase would be wrong")
        finally:
            otr.set_input_mask(False)
            otr._input_buffer[:] = []

    def test_unmasking_restores_the_display(self):
        otr._input_buffer[:] = list("abc")
        try:
            otr.set_input_mask(True)
            otr.set_input_mask(False)
            assert otr._display_buffer() == "abc"
        finally:
            otr._input_buffer[:] = []

    def test_every_redraw_goes_through_the_helper(self):
        """A new redraw site that joins the buffer itself would leak silently.

        The submit path is the single exception: it must return the real text.
        """
        src = inspect.getsource(otr)
        lines = [l.strip() for l in src.split("\n")
                 if '"".join(_input_buffer)' in l]
        # Exactly two are legitimate: the submit, which must return the real
        # text, and _display_buffer's own unmasked branch.
        assert len(lines) == 2, (
            "%d sites join the input buffer directly: %r. Only the submit and "
            "_display_buffer may; everything that renders must go through the "
            "helper." % (len(lines), lines))
        assert any(l.startswith("line =") for l in lines), (
            "the submit path no longer reads the real buffer: %r" % lines)
        assert any(l.startswith("return") for l in lines), (
            "_display_buffer no longer returns the unmasked text: %r" % lines)

    def test_the_character_echo_is_masked_too(self):
        """Redraws are not the only way a character reaches the terminal."""
        src = inspect.getsource(otr)
        i = src.index("if _input_pos == len(_input_buffer):")
        window = src[i - 300:i + 400]
        assert "_mask_input" in window, (
            "the per-keystroke echo does not consult the mask, so every "
            "character is printed as it is typed")


class TestTheClientTurnsItOn:

    def test_the_prompt_masks(self):
        src = inspect.getsource(xmpp.OTRv4PlusXMPP._request_smp_secret)
        assert "_mask_next_input(True)" in src

    def test_the_answer_unmasks(self):
        src = inspect.getsource(xmpp.OTRv4PlusXMPP._handle_smp_secret_answer)
        assert "_mask_next_input(False)" in src, (
            "the mask is never cleared, so every later command is hidden too")

    def test_unmasking_happens_before_any_early_return(self):
        """`skip` and a validation failure both return early."""
        import ast, textwrap
        fn = ast.parse(textwrap.dedent(
            inspect.getsource(xmpp.OTRv4PlusXMPP._handle_smp_secret_answer))).body[0]
        calls = [n for n in ast.walk(fn) if isinstance(n, ast.Call)
                 and isinstance(n.func, ast.Attribute)
                 and n.func.attr == "_mask_next_input"]
        assert calls, "nothing clears the mask"
        first_return = min((n.lineno for n in ast.walk(fn)
                            if isinstance(n, ast.Return)), default=10 ** 9)
        assert min(c.lineno for c in calls) < first_return, (
            "an early return can leave the input line masked for good")

    def test_it_reaches_the_engine(self):
        src = inspect.getsource(xmpp.OTRv4PlusXMPP._mask_next_input)
        assert "set_input_mask" in src

    def test_the_plain_reader_uses_getpass_for_it(self):
        src = inspect.getsource(xmpp._input_loop)
        assert "getpass" in src, "the non-TUI reader still echoes the passphrase"
        assert "_secret_request" in src, (
            "the hidden read is driven by the display mask rather than by the "
            "explicit request; a stray display state must not be able to "
            "start a hidden read")


class TestTheTerminalItselfStopsEchoing:
    """The only mechanism that works once the reader is blocked.

    In plain mode the loop is inside sys.stdin.readline() from BEFORE the
    prompt was raised, and the echo comes from the terminal driver in the
    kernel. A flag set afterwards changes nothing -- the first version of this
    fix printed "what you type is hidden" and then showed the passphrase in the
    session capture anyway.
    """

    def test_echo_is_cleared_and_restored_on_a_real_pty(self):
        """Run in a clean interpreter: conftest stubs `pty` and `termios`.

        Those stubs make an in-process check meaningless -- every attribute
        answers, so the code would appear to work whether or not it does. The
        whole point here is that a real terminal driver changes state.
        """
        import subprocess, textwrap
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        prog = textwrap.dedent("""
            import os, pty, select, sys, termios, time
            sys.path.insert(0, __ROOT__)
            pid, fd = pty.fork()
            if pid == 0:
                try:
                    import otrv4plus_xmpp as XX
                    c = XX.OTRv4PlusXMPP.__new__(XX.OTRv4PlusXMPP)
                    c._tui_enabled = False
                    c._mask_input = False
                    before = bool(termios.tcgetattr(0)[3] & termios.ECHO)
                    ok = XX.OTRv4PlusXMPP._mask_next_input(c, True)
                    during = bool(termios.tcgetattr(0)[3] & termios.ECHO)
                    XX.OTRv4PlusXMPP._mask_next_input(c, False)
                    after = bool(termios.tcgetattr(0)[3] & termios.ECHO)
                    print("RESULT %d %d %d %d" % (before, ok, during, after))
                except Exception as exc:
                    print("RESULT-ERROR %r" % (exc,))
                finally:
                    sys.stdout.flush()
                    os._exit(0)
            out = b""
            deadline = time.time() + 25
            while time.time() < deadline:
                r, _w, _x = select.select([fd], [], [], 0.3)
                if not r:
                    if os.waitpid(pid, os.WNOHANG)[0]:
                        break
                    continue
                try:
                    chunk = os.read(fd, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                out += chunk
            sys.stderr.write(out.decode("utf-8", "replace"))
        """).replace("__ROOT__", repr(root))
        r = subprocess.run([sys.executable, "-c", prog],
                           capture_output=True, text=True, timeout=120)
        text = r.stderr
        assert "RESULT " in text, "child produced no result: %r" % text[-2000:]
        before, ok, during, after = [
            int(v) for v in text.split("RESULT ")[1].split()[:4]]
        assert before == 1, "the pty started with echo already off"
        assert ok == 1, "masking reported itself ineffective on a real tty"
        assert during == 0, "ECHO was still set while a passphrase was expected"
        assert after == 1, (
            "echo was not restored -- the user's shell is left unusable, "
            "which is worse than showing the passphrase")


class TestItNeverPromisesWhatItCannotDo:

    def test_a_non_tty_reports_masking_as_ineffective(self):
        """Piped stdin cannot hide anything, and must say so."""
        c = xmpp.OTRv4PlusXMPP.__new__(xmpp.OTRv4PlusXMPP)
        c._tui_enabled = False
        c._mask_input = False
        # pytest replaces stdin with a non-tty object.
        try:
            assert xmpp.OTRv4PlusXMPP._mask_next_input(c, True) is False
        finally:
            # The engine's mask is module-global; leaving it on would hide
            # every later test's input line and was caught doing exactly that.
            otr.set_input_mask(False)

    def test_the_prompt_branches_on_the_return_value(self):
        src = inspect.getsource(xmpp.OTRv4PlusXMPP._request_smp_secret)
        assert "hidden = self._mask_next_input(True)" in src
        assert "if hidden:" in src
        low = src.lower()
        assert "warning" in low and "will be" in low, (
            "when hiding fails the user must be told plainly, not told the "
            "opposite")

    def test_the_claim_and_the_warning_are_mutually_exclusive(self):
        import ast, textwrap
        fn = ast.parse(textwrap.dedent(
            inspect.getsource(xmpp.OTRv4PlusXMPP._request_smp_secret))).body[0]
        branch = [n for n in ast.walk(fn) if isinstance(n, ast.If)
                  and isinstance(n.test, ast.Name) and n.test.id == "hidden"]
        assert branch, "the promise is not guarded by whether it is true"
        assert branch[0].orelse, "there is no else branch for the failure case"

    def test_echo_restoration_is_registered_for_exit(self):
        src = inspect.getsource(xmpp.OTRv4PlusXMPP._mask_next_input)
        assert "atexit" in src, (
            "nothing restores echo if the process dies mid-prompt")


class TestTheInlineFormIsDiscouraged:

    def test_a_bare_command_prompts_instead_of_storing(self):
        src = inspect.getsource(xmpp.OTRv4PlusXMPP.dispatch_line)
        i = src.index('"/smp-secret", "/smpsecret"')
        assert "_request_smp_secret" in src[i:i + 400], (
            "/smp-secret with no argument does not offer the hidden prompt")

    def test_the_inline_form_warns_that_it_was_echoed(self):
        src = inspect.getsource(xmpp.OTRv4PlusXMPP.dispatch_line)
        assert src.count("_warn_inline_secret") >= 2, (
            "not every inline passphrase path warns")

    def test_the_warning_says_where_it_ended_up(self):
        src = inspect.getsource(xmpp.OTRv4PlusXMPP._warn_inline_secret)
        low = src.lower()
        assert "scrollback" in low and "capture" in low, (
            "the warning must name the log file, which is where this actually "
            "bit")

    def test_the_help_marks_the_inline_form_as_echoed(self):
        src = inspect.getsource(xmpp.OTRv4PlusXMPP)
        assert "ECHOED" in src


class TestNothingElseGotHidden:

    def test_ordinary_commands_are_not_masked(self):
        otr._input_buffer[:] = list("/otr alice@x")
        try:
            assert otr._display_buffer() == "/otr alice@x"
        finally:
            otr._input_buffer[:] = []
