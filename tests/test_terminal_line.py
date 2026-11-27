# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The raw-mode terminal's state is one object, otrv4plus_tty.TTY.

It was fifteen globals in otrv4+.py. Three bugs came with that, and each
has a test here: the IRC full-screen UI set its PgUp/PgDn callback in its
own module's globals, where the key handler never looked; PgUp and PgDn
ran while holding the print lock, which the scroll code takes again, so
the terminal hung; and Backspace in the middle of a masked passphrase
re-echoed the rest of it in clear.
"""
import os
import pathlib
import sys
import threading

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "client"))

import otrv4plus_tty as tty  # noqa: E402
from otrv4plus_tty import TTY  # noqa: E402


@pytest.fixture
def clean_line(capsys):
    """A fresh input line; read what it printed with clean_line.readouterr()."""
    saved = (TTY.prompt, list(TTY.buffer), TTY.pos, TTY.masked, TTY.paused,
             TTY.scroll_callback, TTY.on_keypress, TTY.fd, list(TTY.history))
    TTY.prompt, TTY.buffer[:], TTY.pos, TTY.masked, TTY.paused = "> ", [], 0, False, False
    TTY.scroll_callback = TTY.on_keypress = None
    yield capsys
    (TTY.prompt, TTY.buffer[:], TTY.pos, TTY.masked, TTY.paused,
     TTY.scroll_callback, TTY.on_keypress, TTY.fd, TTY.history[:]) = saved


def _type(text):
    for ch in text:
        tty._handle_input_char(ch)


def test_the_engine_names_read_the_one_state():
    """otrv4+.py's old names read TTY; both of the names the engine file is
    loaded under (otrv4plus, otrv4_) see the same object."""
    otr = pytest.importorskip("otrv4_")
    import otrv4plus
    otr.set_input_mask(True)
    try:
        assert TTY.masked is True
        assert otr._mask_input is True and otrv4plus._mask_input is True
        assert otr._input_buffer is TTY.buffer is otrv4plus._input_buffer
        assert otr._print_lock is TTY.lock
    finally:
        otr.set_input_mask(False)
    with pytest.raises(AttributeError):
        otr.no_such_attribute


def test_typing_and_enter(clean_line):
    _type("hi")
    assert TTY.buffer == ["h", "i"] and TTY.pos == 2
    assert tty._handle_input_char("\r") == "hi"
    assert TTY.buffer == [] and TTY.pos == 0


def test_ctrl_d_on_an_empty_line_is_eof(clean_line):
    assert tty._handle_input_char("\x04") is tty._EOF_SENTINEL
    _type("x")
    assert tty._handle_input_char("\x04") is None


def test_backspace_mid_passphrase_does_not_echo_it(clean_line):
    TTY.masked = True
    _type("hunter2")
    TTY.pos = 3                              # cursor after "hun"
    clean_line.readouterr()                  # forget the typing's echo
    tty._handle_input_char("\x7f")
    echoed = clean_line.readouterr().out
    assert "ter2" not in echoed and "•" * 4 in echoed
    assert "".join(TTY.buffer) == "huter2", "the value itself is unchanged"


def test_pgup_reaches_a_full_screen_ui_and_does_not_hang(clean_line):
    """The callback is run with the lock free: a full-screen redraw takes it."""
    got = []

    def scroll(direction, lines):
        took = TTY.lock.acquire(timeout=2)
        if took:
            TTY.lock.release()
        got.append((direction, took))

    TTY.scroll_callback = scroll
    r, w = os.pipe()
    try:
        TTY.fd = r
        os.write(w, b"[5~")
        tty._consume_escape_seq()
        os.write(w, b"[6~")
        tty._consume_escape_seq()
    finally:
        os.close(r)
        os.close(w)
    assert got == [("pgup", True), ("pgdn", True)]


def test_pgup_in_line_mode_pauses_and_pgdn_resumes(clean_line):
    for i in range(50):
        TTY.remember("line %d" % i)
    r, w = os.pipe()
    try:
        TTY.fd = r
        done = threading.Event()

        def press(seq):
            os.write(w, seq)
            tty._consume_escape_seq()

        t = threading.Thread(target=lambda: (press(b"[5~"), done.set()))
        t.start()
        t.join(5)
        assert done.is_set(), "PgUp hung"
        assert TTY.paused and TTY.scroll_pos > 0
        TTY.scroll_pos = 1
        press(b"[6~")
        assert not TTY.paused and TTY.scroll_pos == 0
    finally:
        os.close(r)
        os.close(w)


def test_lines_printed_while_paused_are_held_then_shown(clean_line):
    TTY.paused = True
    tty._emit_line("one")
    tty._emit_line("two")
    assert list(TTY.held) == ["one", "two"]
    tty._scroll_unlock()
    assert not TTY.paused and not TTY.held
    out = clean_line.readouterr().out
    assert out.index("one") < out.index("two")


def test_history_keeps_the_last_lines_only():
    saved = list(TTY.history)
    try:
        TTY.history.clear()
        for i in range(tty.SCROLLBACK_LINES + 20):
            TTY.remember(str(i))
        assert len(TTY.history) == tty.SCROLLBACK_LINES
        assert TTY.history[-1] == str(tty.SCROLLBACK_LINES + 19)
    finally:
        TTY.history[:] = saved


def test_a_typed_key_calls_the_typing_hook(clean_line):
    calls = []
    TTY.on_keypress = lambda: calls.append(1)
    _type("ab")
    tty._handle_input_char("\x7f")               # not a typed character
    assert len(calls) == 2


def test_nothing_writes_the_state_through_old_names():
    """An assignment to otrv4+._TUI_SCROLL_CALLBACK, or through globals(),
    lands somewhere the terminal never reads."""
    import re
    client = os.path.join(ROOT, "client")
    old = ("_print_lock", "_current_prompt", "_input_buffer", "_input_pos",
           "_mask_input", "_raw_mode_active", "_stdin_fd", "_orig_termios",
           "_scroll_locked", "_scroll_buffer", "_scroll_pos",
           "_scroll_history", "_TUI_SCROLL_CALLBACK", "_display_queue")
    pattern = re.compile(r"(?:\b(?!self\b)\w+\.|globals\(\)\[[\"'])(%s)\b[\"']?\]?\s*=[^=]"
                         % "|".join(old))
    offenders = []
    for name in sorted(os.listdir(client)):
        path = os.path.join(client, name)
        if name.endswith(".py") and not os.path.islink(path):
            for n, line in enumerate(pathlib.Path(path).read_text(encoding="utf-8").splitlines(keepends=True), 1):
                if pattern.search(line):
                    offenders.append("%s:%d: %s" % (name, n, line.strip()))
    assert not offenders, "\n".join(offenders)


def test_the_irc_client_registers_its_hooks():
    src = pathlib.Path(os.path.join(ROOT, "client", "otrv4plus_irc.py")).read_text(encoding="utf-8")
    assert "client.attach_terminal()" in src
    for hook in ("on_keypress", "debug_sink", "refresh_prompt", "redraw"):
        assert "_tty.TTY.%s = " % hook in src, hook


def test_debug_lines_go_to_the_sink_when_there_is_one(clean_line):
    got = []
    tty.debug_line("one")                      # no sink: printed
    assert "one" in clean_line.readouterr().out
    TTY.debug_sink = got.append
    try:
        tty.debug_line("two")
        assert got == ["two"] and "two" not in clean_line.readouterr().out
    finally:
        TTY.debug_sink = None


def test_a_failing_hook_does_not_break_the_caller():
    def boom():
        raise RuntimeError("hook failed")
    saved = TTY.refresh_prompt, TTY.redraw
    TTY.refresh_prompt = TTY.redraw = boom
    try:
        tty.refresh_prompt()
        tty.redraw()
    finally:
        TTY.refresh_prompt, TTY.redraw = saved


def test_no_terminal_client_module_keeps_state_in_builtins():
    """`builtins._active_client` was how the engine reached the IRC client;
    the hooks on TTY replace it."""
    import re
    client = os.path.join(ROOT, "client")
    pattern = re.compile(r"__import__\(\s*[\"']builtins[\"']\s*\)|\b_b\.\w+\s*=")
    offenders = []
    for name in sorted(os.listdir(client)):
        path = os.path.join(client, name)
        if (name.startswith("otrv4plus_irc") or name in (
                "otrv4+.py", "otrv4plus_tty.py", "otrv4plus_panels.py")) \
                and name.endswith(".py") and not os.path.islink(path):
            for n, line in enumerate(pathlib.Path(path).read_text(encoding="utf-8").splitlines(keepends=True), 1):
                if pattern.search(line):
                    offenders.append("%s:%d: %s" % (name, n, line.strip()))
    assert not offenders, "\n".join(offenders)
