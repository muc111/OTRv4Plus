# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The raw-mode terminal: the input line, the prompt, and scrollback.

The terminal clients read keys one at a time (no line discipline) so that
incoming messages can be printed above what the user is typing without
breaking it. That needs some state -- the prompt, the typed text and the
cursor in it, whether the text is masked, whether the screen is paused --
and every printing path has to agree on it.

All of that state is one object, `TTY`. Before, it was fifteen module
globals in otrv4+.py, written through `global` statements and, from one
module, through `globals()`, which wrote the wrong module's copy: the IRC
full-screen UI's PgUp/PgDn callback never reached the key handler. The
functions keep their old names (`_set_prompt`, `_emit_line`, ...) so the
clients did not have to change how they call them.

Masking: while a passphrase is typed, `TTY.masked` is set and every redraw
path renders the line through `_display_buffer()`, which shows dots. No
other function joins `TTY.buffer` for display, so a new redraw path cannot
quietly echo a secret (tests/test_secret_never_echoes.py holds that).
"""
import os
import re
import select
import shutil
import sys
import threading
from collections import deque
from typing import Callable, List, Optional

from otrv4plus_sanitise import sanitise as _sanitise
from otrv4plus_states import UIConstants, colorize

#: Termux, where a narrow width report is usually wrong (see TERMINAL_WIDTH).
IS_TERMUX = "ANDROID_ROOT" in os.environ or "TERMUX_VERSION" in os.environ

try:
    _size = shutil.get_terminal_size(fallback=(80, 24))
    TERMINAL_WIDTH = _size.columns
    TERMINAL_HEIGHT = _size.lines
    if IS_TERMUX and TERMINAL_WIDTH < 40:
        TERMINAL_WIDTH = 80
except Exception:
    TERMINAL_WIDTH = 80
    TERMINAL_HEIGHT = 24

#: How times are shown in the terminal clients.
TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"

#: Returned by _handle_input_char for Ctrl-D on an empty line.
_EOF_SENTINEL = object()

#: How many printed lines PgUp can scroll back through, and how many lines a
#: paused screen holds back.
SCROLLBACK_LINES = 500


class TerminalLine:
    """Everything the raw-mode terminal needs to remember."""

    def __init__(self):
        #: Held while anything writes to the terminal, so a message printed
        #: from a network thread cannot interleave with a keystroke's echo.
        self.lock = threading.Lock()
        self.prompt: str = ""
        #: What has been typed, one character per item, and the cursor in it.
        self.buffer: List[str] = []
        self.pos: int = 0
        #: Show dots instead of the typed characters (passphrase entry).
        self.masked: bool = False
        #: Raw mode: whether it is on, stdin's fd, and the settings to restore.
        self.raw: bool = False
        self.fd: int = -1
        self.saved_termios = None
        #: Paused (Ctrl-S / Ctrl-P, or scrolled back): lines are held, not
        #: printed, until it is resumed.
        self.paused: bool = False
        self.held: deque = deque(maxlen=SCROLLBACK_LINES)
        #: Lines already printed, for PgUp in line mode, and how far back the
        #: view is.
        self.history: List[str] = []
        self.scroll_pos: int = 0
        #: A full-screen UI, when one is up, scrolls itself: it gets
        #: ("pgup" | "pgdn", lines) instead of the line-mode scrollback.
        self.scroll_callback: Optional[Callable[[str, int], None]] = None
        #: Hooks a client registers at start (the IRC client does; the XMPP
        #: client prints through otrv4plus_term instead). Each is optional.
        #: After a printable key is typed (IRC: a typing notification).
        self.on_keypress: Optional[Callable[[], None]] = None
        #: Where a debug line goes instead of the terminal (IRC: the debug
        #: panel).
        self.debug_sink: Optional[Callable[[str], None]] = None
        #: Redraw the prompt after something printed over it.
        self.refresh_prompt: Optional[Callable[[], None]] = None
        #: Redraw everything after a full-screen interruption (the pager).
        self.redraw: Optional[Callable[[], None]] = None
        #: Lines waiting for _flush_display_queue (cooked-mode fallback).
        self.queue: deque = deque()

    def remember(self, line: str) -> None:
        self.history.append(line)
        if len(self.history) > SCROLLBACK_LINES:
            del self.history[:-SCROLLBACK_LINES]


TTY = TerminalLine()


def debug_line(text: str) -> None:
    """A debug line: to the client's debug panel if it has one, else printed."""
    if TTY.debug_sink is not None:
        TTY.debug_sink(text)
    else:
        _emit_line(text)


def _call_hook(hook) -> None:
    if hook is not None:
        try:
            hook()
        except Exception:
            pass


def refresh_prompt() -> None:
    _call_hook(TTY.refresh_prompt)


def redraw() -> None:
    _call_hook(TTY.redraw)


def _page_lines() -> int:
    return max(1, shutil.get_terminal_size(fallback=(80, 20)).lines - 3)


def set_input_mask(on: bool) -> None:
    """Hide or show what is typed on the input line."""
    TTY.masked = bool(on)


def _display_buffer() -> str:
    """What the input line should SHOW. Never what it should submit."""
    if TTY.masked:
        return "•" * len(TTY.buffer)
    return "".join(TTY.buffer)


def _redraw_prompt_line() -> None:
    """Rewrite the prompt and typed text, if there are any. Caller holds the lock."""
    shown = _display_buffer()
    if TTY.prompt or shown:
        sys.stdout.write(TTY.prompt + shown)


# -- raw mode -------------------------------------------------------------

def _setup_raw_mode() -> bool:
    """Disable canonical mode and echo on stdin.  Returns True on success."""
    if not sys.stdin.isatty():
        return False
    try:
        import termios as _tm

        TTY.fd = sys.stdin.fileno()
        TTY.saved_termios = _tm.tcgetattr(TTY.fd)
        new = _tm.tcgetattr(TTY.fd)
        new[3] &= ~(_tm.ECHO | _tm.ICANON | _tm.ECHOE | _tm.ECHOK | _tm.ECHONL)
        new[6][_tm.VMIN] = 1
        new[6][_tm.VTIME] = 0
        _tm.tcsetattr(TTY.fd, _tm.TCSADRAIN, new)
        TTY.raw = True
        return True
    except Exception:
        return False


def _restore_terminal() -> None:
    """Restore the original terminal settings saved by _setup_raw_mode()."""
    if TTY.raw and TTY.fd >= 0 and TTY.saved_termios is not None:
        try:
            import termios as _tm

            _tm.tcsetattr(TTY.fd, _tm.TCSADRAIN, TTY.saved_termios)
        except Exception:
            pass
        TTY.raw = False


def _read_one_char() -> Optional[str]:
    """Read one character from stdin (handles UTF-8 multi-byte).

    Returns the character, or None on EOF.
    Uses os.read() to bypass Python's buffered I/O.
    """
    b = os.read(TTY.fd, 1)
    if not b:
        return None
    byte = b[0]
    if byte < 0x80:
        return chr(byte)
    if byte < 0xC0:
        return None
    remaining = 1 if byte < 0xE0 else 2 if byte < 0xF0 else 3
    data = b
    for _ in range(remaining):
        b2 = os.read(TTY.fd, 1)
        if not b2:
            break
        data += b2
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


# -- keys -----------------------------------------------------------------

def _scroll(direction: str) -> None:
    """PgUp / PgDn: the full-screen UI's own scrolling, or line-mode scrollback."""
    page = _page_lines()
    if TTY.scroll_callback is not None:
        TTY.scroll_callback(direction, page)
        return
    if direction == "pgup":
        TTY.paused = True
        TTY.scroll_pos = min(TTY.scroll_pos + page, len(TTY.history))
        _show_scrollback(TTY.scroll_pos, page)
    else:
        TTY.scroll_pos = max(0, TTY.scroll_pos - page)
        if TTY.scroll_pos == 0:
            _scroll_unlock()
        else:
            _show_scrollback(TTY.scroll_pos, page)


def _consume_escape_seq() -> None:
    """Read ANSI escape sequence; handle arrow/home/end keys."""
    try:
        r, _, _ = select.select([TTY.fd], [], [], 0.05)
        if not r:
            return
        b2 = os.read(TTY.fd, 1)
        if not b2 or b2 not in (b"[", b"O"):
            return
        seq = b""
        while True:
            r2, _, _ = select.select([TTY.fd], [], [], 0.05)
            if not r2:
                break
            b3 = os.read(TTY.fd, 1)
            if not b3:
                break
            seq += b3
            if 0x40 <= b3[0] <= 0x7E:
                break
        if seq in (b"5~", b"6~"):          # PgUp, PgDn
            _scroll("pgup" if seq == b"5~" else "pgdn")
            return
        with TTY.lock:
            n = len(TTY.buffer)
            if seq == b"D":                  # left
                if TTY.pos > 0:
                    TTY.pos -= 1
                    sys.stdout.write("\x1b[D")
            elif seq == b"C":                # right
                if TTY.pos < n:
                    TTY.pos += 1
                    sys.stdout.write("\x1b[C")
            elif seq in (b"H", b"1~"):       # home
                if TTY.pos > 0:
                    sys.stdout.write(f"\x1b[{TTY.pos}D")
                    TTY.pos = 0
            elif seq in (b"F", b"4~"):       # end
                if TTY.pos < n:
                    sys.stdout.write(f"\x1b[{n - TTY.pos}C")
                    TTY.pos = n
            sys.stdout.flush()
    except Exception:
        pass


def _submit_line() -> str:
    """Enter: take the typed line and clear it, and its echo, from the screen."""
    with TTY.lock:
        line = "".join(TTY.buffer)
        TTY.buffer.clear()
        TTY.pos = 0
        visible_prompt = re.sub(r"\x1b\[[0-9;]*m", "", TTY.prompt)
        width = TERMINAL_WIDTH if TERMINAL_WIDTH > 0 else 80
        rows = max(1, (len(visible_prompt) + len(line) + width - 1) // width)
        if rows > 1:
            sys.stdout.write(f"\033[{rows - 1}A")
        sys.stdout.write("\r")
        for _ in range(rows):
            sys.stdout.write("\033[2K\n")
        sys.stdout.write(f"\033[{rows}A\r")
        sys.stdout.flush()
    return line


def _insert_char(ch: str) -> None:
    with TTY.lock:
        TTY.buffer.insert(TTY.pos, ch)
        TTY.pos += 1
        shown = "•" if TTY.masked else ch
        if TTY.pos == len(TTY.buffer):
            sys.stdout.write(shown)
        else:
            after_raw = "".join(TTY.buffer[TTY.pos:])
            after = ("•" * len(after_raw)) if TTY.masked else after_raw
            sys.stdout.write(f"{shown}{after}\x1b[{len(after)}D")
        sys.stdout.flush()
    if TTY.on_keypress is not None:
        try:
            TTY.on_keypress()
        except Exception:
            pass


def _handle_input_char(ch: str):
    """Process one keystroke.

    Returns the finished line on Enter, _EOF_SENTINEL on Ctrl-D at an empty
    line, and None for every other key.
    """
    if ch in ("\r", "\n"):
        return _submit_line()

    if ch == "\x04":                         # Ctrl-D
        with TTY.lock:
            return _EOF_SENTINEL if not TTY.buffer else None

    if ch == "\x15":                         # Ctrl-U: clear the line
        with TTY.lock:
            TTY.buffer.clear()
            TTY.pos = 0
            sys.stdout.write("\r\033[2K" + TTY.prompt)
            sys.stdout.flush()
        return None

    if ch == "\x17":                         # Ctrl-W: delete a word
        with TTY.lock:
            while TTY.buffer and TTY.buffer[-1] == " ":
                TTY.buffer.pop()
            while TTY.buffer and TTY.buffer[-1] != " ":
                TTY.buffer.pop()
            TTY.pos = len(TTY.buffer)
            sys.stdout.write("\r\033[2K" + TTY.prompt + _display_buffer())
            sys.stdout.flush()
        return None

    if ch in ("\x7f", "\x08"):               # Backspace
        with TTY.lock:
            if TTY.buffer and TTY.pos > 0:
                del TTY.buffer[TTY.pos - 1]
                TTY.pos -= 1
                after_raw = "".join(TTY.buffer[TTY.pos:])
                after = ("•" * len(after_raw)) if TTY.masked else after_raw
                sys.stdout.write(f"\x1b[D{after} \x1b[{len(after) + 1}D")
                sys.stdout.flush()
        return None

    # Ctrl-B / Ctrl-F scroll a full-screen UI, like `less` (they work on the
    # Termux keyboard, which has no PgUp key).
    if ch in ("\x02", "\x06") and TTY.scroll_callback is not None:
        TTY.scroll_callback("pgup" if ch == "\x02" else "pgdn", _page_lines())
        return None

    if ch in ("\x13", "\x10"):               # Ctrl-S / Ctrl-P: pause, resume
        if TTY.paused:
            TTY.scroll_pos = 0
            _scroll_unlock()
        else:
            TTY.paused = True
            with TTY.lock:
                sys.stdout.write("\r\033[2K")
                sys.stdout.write(
                    "\x1b[33m[PAUSED - PgUp/PgDn to scroll, Ctrl+P or Ctrl+S to resume]\x1b[0m\n"
                )
                sys.stdout.flush()
        return None

    if ch == "\x1b":
        _consume_escape_seq()
        return None

    if ch >= " ":
        _insert_char(ch)
    return None


def _set_prompt(prompt: str) -> None:
    """Write a prompt string, preserving the user's typed text."""
    with TTY.lock:
        shown = _display_buffer()
        if TTY.prompt or shown:
            sys.stdout.write("\x1b[1G\x1b[2K")
        TTY.prompt = prompt
        sys.stdout.write(prompt + shown)
        sys.stdout.flush()


# -- text that contains colour codes -------------------------------------

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _visible_len(text: str) -> int:
    """Return the visible character count, ignoring ANSI colour codes."""
    return len(_ANSI_RE.sub("", text))


def _truncate_visible(text: str, width: int) -> str:
    """Truncate to *width* visible columns, keeping ANSI codes intact.

    Truncating by len() would count the escape bytes as visible characters,
    so a coloured line gets cut far too early -- and, worse, loses its reset
    sequence, bleeding the colour into everything printed afterwards.  The
    reset is re-appended here for that reason.
    """
    if width <= 0 or _visible_len(text) <= width:
        return text
    out = []
    seen = 0
    i = 0
    while i < len(text) and seen < width:
        m = _ANSI_RE.match(text, i)
        if m:
            out.append(m.group(0))
            i = m.end()
            continue
        out.append(text[i])
        seen += 1
        i += 1
    return "".join(out) + UIConstants.COLORS["reset"]


def _word_wrap(text: str, width: int) -> str:
    """Word-wrap text at *width* visible columns, preserving ANSI codes.

    The first line uses the full width.  Continuation lines are indented
    to align with the message body (detected by finding the first '] '
    in the visible text - the end of the timestamp+tag prefix).

    If the text fits in one line, it is returned unchanged.
    """
    if width < 20 or _visible_len(text) <= width:
        return text

    vis = _ANSI_RE.sub("", text)
    bracket_end = vis.find("] ")
    indent = bracket_end + 2 if bracket_end != -1 and bracket_end < width // 2 else 4
    indent_str = " " * indent

    parts = _ANSI_RE.split(text)
    codes = _ANSI_RE.findall(text)
    tokens = []
    for i, part in enumerate(parts):
        if part:
            tokens.append((part, False))
        if i < len(codes):
            tokens.append((codes[i], True))

    lines = []
    current_line = ""
    current_vis = 0
    for token_str, is_ansi in tokens:
        if is_ansi:
            current_line += token_str
            continue
        for wi, word in enumerate(token_str.split(" ")):
            if wi > 0:
                space_fits = current_vis + 1 + len(word) <= width
                if current_vis > 0 and not space_fits and len(word) > 0:
                    lines.append(current_line)
                    current_line = indent_str + word
                    current_vis = indent + len(word)
                else:
                    current_line += " " + word
                    current_vis += 1 + len(word)
            elif current_vis + len(word) > width and current_vis > 0:
                lines.append(current_line)
                current_line = indent_str + word
                current_vis = indent + len(word)
            else:
                current_line += word
                current_vis += len(word)
    if current_line:
        lines.append(current_line)
    return "\n".join(lines)


# -- printing above the input line ---------------------------------------

def _emit_line(text: str) -> None:
    """Print a message line from any thread, preserving user input.

    Word-wraps at TERMINAL_WIDTH so words are never split mid-word.
    Clears the current terminal line (prompt + typed text), writes the
    message, then restores the prompt and the user's in-progress buffer
    so their typing is never lost or corrupted.

    When the screen is paused, messages are held instead of printed.
    """
    wrapped = _word_wrap(text, TERMINAL_WIDTH)

    if TTY.paused:
        TTY.held.append(wrapped)
        with TTY.lock:
            sys.stdout.write("\r\033[2K")
            sys.stdout.write(
                f"\033[33m[PAUSED - {len(TTY.held)} buffered]\033[0m "
                + TTY.prompt
                + _display_buffer()
            )
            sys.stdout.flush()
        return

    try:
        with TTY.lock:
            sys.stdout.write("\r\x1b[2K")
            sys.stdout.write(wrapped + "\n")
            TTY.remember(wrapped)
            _redraw_prompt_line()
            sys.stdout.flush()
    except (RuntimeError, ValueError, OSError):
        pass


def _show_scrollback(pos: int, page: int) -> None:
    with TTY.lock:
        try:
            rows = shutil.get_terminal_size(fallback=(80, 24)).lines
            body_h = max(1, rows - 3)
            total = len(TTY.history)
            end = min(total, max(0, total - pos + page))
            start = max(0, end - body_h)
            sys.stdout.write("\033[2J\033[H")
            for ln in TTY.history[start:end]:
                sys.stdout.write(ln + "\n")
            pct = int(100 * end / max(1, total))
            sys.stdout.write(
                colorize(f"── SCROLL [{pct}%] PgUp=back PgDn=fwd Ctrl+P/S=live ──", "yellow")
                + "\n"
            )
            sys.stdout.write(TTY.prompt + _display_buffer())
            sys.stdout.flush()
        except Exception:
            pass


def _scroll_unlock() -> None:
    """Print everything held while paused and resume live display."""
    TTY.paused = False
    with TTY.lock:
        sys.stdout.write("\r\033[2K")
        while TTY.held:
            sys.stdout.write(TTY.held.popleft() + "\n")
        _redraw_prompt_line()
        sys.stdout.flush()


def _flush_display_queue() -> None:
    """Flush any queued messages to stdout (cooked-mode fallback only)."""
    if not TTY.queue:
        return
    with TTY.lock:
        sys.stdout.write("\r\033[2K")
        while TTY.queue:
            sys.stdout.write(TTY.queue.popleft() + "\n")
        _redraw_prompt_line()
        sys.stdout.flush()


def safe_print(*args, **kwargs):
    """Thread-safe print with flush, preserving user input in raw mode."""
    kwargs["flush"] = True
    try:
        with TTY.lock:
            shown = _display_buffer()
            redraw = (TTY.prompt or shown) and TTY.raw
            if redraw:
                sys.stdout.write("\x1b[1G\x1b[2K")
            print(*args, **kwargs)
            if redraw:
                sys.stdout.write(TTY.prompt + shown)
                sys.stdout.flush()
    except (RuntimeError, ValueError, OSError):
        pass


def colorize_username(username: str) -> str:
    """Colorize username - FNV-1a hash for colour, italic for server/bot nicks.

    Rules matching the screenshot aesthetic:
      - IRC server names (contain a '.') → dim italic dark_cyan
      - Service bots (ChanServ, NickServ, etc.) → dim italic dark_magenta
      - Normal users → one of 12 bright colours based on FNV-1a hash
    """
    if not username:
        return ""

    username = _sanitise(username, 64)
    if not username:
        return ""
    R = UIConstants.COLORS["reset"]
    DI = UIConstants.COLORS["dim_italic"]
    if "." in username and not username.startswith("#"):
        return f"{DI }{UIConstants .COLORS ['dark_cyan']}{username }{R }"
    _services = (
        "chanserv",
        "nickserv",
        "memoserv",
        "operserv",
        "botserv",
        "hostserv",
        "groupserv",
        "global",
        "alis",
    )
    if username.lower() in _services:
        return f"{DI }{UIConstants .COLORS ['dark_magenta']}{username }{R }"
    h = 2166136261
    for c in username:
        h = ((h ^ ord(c)) * 16777619) & 0xFFFFFFFF
    color = UIConstants.USERNAME_COLORS[h % len(UIConstants.USERNAME_COLORS)]
    return colorize(username, color)
