#!/usr/bin/env python3
# otrv4plus_tui.py — weechat-style terminal UI for the OTRv4+ XMPP client.
#
# ─────────────────────────────────────────────────────────────────────────────
# WHAT THIS IS
# ─────────────────────────────────────────────────────────────────────────────
# A self-contained, zero-dependency (stdlib `curses` + `asyncio`) text UI that
# wraps `otrv4plus_xmpp.py` and gives it the same feel as the weechat IRC
# plugin: a pinned status header, one tab (buffer) per peer, per-tab scrollback,
# a persistent input line that output never clobbers, and live message
# insertion from the asyncio loop *and* the SMP crypto thread.
#
# It is deliberately a PRESENTATION + INPUT layer only. It does not touch the
# OTR protocol, the I2P bridge, fragmentation, or the engine. It captures the
# harness's existing `print()` output and routes each line to the right tab by
# its `[prefix]` and the JID it mentions, so NO existing print call has to
# change. Commands it doesn't own are delegated straight back to the harness,
# so your exact command vocabulary is preserved.
#
# ─────────────────────────────────────────────────────────────────────────────
# HOW TO WIRE IT IN  (≈3 lines in otrv4plus_xmpp.py `main()`)
# ─────────────────────────────────────────────────────────────────────────────
# The harness builds the slixmpp client, then runs the asyncio loop and
# `_input_loop(client)`. Replace the input loop with the TUI:
#
#     import otrv4plus_tui
#     # ... after you have `client` and before loop.run_forever():
#     tui = otrv4plus_tui.install_tui(
#         client, loop,
#         own_jid=args.jid,            # so we never open a tab for ourselves
#         initial_peer=args.peer,      # opens/activates that tab on start
#         debug=args.debug,            # routes slixmpp DEBUG logs to a (debug) tab
#     )
#     loop.create_task(tui.run())      # instead of loop.create_task(_input_loop(client))
#
# `install_tui` needs these methods on `client` (they already exist):
#     start_otr(peer)            send_user_text(peer, text)
#     store_smp_secret(peer, s)  smp_start(peer, secret=None)
#     show_status(peer)          has_pending(peer)   feed_pending(peer, line)
#
# Two integration choices for commands, pick one:
#
#   (A) DEFAULT (works out of the box): the built-in command table below maps
#       /otr /smp /smp-secret /status to the methods above. If your current
#       `_input_loop` uses different command strings, tweak COMMANDS in
#       install_tui — one line each.
#
#   (B) EXACT PARITY (recommended once stable): extract the body of your current
#       `_input_loop` per-line handler into a method, e.g.
#           def dispatch_line(self, peer, line): ...   # the existing logic
#       then pass `delegate=client.dispatch_line` to install_tui. Anything the
#       TUI doesn't recognise as a UI command (/win /close /clear /names /help
#       /debug /scroll /quit) is handed verbatim to your dispatcher, so every
#       command you already support keeps working with zero divergence.
#
# Account password: still read via getpass at startup, BEFORE the TUI takes the
# screen — unchanged. The in-session prompts (trust y/n, SMP passphrase) flow
# through the normal input line via the harness's pending-input state machine.
#
# Run `python3 otrv4plus_tui.py --selftest` to exercise the routing/buffer model
# without a terminal.
# ─────────────────────────────────────────────────────────────────────────────

import asyncio
import re
import sys
from collections import deque

# JID matcher used to auto-discover peers from output lines.
_JID_RE = re.compile(r"[A-Za-z0-9_.+-]+@[A-Za-z0-9_.-]+")

STATUS_TAB = "(status)"
DEBUG_TAB = "(debug)"

# ── line kinds → colour role ────────────────────────────────────────────────
# Mapping from the leading "[prefix]" the harness prints to a semantic kind.
PREFIX_KIND = {
    "[otr-recv]": "recv",
    "[otr-send]": "send",
    "[otr-crypto]": "crypto",
    "[otr-trace]": "trace",
    "[otr]": "msg_in",        # a DECRYPTED incoming message — the important one
    "[plain]": "plain",       # an UNENCRYPTED incoming message — flag loudly
    "[otr error]": "error",
    "[secure]": "secure",
    "[smp]": "smp",
    "[trust]": "trust",
    "[queued]": "info",
    "[keepalive]": "keepalive",
    "[subscribe]": "sys",
    "[connected]": "sys",
    "[ready]": "sys",
    "[i2p]": "sys",
    "[tls]": "sys",
    "[ClientProfile]": "sys",
}

# Security badge shown in the header per tab.
SEC_PLAINTEXT = "plaintext"
SEC_ENCRYPTED = "encrypted"
SEC_VERIFIED = "verified"

_SEC_GLYPH = {
    SEC_PLAINTEXT: "PLAINTEXT",
    SEC_ENCRYPTED: "ENCRYPTED",
    SEC_VERIFIED: "VERIFIED",
}


def _localpart(jid):
    return jid.split("@", 1)[0] if "@" in jid else jid


def _wrap(text, width):
    """Wrap one logical line into >=1 display rows of at most `width` cols.

    Width-safe (never returns rows wider than `width`); preserves blank lines.
    A simple greedy wrap on spaces, falling back to hard splits for long tokens.
    """
    if width <= 0:
        return [text]
    rows = []
    for logical in text.split("\n"):
        if logical == "":
            rows.append("")
            continue
        while len(logical) > width:
            cut = logical.rfind(" ", 0, width)
            if cut <= 0:
                cut = width  # no space to break on; hard split
            rows.append(logical[:cut])
            logical = logical[cut:].lstrip(" ") if cut != width else logical[cut:]
        rows.append(logical)
    return rows


class Buffer:
    """One tab: a scrollback of (text, kind) plus security/identity metadata."""

    def __init__(self, name, title=None):
        self.name = name
        self.title = title or name
        self.lines = deque(maxlen=5000)   # (text, kind)
        self.scroll = 0                   # rows scrolled up from the bottom
        self.unread = 0
        self.activity = False             # any non-trivial line since last view
        self.security = SEC_PLAINTEXT
        self.local_fp = ""
        self.remote_fp = ""

    def add(self, text, kind):
        self.lines.append((text, kind))
        if self.scroll > 0:
            # keep the viewport anchored while scrolled up
            self.scroll += 1


class TuiModel:
    """All UI state + the stdout-routing logic. No curses here, so it is unit
    testable: feed it raw output lines and inspect where they land."""

    def __init__(self, own_jid="", debug=False):
        self.own_jid = own_jid or ""
        self.debug = debug
        self.order = [STATUS_TAB]
        self.buffers = {STATUS_TAB: Buffer(STATUS_TAB)}
        self.active = STATUS_TAB
        self.tick = 0                 # last keepalive tick seen
        self.connected = False
        self.history = deque(maxlen=500)
        self.notice = ""              # transient one-line status (errors, hints)
        self._last_peer = None        # peer continuation lines inherit

    # ---- tab management ----------------------------------------------------
    def ensure(self, name, title=None, activate=False):
        if name not in self.buffers:
            self.buffers[name] = Buffer(name, title)
            self.order.append(name)
        if activate:
            self.switch(name)
        return self.buffers[name]

    def close(self, name):
        if name in (STATUS_TAB,):
            self.notice = "cannot close the status tab"
            return
        if name not in self.buffers:
            return
        idx = self.order.index(name)
        del self.buffers[name]
        self.order.remove(name)
        if self.active == name:
            self.switch(self.order[max(0, idx - 1)])

    def switch(self, name_or_idx):
        if isinstance(name_or_idx, int):
            if 0 <= name_or_idx < len(self.order):
                name = self.order[name_or_idx]
            else:
                self.notice = "no such tab #%d" % (name_or_idx + 1)
                return
        else:
            name = name_or_idx
        if name in self.buffers:
            self.active = name
            b = self.buffers[name]
            b.unread = 0
            b.activity = False
            b.scroll = 0

    def cycle(self, delta):
        i = self.order.index(self.active)
        self.switch(self.order[(i + delta) % len(self.order)])

    def buf(self):
        return self.buffers[self.active]

    # ---- output ingestion --------------------------------------------------
    def line(self, name, text, kind="info"):
        b = self.ensure(name)
        b.add(text, kind)
        if name != self.active and kind not in ("keepalive",):
            b.unread += 1
            b.activity = True

    def _route_peer(self, raw):
        """Pick the destination tab for a raw output line.

        The first non-self JID in the line wins (auto-opening its tab and
        becoming the 'current peer'). Lines that carry no JID — the indented
        fingerprint lines under a [secure] block, the 'SMP VERIFIED' banner —
        are continuations of the current peer's activity, so they inherit the
        last peer routed to. Only with no peer seen yet do we fall to status."""
        for m in _JID_RE.finditer(raw):
            jid = m.group(0)
            if jid == self.own_jid:
                continue
            self.ensure(jid, title=_localpart(jid))
            self._last_peer = jid
            return jid
        return self._last_peer or STATUS_TAB

    @staticmethod
    def _kind_for(raw):
        for pfx, kind in PREFIX_KIND.items():
            if raw.startswith(pfx):
                return kind, pfx
        return None, None

    def _update_badge(self, name, raw):
        """Best-effort security-state tracking from human-readable lines.
        Markers are chosen to match the harness's canonical prints and to
        avoid false positives (e.g. 'TRUSTED' is a substring of 'UNTRUSTED',
        so we key on the success line 'Fingerprint TRUSTED' instead)."""
        b = self.buffers.get(name)
        if b is None:
            return
        if "is ENCRYPTED" in raw or "SECURITY: PLAINTEXT" in raw:
            if b.security == SEC_PLAINTEXT:
                b.security = SEC_ENCRYPTED
        if ("SMP VERIFIED" in raw or "Fingerprint TRUSTED" in raw
                or "identity pinned" in raw):
            b.security = SEC_VERIFIED
        if "SMP" in raw and "FAILED" in raw:
            b.security = SEC_ENCRYPTED  # verified failed → back to merely encrypted
        m = re.search(r"Your fingerprint\s*:\s*([0-9A-Fa-f ]{8,})", raw)
        if m:
            b.local_fp = m.group(1).strip()
        m = re.search(r"Their fingerprint\s*:\s*([0-9A-Fa-f ]{8,})", raw)
        if m:
            b.remote_fp = m.group(1).strip()

    def ingest(self, raw):
        """Entry point for one full line of harness output (no trailing \\n)."""
        raw = raw.rstrip("\n")
        if raw == "":
            return
        kind, pfx = self._kind_for(raw)

        # Keepalive: don't spam any tab; surface the tick in the header instead.
        if kind == "keepalive":
            m = re.search(r"tick\s+(\d+)", raw)
            if m:
                self.tick = int(m.group(1))
            self.connected = True
            if self.debug:
                self.line(DEBUG_TAB, raw, "keepalive")
            return

        # slixmpp DEBUG/INFO logging arrives here too (it has no [prefix]).
        if kind is None and (raw.startswith("DEBUG") or raw.startswith("INFO")
                             or raw.startswith("WARNING")):
            if self.debug:
                self.line(DEBUG_TAB, raw, "trace")
            return

        # System chatter with no peer → status tab.
        if kind == "sys":
            if "[connected]" in raw:
                self.connected = True
            self.line(STATUS_TAB, raw, "sys")
            return

        # Everything else — prefixed protocol/message lines AND prefix-less
        # continuation lines (indented fingerprints, the SMP banner) — gets
        # routed (continuations inherit the current peer) and badge-scanned.
        name = self._route_peer(raw)
        self._update_badge(name, raw)

        # Reformat the two chat kinds into clean conversation lines.
        if kind == "msg_in":
            # "[otr] <jid> text"  ->  "jid │ text"
            m = re.match(r"\[otr\]\s*<([^>]+)>\s?(.*)", raw, re.S)
            if m:
                who, body = _localpart(m.group(1)), m.group(2)
                self.line(name, "%s │ %s" % (who, body), "msg_in")
                return
        if kind == "plain":
            m = re.match(r"\[plain\]\s*<([^>]+)>\s?(.*)", raw, re.S)
            if m:
                who, body = _localpart(m.group(1)), m.group(2)
                self.line(name, "%s (PLAINTEXT!) │ %s" % (who, body), "plain")
                return

        self.line(name, raw, kind or "info")

    def echo_local(self, peer, text):
        """Local echo of the user's own outgoing plaintext (the harness does
        not print it, so we do — like weechat shows your own line)."""
        self.line(peer, "you │ %s" % text, "msg_out")

    # ---- scrolling ---------------------------------------------------------
    def scroll_by(self, rows, page):
        b = self.buf()
        step = page if abs(rows) == 1 else rows
        b.scroll = max(0, b.scroll + (step if rows > 0 else -step))

    # ---- headless layout (shared by curses + selftest) ---------------------
    def layout(self, width, height):
        """Return a structured screen description:
            {header:[(text,kind)...], body:[(text,kind)...],
             tabbar:str, input_prefix:str}
        `body` is already wrapped to `width` and clipped to the body height."""
        width = max(1, width)
        height = max(4, height)
        b = self.buf()

        # Header (1-2 lines): active tab, security, fingerprints, conn/tick.
        sec = _SEC_GLYPH.get(b.security, b.security)
        conn = "online" if self.connected else "connecting"
        h1 = "OTRv4+  %s  [%s]  net:%s  tick:%d" % (
            b.title, sec, conn, self.tick)
        header = [(h1[:width], "header")]
        if b.remote_fp or b.local_fp:
            fp = "you %s  peer %s" % (
                (b.local_fp[:23] or "-"), (b.remote_fp[:23] or "-"))
            header.append((fp[:width], "header_dim"))

        # Tab bar (1 line): "1:status 2:bob* 3:alice"
        parts = []
        for i, name in enumerate(self.order, 1):
            bb = self.buffers[name]
            tag = bb.title if name != STATUS_TAB else "status"
            mark = "*" if (bb.unread and name != self.active) else ""
            label = "%d:%s%s" % (i, tag, mark)
            if name == self.active:
                label = "[" + label + "]"
            parts.append(label)
        tabbar = " ".join(parts)
        if len(tabbar) > width:
            tabbar = tabbar[:width - 1] + "…"

        # Body height = total - header - tabbar - inputline - (notice line)
        notice = self.notice
        reserved = len(header) + 1 + 1 + (1 if notice else 0)
        body_h = max(1, height - reserved)

        # Wrap all lines, then take the last body_h rows offset by scroll.
        wrapped = []
        for text, kind in b.lines:
            for r in _wrap(text, width):
                wrapped.append((r, kind))
        total = len(wrapped)
        # clamp scroll
        max_scroll = max(0, total - body_h)
        if b.scroll > max_scroll:
            b.scroll = max_scroll
        end = total - b.scroll
        start = max(0, end - body_h)
        body = wrapped[start:end]
        # pad to fill the region (top-padding so text sticks to the bottom)
        pad = body_h - len(body)
        if pad > 0:
            body = [("", "info")] * pad + body

        out = {"header": header, "tabbar": tabbar[:width], "body": body}
        if notice:
            out["notice"] = (notice[:width], "error")
        return out


# ─────────────────────────────────────────────────────────────────────────────
# stdout capture: a file-like object that turns the harness's print() output
# into model.ingest() calls, MARSHALLED ONTO THE LOOP THREAD (prints can come
# from the SMP executor thread).
# ─────────────────────────────────────────────────────────────────────────────
class TuiStream:
    def __init__(self, model, loop, on_change):
        self._model = model
        self._loop = loop
        self._on_change = on_change
        self._buf = ""

    def write(self, s):
        if not s:
            return 0
        self._buf += s
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            self._dispatch(line)
        return len(s)

    def _dispatch(self, line):
        def apply():
            try:
                self._model.ingest(line)
            finally:
                self._on_change()
        # Always hop to the loop thread; safe from any thread.
        try:
            self._loop.call_soon_threadsafe(apply)
        except RuntimeError:
            # loop closed during shutdown — fall back to stderr
            sys.__stderr__.write(line + "\n")

    def flush(self):
        if self._buf:
            self._dispatch(self._buf)
            self._buf = ""

    # logging handlers probe these
    def isatty(self):
        return False


def _make_log_handler(model, loop, on_change):
    """Return a real logging.Handler subclass instance that funnels slixmpp
    log records into the model's debug tab (marshalled onto the loop thread).
    Built lazily so `import logging` only happens if --debug is on."""
    import logging

    class _LogToTab(logging.Handler):
        def __init__(self):
            super().__init__(logging.DEBUG)
            self.setFormatter(logging.Formatter("%(levelname)s %(message)s"))

        def emit(self, record):
            try:
                msg = self.format(record)
            except Exception:
                return

            def apply():
                model.line(DEBUG_TAB, msg, "trace")
                on_change()
            try:
                loop.call_soon_threadsafe(apply)
            except RuntimeError:
                pass

    return _LogToTab()


# ─────────────────────────────────────────────────────────────────────────────
# The curses front-end.
# ─────────────────────────────────────────────────────────────────────────────
class Tui:
    def __init__(self, model, loop, submit, debug=False):
        self.model = model
        self.loop = loop
        self.submit = submit            # callable(active_tab, text)
        self.debug = debug
        self.commands = {}              # name -> callable(args:str)
        self.stdscr = None
        self._old_stdout = None
        self.input = ""
        self.cursor = 0
        self._hist_idx = None
        self._stash = ""
        self._pending_esc = False
        self._stopped = asyncio.Event()
        self._color = {}

    # ---- command registry --------------------------------------------------
    def command(self, name, fn):
        self.commands[name] = fn

    def _register_ui_commands(self):
        m = self.model

        def c_help(_a):
            for ln in (
                "commands: /win N  /next /prev  /close  /clear  /names",
                "          /scroll up|down  /debug  /quit",
                "keys: Ctrl-N/Ctrl-P or Alt-1..9 switch · PgUp/PgDn scroll · Ctrl-L redraw",
                "plus your OTR commands (/otr /smp /smp-secret /status ...)",
            ):
                m.line(m.active, ln, "info")

        def c_win(a):
            a = a.strip()
            if a.isdigit():
                m.switch(int(a) - 1)
            elif a in m.buffers:
                m.switch(a)
            else:
                m.notice = "usage: /win <number|jid>"

        def c_close(_a):
            m.close(m.active)

        def c_clear(_a):
            m.buf().lines.clear()
            m.buf().scroll = 0

        def c_names(_a):
            names = ", ".join(
                "%d:%s" % (i, (b if b != STATUS_TAB else "status"))
                for i, b in enumerate(m.order, 1))
            m.line(m.active, "tabs: " + names, "info")

        def c_scroll(a):
            a = a.strip().lower()
            if a.startswith("up"):
                m.scroll_by(-1, page=10)
            elif a.startswith("down"):
                m.scroll_by(1, page=10)
            else:
                m.notice = "usage: /scroll up|down"

        def c_debug(_a):
            m.ensure(DEBUG_TAB, title="debug", activate=True)

        self.command("help", c_help)
        self.command("win", c_win)
        self.command("w", c_win)
        self.command("next", lambda _a: m.cycle(1))
        self.command("prev", lambda _a: m.cycle(-1))
        self.command("close", c_close)
        self.command("clear", c_clear)
        self.command("names", c_names)
        self.command("buffers", c_names)
        self.command("scroll", c_scroll)
        self.command("debug", c_debug)
        # /quit is handled specially in _on_enter so it can stop the loop.

    # ---- lifecycle ---------------------------------------------------------
    def attach(self):
        import curses
        self.stdscr = curses.initscr()
        curses.noecho()
        curses.cbreak()
        self.stdscr.keypad(True)
        try:
            curses.start_color()
            curses.use_default_colors()
            self._init_colors(curses)
        except Exception:
            pass
        try:
            curses.curs_set(1)
        except Exception:
            pass
        self.stdscr.nodelay(True)
        self.loop.add_reader(sys.stdin.fileno(), self._on_readable)
        self.redraw()

    def detach(self):
        import curses
        try:
            self.loop.remove_reader(sys.stdin.fileno())
        except Exception:
            pass
        try:
            curses.nocbreak()
            self.stdscr.keypad(False)
            curses.echo()
            curses.endwin()
        except Exception:
            pass

    def _init_colors(self, curses):
        # pair id -> (fg, attr)
        defs = {
            "recv": (curses.COLOR_CYAN, 0),
            "send": (curses.COLOR_CYAN, 0),
            "crypto": (curses.COLOR_BLUE, 0),
            "trace": (-1, curses.A_DIM),
            "msg_in": (curses.COLOR_WHITE, curses.A_BOLD),
            "msg_out": (curses.COLOR_WHITE, 0),
            "plain": (curses.COLOR_YELLOW, curses.A_BOLD),
            "error": (curses.COLOR_RED, curses.A_BOLD),
            "secure": (curses.COLOR_GREEN, curses.A_BOLD),
            "smp": (curses.COLOR_MAGENTA, 0),
            "trust": (curses.COLOR_YELLOW, 0),
            "sys": (-1, curses.A_DIM),
            "info": (-1, 0),
            "keepalive": (-1, curses.A_DIM),
            "header": (curses.COLOR_BLACK, curses.A_REVERSE),
            "header_dim": (-1, curses.A_DIM),
        }
        i = 1
        for kind, (fg, attr) in defs.items():
            try:
                curses.init_pair(i, fg, -1)
                self._color[kind] = curses.color_pair(i) | attr
            except Exception:
                self._color[kind] = attr
            i += 1

    def _attr(self, kind):
        return self._color.get(kind, 0)

    # ---- rendering ---------------------------------------------------------
    def redraw(self):
        import curses
        if self.stdscr is None:
            return
        try:
            h, w = self.stdscr.getmaxyx()
            self.stdscr.erase()
            lay = self.model.layout(w, h)
            row = 0
            for text, kind in lay["header"]:
                self._put(row, 0, text.ljust(w)[:w], self._attr(kind)); row += 1
            self._put(row, 0, lay["tabbar"].ljust(w)[:w],
                      self._attr("header_dim")); row += 1
            for text, kind in lay["body"]:
                self._put(row, 0, text[:w], self._attr(kind)); row += 1
            if "notice" in lay:
                t, k = lay["notice"]
                self._put(row, 0, t.ljust(w)[:w], self._attr(k)); row += 1
                self.model.notice = ""  # one-shot
            # input line
            prompt = "[%s] " % _localpart(self.model.active) if \
                self.model.active != STATUS_TAB else "> "
            visible = prompt + self.input
            self._put(h - 1, 0, visible[:w], 0)
            cx = min(w - 1, len(prompt) + self.cursor)
            try:
                self.stdscr.move(h - 1, max(0, cx))
            except Exception:
                pass
            self.stdscr.noutrefresh()
            curses.doupdate()
        except Exception:
            # never let a draw error kill the session
            pass

    def _put(self, y, x, s, attr):
        try:
            self.stdscr.addstr(y, x, s, attr)
        except Exception:
            pass  # bottom-right cell / overflow

    # ---- input -------------------------------------------------------------
    def _on_readable(self):
        import curses
        while True:
            try:
                ch = self.stdscr.get_wch()
            except curses.error:
                break          # no more input queued
            except Exception:
                break
            self._handle(ch)
        self.redraw()

    def _handle(self, ch):
        import curses
        # ESC-prefixed (Alt+key): we saw ESC last; this is the second byte.
        if self._pending_esc:
            self._pending_esc = False
            if isinstance(ch, str) and ch.isdigit():
                self.model.switch(int(ch) - 1)
                return
            # fallthrough: treat as normal key

        if ch == "\x1b":               # ESC
            self._pending_esc = True
            return

        if isinstance(ch, int):
            if ch == curses.KEY_RESIZE:
                return
            if ch in (curses.KEY_BACKSPACE,):
                self._backspace(); return
            if ch == curses.KEY_DC:
                self._delete(); return
            if ch == curses.KEY_LEFT:
                self.cursor = max(0, self.cursor - 1); return
            if ch == curses.KEY_RIGHT:
                self.cursor = min(len(self.input), self.cursor + 1); return
            if ch == curses.KEY_HOME:
                self.cursor = 0; return
            if ch == curses.KEY_END:
                self.cursor = len(self.input); return
            if ch == curses.KEY_UP:
                self._history(-1); return
            if ch == curses.KEY_DOWN:
                self._history(1); return
            if ch == curses.KEY_PPAGE:
                self.model.scroll_by(-1, page=10); return
            if ch == curses.KEY_NPAGE:
                self.model.scroll_by(1, page=10); return
            return

        # ch is a str (printable or control char)
        if ch in ("\n", "\r"):
            self._on_enter(); return
        if ch in ("\x7f", "\b"):       # backspace variants
            self._backspace(); return
        if ch == "\t":
            self._complete(); return
        o = ord(ch) if len(ch) == 1 else None
        if o is not None and o < 32:
            if o == 16:   # Ctrl-P
                self.model.cycle(-1); return
            if o == 14:   # Ctrl-N
                self.model.cycle(1); return
            if o == 12:   # Ctrl-L
                self.redraw(); return
            if o == 21:   # Ctrl-U  kill to start
                self.input = self.input[self.cursor:]; self.cursor = 0; return
            if o == 1:    # Ctrl-A
                self.cursor = 0; return
            if o == 5:    # Ctrl-E
                self.cursor = len(self.input); return
            if o == 3:    # Ctrl-C  → quit
                self._quit(); return
            return
        # normal printable (incl. unicode)
        self.input = self.input[:self.cursor] + ch + self.input[self.cursor:]
        self.cursor += len(ch)

    def _backspace(self):
        if self.cursor > 0:
            self.input = self.input[:self.cursor - 1] + self.input[self.cursor:]
            self.cursor -= 1

    def _delete(self):
        if self.cursor < len(self.input):
            self.input = self.input[:self.cursor] + self.input[self.cursor + 1:]

    def _history(self, d):
        hist = self.model.history
        if not hist:
            return
        if self._hist_idx is None:
            if d < 0:
                self._stash = self.input
                self._hist_idx = len(hist) - 1
            else:
                return
        else:
            self._hist_idx += d
        if self._hist_idx < 0:
            self._hist_idx = 0
        if self._hist_idx >= len(hist):
            self._hist_idx = None
            self.input = self._stash
        else:
            self.input = hist[self._hist_idx]
        self.cursor = len(self.input)

    def _complete(self):
        # complete /commands and peer jids
        tok = self.input[:self.cursor]
        if tok.startswith("/") and " " not in tok:
            base = tok[1:]
            opts = [c for c in self.commands if c.startswith(base)]
            opts += [c for c in ("otr", "smp", "smp-secret", "status", "quit")
                     if c.startswith(base) and c not in self.commands]
            if len(opts) == 1:
                self.input = "/" + opts[0] + " " + self.input[self.cursor:]
                self.cursor = len(opts[0]) + 2
        else:
            frag = tok.rsplit(" ", 1)[-1]
            if frag:
                cands = [n for n in self.model.order if n.startswith(frag)
                         and n not in (STATUS_TAB, DEBUG_TAB)]
                if len(cands) == 1:
                    self.input = self.input[:self.cursor - len(frag)] + cands[0] + \
                        self.input[self.cursor:]
                    self.cursor = self.cursor - len(frag) + len(cands[0])

    def _on_enter(self):
        text = self.input
        self.input = ""
        self.cursor = 0
        self._hist_idx = None
        if text == "":
            return
        self.model.history.append(text)
        if text.startswith("/"):
            name, _, args = text[1:].partition(" ")
            name = name.lower()
            if name in ("quit", "exit", "q"):
                self._quit(); return
            fn = self.commands.get(name)
            if fn is not None:
                try:
                    fn(args)
                except Exception as e:
                    self.model.notice = "command error: %s" % e
                return
            # not a UI command → hand to the harness submit handler verbatim
        # plain line or unrecognised command → submit handler decides
        try:
            self.submit(self.model.active, text)
        except Exception as e:
            self.model.notice = "input error: %s" % e

    def _quit(self):
        self._stopped.set()

    # ---- run ---------------------------------------------------------------
    async def run(self):
        self._register_ui_commands()
        self.attach()
        try:
            await self._stopped.wait()
        finally:
            self.detach()
            # graceful loop shutdown
            try:
                self.loop.stop()
            except Exception:
                pass


# ─────────────────────────────────────────────────────────────────────────────
# Convenience wiring: build model + stream + curses front-end and connect the
# default OTR command table to the harness. Returns the Tui (call .run()).
# ─────────────────────────────────────────────────────────────────────────────
def install_tui(client, loop, own_jid="", initial_peer=None, debug=False,
                delegate=None):
    model = TuiModel(own_jid=own_jid, debug=debug)
    if initial_peer:
        model.ensure(initial_peer, title=_localpart(initial_peer), activate=True)

    # redraw hook is filled in once the Tui exists
    box = {}

    def on_change():
        t = box.get("tui")
        if t is not None:
            t.redraw()

    stream = TuiStream(model, loop, on_change)
    sys.stdout = stream  # capture every print() the harness makes

    if debug:
        try:
            import logging
            logging.getLogger().addHandler(_make_log_handler(model, loop, on_change))
        except Exception:
            pass

    def submit(active_tab, text):
        # status tab with no peer: only commands make sense there
        peer = active_tab
        if peer in (STATUS_TAB, DEBUG_TAB):
            model.notice = "no peer here — switch to a conversation tab (Ctrl-N)"
            return
        # pending interactive prompt (trust y/n, SMP passphrase) takes priority
        try:
            if hasattr(client, "has_pending") and client.has_pending(peer):
                client.feed_pending(peer, text)
                return
        except Exception:
            pass
        # local echo, then send
        model.echo_local(peer, text)
        client.send_user_text(peer, text)

    tui = Tui(model, loop, submit, debug=debug)
    box["tui"] = tui

    # ---- default OTR command table (choice A). For exact parity (choice B),
    # pass delegate=client.dispatch_line and these become fallbacks. ----------
    def need_peer():
        p = model.active
        if p in (STATUS_TAB, DEBUG_TAB):
            model.notice = "run this in a conversation tab"
            return None
        return p

    if delegate is None:
        def c_otr(_a):
            p = need_peer()
            if p:
                client.start_otr(p)

        def c_smp(a):
            p = need_peer()
            if not p:
                return
            a = a.strip()
            client.smp_start(p, a if a and a != "start" else None)

        def c_smp_secret(a):
            p = need_peer()
            if p:
                client.store_smp_secret(p, a.strip())

        def c_status(_a):
            p = need_peer()
            if p:
                client.show_status(p)

        tui.command("otr", c_otr)
        tui.command("smp", c_smp)
        tui.command("smp-secret", c_smp_secret)
        tui.command("smpsecret", c_smp_secret)
        tui.command("status", c_status)
    else:
        # Everything the TUI doesn't own is delegated to the harness verbatim,
        # preserving your exact command vocabulary.
        orig_submit = submit

        def submit_delegating(active_tab, text):
            if text.startswith("/"):
                peer = active_tab if active_tab not in (STATUS_TAB, DEBUG_TAB) else None
                try:
                    delegate(peer, text)
                except Exception as e:
                    model.notice = "command error: %s" % e
                return
            orig_submit(active_tab, text)

        tui.submit = submit_delegating

    return tui


# ─────────────────────────────────────────────────────────────────────────────
# Headless self-test: exercises routing, badges, wrapping, command parsing.
# ─────────────────────────────────────────────────────────────────────────────
def _selftest():
    own = "alice@ya5a53qbw3rg3s7pvlqd4c2hlawu3pqflnqpt2tgfoz45cnsjyba.b32.i2p"
    peer = "bob@ya5a53qbw3rg3s7pvlqd4c2hlawu3pqflnqpt2tgfoz45cnsjyba.b32.i2p"
    m = TuiModel(own_jid=own, debug=True)
    passed = failed = 0

    def check(name, cond):
        nonlocal passed, failed
        if cond:
            passed += 1
        else:
            failed += 1
            print("  FAIL:", name)

    # 1. keepalive updates the header tick, opens no peer tab
    m.ingest("[keepalive] tick 7 (loop alive)")
    check("keepalive sets tick", m.tick == 7)
    check("keepalive opens no peer tab", peer not in m.buffers)
    check("keepalive marks connected", m.connected is True)

    # 2. system line lands in status, not a peer tab
    m.ingest("[i2p] SAM stream established.")
    check("sys -> status", m.buffers[STATUS_TAB].lines[-1][0].startswith("[i2p]"))

    # 3. an inbound protocol line auto-opens the peer tab and routes there
    m.ingest("[otr-recv] <- DAKE1 from %s" % peer)
    check("peer tab auto-opened", peer in m.buffers)
    check("recv routed to peer", m.buffers[peer].lines[-1][1] == "recv")
    check("own jid never opened", own not in m.buffers)

    # 4. secure line sets ENCRYPTED and captures fingerprints
    m.ingest("[secure] OTR session with %s is ENCRYPTED (X448 + ML-KEM-1024)." % peer)
    m.ingest("  Your fingerprint  : 17536E21 463BD487 3EA1527A B444BE0F 2075FFEE")
    m.ingest("  Their fingerprint : 786D86AA 28C7A8D1 4151DBCE 776B4ED4 21DC66F1")
    check("encrypted badge", m.buffers[peer].security == SEC_ENCRYPTED)
    check("local fp captured", m.buffers[peer].local_fp.startswith("17536E21"))
    check("remote fp captured", m.buffers[peer].remote_fp.startswith("786D86AA"))

    # 5. SMP VERIFIED upgrades the badge
    m.ingest("[otr-trace] 🔐 SMP step 4/4 · 🔵✅ SMP VERIFIED — identity confirmed!")
    check("verified badge", m.buffers[peer].security == SEC_VERIFIED)

    # 6. decrypted message reformat
    m.ingest("[otr] <%s> hello" % peer)
    last = m.buffers[peer].lines[-1]
    check("msg_in kind", last[1] == "msg_in")
    check("msg_in reformatted", last[0] == "bob │ hello")

    # 7. plaintext (unencrypted) inbound is flagged
    m.ingest("[plain] <%s> sketchy" % peer)
    last = m.buffers[peer].lines[-1]
    check("plain flagged", "PLAINTEXT!" in last[0] and last[1] == "plain")

    # 8. local echo
    m.echo_local(peer, "hi back")
    check("local echo", m.buffers[peer].lines[-1] == ("you │ hi back", "msg_out"))

    # 9. unread tracking when not active
    m.switch(STATUS_TAB)
    before = m.buffers[peer].unread
    m.ingest("[otr-send] -> DATA to %s" % peer)
    check("unread increments off-tab", m.buffers[peer].unread == before + 1)
    m.switch(peer)
    check("unread clears on switch", m.buffers[peer].unread == 0)

    # 10. debug routing
    m.ingest("DEBUG    SEND: <message/>")
    check("debug -> debug tab", DEBUG_TAB in m.buffers
          and m.buffers[DEBUG_TAB].lines[-1][0].startswith("DEBUG"))

    # 11. wrapping is width-safe
    rows = _wrap("x" * 50, 10)
    check("hard wrap width", all(len(r) <= 10 for r in rows) and len(rows) == 5)
    rows = _wrap("one two three four five", 9)
    check("word wrap width", all(len(r) <= 9 for r in rows))

    # 12. layout produces a full screen of the right height
    lay = m.layout(40, 12)
    nbody = len(lay["body"])
    total_rows = len(lay["header"]) + 1 + nbody + 1  # +tabbar +input
    check("layout fills height", total_rows <= 12 and nbody >= 1)
    check("body rows within width", all(len(t) <= 40 for t, _ in lay["body"]))

    # 13. tab switching by index and cycle
    m.switch(0)
    check("switch idx 0 -> status", m.active == STATUS_TAB)
    m.cycle(1)
    check("cycle moves", m.active != STATUS_TAB)

    print("\nselftest: %d passed, %d failed" % (passed, failed))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        raise SystemExit(_selftest())
    print("This module is a UI layer for otrv4plus_xmpp.py — see the docstring "
          "at the top for the ~3-line integration. Run with --selftest to "
          "exercise the model headlessly.")
