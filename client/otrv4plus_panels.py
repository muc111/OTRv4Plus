# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The terminal clients' full-screen UI: tabs, panels and the pager.

* `TabBar`   -- the row of conversation tabs across the top.
* `Pager`    -- a long list (an IRC NAMES reply, help) shown a page at a
  time, optionally ending in a numbered choice.
* `Screen`   -- the full-screen layout: tab bar, the active panel's
  messages, a status line, and the input line at the bottom.
* `ChatPanel` and `PanelManager` -- one panel per conversation, its
  history, security marker and unread count, and which one is shown.

Moved out of otrv4+.py, which re-exports every class. Everything here
prints through otrv4plus_tty, so the input line survives a redraw.
"""
import os
import shutil
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Set

import otrv4plus_tty as _tty
from otrv4plus_states import UIConstants, colorize
from otrv4plus_tty import (
    IS_TERMUX, TERMINAL_HEIGHT, TERMINAL_WIDTH, TIMESTAMP_FORMAT, _ANSI_RE,
    _display_buffer, _flush_display_queue, _truncate_visible, _word_wrap,
    safe_print)


class TabBar:
    """Visual tab bar at top of terminal with Termux optimization"""

    def __init__(self, terminal_width: int = TERMINAL_WIDTH):
        self.terminal_width = terminal_width
        self.visible_start = 0
        self.tab_data: Dict[str, dict] = {}

    def calculate_tab_width(self, tab_name: str, has_unread: int, is_active: bool) -> int:
        """Calculate width needed for a tab"""
        width = len(tab_name) + 2

        if "🔵" in tab_name or "🟢" in tab_name or "🟡" in tab_name or "🔴" in tab_name:
            width += 2

        if has_unread > 0:
            width += len(f"({has_unread })") + 1

        width += 1

        return width

    def render(self, panels: Dict[str, "ChatPanel"], active_panel_name: str) -> List[str]:
        """Render tab bar - returns list of lines to print"""
        if not panels:
            return []

        tabs = []
        total_width = 0
        max_tabs_width = self.terminal_width - 10

        for panel_name, panel in panels.items():
            icon = UIConstants.SECURITY_ICONS.get(panel.security_level, "")

            display_name = panel_name
            if icon:
                display_name = f"{display_name }{icon }"

            is_active = panel_name == active_panel_name

            self.tab_data[panel_name] = {
                "display_name": display_name,
                "icon": icon,
                "unread": panel.unread_count,
                "active": is_active,
                "width": self.calculate_tab_width(display_name, panel.unread_count, is_active),
            }

            tabs.append(panel_name)

        total_tabs_width = sum(self.tab_data[tab]["width"] for tab in tabs)
        need_scroll = total_tabs_width > max_tabs_width

        if need_scroll:
            try:
                active_index = tabs.index(active_panel_name)
            except ValueError:
                active_index = 0

            if active_index < self.visible_start:
                self.visible_start = active_index
            elif active_index >= self.visible_start + self._max_visible_tabs(tabs, max_tabs_width):
                self.visible_start = active_index - 2

            self.visible_start = max(0, min(self.visible_start, len(tabs) - 1))

            visible_tabs = []
            current_width = 0
            max_visible = self._max_visible_tabs(tabs, max_tabs_width)

            for i in range(self.visible_start, min(len(tabs), self.visible_start + max_visible)):
                tab_name = tabs[i]
                tab_info = self.tab_data[tab_name]

                if current_width + tab_info["width"] > max_tabs_width - 6:
                    break

                visible_tabs.append(tab_name)
                current_width += tab_info["width"]

            if self.visible_start > 0:
                visible_tabs.insert(0, "<<")
            if self.visible_start + len(visible_tabs) < len(tabs):
                visible_tabs.append(">>")
        else:
            visible_tabs = tabs
            self.visible_start = 0

        tab_strings = []
        for tab_name in visible_tabs:
            if tab_name == "<<":
                tab_strings.append("◀")
                continue
            elif tab_name == ">>":
                tab_strings.append("▶")
                continue

            tab_info = self.tab_data[tab_name]
            display_name = tab_info["display_name"]
            unread = tab_info["unread"]
            is_active = tab_info["active"]

            if unread > 0:
                tab_display = f"{display_name }({unread })"
            else:
                tab_display = display_name

            if is_active:
                tab_str = f"{colorize ('['+tab_display +']','bg_green')}"
            elif unread > 0:

                _hl = "magenta" if not tab_name.startswith("#") else "cyan"
                tab_str = colorize(f"[{tab_display }]", _hl)
            else:
                tab_str = f"[{tab_display }]"

            tab_strings.append(tab_str)

        tab_line = " | ".join(tab_strings)
        if len(tab_line) > self.terminal_width - 2:
            tab_line = tab_line[: self.terminal_width - 4] + "…"
        return [tab_line]

    def _max_visible_tabs(self, tabs: List[str], max_width: int) -> int:
        """Calculate maximum number of visible tabs"""
        avg_width = 12
        return max(1, max_width // avg_width)


class Pager:
    """Non-destructive inline pager - never clears the screen.

    Prints paginated content inline in the terminal scrollback, so chat
    history above is preserved.  On quit, any messages that arrived while
    the pager was active are flushed to screen before the prompt returns.
    """

    def __init__(self, lines_per_page: int = 20):
        self.lines_per_page = lines_per_page if not IS_TERMUX else 15
        self.active = False

    def display(self, lines: List[str], header: str = "", footer: str = "",
                choices: Optional[List[str]] = None):
        """Display lines with inline pager controls.

        `choices` makes the page selectable: pressing 1-9 picks the matching
        entry, closes the pager and returns it.  Returns None otherwise, so
        callers that ignore the result behave exactly as before.
        """
        if not lines:
            safe_print(colorize("  (empty)", "dim"))
            return None
        choices = choices or []
        chosen = None

        self.active = True
        total_pages = (len(lines) + self.lines_per_page - 1) // self.lines_per_page
        page = 0

        try:
            while self.active:
                start = page * self.lines_per_page
                end = min(start + self.lines_per_page, len(lines))

                safe_print(
                    colorize(f"── {header } ", "cyan")
                    + colorize(f"({page +1 }/{total_pages })" if total_pages > 1 else "", "dim")
                    + colorize(" " + "─" * 30, "cyan")
                )

                for line in lines[start:end]:
                    # This printed the literal string "[IRC line suppressed]"
                    # from v10.11.0 until v10.14.0, discarding the line it had
                    # just measured and truncated.  Every pager consumer was
                    # affected -- /names, /list and /help alike -- which is why
                    # the channel user list looked like a suppression policy
                    # rather than a bug.
                    safe_print(_truncate_visible(line, TERMINAL_WIDTH))

                if footer:
                    safe_print(colorize(footer, "dim"))
                safe_print(colorize("─" * 42, "cyan"))

                if total_pages <= 1 and not choices:
                    self.active = False
                    break

                _keys = "  [n]ext  [p]rev  [q]uit" if total_pages > 1 else "  [q]uit"
                if choices:
                    _keys += "   [1-%d] /otr" % len(choices)
                safe_print(colorize(_keys, "dim"), end="  ", flush=True)
                try:
                    if _tty.TTY.raw:

                        b = os.read(_tty.TTY.fd, 1)
                        ch = chr(b[0]).lower() if b else "q"
                        sys.stdout.write("\n")
                        sys.stdout.flush()
                    else:
                        ch = sys.stdin.readline().strip().lower()
                except (EOFError, KeyboardInterrupt):
                    ch = "q"

                if choices and ch.isdigit() and ch != "0" and int(ch) <= len(choices):
                    chosen = choices[int(ch) - 1]
                    self.active = False
                elif ch in ("n", "\r", "\n", " "):
                    page = min(page + 1, total_pages - 1)
                    if page >= total_pages - 1 and ch == "n":
                        self.active = False
                elif ch == "p":
                    page = max(0, page - 1)
                elif ch in ("q",):
                    self.active = False
        finally:
            try:
                import select as _sel

                while True:
                    r2, _, _ = _sel.select([_tty.TTY.fd], [], [], 0.05)
                    if not r2:
                        break
                    os.read(_tty.TTY.fd, 64)
            except Exception:
                pass
            _tty.TTY.buffer.clear()
            _tty.TTY.pos = 0
            _flush_display_queue()
            try:
                _cr = getattr(__import__("builtins"), "_active_client", None)
                if _cr and getattr(_cr, "_tui_enabled", False) and _cr._screen:
                    _cr._screen.redraw_full()
                elif _cr and _cr._prompt_refresh_cb:
                    _cr._prompt_refresh_cb()
            except Exception:
                pass
        return chosen


class Screen:
    """Region-based terminal renderer for the OTRv4+ TUI (Phase 5.5)."""

    def __init__(self, client):
        self.client = client
        self.scroll_offset = 0
        self.cols = TERMINAL_WIDTH if TERMINAL_WIDTH > 0 else 80
        self.rows = TERMINAL_HEIGHT if TERMINAL_HEIGHT > 0 else 24

    def _measure(self) -> None:
        sz = shutil.get_terminal_size(fallback=(80, 24))
        self.cols = max(20, sz.columns)
        self.rows = max(10, sz.lines)
        if IS_TERMUX and self.cols < 40:
            self.cols = 80

    def _sep(self) -> str:
        if self.scroll_offset > 0:
            tag = f" ↑ scrolled — PgDn to resume · PgUp for more "
            pad = max(0, self.cols - len(tag))
            left = colorize("-" * (pad // 2), "dim")
            right = colorize("-" * (pad - pad // 2), "dim")
            return left + colorize(tag, "yellow") + right
        return colorize("-" * self.cols, "dim")

    def _tabbar_lines(self) -> list:
        pm = self.client.panel_manager
        try:
            bar = TabBar(self.cols)
            lines = bar.render(pm.panels, pm.active_panel)
        except Exception as exc:
            lines = [colorize(f"[tabbar: {exc }]", "red")]
        if isinstance(lines, str):
            lines = [lines]
        return lines or [""]

    def _body_visual_lines(self) -> list:
        pm = self.client.panel_manager
        panel = pm.panels.get(pm.active_panel)
        if panel is None:
            return []
        out = []
        for entry in panel.history:
            ts = colorize(
                time.strftime(TIMESTAMP_FORMAT, time.localtime(entry.get("timestamp", time.time()))),
                "dim",
            )
            line = f"{ts } {entry ['message']}"
            wrapped = _word_wrap(line, self.cols)
            out.extend(wrapped.split("\n"))
        return out

    def _input_line(self) -> str:
        buf = _display_buffer()
        return (_tty.TTY.prompt or "") + buf

    def _chrome(self, tabs):
        return 1 + len(tabs) + 1

    def _row_tab(self, tabs, i):
        return self.rows - 1 - (len(tabs) - 1 - i)

    def redraw_full(self) -> None:
        with _tty.TTY.lock:
            self._measure()
            tabs = self._tabbar_lines()
            body_h = max(1, self.rows - self._chrome(tabs))
            vlines = self._body_visual_lines()
            if self.scroll_offset <= 0:
                shown = vlines[-body_h:]
            else:
                end = max(0, len(vlines) - self.scroll_offset)
                start = max(0, end - body_h)
                shown = vlines[start:end]
            if len(shown) < body_h:
                shown = [""] * (body_h - len(shown)) + shown
            k = "\033[K"
            rows = [ln + k for ln in shown]
            rows.append(self._sep() + k)
            rows += [t + k for t in tabs]
            rows.append(self._input_line() + k)
            sys.stdout.write("\033[2J\033[H")
            sys.stdout.write("\r\n".join(rows))
            sys.stdout.flush()

    def redraw_body(self) -> None:
        with _tty.TTY.lock:
            self._measure()
            tabs = self._tabbar_lines()
            body_h = max(1, self.rows - self._chrome(tabs))
            vlines = self._body_visual_lines()
            if self.scroll_offset <= 0:
                shown = vlines[-body_h:]
            else:
                end = max(0, len(vlines) - self.scroll_offset)
                start = max(0, end - body_h)
                shown = vlines[start:end]
            if len(shown) < body_h:
                shown = [""] * (body_h - len(shown)) + shown
            out = ["\0337"]
            for i, ln in enumerate(shown):
                out.append(f"\033[{1 +i };1H\033[K")
                out.append(ln)
            _input_r = self.rows
            _buf = _display_buffer()
            out.append(f"\033[{_input_r };1H\033[2K")
            out.append((_tty.TTY.prompt or "") + _buf)
            out.append("\0338")
            out.append(f"\033[{_input_r };1H")
            _vis = len(_ANSI_RE.sub("", (_tty.TTY.prompt or "") + _buf))
            if _vis > 0:
                out.append(f"\033[{_vis +1 }G")
            sys.stdout.write("".join(out))
            sys.stdout.flush()

    def redraw_tabbar(self) -> None:
        with _tty.TTY.lock:
            self._measure()
            tabs = self._tabbar_lines()
            out = ["\0337"]
            for i, t in enumerate(tabs):
                out.append(f"\033[{self ._row_tab (tabs ,i )};1H\033[K")
                out.append(t)
            out.append("\0338")
            sys.stdout.write("".join(out))
            sys.stdout.flush()

    def scroll_up(self, page: int) -> None:
        """Scroll the active panel up by page visual lines (away from bottom)."""
        self._measure()
        tabs = self._tabbar_lines()
        body_h = max(1, self.rows - self._chrome(tabs))
        vlines = self._body_visual_lines()
        max_offset = max(0, len(vlines) - body_h)
        self.scroll_offset = min(self.scroll_offset + page, max_offset)
        self.redraw_full()

    def scroll_down(self, page: int) -> None:
        """Scroll the active panel down by page visual lines (toward bottom)."""
        self.scroll_offset = max(0, self.scroll_offset - page)
        self.redraw_full()


class ChatPanel:
    """Chat panel for displaying messages.

    The history is what the tab replays when you switch to it, and until
    v10.19.0 it was unbounded and survived everything: a disconnect, a
    reconnect, a nick change.  A tester watched a whole evening's
    conversation reappear under a nick that had not sent any of it, with the
    unread badge climbing system(53) -> system(105) -> system(158) as each
    reconnect appended a fresh copy of the same connection chatter.

    That is a privacy problem before it is a cosmetic one.  This client runs
    over I2P, where the point is that a session is not linkable to the one
    before it; carrying the previous session's messages into the next one
    links them on the screen, in whatever the terminal has kept in its own
    scrollback, and in any core dump taken afterwards.

    So the history now has a ceiling, and it is emptied at every point where
    one connection ends and another begins.  See
    `OTRv4IRCClient._purge_scrollback`.
    """

    #: Hard ceiling on retained messages per panel.  Reached in a busy
    #: channel within an hour or two; the oldest are dropped first.  A cap
    #: is not a substitute for clearing on disconnect, it is the bound on
    #: how much there is to clear.
    MAX_HISTORY = 1000

    def __init__(self, name: str, panel_type: str):
        self.name = name
        self.type = panel_type
        self.history: List[Dict[str, Any]] = []
        self.unread_count = 0
        self.active = False
        self.created = time.time()
        self.recent_users: Set[str] = set()
        self.secure_session = False
        self.last_activity = time.time()
        self.security_level = UIConstants.SecurityLevel.PLAINTEXT
        self.smp_progress = (0, 4)
        #: Monotonic message id.  Was `len(self.history)`, which stops being
        #: unique the moment pruning removes an entry.
        self._next_id = 0

    def add_message(self, message: str, metadata: Optional[dict] = None) -> int:
        """Add message to history, dropping the oldest past MAX_HISTORY.

        The returned id stays monotonic across pruning: it is a message
        identity, not an index into `history`, and `get_messages` slices the
        list rather than looking ids up.  Handing back a reused id after a
        prune would let a caller holding an old id address a different
        message.
        """
        msg_id = self._next_id
        self._next_id += 1
        self.history.append(
            {"id": msg_id, "message": message, "timestamp": time.time(), "metadata": metadata or {}}
        )
        if len(self.history) > self.MAX_HISTORY:
            overflow = len(self.history) - self.MAX_HISTORY
            for entry in self.history[:overflow]:
                entry["message"] = ""
                entry["metadata"] = {}
            del self.history[:overflow]
        self.last_activity = time.time()
        return msg_id

    def get_messages(self, start: int = 0, count: Optional[int] = None) -> List[str]:
        """Get messages from history as strings"""
        if not self.history:
            return []

        messages = [msg["message"] for msg in self.history]

        if count is None:
            return messages[start:]
        else:
            return messages[start : start + count]

    def clear_unread(self):
        """Clear unread count"""
        self.unread_count = 0
        self.recent_users.clear()

    def mark_secure(self, level: UIConstants.SecurityLevel = UIConstants.SecurityLevel.ENCRYPTED):
        """Mark panel as secure"""
        self.secure_session = True
        self.type = "secure"
        self.security_level = level

    def update_smp_progress(self, step: int, total_steps: int):
        """Update SMP progress"""
        self.smp_progress = (step, total_steps)

    def get_progress_display(self) -> str:
        """Get SMP progress display"""
        step, total = self.smp_progress
        if step == 0:
            return ""
        elif step == total:
            return "✅"
        else:
            progress_chars = ["○", "◔", "◑", "◕", "●"]
            progress_index = min(int((step / total) * len(progress_chars)), len(progress_chars) - 1)
            return f"🔄 {progress_chars [progress_index ]} {step }/{total }"

    def clear_history(self) -> int:
        """Drop every retained message and return how many there were.

        Each entry's text is overwritten before the list is emptied.  Be
        precise about what that buys: a Python `str` is immutable and
        possibly interned, so this does not scrub the characters out of the
        process -- it drops the last reference the panel holds, which is the
        most a pure-Python buffer can do.  The bytes stay in freed heap until
        the allocator reuses them.  Secrets that must actually be destroyed
        do not live here at all; they live in Rust behind `zeroize()`.  What
        this does guarantee is that no later redraw, tab switch or reconnect
        can put the old conversation back on the screen.
        """
        count = len(self.history)
        for entry in self.history:
            entry["message"] = ""
            entry["metadata"] = {}
        self.history.clear()
        self.unread_count = 0
        self.recent_users.clear()
        return count


class PanelManager:
    """
    Manager for chat panels - COMPLETE REPLACEMENT
    Keeps all original methods (add_panel, switch_to_panel, panel_order, etc.)
    and adds security-icon header rendering.
    """

    def __init__(self, client):
        self.client = client
        self.panels: Dict[str, ChatPanel] = {}
        self.active_panel: Optional[str] = None
        self.panel_order: List[str] = []
        self.lock = threading.RLock()
        self.auto_switch_enabled = True
        self.tab_bar = TabBar()

        self.add_panel("system", "system")

    def add_panel(self, name: str, panel_type: str) -> bool:
        """Add a new panel. Returns True if created, False if already exists."""
        with self.lock:
            if name not in self.panels:
                self.panels[name] = ChatPanel(name, panel_type)
                self.panel_order.append(name)
                if not self.active_panel:
                    self.active_panel = name
                    self.panels[name].active = True
                # Load encrypted session history for this channel/nick
                try:
                    cl = getattr(self.client, "channel_log", None)
                    if cl is not None:
                        history = cl.read_recent(name, n=50000)
                        if history:
                            self.panels[name].add_message("── history ─────────────────────────────")
                            for entry in history:
                                if "|" in entry:
                                    ts_str, body = entry.split("|", 1)
                                    try:
                                        orig_ts = time.mktime(
                                            time.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
                                        )
                                    except Exception:
                                        orig_ts = time.time()
                                    self.panels[name].history.append({
                                        "id": len(self.panels[name].history),
                                        "message": body,
                                        "timestamp": orig_ts,
                                        "metadata": {},
                                    })
                                else:
                                    self.panels[name].add_message(entry)
                            self.panels[name].add_message("── live ─────────────────────────────────")
                except Exception:
                    pass
                self._render_ui()
                return True
            return False

    def get_or_create_panel(self, name: str, panel_type: str = "private") -> ChatPanel:
        """Get existing panel or create a new one."""
        with self.lock:
            if name not in self.panels:
                self.add_panel(name, panel_type)
            return self.panels[name]

    def get_panel(self, name: str) -> Optional[ChatPanel]:
        """Get a panel by name, or None."""
        with self.lock:
            return self.panels.get(name)

    def get_active_panel(self) -> Optional[ChatPanel]:
        """Get the currently active panel."""
        with self.lock:
            if self.active_panel in self.panels:
                return self.panels[self.active_panel]
            return None

    def switch_to_panel(self, name: str) -> bool:
        """Switch the active panel. Returns True on success."""
        with self.lock:
            if name in self.panels:
                if self.active_panel and self.active_panel in self.panels:
                    self.panels[self.active_panel].active = False
                    self.panels[self.active_panel].clear_unread()
                self.active_panel = name
                self.panels[name].active = True
                self.panels[name].clear_unread()
                # Snap to bottom when switching so latest messages show
                try:
                    scr = getattr(self.client, "_screen", None)
                    if scr is not None:
                        scr.scroll_offset = 0
                except Exception:
                    pass
                self._render_ui()
                return True
            return False

    def list_panels(self) -> List[str]:
        """Return ordered list of panel names."""
        with self.lock:
            return list(self.panel_order)

    def add_message(self, target: str, message: str) -> None:
        """Store message in panel buffer. Printing is done by the client's emit()."""
        with self.lock:
            if target not in self.panels:
                self.add_panel(target, "private")
            panel = self.panels[target]
            panel.add_message(message)
            if self.active_panel != target:
                panel.unread_count += 1
            try:
                cl = getattr(self.client, "channel_log", None)
                if cl is not None:
                    cl.append(target, message)
            except Exception:
                pass

    def update_panel_security(self, name: str, level: UIConstants.SecurityLevel) -> None:
        """Update the security level for a panel and re-render."""
        with self.lock:
            if name not in self.panels:
                self.add_panel(name, "private")
            panel = self.panels[name]
            panel.security_level = level
            if level in (
                UIConstants.SecurityLevel.ENCRYPTED,
                UIConstants.SecurityLevel.FINGERPRINT,
                UIConstants.SecurityLevel.SMP_VERIFIED,
            ):
                panel.mark_secure(level)
            self._render_ui()

    def update_smp_progress(self, name: str, step: int, total_steps: int) -> None:
        """Update SMP progress bar for a panel."""
        with self.lock:
            if name in self.panels:
                self.panels[name].update_smp_progress(step, total_steps)
                self._render_ui()

    def clear_panel_history(self, panel_name: str) -> None:
        """Clear message history for one panel."""
        with self.lock:
            if panel_name in self.panels:
                self.panels[panel_name].clear_history()
                self._render_ui()

    def clear_all_histories(self) -> None:
        """Clear message history for all panels."""
        with self.lock:
            for panel in self.panels.values():
                panel.clear_history()
            self._render_ui()

    def render_panel_header(self, panel: ChatPanel) -> str:
        """Build header string: [icon] name [SECURITY_NAME]"""
        level = getattr(panel, "security_level", UIConstants.SecurityLevel.PLAINTEXT)
        icon = UIConstants.SECURITY_ICONS.get(level, "")
        name = colorize(panel.name, "cyan")
        sec_name = UIConstants.SECURITY_NAMES.get(level, "PLAINTEXT")

        color_map = {
            UIConstants.SecurityLevel.PLAINTEXT: "bold_red",
            UIConstants.SecurityLevel.ENCRYPTED: "bold_yellow",
            UIConstants.SecurityLevel.FINGERPRINT: "bold_green",
            UIConstants.SecurityLevel.SMP_VERIFIED: "blue",
        }
        sec_color = color_map.get(level, "white")
        sec_text = colorize(f"[{sec_name }]", sec_color)

        if panel.type in ("private", "secure"):
            return f"{icon } {name } {sec_text }"
        return name

    def _render_ui(self) -> None:
        """Refresh the input prompt, rate-limited to once per 250 ms.

        Called by update_panel_security() and update_smp_progress().
        The 250 ms gate coalesces rapid back-to-back state changes (e.g. the
        4 SMP steps arriving in quick succession) into a single prompt redraw
        so the user never sees a burst of prompt replacements while typing.
        """
        now = time.time()
        if now - getattr(self, "_last_render_ts", 0) < 0.25:
            return
        self._last_render_ts = now
        try:
            cb = getattr(self.client, "_prompt_refresh_cb", None)
            if cb is not None:
                cb()
        except Exception:
            pass
