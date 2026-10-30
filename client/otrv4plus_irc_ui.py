# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The IRC client's terminal: panels and tabs, scrollback, and the slash
commands that are not OTR's (/view, /chat, /lookup, /moderate, /otr,
/people, /help).

A mixin of OTRv4IRCClient (otrv4plus_irc.py); the methods moved here
unchanged."""
import gc
import otrv4plus as _engine
import shutil
import sys
import time
from otrv4plus import NetworkConstants, Screen, TIMESTAMP_FORMAT, UIConstants, VERSION, _display_buffer, _print_lock, _sanitise, _scroll_unlock, _word_wrap, colorize, colorize_username, safe_print
from otrv4plus_irc_util import TwentySevenClubNick, _fmt_duration


class IrcUiMixin:
    """See the module docstring."""


    def _switch_panel(self, name: str, force: bool = False) -> bool:
        """Switch the active panel and replay its buffered history to stdout.

        Single choke-point for all tab switches - /switch, /tab-next,
        /tab-prev, JOIN auto-switch, and tab-close fallback all call here.
        Never call panel_manager.switch_to_panel() directly from user-facing
        code; use this method instead.

        Steps
        -----
        1. Flip the active-panel pointer and clear unread count.
        2. Print a centred panel header so the user sees which tab they entered.
        3. Replay up to _REPLAY_LINES messages with their stored timestamps
           (dimmed) so history is distinct from live output.
        4. Print a thin "live" separator to mark where buffered history ends.

        Switching to the tab that is already active is not a switch, and
        `force` is the only way to make it replay.  Steps 2-4 are what makes
        a redundant call visible: they reprint the whole buffer under the
        *original* timestamps, so a user who had just started a handshake saw

            14:52:59 [Iron] Starting OTR session with Iron...
            14:53:50 [Iron] DAKE1 -> sent - waiting for response...
            ---- Iron ----
            14:52:59 [Iron] Starting OTR session with Iron...
            14:53:50 [Iron] DAKE1 -> sent - waiting for response...
            ---- live ----

        and reasonably read it as the client having sent DAKE1 twice.  It had
        sent it once; the inbound DAKE2's first fragment called back into
        here while the peer tab was already focused.  The identical
        timestamps are the tell -- a real second send carries a new one.

        The guard lives here rather than at the call site because there are
        fifteen call sites and only three of them checked.  `force` is for
        the one case where the redraw *is* the request: `/switch <this tab>`
        typed by a user who has scrolled away from the bottom.
        """
        if name not in self.panel_manager.panels:
            return False

        if not force and self.panel_manager.active_panel == name:
            return True

        self.panel_manager.switch_to_panel(name)
        # Rebuild scroll history from this panel-s actual messages
        # so Ctrl+P scrollback shows only the current panel, not all channels

        _switched_panel = self.panel_manager.panels.get(name)
        if _switched_panel:
            _engine._scroll_history.clear()
            for _e in _switched_panel.history:
                _m = _e.get("message", "").strip()
                if _m:
                    _engine._scroll_history.append(_m)
            if len(_engine._scroll_history) > 500:
                _engine._scroll_history = _engine._scroll_history[-500:]
        if getattr(self, "_tui_enabled", False) and self._screen is not None:
            self._screen.scroll_offset = 0
            self._screen.redraw_full()
            if self._prompt_refresh_cb is not None:
                self._prompt_refresh_cb()
            return True
        panel = self.panel_manager.panels[name]
        if name == "system":
            tag = colorize("[sys]  ", "dim")
        elif name == "debug":
            tag = colorize("[debug]", "magenta")
        elif name.startswith("#"):
            tag = colorize(f"[{name }]", "cyan")
        else:
            tag = colorize(f"[{name }]", "green")
        icon = UIConstants.SECURITY_ICONS.get(panel.security_level, "")
        width = 46
        hdr_name = f" {icon }{name } "
        dashes = max(0, width - len(hdr_name))
        left = dashes // 2
        right = dashes - left
        lines_out = [colorize("─" * left + hdr_name + "─" * right, "cyan")]
        history = panel.history
        if not history:
            lines_out.append(colorize("  (no messages yet)", "dim"))
        else:
            # Replay full history, skip blank entries only
            for entry in history:
                if not entry.get("message", "").strip():
                    continue
                ts = colorize(
                    time.strftime(TIMESTAMP_FORMAT, time.localtime(entry["timestamp"])), "dim")
                lines_out.append(f"{ts } {tag } {entry ['message']}")
        lines_out.append(colorize("─" * left + " live " + "─" * max(0, right - 1), "dim"))
        # Build tab bar line showing all open panels
        try:
            _cols = shutil.get_terminal_size(fallback=(80, 24)).columns
        except Exception:
            _cols = 80
        _pm = self.panel_manager
        _tab_parts = []
        for _pn in _pm.panel_order:
            _pp = _pm.panels.get(_pn)
            if _pp is None:
                continue
            _icon = UIConstants.SECURITY_ICONS.get(_pp.security_level, "🔴")
            _unread = f"({_pp .unread_count })" if _pp.unread_count > 0 else ""
            _label = f"{_icon }{_pn }{_unread }"
            if _pn == name:
                _tab_parts.append(colorize(_label, "cyan"))
            else:
                _tab_parts.append(colorize(_label, "dim"))
        _tab_str = " | ".join(_tab_parts)
        _sep_str = colorize("─" * min(_cols, 80), "dim")
        with _print_lock:
            try:
                buf = _display_buffer()
                if _engine._current_prompt or buf:
                    sys.stdout.write("\x1b[1G\x1b[2K")
                for ln in lines_out:
                    wrapped = _word_wrap(ln, _cols)
                    sys.stdout.write(wrapped + "\n")
                sys.stdout.write(_sep_str + "\n")
                sys.stdout.write(_tab_str + "\n")
                if _engine._current_prompt or buf:
                    sys.stdout.write(_engine._current_prompt + buf)
                sys.stdout.flush()
            except (RuntimeError, ValueError, OSError):
                pass
        return True

    def _purge_scrollback(self, reason: str, announce: bool = True,
                          wipe_terminal: bool = True) -> int:
        """Empty every panel's retained history.  Returns the message count.

        Called at each boundary between one connection and the next --
        disconnect, reconnect, shutdown -- and by `/clear` on demand.

        The boundary is the point: an I2P session is meant to be unlinkable
        to the one before it, and replaying the previous session's
        conversation into the new one links them on the screen no matter what
        the transport did.  It also stopped the unread badges accumulating
        across reconnects (system(53) -> system(105) -> system(158)), which
        was the visible symptom of the same bug.

        `announce` is False on the shutdown path, where adding a message to a
        panel we have just emptied would leave one line behind.

        `wipe_terminal` is False on the automatic-reconnect path, and that is
        a deliberate split rather than an oversight.  Blanking the emulator
        is right when the user is leaving (/quit, process exit) or has asked
        (/clear); doing it on every dropped connection would destroy the
        error messages they are reading to find out what just happened, on a
        transport where a blip is routine.  What the reconnect purge stops is
        the *replay* -- the reported bug -- not the lines already printed.
        """
        purged = 0
        try:
            for panel in self.panel_manager.panels.values():
                try:
                    purged += panel.clear_history()
                except Exception:
                    pass
        except Exception:
            return 0

        # Drop the terminal's own scrollback too.  Clearing our buffers while
        # the emulator still holds the rendered lines would be a half
        # measure: on Termux the visible history IS the scrollback.  \033[3J
        # is the one that empties the saved lines rather than just the
        # viewport.
        try:
            if wipe_terminal and sys.stdout.isatty():
                sys.stdout.write("\033[3J\033[H\033[2J")
                sys.stdout.flush()
        except Exception:
            pass

        # The panel dicts are gone; ask for the collection rather than
        # waiting for it, so the strings are unreferenced promptly instead of
        # at whatever point the allocator next feels like it.
        try:
            gc.collect()
        except Exception:
            pass

        if announce and purged:
            try:
                self.add_message(
                    "system",
                    colorize(f"\U0001f9f9 scrollback cleared ({purged} messages) - {reason}", "dim"),
                )
            except Exception:
                pass
        return purged

    def get_timestamp(self) -> str:
        return time.strftime(TIMESTAMP_FORMAT)

    def clear_screen(self):
        if _engine.IS_TERMUX:
            safe_print("\n" * 60)
        else:
            self.panel_manager._render_ui()

    def switch_to_next_tab(self):
        order = self.panel_manager.panel_order
        if not order:
            return
        cur = self.panel_manager.active_panel
        idx = order.index(cur) if cur in order else -1
        self._switch_panel(order[(idx + 1) % len(order)])

    def switch_to_previous_tab(self):
        order = self.panel_manager.panel_order
        if not order:
            return
        cur = self.panel_manager.active_panel
        idx = order.index(cur) if cur in order else 0
        self._switch_panel(order[(idx - 1) % len(order)])

    def show_tabs(self):
        """List all open panels with unread counts and security indicators."""
        self.add_message("system", colorize("─── Tabs ───────────────────────────────────", "cyan"))
        for i, name in enumerate(self.panel_manager.panel_order):
            p = self.panel_manager.panels[name]
            is_active = name == self.panel_manager.active_panel
            marker = colorize("▶", "green") if is_active else " "
            icon = UIConstants.SECURITY_ICONS.get(p.security_level, "")
            badge = colorize(f" [{p .unread_count } new]", "yellow") if p.unread_count else ""
            name_col = colorize(name, "green" if is_active else "white")
            self.add_message("system", f"  {marker } {i +1 :2d}.  {icon }{name_col }{badge }")
        self.add_message("system", colorize("  /switch <name>  /tab-next  /tab-prev", "dim"))

    def show_status_panel(self):
        self.add_message("system", colorize("── Client Status ─────────────────────────", "cyan"))
        conn_str = colorize("YES", "green") if self.connected else colorize("NO", "red")
        uptime = ""
        if self.connected and hasattr(self, "connected_at"):
            uptime = f"  ({_fmt_duration (time .time ()-self .connected_at )})"
        self.add_message("system", f"  Connected : {conn_str }{uptime }")
        self.add_message("system", f"  Server    : {self .server }")
        self.add_message("system", f"  Nick      : {colorize_username (self .nick )}")
        real = TwentySevenClubNick.real_name(self.nick)
        if real != self.nick:
            self.add_message("system", f"  Identity  : {real }")
        ns_status = ""
        if self.nickserv_identified:
            ns_status = colorize("  (NickServ ✓)", "green")
        elif self.config.nickserv_login or self.config.nickserv_register:
            ns_status = colorize("  (NickServ pending)", "yellow")
        self.add_message(
            "system",
            f"  IRC ready : {colorize ('YES','green')if self .auth_complete else colorize ('NO','yellow')}{ns_status }",
        )
        self.add_message("system", f"  Channels  : {len (self .channels )}")
        self.add_message("system", f"  OTR sess  : {len (self .session_manager .sessions )}")
        self.add_message("system", colorize("──────────────────────────────────────────", "cyan"))

    def handle_chat_message(self, msg: str):
        """Send msg to active panel target, OTR-encrypted if session exists."""
        if not self.connected:
            self.add_message("system", colorize("Not connected", "red"))
            return
        active = self.panel_manager.get_active_panel()
        if not active or active.type in ("system", "debug"):
            self.add_message("system", colorize("Switch to a chat panel first", "red"))
            return
        target = active.name
        if self.session_manager.has_session(target):
            enc = self.session_manager.encrypt_message(target, msg)
            if enc and self.send_otr_message(target, enc):
                sec = self.session_manager.get_security_level(target)
                self.add_message(
                    target,
                    colorize_username(self.nick) + colorize(": ", "dim") + colorize(msg, "white"),
                    sec,
                )
            else:
                self.add_message("system", colorize("❌ Encryption failed", "red"))
        else:
            if self.send(f"PRIVMSG {target } :{msg }"):
                self.add_message(
                    target,
                    colorize_username(self.nick) + colorize(": ", "dim") + colorize(msg, "white"),
                )

    def handle_command(self, command: str):
        """Handle /command from user input."""
        parts = command.strip().split()
        if not parts:
            return
        cmd = parts[0].lower()

        for family in (self._cmd_view, self._cmd_chat, self._cmd_lookup,
                       self._cmd_moderate, self._cmd_otr, self._cmd_people):
            if family(cmd, parts):
                return

        if cmd == "/server":
            if not parts[1:]:
                _cur_net = NetworkConstants.detect(self.server)
                _icons = {"i2p": "🧅 I2P", "tor": "🧅 Tor", "clearnet": "🌐 Clearnet"}
                self.add_message(
                    "system",
                    f"Current server: {colorize (self .server ,'cyan')} "
                    f"({colorize (_icons .get (_cur_net ,_cur_net ),'dark_cyan')})",
                )
                self.add_message("system", colorize("Usage: /server <hostname[:port]>", "dim"))
            else:
                new_srv = parts[1]
                _new_net = NetworkConstants.detect(new_srv)
                _icons = {"i2p": "🧅 I2P", "tor": "🧅 Tor", "clearnet": "🌐 Clearnet"}
                _cols = {"i2p": "dark_cyan", "tor": "dark_magenta", "clearnet": "grey"}
                self.add_message(
                    "system",
                    f"Switching to {colorize (new_srv ,'cyan')} "
                    f"({colorize (_icons .get (_new_net ,_new_net ),_cols .get (_new_net ,'white'))})…",
                )
                if self.connected:
                    self.send_raw("QUIT :switching server")
                    self.connected = False
                    self.running = False
                    try:
                        if self.sock:
                            self.sock.close()
                    except Exception:
                        pass
                self.server = new_srv
                self.config.server = new_srv
                if not self.connect():
                    self.add_message(
                        "system", colorize(f"❌ Failed to connect to {new_srv }", "bold_red")
                    )
            return

        self.add_message(
            "system", colorize(f"❌ Unknown command: {cmd }  (try /help)", "bold_red")
        )

    def _cmd_view(self, cmd, parts):
        """Help, the panels and tabs, the screen, status and diagnostics. True if *cmd* was one of them."""
        if cmd == "help":
            topic = parts[1] if len(parts) > 1 else None
            self.show_help(topic)
        elif cmd == "tui":
            arg = parts[1].lower() if len(parts) > 1 else "toggle"
            if arg in ("on", "1", "yes"):
                want = True
            elif arg in ("off", "0", "no"):
                want = False
            else:
                want = not self._tui_enabled
            self._tui_enabled = want
            if want:
                if self._screen is None:
                    self._screen = Screen(self)
                self._screen.scroll_offset = 0
                _scr = self._screen
                globals()["_TUI_SCROLL_CALLBACK"] = lambda d, p, s=_scr: (
                    s.scroll_up(p) if d == "pgup" else s.scroll_down(p)
                )
                self._screen.redraw_full()
            else:
                globals()["_TUI_SCROLL_CALLBACK"] = None
                with _print_lock:
                    sys.stdout.write("\033[2J\033[H")
                    sys.stdout.flush()
                self.add_message("system", colorize("TUI off - back to scrollback mode.", "dim"))
                if self._prompt_refresh_cb is not None:
                    self._prompt_refresh_cb()
        elif cmd in ("switch", "tab") and len(parts) > 1:
            _sw_name = parts[1]

            if not self._switch_panel(_sw_name, force=True):
                _sw_hashed = "#" + _sw_name if not _sw_name.startswith("#") else _sw_name
                if not self._switch_panel(_sw_hashed, force=True):
                    self.add_message("system", colorize(f"❌ No panel: {_sw_name }", "red"))
        elif cmd == "fragrate":
            self._cmd_fragrate(parts[1] if len(parts) > 1 else "")
        elif cmd == "tabs":
            self.show_tabs()
        elif cmd == "tab-next":
            self.switch_to_next_tab()
        elif cmd == "tab-prev":
            self.switch_to_previous_tab()
        elif cmd == "tab-close" and len(parts) > 1:
            p = parts[1]
            if p in ("system", "debug"):
                return True

            if p not in self.panel_manager.panels and not p.startswith("#"):
                p = "#" + p
            if p in self.panel_manager.panels:
                if self.panel_manager.active_panel == p:
                    self._switch_panel("system")
                del self.panel_manager.panels[p]
                if p in self.panel_manager.panel_order:
                    self.panel_manager.panel_order.remove(p)
                self.panel_manager._render_ui()
        elif cmd == "clear":
            # Bare /clear now empties EVERY panel and the terminal's own
            # scrollback, not just the active tab.  Clearing one tab while
            # the others still hold the conversation -- and while the
            # emulator still has every line of it scrolled off the top -- is
            # not what anyone typing /clear wants; on a handset the threat
            # is someone picking the phone up, and a per-tab clear does
            # nothing about that.  `/clear <panel>` keeps the old behaviour
            # for when you really do mean one tab.
            if len(parts) > 1:
                target = parts[1]
                if target in self.panel_manager.panels:
                    self.panel_manager.clear_panel_history(target)
                else:
                    self.add_message(
                        "system", colorize(f"No such panel: {_sanitise(target, 64)}", "yellow"))
            else:
                self._purge_scrollback("/clear")
        elif cmd == "clear-screen":
            self.clear_screen()
        elif cmd == "status":
            self.show_status_panel()
        elif cmd == "debug":

            _engine.DEBUG_MODE = not _engine.DEBUG_MODE
            if hasattr(self, "logger") and hasattr(self.logger, "set_debug"):
                self.logger.set_debug(_engine.DEBUG_MODE)
            self.add_message("system", f"Debug: {'ON'if _engine.DEBUG_MODE else 'OFF'}")
            if _engine.DEBUG_MODE and "debug" not in self.panel_manager.panels:
                self.panel_manager.add_panel("debug", "debug")
        elif cmd == "version":
            self.add_message("system", f"Version: {VERSION }")
            self.add_message("system", "DAKE   : 🦀 Rust (X448 + ML-KEM-1024 + ML-DSA-87)")
            self.add_message("system", "Ratchet: 🦀 Rust (zeroize-on-drop)")
            self.add_message(
                "system", "SMP    : 🦀 Rust (ML-KEM-1024 + ML-DSA-87 hybrid PQC, ZeroizeOnDrop)"
            )
        elif cmd == "pause":

            _engine._scroll_locked = True
            self.add_message("system", colorize("⏸ Scroll paused - /resume to continue", "yellow"))
        elif cmd == "resume":
            _scroll_unlock()
            self.add_message("system", colorize("▶ Scroll resumed", "green"))
        else:
            return False
        return True

    def _cmd_chat(self, cmd, parts):
        """Joining, leaving and talking: channels, messages, the server. True if *cmd* was one of them."""
        if cmd == "join" and len(parts) > 1:
            _raw = " ".join(parts[1:]).replace(",", " ")
            for _ch in _raw.split():
                _ch = _ch.strip()
                if not _ch:
                    continue
                if not _ch.startswith("#"):
                    _ch = "#" + _ch
                self.send(f"JOIN {_ch }")
        elif cmd == "part":
            ch = parts[1] if len(parts) > 1 else (self.panel_manager.active_panel or "")
            if ch:

                if ch and not ch.startswith("#"):
                    ch = "#" + ch
                self.send(f"PART {ch }")
        elif cmd == "nick" and len(parts) > 1:
            _new_nick = (
                _sanitise(parts[1], 64).split()[0] if _sanitise(parts[1], 64).split() else ""
            )
            if _new_nick:
                self.send(f"NICK {_new_nick }")
        elif cmd == "msg" and len(parts) > 2:
            _msg_target = (
                _sanitise(parts[1], 64).split()[0] if _sanitise(parts[1], 64).split() else ""
            )
            _msg_text = _sanitise(" ".join(parts[2:]), 490)
            if _msg_target:
                self.send(f"PRIVMSG {_msg_target } :{_msg_text }")
                self.add_message(
                    _msg_target,
                    colorize_username(self.nick)
                    + colorize(": ", "dim")
                    + colorize(_msg_text, "white"),
                )
        elif cmd == "topic":
            ch = self.panel_manager.active_panel or ""
            if len(parts) > 1 and parts[1].startswith("#"):
                ch = parts[1]
                new_topic = " ".join(parts[2:]) if len(parts) > 2 else ""
            else:
                new_topic = " ".join(parts[1:]) if len(parts) > 1 else ""
            if new_topic:
                self.send(f"TOPIC {ch } :{new_topic }")
            else:
                self.send(f"TOPIC {ch }")
        elif cmd == "notice" and len(parts) > 2:
            target = _sanitise(parts[1], 64).split()[0] if _sanitise(parts[1], 64).split() else ""
            text = _sanitise(" ".join(parts[2:]), 490)
            if target:
                self.send(f"NOTICE {target } :{text }")
        elif cmd == "invite" and len(parts) > 2:
            _inv_nick = (
                _sanitise(parts[1], 64).split()[0] if _sanitise(parts[1], 64).split() else ""
            )
            _inv_chan = parts[2] if parts[2].startswith("#") else "#" + parts[2]
            _inv_chan = (
                _sanitise(_inv_chan, 64).split()[0] if _sanitise(_inv_chan, 64).split() else ""
            )
            if _inv_nick and _inv_chan:
                self.send(f"INVITE {_inv_nick } {_inv_chan }")
        elif cmd == "away":
            reason = " ".join(parts[1:]) if len(parts) > 1 else "Away"
            self.send(f"AWAY :{reason }")
            self.add_message("system", colorize(f"Set away: {reason }", "dim"))
        elif cmd == "back":
            self.send("AWAY")
            self.add_message("system", colorize("No longer away", "green"))
        elif cmd == "raw" and len(parts) > 1:
            self.send(" ".join(parts[1:]))
        elif cmd == "motd":
            self.send("MOTD")
        elif cmd == "time":
            self.send("TIME")
        elif cmd == "me" and len(parts) > 1:
            _t2 = self.panel_manager.active_panel or ""
            if _t2 and _t2 not in ("system", "debug"):
                _mt = _sanitise(" ".join(parts[1:]), 490)
                self.send(f"PRIVMSG {_t2 } :\x01ACTION {_mt }\x01")
                self.add_message(_t2, colorize(f"* {self .nick } {_mt }", "cyan"))
        elif cmd == "ctcp" and len(parts) > 2:
            _cn = _sanitise(parts[1], 64).split()[0]
            _cc = _sanitise(parts[2], 32).upper()
            _ca = (" " + _sanitise(" ".join(parts[3:]), 400)) if len(parts) > 3 else ""
            if _cn:
                self.send(f"PRIVMSG {_cn } :\x01{_cc }{_ca }\x01")
        elif cmd == "cycle":
            _cy = parts[1] if len(parts) > 1 else self.panel_manager.active_panel or ""
            if _cy and not _cy.startswith("#"):
                _cy = "#" + _cy
            if _cy:
                self.send(f"PART {_cy } :cycling")
                import time as _t3

                _t3.sleep(0.5)
                self.send(f"JOIN {_cy }")
        elif cmd == "setname" and len(parts) > 1:
            self.send(f"SETNAME :{_sanitise (' '.join (parts [1 :]),128 )}")
        elif cmd == "server" and len(parts) > 1:
            _sv = _sanitise(parts[1], 256).split()[0]
            try:
                _sp = int(parts[2]) if len(parts) > 2 else self.config.port
            except ValueError:
                _sp = self.config.port
            if _sv:
                self.config.server = _sv
                self.config.port = _sp
                self.server = _sv
                self.add_message("system", colorize(f"Switching to {_sv }:{_sp }…", "cyan"))
                self._try_reconnect()
        else:
            return False
        return True

    def _cmd_lookup(self, cmd, parts):
        """Finding people: WHOIS, NAMES, WHO, LIST, MONITOR and friends. True if *cmd* was one of them."""
        if cmd == "list":
            self.send("LIST")
        elif cmd == "whois" and len(parts) > 1:
            _whois_nick = (
                _sanitise(parts[1], 64).split()[0] if _sanitise(parts[1], 64).split() else ""
            )
            if _whois_nick:
                self.send(f"WHOIS {_whois_nick }")
        elif cmd == "names":
            ch = parts[1] if len(parts) > 1 else (self.panel_manager.active_panel or "")

            if ch and not ch.startswith("#"):
                ch = "#" + ch
            if ch and ch.startswith("#"):
                self.names_data[ch] = []
                if not hasattr(self, "_otrv4_users"):
                    self._otrv4_users: Dict[str, bool] = {}
                if not hasattr(self, "_names_total"):
                    self._names_total = {}
                self._names_total.pop(ch, None)
                self.send(f"WHO {ch }")
                self.send(f"NAMES {ch }")
                self._pending_names_pager = ch
            else:
                self.add_message("system", colorize("Usage: /names [#channel]", "dim"))
        elif cmd == "who":
            _t = parts[1] if len(parts) > 1 else (self.panel_manager.active_panel or "")
            if _t and not _t.startswith("#"):
                _t = "#" + _t
            if _t:
                self.send(f"WHO {_t }")
            else:
                self.send("WHO")
            self._who_pending = True
            self._who_count = 0
            self.add_message(
                self.panel_manager.active_panel or "system",
                colorize("── WHO (max 200 rows) ────────────────────────────────────", "dim"),
            )
        elif cmd == "whowas" and len(parts) > 1:
            _w = _sanitise(parts[1], 64).split()[0]
            if _w:
                self.send(f"WHOWAS {_w }")
        elif cmd == "ison" and len(parts) > 1:
            self.send(f"ISON {' '.join (_sanitise (p2 ,64 )for p2 in parts [1 :])}")
        elif cmd == "userhost" and len(parts) > 1:
            self.send(f"USERHOST {' '.join (_sanitise (p2 ,64 )for p2 in parts [1 :6 ])}")
        elif cmd == "accept" and len(parts) > 1:
            self.send(f"ACCEPT {_sanitise (parts [1 ],64 )}")
        elif cmd == "monitor" and len(parts) > 1:
            _mop = parts[1]
            if _mop == "l":
                self.send("MONITOR L")
            elif len(parts) > 2:
                self.send(
                    f"MONITOR {_mop .upper ()} {','.join (_sanitise (p2 ,64 )for p2 in parts [2 :])}"
                )
        else:
            return False
        return True

    def _cmd_moderate(self, cmd, parts):
        """Channel moderation: kick, modes, op, voice, bans. True if *cmd* was one of them."""
        if cmd == "kick" and len(parts) > 1:
            ch = self.panel_manager.active_panel or ""
            target = _sanitise(parts[1], 64).split()[0] if _sanitise(parts[1], 64).split() else ""
            reason = _sanitise(" ".join(parts[2:]), 256) if len(parts) > 2 else ""
            if ch.startswith("#") and target:
                self.send(f"KICK {ch } {target }" + (f" :{reason }" if reason else ""))
            elif not target:
                self.add_message("system", colorize("Usage: /kick <nick> [reason]", "dim"))
            else:
                self.add_message("system", colorize("Must be in a channel to kick", "red"))
        elif cmd == "mode":
            if len(parts) > 1:

                _mode_args = [
                    _sanitise(p, 64).split()[0] for p in parts[1:] if _sanitise(p, 64).split()
                ]
                if _mode_args:
                    self.send(f"MODE {' '.join (_mode_args )}")
            else:
                self.add_message("system", colorize("Usage: /mode <target> <+/-flag>", "dim"))
                self.add_message("system", "  Type /help mode for all available modes")
        elif cmd == "op" and len(parts) > 1:
            _ch2 = self.panel_manager.active_panel or ""
            if _ch2.startswith("#"):
                self.send(f"MODE {_ch2 } +{'o'*len (parts [1 :])} {' '.join (parts [1 :])}")
        elif cmd == "deop" and len(parts) > 1:
            _ch2 = self.panel_manager.active_panel or ""
            if _ch2.startswith("#"):
                self.send(f"MODE {_ch2 } -{'o'*len (parts [1 :])} {' '.join (parts [1 :])}")
        elif cmd == "voice" and len(parts) > 1:
            _ch2 = self.panel_manager.active_panel or ""
            if _ch2.startswith("#"):
                self.send(f"MODE {_ch2 } +{'v'*len (parts [1 :])} {' '.join (parts [1 :])}")
        elif cmd == "devoice" and len(parts) > 1:
            _ch2 = self.panel_manager.active_panel or ""
            if _ch2.startswith("#"):
                self.send(f"MODE {_ch2 } -{'v'*len (parts [1 :])} {' '.join (parts [1 :])}")
        elif cmd == "ban" and len(parts) > 1:
            _ch2 = self.panel_manager.active_panel or ""
            if _ch2.startswith("#"):
                self.send(f"MODE {_ch2 } +b {_sanitise (parts [1 ],128 )}")
        elif cmd == "unban" and len(parts) > 1:
            _ch2 = self.panel_manager.active_panel or ""
            if _ch2.startswith("#"):
                self.send(f"MODE {_ch2 } -b {_sanitise (parts [1 ],128 )}")
        elif cmd == "kickban" and len(parts) > 1:
            _ch2 = self.panel_manager.active_panel or ""
            _kbn = _sanitise(parts[1], 64).split()[0]
            _kbr = _sanitise(" ".join(parts[2:]), 200) if len(parts) > 2 else "banned"
            if _ch2.startswith("#") and _kbn:
                self.send(f"MODE {_ch2 } +b {_kbn }!*@*")
                self.send(f"KICK {_ch2 } {_kbn } :{_kbr }")
        else:
            return False
        return True

    def _cmd_otr(self, cmd, parts):
        """OTR sessions, fingerprints, trust and SMP. True if *cmd* was one of them."""
        if cmd == "otr" and len(parts) > 1:
            self.start_guided_otr_session(parts[1])
        elif cmd == "fingerprint":
            fp = (
                self.session_manager.client_profile.get_fingerprint()
                if hasattr(self.session_manager, "client_profile")
                else "N/A"
            )
            self.add_message("system", f"Your fingerprint: {colorize (fp ,'cyan')}")
        elif cmd == "trust" and len(parts) > 2:
            self.session_manager.trust_db.add_trust(parts[1], parts[2])
            self.add_message("system", f"✅ Trusted {parts [1 ]}: {parts [2 ][:16 ]}…")
        # `/smp` is NOT handled here.  It was, from v10.23.0 until v10.23.2,
        # and it never once ran: EnhancedOTRv4IRCClient -- the only class this
        # program instantiates -- overrides handle_command and claims "smp"
        # before the branch that delegates here, so a user typing /smp got
        # "Usage: /smp <command> [args]" from the override while the guided
        # prompt sat in this method unreachable.  Two dispatchers for one
        # command is how that happened; there is now one, in the subclass.
        # `self._smp_verify` is defined there too, so a branch here would
        # raise AttributeError on this class in any case.
        elif cmd == "smp-secret" and len(parts) > 2:
            peer = parts[1]
            secret = " ".join(parts[2:])
            if len(secret) < 8:
                self.add_message(
                    "system",
                    colorize(
                        f"⚠ SMP secret rejected - only {len (secret )} chars. "
                        "Minimum 8 required to resist brute-force attacks.",
                        "red",
                    ),
                )
                return True
            if hasattr(self.session_manager, "smp_storage"):
                self.session_manager.smp_storage.set_secret(peer, secret)
            self.add_message("system", f"🔑 SMP secret set for {peer }")
        elif cmd == "smp-auto" and len(parts) > 1:
            self.schedule_auto_smp(parts[1], delay=1.0)
            self.add_message("system", f"🔄 Auto-SMP scheduled for {parts [1 ]}")
        elif cmd == "smp-abort" and len(parts) > 1:
            self.clear_pending_smp(parts[1])
            self.add_message("system", f"🛑 SMP aborted for {parts [1 ]}")
        elif cmd == "smp-status" and len(parts) > 1:
            status = self.session_manager.get_smp_status(parts[1])
            self.add_message("system", f"SMP {parts [1 ]}: {status }")
        elif cmd in ("secure", "sessions"):
            if not self.session_manager.sessions:
                self.add_message("system", "No OTR sessions active")
            for peer, sess in self.session_manager.sessions.items():
                sec = getattr(sess, "security_level", UIConstants.SecurityLevel.PLAINTEXT)
                icon = UIConstants.SECURITY_ICONS.get(sec, "")
                self.add_message("system", f"  {icon } {colorize_username (peer )}: {sec .name }")
        else:
            return False
        return True

    def _cmd_people(self, cmd, parts):
        """Ignoring people, quitting and reconnecting. True if *cmd* was one of them."""
        if cmd == "ignore" and len(parts) > 1:
            self.ignored_users.add(parts[1])
            self.add_message("system", f"🚫 Ignoring {colorize_username (parts [1 ])}")
        elif cmd == "unignore" and len(parts) > 1:
            self.ignored_users.discard(parts[1])
            self.add_message("system", f"✅ Unignored {colorize_username (parts [1 ])}")
        elif cmd == "ignored":
            if self.ignored_users:
                self.add_message("system", colorize("Ignored users:", "cyan"))
                for u in sorted(self.ignored_users):
                    self.add_message("system", f"  🚫 {colorize_username (u )}")
            else:
                self.add_message("system", colorize("No users ignored", "dim"))
        elif cmd == "quit":
            self.shutdown()
        elif cmd == "reconnect":
            if self.running and self.connected:
                self.add_message("system", colorize("Already connected.", "yellow"))
            else:
                self.add_message("system", colorize("🔄 Reconnecting…", "cyan"))
                self._try_reconnect()
        else:
            return False
        return True


    def show_help(self, topic=None):
        if topic:
            topic = topic.lower().strip()
        lines = []
        header = "OTRv4+ Help"
        if topic in ("mode", "modes"):
            header = "IRC Modes"
            lines = [
                colorize("  User modes (/mode YourNick +flag):", "cyan"),
                "    +i  Invisible - hidden from /who and /names",
                "    +g  Caller-ID - must /accept nick before they can PM you",
                "    +R  Block PMs from unregistered users",
                "    +w  Receive wallops (server announcements)",
                "    +x  Cloak your hostname (hide IP in /whois)",
                "",
                colorize("  Channel modes (/mode #channel +flag):", "cyan"),
                "    +o nick  Give operator status (@)",
                "    +v nick  Give voice status (+)",
                "    +b mask  Ban (e.g. +b *!*@bad.host)",
                "    +m       Moderated - only ops/voiced speak",
                "    +n       No external messages",
                "    +t       Only ops change topic",
                "    +i       Invite-only",
                "    +k pass  Channel password",
                "    +l N     User limit",
                "    +s       Secret - hidden from /list",
                "",
                colorize("  Recommended for privacy:", "yellow"),
                "    /mode YourNick +gi",
            ]
        elif topic == "otr":
            header = "OTR Commands"
            lines = [
                "  /otr <nick>          Start encrypted session",
                "  /endotr <nick>       End session",
                "  /fingerprint         Show your Ed448 fingerprint",
                "  /trust <nick> <fp>   Trust a fingerprint",
                "  /smp                 Verify identity - asks for the",
                "                       passphrase, hidden, and starts",
                "  /smp start           Same as /smp",
                "  /smp <secret>        Same, but typed in the clear (ECHOED)",
                "  /fragrate [preset]   Fragment pacing (safe/normal/fast/turbo/auto)",
                "  /smp abort           Abort SMP",
                "  /smp status          SMP status",
                "  /secure              Show session security levels",
                "",
                colorize("  Security icons:", "yellow"),
                "    🔴 Plaintext  🟡 Encrypted  🟢 Trusted  🔵 SMP verified",
            ]
        elif topic == "irc":
            header = "IRC Commands"
            lines = [
                "  /join <#ch>          Join channel(s) - /join a,b,c",
                "  /part [#ch]          Leave channel",
                "  /nick <name>         Change nickname",
                "  /msg <nick> <text>   Private message",
                "  /names [#ch]         List users - \U0001F535 = OTRv4+ client, 1-9 to /otr",
                "  /list                List channels - pager, q to quit",
                "  /who [#ch]           WHO query with OTRv4+ detection",
                "  /whois <nick>        User info",
                "  /whowas <nick>       Recent disconnected nick",
                "  /ison <nicks>        Check who is online",
                "  /topic [#ch] [text]  View or set topic",
                "  /invite <n> <#ch>    Invite to channel",
                "  /kick <nick> [why]   Kick from channel",
                "  /mode <t> <flag>     Set mode (/help mode)",
                "  /notice <t> <msg>    Send notice",
                "  /away [msg]          Set away",
                "  /back                Clear away",
                "  /me <text>           CTCP ACTION (/me waves)",
                "  /ctcp <n> <cmd>      Send CTCP request",
                "  /cycle [#ch]         Part then rejoin",
                "  /op <nick>           Give op status",
                "  /deop <nick>         Remove op status",
                "  /voice <nick>        Give voice",
                "  /devoice <nick>      Remove voice",
                "  /ban <mask>          Set ban",
                "  /unban <mask>        Remove ban",
                "  /kickban <nick>      Ban + kick",
                "  /accept <nick>       Add to caller-ID list (+g)",
                "  /monitor + <nick>    Watch for nick online/offline",
                "  /setname <text>      Change your realname",
                "  /server <host>       Switch server",
                "  /raw <cmd>           Raw IRC command",
                "  /motd                Fetch server MOTD",
                "  /time                Server time",
                "  /reconnect           Reconnect",
                "  /quit                Disconnect and exit",
            ]
        elif topic == "ui":
            header = "UI Commands"
            lines = [
                "  /tui                 Toggle TUI mode (pinned chrome)",
                "  /tui on|off          Force TUI on or off",
                "  /switch <panel>      Switch to tab",
                "  /tabs                List open tabs",
                "  /tab-next            Next tab",
                "  /tab-prev            Previous tab",
                "  /tab-close <panel>   Close tab",
                "  /clear               Clear all scrollback (local only)",
                "  /clear <panel>       Clear just that tab",
                "  /ignore <nick>       Ignore user",
                "  /unignore <nick>     Unignore",
                "  /status              Connection status",
                "  /debug               Toggle debug mode",
                "  /version             Version info",
                "  /pause               Pause scrolling",
                "  /resume              Resume scrolling",
            ]
        else:
            lines = [
                colorize("  Quick start:", "yellow"),
                "    /join #channel     Join a channel",
                "    /otr <nick>        Start encrypted chat",
                "    /smp               Verify identity - prompts, hidden",
                "    /names             List users - \U0001F535 = OTRv4+ (identification only)",
                "    /list              List all channels - pager",
                "    /quit              Exit",
                "",
                colorize("  Help topics (type /help <topic>):", "yellow"),
                "    /help irc    - all IRC commands",
                "    /help otr    - OTR encryption",
                "    /help mode   - IRC modes (+g, +i, etc)",
                "    /help ui     - TUI and navigation",
                "",
                colorize("  Privacy tip:", "green"),
                "    /mode YourNick +gi   Invisible + block unsolicited PMs",
            ]
        self.pager.display(lines, header)
