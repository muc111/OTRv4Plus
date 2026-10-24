# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""The XMPP client's inline terminal UI: panels, routing and keys.

A mixin of OTRv4PlusXMPP (otrv4plus_xmpp.py). The panels and the screen
are the engine's (otrv4+.py); this module routes the client's output to
them and turns key presses into commands.

The engine's TUI pieces are handed over by the client once it has loaded
the engine (`bind_engine`): this module does not import the engine."""
import builtins
import re
import sys
import time

import otrv4plus_term as _term
from otrv4plus_term import print  # noqa: A004 (the client's print)

# The engine's TUI pieces; set by bind_engine().
_otr = None
_PanelManager = _Screen = _UIConstants = None
_setup_raw_mode = _restore_terminal = _read_one_char = None
_handle_input_char = _set_prompt = None
_EOF_SENTINEL = object()
_TUI_AVAILABLE = False
_colorize = lambda s, c: s  # noqa: E731

# Matches a bare JID for output panel routing.
_JID_PATTERN = re.compile(r"[A-Za-z0-9_.+-]+@[A-Za-z0-9_.-]+")


def bind_engine(otr, colorize) -> None:
    """Take the engine's TUI from the client, which calls this once it has
    loaded the engine (this module does not import it)."""
    global _otr, _PanelManager, _Screen, _UIConstants, _setup_raw_mode
    global _restore_terminal, _read_one_char, _handle_input_char, _set_prompt
    global _EOF_SENTINEL, _TUI_AVAILABLE, _colorize
    _otr = otr
    _PanelManager = getattr(otr, "PanelManager", None)
    _Screen = getattr(otr, "Screen", None)
    _UIConstants = getattr(otr, "UIConstants", None)
    _setup_raw_mode = getattr(otr, "_setup_raw_mode", None)
    _restore_terminal = getattr(otr, "_restore_terminal", None)
    _read_one_char = getattr(otr, "_read_one_char", None)
    _handle_input_char = getattr(otr, "_handle_input_char", None)
    _set_prompt = getattr(otr, "_set_prompt", None)
    _EOF_SENTINEL = getattr(otr, "_EOF_SENTINEL", object())
    _TUI_AVAILABLE = all(x is not None for x in (
        _PanelManager, _Screen, _UIConstants, _setup_raw_mode,
        _restore_terminal, _read_one_char, _handle_input_char, _set_prompt))
    _colorize = colorize

class TuiMixin:
    """The inline TUI. Mixed into OTRv4PlusXMPP."""

    # =========================================================================
    # Inline terminal UI (drives the engine's TUI)
    # =========================================================================

    _SYS_PREFIXES = (
        "[i2p]",
        "[tls]",
        "[connected]",
        "[version]",
        "[ready]",
        "[sub]",
        "[status]",
        "[keepalive]",
        "[disconnected]",
        "[connection",
        "[stream",
        "[reconnect]",
        "[auth",
        "[delivery",
        "[sent plain]",
        "[queued]",
        "[roster]",
        "[block]",
        "[help]",
        "[rate-limit]",
        "[receipt]",
        "[ping]",
        "[presence]",
    )

    def _tui_label_for(self, jid):
        """Return a short, unique tab label for a peer JID."""
        jid = jid.split("/", 1)[0].rstrip(".,;:!?)]}>\"'")
        existing = self._tui_label_by_jid.get(jid)
        if existing is not None:
            return existing
        local = jid.split("@", 1)[0] or jid
        label = local
        if label in self._tui_jid_by_label and self._tui_jid_by_label[label] != jid:
            dom = jid.split("@", 1)[1] if "@" in jid else ""
            label = "%s@%s" % (local, dom[:6])
            if label in self._tui_jid_by_label and self._tui_jid_by_label[label] != jid:
                label = jid
        self._tui_jid_by_label[label] = jid
        self._tui_label_by_jid[jid] = label
        return label

    def _extract_peer(self, line: str) -> "str | None":
        """Return the first non-self bare JID found in a line, or None.
        Shared by the module-level print() channel-log hook and by
        _tui_route_output so both use identical peer-identification logic."""
        own_bare = self.boundjid.bare if self.boundjid else None
        for mm in _JID_PATTERN.finditer(line):
            cand = mm.group(0).split("/", 1)[0].rstrip(".,;:!?)]}>\"'")
            if cand == self._own_bare or (own_bare and cand == own_bare):
                continue
            return cand
        return None

    def _tui_route_output(self, line):
        """Route one harness output line into the panel system.

        Routing priority:
          1. Protocol/trace lines ([otr-trace], [otr-recv], [otr-send],
             [otr-probe], [otr-crypto], [keepalive]) → debug panel.
             They contain the peer JID and would flood the peer panel.
          2. System lines ([connected], [i2p], ...) → system panel.
          3. Lines with a peer JID → that peer's panel.
          4. Continuation lines (no JID, no sys prefix) → last peer panel.
        """
        if line == "":
            return

        # --- Protocol / trace lines → debug panel (keep peer panel clean) ---
        _PROTO_PREFIXES = (
            "[otr-trace]", "[otr-recv]", "[otr-send]",
            "[otr-probe]", "[otr-crypto]", "[keepalive]",
        )
        stripped = line.lstrip()
        if any(stripped.startswith(p) for p in _PROTO_PREFIXES):
            # Still scan for SMP/badge signals before routing to debug
            jid = None
            for mm in _JID_PATTERN.finditer(line):
                cand = mm.group(0).split("/", 1)[0].rstrip(".,;:!?)]}>\"'")
                if cand != self._own_bare:
                    jid = cand
                    break
            # Belt-and-braces SMP detection: update peer panel badge even
            # when the trace line itself goes to debug
            _smp_ok_signals = ("SMP VERIFIED", "SMP complete",
                               "IDENTITY VERIFIED", "VERIFIED → STATE_UPDATED",
                               "SMP_VERIFIED")
            if any(s in line for s in _smp_ok_signals):
                check_peer = jid or self._tui_jid_by_label.get(
                    self._tui_last_panel)
                if check_peer and (check_peer, "SUCCEEDED") not in self._smp_display_hints:
                    self._smp_display_hints.add((check_peer, "SUCCEEDED"))
                    try:
                        SL = _UIConstants.SecurityLevel
                        lbl = self._tui_label_for(check_peer)
                        self.panel_manager.update_panel_security(
                            lbl, SL.SMP_VERIFIED)
                    except Exception:
                        pass
            try:
                self.panel_manager.add_message("debug", line)
            except Exception:
                pass
            if self._tui_enabled and self._screen is not None:
                try:
                    if self.panel_manager.active_panel == "debug":
                        self._screen.redraw_body()
                    self._screen.redraw_tabbar()
                except Exception:
                    pass
            return

        # --- Normal routing for everything else ---
        own_bare = self.boundjid.bare if self.boundjid else None
        jid = None
        for mm in _JID_PATTERN.finditer(line):
            cand = mm.group(0).split("/", 1)[0].rstrip(".,;:!?)]}>\"'")
            if cand == self._own_bare or (own_bare and cand == own_bare):
                continue
            jid = cand
            break
        if jid:
            target = self._tui_label_for(jid)
            self._tui_last_panel = target
        else:
            if any(stripped.startswith(p) for p in self._SYS_PREFIXES):
                target = "system"
            else:
                target = self._tui_last_panel or "system"

        self._tui_update_badge(target, line)

        # Belt-and-braces SMP signal detection on non-trace lines
        _smp_ok_signals = ("SMP VERIFIED", "SMP complete",
                           "IDENTITY VERIFIED", "SMP_VERIFIED")
        if any(s in line for s in _smp_ok_signals):
            check_peer = jid or self._tui_jid_by_label.get(target)
            if check_peer and (check_peer, "SUCCEEDED") not in self._smp_display_hints:
                self._smp_display_hints.add((check_peer, "SUCCEEDED"))
                try:
                    SL = _UIConstants.SecurityLevel
                    lbl = self._tui_label_for(check_peer)
                    self.panel_manager.update_panel_security(lbl, SL.SMP_VERIFIED)
                except Exception:
                    pass

        try:
            self.panel_manager.add_message(target, line)
        except Exception:
            return
        if (
            not self._tui_autofocused
            and target != "system"
            and self.panel_manager.active_panel == "system"
        ):
            self._tui_autofocused = True
            try:
                self.panel_manager.switch_to_panel(target)
                self._refresh_prompt()
                if self._screen is not None:
                    self._screen.redraw_full()
                return
            except Exception:
                pass
        if self._tui_enabled and self._screen is not None:
            try:
                if target == self.panel_manager.active_panel:
                    self._screen.redraw_body()
                self._screen.redraw_tabbar()
            except Exception:
                pass

    def _tui_update_badge(self, target, line):
        if target == "system" or _UIConstants is None:
            return
        SL = _UIConstants.SecurityLevel
        try:
            if "SMP VERIFIED" in line or "SMP complete" in line:
                # 🔵 Blue: only after SMP identity verification completes
                self.panel_manager.update_panel_security(target, SL.SMP_VERIFIED)
            elif "Fingerprint TRUSTED" in line or "identity pinned" in line:
                # 🟢 Green: fingerprint accepted / TOFU trust pinned, not yet SMP
                fp_level = getattr(SL, "FINGERPRINT", SL.ENCRYPTED)
                self.panel_manager.update_panel_security(target, fp_level)
            elif "is ENCRYPTED" in line:
                # Intermediate: DAKE complete but fingerprint not yet confirmed
                self.panel_manager.update_panel_security(target, SL.ENCRYPTED)
        except Exception:
            pass

    def _refresh_prompt(self):
        pm = getattr(self, "panel_manager", None)
        active = pm.get_active_panel() if pm else None
        if active is None:
            _set_prompt(_colorize("> ", "green"))
            return
        icon = ""
        if _UIConstants is not None:
            icon = _UIConstants.SECURITY_ICONS.get(active.security_level, "")
        name = "system" if active.name == "system" else active.name
        _set_prompt(
            _colorize(self.nick, "cyan")
            + _colorize(" | ", "dim")
            + _colorize(f"[{icon}{name}]", "green")
            + " "
        )

    def _tui_peer_hint(self, label):
        hint = (
            "Type /otr to start an encrypted session with %s.  You'll then "
            "confirm the fingerprint and set a shared SMP secret to verify "
            "identity.  /help for all commands.  /quit to exit." % label
        )
        try:
            self.panel_manager.add_message(label, _colorize(hint, "yellow"))
        except Exception:
            pass

    def _make_debug_log_handler(self):
        import logging as _logging
        client = self

        class _DebugTabHandler(_logging.Handler):
            def __init__(self):
                super().__init__(_logging.DEBUG)
                self.setFormatter(
                    _logging.Formatter("%(levelname)s %(name)s: %(message)s")
                )

            def emit(self, record):
                try:
                    msg = self.format(record)
                except Exception:
                    return
                try:
                    client._tui_log_to_debug(msg)
                except Exception:
                    pass

        return _DebugTabHandler()

    def _tui_log_to_debug(self, msg):
        if not (self._tui_enabled and self.panel_manager is not None):
            return
        try:
            self.panel_manager.add_message("debug", _colorize(msg, "magenta"))
        except Exception:
            return
        if self._screen is not None:
            try:
                if self.panel_manager.active_panel == "debug":
                    self._screen.redraw_body()
                self._screen.redraw_tabbar()
            except Exception:
                pass

    def _start_tui(self, loop, debug=False):
        """Attach and start the engine's TUI. Returns True if it took over."""
        if not (_TUI_AVAILABLE and sys.stdin.isatty() and sys.stdout.isatty()):
            return False
        self._loop = loop
        self.panel_manager = _PanelManager(self)
        self._screen = _Screen(self)
        self._tui_enabled = True
        self._prompt_refresh_cb = self._refresh_prompt
        _term._ACTIVE_TUI_CLIENT = self

        import logging as _logging
        root = _logging.getLogger()
        self._saved_log_handlers = root.handlers[:]
        for h in self._saved_log_handlers:
            root.removeHandler(h)
        if debug:
            self.panel_manager.get_or_create_panel("debug", "debug")
            root.addHandler(self._make_debug_log_handler())
            root.setLevel(_logging.DEBUG)
        else:
            root.addHandler(_logging.NullHandler())

        self._raw = _setup_raw_mode()
        try:
            loop.add_reader(sys.stdin.fileno(), self._tui_on_readable)
        except Exception:
            pass
        # Wire Page Up/Down into the TUI screen scroll
        try:
            scr = self._screen
            _otr._TUI_SCROLL_CALLBACK = lambda d, p, s=scr: (
                s.scroll_up(p) if d == "pgup" else s.scroll_down(p)
            )
        except Exception:
            pass
        if self.peer:
            label = self._tui_label_for(self.peer)
            self.panel_manager.get_or_create_panel(label, "private")
            # Load persistent encrypted history into the panel
            try:
                if self.channel_log is not None:
                    panel = self.panel_manager.panels.get(label)
                    if panel is not None:
                        history = self.channel_log.read_recent(label, n=50000)
                        if history:
                            panel.add_message("── history ─────────────────────────────")
                            for entry in history:
                                if "|" in entry:
                                    ts_str, body = entry.split("|", 1)
                                    try:
                                        orig_ts = time.mktime(
                                            time.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
                                        )
                                    except Exception:
                                        orig_ts = time.time()
                                    panel.history.append({
                                        "id": len(panel.history),
                                        "message": body,
                                        "timestamp": orig_ts,
                                        "metadata": {},
                                    })
                                else:
                                    panel.add_message(entry)
                            panel.add_message("── live ─────────────────────────────────")
            except Exception:
                pass
            self.panel_manager.switch_to_panel(label)
            self._tui_last_panel = label
            self._tui_autofocused = True
            self._tui_peer_hint(label)
        self._refresh_prompt()
        self._screen.redraw_full()
        return True

    def _stop_tui(self):
        if not getattr(self, "_tui_enabled", False):
            return
        self._tui_enabled = False
        _term._ACTIVE_TUI_CLIENT = None
        try:
            _otr._TUI_SCROLL_CALLBACK = None
        except Exception:
            pass
        try:
            self._loop.remove_reader(sys.stdin.fileno())
        except Exception:
            pass
        try:
            _restore_terminal()
        except Exception:
            pass
        try:
            import logging as _logging
            root = _logging.getLogger()
            for h in list(root.handlers):
                root.removeHandler(h)
            for h in getattr(self, "_saved_log_handlers", []):
                root.addHandler(h)
        except Exception:
            pass
        builtins.print("\r")

    def _clear_and_exit_msg(self) -> None:
        """Clear the Termux screen and print termination message — mirrors IRC."""
        try:
            sys.stdout.write("\033[2J")
            sys.stdout.write("\033[H")
            sys.stdout.write("\033[3J")
            sys.stdout.flush()
            builtins.print("\n" * 100, end="")
            try:
                import subprocess as _subp
                _subp.run(["clear"], check=False)
            except Exception:
                pass
            _rust = getattr(_otr, "RUST_RATCHET_AVAILABLE", False)
            _wipe = "🦀 Rust memory zeroized" if _rust else "Memory cleared"
            builtins.print(f"\nOTRv4+ XMPP terminated - {_wipe} - screen cleared")
            builtins.print("Type 'python otrv4plus_xmpp.py' to start again")
        except Exception:
            pass

    def _tui_quit_to_plain(self) -> None:
        """Stop the tabbed TUI and revert to plain scrollback, keeping the
        XMPP connection alive. Called by the /tui runtime toggle command."""
        if not getattr(self, "_tui_enabled", False):
            return
        self._stop_tui()
        builtins.print(
            "\n[tui] reverted to plain scrollback. "
            "Type /tui to switch back. Commands still work."
        )

    def _tui_quit(self):
        self._shutting_down = True
        self.cleanup()
        self._stop_tui()
        self._clear_and_exit_msg()
        try:
            self.disconnect()
        except Exception:
            pass

    def _tui_on_readable(self):
        try:
            ch = _read_one_char()
        except Exception:
            return
        if ch is None:
            self._tui_quit()
            return
        try:
            res = _handle_input_char(ch)
        except Exception:
            return
        if res is None:
            return
        if res is _EOF_SENTINEL:
            self._tui_quit()
            return
        self._tui_handle_line(res)

    def _tui_handle_line(self, line):
        if not line:
            self._refresh_prompt()
            return
        if self._tui_nav(line):
            self._refresh_prompt()
            if self._screen is not None:
                self._screen.redraw_full()
            return
        active = self.panel_manager.active_panel
        peer = self._tui_jid_by_label.get(active)
        if peer is None:
            peer = self.peer or None
        if peer and not line.startswith("/") and not self.has_pending(peer):
            smp_ok = peer and (peer, "SUCCEEDED") in getattr(self, "_smp_reported", set())
            you_s = _colorize("you", "cyan")
            msg_s = _colorize(line, "dark_blue") if smp_ok else line
            self.panel_manager.add_message(active, you_s + ": " + msg_s)
        try:
            keep = self.dispatch_line(peer, line)
        except Exception as exc:
            self.panel_manager.add_message(active, _colorize(f"[error] {exc}", "red"))
            keep = True
        if keep is False:
            self._tui_quit()
            return
        self._refresh_prompt()
        if self._tui_enabled and self._screen is not None:
            self._screen.redraw_full()

    def _tui_nav(self, line):
        """Handle TUI-only tab navigation commands. Returns True if consumed."""
        pm = self.panel_manager
        parts = line.split()
        cmd = parts[0]
        order = pm.panel_order
        if cmd in ("/next", "/n"):
            i = order.index(pm.active_panel)
            pm.switch_to_panel(order[(i + 1) % len(order)])
            return True
        if cmd in ("/prev", "/p"):
            i = order.index(pm.active_panel)
            pm.switch_to_panel(order[(i - 1) % len(order)])
            return True
        if cmd in ("/win", "/window", "/w", "/switch", "/sw", "/go", "/buffer", "/b", "/j"):
            if len(parts) > 1:
                a = parts[1]
                if a.isdigit():
                    idx = int(a) - 1
                    if 0 <= idx < len(order):
                        pm.switch_to_panel(order[idx])
                elif a in pm.panels:
                    pm.switch_to_panel(a)
                else:
                    hit = [n for n in order if n.startswith(a)]
                    if len(hit) == 1:
                        pm.switch_to_panel(hit[0])
                    else:
                        pm.add_message(
                            pm.active_panel,
                            "no tab '%s'. tabs: %s" % (a, ", ".join(order))
                        )
            else:
                names = ", ".join(
                    "%d:%s" % (i + 1, n) for i, n in enumerate(order)
                )
                pm.add_message(pm.active_panel, "tabs: " + names)
            return True
        if cmd[1:].isdigit():
            idx = int(cmd[1:]) - 1
            if 0 <= idx < len(order):
                pm.switch_to_panel(order[idx])
            return True
        if cmd in ("/tabs", "/windows"):
            names = ", ".join(
                "%d:%s" % (i + 1, n) for i, n in enumerate(order)
            )
            pm.add_message(pm.active_panel, "tabs: " + names)
            return True
        if cmd in ("/close", "/wc"):
            name = pm.active_panel
            if name != "system" and name in pm.panels:
                i = order.index(name)
                pm.panels.pop(name, None)
                order.remove(name)
                pm.switch_to_panel(order[max(0, i - 1)])
            return True
        if cmd == "/clear":
            p = pm.panels.get(pm.active_panel)
            if p is not None:
                p.clear_history()
            return True
        return False
